/*
 * XnuLoader for Xiaomi peridot (Poco F6 / SM8635) — fresh rewrite.
 *
 * Handoff contract (Mu-Silicium + BootShim, see ../../PORTING.md):
 *   - BootShim copies FD_SIZE bytes to FD_BASE (0xA7100000), then stores the
 *     address of the tail chain (the bytes appended after the FD image) at
 *     0xA7400000 (= FD_BASE + FD_SIZE). Tail blocks (appended by build_uefi.py,
 *     each 16-byte aligned):
 *         [pad] "XNUKERN1" | u64 size | kernel Mach-O
 *         [pad] "XNUFDT01" | u64 size | Apple device tree (ADT)
 *         [pad] "XNUROOT1" | u64 size | HFS+ ram disk (optional)
 *   - This EFI application is embedded into the FV as USAGE=APPLICATION with
 *     GUID 7A3B1C2D-4E5F-4061-8234-9A0B1C2D3E4F and launched by BootManagerLib
 *     (LoadImage from buffer, no device path — hence the fixed tail address).
 *
 * Kernel placement (block-mapping contract of osfmk/arm64/start.s):
 *   - Two kernel flavours are handled:
 *       * legacy 0-based PIE: __TEXT.vmaddr == 0, LC_MAIN entry and a
 *         classic LC_DYLD_INFO_ONLY rebase stream (every pointer needs
 *         +XNU_KVA_BASE before handoff);
 *       * natively linked: __TEXT.vmaddr == the link base (e.g.
 *         0xfffffe0007004000), LC_UNIXTHREAD entry, no rebases — the
 *         pointers already carry their final VAs, so the kernel is mapped
 *         at its own link base (virtBase == link base, slide 0).
 *   - The load base is chosen from the actual EFI memory map (conventional
 *     descriptors), big enough for kernel + 16MB headroom, and never
 *     overlapping the BootShim/payload RAM. It also preserves the start.s
 *     block-pairing invariant "physBase mod 32MB == virtBase mod 32MB" by
 *     carrying the link base's low 25 bits. The image is copied so that
 *     link VA v maps to physical mLoadBase + (v - link base); the mach
 *     header therefore lands exactly at mLoadBase, which start.cpu.s relies
 *     on ("adrp _mh_execute_header" at runtime).
 *   - boot_args: physBase = mLoadBase, virtBase = mKvaBase (link base for
 *     natively linked kernels, XNU_KVA_BASE for the PIE), memSize = flat
 *     span from the chosen region (capped). start.s's ptovirt reduction
 *     then yields kva(pa) = pa - physBase + virtBase for every loaded byte.
 *   - The LC_DYLD_INFO rebase opcode stream, when present, is parsed and
 *     each REBASE_TYPE_POINTER slot gains the slide (virtBase - link base)
 *     before handoff (the image is fully pre-linked; there are no binds).
 *   - The /chosen dram-base/dram-size properties are rewritten to the
 *     runtime placement before handoff, and /chosen/memory-map/RAMDisk is
 *     pointed at a ram disk image (placed right after the kernel inside the
 *     reserved region) so IOFindBSDRoot can create md0 with "rd=md0".
 *   - Entry: LC_MAIN entryoff or the LC_UNIXTHREAD pc. The jump happens at
 *     EL1 with MMU off; if we are at EL2 we drop to EL1 via ERET first
 *     (HCR=0, CNTVOFF=0, timers accessible from EL1). x0 = physical pointer
 *     of boot_args.
 *
 * Memory model reported to XNU: flat span [physBase, physBase+memSize) where
 * both come from the chosen load region (capped at XNU_MEM_SIZE_CAP). Boot
 * args + ADT copy live in a window above topOfKernelData, inside the flat
 * span, with 16MB of headroom reserved.
 */

#include <Uefi.h>
#include <Library/UefiApplicationEntryPoint.h>
#include <Library/UefiLib.h>
#include <Library/UefiBootServicesTableLib.h>
#include <Library/BaseLib.h>
#include <Library/BaseMemoryLib.h>
#include <Library/MemoryAllocationLib.h>
#include <Library/PrintLib.h>
#include <Library/DebugLib.h>
#include <Protocol/GraphicsOutput.h>

#define BOOTSHIM_TAIL_PTR_ADDR  0xA7400000ULL

#define XNU_MEM_SIZE_CAP        0x38000000ULL   /* reported memSize cap               */
#define XNU_KVA_BASE            0xFFFFFFF008000000ULL   /* virtBase for 0-based PIE   */
#define XNU_HEADROOM            0x01000000ULL   /* 16MB window for args + ADT         */
#define XNU_LOAD_ALIGN          0x02000000ULL   /* 32MB: block-map invariant          */

#define XNUKERN1_MAGIC          0x314E52454B554E58ULL  /* "XNUKERN1" */
#define XNUFDT01_MAGIC          0x3130544446554E58ULL  /* "XNUFDT01" */
#define XNUROOT1_MAGIC          0x31544F4F52554E58ULL  /* "XNUROOT1" */

#define XNU_LOG_STALL_US        20000
#define XNU_PRINT(...)          do { Print (__VA_ARGS__); if (gBS != NULL) { gBS->Stall (XNU_LOG_STALL_US); } } while (0)

#define MH_MAGIC_64             0xfeedfacfU
#define CPU_TYPE_ARM64          0x0100000cU
#define MH_EXECUTE              2U

#define LC_SEGMENT_64           0x19U
#define LC_UNIXTHREAD           0x05U
#define LC_DYLD_INFO            0x1DU
#define LC_DYLD_INFO_ONLY       0x80000022U   /* NOT 0x22! */
#define LC_MAIN                 0x80000028U

#define ARM_THREAD_STATE64      6U            /* LC_UNIXTHREAD flavor       */
#define ARM_THREAD_STATE64_PC_OFF 256U        /* state: x[29],fp,lr,sp,pc    */

/* dyld rebase opcodes — per EXTERNAL_HEADERS/mach-o/loader.h (xnu-8796.141.3):
 *   0x10 SET_TYPE_IMM           imm   = type
 *   0x20 SET_SEGMENT_AND_OFFSET imm   = seg index, + uleb offset
 *   0x30 ADD_ADDR_ULEB                + uleb
 *   0x40 ADD_ADDR_IMM_SCALED    imm   = scale (x pointer size)
 *   0x50 DO_REBASE_IMM_TIMES    imm   = count
 *   0x60 DO_REBASE_ULEB_TIMES         + uleb count
 *   0x70 DO_REBASE_ADD_ADDR_ULEB      1 rebase, then advance + uleb
 *   0x80 DO_REBASE_ULEB_TIMES_SKIPPING_ULEB + uleb count + uleb skip
 */
#define REBASE_TYPE_POINTER     1
#define RP_DONE                 0x00
#define RP_SET_TYPE_IMM         0x10
#define RP_SET_SEG_OFF_ULEB     0x20
#define RP_ADD_ADDR_ULEB        0x30
#define RP_ADD_ADDR_IMM_SCALED  0x40
#define RP_DO_REBASE_IMM_TIMES  0x50
#define RP_DO_REBASE_ULEB_TIMES 0x60
#define RP_DO_REBASE_ADD_ADDR_ULEB             0x70
#define RP_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB  0x80

/* Base command line; " rd=md0" is appended when a ram disk is present.
 * peridotusb=2 starts the USB device-mode gadget (ECM) once the kernel is up;
 * cpus=8 brings up all eight cores (3x A520 + 4x A720 + 1x X4, one
 * homogeneous cluster; PERIDOT_SMP_MAX_CPUS is 8). */
#define BOOTARG_STRING          "-v -noprogress keepsyms=1 debug=0x14e serial=3 peridotusb=2 peridottouch=1 peridottouchstage=4 peridottouchdelay=120 cpus=8 rd=ufsroot0 ufsrw=1 rootrw=1 unentitled_ios_sim_launch=1 launchd_unsecure_cache=1 wdt=-1 peridotfb_hz=30 peridotfb_force_on=1 peridotfb_noconsole=1 peridotfb_default=1080 peridotlogpace=30000 peridotscan=backboardd,SpringBoard,bluetoothd,fairplayd.H2,xpcproxy peridotsample=-"

#define BOOT_LINE_LENGTH        608
#define MAX_SEGMENTS            32
#define MAX_TAIL_BLOCKS         8

/* ------------------------------------------------------------------ */
/* Boot_args — pexpert/pexpert/arm64/boot.h (xnu-8796.141.3)            */
/* ------------------------------------------------------------------ */
typedef struct Boot_Video {
    UINT64 v_baseAddr;
    UINT64 v_display;
    UINT64 v_rowBytes;
    UINT64 v_width;
    UINT64 v_height;
    UINT64 v_depth;
} Boot_Video;

typedef struct boot_args {
    UINT16     Revision;               /* +0   */
    UINT16     Version;                /* +2   */
    UINT64     virtBase;               /* +8   */
    UINT64     physBase;               /* +16  */
    UINT64     memSize;                /* +24  */
    UINT64     topOfKernelData;        /* +32  */
    Boot_Video Video;                  /* +40  */
    UINT32     machineType;            /* +88  */
    UINT32     _pad_machineType;
    UINT64     deviceTreeP;            /* +96  */
    UINT32     deviceTreeLength;       /* +104 */
    char       CommandLine[BOOT_LINE_LENGTH];  /* +108 */
    UINT64     bootFlags;              /* +720 */
    UINT64     memSizeActual;          /* +728 */
} boot_args;

/* The kernel interprets raw memory at these offsets; a layout drift here
 * produces a silent triple fault, not a diagnostic. Pin it at compile time. */
STATIC_ASSERT (OFFSET_OF (boot_args, Video) == 40, "boot_args Video offset");
STATIC_ASSERT (OFFSET_OF (boot_args, machineType) == 88, "boot_args machineType offset");
STATIC_ASSERT (OFFSET_OF (boot_args, deviceTreeP) == 96, "boot_args deviceTreeP offset");
STATIC_ASSERT (OFFSET_OF (boot_args, deviceTreeLength) == 104, "boot_args deviceTreeLength offset");
STATIC_ASSERT (OFFSET_OF (boot_args, CommandLine) == 108, "boot_args CommandLine offset");
STATIC_ASSERT (OFFSET_OF (boot_args, bootFlags) == 720, "boot_args bootFlags offset");
STATIC_ASSERT (OFFSET_OF (boot_args, memSizeActual) == 728, "boot_args memSizeActual offset");
STATIC_ASSERT (sizeof (boot_args) == 736, "boot_args size");

/* ------------------------------------------------------------------ */
/* Mach-O                                                              */
/* ------------------------------------------------------------------ */
typedef struct {
    UINT32 magic;
    UINT32 cputype;
    UINT32 cpusubtype;
    UINT32 filetype;
    UINT32 ncmds;
    UINT32 sizeofcmds;
    UINT32 flags;
    UINT32 reserved;
} mach_header_64;

typedef struct {
    UINT32 cmd;
    UINT32 cmdsize;
} load_command;

typedef struct {
    UINT32 cmd;
    UINT32 cmdsize;
    CHAR8  segname[16];
    UINT64 vmaddr;
    UINT64 vmsize;
    UINT64 fileoff;
    UINT64 filesize;
    UINT32 maxprot;
    UINT32 initprot;
    UINT32 nsects;
    UINT32 flags;
} segment_command_64;

typedef struct {
    UINT32 cmd;
    UINT32 cmdsize;
    UINT64 entryoff;
    UINT64 stacksize;
} entry_point_command;

typedef struct {
    UINT32 cmd;
    UINT32 cmdsize;
    UINT32 rebase_off;
    UINT32 rebase_size;
    UINT32 bind_off;
    UINT32 bind_size;
    UINT32 weak_bind_off;
    UINT32 weak_bind_size;
    UINT32 lazy_bind_off;
    UINT32 lazy_bind_size;
    UINT32 export_off;
    UINT32 export_size;
} dyld_info_command;

/* ------------------------------------------------------------------ */
/* Globals collected from the kernel image                             */
/* ------------------------------------------------------------------ */
STATIC UINT8  *mKernelPtr = NULL;
STATIC UINT64 mKernelSize = 0;
STATIC UINT8 *mDeviceTree = NULL;
STATIC UINT64 mDeviceTreeSize = 0;
STATIC UINT8 *mRamdiskPtr = NULL;
STATIC UINT64 mRamdiskSize = 0;

STATIC UINT32 mSegCount = 0;
STATIC UINT64 mSegVa[MAX_SEGMENTS];
STATIC UINT64 mSegFileOff[MAX_SEGMENTS];
STATIC UINT64 mSegFileSize[MAX_SEGMENTS];
STATIC UINT64 mSegVmSize[MAX_SEGMENTS];

STATIC UINT64 mKernelLinkBase = 0;  /* __TEXT.vmaddr (0 = legacy 0-based PIE) */
STATIC UINT64 mEntryFileOff = 0;   /* LC_MAIN entryoff (link-relative)      */
STATIC UINT64 mEntryVa = 0;        /* absolute entry VA (LC_MAIN or thread) */
STATIC UINT64 mKvaBase = 0;        /* virtBase handed to the kernel         */
STATIC UINT64 mSlide = 0;          /* mKvaBase - mKernelLinkBase            */
STATIC UINT64 mLoadEnd = 0;        /* image span relative to link base      */
STATIC UINT64 mRebaseOff = 0;
STATIC UINT64 mRebaseSize = 0;

STATIC UINT64 mLoadBase = 0;   /* chosen (32MB-aligned) load base          */
STATIC UINT64 mLoadSpan = 0;   /* conventional span above the load base    */
STATIC UINT64 mTailStart = 0;  /* payload RAM in use by the tail chain     */
STATIC UINT64 mTailEnd = 0;

/* ------------------------------------------------------------------ */
/* ULEB128                                                              */
/* ------------------------------------------------------------------ */
STATIC UINT64 ReadUleb (UINT8 **Ptr)
{
    UINT64 Result = 0;
    UINTN  Shift  = 0;
    UINT8  Byte;

    do {
        Byte   = *(*Ptr)++;
        Result |= ((UINT64)(Byte & 0x7F)) << Shift;
        Shift += 7;
    } while ((Byte & 0x80) != 0);

    return Result;
}

/* ------------------------------------------------------------------ */
/* Parse the tail blocks; chain starts at the ADDRESS the BootShim published
 * at BOOTSHIM_TAIL_PTR_ADDR (payload position in RAM = where the FD copy
 * ended, so it is NOT the scratch page itself), with up to 16 bytes of
 * 16-alignment padding before the first magic.                       */
/* ------------------------------------------------------------------ */
STATIC EFI_STATUS ParseTailBlocks (IN UINT64 TailAddr)
{
    UINTN BlockAddr = (UINTN)TailAddr;
    UINTN Index;

    mTailStart = TailAddr;
    mTailEnd   = TailAddr;

    for (Index = 0; Index < MAX_TAIL_BLOCKS; Index++) {
        UINTN  Probe;
        UINT64 Magic = 0;
        UINT64 Size;
        BOOLEAN Found = FALSE;

        /* Look for the next block magic within a small pad window. */
        for (Probe = 0; Probe <= 16; Probe += 8) {
            Magic = *(UINT64 *)(BlockAddr + Probe);
            if (Magic == XNUKERN1_MAGIC || Magic == XNUFDT01_MAGIC ||
                Magic == XNUROOT1_MAGIC) {
                Found = TRUE;
                break;
            }
        }
        if (!Found) {
            break;
        }
        BlockAddr += Probe;

        Size = *(UINT64 *)(BlockAddr + 8);
        if (Size == 0 || Size > SIZE_1GB) {
            return EFI_LOAD_ERROR;
        }

        if (Magic == XNUKERN1_MAGIC) {
            mKernelPtr  = (UINT8 *)BlockAddr + 16;
            mKernelSize = Size;
        } else if (Magic == XNUROOT1_MAGIC) {
            mRamdiskPtr  = (UINT8 *)BlockAddr + 16;
            mRamdiskSize = Size;
        } else {
            mDeviceTree     = (UINT8 *)BlockAddr + 16;
            mDeviceTreeSize = Size;
        }

        BlockAddr = ((BlockAddr + 16 + Size + 0xF) & ~(UINTN)0xF);
        mTailEnd = BlockAddr;
    }

    if (mKernelPtr == NULL) {
        return EFI_NOT_FOUND;
    }

    return EFI_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* Single scan of the Mach-O: segments, entry, rebase stream            */
/* ------------------------------------------------------------------ */
STATIC EFI_STATUS ScanKernelImage (VOID)
{
    mach_header_64 *Header   = (mach_header_64 *)mKernelPtr;
    UINT8          *CmdPtr;
    UINTN           CmdIdx;
    BOOLEAN         SeenText = FALSE;

    if (Header->magic != MH_MAGIC_64) {
        XNU_PRINT (L"Xnuload: Kernel has unexpected magic 0x%x (want 0x%8x)\n",
               Header->magic, (UINT32)MH_MAGIC_64);
        return EFI_LOAD_ERROR;
    }
    if (Header->cputype != CPU_TYPE_ARM64) {
        XNU_PRINT (L"Xnuload: Kernel is not arm64 (cputype 0x%x)\n", Header->cputype);
        return EFI_LOAD_ERROR;
    }
    if (Header->filetype != MH_EXECUTE) {
        XNU_PRINT (L"Xnuload: Kernel is not MH_EXECUTE (0x%x)\n", Header->filetype);
        return EFI_LOAD_ERROR;
    }

    CmdPtr = mKernelPtr + sizeof (mach_header_64);
    for (CmdIdx = 0; CmdIdx < Header->ncmds; CmdIdx++) {
        load_command *Cmd = (load_command *)CmdPtr;

        if (Cmd->cmdsize < sizeof (load_command) ||
            (UINTN)CmdPtr + Cmd->cmdsize > (UINTN)mKernelPtr + mKernelSize) {
            XNU_PRINT (L"Xnuload: Load command overflow\n");
            return EFI_LOAD_ERROR;
        }

        switch (Cmd->cmd) {
            case LC_SEGMENT_64: {
                segment_command_64 *Seg = (segment_command_64 *)CmdPtr;
                UINT64 SegEnd;

                if (mSegCount >= MAX_SEGMENTS) {
                    XNU_PRINT (L"Xnuload: Too many segments (%u)\n", mSegCount);
                    return EFI_LOAD_ERROR;
                }
                if (!SeenText) {
                    SeenText = TRUE;
                    /* __TEXT.vmaddr is the link base: 0 for the legacy
                     * 0-based PIE kernels, the real anchor VA (e.g.
                     * 0xfffffe0007004000) for natively linked ones. */
                    mKernelLinkBase = Seg->vmaddr;
                    if ((mKernelLinkBase & 0xFFF) != 0 ||
                        mKernelLinkBase > 0xFFFFFFFF00000000ULL) {
                        XNU_PRINT (L"Xnuload: Bogus kernel link base 0x%Lx\n",
                               mKernelLinkBase);
                        return EFI_LOAD_ERROR;
                    }
                }

                mSegVa[mSegCount]       = Seg->vmaddr;
                mSegFileOff[mSegCount]  = Seg->fileoff;
                mSegFileSize[mSegCount] = Seg->filesize;
                mSegVmSize[mSegCount]   = Seg->vmsize;
                mSegCount++;

                /* Empty placeholder segments (__PRELINK_*, __LAST, __CTF)
                 * load nothing; some sit deliberately below the link base
                 * (__PRELINK_TEXT lives at 0xfffffe0004004000). Keep them
                 * in the array for rebase segment indexing, but never load
                 * or size-check them. */
                if (Seg->vmsize == 0 && Seg->filesize == 0) {
                    break;
                }
                if (Seg->vmaddr < mKernelLinkBase) {
                    XNU_PRINT (L"Xnuload: Segment below link base (0x%Lx < 0x%Lx)\n",
                           Seg->vmaddr, mKernelLinkBase);
                    return EFI_LOAD_ERROR;
                }

                SegEnd = Seg->vmaddr + Seg->vmsize - mKernelLinkBase;

                if (SegEnd > SIZE_128MB) {
                    XNU_PRINT (L"Xnuload: Segment image too large (0x%Lx)\n", SegEnd);
                    return EFI_LOAD_ERROR;
                }
                if (SegEnd > mLoadEnd) {
                    mLoadEnd = SegEnd;
                }
                break;
            }

            case LC_MAIN: {
                entry_point_command *Ep = (entry_point_command *)CmdPtr;
                if (mEntryFileOff == 0 && mEntryVa == 0 &&
                    Ep->entryoff != 0 && Ep->entryoff < mKernelSize) {
                    mEntryFileOff = Ep->entryoff;
                }
                break;
            }

            case LC_UNIXTHREAD: {
                /* arm_thread_state64_t: x[29], fp, lr, sp, pc, cpsr */
                UINT32 Flavor;

                if (Cmd->cmdsize < 16 + ARM_THREAD_STATE64_PC_OFF + 8) {
                    XNU_PRINT (L"Xnuload: LC_UNIXTHREAD too small (%u)\n",
                           Cmd->cmdsize);
                    return EFI_LOAD_ERROR;
                }
                Flavor = *(UINT32 *)(CmdPtr + 8);
                if (Flavor != ARM_THREAD_STATE64) {
                    XNU_PRINT (L"Xnuload: LC_UNIXTHREAD flavor %u unsupported\n",
                           Flavor);
                    return EFI_UNSUPPORTED;
                }
                if (mEntryVa == 0 && mEntryFileOff == 0) {
                    mEntryVa = *(UINT64 *)(CmdPtr + 16 + ARM_THREAD_STATE64_PC_OFF);
                }
                break;
            }

            case LC_DYLD_INFO:
            case LC_DYLD_INFO_ONLY: {
                dyld_info_command *Dyld = (dyld_info_command *)CmdPtr;

                /* The command must be full-size (spec: 48 bytes). Some xnu
                 * builds emit a bogus 16-byte "0x1d" record right after
                 * LC_MAIN whose rebase_off points at __LINKEDIT data —
                 * that is NOT a dyld rebase stream, ignore it. */
                if (Cmd->cmdsize < sizeof (dyld_info_command)) {
                    break;
                }

                /* Keep the first real stream; never let a later record
                 * clobber a valid one. */
                if (mRebaseOff == 0 && mRebaseSize == 0) {
                    mRebaseOff  = Dyld->rebase_off;
                    mRebaseSize = Dyld->rebase_size;
                }
                if (Dyld->bind_size != 0 || Dyld->weak_bind_size != 0 ||
                    Dyld->lazy_bind_size != 0) {
                    XNU_PRINT (L"Xnuload: Kernel has binds (unsupported)\n");
                    return EFI_UNSUPPORTED;
                }
                break;
            }

            default:
                break;
        }

        CmdPtr += Cmd->cmdsize;
    }

    if (mSegCount == 0) {
        XNU_PRINT (L"Xnuload: No segments found\n");
        return EFI_LOAD_ERROR;
    }
    if (mLoadEnd == 0) {
        XNU_PRINT (L"Xnuload: Kernel image is empty\n");
        return EFI_LOAD_ERROR;
    }

    if (mEntryVa == 0 && mEntryFileOff != 0) {
        mEntryVa = mKernelLinkBase + mEntryFileOff;
    }
    if (mEntryVa == 0) {
        XNU_PRINT (L"Xnuload: No entry point found\n");
        return EFI_LOAD_ERROR;
    }
    if (mEntryVa < mKernelLinkBase ||
        mEntryVa - mKernelLinkBase >= mLoadEnd) {
        XNU_PRINT (L"Xnuload: Entry 0x%Lx outside loaded image\n", mEntryVa);
        return EFI_LOAD_ERROR;
    }

    /* Legacy 0-based PIE kernels need the rebase stream to move to
     * XNU_KVA_BASE; natively linked kernels keep their own VAs. */
    if (mKernelLinkBase == 0) {
        mKvaBase = XNU_KVA_BASE;
        if (mRebaseOff == 0 || mRebaseSize == 0) {
            XNU_PRINT (L"Xnuload: 0-based kernel lacks a rebasable LC_DYLD_INFO stream\n");
            return EFI_LOAD_ERROR;
        }
    } else {
        mKvaBase = mKernelLinkBase;
    }
    mSlide = mKvaBase - mKernelLinkBase;

    return EFI_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* Memory-map driven load-base selection                                */
/*                                                                      */
/* The kernel must load into RAM that UEFI actually leaves free, so we   */
/* scan the memory map for conventional descriptors and pick the ranges */
/* that can hold kernel + headroom at a centred 32MB-aligned address     */
/* (candidate base carries the link base's low 25 bits), sorted by the  */
/* room they leave above that address. AllocateAddress is then tried    */
/* against the candidates in order. Ranges overlapping the payload/tail */
/* RAM (which we still read from) are skipped. Because physBase keeps   */
/* the link base's low bits, the start.s block-pairing invariant and    */
/* the kva() math are valid for every possible choice.                  */
/* ------------------------------------------------------------------ */
#define LOAD_BASE_CANDIDATES 6

typedef struct {
    UINT64 Base;
    UINT64 Span;
} LOAD_CANDIDATE;

STATIC EFI_STATUS CaptureMemoryMap (
    OUT EFI_MEMORY_DESCRIPTOR **Map,
    OUT UINTN                  *MapSize,
    OUT UINTN                  *DescSize
    )
{
    UINTN   Key;
    UINT32  DescVer;
    UINTN   Attempt;

    *Map = NULL;
    *MapSize = 0;
    *DescSize = 0;

    for (Attempt = 0; Attempt < 16; Attempt++) {
        EFI_STATUS S = gBS->GetMemoryMap (MapSize, *Map, &Key, DescSize, &DescVer);
        if (S == EFI_BUFFER_TOO_SMALL) {
            if (*Map != NULL) gBS->FreePool (*Map);
            *MapSize += 128 * sizeof (EFI_MEMORY_DESCRIPTOR);
            *Map = AllocatePool (*MapSize);
            if (*Map == NULL) {
                return EFI_OUT_OF_RESOURCES;
            }
            continue;
        } else if (EFI_ERROR (S)) {
            if (*Map != NULL) gBS->FreePool (*Map);
            *Map = NULL;
            return S;
        }
        return EFI_SUCCESS;
    }

    return EFI_NOT_READY;
}

STATIC EFI_STATUS ReserveKernelRegion (UINT64 ReserveSize)
{
    EFI_MEMORY_DESCRIPTOR  *Map;
    UINTN                   MapSize;
    UINTN                   DescSize;
    LOAD_CANDIDATE          Cand[LOAD_BASE_CANDIDATES];
    UINTN                   Count = 0;
    UINTN                   Offset;
    UINTN                   Pages = (ReserveSize + SIZE_4KB - 1) / SIZE_4KB;
    EFI_STATUS              Status;
    UINTN                   i;

    Status = CaptureMemoryMap (&Map, &MapSize, &DescSize);
    if (EFI_ERROR (Status)) {
        XNU_PRINT (L"Xnuload: GetMemoryMap for load-base selection failed: %r\n", Status);
        return Status;
    }

    /* Diagnostics first: where the payload lives and what UEFI offers. */
    XNU_PRINT (L"[Xnuload] payload tail [0x%Lx, 0x%Lx)\n", mTailStart, mTailEnd);
    for (Offset = 0; Offset < MapSize && DescSize != 0; Offset += DescSize) {
        EFI_MEMORY_DESCRIPTOR *D = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)Map + Offset);
        UINT64 DStart;
        UINT64 DEnd;

        if (D->Type != EfiConventionalMemory) {
            continue;
        }
        DStart = D->PhysicalStart;
        DEnd   = D->PhysicalStart + D->NumberOfPages * SIZE_4KB;
        if (DEnd - DStart >= SIZE_16MB) {
            XNU_PRINT (L"[Xnuload] free [0x%Lx, 0x%Lx) span 0x%Lx\n",
                   DStart, DEnd, DEnd - DStart);
        }
    }

    for (Offset = 0; Offset < MapSize && DescSize != 0; Offset += DescSize) {
        EFI_MEMORY_DESCRIPTOR *D = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)Map + Offset);
        UINT64 DStart;
        UINT64 DEnd;
        UINT64 RangeStart[2];
        UINT64 RangeEnd[2];
        UINTN  RangeCount = 0;
        UINTN  Range;

        if (D->Type != EfiConventionalMemory) {
            continue;
        }

        DStart = D->PhysicalStart;
        DEnd   = D->PhysicalStart + D->NumberOfPages * SIZE_4KB;

        /* Split the descriptor around the payload RAM. The tail chain is
         * copied there by BootShim, but UEFI need not describe that area
         * as allocated, so a naive candidate could cover (and overwrite)
         * the kernel image we are still reading from. */
        if (mTailEnd != 0 && DStart < mTailEnd && DEnd > mTailStart) {
            if (DStart < mTailStart) {
                RangeStart[RangeCount] = DStart;
                RangeEnd[RangeCount]   = mTailStart;
                RangeCount++;
            }
            if (mTailEnd < DEnd) {
                RangeStart[RangeCount] = mTailEnd;
                RangeEnd[RangeCount]   = DEnd;
                RangeCount++;
            }
        } else {
            RangeStart[0] = DStart;
            RangeEnd[0]   = DEnd;
            RangeCount    = 1;
        }

        for (Range = 0; Range < RangeCount; Range++) {
            /* Load base = first 32MB-aligned address at/above the range
             * start, keeping the low bits of the kernel link base so that
             * physBase mod 32MB == virtBase mod 32MB (start.s pairs its
             * bootstrap block entries on that equality). */
            UINT64 Off  = mKernelLinkBase & (XNU_LOAD_ALIGN - 1);
            UINT64 Base = ((RangeStart[Range] + XNU_LOAD_ALIGN - 1) &
                           ~(XNU_LOAD_ALIGN - 1)) | Off;
            UINT64 End  = RangeEnd[Range];
            UINT64 Span;
            UINTN  Pos;

            /* Range too small to hold an aligned address. */
            if (Base >= End) {
                continue;
            }

            Span = End - Base;
            if (Span < ReserveSize) {
                continue;
            }

            /* Keep the best LOAD_BASE_CANDIDATES ranges by span. */
            if (Count == LOAD_BASE_CANDIDATES && Span <= Cand[Count - 1].Span) {
                continue;
            }
            Pos = 0;
            while (Pos < Count && Cand[Pos].Span >= Span) {
                Pos++;
            }
            if (Count < LOAD_BASE_CANDIDATES) {
                Count++;
            }
            for (i = Count - 1; i > Pos; i--) {
                Cand[i] = Cand[i - 1];
            }
            Cand[Pos].Base = Base;
            Cand[Pos].Span = Span;
            XNU_PRINT (L"[Xnuload] candidate [0x%Lx, 0x%Lx) span 0x%Lx\n",
                   Base, End, Span);
        }
    }

    for (i = 0; i < Count; i++) {
        EFI_PHYSICAL_ADDRESS Base = Cand[i].Base;

        Status = gBS->AllocatePages (
            AllocateAddress, EfiBootServicesData, Pages, &Base);
        if (EFI_ERROR (Status)) {
            XNU_PRINT (L"Xnuload: candidate 0x%Lx failed: %r\n", Cand[i].Base, Status);
            continue;
        }

        /* Defense in depth: never place the kernel over the payload. */
        if (mTailEnd != 0 &&
            Base < mTailEnd && Base + Pages * SIZE_4KB > mTailStart) {
            XNU_PRINT (L"[Xnuload] BUG: 0x%Lx overlaps payload, freeing\n",
                   (UINT64)Base);
            gBS->FreePages (Base, Pages);
            continue;
        }

        mLoadBase = Cand[i].Base;
        mLoadSpan = Cand[i].Span;
        gBS->FreePool (Map);
        XNU_PRINT (L"[Xnuload] Reserved %Lu pages @ 0x%Lx (span 0x%Lx)\n",
               (UINT64)Pages, mLoadBase, mLoadSpan);
        return EFI_SUCCESS;
    }

    /* Diagnostics: list the conventional spans we saw (16MB or bigger). */
    for (Offset = 0; Offset < MapSize && DescSize != 0; Offset += DescSize) {
        EFI_MEMORY_DESCRIPTOR *D = (EFI_MEMORY_DESCRIPTOR *)((UINT8 *)Map + Offset);
        UINT64 Span;

        if (D->Type != EfiConventionalMemory) {
            continue;
        }
        Span = D->NumberOfPages * SIZE_4KB;
        if (Span >= SIZE_16MB) {
            XNU_PRINT (L"Xnuload: free [0x%Lx, 0x%Lx) span 0x%Lx\n",
                   D->PhysicalStart, D->PhysicalStart + Span, Span);
        }
    }

    gBS->FreePool (Map);
    XNU_PRINT (L"Xnuload: no conventional region fits the kernel (need 0x%Lx, tail [0x%Lx, 0x%Lx))\n",
           ReserveSize, mTailStart, mTailEnd);
    return EFI_NOT_FOUND;
}

/* ------------------------------------------------------------------ */
/* Copy the segments: link VA v -> PA mLoadBase + (v - link base)       */
/* ------------------------------------------------------------------ */
STATIC EFI_STATUS LoadKernelImage (VOID)
{
    UINTN SegIdx;

    ZeroMem ((VOID *)mLoadBase, mLoadEnd);

    for (SegIdx = 0; SegIdx < mSegCount; SegIdx++) {
        UINT64 Pa;

        if (mSegFileSize[SegIdx] == 0) {
            continue;               /* placeholder segment (PRELINK, __LAST) */
        }
        Pa = mLoadBase + (mSegVa[SegIdx] - mKernelLinkBase);

        if (mSegFileOff[SegIdx] > mKernelSize ||
            mSegFileOff[SegIdx] + mSegFileSize[SegIdx] > mKernelSize) {
            XNU_PRINT (L"Xnuload: Segment %Lu file data out of range\n", (UINT64)SegIdx);
            return EFI_LOAD_ERROR;
        }

        CopyMem (
            (VOID *)Pa,
            mKernelPtr + mSegFileOff[SegIdx],
            mSegFileSize[SegIdx]
        );
    }

    return EFI_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* Apply the LC_DYLD_INFO rebase opcode stream                          */
/*   Slot PA = mLoadBase + (seg VA - link base) + offset; natively      */
/*   linked kernels have slide 0 and no rebase stream at all.           */
/* ------------------------------------------------------------------ */
STATIC EFI_STATUS ApplyRebases (VOID)
{
    UINT8  *Stream;
    UINT8  *End;
    UINT64 Slide;
    UINT64 Slots = 0;
    UINT32 CurType = 0;

    if (mSlide == 0 || mRebaseOff == 0 || mRebaseSize == 0) {
        return EFI_SUCCESS;               /* nothing to fixup */
    }

    Slide   = mSlide;                     /* XNU_KVA_BASE for the PIE  */
    Stream  = mKernelPtr + mRebaseOff;
    End     = Stream + mRebaseSize;

    /* Needed because the stream references load-time content offsets,
     * while the segments were already relocated in place. */
    UINT64 CurSeg  = 0;
    UINT64 CurOff  = 0;

    while (Stream < End) {
        UINT8 Op = *Stream++;

        if (Op == RP_DONE) {
            break;
        }

        UINT8 Hi  = Op & 0xF0;
        UINT8 Imm = Op & 0x0F;

        if (Hi == RP_SET_TYPE_IMM) {
            CurType = Imm;
            if (CurType != REBASE_TYPE_POINTER) {
                XNU_PRINT (L"Xnuload: Unsupported rebase type %u\n", CurType);
                return EFI_UNSUPPORTED;
            }
        } else if (Hi == RP_SET_SEG_OFF_ULEB) {
            /* The dyld spec: segment index lives in the immediate bits,
             * followed by one ULEB offset. */
            UINT32 SegIdx = Imm;
            if (SegIdx >= mSegCount) {
                XNU_PRINT (L"Xnuload: Rebase references segment %u (only %u)\n",
                       SegIdx, mSegCount);
                return EFI_LOAD_ERROR;
            }
            CurSeg = mSegVa[SegIdx] - mKernelLinkBase;
            CurOff = ReadUleb (&Stream);
        } else if (Hi == RP_ADD_ADDR_ULEB) {
            CurOff += ReadUleb (&Stream);
        } else if (Hi == RP_ADD_ADDR_IMM_SCALED) {
            CurOff += (UINT64)Imm * 8;
        } else if (Hi == RP_DO_REBASE_IMM_TIMES) {
            UINTN i;
            for (i = 0; i < Imm; i++) {
                UINT64 *Slot = (UINT64 *)(mLoadBase + CurSeg + CurOff);
                *Slot += Slide;
                CurOff += 8;
                Slots++;
            }
        } else if (Hi == RP_DO_REBASE_ULEB_TIMES) {
            UINT64 Count = ReadUleb (&Stream);
            UINTN  i;
            for (i = 0; i < Count; i++) {
                UINT64 *Slot = (UINT64 *)(mLoadBase + CurSeg + CurOff);
                *Slot += Slide;
                CurOff += 8;
                Slots++;
            }
        } else if (Hi == RP_DO_REBASE_ADD_ADDR_ULEB) {
            /* A single rebase here, then advance by the ULEB value. */
            UINT64 *Slot = (UINT64 *)(mLoadBase + CurSeg + CurOff);
            *Slot += Slide;
            CurOff += ReadUleb (&Stream);
            Slots++;
        } else if (Hi == RP_DO_REBASE_ULEB_TIMES_SKIPPING_ULEB) {
            UINT64 Count = ReadUleb (&Stream);
            UINT64 Skip  = ReadUleb (&Stream);
            UINTN  i;
            for (i = 0; i < Count; i++) {
                UINT64 *Slot = (UINT64 *)(mLoadBase + CurSeg + CurOff);
                *Slot += Slide;
                CurOff += 8 + Skip;
                Slots++;
            }
        } else {
            XNU_PRINT (L"Xnuload: Unsupported rebase opcode 0x%x\n", (UINT32)Op);
            return EFI_UNSUPPORTED;
        }
    }

    XNU_PRINT (L"[Xnuload] Rebase fixups applied: %Lu slots (slide 0x%Lx)\n", Slots, Slide);
    return EFI_SUCCESS;
}

/* ------------------------------------------------------------------ */
/* Fetch the framebuffer parameters from the GOP                        */
/* ------------------------------------------------------------------ */
STATIC BOOLEAN FetchGopFramebuffer (boot_args *Args)
{
    EFI_GRAPHICS_OUTPUT_PROTOCOL      *Gop;
    EFI_GRAPHICS_OUTPUT_PROTOCOL_MODE *Mode;
    EFI_STATUS Status = gBS->LocateProtocol (
        &gEfiGraphicsOutputProtocolGuid, NULL, (VOID **)&Gop);

    if (EFI_ERROR (Status) || Gop == NULL || Gop->Mode == NULL ||
        Gop->Mode->Info == NULL) {
        XNU_PRINT (L"Xnuload: GOP unavailable, no framebuffer info\n");
        return FALSE;
    }

    Mode = Gop->Mode;

    Args->Video.v_baseAddr = Mode->FrameBufferBase;
    Args->Video.v_rowBytes = Mode->Info->PixelsPerScanLine * 4;
    Args->Video.v_width    = Mode->Info->HorizontalResolution;
    Args->Video.v_height   = Mode->Info->VerticalResolution;
    Args->Video.v_depth    = 32;
    Args->Video.v_display  = 0;

    return TRUE;
}

/* ------------------------------------------------------------------ */
/* Handoff to the kernel. Assumes the final ExitBootServices succeeded:  */
/* after this point no EFI services may be used.                         */
/*   ArgsPa     -> x0 : PA of boot_args (XNU start expects it there)     */
/*   EntryPa    -> x1 : kernel entry PA (LC_MAIN entryoff)               */
/*   CacheStart -> x2 : start of the kernel load region (for DC CI)      */
/*   CacheEnd   -> x3 : end of the kernel load region (for DC CI)        */
/* ------------------------------------------------------------------ */
STATIC VOID Handoff (
    UINT64 ArgsPa,
    UINT64 EntryPa,
    UINT64 CacheStart,
    UINT64 CacheEnd
    )
{
    register UINT64 R0 __asm__ ("x0") = ArgsPa;
    register UINT64 R1 __asm__ ("x1") = EntryPa;
    register UINT64 R2 __asm__ ("x2") = CacheStart;
    register UINT64 R3 __asm__ ("x3") = CacheEnd;

    __asm__ __volatile__ (
        "msr    daifset, #0xF\n"

        /* Clean + invalidate D-cache over [x2, x3) and invalidate the
         * icache so that the loaded, rebased image is fully visible. */
        "1:     dc      civac, x2\n"
        "add    x2, x2, #64\n"
        "cmp    x2, x3\n"
        "b.lt   1b\n"
        "ic     iallu\n"
        "dsb    sy\n"
        "isb\n"

        /* What exception level are we executing at?               */
        "mrs    x4, CurrentEL\n"
        "cmp    x4, #0xC\n"
        "b.eq   3f\n"
        "cmp    x4, #0x8\n"
        "b.eq   2f\n"

        /* EL1: turn off MMU + caches, then jump.                  */
        "mrs    x5, sctlr_el1\n"
        "bic    x5, x5, #(1 << 0)\n"    /* M   */
        "bic    x5, x5, #(1 << 2)\n"    /* C   */
        "bic    x5, x5, #(1 << 12)\n"   /* I   */
        "bic    x5, x5, #(1 << 3)\n"    /* SA  */
        "msr    sctlr_el1, x5\n"
        "isb\n"
        "br     x1\n"

        /* EL3: shouldn't ever happen; park                        */
        "3:     wfi\n"
        "b      3b\n"

        /* EL2: drop to EL1 with the arch timers visible.          */
        "2:     msr     sctlr_el1, xzr\n"
        "msr    hcr_el2, xzr\n"
        "msr    cptr_el2, xzr\n"        /* no FP/SIMD traps to EL2 */
        "msr    vbar_el2, xzr\n"        /* must never take an EL2 exception */
        "msr    vbar_el1, xzr\n"
        "mov    x6, #0x3\n"             /* CNTKCTL: EL1PCTEN|EL1PCEN */
        "msr    cnthctl_el2, x6\n"
        "msr    cntvoff_el2, xzr\n"
        "mov    x7, #0x3C5\n"           /* SPSR: EL1h | DAIF */
        "msr    spsr_el2, x7\n"
        "msr    elr_el2, x1\n"
        "eret\n"
        :
        : "r" (R0), "r" (R1), "r" (R2), "r" (R3)
        : "x4", "x5", "x6", "x7", "memory", "cc"
    );

    __builtin_unreachable ();
}

/* ------------------------------------------------------------------ */
/* Rewrite the /chosen dram-base/dram-size ADT properties               */
/* ------------------------------------------------------------------ */
/*
 * ADT nodes are {u32 nprops, u32 nchildren, props..., children...} and
 * properties are {char name[32], u32 size (bit31 = placeholder flag),
 * value padded to 4 bytes}; all integers are little-endian (tools/mkadt.py
 * serializes this exact layout). dram-base/dram-size are unique u64
 * properties in the peridot tree; RAMDisk (memory-map, 2x u64) exists only
 * when mkadt.py was asked for it. All three get the runtime values.
 */
STATIC UINTN mAdtPatched = 0;

STATIC BOOLEAN AdtNameIs (UINT8 *Name, CONST CHAR8 *Want)
{
    UINTN Len = AsciiStrLen (Want);
    return (CompareMem (Name, Want, Len) == 0) && (Name[Len] == 0);
}

STATIC UINTN PatchAdtNode (
    UINT8   *Adt,
    UINTN    Size,
    UINTN    Off,
    UINT64   DramBase,
    UINT64   DramSize,
    UINT64   RdPa,
    UINT64   RdSize
    )
{
    UINT32 NProps = 0;
    UINT32 NChild = 0;
    UINT32 i;

    if (Off + 8 > Size) {
        return Size;
    }
    CopyMem (&NProps, Adt + Off, 4);
    CopyMem (&NChild, Adt + Off + 4, 4);
    Off += 8;

    for (i = 0; i < NProps; i++) {
        UINT32 PSize;
        UINTN  Len;
        UINTN  Advance;

        if (Off + 36 > Size) {
            return Size;
        }
        CopyMem (&PSize, Adt + Off + 32, 4);
        Len     = PSize & 0x7FFFFFFFU;
        Advance = 36 + ((Len + 3) & ~3U);
        if (Off + Advance > Size) {
            return Size;
        }

        if (Len == 8 && AdtNameIs (Adt + Off, "dram-base")) {
            CopyMem (Adt + Off + 36, &DramBase, 8);
            mAdtPatched |= 1;
        } else if (Len == 8 && AdtNameIs (Adt + Off, "dram-size")) {
            CopyMem (Adt + Off + 36, &DramSize, 8);
            mAdtPatched |= 2;
        } else if (Len == 16 && RdSize != 0 &&
                   AdtNameIs (Adt + Off, "RAMDisk")) {
            CopyMem (Adt + Off + 36, &RdPa, 8);
            CopyMem (Adt + Off + 44, &RdSize, 8);
            mAdtPatched |= 4;
        }
        Off += Advance;
    }

    for (i = 0; i < NChild; i++) {
        if (Off >= Size) {
            break;
        }
        Off = PatchAdtNode (Adt, Size, Off, DramBase, DramSize, RdPa, RdSize);
    }

    return Off;
}

/* ------------------------------------------------------------------ */
/* EFI entry point                                                      */
/* ------------------------------------------------------------------ */
EFI_STATUS
EFIAPI
UefiMain (
    IN EFI_HANDLE        ImageHandle,
    IN EFI_SYSTEM_TABLE  *SystemTable
    )
{
    EFI_STATUS             Status;
    UINT64                 TailAddr;
    UINT64                 KernelLoadSize;
    UINT64                 RamdiskLoadSize;
    UINT64                 RamdiskPa;
    UINT64                 ReserveSize;
    UINT64                 HeadroomBase;
    UINT64                 DtbPa;
    UINT64                 ArgsPa;
    UINT64                 EntryPa;
    UINT64                 TopOfKernelData;
    boot_args              *Args;
    EFI_MEMORY_DESCRIPTOR  *MemoryMap;
    UINTN                  MemoryMapSize;
    UINTN                  MapKey;
    UINTN                  DescriptorSize;
    UINT32                 MemDescVersion;
    UINTN                  Attempt;
    UINT64                 CurrentEl;

    XNU_PRINT (L"[Xnuload] Darwin/XNU loader v9 (Mu-Silicium UEFI, peridot)\n");

    __asm__ __volatile__ ("mrs %0, CurrentEL" : "=r" (CurrentEl));
    XNU_PRINT (L"[Xnuload] CurrentEL 0x%Lx\n", CurrentEl);

    /* Boot shim tail pointer. */
    TailAddr = *(UINT64 *)BOOTSHIM_TAIL_PTR_ADDR;
    if (TailAddr == 0 || (TailAddr & 0x7) != 0) {
        XNU_PRINT (L"[Xnuload] BootShim tail pointer invalid (0x%Lx)\n", TailAddr);
        return EFI_NOT_FOUND;
    }

    Status = ParseTailBlocks (TailAddr);
    if (EFI_ERROR (Status)) {
        XNU_PRINT (L"[Xnuload] Failed to find XNU payload at 0x%Lx\n", TailAddr);
        return Status;
    }

    Status = ScanKernelImage ();
    if (EFI_ERROR (Status)) {
        XNU_PRINT (L"[Xnuload] Mach-O scan failed: %r\n", Status);
        return Status;
    }

    XNU_PRINT (L"[Xnuload] Kernel 0x%Lx bytes @ 0x%Lx, DT 0x%Lx bytes @ 0x%Lx\n",
           mKernelSize, mKernelPtr, mDeviceTreeSize, mDeviceTree);
    XNU_PRINT (L"[Xnuload] link base 0x%Lx, entry VA 0x%Lx, KVA base 0x%Lx (slide 0x%Lx)\n",
           mKernelLinkBase, mEntryVa, mKvaBase, mSlide);
    if (mRebaseSize != 0) {
        XNU_PRINT (L"[Xnuload] Rebase stream @ +0x%Lx size 0x%Lx\n",
               mRebaseOff, mRebaseSize);
    }
    if (mRamdiskSize != 0) {
        XNU_PRINT (L"[Xnuload] Ram disk 0x%Lx bytes @ 0x%Lx\n",
               mRamdiskSize, mRamdiskPtr);
    }

    KernelLoadSize = (mLoadEnd + 0x1FFFFULL) & ~0x1FFFFULL;   /* 128KB align */
    if (KernelLoadSize == 0 || KernelLoadSize > SIZE_128MB) {
        XNU_PRINT (L"[Xnuload] Load size bogus (0x%Lx)\n", KernelLoadSize);
        return EFI_LOAD_ERROR;
    }
    RamdiskLoadSize = (mRamdiskSize + 0x1FFFFULL) & ~0x1FFFFULL;

    /* Reserve kernel + ram disk + headroom so EFI leaves it alone. */
    ReserveSize = KernelLoadSize + RamdiskLoadSize + XNU_HEADROOM;
    Status = ReserveKernelRegion (ReserveSize);
    if (EFI_ERROR (Status)) {
        return Status;
    }

    /* Copy the image (mach header lands at mLoadBase). */
    Status = LoadKernelImage ();
    if (EFI_ERROR (Status)) {
        XNU_PRINT (L"[Xnuload] Segment load failed: %r\n", Status);
        return Status;
    }

    /* Ram disk right after the kernel, inside the same reservation. */
    RamdiskPa = mLoadBase + KernelLoadSize;
    if (mRamdiskSize != 0) {
        CopyMem ((VOID *)RamdiskPa, mRamdiskPtr, mRamdiskSize);
    }

    /* Apply the rebases (this kernel needs it). */
    Status = ApplyRebases ();
    if (EFI_ERROR (Status)) {
        XNU_PRINT (L"[Xnuload] Rebase failed: %r\n", Status);
        return Status;
    }

    /* Flat span reported to XNU: [mLoadBase, mLoadBase + MemSize). Both
     * come from the chosen conventional region, capped by XNU_MEM_SIZE_CAP. */
    UINT64 MemSize = MIN (XNU_MEM_SIZE_CAP, mLoadSpan);
    if (MemSize < ReserveSize) {
        XNU_PRINT (L"[Xnuload] Chosen span 0x%Lx too small (need 0x%Lx)\n",
               MemSize, ReserveSize);
        return EFI_OUT_OF_RESOURCES;
    }

    /* Headroom layout (per the reference loader):
     *   [kernel] [ram disk] ADT copy | 16K-align | boot_args (16K) — all
     *   BELOW topOfKernelData, which arm_vm_physmap_init maps as the
     *   end_kern..topOfKernelData region ("Device Tree, RAM Disk, bootArgs"). */
    HeadroomBase = mLoadBase + KernelLoadSize + RamdiskLoadSize;
    DtbPa = HeadroomBase;
    if (mDeviceTree != NULL && mDeviceTreeSize != 0) {
        CopyMem ((VOID *)DtbPa, mDeviceTree, mDeviceTreeSize);
        /* The kernel walks the ADT with the MMU on and expects the DRAM
         * window to start at the runtime physBase, which is not the
         * mkadt default (the load base carries the link base's low bits). */
        PatchAdtNode ((UINT8 *)DtbPa, mDeviceTreeSize, 0,
                      mLoadBase, MemSize, RamdiskPa, mRamdiskSize);
        if ((mAdtPatched & 3) != 3) {
            XNU_PRINT (L"Xnuload: ADT dram-base/dram-size props missing (0x%x)\n",
                   mAdtPatched);
            return EFI_LOAD_ERROR;
        }
        if (mRamdiskSize != 0 && (mAdtPatched & 4) == 0) {
            XNU_PRINT (L"Xnuload: Ram disk given but ADT has no RAMDisk property\n");
            return EFI_LOAD_ERROR;
        }
        XNU_PRINT (L"[Xnuload] ADT dram-base/dram-size rewritten to 0x%Lx/0x%Lx\n",
               mLoadBase, MemSize);
        if (mRamdiskSize != 0) {
            XNU_PRINT (L"[Xnuload] ADT RAMDisk rewritten to 0x%Lx/0x%Lx\n",
                   RamdiskPa, mRamdiskSize);
        }
    }
    ArgsPa = (DtbPa + mDeviceTreeSize + 0x3FFFULL) & ~0x3FFFULL;
    Args   = (boot_args *)ArgsPa;

    /* xnu reads topOfKernelData as a physical address and converts it via
     * topOfKernelData - gPhysBase + gVirtBase, so keep PA form here. */
    TopOfKernelData = ArgsPa + 0x4000;

    ZeroMem (Args, sizeof (boot_args));
    Args->Revision = 2;
    Args->Version  = 2;
    Args->virtBase = mKvaBase;
    Args->physBase = mLoadBase;
    Args->memSize  = MemSize;
    Args->topOfKernelData = TopOfKernelData;
    /* xnu reads the device tree with the MMU on: it must be a VA. */
    Args->deviceTreeP       = DtbPa - mLoadBase + mKvaBase;
    Args->deviceTreeLength  = (UINT32)mDeviceTreeSize;
    Args->bootFlags         = 0;
    Args->machineType       = 0;
    Args->memSizeActual     = MemSize;
    FetchGopFramebuffer (Args);
    Args->Video.v_display = 1;
    AsciiStrCpyS (Args->CommandLine, BOOT_LINE_LENGTH, BOOTARG_STRING);
    if (mRamdiskSize != 0) {
        AsciiStrCatS (Args->CommandLine, BOOT_LINE_LENGTH, " rd=md0");
    }

    EntryPa = mLoadBase + (mEntryVa - mKernelLinkBase);

    XNU_PRINT (L"[Xnuload] physBase 0x%Lx, virtBase 0x%Lx, memSize 0x%Lx\n",
           Args->physBase, Args->virtBase, Args->memSize);
    XNU_PRINT (L"[Xnuload] FB@0x%Lx %ux%u row 0x%Lx\n",
           Args->Video.v_baseAddr, Args->Video.v_width, Args->Video.v_height,
           Args->Video.v_rowBytes);
    XNU_PRINT (L"[Xnuload] DT pa 0x%Lx, DT va 0x%Lx, %u bytes\n",
           DtbPa, Args->deviceTreeP, Args->deviceTreeLength);
    XNU_PRINT (L"[Xnuload] args pa 0x%Lx, topK 0x%Lx, entry 0x%Lx\n",
           ArgsPa, TopOfKernelData, EntryPa);

    /* All diagnostics must happen before ExitBootServices: the UEFI console
     * (and every other boot service) is gone after it succeeds. */
    XNU_PRINT (L"[Xnuload] Handing off to the kernel at 0x%Lx with args @ 0x%Lx\n",
           EntryPa, ArgsPa);

    /* Get the memory map (ExitBootServices requires the key). */
    MemoryMapSize = 0;
    MemoryMap     = NULL;
    for (Attempt = 0; Attempt < 16; Attempt++) {
        Status = gBS->GetMemoryMap (&MemoryMapSize, MemoryMap, &MapKey,
                                    &DescriptorSize, &MemDescVersion);
        if (Status == EFI_BUFFER_TOO_SMALL) {
            if (MemoryMap != NULL) gBS->FreePool (MemoryMap);
            MemoryMapSize += 128 * sizeof (EFI_MEMORY_DESCRIPTOR);
            MemoryMap = AllocatePool (MemoryMapSize);
            if (MemoryMap == NULL) {
                XNU_PRINT (L"[Xnuload] Allocate pool for memory map failed\n");
                return EFI_OUT_OF_RESOURCES;
            }
            continue;
        } else if (EFI_ERROR (Status)) {
            XNU_PRINT (L"[Xnuload] GetMemoryMap failed: %r\n", Status);
            return Status;
        }
        break;
    }

    /* Exit the boot services (re-tries if the map key went stale). */
    for (Attempt = 0;; Attempt++) {
        Status = gBS->ExitBootServices (ImageHandle, MapKey);
        if (!EFI_ERROR (Status)) break;

        if (Status == EFI_INVALID_PARAMETER && Attempt < 4) {
            gBS->GetMemoryMap (&MemoryMapSize, MemoryMap, &MapKey,
                               &DescriptorSize, &MemDescVersion);
            continue;
        }
        XNU_PRINT (L"[Xnuload] ExitBootServices failed: %r\n", Status);
        return Status;
    }

    /* Hand off to the kernel with x0 = boot args PA. No EFI calls from here
     * on (not even Print): the console may already be torn down. */
    Handoff (ArgsPa, EntryPa, mLoadBase,
             mLoadBase + KernelLoadSize + RamdiskLoadSize + XNU_HEADROOM);

    /* Unreachable. */
    return EFI_NOT_READY;
}
