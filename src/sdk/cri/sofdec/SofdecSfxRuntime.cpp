/**
 * CRI Sofdec SFX (Special-Effect / frame composition) subsystem runtime.
 *
 * This file contains recovered init/finish/create-chain entry points for the
 * statically linked CRI Sofdec MWSFSFX layer shipped in Forged Alliance.
 *
 * The MWSFSFX_* entry points are thin facades published to the rest of the
 * Moho movie player (`mwPly*` family). They forward to the lower-level
 * `SFX_*` routines which implement the actual frame-composition state
 * machine. The 2007 CRI source wrote these as one-line forwarders so that
 * callers could link against the stable MWSFSFX_ ABI regardless of which
 * backend `SFX_*` variant the engine happened to pull in.
 *
 * All bodies here are recovered 1:1 from binary evidence (IDA/Hex-Rays) and
 * preserve the original control flow and side effects exactly.
 */

#include <cstddef>
#include <cstdint>
#include <cstring>

// ---------------------------------------------------------------------------
// Forward declarations for lower-level CRI Sofdec SFX functions
// ---------------------------------------------------------------------------
//
// These live in the rest of the statically linked CRI Sofdec code. They are
// declared here instead of pulled from a shared header because the recovered
// SDK intentionally keeps each subsystem runtime self-contained while the
// overall CRI header layout is still being reconstructed.

extern "C" {

/// SFX core initialiser. Defined later in this translation unit; the
/// forward declaration here lets the public `MWSFSFX_Init` facade call it
/// without re-ordering the file.
void SFX_Init();

/// Installs the SFX error callback and its context. Defined below, once the
/// work-area globals are in scope.
std::int32_t SFX_SetErrFn(std::int32_t errorCallbackAddress,
                          std::int32_t errorCallbackContext);

/// SFX core teardown. Pairs with SFX_Init().
std::int32_t SFX_Finish();

/// Allocates / initialises an SFX handle from a caller-provided work buffer,
/// work-buffer size, and configuration tag. Returns an opaque handle pointer
/// (`struct_sofdec_sfx_hn*`).
void* SFX_Create(std::int32_t workBufferAddress,
                 std::int32_t workBufferSize,
                 std::int32_t configTag);

/// Reports a formatted Sofdec-SVM error message through the shared MWSFSVM
/// error channel. Only the string pointer is used; the leading context slot
/// matches the CRI-internal error-callback ABI.
std::int32_t MWSFSVM_Error(const char* format, ...);

// Lower-level SFX dependencies pulled in by `SFX_Init` and the SFX init
// chain. These remain externs because their bodies live in deeper SFX
// subsystems whose layouts are still being reconstructed; each is a thin
// init/dispatch entry point with no engine-visible side effects beyond the
// Sofdec library work area.

/// Selects the CCIR matrix variant used by the SFX colour pipeline. Defined
/// below, once the work-area globals are in scope.
std::int32_t SFX_SetCcirFx(std::int32_t mode);

/// Initialises the CFT (Color Format Table) module. Pairs with the matching
/// teardown in the CFT runtime.
void CFT_Init();

/// SFXZ (depth/Z-blit) library work-area initialiser. Defined below, once the
/// work-area globals are in scope.
std::int32_t SFXZ_SetZbufType(std::int32_t zbufType);
std::int32_t sfxzmv_InitLibWork();

/// SFXA (audio) library work-area initialiser. Returns the CRI
/// success/error status of the underlying init.
std::int32_t sfxalp_InitLibWork();

/// SUD (Sofdec Universal Dispatch) module initialiser. Resets the dispatch
/// table used by SFXSUD callers.
void SUD_Init();

}  // extern "C"

// ---------------------------------------------------------------------------
// SFX library work area
// ---------------------------------------------------------------------------
//
// `_sfx_libwork` is the global work-area struct shared by every SFX init /
// teardown path. The full layout is still being recovered; the fields below
// are the ones reached from the recovered SFX_Init / sfx_InitLibWork paths.
// Field offsets are pinned to the binary so that pointer arithmetic in the
// rest of the SFX runtime keeps matching `[esi+4]` style accesses observed
// in the disassembly.
//
// The struct intentionally has no size assertion: only the head of the
// layout is known with high confidence.

namespace moho_cri_sfx_internal {

/// One SFX composition handle. `sfx_InitHn` clears all 0x94 bytes and then
/// seeds the lanes below; `sfx_SearchFreeHn` walks the pool at stride 0x94
/// testing the first dword.
using SfxCnvFrmCallback = std::int32_t(__cdecl*)(
  const CftYcc420PlanarPackedWords* source,
  const CftRgb16OutputPackedWords* target,
  const std::int32_t* tableParams
);
using SfxCopyAlphaCallback = std::uint8_t*(__cdecl*)(
  std::uint8_t** sourcePlanes,
  const std::int32_t* conversionWords,
  const std::int32_t* userTableAddress
);

/// Signature of the three alpha/luminance table builders reached through the
/// SFXA sub-handle: <pivot, min, max, tableAddress>.
using SfxMakeTableCallback = std::int32_t(__cdecl*)(
  std::int32_t luminancePivot,
  std::int32_t luminanceMin,
  std::int32_t luminanceMax,
  std::int32_t tableAddress
);

/// The colour-adjust builder takes only the table address.
using SfxMakeColorAdjustTableCallback = std::int32_t(__cdecl*)(std::int32_t tableAddress);

struct SfxHandle {
  std::int32_t used;          ///< +0x00 set to 1 by sfx_InitHn
  std::int32_t compositionCode; ///< +0x04 composition mode (sfxcnv_IsCnvUpHalf)
  std::int32_t outputBufferWidth;  ///< +0x08 SFX_Set/GetOutBufSize
  std::int32_t outputBufferHeight; ///< +0x0C SFX_Set/GetOutBufSize
  std::int32_t unitWidth;     ///< +0x10 SFX_SetUnitWidth
  std::uint8_t mUnknown14[0x10]; ///< +0x14
  std::int32_t sfxz;          ///< +0x24 SFXZ sub-handle (SFX_Create)
  std::uint8_t mUnknown28_[0x08]; ///< +0x28 (+0x28 = 1, +0x2C = 0)
  std::int32_t sfxa;          ///< +0x30 SFXA sub-handle (SFX_Create)
  std::int32_t reserved34;    ///< +0x34
  std::int32_t planeBase;     ///< +0x38 work address aligned up to 32
  std::int32_t plane1;        ///< +0x3C planeBase + 1024
  std::int32_t plane2;        ///< +0x40 plane1 + 1024
  std::int32_t plane3;        ///< +0x44 plane2 + 1024
  std::uint8_t mUnknown48[0x08]; ///< +0x48
  /// +0x50 seeded with the raw work address by `sfx_InitHn`, then reused by
  /// `SFX_CnvFrmARGB8888ByCbFunc` as the colour-adjust table base. Nothing
  /// reads it back as a work address, so both writes stand.
  std::int32_t tableBase;
  std::int32_t configTag;     ///< +0x54
  std::int32_t splitField;    ///< +0x58 seeded to -1 = "decide from the stream"
  std::int32_t progOut;       ///< +0x5C progressive-output request
  std::int32_t mUnknown60;    ///< +0x60
  std::int32_t cnvBottomUp;   ///< +0x64 write converted rows bottom-up
  SfxCnvFrmCallback  cnvFrmCallback;    ///< +0x68 installed per pixel format
  SfxCopyAlphaCallback copyAlphaCallback; ///< +0x6C
  SfxMakeColorAdjustTableCallback colorAdjustTableCallback; ///< +0x70
  std::uint8_t mUnknown74[0x20]; ///< +0x74
};

static_assert(sizeof(SfxHandle) == 0x94, "SfxHandle size must be 0x94");
static_assert(offsetof(SfxHandle, sfxz) == 0x24, "SfxHandle::sfxz must live at offset 0x24");
static_assert(offsetof(SfxHandle, compositionCode) == 0x04, "SfxHandle::compositionCode must live at offset 0x04");
static_assert(offsetof(SfxHandle, outputBufferWidth) == 0x08, "SfxHandle::outputBufferWidth must live at offset 0x08");
static_assert(offsetof(SfxHandle, outputBufferHeight) == 0x0C, "SfxHandle::outputBufferHeight must live at offset 0x0C");
static_assert(offsetof(SfxHandle, unitWidth) == 0x10, "SfxHandle::unitWidth must live at offset 0x10");
static_assert(offsetof(SfxHandle, sfxa) == 0x30, "SfxHandle::sfxa must live at offset 0x30");
static_assert(offsetof(SfxHandle, planeBase) == 0x38, "SfxHandle::planeBase must live at offset 0x38");
static_assert(offsetof(SfxHandle, tableBase) == 0x50, "SfxHandle::tableBase must live at offset 0x50");
static_assert(offsetof(SfxHandle, splitField) == 0x58, "SfxHandle::splitField must live at offset 0x58");
static_assert(offsetof(SfxHandle, progOut) == 0x5C, "SfxHandle::progOut must live at offset 0x5C");
static_assert(offsetof(SfxHandle, cnvBottomUp) == 0x64, "SfxHandle::cnvBottomUp must live at offset 0x64");
static_assert(offsetof(SfxHandle, cnvFrmCallback) == 0x68, "SfxHandle::cnvFrmCallback must live at offset 0x68");
static_assert(offsetof(SfxHandle, configTag) == 0x54, "SfxHandle::configTag must live at offset 0x54");

/// Handles the SFX pool holds. `sfx_InitLibWork` seeds `last` with this.
constexpr std::int32_t kSfxHandlePoolSize = 32;

/// Global SFX library work area (0x011F9B20). `cur` counts live handles and
/// `last` is the cell cap `sfx_InitLibWork` seeds with 32; the handle pool
/// follows at +0x18.
struct SfxLibWorkHead {
  std::int32_t  cur;             ///< +0x00 live-handle count (SFX_Create/Destroy)
  std::int32_t  last;            ///< +0x04 last-cell sentinel (= 32)
  std::int32_t  errFn;           ///< +0x08 error callback (SFX_SetErrFn)
  std::int32_t  errParam;        ///< +0x0C error callback context
  std::int32_t  numErrs;         ///< +0x10 error count (SFXLIB_Error)
  std::int32_t  cirFx;           ///< +0x14 CCIR matrix selector
  SfxHandle     objs[kSfxHandlePoolSize]; ///< +0x18, stride 0x94
};

static_assert(offsetof(SfxLibWorkHead, objs) == 0x18,
              "SfxLibWorkHead::objs must live at offset 0x18");

static_assert(offsetof(SfxLibWorkHead, last) == 0x04,
              "SfxLibWorkHead::last must live at offset 0x04");
static_assert(offsetof(SfxLibWorkHead, errFn) == 0x08,
              "SfxLibWorkHead::errFn must live at offset 0x08");
static_assert(offsetof(SfxLibWorkHead, numErrs) == 0x10,
              "SfxLibWorkHead::numErrs must live at offset 0x10");
static_assert(offsetof(SfxLibWorkHead, cirFx) == 0x14,
              "SfxLibWorkHead::cirFx must live at offset 0x14");

/// Head of the SFXZ (depth/Z-blit) work area (0x011F9180, 0x98C bytes).
/// One SFXZ (depth/Z-blit) handle; the pool stride is 0x4C.
struct SfxzHandle {
  std::int32_t used;             ///< +0x00 set to 1 by SFXZ_Create
  std::int32_t reserved04;       ///< +0x04 cleared by sfxzmv_InitHn
  std::uint8_t mUnknown08[0x34]; ///< +0x08
  std::int32_t reserved3C;       ///< +0x3C cleared by sfxzmv_InitHn
  std::int32_t reserved40;       ///< +0x40
  std::int32_t reserved44;       ///< +0x44
  std::int32_t reserved48;       ///< +0x48
};

static_assert(sizeof(SfxzHandle) == 0x4C, "SfxzHandle size must be 0x4C");

struct SfxzWorkHead {
  std::int32_t cur;         ///< +0x00 live-handle count (SFXZ_Create)
  std::int32_t zbufType;    ///< +0x04 selector written by SFXZ_SetZbufType
  std::int32_t last;        ///< +0x08 last-cell sentinel (= 32)
  SfxzHandle   objs[32];    ///< +0x0C, stride 0x4C
};

static_assert(offsetof(SfxzWorkHead, objs) == 0x0C,
              "SfxzWorkHead::objs must live at offset 0x0C");
// 0x0C + 32 * 0x4C == 0x98C, the extent sfxzmv_InitLibWork clears.
static_assert(sizeof(SfxzWorkHead) == 0x98C, "SfxzWorkHead size must be 0x98C");

static_assert(offsetof(SfxzWorkHead, zbufType) == 0x04,
              "SfxzWorkHead::zbufType must live at offset 0x04");
static_assert(offsetof(SfxzWorkHead, last) == 0x08,
              "SfxzWorkHead::last must live at offset 0x08");

}  // namespace moho_cri_sfx_internal

// SFX library global storage. These are the linker-visible globals the
// rest of the CRI SFX runtime touches via `_sfx_*` symbols. They live in
// this translation unit because the SFX init/teardown chain owns them and
// no other recovered SFX source has reached them yet. The work-area
// definition is kept outside the `extern "C"` block because its type is
// a C++ struct in a namespace; the storage symbol still has C linkage by
// virtue of being a non-mangled global.

/// Global SFX library work area. The full struct is larger than
/// `SfxLibWorkHead`; only the head is typed here while the rest of the
/// SFX runtime is being reconstructed.
moho_cri_sfx_internal::SfxLibWorkHead sfx_libwork{};

/// Global SFXZ work area. Like `sfx_libwork` only the head is typed; the
/// full 0x98C-byte extent is reserved so `sfxzmv_InitLibWork`'s clear covers
/// the same range the binary clears.
struct SfxzWorkStorage {
  moho_cri_sfx_internal::SfxzWorkHead head;
};
SfxzWorkStorage sfxz_work{};

extern "C" {

/**
 * Address: 0x00ACC840 (FUN_00ACC840, _SFX_SetErrFn)
 *
 * IDA signature:
 * int __cdecl SFX_SetErrFn(int a1, int a2);
 *
 * What it does:
 * Installs the SFX error callback and its context, and echoes the callback
 * back to the caller.
 */
std::int32_t SFX_SetErrFn(std::int32_t errorCallbackAddress,
                          std::int32_t errorCallbackContext)
{
  sfx_libwork.errFn = errorCallbackAddress;
  sfx_libwork.errParam = errorCallbackContext;
  return errorCallbackAddress;
}

/**
 * Address: 0x00ACCA20 (FUN_00ACCA20, _SFXLIB_Error)
 *
 * What it does:
 * Increments the SFX library's error count and, when an error callback is
 * installed (`SFX_SetErrFn`), invokes it with the stored context and the
 * error message. `conversionState`/`streamState` are accepted to match the
 * real call sites but are not read by the binary body. Previously a
 * no-argument stub in SofdecExternalStubs.cpp; every real call site
 * (SFX_CnvFrmByCbFunc's unsupported-composition-mode paths) silently
 * discarded all three arguments, so error reporting never fired.
 */
void SFXLIB_Error(
  moho::SfxCallbackFrameContext* const conversionState,
  moho::SfxStreamState* const streamState,
  const char* const message
)
{
  (void)conversionState;
  (void)streamState;

  ++sfx_libwork.numErrs;
  if (sfx_libwork.errFn != 0) {
    using SfxErrorCallback = void(__cdecl*)(std::int32_t errorCallbackContext, const char* message);
    reinterpret_cast<SfxErrorCallback>(static_cast<std::intptr_t>(sfx_libwork.errFn))(sfx_libwork.errParam, message);
  }
}

/**
 * Address: 0x00ACCA50 (FUN_00ACCA50, _SFX_SetCcirFx)
 *
 * What it does:
 * Selects the CCIR matrix variant used by the SFX colour pipeline. The
 * argument is a small enum-like selector; `sfx_InitLibWork` installs `1`.
 */
std::int32_t SFX_SetCcirFx(std::int32_t mode)
{
  sfx_libwork.cirFx = mode;
  return mode;
}

/**
 * Address: 0x00ACDDF0 (FUN_00ACDDF0, _SFXZ_SetZbufType)
 */
std::int32_t SFXZ_SetZbufType(std::int32_t zbufType)
{
  sfxz_work.head.zbufType = zbufType;
  return zbufType;
}

/**
 * Address: 0x00ACD5B0 (FUN_00ACD5B0, _sfxzmv_InitLibWork)
 *
 * What it does:
 * Clears the SFXZ work area, primes the cell-cap sentinel and selects the
 * default Z-buffer type. This is the leaf `SFXZ_Init` tail-jumps to, and it
 * sits on the startup path through `MWSFSFX_Init` -> `SFX_Init`.
 */
std::int32_t sfxzmv_InitLibWork()
{
  constexpr std::int32_t kSfxzLastCellSentinel = 32;
  constexpr std::int32_t kSfxzDefaultZbufType = 0;

  std::memset(&sfxz_work, 0, sizeof(sfxz_work));
  sfxz_work.head.last = kSfxzLastCellSentinel;
  return SFXZ_SetZbufType(kSfxzDefaultZbufType);
}

/// One-shot init guard for `SFX_Init`. Incremented on first successful
/// init; subsequent calls become no-ops.
std::int32_t sfx_init_cnt = 0;

/// Discardable slot used by `SFX_Init` to keep the version-string call
/// from being optimised out. Reflects the original CRI source pattern
/// (`sfx_dummy = (int)sfx_GetVersionStr();`).
std::int32_t sfx_dummy = 0;

/// SFX converter "force split" flag. Reset to `0` by `SFX_Init` so that
/// the converter does not inherit a stale setting across re-inits.
std::int32_t sfxcnv_forcesplit = 0;

}  // extern "C"

// ---------------------------------------------------------------------------
// Internal error-callback trampoline (defined below)
// ---------------------------------------------------------------------------

extern "C" void __cdecl mwsfsfx_SfxErrCbFn(int contextTag,
                                           const char* errorMessage);

// ---------------------------------------------------------------------------
// Public MWSFSFX_* facade entry points
// ---------------------------------------------------------------------------

extern "C" {

/**
 * Address: 0x00AC6660 (FUN_00AC6660)
 * Mangled: _MWSFSFX_Init
 *
 * IDA signature:
 * int MWSFSFX_Init();
 *
 * What it does:
 * Initialises the SFX core and installs the Sofdec-SVM error-forwarding
 * callback so that CRI-internal SFX error strings flow through the same
 * channel as the rest of the movie player. Returns the status code produced
 * by `SFX_SetErrFn`.
 */
std::int32_t MWSFSFX_Init()
{
  SFX_Init();
  return SFX_SetErrFn(
      reinterpret_cast<std::int32_t>(&mwsfsfx_SfxErrCbFn),
      0);
}

}  // extern "C"

// ---------------------------------------------------------------------------
// Error-forwarding callback registered by MWSFSFX_Init
// ---------------------------------------------------------------------------

/**
 * Address: 0x00AC6680 (FUN_00AC6680)
 * Mangled: _mwsfsfx_SfxErrCbFn
 *
 * IDA signature:
 * void __cdecl mwsfsfx_SfxErrCbFn(int contextTag, char* errorMessage);
 *
 * What it does:
 * Error-callback trampoline registered with the SFX core by
 * `MWSFSFX_Init`. Forwards any SFX-emitted error string to the Sofdec-SVM
 * error channel (`MWSFSVM_Error`). The leading context slot is ignored and
 * exists only to match the CRI callback ABI (`void(*)(int, const char*)`).
 */
extern "C" void __cdecl mwsfsfx_SfxErrCbFn(int /*contextTag*/,
                                           const char* errorMessage)
{
  MWSFSVM_Error(errorMessage);
}

// ---------------------------------------------------------------------------
// Teardown / handle-lifecycle facade
// ---------------------------------------------------------------------------

extern "C" {

/**
 * Address: 0x00AC6690 (FUN_00AC6690)
 * Mangled: _MWSFSFX_Finish
 *
 * IDA signature:
 * int MWSFSFX_Finish();  // attributes: thunk
 *
 * What it does:
 * Public teardown entry for the MWSFSFX layer. Forwards to the SFX core
 * `SFX_Finish` routine which releases all SFX-internal state allocated
 * during `MWSFSFX_Init`. The original binary is a single-instruction
 * tail-jump thunk (`jmp _SFX_Finish`); the C++ forwarder below preserves the
 * same externally observable behaviour.
 */
std::int32_t MWSFSFX_Finish()
{
  return SFX_Finish();
}

/**
 * Address: 0x00AC66A0 (FUN_00AC66A0)
 * Mangled: _MWSFSFX_CalcHnWorkSiz
 *
 * IDA signature:
 * int __cdecl MWSFSFX_CalcHnWorkSiz(int cellCount);
 *
 * What it does:
 * Returns the size in bytes of the SFX work buffer required to host an
 * SFX handle that manages `cellCount` composition cells.
 *
 * Recovered from ASM: the binary computes
 *
 *   tmp     = cellCount + (cellCount SAR 1)   // signed "ceil half" form
 *   return (tmp << 3) + 0x205D                // 8 * tmp + 8285
 *
 * Hex-Rays renders this as `8 * (a1 + a1 / 2) + 8285`. For non-negative
 * inputs the expression is equivalent to `12 * cellCount + 8285`; the
 * original compiler emitted the `SAR/add/LEA*8` form, which is preserved
 * here verbatim via the `(cellCount + cellCount/2) * 8 + 0x205D`
 * spelling so that the recovered bytecode trivially matches the binary.
 */
std::int32_t MWSFSFX_CalcHnWorkSiz(std::int32_t cellCount)
{
  // Matches the `cdq / sub / sar 1 / add / lea [eax*8 + 0x205D]` sequence
  // at 0x00AC66A0 .. 0x00AC66B4 exactly. The SDK-visible header size
  // constant 0x205D (8285) is the fixed per-handle overhead.
  constexpr std::int32_t kSfxWorkHeaderBytes = 0x205D;
  const std::int32_t halfCells = cellCount / 2;          // signed, CDQ/SAR
  const std::int32_t scaledCellTotal = (cellCount + halfCells) * 8;
  return scaledCellTotal + kSfxWorkHeaderBytes;
}

/**
 * Address: 0x00AC66C0 (FUN_00AC66C0)
 * Mangled: _MWSFSFX_Create
 *
 * IDA signature:
 * struct_sofdec_sfx_hn* __cdecl MWSFSFX_Create(int workBufferAddress,
 *                                              int workBufferSize,
 *                                              int configTag);
 *
 * What it does:
 * Public handle-creation entry for the MWSFSFX layer. Forwards the
 * caller-provided work buffer, buffer size, and configuration tag to the
 * SFX core `SFX_Create` routine and returns the resulting opaque SFX
 * handle. The original binary is a single-instruction tail-jump thunk
 * (`jmp _SFX_Create`); the C++ forwarder below preserves the same
 * externally observable behaviour.
 */
void* MWSFSFX_Create(std::int32_t workBufferAddress,
                     std::int32_t workBufferSize,
                     std::int32_t configTag)
{
  return SFX_Create(workBufferAddress, workBufferSize, configTag);
}

}  // extern "C"

// ---------------------------------------------------------------------------
// SFX core init chain
// ---------------------------------------------------------------------------
//
// The five entry points below are the recovered bodies of the lower-level
// `SFX_*` / `sfx_*` calls invoked from `MWSFSFX_Init` -> `SFX_Init`. They
// were previously left as `extern "C"` declarations in this file; the
// recovered bodies replace those stubs and complete the SFX init chain
// 1:1 with the binary evidence.

extern "C" {

/**
 * Address: 0x00ACC7D0 (FUN_00ACC7D0)
 * Mangled: _sfx_GetVersionStr
 *
 * IDA signature:
 * const char *sfx_GetVersionStr();
 *
 * What it does:
 * Returns the embedded CRI SFX library banner string. The pointer is the
 * address of the `_sfx_ver_str` constant in `.rdata`; SFX_Init keeps the
 * call live so the banner survives link-time dead-code elimination.
 */
const char* sfx_GetVersionStr()
{
  return "\nCRI SFX/PC Ver.2.29 Build:Feb 28 2005 21:33:58\n";
}

/**
 * Address: 0x00ACC7E0 (FUN_00ACC7E0)
 * Mangled: _sfx_InitLibWork
 *
 * IDA signature:
 * void sfx_InitLibWork();
 *
 * What it does:
 * Zero-fills the global `sfx_libwork` work area, then primes the
 * `last` slot with the cell-cap sentinel `32`. Finally selects the
 * default CCIR colour pipeline (`SFX_SetCcirFx(1)`) and initialises
 * the colour-format table (`CFT_Init`). Called once from `SFX_Init`
 * before the SFXSUD/SFXZ/SFXA submodule init calls.
 */
void sfx_InitLibWork()
{
  std::memset(&sfx_libwork, 0, sizeof(sfx_libwork));
  sfx_libwork.last = 32;
  SFX_SetCcirFx(1);
  CFT_Init();
}

/**
 * Address: 0x00ACD5A0 (FUN_00ACD5A0)
 * Mangled: _SFXZ_Init
 *
 * IDA signature:
 * int SFXZ_Init();  // attributes: thunk
 *
 * What it does:
 * Thin forwarder for the SFXZ (depth/Z-blit) submodule. The original
 * binary is a single-instruction tail-jump thunk to
 * `_sfxzmv_InitLibWork`; the C++ forwarder preserves the same call
 * semantics and returns the underlying init status code.
 */
std::int32_t SFXZ_Init()
{
  return sfxzmv_InitLibWork();
}

/**
 * Address: 0x00ADE1C0 (FUN_00ADE1C0)
 * Mangled: _SFXA_Init
 *
 * IDA signature:
 * int SFXA_Init();  // attributes: thunk
 *
 * What it does:
 * Thin forwarder for the SFXA (audio) submodule. Tail-jumps to
 * `_sfxalp_InitLibWork` in the binary; the C++ forwarder preserves the
 * same call semantics and returns the underlying init status code.
 */
// Body lives in cri/sofdec/SofdecSvmTransferRuntime.cpp, which is part of the
// same aggregate translation unit as this fragment.

/**
 * Address: 0x00ADE3E0 (FUN_00ADE3E0)
 * Mangled: _SFXSUD_Init
 *
 * IDA signature:
 * void SFXSUD_Init();  // attributes: thunk
 *
 * What it does:
 * Thin forwarder for the SFXSUD (Sofdec Universal Dispatch) submodule.
 * Tail-jumps to `_SUD_Init` in the binary; the C++ forwarder preserves
 * the same call semantics.
 */
// Body lives in cri/sofdec/SofdecSvmTransferRuntime.cpp, which is part of the
// same aggregate translation unit as this fragment.

/**
 * Address: 0x00ACC790 (FUN_00ACC790)
 * Mangled: _SFX_Init
 *
 * IDA signature:
 * void SFX_Init();
 *
 * What it does:
 * One-shot initialiser for the entire CRI SFX library. Idempotent: if
 * `sfx_init_cnt` is already at least 1 the routine returns without
 * touching any state. Otherwise it stores the embedded version banner
 * pointer into the discardable `sfx_dummy` slot (so the call is not
 * dead-code-eliminated), runs `sfx_InitLibWork` to prime the global
 * work area, then chains the three SFX submodule initialisers
 * (`SFXSUD_Init`, `SFXZ_Init`, `SFXA_Init`). Finally clears the
 * converter `force split` flag and increments the init guard.
 *
 * Reconstructed from the 13-instruction body at 0x00ACC790..0x00ACC7CC.
 * The original asm uses a `mov eax, sfx_init_cnt / inc eax / mov
 * sfx_init_cnt, eax` triple instead of `++sfx_init_cnt`; the recovered
 * source uses the increment idiom which the compiler emits identically.
 */
void SFX_Init()
{
  if (sfx_init_cnt < 1) {
    sfx_dummy = reinterpret_cast<std::int32_t>(sfx_GetVersionStr());
    sfx_InitLibWork();
    SFXSUD_Init();
    SFXZ_Init();
    SFXA_Init();
    sfxcnv_forcesplit = 0;
    ++sfx_init_cnt;
  }
}

/**
 * Address: 0x00ACD5E0 (FUN_00ACD5E0, _SFXZ_Finish)
 * Mangled: _SFXZ_Finish (C linkage)
 *
 * IDA signature:
 * void SFXZ_Finish();
 *
 * What it does:
 * Nothing. The SFXZ teardown hook exists so `SFX_Finish` can call every
 * submodule uniformly, but this build's Z-buffer path holds no resources
 * that need releasing - the body really is a bare `retn` at 0x00ACD5E0.
 */
void SFXZ_Finish()
{
}

/**
 * Address: 0x00ACC810 (FUN_00ACC810, _SFX_Finish)
 * Mangled: _SFX_Finish (C linkage)
 *
 * IDA signature:
 * int SFX_Finish();
 *
 * What it does:
 * Mirror of `SFX_Init`: guarded by the same init counter, tears down the
 * submodules in reverse order and decrements the guard. Returns the counter
 * unchanged when the library was never initialized, otherwise the result of
 * the final `CFT_Finish`.
 */
std::int32_t SFX_Finish()
{
  if (sfx_init_cnt <= 0) {
    return sfx_init_cnt;
  }

  SFXZ_Finish();
  SFXA_Finish();
  (void)SFXSUD_Finish();
  // The binary returns whatever CFT_Finish left in eax. Our recovered
  // CFT_Finish is void - it has no failure path - so the observable result is
  // the success code its callers test for.
  CFT_Finish();
  --sfx_init_cnt;
  return 0;
}

// Declared with the shared parameter types in SofdecAdxDeclarationsRuntime.cpp
// and SofdecSvmTransferRuntime.cpp; SFX_Destroy has no declaration of its own
// yet. SFXLIB_Error takes typed context pointers the create path has none of,
// which is why the calls below pass null for both.
void SFX_Destroy(void* sfxHandle);

namespace {

constexpr char kSfxErrWorkSizeShort[] = "E201194: sfx_InitHn: work size is short.";
constexpr char kSfxErrSfxzCreate[] = "E201281: SfxZHn: can't create.";
constexpr char kSfxErrSfxaCreate[] = "E202011: SfxAHn: can't create.";

/// Composition planes are 1 KB apart, starting from a 32-byte-aligned base.
constexpr std::int32_t kSfxPlaneStrideBytes = 1024;
constexpr std::int32_t kSfxPlaneAlignBytes = 32;

}  // namespace

/**
 * Address: 0x00ACC910 (FUN_00ACC910, _sfx_SearchFreeHn)
 *
 * What it does:
 * Returns the first unused SFX handle in the pool, or null when all `last`
 * slots are taken.
 */
moho_cri_sfx_internal::SfxHandle* sfx_SearchFreeHn()
{
  for (std::int32_t index = 0; index < sfx_libwork.last; ++index) {
    if (sfx_libwork.objs[index].used == 0) {
      return &sfx_libwork.objs[index];
    }
  }
  return nullptr;
}

/**
 * Address: 0x00ACC9B0 (FUN_00ACC9B0, _sfx_IsEnoughHnWorkSize)
 *
 * What it does:
 * Reports whether a caller-supplied work buffer covers the three composition
 * planes plus fixed overhead for a stream `frameWidth` wide.
 */
std::int32_t sfx_IsEnoughHnWorkSize(const std::int32_t workBytes, const std::int32_t frameWidth)
{
  return workBytes >= 8 * (frameWidth + frameWidth / 2) + 8285;
}

/**
 * Address: 0x00ACC940 (FUN_00ACC940, _sfx_InitHn)
 *
 * What it does:
 * Clears one SFX handle and lays the composition planes out across the
 * caller's work buffer, 1 KB apart from a 32-byte-aligned base.
 */
std::int32_t sfx_InitHn(
  moho_cri_sfx_internal::SfxHandle* const handle,
  const std::int32_t workAddress,
  const std::int32_t configTag
)
{
  std::memset(handle, 0, sizeof(*handle));

  const std::int32_t planeBase = (workAddress + (kSfxPlaneAlignBytes - 1)) & ~(kSfxPlaneAlignBytes - 1);
  handle->tableBase = workAddress;
  handle->planeBase = planeBase;
  handle->plane1 = planeBase + kSfxPlaneStrideBytes;
  handle->plane2 = handle->plane1 + kSfxPlaneStrideBytes;
  handle->plane3 = handle->plane2 + kSfxPlaneStrideBytes;

  // The memset already zeroed every other lane the binary writes zero to; only
  // the two non-zero seeds and the -1 sentinel are left.
  *reinterpret_cast<std::int32_t*>(reinterpret_cast<std::uint8_t*>(handle) + 0x28) = 1;
  handle->configTag = configTag;
  handle->splitField = -1;
  handle->used = 1;
  return configTag;
}

/**
 * Address: 0x00ACD620 (FUN_00ACD620, _sfxzmv_SearchFreeHn)
 *
 * What it does:
 * Returns the first unused SFXZ handle in the pool.
 */
moho_cri_sfx_internal::SfxzHandle* sfxzmv_SearchFreeHn()
{
  for (std::int32_t index = 0; index < sfxz_work.head.last; ++index) {
    if (sfxz_work.head.objs[index].used == 0) {
      return &sfxz_work.head.objs[index];
    }
  }
  return nullptr;
}

/**
 * Address: 0x00ACD650 (FUN_00ACD650, _sfxzmv_InitHn)
 *
 * What it does:
 * Clears the mutable lanes of one SFXZ handle, leaving the rest of the slot
 * as the pool left it.
 */
moho_cri_sfx_internal::SfxzHandle* sfxzmv_InitHn(moho_cri_sfx_internal::SfxzHandle* const handle)
{
  handle->reserved3C = 0;
  handle->reserved40 = 0;
  handle->reserved44 = 0;
  handle->reserved48 = 0;
  handle->reserved04 = 0;
  return handle;
}

/**
 * Address: 0x00ACD5F0 (FUN_00ACD5F0, _SFXZ_Create)
 *
 * What it does:
 * Claims one SFXZ handle out of the pool and marks it live.
 */
moho_cri_sfx_internal::SfxzHandle* SFXZ_Create()
{
  moho_cri_sfx_internal::SfxzHandle* const handle = sfxzmv_SearchFreeHn();
  if (handle == nullptr) {
    return nullptr;
  }

  (void)sfxzmv_InitHn(handle);
  ++sfxz_work.head.cur;
  handle->used = 1;
  return handle;
}

/**
 * Address: 0x00ACD670 (FUN_00ACD670, _SFXZ_Destroy)
 *
 * IDA signature:
 * void __cdecl SFXZ_Destroy(struct_sofdec_sfxz_hn *a1);
 *
 * What it does:
 * Returns one SFXZ handle to the pool. `SFX_Destroy` is its only caller.
 *
 * It was a no-argument `nullptr` stub, so the pool's 32 slots were claimed once
 * and never released: the 33rd `SFX_Create` of a session failed at `SFXZ_Create`
 * and reported "E201185: can't create SfxHn". The parameter is `void*` to match
 * the declaration `SFX_Destroy` calls through.
 */
void SFXZ_Destroy(void* const sfxzHandle)
{
  if (sfxzHandle == nullptr) {
    return;
  }

  static_cast<moho_cri_sfx_internal::SfxzHandle*>(sfxzHandle)->used = 0;
  --sfxz_work.head.cur;
}

/**
 * Address: 0x00ACC860 (FUN_00ACC860, _SFX_Create)
 *
 * IDA signature:
 * struct_sofdec_sfx_hn *__cdecl SFX_Create(int a1, int a2, int a3);
 *
 * What it does:
 * Builds one SFX composition handle: claims a pool slot, checks the caller's
 * work buffer is big enough for the frame width, lays the planes out in it,
 * then attaches the SFXZ and SFXA sub-handles. Any failure after the slot is
 * claimed tears the whole handle back down.
 */
void* SFX_Create(
  const std::int32_t workAddress,
  const std::int32_t workBytes,
  const std::int32_t frameWidth
)
{
  moho_cri_sfx_internal::SfxHandle* const handle = sfx_SearchFreeHn();
  if (handle == nullptr) {
    return nullptr;
  }

  if (sfx_IsEnoughHnWorkSize(workBytes, frameWidth) == 0) {
    SFXLIB_Error(nullptr, nullptr, kSfxErrWorkSizeShort);
    return nullptr;
  }

  (void)sfx_InitHn(handle, workAddress, workBytes);

  moho_cri_sfx_internal::SfxzHandle* const depthHandle = SFXZ_Create();
  if (depthHandle == nullptr) {
    SFXLIB_Error(nullptr, nullptr, kSfxErrSfxzCreate);
    SFX_Destroy(handle);
    return nullptr;
  }
  handle->sfxz = static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(depthHandle));

  const std::int32_t audioHandle = SFXA_Create();
  if (audioHandle == 0) {
    SFXLIB_Error(nullptr, nullptr, kSfxErrSfxaCreate);
    SFX_Destroy(handle);
    return nullptr;
  }
  handle->sfxa = audioHandle;

  ++sfx_libwork.cur;
  return handle;
}

}  // extern "C"

// ---------------------------------------------------------------------------
// SFX -> CFT frame conversion.
//
// This is the tail of the movie pipeline: it flattens one decoded frame's
// plane descriptors into the buffer shape the CFT kernels read, then invokes
// the pixel-format callback that was installed on the handle.
//
// The two parameter types the shared declarations use are placeholders for the
// real ones. `SfxCallbackFrameContext` is an `SfxHandle` - every offset the
// binary touches here (+0x38 planeBase, +0x50 tableBase, +0x64 cnvBottomUp,
// +0x68 cnvFrmCallback) is a named field of it - and `SfxStreamState` is a
// `MwsfdSfxFrameInfo`, whose 0x94-byte span and +0x90 lane the placeholder was
// modelled from. They are aliased here rather than renamed globally because
// the placeholders live in moho/audio/SofdecRuntime.h while `SfxHandle` is
// local to this fragment; the same aliasing pattern is already used by
// `CFT_Ycc420plnToArgb8888` for its `...View` types.
// ---------------------------------------------------------------------------

namespace moho_cri_sfx_internal {

/// One plane descriptor in the buffer the CFT kernels read.
struct SfxCftPlaneRecord
{
  std::int32_t address; ///< +0x00
  std::int32_t width;   ///< +0x04
  std::int32_t height;  ///< +0x08
  std::int32_t pitch;   ///< +0x0C
};
static_assert(sizeof(SfxCftPlaneRecord) == 0x10, "SfxCftPlaneRecord must be 16 bytes");

/**
 * Source descriptor `sfxcnv_MakeCftSrcBuf` fills.
 *
 * The CFT side sees this same block as `CftYcc420PlanarPackedWords`, which is
 * why the plane addresses land at +0x04 / +0x14 / +0x24 and the pitches at
 * +0x10 / +0x20 / +0x30. The binary's stack object is 68 bytes and memset to
 * zero before use, so the tail beyond the three records is kept.
 */
struct SfxCftSourceBuffer
{
  std::int32_t planeCount = 0;      ///< +0x00 1 = packed, 3 = planar YCbCr
  SfxCftPlaneRecord planes[3]{};    ///< +0x04, +0x14, +0x24
  std::int32_t reserved34[4]{};     ///< +0x34
};
static_assert(offsetof(SfxCftSourceBuffer, planes) == 0x04, "SfxCftSourceBuffer::planes offset must be 0x04");
static_assert(sizeof(SfxCftSourceBuffer) == 0x44, "SfxCftSourceBuffer must be 68 bytes");

/**
 * Destination rectangle handed to the CFT kernels; the CFT side sees it as
 * `CftRgb16OutputPackedWords`.
 */
struct SfxCftTargetBuffer
{
  std::int32_t planeCount; ///< +0x00
  std::int32_t pixels;     ///< +0x04
  std::int32_t width;      ///< +0x08
  std::int32_t height;     ///< +0x0C
  std::int32_t pitch;      ///< +0x10 negative once flipped bottom-up
};
static_assert(offsetof(SfxCftTargetBuffer, pitch) == 0x10, "SfxCftTargetBuffer::pitch offset must be 0x10");

constexpr char kSfxErrCnvSrcFrameFormat[] = "E4111901: sfxcnv_MakeCftSrcBuf : frame format is invalid.";

/// Composition codes `sfxcnv_MakeCftSrcBuf` accepts, from the frame info's +0x00 lane.
constexpr std::int32_t kSfxFrameFormatPacked = 1;
constexpr std::int32_t kSfxFrameFormatPackedAlt = 2;
constexpr std::int32_t kSfxFrameFormatPlanarYcc420 = 3;

}  // namespace moho_cri_sfx_internal

/**
 * Address: 0x00ACCFE0 (FUN_00ACCFE0, _SFX_GetCnvBottomUp)
 *
 * IDA signature:
 * int __cdecl SFX_GetCnvBottomUp(int a1);
 *
 * What it does:
 * Reports whether converted rows are to be written bottom-up.
 */
std::int32_t SFX_GetCnvBottomUp(const moho_cri_sfx_internal::SfxHandle* const handle)
{
  return handle->cnvBottomUp;
}

/**
 * Address: 0x00ACE4B0 (FUN_00ACE4B0, _SFX_SetBottomUpDstBuf)
 *
 * IDA signature:
 * _DWORD* __cdecl SFX_SetBottomUpDstBuf(_DWORD *a1);
 *
 * What it does:
 * Re-points a destination rectangle at its last row and negates the pitch, so
 * the same kernel fills it bottom-up without needing a second code path.
 */
moho_cri_sfx_internal::SfxCftTargetBuffer*
SFX_SetBottomUpDstBuf(moho_cri_sfx_internal::SfxCftTargetBuffer* const target)
{
  const std::int32_t pitch = target->pitch;
  target->pixels += pitch * (target->height - 1);
  target->pitch = -pitch;
  return target;
}

/**
 * Address: 0x00ACEB90 (FUN_00ACEB90, _sfxcnv_MakeCftSrcBuf)
 *
 * IDA signature:
 * void __cdecl sfxcnv_MakeCftSrcBuf(int a1, _DWORD *a2, _DWORD *a3);
 *
 * What it does:
 * Flattens one decoded frame's plane descriptors into the record layout the
 * CFT kernels read. Packed formats carry a single plane; planar YCC 4:2:0
 * carries three, with the chroma planes half as wide. Anything else is a
 * library error and leaves the buffer as the caller zeroed it.
 *
 * Note the width comes from the frame info's cached width lane rather than
 * from each plane record - the plane records carry pitch and height only.
 */
void sfxcnv_MakeCftSrcBuf(
  moho_cri_sfx_internal::SfxHandle* const handle,
  const MwsfdSfxFrameInfo* const frameInfo,
  moho_cri_sfx_internal::SfxCftSourceBuffer* const outSource
)
{
  using namespace moho_cri_sfx_internal;

  const std::int32_t frameFormat = frameInfo->compositionMode;
  const std::int32_t lumaWidth = frameInfo->cachedWidth;

  if (frameFormat == kSfxFrameFormatPacked || frameFormat == kSfxFrameFormatPackedAlt) {
    outSource->planeCount = 1;
    outSource->planes[0] = {frameInfo->yPlane.address, lumaWidth, frameInfo->yPlane.height, frameInfo->yPlane.pitch};
    return;
  }

  if (frameFormat == kSfxFrameFormatPlanarYcc420) {
    const std::int32_t chromaWidth = lumaWidth / 2;
    outSource->planeCount = 3;
    outSource->planes[0] = {frameInfo->yPlane.address, lumaWidth, frameInfo->yPlane.height, frameInfo->yPlane.pitch};
    outSource->planes[1] = {
      frameInfo->cbPlane.address, chromaWidth, frameInfo->cbPlane.height, frameInfo->cbPlane.pitch
    };
    outSource->planes[2] = {
      frameInfo->crPlane.address, chromaWidth, frameInfo->crPlane.height, frameInfo->crPlane.pitch
    };
    return;
  }

  SFXLIB_Error(
    reinterpret_cast<moho::SfxCallbackFrameContext*>(handle),
    reinterpret_cast<moho::SfxStreamState*>(const_cast<MwsfdSfxFrameInfo*>(frameInfo)),
    kSfxErrCnvSrcFrameFormat
  );
}

/**
 * Address: 0x00ACEB10 (FUN_00ACEB10, _sfxcnv_ExecCnvFrmByCbFunc)
 *
 * IDA signature:
 * int __cdecl sfxcnv_ExecCnvFrmByCbFunc(_DWORD *a1, int a2, int a3, int a4);
 *
 * What it does:
 * Runs one decoded frame through the pixel-format callback installed on the
 * handle. This is where a frame becomes pixels; while it stood as a
 * `{ return nullptr; }` C-linkage stub the whole conversion path completed and
 * reported success without ever writing to the destination surface.
 *
 * `useLookupTable` selects whether the callback gets the handle's composition
 * plane base as its table - the composition modes that call `SFX_MakeTable`
 * first pass 1 - or zero, which makes the CFT entry fall back to the static
 * default table.
 */
void sfxcnv_ExecCnvFrmByCbFunc(
  moho::SfxCallbackFrameContext* const conversionState,
  moho::SfxStreamState* const streamState,
  const std::int32_t callbackArg,
  const std::int32_t useLookupTable
)
{
  using namespace moho_cri_sfx_internal;

  auto* const handle = reinterpret_cast<SfxHandle*>(conversionState);
  const auto* const frameInfo = reinterpret_cast<const MwsfdSfxFrameInfo*>(streamState);
  auto* const target = reinterpret_cast<SfxCftTargetBuffer*>(static_cast<std::uintptr_t>(callbackArg));

  SfxCftSourceBuffer source{};
  sfxcnv_MakeCftSrcBuf(handle, frameInfo, &source);

  const std::int32_t tableParams[2] = {
    (useLookupTable == 1) ? handle->planeBase : 0,
    handle->tableBase,
  };

  if (SFX_GetCnvBottomUp(handle) == 1) {
    (void)SFX_SetBottomUpDstBuf(target);
  }

  if (handle->cnvFrmCallback != nullptr) {
    (void)handle->cnvFrmCallback(
      reinterpret_cast<const CftYcc420PlanarPackedWords*>(&source),
      reinterpret_cast<const CftRgb16OutputPackedWords*>(target),
      tableParams
    );
  }
}

namespace moho_cri_sfx_internal {

/**
 * Head of the SFXA sub-handle, far enough to reach the table-building
 * callbacks. Three of the six setters below dereference `SfxHandle::sfxa`
 * (+0x30) before writing, so these callbacks live here rather than on the SFX
 * handle itself.
 */
struct SfxaTableCallbacks
{
  std::uint8_t mUnknown00[0x18];         ///< +0x00
  SfxMakeTableCallback makeLumiTable;    ///< +0x18
  SfxMakeTableCallback makeAlp3110Table; ///< +0x1C
  SfxMakeTableCallback makeAlp3Table;    ///< +0x20
};
static_assert(offsetof(SfxaTableCallbacks, makeLumiTable) == 0x18, "SfxaTableCallbacks::makeLumiTable offset");
static_assert(offsetof(SfxaTableCallbacks, makeAlp3110Table) == 0x1C, "SfxaTableCallbacks::makeAlp3110Table offset");
static_assert(offsetof(SfxaTableCallbacks, makeAlp3Table) == 0x20, "SfxaTableCallbacks::makeAlp3Table offset");

[[nodiscard]] inline SfxaTableCallbacks* SfxaTableCallbacksOf(SfxHandle* const handle) noexcept
{
  return reinterpret_cast<SfxaTableCallbacks*>(
    static_cast<std::uintptr_t>(static_cast<std::uint32_t>(handle->sfxa))
  );
}

}  // namespace moho_cri_sfx_internal

/**
 * Address: 0x00ACE940 (FUN_00ACE940, _SFX_SetCnvFrmCbFunc)
 *
 * What it does:
 * Installs the per-pixel-format frame converter the executor invokes.
 */
moho_cri_sfx_internal::SfxCnvFrmCallback SFX_SetCnvFrmCbFunc(
  moho_cri_sfx_internal::SfxHandle* const handle, const moho_cri_sfx_internal::SfxCnvFrmCallback callback
)
{
  handle->cnvFrmCallback = callback;
  return callback;
}

/**
 * Address: 0x00ACE950 (FUN_00ACE950, _SFX_SetCopyAlphaCbFunc)
 *
 * What it does:
 * Installs the alpha-plane copier used by the full-alpha composition modes.
 */
moho_cri_sfx_internal::SfxCopyAlphaCallback SFX_SetCopyAlphaCbFunc(
  moho_cri_sfx_internal::SfxHandle* const handle, const moho_cri_sfx_internal::SfxCopyAlphaCallback callback
)
{
  handle->copyAlphaCallback = callback;
  return callback;
}

/**
 * Address: 0x00ACE960 (FUN_00ACE960, _SFX_SetMakeLumiTableCbFunc)
 *
 * What it does:
 * Installs the luminance-table builder on the SFXA sub-handle.
 */
moho_cri_sfx_internal::SfxHandle* SFX_SetMakeLumiTableCbFunc(
  moho_cri_sfx_internal::SfxHandle* const handle, const moho_cri_sfx_internal::SfxMakeTableCallback callback
)
{
  moho_cri_sfx_internal::SfxaTableCallbacksOf(handle)->makeLumiTable = callback;
  return handle;
}

/**
 * Address: 0x00ACE970 (FUN_00ACE970, _SFX_SetMakeAlp3TableCbFunc)
 *
 * What it does:
 * Installs the 3-bit-alpha (3:2:1:1) table builder on the SFXA sub-handle.
 */
moho_cri_sfx_internal::SfxHandle* SFX_SetMakeAlp3TableCbFunc(
  moho_cri_sfx_internal::SfxHandle* const handle, const moho_cri_sfx_internal::SfxMakeTableCallback callback
)
{
  moho_cri_sfx_internal::SfxaTableCallbacksOf(handle)->makeAlp3Table = callback;
  return handle;
}

/**
 * Address: 0x00ACE980 (FUN_00ACE980, _SFX_SetMakeAlp3110TableCbFunc)
 *
 * What it does:
 * Installs the 3:1:1:0-alpha table builder on the SFXA sub-handle.
 */
moho_cri_sfx_internal::SfxHandle* SFX_SetMakeAlp3110TableCbFunc(
  moho_cri_sfx_internal::SfxHandle* const handle, const moho_cri_sfx_internal::SfxMakeTableCallback callback
)
{
  moho_cri_sfx_internal::SfxaTableCallbacksOf(handle)->makeAlp3110Table = callback;
  return handle;
}

/**
 * Address: 0x00ACE990 (FUN_00ACE990, _SFX_SetMakeColAdjTableCbFunc)
 *
 * What it does:
 * Installs the colour-adjust table builder. Unlike the three above this one
 * lives on the SFX handle itself.
 */
moho_cri_sfx_internal::SfxMakeColorAdjustTableCallback SFX_SetMakeColAdjTableCbFunc(
  moho_cri_sfx_internal::SfxHandle* const handle,
  const moho_cri_sfx_internal::SfxMakeColorAdjustTableCallback callback
)
{
  handle->colorAdjustTableCallback = callback;
  return callback;
}

// ---------------------------------------------------------------------------
// ARGB8888 conversion entry points.
//
// This is the top of the movie pipeline tail: CMovie locks its texture sheet
// and calls mwPlyFxCnvFrmARGB8888, which walks down through the clipping and
// destination-buffer setup below to SFX_CnvFrmByCbFunc and finally the CFT
// pixel kernel.
// ---------------------------------------------------------------------------

// The progressive and interlaced ARGB variants are only address-taken by
// SFX_CnvFrmARGB8888ByCbFunc below. Their bodies (0x00AEEB40 / 0x00AEE960)
// and the cft_c_/cft_sse_ leaf tier under them are the next recovery step.
extern "C" std::int32_t CFT_Ycc420plnToArgb8888Prg(
  const CftYcc420PlanarPackedWords* inputWords,
  const CftRgb16OutputPackedWords* outputWords,
  const std::int32_t* userTableAddress
);
extern "C" std::int32_t CFT_Ycc420plnToArgb8888Int(
  const CftYcc420PlanarPackedWords* inputWords,
  const CftRgb16OutputPackedWords* outputWords,
  const std::int32_t* userTableAddress
);

namespace moho_cri_sfx_internal {

/// `sfxcnv_forcesplit`: library-wide override that suppresses field merging
/// regardless of what the stream asks for. Nothing in this build sets it;
/// `SFX_SetForceSplitField` is its only writer.
std::int32_t sfxcnv_forcesplit = 0;

constexpr char kSfxErrCnvUpHalfCompo[] = "E201312: sfxcnv_IsCnvUpHalf : compo is invalid.";

/// First byte `SUD_AnalyTypeDivField` matches in a SUD type string.
constexpr char kSudDivFieldTypeTag[] = "d";

/// Offset of the type string inside a SUD record.
constexpr std::int32_t kSudTypeStringOffset = 18;

/// Distance from the composition plane base to the colour-adjust table.
constexpr std::int32_t kSfxColorAdjustTableOffset = 8223;

/**
 * Composition codes whose converted output covers only the top half of the
 * destination rectangle. `sfxcnv_IsCnvUpHalf` accepts exactly this set plus
 * the full-height set below; anything else is a library error.
 */
constexpr std::int32_t kSfxCompoUpHalfCodes[] = {33, 257};

/// Composition codes whose converted output covers the full destination.
constexpr std::int32_t kSfxCompoFullHeightCodes[] = {17, 49, 65, 81, 97, 113, 241, 273, 4097};

}  // namespace moho_cri_sfx_internal

/**
 * Address: 0x00ACD0D0 (FUN_00ACD0D0, _sfxset_ShiftBufInfByPix)
 *
 * IDA signature:
 * _DWORD* __cdecl sfxset_ShiftBufInfByPix(_DWORD *a1, int a2, int a3);
 *
 * What it does:
 * Advances one plane record to a clip origin and shrinks its remaining row
 * count to match.
 */
MwsfdSfxBufInf* sfxset_ShiftBufInfByPix(
  MwsfdSfxBufInf* const plane, const std::int32_t rows, const std::int32_t columns
)
{
  const std::int32_t remainingRows = plane->height - rows;
  plane->address += columns + rows * plane->pitch;
  plane->height = remainingRows;
  return plane;
}

/**
 * Address: 0x00ACD030 (FUN_00ACD030, _sfxset_ShiftBufInfByLine)
 *
 * IDA signature:
 * _DWORD* __cdecl sfxset_ShiftBufInfByLine(_DWORD *a1, int a2);
 *
 * What it does:
 * Row-only form of the shift above, used when merging the second field.
 */
MwsfdSfxBufInf* sfxset_ShiftBufInfByLine(MwsfdSfxBufInf* const plane, const std::int32_t rows)
{
  const std::int32_t remainingRows = plane->height - rows;
  plane->address += rows * plane->pitch;
  plane->height = remainingRows;
  return plane;
}

/**
 * Address: 0x00ACD070 (FUN_00ACD070, _SFX_ShiftYccPtrByPix)
 *
 * What it does:
 * Moves all three YCbCr plane records to a clip origin. The origin is snapped
 * down to an even pixel so the chroma planes, which move by half as much, stay
 * aligned to the luma quad grid.
 */
void SFX_ShiftYccPtrByPix(
  MwsfdSfxFrameInfo* const frameInfo, const std::int32_t left, const std::int32_t top
)
{
  const std::int32_t lumaLeft = 2 * (left / 2);
  const std::int32_t lumaTop = 2 * (top / 2);
  (void)sfxset_ShiftBufInfByPix(&frameInfo->yPlane, lumaTop, lumaLeft);

  const std::int32_t chromaLeft = lumaLeft / 2;
  const std::int32_t chromaTop = lumaTop / 2;
  (void)sfxset_ShiftBufInfByPix(&frameInfo->cbPlane, chromaTop, chromaLeft);
  (void)sfxset_ShiftBufInfByPix(&frameInfo->crPlane, chromaTop, chromaLeft);
}

/**
 * Address: 0x00ACCFF0 (FUN_00ACCFF0, _SFX_ShiftYccPtrByLine)
 *
 * What it does:
 * Row-only form of the shift above; the field-merge path uses it to step from
 * the first field to the second.
 */
void SFX_ShiftYccPtrByLine(MwsfdSfxFrameInfo* const frameInfo, const std::int32_t rows)
{
  const std::int32_t lumaRows = 2 * (rows / 2);
  (void)sfxset_ShiftBufInfByLine(&frameInfo->yPlane, lumaRows);

  const std::int32_t chromaRows = lumaRows / 2;
  (void)sfxset_ShiftBufInfByLine(&frameInfo->cbPlane, chromaRows);
  (void)sfxset_ShiftBufInfByLine(&frameInfo->crPlane, chromaRows);
}

/**
 * Address: 0x00ACD050 (FUN_00ACD050, _SFX_SetMaxRowToYccPln)
 *
 * What it does:
 * Caps the row count of all three plane records, halving it for chroma.
 */
std::int32_t SFX_SetMaxRowToYccPln(MwsfdSfxFrameInfo* const frameInfo, const std::int32_t rows)
{
  const std::int32_t lumaRows = 2 * (rows / 2);
  frameInfo->yPlane.height = lumaRows;

  const std::int32_t chromaRows = lumaRows / 2;
  frameInfo->cbPlane.height = chromaRows;
  frameInfo->crPlane.height = chromaRows;
  return chromaRows;
}

/**
 * Address: 0x00ACE480 (FUN_00ACE480, _SFX_SetClipping)
 *
 * IDA signature:
 * int __cdecl SFX_SetClipping(int a1, int a2, int a3, int a4, int a5, int a6);
 *
 * What it does:
 * Records the clip rectangle size on the frame info and shifts the plane
 * pointers to its origin. The handle argument is unused - the binary takes it
 * only to keep the SFX calling shape uniform.
 */
void SFX_SetClipping(
  moho_cri_sfx_internal::SfxHandle* const /*handle*/,
  MwsfdSfxFrameInfo* const frameInfo,
  const std::int32_t left,
  const std::int32_t top,
  const std::int32_t width,
  const std::int32_t height
)
{
  frameInfo->cachedWidth = width;
  frameInfo->cachedHeight = height;
  SFX_ShiftYccPtrByPix(frameInfo, left, top);
}

/**
 * Address: 0x00ACE510 (FUN_00ACE510, _sfxcnv_IsCnvUpHalf)
 *
 * IDA signature:
 * int __cdecl sfxcnv_IsCnvUpHalf(int a1);
 *
 * What it does:
 * Reports whether the composition mode on the handle produces output covering
 * only the top half of the destination rectangle, which is how the interlaced
 * modes hand back one field at a time. Unrecognised codes are a library error
 * and fall through as full-height.
 */
std::int32_t sfxcnv_IsCnvUpHalf(const moho_cri_sfx_internal::SfxHandle* const handle)
{
  using namespace moho_cri_sfx_internal;

  const std::int32_t compositionCode = handle->compositionCode;

  if (std::ranges::find(kSfxCompoUpHalfCodes, compositionCode) != std::ranges::end(kSfxCompoUpHalfCodes)) {
    return 1;
  }

  if (std::ranges::find(kSfxCompoFullHeightCodes, compositionCode) == std::ranges::end(kSfxCompoFullHeightCodes)) {
    SFXLIB_Error(nullptr, nullptr, kSfxErrCnvUpHalfCompo);
  }

  return 0;
}

/**
 * Address: 0x00ACEDB0 (FUN_00ACEDB0, _sfxcnv_MakeDstBufInf)
 *
 * IDA signature:
 * int __cdecl sfxcnv_MakeDstBufInf(int a1, int a2, int a3, int a4, int a5);
 *
 * What it does:
 * Fills one destination record from the clip rectangle. The pitch comes from
 * the output-buffer width on the handle when one has been set, otherwise the
 * clip width is used, and modes that convert only the top field get half the
 * rows.
 *
 * The records overlap by one dword - record N owns dwords 4N..4N+4 - so the
 * pitch of record N is written through the base of record N+1, exactly as the
 * binary does.
 */
std::int32_t sfxcnv_MakeDstBufInf(
  const moho_cri_sfx_internal::SfxHandle* const handle,
  const MwsfdSfxFrameInfo* const frameInfo,
  const std::int32_t pixels,
  moho_cri_sfx_internal::SfxCftTargetBuffer* const outTarget,
  const std::int32_t recordIndex
)
{
  using namespace moho_cri_sfx_internal;

  auto* const record = reinterpret_cast<SfxCftTargetBuffer*>(
    reinterpret_cast<std::uint8_t*>(outTarget) + (0x10 * recordIndex)
  );

  record->pixels = pixels;
  record->width = frameInfo->cachedWidth;
  record->height =
    (sfxcnv_IsCnvUpHalf(handle) == 1) ? frameInfo->cachedHeight / 2 : frameInfo->cachedHeight;

  const std::int32_t outputBufferWidth = handle->outputBufferWidth;
  auto* const nextRecord = reinterpret_cast<SfxCftTargetBuffer*>(
    reinterpret_cast<std::uint8_t*>(outTarget) + (0x10 * (recordIndex + 1))
  );
  nextRecord->planeCount = (outputBufferWidth != 0) ? outputBufferWidth : frameInfo->cachedWidth;
  return outputBufferWidth;
}

/**
 * Address: 0x00ACED60 (FUN_00ACED60, _SFX_Make1PlaneCftDstBuf)
 *
 * What it does:
 * Applies the clip rectangle and builds the single-plane destination
 * descriptor the ARGB converters write into.
 */
std::int32_t SFX_Make1PlaneCftDstBuf(
  moho_cri_sfx_internal::SfxHandle* const handle,
  MwsfdSfxFrameInfo* const frameInfo,
  const std::int32_t pixels,
  moho_cri_sfx_internal::SfxCftTargetBuffer* const outTarget,
  const std::int32_t left,
  const std::int32_t top,
  const std::int32_t width,
  const std::int32_t height
)
{
  SFX_SetClipping(handle, frameInfo, left, top, width, height);
  const std::int32_t result = sfxcnv_MakeDstBufInf(handle, frameInfo, pixels, outTarget, 0);
  outTarget->planeCount = 1;
  return result;
}

/**
 * Address: 0x00ACCA80 (FUN_00ACCA80, _SFX_GetForceSplitField)
 *
 * What it does:
 * Reports the library-wide override that suppresses field merging.
 */
std::int32_t SFX_GetForceSplitField()
{
  return moho_cri_sfx_internal::sfxcnv_forcesplit;
}

// SFX_GetSplitField: already recovered in SofdecAdxPlatformRuntime.cpp against its own
// SfxHandleSettingsView; this chain calls that definition rather than adding a
// second one with the same C linkage.

// SFX_GetProgOut: already recovered in SofdecAdxPlatformRuntime.cpp against its own
// SfxHandleSettingsView; this chain calls that definition rather than adding a
// second one with the same C linkage.

/**
 * Address: 0x00ACD290 (FUN_00ACD290, _SUD_AnalyTypeDivField)
 *
 * IDA signature:
 * BOOL __cdecl SUD_AnalyTypeDivField(int a1, int a2);
 *
 * What it does:
 * Reports whether a SUD record describes a divided-field stream, which it does
 * by matching the first character of the type string in the record.
 */
std::int32_t SUD_AnalyTypeDivField(const std::int32_t sudRecordAddress, const std::int32_t sudFieldIndex)
{
  using namespace moho_cri_sfx_internal;

  if (sudRecordAddress == 0 || sudFieldIndex < 0) {
    return 0;
  }

  const auto* const typeString = reinterpret_cast<const char*>(
    static_cast<std::uintptr_t>(static_cast<std::uint32_t>(sudRecordAddress)) + kSudTypeStringOffset
  );
  return std::strncmp(typeString, kSudDivFieldTypeTag, 1) == 0 ? 1 : 0;
}

/**
 * Address: 0x00ACE3C0 (FUN_00ACE3C0, _SFX_IsMergeField)
 *
 * IDA signature:
 * BOOL __cdecl SFX_IsMergeField(int a1, int a2);
 *
 * What it does:
 * Decides whether the two fields of one frame are to be merged into a single
 * destination rectangle. An explicit per-handle request wins; the seeded -1
 * defers to the stream, where a divided-field SUD record merges only when
 * progressive output was not asked for.
 */
std::int32_t SFX_IsMergeField(
  const moho_cri_sfx_internal::SfxHandle* const handle, const MwsfdSfxFrameInfo* const frameInfo
)
{
  if (SFX_GetForceSplitField() == 1) {
    return 0;
  }

  const std::int32_t splitField = SFX_GetSplitField(const_cast<moho_cri_sfx_internal::SfxHandle*>(handle));
  if (splitField != -1) {
    return (splitField == 1) ? 1 : 0;
  }

  const std::int32_t sudRecordAddress = frameInfo->constrainedParametersFlag;
  if (sudRecordAddress != 0 && SUD_AnalyTypeDivField(sudRecordAddress, frameInfo->progressiveSequence) != 0) {
    return (SFX_GetProgOut(const_cast<moho_cri_sfx_internal::SfxHandle*>(handle)) == 0) ? 1 : 0;
  }

  return 0;
}

/**
 * Address: 0x00ACCD50 (FUN_00ACCD50, _SFX_SetOutBufSize)
 *
 * IDA signature:
 * int __cdecl SFX_SetOutBufSize(int a1, int a2, int a3);
 *
 * What it does:
 * Records the destination surface dimensions on the handle. The width becomes
 * the pitch `sfxcnv_MakeDstBufInf` hands the converters when it is non-zero,
 * which is how a caller makes them write into a surface wider than the frame.
 *
 * The parameter is spelled `void*` to match the declaration
 * SofdecFoundationRuntime.cpp already publishes for MWSFSFX_SetOutBufSize.
 */
void SFX_SetOutBufSize(void* const sfxHandle, const std::int32_t outputPitch, const std::int32_t outputHeight)
{
  auto* const handle = static_cast<moho_cri_sfx_internal::SfxHandle*>(sfxHandle);
  handle->outputBufferWidth = outputPitch;
  handle->outputBufferHeight = outputHeight;
}

/**
 * Address: 0x00ACCD90 (FUN_00ACCD90, _SFX_SetUnitWidth)
 *
 * IDA signature:
 * int __cdecl SFX_SetUnitWidth(int a1, int a2);
 *
 * What it does:
 * Records the destination pixel unit-width on the handle, matching
 * `SFX_SetOutBufSize`'s parameter spelling for the same reason (the
 * declaration `SofdecFoundationRuntime.cpp` publishes for
 * `MWSFSFX_SetOutBufSize`, which calls this with the handle it resolved from
 * `MWSFSFX_GetSfxHn`). Previously a no-argument stub in
 * `SofdecExternalStubs.cpp` that silently discarded both arguments.
 */
void SFX_SetUnitWidth(void* const sfxHandle, const std::int32_t unitWidth)
{
  static_cast<moho_cri_sfx_internal::SfxHandle*>(sfxHandle)->unitWidth = unitWidth;
}

/**
 * Address: 0x00ACCD70 (FUN_00ACCD70, _SFX_GetOutBufSize)
 *
 * What it does:
 * Reads back the output-buffer dimensions set by `SFX_SetOutBufSize`.
 */
std::int32_t SFX_GetOutBufSize(
  const moho_cri_sfx_internal::SfxHandle* const handle, std::int32_t* const outWidth, std::int32_t* const outHeight
)
{
  *outWidth = handle->outputBufferWidth;
  *outHeight = handle->outputBufferHeight;
  return handle->outputBufferHeight;
}

/**
 * Address: 0x00ACEE30 (FUN_00ACEE30, _SFX_CnvFrmAndMargFieldByCbFunc)
 *
 * What it does:
 * Converts an interlaced frame as two half-height passes woven into one
 * destination rectangle: the first field fills one set of rows, then the plane
 * pointers advance by half a frame and the second pass fills from the next row
 * down. The doubled width handed to `SFX_SetOutBufSize` is what leaves a whole
 * row of gap between the output rows of the two passes.
 */
std::int32_t SFX_CnvFrmAndMargFieldByCbFunc(
  moho_cri_sfx_internal::SfxHandle* const handle,
  MwsfdSfxFrameInfo* const frameInfo,
  moho_cri_sfx_internal::SfxCftTargetBuffer* const target
)
{
  const std::int32_t fullHeight = frameInfo->cachedHeight;

  std::int32_t outputBufferWidth = 0;
  std::int32_t outputBufferHeight = 0;
  (void)SFX_GetOutBufSize(handle, &outputBufferWidth, &outputBufferHeight);

  SFX_SetOutBufSize(handle, 2 * outputBufferWidth, fullHeight);
  frameInfo->cachedHeight /= 2;
  (void)SFX_SetMaxRowToYccPln(frameInfo, fullHeight / 2);
  (void)SFX_Make1PlaneCftDstBuf(
    handle, frameInfo, target->pixels, target, 0, 0, frameInfo->cachedWidth, frameInfo->cachedHeight
  );
  SFX_CnvFrmByCbFunc(
    reinterpret_cast<moho::SfxCallbackFrameContext*>(handle),
    reinterpret_cast<moho::SfxStreamState*>(frameInfo),
    static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(target))
  );

  SFX_SetOutBufSize(handle, 2 * outputBufferWidth, fullHeight);
  (void)SFX_SetMaxRowToYccPln(frameInfo, fullHeight);
  SFX_ShiftYccPtrByLine(frameInfo, fullHeight / 2);

  target->pixels += outputBufferWidth;
  (void)SFX_Make1PlaneCftDstBuf(
    handle, frameInfo, target->pixels, target, 0, 0, frameInfo->cachedWidth, frameInfo->cachedHeight
  );
  SFX_CnvFrmByCbFunc(
    reinterpret_cast<moho::SfxCallbackFrameContext*>(handle),
    reinterpret_cast<moho::SfxStreamState*>(frameInfo),
    static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(target))
  );
  return 0;
}

/**
 * Address: 0x00ADE110 (FUN_00ADE110, _SFX_CnvFrmARGB8888ByCbFunc)
 *
 * IDA signature:
 * int __cdecl SFX_CnvFrmARGB8888ByCbFunc(int a1, int a2, _DWORD *a3);
 *
 * What it does:
 * Installs the ARGB8888 family of conversion callbacks on the handle and runs
 * the frame through whichever field strategy the stream calls for. The plain
 * converter is used when the frame reports a single chroma-position lane;
 * otherwise the colour-adjust table base is armed and the progressive or
 * interlaced variant is chosen from the picture detail on the frame.
 *
 * The four table-building callbacks are only address-taken here; they run
 * later, from `SFX_MakeTable`.
 */
std::int32_t SFX_CnvFrmARGB8888ByCbFunc(
  moho_cri_sfx_internal::SfxHandle* const handle,
  MwsfdSfxFrameInfo* const frameInfo,
  moho_cri_sfx_internal::SfxCftTargetBuffer* const target
)
{
  using namespace moho_cri_sfx_internal;

  handle->tableBase = 0;

  SfxCnvFrmCallback conversion = &CFT_Ycc420plnToArgb8888;
  if (frameInfo->chromaPosLo != 1) {
    handle->tableBase = handle->planeBase + kSfxColorAdjustTableOffset;
    conversion = (frameInfo->pictureDetail68 == 1) ? &CFT_Ycc420plnToArgb8888Prg : &CFT_Ycc420plnToArgb8888Int;
  }

  (void)SFX_SetCnvFrmCbFunc(handle, conversion);
  (void)SFX_SetCopyAlphaCbFunc(handle, &CFT_Ycc420plnToA256V);
  (void)SFX_SetMakeLumiTableCbFunc(handle, &CFT_MakeArgb8888AlpLumiTbl);
  (void)SFX_SetMakeAlp3TableCbFunc(handle, &CFT_MakeArgb8888Alp3211Tbl);
  (void)SFX_SetMakeAlp3110TableCbFunc(handle, &CFT_MakeArgb8888Alp3110Tbl);
  (void)SFX_SetMakeColAdjTableCbFunc(handle, &CFT_MakeArgb8888ColAdjTbl);

  if (SFX_IsMergeField(handle, frameInfo) == 1) {
    return SFX_CnvFrmAndMargFieldByCbFunc(handle, frameInfo, target);
  }

  SFX_CnvFrmByCbFunc(
    reinterpret_cast<moho::SfxCallbackFrameContext*>(handle),
    reinterpret_cast<moho::SfxStreamState*>(frameInfo),
    static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(target))
  );
  return 0;
}

/**
 * Address: 0x00ACC710 (FUN_00ACC710, _mwPlyFxCnvFrmClipARGB8888)
 *
 * IDA signature:
 * int __cdecl mwPlyFxCnvFrmClipARGB8888(MWPLY a1, MwsfdFrmObj *a2, int a3,
 *                                       int a4, int a5, int a6, int a7);
 *
 * What it does:
 * Converts the clip rectangle of one decoded frame into ARGB8888 pixels in the
 * caller buffer. The frame descriptor is translated into the SFX-side info
 * block on the stack, the destination descriptor is built from the clip
 * rectangle, and the ARGB dispatcher does the rest.
 */
void mwPlyFxCnvFrmClipARGB8888(
  moho::MwsfdPlaybackStateSubobj* const ply,
  MwsfdSfdFrmObj* const frm,
  void* const outputBits,
  const std::int32_t left,
  const std::int32_t top,
  const std::int32_t width,
  const std::int32_t height
)
{
  using namespace moho_cri_sfx_internal;

  auto* const handle = static_cast<SfxHandle*>(MWSFSFX_GetSfxHn(ply));

  MwsfdSfxFrameInfo frameInfo{};
  (void)MWSFSFX_CnvFrmInfToSfx(ply, frm, &frameInfo);

  SfxCftTargetBuffer target{};
  (void)SFX_Make1PlaneCftDstBuf(
    handle,
    &frameInfo,
    static_cast<std::int32_t>(reinterpret_cast<std::uintptr_t>(outputBits)),
    &target,
    left,
    top,
    width,
    height
  );

  (void)SFX_CnvFrmARGB8888ByCbFunc(handle, &frameInfo, &target);
}

/**
 * Address: 0x00ACC6E0 (FUN_00ACC6E0, _mwPlyFxCnvFrmARGB8888)
 *
 * IDA signature:
 * int __cdecl mwPlyFxCnvFrmARGB8888(MWPLY a1, MwsfdFrmObj *a2, int a3);
 *
 * What it does:
 * Converts one whole decoded frame to ARGB8888 - the unclipped form of the
 * call above, with the clip rectangle set to the frame dimensions.
 * `CMovie::UploadCurrentFrameToTexture` calls this with a locked texture
 * surface; while it was an empty stub the surface was locked, left untouched
 * and unlocked, so every frame arrived transparent black.
 */
void mwPlyFxCnvFrmARGB8888(
  moho::MwsfdPlaybackStateSubobj* const ply, const moho::MwsfdFrameInfo* const frameObject, void* const outputBits
)
{
  // The parameter type comes from the declaration CMovie.cpp calls through;
  // `moho::MwsfdFrameInfo` and `MwsfdSfdFrmObj` model the same SFD frame
  // descriptor, and only the latter names the plane geometry this needs.
  auto* const frm = const_cast<MwsfdSfdFrmObj*>(reinterpret_cast<const MwsfdSfdFrmObj*>(frameObject));
  mwPlyFxCnvFrmClipARGB8888(ply, frm, outputBits, 0, 0, frm->planeWidth, frm->planeHeight);
}
