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
using SfxCnvFrmCallback = void(__cdecl*)(const std::int32_t* source, const std::int32_t* target, const std::int32_t* tableParams);
using SfxCopyAlphaCallback = void(__cdecl*)(const std::int32_t* source, const std::int32_t* target, const std::int32_t* tableParams);
using SfxMakeTableCallback = void(__cdecl*)(std::int32_t tableBase, std::int32_t param);

struct SfxHandle {
  std::int32_t used;          ///< +0x00 set to 1 by sfx_InitHn
  std::int32_t reserved04;    ///< +0x04
  std::int32_t reserved08;    ///< +0x08
  std::int32_t reserved0C;    ///< +0x0C
  std::uint8_t mUnknown10[0x14]; ///< +0x10
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
  SfxMakeTableCallback colorAdjustTableCallback; ///< +0x70
  std::uint8_t mUnknown74[0x20]; ///< +0x74
};

static_assert(sizeof(SfxHandle) == 0x94, "SfxHandle size must be 0x94");
static_assert(offsetof(SfxHandle, sfxz) == 0x24, "SfxHandle::sfxz must live at offset 0x24");
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
  std::int32_t  reserved10;      ///< +0x10
  std::int32_t  cirFx;           ///< +0x14 CCIR matrix selector
  SfxHandle     objs[kSfxHandlePoolSize]; ///< +0x18, stride 0x94
};

static_assert(offsetof(SfxLibWorkHead, objs) == 0x18,
              "SfxLibWorkHead::objs must live at offset 0x18");

static_assert(offsetof(SfxLibWorkHead, last) == 0x04,
              "SfxLibWorkHead::last must live at offset 0x04");
static_assert(offsetof(SfxLibWorkHead, errFn) == 0x08,
              "SfxLibWorkHead::errFn must live at offset 0x08");
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
