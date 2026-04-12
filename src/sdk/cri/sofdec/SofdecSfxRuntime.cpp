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

/// Registers an error-callback with the SFX core. The callback receives a
/// context tag and an error-message string pointer. Returns an opaque status
/// code from the CRI error dispatcher.
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
void MWSFSVM_Error(const char* errorMessage);

// Lower-level SFX dependencies pulled in by `SFX_Init` and the SFX init
// chain. These remain externs because their bodies live in deeper SFX
// subsystems whose layouts are still being reconstructed; each is a thin
// init/dispatch entry point with no engine-visible side effects beyond the
// Sofdec library work area.

/// Selects the CCIR matrix variant used by the SFX colour pipeline. The
/// argument is a small enum-like selector (`1` = the standard CCIR-601
/// pipeline used by the Forged Alliance build).
void SFX_SetCcirFx(std::int32_t mode);

/// Initialises the CFT (Color Format Table) module. Pairs with the matching
/// teardown in the CFT runtime.
void CFT_Init();

/// SFXZ (depth/Z-blit) library work-area initialiser. Returns the CRI
/// success/error status of the underlying init.
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

/// Recovered head of the global SFX library work area. The first DWORD is
/// the dispatcher tag set by SFX_Init's callees; the second is the
/// `last` slot reset by `sfx_InitLibWork` to the cell-cap sentinel `32`.
struct SfxLibWorkHead {
  std::uint32_t dispatcher_tag;  ///< +0x00 (filled in by deeper SFX init)
  std::int32_t  last;            ///< +0x04 last-cell sentinel (= 32)
};

static_assert(offsetof(SfxLibWorkHead, last) == 0x04,
              "SfxLibWorkHead::last must live at offset 0x04");

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

extern "C" {

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
std::int32_t SFXA_Init()
{
  return sfxalp_InitLibWork();
}

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
void SFXSUD_Init()
{
  SUD_Init();
}

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

}  // extern "C"
