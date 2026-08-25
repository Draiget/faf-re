#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E0F988
   */
  class SEfxCurveSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC8440 (FUN_00BC8440, register_SEfxCurveSerializer)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this`
     * and splices it into the process-global `sNewHelpers` pending list) and
     * binds the load/save callback fields. Confirmed from raw disassembly:
     * calls `gpg::SerHelperBase::SerHelperBase()` directly, then installs
     * `??_7SEfxCurveSerializer@Moho@@6B@` -- no eager `Init()` call exists
     * here. The `push offset ~SEfxCurveSerializer; call _atexit` sequence
     * visible in the real ctor's tail is the compiler's own implicit
     * static-destructor registration for a global with a non-trivial
     * destructor (it pushes the mangled
     * `??1SEfxCurveSerializer@Moho@@QAE@@Z` symbol directly, not a call the
     * 2007 source wrote), so it is not reproduced explicitly here --
     * declaring a real destructor below is sufficient for the compiler to
     * emit the same registration.
     */
    SEfxCurveSerializer();

    /**
     * Address: 0x00BF29D0 (FUN_00BF29D0, Moho::SEfxCurveSerializer::~SEfxCurveSerializer)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~SEfxCurveSerializer();

    /**
     * Address: 0x00515B30 (FUN_00515B30, gpg::SerSaveLoadHelper_SEfxCurve::Init)
     *
     * IDA signature:
     * void __thiscall gpg::SerSaveLoadHelper_SEfxCurve::Init(_DWORD *this);
     *
     * What it does:
     * Binds `SEfxCurve` load/save archive callbacks into its RTTI descriptor.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(SEfxCurveSerializer, mLoadCallback) == 0x0C, "SEfxCurveSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(SEfxCurveSerializer, mSaveCallback) == 0x10, "SEfxCurveSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(SEfxCurveSerializer) == 0x14, "SEfxCurveSerializer size must be 0x14");
} // namespace moho
