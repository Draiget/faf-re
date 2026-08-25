#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1ED54
   * COL:  0x00E76220
   */
  class CAiTargetSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BCEC50 (FUN_00BCEC50, dynamic initializer for the global
     * `CAiTargetSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this`
     * and splices it into the process-global `sNewHelpers` pending list),
     * then binds the load/save callback fields. Confirmed from raw
     * disassembly: calls `gpg::SerHelperBase::SerHelperBase()` directly,
     * then installs `??_7CAiTargetSerializer@Moho@@6B@` -- no eager
     * `Init()` call exists here.
     */
    CAiTargetSerializer();

    /**
     * Address: 0x005E2E60 (FUN_005E2E60, Moho::CAiTargetSerializer::~CAiTargetSerializer)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~CAiTargetSerializer();

    /**
     * Address: 0x005E3540 (FUN_005E3540, gpg::SerSaveLoadHelper_CAiTarget::Init)
     *
     * What it does:
     * Binds load/save serializer callbacks into CAiTarget RTTI. Dispatched
     * by `gpg::SerHelperBase::InitNewHelpers` when this helper is drained
     * from the pending list (vtable slot 0).
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(CAiTargetSerializer, mLoadCallback) == 0x0C, "CAiTargetSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CAiTargetSerializer, mSaveCallback) == 0x10, "CAiTargetSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CAiTargetSerializer) == 0x14, "CAiTargetSerializer size must be 0x14");
} // namespace moho
