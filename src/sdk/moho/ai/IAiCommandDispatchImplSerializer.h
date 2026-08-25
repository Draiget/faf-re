#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1B408
   * COL:  0x00E70384
   */
  class IAiCommandDispatchImplSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x005993C0 (FUN_005993C0, Moho::IAiCommandDispatchImplSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive loading into `IAiCommandDispatchImpl::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005993D0 (FUN_005993D0, Moho::IAiCommandDispatchImplSerializer::Serialize)
     *
     * What it does:
     * Forwards archive saving into `IAiCommandDispatchImpl::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00BCBF00 (FUN_00BCBF00, dynamic initializer for the global
     * `IAiCommandDispatchImplSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this` and
     * splices it into the process-global `sNewHelpers` pending list), then
     * binds the load/save callback fields. Confirmed from raw disassembly:
     * calls `gpg::SerHelperBase::SerHelperBase()` directly, then installs
     * `??_7IAiCommandDispatchImplSerializer@Moho@@6B@` -- no eager `Init()`
     * call exists here.
     */
    IAiCommandDispatchImplSerializer();

    /**
     * Address: 0x00BF66F0 (FUN_00BF66F0, ??1IAiCommandDispatchImplSerializer@Moho@@QAE@@Z)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~IAiCommandDispatchImplSerializer();

    /**
     * Address: 0x005996D0 (FUN_005996D0)
     *
     * What it does:
     * Binds load/save serializer callbacks into IAiCommandDispatchImpl RTTI.
     * Dispatched by `gpg::SerHelperBase::InitNewHelpers` when this helper is
     * drained from the pending list (vtable slot 0).
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(IAiCommandDispatchImplSerializer, mLoadCallback) == 0x0C,
    "IAiCommandDispatchImplSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(IAiCommandDispatchImplSerializer, mSaveCallback) == 0x10,
    "IAiCommandDispatchImplSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(IAiCommandDispatchImplSerializer) == 0x14, "IAiCommandDispatchImplSerializer size must be 0x14");

  /**
   * Address: 0x00BCBF40 (FUN_00BCBF40, register_IAiCommandDispatchImplStartupStatsCleanup)
   *
   * What it does:
   * Registers an atexit cleanup thunk for one startup-owned engine-stats slot.
   */
  int register_IAiCommandDispatchImplStartupStatsCleanup();
} // namespace moho
