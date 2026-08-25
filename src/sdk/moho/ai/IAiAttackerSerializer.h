#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class IAiAttackerSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BCE7D0 (FUN_00BCE7D0, dynamic initializer for the global
     * `IAiAttackerSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this` and
     * splices it into the process-global `sNewHelpers` pending list), then
     * binds the load/save callback fields. Confirmed from raw disassembly:
     * calls `gpg::SerHelperBase::SerHelperBase()` directly, then installs
     * `??_7IAiAttackerSerializer@Moho@@6B@` -- no eager `Init()` call exists
     * here.
     */
    IAiAttackerSerializer();

    /**
     * Address: 0x005DE8D0 (FUN_005DE8D0, sub_5DE8D0)
     *
     * What it does:
     * Loads `IAiAttacker` broadcaster event-list lanes.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005DE920 (FUN_005DE920, sub_5DE920)
     *
     * What it does:
     * Saves `IAiAttacker` broadcaster event-list lanes.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005DBC90 (FUN_005DBC90)
     *
     * What it does:
     * Binds load/save serializer callbacks into IAiAttacker RTTI. Dispatched
     * by `gpg::SerHelperBase::InitNewHelpers` when this helper is drained
     * from the pending list (vtable slot 0).
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(IAiAttackerSerializer, mLoadCallback) == 0x0C, "IAiAttackerSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(IAiAttackerSerializer, mSaveCallback) == 0x10, "IAiAttackerSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(IAiAttackerSerializer) == 0x14, "IAiAttackerSerializer size must be 0x14");

  /**
   * Compatibility no-op: `IAiAttacker.cpp`'s reflection bootstrap sequence
   * still calls this by name. See the definition in IAiAttackerSerializer.cpp
   * for why it no longer needs to do anything.
   */
  int register_IAiAttackerSerializer();
} // namespace moho
