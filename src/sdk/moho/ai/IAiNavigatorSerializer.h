#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1C068
   * COL:  0x00E71870
   */
  class IAiNavigatorSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x005A32D0 (FUN_005A32D0, Moho::IAiNavigatorSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive loading into `IAiNavigator::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005A32E0 (FUN_005A32E0, Moho::IAiNavigatorSerializer::Serialize)
     *
     * What it does:
     * Forwards archive saving into `IAiNavigator::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00BCC6C0 (FUN_00BCC6C0, dynamic initializer for the global
     * `IAiNavigatorSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this` and
     * splices it into the process-global `sNewHelpers` pending list), then
     * binds the load/save callback fields. Confirmed from raw disassembly:
     * calls `gpg::SerHelperBase::SerHelperBase()` directly, then installs
     * `??_7IAiNavigatorSerializer@Moho@@6B@` -- no eager `Init()` call
     * exists here.
     */
    IAiNavigatorSerializer();

    /**
     * Address: 0x00BF6D60 (FUN_00BF6D60, ??1IAiNavigatorSerializer@Moho@@QAE@@Z)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~IAiNavigatorSerializer();

    /**
     * Address: 0x005A71A0 (FUN_005A71A0)
     *
     * What it does:
     * Binds load/save serializer callbacks into IAiNavigator RTTI. Dispatched
     * by `gpg::SerHelperBase::InitNewHelpers` when this helper is drained
     * from the pending list (vtable slot 0).
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(IAiNavigatorSerializer, mLoadCallback) == 0x0C,
    "IAiNavigatorSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(IAiNavigatorSerializer, mSaveCallback) == 0x10,
    "IAiNavigatorSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(IAiNavigatorSerializer) == 0x14, "IAiNavigatorSerializer size must be 0x14");
} // namespace moho
