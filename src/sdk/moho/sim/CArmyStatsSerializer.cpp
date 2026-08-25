#include "moho/sim/CArmyStatsSerializer.h"

#include "moho/sim/CArmyStats.h"

namespace
{
  // Address: 0x010B8FB4 -- process-global `CArmyStatsSerializer` singleton.
  moho::CArmyStatsSerializer gCArmyStatsSerializer;
} // namespace

namespace moho
{
  /**
   * Address: 0x0070E1F0 (FUN_0070E1F0, Moho::CArmyStatsSerializer::Deserialize)
   *
   * What it does:
   * Reflection load callback that forwards archive-load flow into
   * `CArmyStats::MemberDeserialize`.
   */
  void CArmyStatsSerializer::Deserialize(
    gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const)
  {
    auto* const object = reinterpret_cast<CArmyStats*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(object != nullptr);
    if (!archive || !object) {
      return;
    }

    object->MemberDeserialize(archive);
  }

  /**
   * Address: 0x0070E200 (FUN_0070E200, Moho::CArmyStatsSerializer::Serialize)
   *
   * What it does:
   * Reflection save callback that forwards archive-save flow into
   * `CArmyStats::MemberSerialize`.
   */
  void CArmyStatsSerializer::Serialize(
    gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const)
  {
    auto* const object = reinterpret_cast<CArmyStats*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(object != nullptr);
    if (!archive || !object) {
      return;
    }

    object->MemberSerialize(archive);
  }

  /**
   * Address: 0x00BDA210 (FUN_00BDA210, register_CArmyStatsSerializer)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields.
   */
  CArmyStatsSerializer::CArmyStatsSerializer()
    : mLoadCallback(&CArmyStatsSerializer::Deserialize)
    , mSaveCallback(&CArmyStatsSerializer::Serialize)
  {}

  /**
   * Address: 0x00BFF850 (FUN_00BFF850, Moho::CArmyStatsSerializer::~CArmyStatsSerializer)
   */
  CArmyStatsSerializer::~CArmyStatsSerializer()
  {
    ResetLinks();
  }

  /**
   * Address: 0x0070F5E0 (FUN_0070F5E0, gpg::SerSaveLoadHelper_CArmyStats::Init)
   *
   * IDA signature:
   * void (__cdecl *__thiscall sub_70F5E0(void (__cdecl **this)(...)))(...);
   */
  void CArmyStatsSerializer::Init()
  {
    gpg::RType* const type = CArmyStats::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho
