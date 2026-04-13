#include "moho/sim/CArmyStatsSerializer.h"

#include "moho/sim/CArmyStats.h"

namespace
{
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
   * Initializes `CArmyStats` serializer helper callback slots and registers
   * them into reflected RTTI.
   */
  void register_CArmyStatsSerializer()
  {
    gCArmyStatsSerializer.mHelperNext = nullptr;
    gCArmyStatsSerializer.mHelperPrev = nullptr;
    gCArmyStatsSerializer.mLoadCallback = &CArmyStatsSerializer::Deserialize;
    gCArmyStatsSerializer.mSaveCallback = &CArmyStatsSerializer::Serialize;
    gCArmyStatsSerializer.RegisterSerializeFunctions();
  }

  /**
   * Address: 0x0070F5E0 (FUN_0070F5E0, gpg::SerSaveLoadHelper_CArmyStats::Init)
   *
   * IDA signature:
   * void (__cdecl *__thiscall sub_70F5E0(void (__cdecl **this)(...)))(...);
   */
  void CArmyStatsSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CArmyStats::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho

namespace
{
  struct CArmyStatsSerializerBootstrap
  {
    CArmyStatsSerializerBootstrap()
    {
      moho::register_CArmyStatsSerializer();
    }
  };

  CArmyStatsSerializerBootstrap gCArmyStatsSerializerBootstrap;
} // namespace
