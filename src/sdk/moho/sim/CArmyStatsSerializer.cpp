#include "moho/sim/CArmyStatsSerializer.h"

#include <cstdlib>

#include "moho/sim/CArmyStats.h"

namespace
{
  moho::CArmyStatsSerializer gCArmyStatsSerializer;

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* HelperSelfNode(THelper& helper) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&helper.mHelperNext);
  }

  template <typename THelper>
  void InitializeHelperNode(THelper& helper) noexcept
  {
    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperNext = self;
    helper.mHelperPrev = self;
  }

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* UnlinkHelperNode(THelper& helper) noexcept
  {
    if (helper.mHelperNext != nullptr && helper.mHelperPrev != nullptr) {
      helper.mHelperNext->mPrev = helper.mHelperPrev;
      helper.mHelperPrev->mNext = helper.mHelperNext;
    }

    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperPrev = self;
    helper.mHelperNext = self;
    return self;
  }

  void CleanupCArmyStatsSerializerAtexit()
  {
    (void)UnlinkHelperNode(gCArmyStatsSerializer);
  }
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
    InitializeHelperNode(gCArmyStatsSerializer);
    gCArmyStatsSerializer.mLoadCallback = &CArmyStatsSerializer::Deserialize;
    gCArmyStatsSerializer.mSaveCallback = &CArmyStatsSerializer::Serialize;
    (void)std::atexit(&CleanupCArmyStatsSerializerAtexit);
  }

  /**
   * Address: 0x0070E240 (FUN_0070E240)
   *
   * What it does:
   * Duplicated teardown lane for `CArmyStatsSerializer` helper links.
   */
  gpg::SerHelperBase* cleanup_CArmyStatsSerializer_variant_primary()
  {
    return UnlinkHelperNode(gCArmyStatsSerializer);
  }

  /**
   * Address: 0x0070E270 (FUN_0070E270)
   *
   * What it does:
   * Secondary duplicated teardown lane for `CArmyStatsSerializer` helper
   * links.
   */
  gpg::SerHelperBase* cleanup_CArmyStatsSerializer_variant_secondary()
  {
    return UnlinkHelperNode(gCArmyStatsSerializer);
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
