#include "moho/sim/CArmyStatItemSerializer.h"

#include <typeinfo>

#include "moho/sim/CArmyStats.h"

namespace
{
  template <class TObject>
  [[nodiscard]] gpg::RType* CachedType(gpg::RType*& slot)
  {
    if (!slot) {
      slot = gpg::LookupRType(typeid(TObject));
    }
    return slot;
  }

  gpg::RType* gStatItemType = nullptr;
  gpg::RType* gBlueprintStatsType = nullptr;
  moho::CArmyStatItemSerializer gCArmyStatItemSerializer;
} // namespace

namespace moho
{
  /**
   * Address: 0x0070B770 (FUN_0070B770, sub_70B770)
   */
  void CArmyStatItemSerializer::Deserialize(
    gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const ownerRef
  )
  {
    auto* const object = reinterpret_cast<CArmyStatItem*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(object != nullptr);
    if (!archive || !object) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    archive->Read(CachedType<StatItem>(gStatItemType), static_cast<StatItem*>(object), owner);
    archive->Read(CachedType<ArmyBlueprintStatTree>(gBlueprintStatsType), &object->mBlueprintStats, owner);
  }

  /**
   * Address: 0x0070B780 (FUN_0070B780, sub_70B780)
   */
  void CArmyStatItemSerializer::Serialize(
    gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const ownerRef
  )
  {
    auto* const object = reinterpret_cast<CArmyStatItem*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(object != nullptr);
    if (!archive || !object) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    archive->Write(CachedType<StatItem>(gStatItemType), static_cast<StatItem*>(object), owner);
    archive->Write(CachedType<ArmyBlueprintStatTree>(gBlueprintStatsType), &object->mBlueprintStats, owner);
  }

  /**
   * Address: 0x00BDA120 (FUN_00BDA120, sub_BDA120)
   *
   * What it does:
   * Initializes `CArmyStatItem` serializer helper callback slots and registers
   * them into reflected RTTI.
   */
  void register_CArmyStatItemSerializer()
  {
    gCArmyStatItemSerializer.mHelperNext = nullptr;
    gCArmyStatItemSerializer.mHelperPrev = nullptr;
    gCArmyStatItemSerializer.mLoadCallback = &CArmyStatItemSerializer::Deserialize;
    gCArmyStatItemSerializer.mSaveCallback = &CArmyStatItemSerializer::Serialize;
    gCArmyStatItemSerializer.RegisterSerializeFunctions();
  }

  /**
   * Address: 0x0070EEE0 (FUN_0070EEE0, gpg::SerSaveLoadHelper_CArmyStatItem::Init)
   *
   * IDA signature:
   * void (__cdecl *__thiscall sub_70EEE0(void (__cdecl **this)(...)))(...);
   */
  void CArmyStatItemSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CArmyStatItem::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho

namespace
{
  struct CArmyStatItemSerializerBootstrap
  {
    CArmyStatItemSerializerBootstrap()
    {
      moho::register_CArmyStatItemSerializer();
    }
  };

  CArmyStatItemSerializerBootstrap gCArmyStatItemSerializerBootstrap;
} // namespace
