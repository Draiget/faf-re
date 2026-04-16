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

  /**
   * Address: 0x00714750 (FUN_00714750)
   *
   * What it does:
   * Deserializes one `CArmyStatItem` lane by loading `StatItem` base state and
   * the blueprint-weight map payload.
   */
  void DeserializeCArmyStatItemSerializerBody(moho::CArmyStatItem* const object, gpg::ReadArchive* const archive)
  {
    if (!archive || !object) {
      return;
    }

    const gpg::RRef owner{};
    archive->Read(CachedType<moho::StatItem>(gStatItemType), static_cast<moho::StatItem*>(object), owner);
    archive->Read(CachedType<moho::ArmyBlueprintStatTree>(gBlueprintStatsType), &object->mBlueprintStats, owner);
  }

  /**
   * Address: 0x00712560 (FUN_00712560)
   *
   * What it does:
   * Thin jump-thunk alias to `FUN_00714750` deserialize body.
   */
  [[maybe_unused]] void DeserializeCArmyStatItemSerializerBodyThunkA(
    moho::CArmyStatItem* const object,
    gpg::ReadArchive* const archive
  )
  {
    DeserializeCArmyStatItemSerializerBody(object, archive);
  }

  /**
   * Address: 0x007134A0 (FUN_007134A0)
   *
   * What it does:
   * Secondary jump-thunk alias to `FUN_00714750` deserialize body.
   */
  [[maybe_unused]] void DeserializeCArmyStatItemSerializerBodyThunkB(
    moho::CArmyStatItem* const object,
    gpg::ReadArchive* const archive
  )
  {
    DeserializeCArmyStatItemSerializerBody(object, archive);
  }

  /**
   * Address: 0x007147D0 (FUN_007147D0)
   *
   * What it does:
   * Serializes one `CArmyStatItem` lane by saving `StatItem` base state and
   * the blueprint-weight map payload.
   */
  void SerializeCArmyStatItemSerializerBody(const moho::CArmyStatItem* const object, gpg::WriteArchive* const archive)
  {
    if (!archive || !object) {
      return;
    }

    const gpg::RRef owner{};
    archive->Write(CachedType<moho::StatItem>(gStatItemType), const_cast<moho::StatItem*>(static_cast<const moho::StatItem*>(object)), owner);
    archive->Write(CachedType<moho::ArmyBlueprintStatTree>(gBlueprintStatsType), &object->mBlueprintStats, owner);
  }

  /**
   * Address: 0x00712570 (FUN_00712570)
   *
   * What it does:
   * Thin jump-thunk alias to `FUN_007147D0` serialize body.
   */
  [[maybe_unused]] void SerializeCArmyStatItemSerializerBodyThunkA(
    const moho::CArmyStatItem* const object,
    gpg::WriteArchive* const archive
  )
  {
    SerializeCArmyStatItemSerializerBody(object, archive);
  }

  /**
   * Address: 0x007134B0 (FUN_007134B0)
   *
   * What it does:
   * Secondary jump-thunk alias to `FUN_007147D0` serialize body.
   */
  [[maybe_unused]] void SerializeCArmyStatItemSerializerBodyThunkB(
    const moho::CArmyStatItem* const object,
    gpg::WriteArchive* const archive
  )
  {
    SerializeCArmyStatItemSerializerBody(object, archive);
  }
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
    (void)ownerRef;
    auto* const object = reinterpret_cast<CArmyStatItem*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(object != nullptr);
    if (!archive || !object) {
      return;
    }
    DeserializeCArmyStatItemSerializerBody(object, archive);
  }

  /**
   * Address: 0x0070B780 (FUN_0070B780, sub_70B780)
   */
  void CArmyStatItemSerializer::Serialize(
    gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const ownerRef
  )
  {
    (void)ownerRef;
    auto* const object = reinterpret_cast<CArmyStatItem*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(object != nullptr);
    if (!archive || !object) {
      return;
    }
    SerializeCArmyStatItemSerializerBody(object, archive);
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
