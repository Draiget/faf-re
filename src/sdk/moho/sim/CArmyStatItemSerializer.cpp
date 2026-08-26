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
    archive->Write(
      CachedType<moho::StatItem>(gStatItemType),
      const_cast<moho::StatItem*>(static_cast<const moho::StatItem*>(object)),
      owner
    );
    archive->Write(CachedType<moho::ArmyBlueprintStatTree>(gBlueprintStatsType), &object->mBlueprintStats, owner);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00BDA120 (FUN_00BDA120, dynamic initializer for the global
   * `CArmyStatItemSerializer` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields.
   */
  CArmyStatItemSerializer::CArmyStatItemSerializer()
    : mLoadCallback(&CArmyStatItemSerializer::Deserialize)
    , mSaveCallback(&CArmyStatItemSerializer::Serialize)
  {}

  /**
   * Address: 0x00BFF730 (FUN_00BFF730, atexit target registered by the real
   * ctor above)
   */
  CArmyStatItemSerializer::~CArmyStatItemSerializer()
  {
    ResetLinks();
  }

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
   * Address: 0x0070EEE0 (FUN_0070EEE0, gpg::SerSaveLoadHelper_CArmyStatItem::Init)
   *
   * IDA signature:
   * void (__cdecl *__thiscall sub_70EEE0(void (__cdecl **this)(...)))(...);
   */
  void CArmyStatItemSerializer::Init()
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
  // Address: 0x010B8F8C -- process-global `CArmyStatItemSerializer` singleton.
  moho::CArmyStatItemSerializer gCArmyStatItemSerializer;
} // namespace
