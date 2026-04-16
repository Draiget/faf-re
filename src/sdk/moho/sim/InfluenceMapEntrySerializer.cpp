#include "moho/sim/InfluenceMapEntrySerializer.h"

#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CInfluenceMap.h"

namespace
{
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

  template <class TObject>
  [[nodiscard]] gpg::RType* CachedType(gpg::RType*& slot)
  {
    if (!slot) {
      slot = gpg::LookupRType(typeid(TObject));
    }
    return slot;
  }

  gpg::RType* gVec3fType = nullptr;
  moho::InfluenceMapEntrySerializer gInfluenceMapEntrySerializer;

  // Alias of FUN_007178F0 behavior from CInfluenceMap.cpp.
  void DeserializeInfluenceMapEntrySerializerBridge(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const ownerRef
  )
  {
    auto* const entry = reinterpret_cast<moho::InfluenceMapEntry*>(objectPtr);
    if (!archive || !entry) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    archive->ReadUInt(&entry->entityId);

    moho::SimArmy* sourceArmy = nullptr;
    archive->ReadPointer_SimArmy(&sourceArmy, &owner);
    entry->sourceArmy = static_cast<moho::CArmyImpl*>(sourceArmy);

    archive->Read(CachedType<Wm3::Vec3f>(gVec3fType), &entry->lastPosition, owner);

    moho::RUnitBlueprint* sourceBlueprint = nullptr;
    archive->ReadPointer_RUnitBlueprint(&sourceBlueprint, &owner);
    entry->sourceBlueprint = sourceBlueprint;

    int sourceLayer = 0;
    archive->ReadInt(&sourceLayer);
    entry->sourceLayer = sourceLayer;

    bool isDetailed = false;
    archive->ReadBool(&isDetailed);
    entry->isDetailed = isDetailed ? 1u : 0u;

    archive->ReadFloat(&entry->threatStrength);
    archive->ReadFloat(&entry->threatDecay);
    archive->ReadInt(&entry->decayTicks);
  }

  // Alias of FUN_00717900 behavior from CInfluenceMap.cpp.
  void SerializeInfluenceMapEntrySerializerBridge(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef* const ownerRef
  )
  {
    const auto* const entry = reinterpret_cast<const moho::InfluenceMapEntry*>(objectPtr);
    if (!archive || !entry) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    archive->WriteUInt(entry->entityId);

    gpg::RRef armyRef{};
    (void)gpg::RRef_SimArmy(&armyRef, static_cast<moho::SimArmy*>(entry->sourceArmy));
    gpg::WriteRawPointer(archive, armyRef, gpg::TrackedPointerState::Unowned, owner);

    archive->Write(CachedType<Wm3::Vec3f>(gVec3fType), const_cast<Wm3::Vec3f*>(&entry->lastPosition), owner);

    gpg::RRef blueprintRef{};
    (void)gpg::RRef_RUnitBlueprint(&blueprintRef, const_cast<moho::RUnitBlueprint*>(entry->sourceBlueprint));
    gpg::WriteRawPointer(archive, blueprintRef, gpg::TrackedPointerState::Unowned, owner);

    archive->WriteInt(entry->sourceLayer);
    archive->WriteBool(entry->isDetailed != 0u);
    archive->WriteFloat(entry->threatStrength);
    archive->WriteFloat(entry->threatDecay);
    archive->WriteInt(entry->decayTicks);
  }

  /**
   * Address: 0x00718BD0 (FUN_00718BD0)
   *
   * What it does:
   * Initializes startup `InfluenceMapEntry` helper links and callback slots.
   */
  [[maybe_unused]] [[nodiscard]] moho::InfluenceMapEntrySerializer* InitializeInfluenceMapEntrySerializerHelperStorage() noexcept
  {
    InitializeHelperNode(gInfluenceMapEntrySerializer);
    gInfluenceMapEntrySerializer.mLoadCallback = &DeserializeInfluenceMapEntrySerializerBridge;
    gInfluenceMapEntrySerializer.mSaveCallback = &SerializeInfluenceMapEntrySerializerBridge;
    return &gInfluenceMapEntrySerializer;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00718C00 (FUN_00718C00, gpg::SerSaveLoadHelper_InfluenceMapEntry::Init)
   *
   * IDA signature:
   * void __thiscall gpg::SerSaveLoadHelper_InfluenceMapEntry::Init(_DWORD *this);
   */
  void InfluenceMapEntrySerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = InfluenceMapEntry::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho

namespace
{
  struct InfluenceMapEntrySerializerBootstrap
  {
    InfluenceMapEntrySerializerBootstrap()
    {
      (void)InitializeInfluenceMapEntrySerializerHelperStorage();
    }
  };

  [[maybe_unused]] InfluenceMapEntrySerializerBootstrap gInfluenceMapEntrySerializerBootstrap;
} // namespace
