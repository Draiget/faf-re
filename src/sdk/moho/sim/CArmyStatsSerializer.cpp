#include "moho/sim/CArmyStatsSerializer.h"

#include <cstdint>
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

  struct ArmyNameIndexMapRuntime
  {
    std::uint32_t meta0;
    moho::ArmyNameIndexNode* head;
    std::uint32_t size;
  };
  static_assert(sizeof(ArmyNameIndexMapRuntime) == 0x0C, "ArmyNameIndexMapRuntime size must be 0x0C");

  struct ArmyTriggerListRuntime
  {
    void* proxy;
    moho::ArmyAuxListNode* head;
    std::uint32_t size;
  };
  static_assert(sizeof(ArmyTriggerListRuntime) == 0x0C, "ArmyTriggerListRuntime size must be 0x0C");

  [[nodiscard]] ArmyNameIndexMapRuntime* NameIndexView(moho::CArmyStats* const object)
  {
    return reinterpret_cast<ArmyNameIndexMapRuntime*>(&object->mNameIndex);
  }

  [[nodiscard]] ArmyTriggerListRuntime* TriggerListView(moho::CArmyStats* const object)
  {
    return reinterpret_cast<ArmyTriggerListRuntime*>(&object->mNameIndex.metaC);
  }

  gpg::RType* gArmyStatsBaseType = nullptr;
  gpg::RType* gArmyNameIndexType = nullptr;
  gpg::RType* gArmyTriggerListType = nullptr;
  moho::CArmyStatsSerializer gCArmyStatsSerializer;
} // namespace

namespace moho
{
  /**
   * Address: 0x0070E1F0 (FUN_0070E1F0, Moho::CArmyStatsSerializer::Deserialize)
   */
  void CArmyStatsSerializer::Deserialize(
    gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const ownerRef
  )
  {
    auto* const object = reinterpret_cast<CArmyStats*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(object != nullptr);
    if (!archive || !object) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    archive->Read(CachedType<Stats<CArmyStatItem>>(gArmyStatsBaseType), static_cast<Stats<CArmyStatItem>*>(object), owner);
    archive->Read(CachedType<ArmyNameIndexMapRuntime>(gArmyNameIndexType), NameIndexView(object), owner);
    archive->Read(CachedType<ArmyTriggerListRuntime>(gArmyTriggerListType), TriggerListView(object), owner);
  }

  /**
   * Address: 0x0070E200 (FUN_0070E200, Moho::CArmyStatsSerializer::Serialize)
   */
  void CArmyStatsSerializer::Serialize(
    gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const ownerRef
  )
  {
    auto* const object = reinterpret_cast<CArmyStats*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(object != nullptr);
    if (!archive || !object) {
      return;
    }

    const gpg::RRef owner = ownerRef ? *ownerRef : gpg::RRef{};
    archive->Write(CachedType<Stats<CArmyStatItem>>(gArmyStatsBaseType), static_cast<Stats<CArmyStatItem>*>(object), owner);
    archive->Write(CachedType<ArmyNameIndexMapRuntime>(gArmyNameIndexType), NameIndexView(object), owner);
    archive->Write(CachedType<ArmyTriggerListRuntime>(gArmyTriggerListType), TriggerListView(object), owner);
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
