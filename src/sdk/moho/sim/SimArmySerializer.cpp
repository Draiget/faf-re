#include "moho/sim/SimArmySerializer.h"

#include "moho/sim/SimArmy.h"

namespace
{
  moho::SimArmySerializer gSimArmySerializer;
}

namespace moho
{
  /**
   * Address: 0x006FDB60 (FUN_006FDB60, Moho::SimArmySerializer::Deserialize)
   */
  void SimArmySerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    auto* const object = reinterpret_cast<SimArmy*>(objectPtr);
    if (!object || !archive) {
      return;
    }
    object->MemberDeserialize(archive);
  }

  /**
   * Address: 0x006FDB70 (FUN_006FDB70, Moho::SimArmySerializer::Serialize)
   */
  void SimArmySerializer::Serialize(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    auto* const object = reinterpret_cast<SimArmy*>(objectPtr);
    if (!object || !archive) {
      return;
    }
    object->MemberSerialize(archive);
  }

  /**
   * Address: 0x00701610 (FUN_00701610, gpg::SerSaveLoadHelper_SimArmy::Init)
   *
   * IDA signature:
   * void (__cdecl *__thiscall sub_701610(void (__cdecl **this)(...)))(...);
   */
  void SimArmySerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = SimArmy::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }

  /**
   * Address: 0x00BD9BC0 (FUN_00BD9BC0, register_SimArmySerializer)
   *
   * What it does:
   * Initializes the SimArmy serializer helper and binds it into the reflected
   * RTTI load/save callback lanes.
   */
  void register_SimArmySerializer()
  {
    gSimArmySerializer.mHelperNext = nullptr;
    gSimArmySerializer.mHelperPrev = nullptr;
    gSimArmySerializer.mLoadCallback = &SimArmySerializer::Deserialize;
    gSimArmySerializer.mSaveCallback = &SimArmySerializer::Serialize;
    gSimArmySerializer.RegisterSerializeFunctions();
  }
} // namespace moho

namespace
{
  struct SimArmySerializerBootstrap
  {
    SimArmySerializerBootstrap()
    {
      moho::register_SimArmySerializer();
    }
  };

  SimArmySerializerBootstrap gSimArmySerializerBootstrap;
} // namespace
