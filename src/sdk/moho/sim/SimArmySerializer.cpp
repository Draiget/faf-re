#include "moho/sim/SimArmySerializer.h"

#include <cstdlib>

#include "moho/sim/SimArmy.h"

namespace
{
  moho::SimArmySerializer gSimArmySerializer;

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

  void CleanupSimArmySerializerAtexit()
  {
    (void)UnlinkHelperNode(gSimArmySerializer);
  }
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
    InitializeHelperNode(gSimArmySerializer);
    gSimArmySerializer.mLoadCallback = &SimArmySerializer::Deserialize;
    gSimArmySerializer.mSaveCallback = &SimArmySerializer::Serialize;
    (void)std::atexit(&CleanupSimArmySerializerAtexit);
  }

  /**
   * Address: 0x006FDBB0 (FUN_006FDBB0)
   *
   * What it does:
   * Duplicated teardown lane for `SimArmySerializer` helper links.
   */
  gpg::SerHelperBase* cleanup_SimArmySerializer_variant_primary()
  {
    return UnlinkHelperNode(gSimArmySerializer);
  }

  /**
   * Address: 0x006FDBE0 (FUN_006FDBE0)
   *
   * What it does:
   * Secondary duplicated teardown lane for `SimArmySerializer` helper links.
   */
  gpg::SerHelperBase* cleanup_SimArmySerializer_variant_secondary()
  {
    return UnlinkHelperNode(gSimArmySerializer);
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
