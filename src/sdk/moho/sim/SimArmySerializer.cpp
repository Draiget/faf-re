#include "moho/sim/SimArmySerializer.h"

#include "moho/sim/SimArmy.h"

namespace moho
{
  /**
   * Address: 0x00BD9BC0 (FUN_00BD9BC0, dynamic initializer for the global
   * `SimArmySerializer` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields.
   */
  SimArmySerializer::SimArmySerializer()
    : mLoadCallback(&SimArmySerializer::Deserialize)
    , mSaveCallback(&SimArmySerializer::Serialize)
  {}

  SimArmySerializer::~SimArmySerializer()
  {
    ResetLinks();
  }

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
  void SimArmySerializer::Init()
  {
    gpg::RType* const type = SimArmy::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho

namespace
{
  // Address: 0x010B8A48 -- process-global `SimArmySerializer` singleton.
  moho::SimArmySerializer gSimArmySerializer;
} // namespace
