#include "moho/serialization/SSavedGameArmyInfo.h"

#include <typeinfo>

#include "gpg/core/utils/Global.h"

namespace
{
  /**
   * Address: 0x00881EA0 / 0x00882620 path (callback lane used by 0x00882090).
   *
   * What it does:
   * Loads one saved-army info row from archive string payload.
   */
  void LoadSavedGameArmyInfo(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef*)
  {
    auto* const info = reinterpret_cast<moho::SSavedGameArmyInfo*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(info != nullptr);
    if (!archive || !info) {
      return;
    }

    archive->ReadString(&info->mPlayerName);
  }

  /**
   * Address: 0x00881F10 / 0x00882670 path (callback lane used by 0x00882090).
   *
   * What it does:
   * Saves one saved-army info row into archive string payload.
   */
  void SaveSavedGameArmyInfo(gpg::WriteArchive* archive, int objectPtr, int, gpg::RRef*)
  {
    auto* const info = reinterpret_cast<moho::SSavedGameArmyInfo*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(info != nullptr);
    if (!archive || !info) {
      return;
    }

    archive->WriteString(&info->mPlayerName);
  }

  moho::SSavedGameArmyInfoTypeInfo gSavedGameArmyInfoTypeInfo;
  moho::SSavedGameArmyInfoSerializer gSavedGameArmyInfoSerializer;

  void EnsureSavedGameArmyInfoRegistered()
  {
    static const bool kRegistered = []() {
      gpg::PreRegisterRType(typeid(moho::SSavedGameArmyInfo), &gSavedGameArmyInfoTypeInfo);
      gSavedGameArmyInfoSerializer.mNext = nullptr;
      gSavedGameArmyInfoSerializer.mPrev = nullptr;
      gSavedGameArmyInfoSerializer.mSerLoadFunc = &LoadSavedGameArmyInfo;
      gSavedGameArmyInfoSerializer.mSerSaveFunc = &SaveSavedGameArmyInfo;
      gSavedGameArmyInfoSerializer.RegisterSerializeFunctions();
      return true;
    }();

    (void)kRegistered;
  }
} // namespace

namespace moho
{
  gpg::RType* SSavedGameArmyInfo::sType = nullptr;

  gpg::RType* SSavedGameArmyInfo::StaticGetClass()
  {
    EnsureSavedGameArmyInfoRegistered();
    if (!sType) {
      sType = gpg::LookupRType(typeid(SSavedGameArmyInfo));
    }
    return sType;
  }

  /**
   * Address: 0x0087FF80 (FUN_0087FF80)
   */
  const char* SSavedGameArmyInfoTypeInfo::GetName() const
  {
    return "SSavedGameArmyInfo";
  }

  /**
   * Address: 0x0087FF60 (FUN_0087FF60)
   */
  void SSavedGameArmyInfoTypeInfo::Init()
  {
    size_ = sizeof(SSavedGameArmyInfo);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00882090 (FUN_00882090)
   *
   * What it does:
   * Registers load/save callbacks for SSavedGameArmyInfo.
   */
  void SSavedGameArmyInfoSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = SSavedGameArmyInfo::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mSerLoadFunc;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerSaveFunc;
  }
} // namespace moho
