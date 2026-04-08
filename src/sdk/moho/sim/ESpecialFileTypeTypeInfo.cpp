#include "moho/sim/ESpecialFileTypeTypeInfo.h"

#include <cstdlib>
#include <cstdint>
#include <new>
#include <typeinfo>

namespace
{
  alignas(moho::ESpecialFileTypeTypeInfo)
    unsigned char gESpecialFileTypeTypeInfoStorage[sizeof(moho::ESpecialFileTypeTypeInfo)];
  bool gESpecialFileTypeTypeInfoConstructed = false;
  bool gESpecialFileTypeTypeInfoPreregistered = false;

  [[nodiscard]] moho::ESpecialFileTypeTypeInfo* AcquireESpecialFileTypeTypeInfo()
  {
    if (!gESpecialFileTypeTypeInfoConstructed) {
      new (gESpecialFileTypeTypeInfoStorage) moho::ESpecialFileTypeTypeInfo();
      gESpecialFileTypeTypeInfoConstructed = true;
    }

    return reinterpret_cast<moho::ESpecialFileTypeTypeInfo*>(gESpecialFileTypeTypeInfoStorage);
  }

  /**
   * Address: 0x00C08940 (FUN_00C08940, cleanup_ESpecialFileTypeTypeInfo)
   *
   * What it does:
   * Tears down process-global `ESpecialFileTypeTypeInfo` storage.
   */
  void cleanup_ESpecialFileTypeTypeInfo()
  {
    if (!gESpecialFileTypeTypeInfoConstructed) {
      return;
    }

    AcquireESpecialFileTypeTypeInfo()->~ESpecialFileTypeTypeInfo();
    gESpecialFileTypeTypeInfoConstructed = false;
    gESpecialFileTypeTypeInfoPreregistered = false;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x008CA250 (FUN_008CA250, Moho::ESpecialFileTypeTypeInfo::dtr)
   */
  ESpecialFileTypeTypeInfo::~ESpecialFileTypeTypeInfo() = default;

  /**
   * Address: 0x008CA240 (FUN_008CA240, Moho::ESpecialFileTypeTypeInfo::GetName)
   */
  const char* ESpecialFileTypeTypeInfo::GetName() const
  {
    return "ESpecialFileType";
  }

  /**
   * Address: 0x008CA220 (FUN_008CA220, Moho::ESpecialFileTypeTypeInfo::Init)
   */
  void ESpecialFileTypeTypeInfo::Init()
  {
    size_ = sizeof(ESpecialFileType);
    gpg::RType::Init();
    AddEnums(this);
    Finish();
  }

  /**
   * Address: 0x008CA280 (FUN_008CA280, Moho::ESpecialFileTypeTypeInfo::AddEnums)
   */
  void ESpecialFileTypeTypeInfo::AddEnums(gpg::REnumType* const typeInfo)
  {
    typeInfo->mPrefix = "SFT_";
    typeInfo->AddEnum(typeInfo->StripPrefix("SFT_SaveGame"), static_cast<std::int32_t>(SaveGame));
    typeInfo->AddEnum(typeInfo->StripPrefix("SFT_Replay"), static_cast<std::int32_t>(Replay));
    typeInfo->AddEnum(typeInfo->StripPrefix("SFT_CampaignSave"), static_cast<std::int32_t>(CampaignSave));
  }

  /**
   * Address: 0x008CA1C0 (FUN_008CA1C0, preregister_ESpecialFileTypeTypeInfo)
   */
  gpg::REnumType* preregister_ESpecialFileTypeTypeInfo()
  {
    auto* const typeInfo = AcquireESpecialFileTypeTypeInfo();
    if (!gESpecialFileTypeTypeInfoPreregistered) {
      gpg::PreRegisterRType(typeid(ESpecialFileType), typeInfo);
      gESpecialFileTypeTypeInfoPreregistered = true;
    }
    return typeInfo;
  }

  /**
   * Address: 0x00BE8C00 (FUN_00BE8C00, register_ESpecialFileTypeTypeInfo)
   */
  int register_ESpecialFileTypeTypeInfo()
  {
    (void)preregister_ESpecialFileTypeTypeInfo();
    return std::atexit(&cleanup_ESpecialFileTypeTypeInfo);
  }
} // namespace moho

namespace
{
  struct ESpecialFileTypeTypeInfoBootstrap
  {
    ESpecialFileTypeTypeInfoBootstrap()
    {
      (void)moho::register_ESpecialFileTypeTypeInfo();
    }
  };

  [[maybe_unused]] ESpecialFileTypeTypeInfoBootstrap gESpecialFileTypeTypeInfoBootstrap;
} // namespace
