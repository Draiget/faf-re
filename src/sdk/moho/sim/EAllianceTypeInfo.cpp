#include "moho/sim/EAllianceTypeInfo.h"

#include <new>
#include <typeinfo>

namespace
{
  alignas(moho::EAllianceTypeInfo) unsigned char gEAllianceTypeInfoStorage[sizeof(moho::EAllianceTypeInfo)]{};
  bool gEAllianceTypeInfoConstructed = false;

  /**
   * Address: 0x00509D60 (FUN_00509D60, EAllianceTypeInfo construct/register lane)
   *
   * What it does:
   * Constructs one static `EAllianceTypeInfo` instance and pre-registers RTTI
   * ownership for `EAlliance`.
   */
  [[maybe_unused]] gpg::REnumType* ConstructEAllianceTypeInfo()
  {
    if (!gEAllianceTypeInfoConstructed) {
      new (gEAllianceTypeInfoStorage) moho::EAllianceTypeInfo();
      gEAllianceTypeInfoConstructed = true;
    }

    auto* const typeInfo = reinterpret_cast<moho::EAllianceTypeInfo*>(gEAllianceTypeInfoStorage);
    gpg::PreRegisterRType(typeid(moho::EAlliance), typeInfo);
    return typeInfo;
  }

  /**
   * Address: 0x00509E10 (FUN_00509E10, REnumType dtor thunk for EAlliance block)
   */
  [[maybe_unused]] void ThunkREnumTypeDestructorVariant1(gpg::REnumType* const typeInfo)
  {
    if (typeInfo) {
      typeInfo->gpg::REnumType::~REnumType();
    }
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00509DF0 (FUN_00509DF0, Moho::EAllianceTypeInfo::dtr)
   */
  EAllianceTypeInfo::~EAllianceTypeInfo() = default;

  /**
   * Address: 0x00509DE0 (FUN_00509DE0, Moho::EAllianceTypeInfo::GetName)
   */
  const char* EAllianceTypeInfo::GetName() const
  {
    return "EAlliance";
  }

  /**
   * Address: 0x00509DC0 (FUN_00509DC0, Moho::EAllianceTypeInfo::Init)
   */
  void EAllianceTypeInfo::Init()
  {
    size_ = sizeof(EAlliance);
    gpg::RType::Init();
    AddEnums();
    Finish();
  }

  /**
   * Address: 0x00509E20 (FUN_00509E20, Moho::EAllianceTypeInfo::AddEnums)
   */
  void EAllianceTypeInfo::AddEnums()
  {
    mPrefix = "ALLIANCE_";
    AddEnum(StripPrefix("ALLIANCE_Neutral"), static_cast<std::int32_t>(ALLIANCE_Neutral));
    AddEnum(StripPrefix("ALLIANCE_Ally"), static_cast<std::int32_t>(ALLIANCE_Ally));
    AddEnum(StripPrefix("ALLIANCE_Enemy"), static_cast<std::int32_t>(ALLIANCE_Enemy));
  }
} // namespace moho
