#include "moho/sim/EImpactTypeTypeInfo.h"

namespace
{
  /**
   * Address: 0x00509F80 (FUN_00509F80, REnumType dtor thunk for EImpactType block)
   */
  [[maybe_unused]] void ThunkREnumTypeDestructorVariant2(gpg::REnumType* const typeInfo)
  {
    if (typeInfo) {
      typeInfo->gpg::REnumType::~REnumType();
    }
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0067B320 (FUN_0067B320, Moho::ENT_GetImpactTypeString)
   */
  const char* ENT_GetImpactTypeString(const EImpactType impactType)
  {
    switch (impactType) {
      case IMPACT_Terrain:
        return "Terrain";
      case IMPACT_Water:
        return "Water";
      case IMPACT_Air:
        return "Air";
      case IMPACT_Underwater:
        return "Underwater";
      case IMPACT_Projectile:
        return "Projectile";
      case IMPACT_ProjectileUnderwater:
        return "ProjectileUnderwater";
      case IMPACT_Prop:
        return "Prop";
      case IMPACT_Shield:
        return "Shield";
      case IMPACT_Unit:
        return "Unit";
      case IMPACT_UnitAir:
        return "UnitAir";
      case IMPACT_UnitUnderwater:
        return "UnitUnderwater";
      default:
        return "Unknown";
    }
  }

  /**
   * Address: 0x00509F60 (FUN_00509F60, Moho::EImpactTypeTypeInfo::dtr)
   */
  EImpactTypeTypeInfo::~EImpactTypeTypeInfo() = default;

  /**
   * Address: 0x00509F50 (FUN_00509F50, Moho::EImpactTypeTypeInfo::GetName)
   */
  const char* EImpactTypeTypeInfo::GetName() const
  {
    return "EImpactType";
  }

  /**
   * Address: 0x00509F30 (FUN_00509F30, Moho::EImpactTypeTypeInfo::Init)
   */
  void EImpactTypeTypeInfo::Init()
  {
    size_ = sizeof(EImpactType);
    gpg::RType::Init();
    AddEnums();
    Finish();
  }

  /**
   * Address: 0x00509F90 (FUN_00509F90, Moho::EImpactTypeTypeInfo::AddEnums)
   */
  void EImpactTypeTypeInfo::AddEnums()
  {
    mPrefix = "IMPACT_";
    AddEnum(StripPrefix("IMPACT_Invalid"), static_cast<std::int32_t>(IMPACT_Invalid));
    AddEnum(StripPrefix("IMPACT_Terrain"), static_cast<std::int32_t>(IMPACT_Terrain));
    AddEnum(StripPrefix("IMPACT_Water"), static_cast<std::int32_t>(IMPACT_Water));
    AddEnum(StripPrefix("IMPACT_Air"), static_cast<std::int32_t>(IMPACT_Air));
    AddEnum(StripPrefix("IMPACT_Underwater"), static_cast<std::int32_t>(IMPACT_Underwater));
    AddEnum(StripPrefix("IMPACT_Projectile"), static_cast<std::int32_t>(IMPACT_Projectile));
    AddEnum(
      StripPrefix("IMPACT_ProjectileUnderwater"),
      static_cast<std::int32_t>(IMPACT_ProjectileUnderwater)
    );
    AddEnum(StripPrefix("IMPACT_Prop"), static_cast<std::int32_t>(IMPACT_Prop));
    AddEnum(StripPrefix("IMPACT_Shield"), static_cast<std::int32_t>(IMPACT_Shield));
    AddEnum(StripPrefix("IMPACT_Unit"), static_cast<std::int32_t>(IMPACT_Unit));
    AddEnum(StripPrefix("IMPACT_UnitAir"), static_cast<std::int32_t>(IMPACT_UnitAir));
    AddEnum(StripPrefix("IMPACT_UnitUnderwater"), static_cast<std::int32_t>(IMPACT_UnitUnderwater));
  }
} // namespace moho
