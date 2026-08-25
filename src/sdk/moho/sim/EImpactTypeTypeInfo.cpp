#include "moho/sim/EImpactTypeTypeInfo.h"

#include <cstdlib>
#include <cstdint>
#include <new>
#include <typeinfo>

#include "moho/entity/Entity.h"
#include "moho/sim/Sim.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  alignas(moho::EImpactTypeTypeInfo) unsigned char gEImpactTypeTypeInfoStorage[sizeof(moho::EImpactTypeTypeInfo)]{};
  bool gEImpactTypeTypeInfoConstructed = false;
  bool gEImpactTypeTypeInfoPreregistered = false;

  /**
   * Address: 0x00BC7A90 (FUN_00BC7A90, dynamic initializer for the global
   * `PrimitiveSerHelper<EImpactType,int>` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields (vtable slot 0 `Init()` dispatched later by
   * `gpg::SerHelperBase::InitNewHelpers`). The previous raw-struct stand-in
   * for this helper required an explicit
   * `register_EImpactTypePrimitiveSerializer()` call from a bootstrap
   * struct to run its equivalent logic; the real binary never does that --
   * the global's own dynamic initializer is the entire registration.
   */
  moho::EImpactTypePrimitiveSerializer gEImpactTypePrimitiveSerializer;

  /**
   * Address: 0x00509F80 (FUN_00509F80, REnumType dtor thunk for EImpactType block)
   */
  [[maybe_unused]] void ThunkREnumTypeDestructorVariant2(gpg::REnumType* const typeInfo)
  {
    if (typeInfo) {
      typeInfo->gpg::REnumType::~REnumType();
    }
  }

  [[nodiscard]] moho::EImpactTypeTypeInfo* AcquireEImpactTypeTypeInfo()
  {
    if (!gEImpactTypeTypeInfoConstructed) {
      new (gEImpactTypeTypeInfoStorage) moho::EImpactTypeTypeInfo();
      gEImpactTypeTypeInfoConstructed = true;
    }

    return reinterpret_cast<moho::EImpactTypeTypeInfo*>(gEImpactTypeTypeInfoStorage);
  }

  /**
   * Address: 0x00509ED0 (FUN_00509ED0, preregister_EImpactTypeTypeInfo)
   */
  [[nodiscard]] gpg::REnumType* ConstructEImpactTypeTypeInfoInternal()
  {
    auto* const typeInfo = AcquireEImpactTypeTypeInfo();
    if (!gEImpactTypeTypeInfoPreregistered) {
      gpg::PreRegisterRType(typeid(moho::EImpactType), typeInfo);
      gEImpactTypeTypeInfoPreregistered = true;
    }

    return typeInfo;
  }

  /**
   * Address: 0x00BF1F50 (FUN_00BF1F50, cleanup_EImpactTypeTypeInfo)
   */
  void cleanup_EImpactTypeTypeInfo()
  {
    if (!gEImpactTypeTypeInfoConstructed) {
      return;
    }

    AcquireEImpactTypeTypeInfo()->~EImpactTypeTypeInfo();
    gEImpactTypeTypeInfoConstructed = false;
    gEImpactTypeTypeInfoPreregistered = false;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0067B240 (FUN_0067B240, Moho::ENT_GetImpactType)
   */
  EImpactType ENT_GetImpactType(Sim* const sim, Entity* const entity, const Wm3::Vector3f& hitPosition)
  {
    static constexpr float kNoWaterElevation = -10000.0f;
    static constexpr std::uint32_t kShieldEntityMask = 0xF0000000u;
    static constexpr std::uint32_t kShieldEntityTag = 0x40000000u;

    const STIMap* const mapData = sim->mMapData;
    const float waterElevation = (mapData->mWaterEnabled != 0u) ? mapData->mWaterElevation : kNoWaterElevation;

    if (waterElevation > hitPosition.y) {
      if (entity == nullptr) {
        return IMPACT_Underwater;
      }

      if (entity->IsUnit() != nullptr) {
        return IMPACT_UnitUnderwater;
      }

      if (entity->IsProjectile() != nullptr) {
        return IMPACT_ProjectileUnderwater;
      }

      if ((entity->id_ & kShieldEntityMask) == kShieldEntityTag) {
        return IMPACT_Shield;
      }

      return IMPACT_Underwater;
    }

    if (entity == nullptr) {
      return IMPACT_Air;
    }

    if (entity->IsUnit() != nullptr) {
      return (entity->mCurrentLayer == LAYER_Air) ? IMPACT_UnitAir : IMPACT_Unit;
    }

    if (entity->IsProjectile() != nullptr) {
      return IMPACT_Projectile;
    }

    if (entity->IsProp() != nullptr) {
      return IMPACT_Prop;
    }

    if ((entity->id_ & kShieldEntityMask) == kShieldEntityTag) {
      return IMPACT_Shield;
    }

    return IMPACT_Air;
  }

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

  /**
   * Address: 0x00BC7A70 (FUN_00BC7A70, register_EImpactTypeTypeInfo)
   */
  int register_EImpactTypeTypeInfo()
  {
    (void)ConstructEImpactTypeTypeInfoInternal();
    return std::atexit(&cleanup_EImpactTypeTypeInfo);
  }
} // namespace moho

namespace
{
  struct EImpactTypeTypeInfoBootstrap
  {
    EImpactTypeTypeInfoBootstrap()
    {
      (void)moho::register_EImpactTypeTypeInfo();
    }
  };

  [[maybe_unused]] EImpactTypeTypeInfoBootstrap gEImpactTypeTypeInfoBootstrap;
} // namespace


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_EImpactTypeTypeInfo_c2a1f9, moho::register_EImpactTypeTypeInfo)

GPG_PREREGISTER_INIT(ConstructEImpactTypeTypeInfoInternal_c2a1f9, ConstructEImpactTypeTypeInfoInternal)
