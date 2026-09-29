#include "RProjectileBlueprintNestedTypeInfo.h"

#include <typeinfo>

#include "moho/resource/RResId.h"
#include "moho/resource/blueprints/RProjectileBlueprint.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  using DisplayTypeInfo = moho::RProjectileBlueprintDisplayTypeInfo;
  using EconomyTypeInfo = moho::RProjectileBlueprintEconomyTypeInfo;
  using PhysicsTypeInfo = moho::RProjectileBlueprintPhysicsTypeInfo;

  /**
   * Address: 0x00BF2DD0 (FUN_00BF2DD0, atexit destructor of the RProjectileBlueprintDisplayTypeInfo object)
   */
  [[nodiscard]] DisplayTypeInfo& AcquireRProjectileBlueprintDisplayTypeInfo()
  {
    static DisplayTypeInfo sInstance;
    return sInstance;
  }

  /**
   * Address: 0x00BF2E30 (FUN_00BF2E30, atexit destructor of the RProjectileBlueprintEconomyTypeInfo object)
   */
  [[nodiscard]] EconomyTypeInfo& AcquireRProjectileBlueprintEconomyTypeInfo()
  {
    static EconomyTypeInfo sInstance;
    return sInstance;
  }

  /**
   * Address: 0x00BF2E90 (FUN_00BF2E90, atexit destructor of the RProjectileBlueprintPhysicsTypeInfo object)
   */
  [[nodiscard]] PhysicsTypeInfo& AcquireRProjectileBlueprintPhysicsTypeInfo()
  {
    static PhysicsTypeInfo sInstance;
    return sInstance;
  }

  gpg::RType* CachedFloatType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(float));
    }
    return cached;
  }

  gpg::RType* CachedBoolType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(bool));
    }
    return cached;
  }

  gpg::RType* CachedIntType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(int));
    }
    return cached;
  }

  gpg::RType* CachedRResIdType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::RResId));
    }
    return cached;
  }

  void AddFieldWithDescription(
    gpg::RType* const typeInfo,
    const char* const fieldName,
    gpg::RType* const fieldType,
    const int offset,
    const char* const description
  )
  {
    typeInfo->fields_.push_back(gpg::RField(fieldName, fieldType, offset, 3, description));
  }

  struct RProjectileBlueprintNestedTypeInfoBootstrap
  {
    RProjectileBlueprintNestedTypeInfoBootstrap()
    {
      moho::register_RProjectileBlueprintDisplayTypeInfo();
      moho::register_RProjectileBlueprintEconomyTypeInfo();
      moho::register_RProjectileBlueprintPhysicsTypeInfo();
    }
  };

  RProjectileBlueprintNestedTypeInfoBootstrap gRProjectileBlueprintNestedTypeInfoBootstrap;
} // namespace

namespace moho
{
  /**
   * Address: 0x0051B9A0 (FUN_0051B9A0, Moho::RProjectileBlueprintDisplayTypeInfo::RProjectileBlueprintDisplayTypeInfo)
   */
  RProjectileBlueprintDisplayTypeInfo::RProjectileBlueprintDisplayTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(RProjectileBlueprintDisplay), this);
  }

  /**
   * Address: 0x0051BA30 (FUN_0051BA30, scalar deleting destructor thunk)
   */
  RProjectileBlueprintDisplayTypeInfo::~RProjectileBlueprintDisplayTypeInfo() = default;

  /**
   * Address: 0x0051BA20 (FUN_0051BA20)
   */
  const char* RProjectileBlueprintDisplayTypeInfo::GetName() const
  {
    return "RProjectileBlueprintDisplay";
  }

  /**
   * Address: 0x0051BAD0 (FUN_0051BAD0)
   *
   * What it does:
   * Registers projectile display field descriptors and descriptions.
   */
  void RProjectileBlueprintDisplayTypeInfo::AddFields(gpg::RType* const typeInfo)
  {
    AddFieldWithDescription(typeInfo, "MeshBlueprint", CachedRResIdType(), offsetof(RProjectileBlueprintDisplay, MeshBlueprint), "Mesh to use as the display of this projectile");
    AddFieldWithDescription(typeInfo, "UniformScale", CachedFloatType(), offsetof(RProjectileBlueprintDisplay, UniformScale), "Uniform scale to apply to mesh");
    AddFieldWithDescription(typeInfo, "MeshScaleRange", CachedFloatType(), offsetof(RProjectileBlueprintDisplay, MeshScaleRange), "range uniform scale of this projectile");
    AddFieldWithDescription(typeInfo, "MeshScaleVelocity", CachedFloatType(), offsetof(RProjectileBlueprintDisplay, MeshScaleVelocity), "rate at which scale changes");
    AddFieldWithDescription(typeInfo, "MeshScaleVelocityRange", CachedFloatType(), offsetof(RProjectileBlueprintDisplay, MeshScaleVelocityRange), "range rate at which scale changes");
    AddFieldWithDescription(
      typeInfo,
      "CameraFollowsProjectile",
      CachedBoolType(),
      offsetof(RProjectileBlueprintDisplay, CameraFollowsProjectile),
      "Set if tracking camera should follow this projectile when it's created."
    );
    AddFieldWithDescription(
      typeInfo,
      "CameraFollowTimeout",
      CachedFloatType(),
      offsetof(RProjectileBlueprintDisplay, CameraFollowTimeout),
      "After I die, how long until we snap the camera back to the launcher?"
    );
    AddFieldWithDescription(
      typeInfo, "StrategicIconSize", CachedFloatType(), offsetof(RProjectileBlueprintDisplay, StrategicIconSize), "How large is the strategic icon square for the projectile"
    );
  }

  /**
   * Address: 0x0051BA00 (FUN_0051BA00)
   *
   * What it does:
   * Sets `RProjectileBlueprintDisplay` size and publishes display field
   * metadata.
   */
  void RProjectileBlueprintDisplayTypeInfo::Init()
  {
    size_ = sizeof(RProjectileBlueprintDisplay);
    gpg::RType::Init();
    AddFields(this);
    Finish();
  }

  /**
   * Address: 0x0051BBA0 (FUN_0051BBA0, Moho::RProjectileBlueprintEconomyTypeInfo::RProjectileBlueprintEconomyTypeInfo)
   */
  RProjectileBlueprintEconomyTypeInfo::RProjectileBlueprintEconomyTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(RProjectileBlueprintEconomy), this);
  }

  /**
   * Address: 0x0051BC30 (FUN_0051BC30, scalar deleting destructor thunk)
   */
  RProjectileBlueprintEconomyTypeInfo::~RProjectileBlueprintEconomyTypeInfo() = default;

  /**
   * Address: 0x0051BC20 (FUN_0051BC20)
   */
  const char* RProjectileBlueprintEconomyTypeInfo::GetName() const
  {
    return "RProjectileBlueprintEconomy";
  }

  /**
   * Address: 0x0051BCD0 (FUN_0051BCD0)
   *
   * What it does:
   * Registers projectile economy field descriptors and descriptions.
   */
  void RProjectileBlueprintEconomyTypeInfo::AddFields(gpg::RType* const typeInfo)
  {
    AddFieldWithDescription(typeInfo, "BuildCostEnergy", CachedFloatType(), offsetof(RProjectileBlueprintEconomy, BuildCostEnergy), "Energy cost to build this projectile");
    AddFieldWithDescription(typeInfo, "BuildCostMass", CachedFloatType(), offsetof(RProjectileBlueprintEconomy, BuildCostMass), "Mass cost to build this projectile");
    AddFieldWithDescription(typeInfo, "BuildTime", CachedFloatType(), offsetof(RProjectileBlueprintEconomy, BuildTime), "Time in seconds to build this projectile");
  }

  /**
   * Address: 0x0051BC00 (FUN_0051BC00)
   *
   * What it does:
   * Sets `RProjectileBlueprintEconomy` size and publishes economy field
   * metadata.
   */
  void RProjectileBlueprintEconomyTypeInfo::Init()
  {
    size_ = sizeof(RProjectileBlueprintEconomy);
    gpg::RType::Init();
    AddFields(this);
    Finish();
  }

  /**
   * Address: 0x0051BD30 (FUN_0051BD30, Moho::RProjectileBlueprintPhysicsTypeInfo::RProjectileBlueprintPhysicsTypeInfo)
   */
  RProjectileBlueprintPhysicsTypeInfo::RProjectileBlueprintPhysicsTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(RProjectileBlueprintPhysics), this);
  }

  /**
   * Address: 0x0051BDC0 (FUN_0051BDC0, scalar deleting destructor thunk)
   */
  RProjectileBlueprintPhysicsTypeInfo::~RProjectileBlueprintPhysicsTypeInfo() = default;

  /**
   * Address: 0x0051BDB0 (FUN_0051BDB0, Moho::RProjectileBlueprintPhysicsTypeInfo::GetName)
   */
  const char* RProjectileBlueprintPhysicsTypeInfo::GetName() const
  {
    return "RProjectileBlueprintPhysics";
  }

  /**
   * Address: 0x0051BE60 (FUN_0051BE60, Moho::RProjectileBlueprintPhysicsTypeInfo::AddFields)
   *
   * What it does:
   * Registers projectile physics field descriptors and descriptions.
   */
  void RProjectileBlueprintPhysicsTypeInfo::AddFields(gpg::RType* const typeInfo)
  {
    AddFieldWithDescription(
      typeInfo,
      "CollideSurface",
      CachedBoolType(),
      offsetof(RProjectileBlueprintPhysics, CollideSurface),
      "Whether to check the projectile for collisions against terrain/water"
    );
    AddFieldWithDescription(
      typeInfo,
      "CollideEntity",
      CachedBoolType(),
      offsetof(RProjectileBlueprintPhysics, CollideEntity),
      "Whether to check the projectile for collisions against other entities"
    );
    AddFieldWithDescription(
      typeInfo, "TrackTarget", CachedBoolType(), offsetof(RProjectileBlueprintPhysics, TrackTarget), "True if projectile should turn to track its target"
    );
    AddFieldWithDescription(
      typeInfo, "VelocityAlign", CachedBoolType(), offsetof(RProjectileBlueprintPhysics, VelocityAlign), "True if projectile should always face the direction its moving"
    );
    AddFieldWithDescription(typeInfo, "StayUpright", CachedBoolType(), offsetof(RProjectileBlueprintPhysics, StayUpright), "True if projectile should always remain upright");
    AddFieldWithDescription(
      typeInfo,
      "LeadTarget",
      CachedBoolType(),
      offsetof(RProjectileBlueprintPhysics, LeadTarget),
      "Whether projectiles should lead their target. Applies only to tracking projectiles."
    );
    AddFieldWithDescription(
      typeInfo,
      "StayUnderwater",
      CachedBoolType(),
      offsetof(RProjectileBlueprintPhysics, StayUnderwater),
      "Whether projectiles should try to stay underwater. Applies only to tracking projectiles."
    );
    AddFieldWithDescription(
      typeInfo, "UseGravity", CachedBoolType(), offsetof(RProjectileBlueprintPhysics, UseGravity), "True if the projectile is initially affected by gravity."
    );
    AddFieldWithDescription(
      typeInfo,
      "DetonateAboveHeight",
      CachedFloatType(),
      offsetof(RProjectileBlueprintPhysics, DetonateAboveHeight),
      "Projectile will detonate when going above this height above ground."
    );
    AddFieldWithDescription(
      typeInfo,
      "DetonateBelowHeight",
      CachedFloatType(),
      offsetof(RProjectileBlueprintPhysics, DetonateBelowHeight),
      "Projectile will detonate when dipping under this height above ground."
    );
    AddFieldWithDescription(
      typeInfo,
      "TurnRate",
      CachedFloatType(),
      offsetof(RProjectileBlueprintPhysics, TurnRate),
      "Max turn rate for the projectile, in degrees per second. Applies only to tracking and velocity-aligned projectiles."
    );
    AddFieldWithDescription(typeInfo, "TurnRateRange", CachedFloatType(), offsetof(RProjectileBlueprintPhysics, TurnRateRange), "Random variation around TurnRate");
    AddFieldWithDescription(typeInfo, "Lifetime", CachedFloatType(), offsetof(RProjectileBlueprintPhysics, Lifetime), "Numbers of seconds I'm alive");
    AddFieldWithDescription(typeInfo, "LifetimeRange", CachedFloatType(), offsetof(RProjectileBlueprintPhysics, LifetimeRange), "Random variation around Lifetime");
    AddFieldWithDescription(typeInfo, "InitialSpeed", CachedFloatType(), offsetof(RProjectileBlueprintPhysics, InitialSpeed), "Initial speed for the projectile.");
    AddFieldWithDescription(typeInfo, "InitialSpeedRange", CachedFloatType(), offsetof(RProjectileBlueprintPhysics, InitialSpeedRange), "Random variation around InitialSpeed");
    AddFieldWithDescription(typeInfo, "MaxSpeed", CachedFloatType(), offsetof(RProjectileBlueprintPhysics, MaxSpeed), "Maximum speed for the Projectile");
    AddFieldWithDescription(typeInfo, "MaxSpeedRange", CachedFloatType(), offsetof(RProjectileBlueprintPhysics, MaxSpeedRange), "Random variation around MaxSpeed");
    AddFieldWithDescription(typeInfo, "Acceleration", CachedFloatType(), offsetof(RProjectileBlueprintPhysics, Acceleration), "Forward acceleration of the Projectile");
    AddFieldWithDescription(typeInfo, "AccelerationRange", CachedFloatType(), offsetof(RProjectileBlueprintPhysics, AccelerationRange), "Random variation around Acceleration");
    AddFieldWithDescription(typeInfo, "PositionX", CachedFloatType(), offsetof(RProjectileBlueprintPhysics, PositionX), "Initial Position offset X component");
    AddFieldWithDescription(typeInfo, "PositionXRange", CachedFloatType(), offsetof(RProjectileBlueprintPhysics, PositionXRange), "Random variation around PositionX");
    AddFieldWithDescription(typeInfo, "PositionY", CachedFloatType(), offsetof(RProjectileBlueprintPhysics, PositionY), "Initial Position offset Y component");
    AddFieldWithDescription(typeInfo, "PositionYRange", CachedFloatType(), offsetof(RProjectileBlueprintPhysics, PositionYRange), "Random variation around PositionY");
    AddFieldWithDescription(typeInfo, "PositionZ", CachedFloatType(), offsetof(RProjectileBlueprintPhysics, PositionZ), "Initial Position offset Z component");
    AddFieldWithDescription(typeInfo, "PositionZRange", CachedFloatType(), offsetof(RProjectileBlueprintPhysics, PositionZRange), "Random variation around PositionZ");
    AddFieldWithDescription(typeInfo, "DirectionX", CachedFloatType(), offsetof(RProjectileBlueprintPhysics, DirectionX), "Initial Direction X component");
    AddFieldWithDescription(typeInfo, "DirectionXRange", CachedFloatType(), offsetof(RProjectileBlueprintPhysics, DirectionXRange), "Random variation around DirectionX");
    AddFieldWithDescription(typeInfo, "DirectionY", CachedFloatType(), offsetof(RProjectileBlueprintPhysics, DirectionY), "Initial Direction Y component");
    AddFieldWithDescription(typeInfo, "DirectionYRange", CachedFloatType(), offsetof(RProjectileBlueprintPhysics, DirectionYRange), "Random variation around DirectionY");
    AddFieldWithDescription(typeInfo, "DirectionZ", CachedFloatType(), offsetof(RProjectileBlueprintPhysics, DirectionZ), "Initial Direction Z component");
    AddFieldWithDescription(typeInfo, "DirectionZRange", CachedFloatType(), offsetof(RProjectileBlueprintPhysics, DirectionZRange), "Random variation around DirectionZ");
    AddFieldWithDescription(typeInfo, "RotationalVelocity", CachedFloatType(), offsetof(RProjectileBlueprintPhysics, RotationalVelocity), "rotation rate in random direction");
    AddFieldWithDescription(
      typeInfo, "RotationalVelocityRange", CachedFloatType(), offsetof(RProjectileBlueprintPhysics, RotationalVelocityRange), "range rotation rate in random direction"
    );
    AddFieldWithDescription(
      typeInfo, "MinBounceCount", CachedIntType(), offsetof(RProjectileBlueprintPhysics, MinBounceCount), "Minimum times to bounce on terrain before impact"
    );
    AddFieldWithDescription(
      typeInfo, "MaxBounceCount", CachedIntType(), offsetof(RProjectileBlueprintPhysics, MaxBounceCount), "Maximum times to bounce on terrain before impact"
    );
    AddFieldWithDescription(
      typeInfo, "BounceVelDamp", CachedFloatType(), offsetof(RProjectileBlueprintPhysics, BounceVelDamp), "Bounce velocity dampening. .75 loses 75% velocity, def: 0.5f"
    );
    AddFieldWithDescription(typeInfo, "DestroyOnWater", CachedBoolType(), offsetof(RProjectileBlueprintPhysics, DestroyOnWater), "Destroy this entity if it touches water");
    AddFieldWithDescription(typeInfo, "MaxZigZag", CachedFloatType(), offsetof(RProjectileBlueprintPhysics, MaxZigZag), "Max amount of zig-zag deflection");
    AddFieldWithDescription(
      typeInfo,
      "ZigZagFrequency",
      CachedFloatType(),
      offsetof(RProjectileBlueprintPhysics, ZigZagFrequency),
      "Frequency of zig-zag directional changes in seconds"
    );
    AddFieldWithDescription(typeInfo, "RealisticOrdinance", CachedBoolType(), offsetof(RProjectileBlueprintPhysics, RealisticOrdinance), "Realistic free fall ordinance type weapon");
    AddFieldWithDescription(typeInfo, "StraightDownOrdinance", CachedBoolType(), offsetof(RProjectileBlueprintPhysics, StraightDownOrdinance), "bombs that always drop stright down");
  }

  /**
   * Address: 0x0051BD90 (FUN_0051BD90, Moho::RProjectileBlueprintPhysicsTypeInfo::Init)
   *
   * What it does:
   * Sets `RProjectileBlueprintPhysics` size and publishes physics field
   * metadata.
   */
  void RProjectileBlueprintPhysicsTypeInfo::Init()
  {
    size_ = sizeof(RProjectileBlueprintPhysics);
    gpg::RType::Init();
    AddFields(this);
    Finish();
  }

  /**
   * Address: 0x00BC8650 (FUN_00BC8650, register_RProjectileBlueprintDisplayTypeInfo)
   */
  void register_RProjectileBlueprintDisplayTypeInfo()
  {
    (void)AcquireRProjectileBlueprintDisplayTypeInfo();
  }

  /**
   * Address: 0x00BC8670 (FUN_00BC8670, register_RProjectileBlueprintEconomyTypeInfo)
   */
  void register_RProjectileBlueprintEconomyTypeInfo()
  {
    (void)AcquireRProjectileBlueprintEconomyTypeInfo();
  }

  /**
   * Address: 0x00BC8690 (FUN_00BC8690, register_RProjectileBlueprintPhysicsTypeInfo)
   */
  void register_RProjectileBlueprintPhysicsTypeInfo()
  {
    (void)AcquireRProjectileBlueprintPhysicsTypeInfo();
  }
} // namespace moho

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_RProjectileBlueprintDisplayTypeInfo_131585, moho::register_RProjectileBlueprintDisplayTypeInfo)
GPG_PREREGISTER_INIT(register_RProjectileBlueprintEconomyTypeInfo_131585, moho::register_RProjectileBlueprintEconomyTypeInfo)
GPG_PREREGISTER_INIT(register_RProjectileBlueprintPhysicsTypeInfo_131585, moho::register_RProjectileBlueprintPhysicsTypeInfo)
