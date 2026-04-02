#include "RProjectileBlueprintNestedTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/resource/RResId.h"
#include "moho/resource/blueprints/RProjectileBlueprint.h"

namespace
{
  using DisplayTypeInfo = moho::RProjectileBlueprintDisplayTypeInfo;
  using EconomyTypeInfo = moho::RProjectileBlueprintEconomyTypeInfo;
  using PhysicsTypeInfo = moho::RProjectileBlueprintPhysicsTypeInfo;

  alignas(DisplayTypeInfo) unsigned char gRProjectileBlueprintDisplayTypeInfoStorage[sizeof(DisplayTypeInfo)];
  bool gRProjectileBlueprintDisplayTypeInfoConstructed = false;

  alignas(EconomyTypeInfo) unsigned char gRProjectileBlueprintEconomyTypeInfoStorage[sizeof(EconomyTypeInfo)];
  bool gRProjectileBlueprintEconomyTypeInfoConstructed = false;

  alignas(PhysicsTypeInfo) unsigned char gRProjectileBlueprintPhysicsTypeInfoStorage[sizeof(PhysicsTypeInfo)];
  bool gRProjectileBlueprintPhysicsTypeInfoConstructed = false;

  [[nodiscard]] DisplayTypeInfo& AcquireRProjectileBlueprintDisplayTypeInfo()
  {
    if (!gRProjectileBlueprintDisplayTypeInfoConstructed) {
      new (gRProjectileBlueprintDisplayTypeInfoStorage) DisplayTypeInfo();
      gRProjectileBlueprintDisplayTypeInfoConstructed = true;
    }

    return *reinterpret_cast<DisplayTypeInfo*>(gRProjectileBlueprintDisplayTypeInfoStorage);
  }

  [[nodiscard]] EconomyTypeInfo& AcquireRProjectileBlueprintEconomyTypeInfo()
  {
    if (!gRProjectileBlueprintEconomyTypeInfoConstructed) {
      new (gRProjectileBlueprintEconomyTypeInfoStorage) EconomyTypeInfo();
      gRProjectileBlueprintEconomyTypeInfoConstructed = true;
    }

    return *reinterpret_cast<EconomyTypeInfo*>(gRProjectileBlueprintEconomyTypeInfoStorage);
  }

  [[nodiscard]] PhysicsTypeInfo& AcquireRProjectileBlueprintPhysicsTypeInfoStorage()
  {
    if (!gRProjectileBlueprintPhysicsTypeInfoConstructed) {
      new (gRProjectileBlueprintPhysicsTypeInfoStorage) PhysicsTypeInfo();
      gRProjectileBlueprintPhysicsTypeInfoConstructed = true;
    }

    return *reinterpret_cast<PhysicsTypeInfo*>(gRProjectileBlueprintPhysicsTypeInfoStorage);
  }

  void cleanup_RProjectileBlueprintDisplayTypeInfo()
  {
    if (!gRProjectileBlueprintDisplayTypeInfoConstructed) {
      return;
    }

    AcquireRProjectileBlueprintDisplayTypeInfo().~DisplayTypeInfo();
    gRProjectileBlueprintDisplayTypeInfoConstructed = false;
  }

  void cleanup_RProjectileBlueprintEconomyTypeInfo()
  {
    if (!gRProjectileBlueprintEconomyTypeInfoConstructed) {
      return;
    }

    AcquireRProjectileBlueprintEconomyTypeInfo().~EconomyTypeInfo();
    gRProjectileBlueprintEconomyTypeInfoConstructed = false;
  }

  void cleanup_RProjectileBlueprintPhysicsTypeInfo()
  {
    if (!gRProjectileBlueprintPhysicsTypeInfoConstructed) {
      return;
    }

    AcquireRProjectileBlueprintPhysicsTypeInfoStorage().~PhysicsTypeInfo();
    gRProjectileBlueprintPhysicsTypeInfoConstructed = false;
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
      (void)moho::register_RProjectileBlueprintDisplayTypeInfo();
      (void)moho::register_RProjectileBlueprintEconomyTypeInfo();
      (void)moho::register_RProjectileBlueprintPhysicsTypeInfo();
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
    AddFieldWithDescription(typeInfo, "MeshBlueprint", CachedRResIdType(), 0x00, "Mesh to use as the display of this projectile");
    AddFieldWithDescription(typeInfo, "UniformScale", CachedFloatType(), 0x1C, "Uniform scale to apply to mesh");
    AddFieldWithDescription(typeInfo, "MeshScaleRange", CachedFloatType(), 0x20, "range uniform scale of this projectile");
    AddFieldWithDescription(typeInfo, "MeshScaleVelocity", CachedFloatType(), 0x24, "rate at which scale changes");
    AddFieldWithDescription(typeInfo, "MeshScaleVelocityRange", CachedFloatType(), 0x28, "range rate at which scale changes");
    AddFieldWithDescription(
      typeInfo,
      "CameraFollowsProjectile",
      CachedBoolType(),
      0x2C,
      "Set if tracking camera should follow this projectile when it's created."
    );
    AddFieldWithDescription(
      typeInfo,
      "CameraFollowTimeout",
      CachedFloatType(),
      0x30,
      "After I die, how long until we snap the camera back to the launcher?"
    );
    AddFieldWithDescription(
      typeInfo, "StrategicIconSize", CachedFloatType(), 0x34, "How large is the strategic icon square for the projectile"
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
    AddFieldWithDescription(typeInfo, "BuildCostEnergy", CachedFloatType(), 0x00, "Energy cost to build this projectile");
    AddFieldWithDescription(typeInfo, "BuildCostMass", CachedFloatType(), 0x04, "Mass cost to build this projectile");
    AddFieldWithDescription(typeInfo, "BuildTime", CachedFloatType(), 0x08, "Time in seconds to build this projectile");
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
      0x00,
      "Whether to check the projectile for collisions against terrain/water"
    );
    AddFieldWithDescription(
      typeInfo,
      "CollideEntity",
      CachedBoolType(),
      0x01,
      "Whether to check the projectile for collisions against other entities"
    );
    AddFieldWithDescription(
      typeInfo, "TrackTarget", CachedBoolType(), 0x02, "True if projectile should turn to track its target"
    );
    AddFieldWithDescription(
      typeInfo, "VelocityAlign", CachedBoolType(), 0x03, "True if projectile should always face the direction its moving"
    );
    AddFieldWithDescription(typeInfo, "StayUpright", CachedBoolType(), 0x04, "True if projectile should always remain upright");
    AddFieldWithDescription(
      typeInfo,
      "LeadTarget",
      CachedBoolType(),
      0x05,
      "Whether projectiles should lead their target. Applies only to tracking projectiles."
    );
    AddFieldWithDescription(
      typeInfo,
      "StayUnderwater",
      CachedBoolType(),
      0x06,
      "Whether projectiles should try to stay underwater. Applies only to tracking projectiles."
    );
    AddFieldWithDescription(
      typeInfo, "UseGravity", CachedBoolType(), 0x07, "True if the projectile is initially affected by gravity."
    );
    AddFieldWithDescription(
      typeInfo,
      "DetonateAboveHeight",
      CachedFloatType(),
      0x08,
      "Projectile will detonate when going above this height above ground."
    );
    AddFieldWithDescription(
      typeInfo,
      "DetonateBelowHeight",
      CachedFloatType(),
      0x0C,
      "Projectile will detonate when dipping under this height above ground."
    );
    AddFieldWithDescription(
      typeInfo,
      "TurnRate",
      CachedFloatType(),
      0x10,
      "Max turn rate for the projectile, in degrees per second. Applies only to tracking and velocity-aligned projectiles."
    );
    AddFieldWithDescription(typeInfo, "TurnRateRange", CachedFloatType(), 0x14, "Random variation around TurnRate");
    AddFieldWithDescription(typeInfo, "Lifetime", CachedFloatType(), 0x18, "Numbers of seconds I'm alive");
    AddFieldWithDescription(typeInfo, "LifetimeRange", CachedFloatType(), 0x1C, "Random variation around Lifetime");
    AddFieldWithDescription(typeInfo, "InitialSpeed", CachedFloatType(), 0x20, "Initial speed for the projectile.");
    AddFieldWithDescription(typeInfo, "InitialSpeedRange", CachedFloatType(), 0x24, "Random variation around InitialSpeed");
    AddFieldWithDescription(typeInfo, "MaxSpeed", CachedFloatType(), 0x28, "Maximum speed for the Projectile");
    AddFieldWithDescription(typeInfo, "MaxSpeedRange", CachedFloatType(), 0x2C, "Random variation around MaxSpeed");
    AddFieldWithDescription(typeInfo, "Acceleration", CachedFloatType(), 0x30, "Forward acceleration of the Projectile");
    AddFieldWithDescription(typeInfo, "AccelerationRange", CachedFloatType(), 0x34, "Random variation around Acceleration");
    AddFieldWithDescription(typeInfo, "PositionX", CachedFloatType(), 0x38, "Initial Position offset X component");
    AddFieldWithDescription(typeInfo, "PositionXRange", CachedFloatType(), 0x44, "Random variation around PositionX");
    AddFieldWithDescription(typeInfo, "PositionY", CachedFloatType(), 0x3C, "Initial Position offset Y component");
    AddFieldWithDescription(typeInfo, "PositionYRange", CachedFloatType(), 0x48, "Random variation around PositionY");
    AddFieldWithDescription(typeInfo, "PositionZ", CachedFloatType(), 0x40, "Initial Position offset Z component");
    AddFieldWithDescription(typeInfo, "PositionZRange", CachedFloatType(), 0x4C, "Random variation around PositionZ");
    AddFieldWithDescription(typeInfo, "DirectionX", CachedFloatType(), 0x50, "Initial Direction X component");
    AddFieldWithDescription(typeInfo, "DirectionXRange", CachedFloatType(), 0x5C, "Random variation around DirectionX");
    AddFieldWithDescription(typeInfo, "DirectionY", CachedFloatType(), 0x54, "Initial Direction Y component");
    AddFieldWithDescription(typeInfo, "DirectionYRange", CachedFloatType(), 0x60, "Random variation around DirectionY");
    AddFieldWithDescription(typeInfo, "DirectionZ", CachedFloatType(), 0x58, "Initial Direction Z component");
    AddFieldWithDescription(typeInfo, "DirectionZRange", CachedFloatType(), 0x64, "Random variation around DirectionZ");
    AddFieldWithDescription(typeInfo, "RotationalVelocity", CachedFloatType(), 0x68, "rotation rate in random direction");
    AddFieldWithDescription(
      typeInfo, "RotationalVelocityRange", CachedFloatType(), 0x6C, "range rotation rate in random direction"
    );
    AddFieldWithDescription(
      typeInfo, "MinBounceCount", CachedIntType(), 0x7C, "Minimum times to bounce on terrain before impact"
    );
    AddFieldWithDescription(
      typeInfo, "MaxBounceCount", CachedIntType(), 0x80, "Maximum times to bounce on terrain before impact"
    );
    AddFieldWithDescription(
      typeInfo, "BounceVelDamp", CachedFloatType(), 0x84, "Bounce velocity dampening. .75 loses 75% velocity, def: 0.5f"
    );
    AddFieldWithDescription(typeInfo, "DestroyOnWater", CachedBoolType(), 0x78, "Destroy this entity if it touches water");
    AddFieldWithDescription(typeInfo, "MaxZigZag", CachedFloatType(), 0x70, "Max amount of zig-zag deflection");
    AddFieldWithDescription(
      typeInfo,
      "ZigZagFrequency",
      CachedFloatType(),
      0x74,
      "Frequency of zig-zag directional changes in seconds"
    );
    AddFieldWithDescription(typeInfo, "RealisticOrdinance", CachedBoolType(), 0x88, "Realistic free fall ordinance type weapon");
    AddFieldWithDescription(typeInfo, "StraightDownOrdinance", CachedBoolType(), 0x89, "bombs that always drop stright down");
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
   * Address: 0x0051BD30 (FUN_0051BD30, preregister_RProjectileBlueprintPhysicsTypeInfo)
   */
  gpg::RType* preregister_RProjectileBlueprintPhysicsTypeInfo()
  {
    if (!gRProjectileBlueprintPhysicsTypeInfoConstructed) {
      PhysicsTypeInfo& typeInfo = AcquireRProjectileBlueprintPhysicsTypeInfoStorage();
      gpg::PreRegisterRType(typeid(RProjectileBlueprintPhysics), &typeInfo);
    }

    return &AcquireRProjectileBlueprintPhysicsTypeInfoStorage();
  }

  /**
   * Address: 0x00BC8650 (FUN_00BC8650, register_RProjectileBlueprintDisplayTypeInfo)
   */
  int register_RProjectileBlueprintDisplayTypeInfo()
  {
    (void)AcquireRProjectileBlueprintDisplayTypeInfo();
    return std::atexit(&cleanup_RProjectileBlueprintDisplayTypeInfo);
  }

  /**
   * Address: 0x00BC8670 (FUN_00BC8670, register_RProjectileBlueprintEconomyTypeInfo)
   */
  int register_RProjectileBlueprintEconomyTypeInfo()
  {
    (void)AcquireRProjectileBlueprintEconomyTypeInfo();
    return std::atexit(&cleanup_RProjectileBlueprintEconomyTypeInfo);
  }

  /**
   * Address: 0x00BC8690 (FUN_00BC8690, register_RProjectileBlueprintPhysicsTypeInfo)
   */
  int register_RProjectileBlueprintPhysicsTypeInfo()
  {
    (void)preregister_RProjectileBlueprintPhysicsTypeInfo();
    return std::atexit(&cleanup_RProjectileBlueprintPhysicsTypeInfo);
  }
} // namespace moho
