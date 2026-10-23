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
    typeInfo->AddField<moho::RResId>("MeshBlueprint", offsetof(RProjectileBlueprintDisplay, MeshBlueprint), 3, "Mesh to use as the display of this projectile");
    typeInfo->AddField<float>("UniformScale", offsetof(RProjectileBlueprintDisplay, UniformScale), 3, "Uniform scale to apply to mesh");
    typeInfo->AddField<float>("MeshScaleRange", offsetof(RProjectileBlueprintDisplay, MeshScaleRange), 3, "range uniform scale of this projectile");
    typeInfo->AddField<float>("MeshScaleVelocity", offsetof(RProjectileBlueprintDisplay, MeshScaleVelocity), 3, "rate at which scale changes");
    typeInfo->AddField<float>("MeshScaleVelocityRange", offsetof(RProjectileBlueprintDisplay, MeshScaleVelocityRange), 3, "range rate at which scale changes");
    typeInfo->AddField<bool>("CameraFollowsProjectile", offsetof(RProjectileBlueprintDisplay, CameraFollowsProjectile), 3, "Set if tracking camera should follow this projectile when it's created.");
    typeInfo->AddField<float>("CameraFollowTimeout", offsetof(RProjectileBlueprintDisplay, CameraFollowTimeout), 3, "After I die, how long until we snap the camera back to the launcher?");
    typeInfo->AddField<float>("StrategicIconSize", offsetof(RProjectileBlueprintDisplay, StrategicIconSize), 3, "How large is the strategic icon square for the projectile");
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
    typeInfo->AddField<float>("BuildCostEnergy", offsetof(RProjectileBlueprintEconomy, BuildCostEnergy), 3, "Energy cost to build this projectile");
    typeInfo->AddField<float>("BuildCostMass", offsetof(RProjectileBlueprintEconomy, BuildCostMass), 3, "Mass cost to build this projectile");
    typeInfo->AddField<float>("BuildTime", offsetof(RProjectileBlueprintEconomy, BuildTime), 3, "Time in seconds to build this projectile");
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
    typeInfo->AddField<bool>("CollideSurface", offsetof(RProjectileBlueprintPhysics, CollideSurface), 3, "Whether to check the projectile for collisions against terrain/water");
    typeInfo->AddField<bool>("CollideEntity", offsetof(RProjectileBlueprintPhysics, CollideEntity), 3, "Whether to check the projectile for collisions against other entities");
    typeInfo->AddField<bool>("TrackTarget", offsetof(RProjectileBlueprintPhysics, TrackTarget), 3, "True if projectile should turn to track its target");
    typeInfo->AddField<bool>("VelocityAlign", offsetof(RProjectileBlueprintPhysics, VelocityAlign), 3, "True if projectile should always face the direction its moving");
    typeInfo->AddField<bool>("StayUpright", offsetof(RProjectileBlueprintPhysics, StayUpright), 3, "True if projectile should always remain upright");
    typeInfo->AddField<bool>("LeadTarget", offsetof(RProjectileBlueprintPhysics, LeadTarget), 3, "Whether projectiles should lead their target. Applies only to tracking projectiles.");
    typeInfo->AddField<bool>("StayUnderwater", offsetof(RProjectileBlueprintPhysics, StayUnderwater), 3, "Whether projectiles should try to stay underwater. Applies only to tracking projectiles.");
    typeInfo->AddField<bool>("UseGravity", offsetof(RProjectileBlueprintPhysics, UseGravity), 3, "True if the projectile is initially affected by gravity.");
    typeInfo->AddField<float>("DetonateAboveHeight", offsetof(RProjectileBlueprintPhysics, DetonateAboveHeight), 3, "Projectile will detonate when going above this height above ground.");
    typeInfo->AddField<float>("DetonateBelowHeight", offsetof(RProjectileBlueprintPhysics, DetonateBelowHeight), 3, "Projectile will detonate when dipping under this height above ground.");
    typeInfo->AddField<float>("TurnRate", offsetof(RProjectileBlueprintPhysics, TurnRate), 3, "Max turn rate for the projectile, in degrees per second. Applies only to tracking and velocity-aligned projectiles.");
    typeInfo->AddField<float>("TurnRateRange", offsetof(RProjectileBlueprintPhysics, TurnRateRange), 3, "Random variation around TurnRate");
    typeInfo->AddField<float>("Lifetime", offsetof(RProjectileBlueprintPhysics, Lifetime), 3, "Numbers of seconds I'm alive");
    typeInfo->AddField<float>("LifetimeRange", offsetof(RProjectileBlueprintPhysics, LifetimeRange), 3, "Random variation around Lifetime");
    typeInfo->AddField<float>("InitialSpeed", offsetof(RProjectileBlueprintPhysics, InitialSpeed), 3, "Initial speed for the projectile.");
    typeInfo->AddField<float>("InitialSpeedRange", offsetof(RProjectileBlueprintPhysics, InitialSpeedRange), 3, "Random variation around InitialSpeed");
    typeInfo->AddField<float>("MaxSpeed", offsetof(RProjectileBlueprintPhysics, MaxSpeed), 3, "Maximum speed for the Projectile");
    typeInfo->AddField<float>("MaxSpeedRange", offsetof(RProjectileBlueprintPhysics, MaxSpeedRange), 3, "Random variation around MaxSpeed");
    typeInfo->AddField<float>("Acceleration", offsetof(RProjectileBlueprintPhysics, Acceleration), 3, "Forward acceleration of the Projectile");
    typeInfo->AddField<float>("AccelerationRange", offsetof(RProjectileBlueprintPhysics, AccelerationRange), 3, "Random variation around Acceleration");
    typeInfo->AddField<float>("PositionX", offsetof(RProjectileBlueprintPhysics, PositionX), 3, "Initial Position offset X component");
    typeInfo->AddField<float>("PositionXRange", offsetof(RProjectileBlueprintPhysics, PositionXRange), 3, "Random variation around PositionX");
    typeInfo->AddField<float>("PositionY", offsetof(RProjectileBlueprintPhysics, PositionY), 3, "Initial Position offset Y component");
    typeInfo->AddField<float>("PositionYRange", offsetof(RProjectileBlueprintPhysics, PositionYRange), 3, "Random variation around PositionY");
    typeInfo->AddField<float>("PositionZ", offsetof(RProjectileBlueprintPhysics, PositionZ), 3, "Initial Position offset Z component");
    typeInfo->AddField<float>("PositionZRange", offsetof(RProjectileBlueprintPhysics, PositionZRange), 3, "Random variation around PositionZ");
    typeInfo->AddField<float>("DirectionX", offsetof(RProjectileBlueprintPhysics, DirectionX), 3, "Initial Direction X component");
    typeInfo->AddField<float>("DirectionXRange", offsetof(RProjectileBlueprintPhysics, DirectionXRange), 3, "Random variation around DirectionX");
    typeInfo->AddField<float>("DirectionY", offsetof(RProjectileBlueprintPhysics, DirectionY), 3, "Initial Direction Y component");
    typeInfo->AddField<float>("DirectionYRange", offsetof(RProjectileBlueprintPhysics, DirectionYRange), 3, "Random variation around DirectionY");
    typeInfo->AddField<float>("DirectionZ", offsetof(RProjectileBlueprintPhysics, DirectionZ), 3, "Initial Direction Z component");
    typeInfo->AddField<float>("DirectionZRange", offsetof(RProjectileBlueprintPhysics, DirectionZRange), 3, "Random variation around DirectionZ");
    typeInfo->AddField<float>("RotationalVelocity", offsetof(RProjectileBlueprintPhysics, RotationalVelocity), 3, "rotation rate in random direction");
    typeInfo->AddField<float>("RotationalVelocityRange", offsetof(RProjectileBlueprintPhysics, RotationalVelocityRange), 3, "range rotation rate in random direction");
    typeInfo->AddField<int>("MinBounceCount", offsetof(RProjectileBlueprintPhysics, MinBounceCount), 3, "Minimum times to bounce on terrain before impact");
    typeInfo->AddField<int>("MaxBounceCount", offsetof(RProjectileBlueprintPhysics, MaxBounceCount), 3, "Maximum times to bounce on terrain before impact");
    typeInfo->AddField<float>("BounceVelDamp", offsetof(RProjectileBlueprintPhysics, BounceVelDamp), 3, "Bounce velocity dampening. .75 loses 75% velocity, def: 0.5f");
    typeInfo->AddField<bool>("DestroyOnWater", offsetof(RProjectileBlueprintPhysics, DestroyOnWater), 3, "Destroy this entity if it touches water");
    typeInfo->AddField<float>("MaxZigZag", offsetof(RProjectileBlueprintPhysics, MaxZigZag), 3, "Max amount of zig-zag deflection");
    typeInfo->AddField<float>("ZigZagFrequency", offsetof(RProjectileBlueprintPhysics, ZigZagFrequency), 3, "Frequency of zig-zag directional changes in seconds");
    typeInfo->AddField<bool>("RealisticOrdinance", offsetof(RProjectileBlueprintPhysics, RealisticOrdinance), 3, "Realistic free fall ordinance type weapon");
    typeInfo->AddField<bool>("StraightDownOrdinance", offsetof(RProjectileBlueprintPhysics, StraightDownOrdinance), 3, "bombs that always drop stright down");
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
