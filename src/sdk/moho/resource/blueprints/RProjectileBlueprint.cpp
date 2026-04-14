#include "RProjectileBlueprint.h"

#include <algorithm>
#include <cstring>
#include <limits>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/String.h"
#include "moho/resource/RResId.h"
#include "moho/sim/CRandomStream.h"

namespace moho
{
  namespace
  {
    /**
     * Address: 0x0051C510 (FUN_0051C510, func_RandomDirection)
     *
     * What it does:
     * Builds one randomized launch direction from blueprint direction lanes
     * (`DirectionX/Y/Z`) plus symmetric per-axis ranges.
     */
    [[nodiscard]] Wm3::Vector3f* BuildRandomDirectionVector(
      CRandomStream* const randomStream, Wm3::Vector3f* const destination, const RProjectileBlueprint* const blueprint
    )
    {
      const auto sampleSymmetricOffset = [randomStream](const float range) {
        const float unit = CMersenneTwister::ToUnitFloat(randomStream->twister.NextUInt32());
        return (-range) + ((range - (-range)) * unit);
      };

      destination->x = sampleSymmetricOffset(blueprint->Physics.DirectionXRange) + blueprint->Physics.DirectionX;
      destination->y = sampleSymmetricOffset(blueprint->Physics.DirectionYRange) + blueprint->Physics.DirectionY;
      destination->z = sampleSymmetricOffset(blueprint->Physics.DirectionZRange) + blueprint->Physics.DirectionZ;
      return destination;
    }
  } // namespace

  gpg::RType* RProjectileBlueprint::sType = nullptr;

  /**
   * Address: 0x0051B740 (FUN_0051B740, Moho::RProjectileBlueprint::RProjectileBlueprint)
   *
   * What it does:
   * Constructs projectile-blueprint lanes on top of `REntityBlueprint` and
   * restores projectile collision-shape defaults.
   */
  RProjectileBlueprint::RProjectileBlueprint(RRuleGameRules* const owner, const RResId& resId)
    : REntityBlueprint(owner, resId)
    , DevStatus()
    , Display()
    , Economy()
    , Physics()
  {
    mCollisionShape = COLSHAPE_None;
  }

  /**
   * Address: 0x0051B650 (FUN_0051B650)
   *
   * What it does:
   * Initializes projectile physics defaults used by blueprint construction.
   */
  RProjectileBlueprintPhysics::RProjectileBlueprintPhysics()
    : CollideSurface(1)
    , CollideEntity(1)
    , TrackTarget(0)
    , VelocityAlign(1)
    , StayUpright(0)
    , LeadTarget(1)
    , StayUnderwater(0)
    , UseGravity(1)
    , DetonateAboveHeight(0.0f)
    , DetonateBelowHeight(0.0f)
    , TurnRate(0.0f)
    , TurnRateRange(0.0f)
    , Lifetime(15.0f)
    , LifetimeRange(0.0f)
    , InitialSpeed(1.0f)
    , InitialSpeedRange(0.0f)
    , MaxSpeed(0.0f)
    , MaxSpeedRange(0.0f)
    , Acceleration(0.0f)
    , AccelerationRange(0.0f)
    , PositionX(0.0f)
    , PositionY(0.0f)
    , PositionZ(0.0f)
    , PositionXRange(0.0f)
    , PositionYRange(0.0f)
    , PositionZRange(0.0f)
    , DirectionX(0.0f)
    , DirectionY(1.0f)
    , DirectionZ(0.0f)
    , DirectionXRange(1.5f)
    , DirectionYRange(0.0f)
    , DirectionZRange(1.5f)
    , RotationalVelocity(0.0f)
    , RotationalVelocityRange(0.0f)
    , MaxZigZag(0.0f)
    , ZigZagFrequency(0.0f)
    , DestroyOnWater(0)
    , pad_0079_007C{0, 0, 0}
    , MinBounceCount(0)
    , MaxBounceCount(0)
    , BounceVelDamp(0.5f)
    , RealisticOrdinance(0)
    , StraightDownOrdinance(0)
    , pad_008A_008C{0, 0}
  {}

  /**
   * Address: 0x0051B580 (FUN_0051B580)
   * Mangled: ?GetClass@RProjectileBlueprint@Moho@@UBEPAVRType@gpg@@XZ
   *
   * What it does:
   * Returns cached reflection descriptor for `RProjectileBlueprint`.
   */
  gpg::RType* RProjectileBlueprint::GetClass() const
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(RProjectileBlueprint));
    }
    return sType;
  }

  /**
   * Address: 0x0051B5A0 (FUN_0051B5A0)
   * Mangled: ?GetDerivedObjectRef@RProjectileBlueprint@Moho@@UAE?AVRRef@gpg@@XZ
   *
   * What it does:
   * Packs `{this, GetClass()}` as a reflection reference handle.
   */
  gpg::RRef RProjectileBlueprint::GetDerivedObjectRef()
  {
    gpg::RRef out{};
    out.mObj = this;
    out.mType = GetClass();
    return out;
  }

  /**
   * Address: 0x0051B8B0 (FUN_0051B8B0)
   * Mangled: ?OnInitBlueprint@RProjectileBlueprint@Moho@@MAEXXZ
   *
   * What it does:
   * Runs base entity-blueprint init and canonicalizes `Display.MeshBlueprint`
   * to a completed, lowercase, slash-normalized resource path.
   */
  void RProjectileBlueprint::OnInitBlueprint()
  {
    REntityBlueprint::OnInitBlueprint();

    msvc8::string completedMeshPath = RES_CompletePath(Display.MeshBlueprint.name.c_str(), mSource.c_str());
    gpg::STR_NormalizeFilenameLowerSlash(completedMeshPath);
    Display.MeshBlueprint.name.assign_owned(completedMeshPath.view());
  }

  /**
   * Address: 0x0051C8C0 (FUN_0051C8C0)
   * Mangled: ?GetAngularVelocity@RProjectileBlueprint@Moho@@QBE?AV?$Vector3@M@Wm3@@PAVCRandomStream@2@@Z
   *
   * What it does:
   * Samples one random unit axis and scales it by blueprint rotational speed
   * plus symmetric random spread, then converts degrees/sec to radians/sec.
   */
  Wm3::Vector3f RProjectileBlueprint::GetAngularVelocity(CRandomStream* const randomStream) const
  {
    Wm3::Vector3f randomAxis{};
    randomAxis.x = randomStream->FRandGaussian();
    randomAxis.y = randomStream->FRandGaussian();
    randomAxis.z = randomStream->FRandGaussian();
    Wm3::Vector3f::Normalize(&randomAxis);

    const float randomRange = Physics.RotationalVelocityRange;
    const float randomUnit = CMersenneTwister::ToUnitFloat(randomStream->twister.NextUInt32());
    const float randomOffset = (-randomRange) + ((randomRange - (-randomRange)) * randomUnit);

    constexpr float kDegreesToRadians = 0.017453292f;
    const float angularSpeed = (Physics.RotationalVelocity + randomOffset) * kDegreesToRadians;

    Wm3::Vector3f angularVelocity{};
    angularVelocity.x = randomAxis.x * angularSpeed;
    angularVelocity.y = randomAxis.y * angularSpeed;
    angularVelocity.z = randomAxis.z * angularSpeed;
    return angularVelocity;
  }

  /**
   * Address: 0x0051C680 (?GetRandomInitialSpeed@RProjectileBlueprint@Moho@@QBEMPAVCRandomStream@2@@Z)
   * Mangled: ?GetRandomInitialSpeed@RProjectileBlueprint@Moho@@QBEMPAVCRandomStream@2@@Z
   *
   * What it does:
   * Samples a symmetric launch-speed offset around `Physics.InitialSpeed`
   * using `Physics.InitialSpeedRange`.
   */
  float RProjectileBlueprint::GetRandomInitialSpeed(CRandomStream* const randomStream) const
  {
    const float range = Physics.InitialSpeedRange;
    const float minSpeed = -range;
    const float maxSpeed = range;
    const float unit = CMersenneTwister::ToUnitFloat(randomStream->twister.NextUInt32());
    return minSpeed + ((maxSpeed - minSpeed) * unit) + Physics.InitialSpeed;
  }
} // namespace moho
