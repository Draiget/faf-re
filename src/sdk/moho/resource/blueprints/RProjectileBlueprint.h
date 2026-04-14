#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "moho/entity/REntityBlueprint.h"
#include "moho/resource/RResId.h"

namespace moho
{
  class CRandomStream;

  /**
   * Address: 0x0051BA00 (FUN_0051BA00)
   *
   * What it does:
   * Reflection type init for `RProjectileBlueprintDisplay` (`sizeof = 0x38`).
   */
  struct RProjectileBlueprintDisplay
  {
    RResId MeshBlueprint;                      // +0x00
    float UniformScale{0.0f};                  // +0x1C
    float MeshScaleRange{0.0f};                // +0x20
    float MeshScaleVelocity{0.0f};             // +0x24
    float MeshScaleVelocityRange{0.0f};        // +0x28
    std::uint8_t CameraFollowsProjectile{0};   // +0x2C
    std::uint8_t pad_002D_0030[0x03]{0, 0, 0}; // +0x2D
    float CameraFollowTimeout{1.0f};           // +0x30
    float StrategicIconSize{1.0f};             // +0x34
  };

  /**
   * Address: 0x0051BC00 (FUN_0051BC00)
   *
   * What it does:
   * Reflection type init for `RProjectileBlueprintEconomy` (`sizeof = 0x0C`).
   */
  struct RProjectileBlueprintEconomy
  {
    float BuildCostEnergy{0.0f}; // +0x00
    float BuildCostMass{0.0f};   // +0x04
    float BuildTime{10.0f};      // +0x08
  };

  /**
   * Address: 0x0051BD90 (FUN_0051BD90)
   *
   * What it does:
   * Reflection type init for `RProjectileBlueprintPhysics` (`sizeof = 0x8C`).
   */
  struct RProjectileBlueprintPhysics
  {
    std::uint8_t CollideSurface;        // +0x00
    std::uint8_t CollideEntity;         // +0x01
    std::uint8_t TrackTarget;           // +0x02
    std::uint8_t VelocityAlign;         // +0x03
    std::uint8_t StayUpright;           // +0x04
    std::uint8_t LeadTarget;            // +0x05
    std::uint8_t StayUnderwater;        // +0x06
    std::uint8_t UseGravity;            // +0x07
    float DetonateAboveHeight;          // +0x08
    float DetonateBelowHeight;          // +0x0C
    float TurnRate;                     // +0x10
    float TurnRateRange;                // +0x14
    float Lifetime;                     // +0x18
    float LifetimeRange;                // +0x1C
    float InitialSpeed;                 // +0x20
    float InitialSpeedRange;            // +0x24
    float MaxSpeed;                     // +0x28
    float MaxSpeedRange;                // +0x2C
    float Acceleration;                 // +0x30
    float AccelerationRange;            // +0x34
    float PositionX;                    // +0x38
    float PositionY;                    // +0x3C
    float PositionZ;                    // +0x40
    float PositionXRange;               // +0x44
    float PositionYRange;               // +0x48
    float PositionZRange;               // +0x4C
    float DirectionX;                   // +0x50
    float DirectionY;                   // +0x54
    float DirectionZ;                   // +0x58
    float DirectionXRange;              // +0x5C
    float DirectionYRange;              // +0x60
    float DirectionZRange;              // +0x64
    float RotationalVelocity;           // +0x68
    float RotationalVelocityRange;      // +0x6C
    float MaxZigZag;                    // +0x70
    float ZigZagFrequency;              // +0x74
    std::uint8_t DestroyOnWater;        // +0x78
    std::uint8_t pad_0079_007C[0x03];   // +0x79
    std::int32_t MinBounceCount;        // +0x7C
    std::int32_t MaxBounceCount;        // +0x80
    float BounceVelDamp;                // +0x84
    std::uint8_t RealisticOrdinance;    // +0x88
    std::uint8_t StraightDownOrdinance; // +0x89
    std::uint8_t pad_008A_008C[0x02];   // +0x8A

    /**
     * Address: 0x0051B650 (FUN_0051B650)
     *
     * What it does:
     * Initializes projectile physics defaults used by blueprint construction.
     */
    RProjectileBlueprintPhysics();
  };

  /**
   * Address: 0x0051C2C0 (FUN_0051C2C0)
   *
   * What it does:
   * Reflection type init for `RProjectileBlueprint` (`sizeof = 0x268`) and
   * nested fields: `DevStatus` (+0x17C), `Display` (+0x198),
   * `Economy` (+0x1D0), `Physics` (+0x1DC).
   */
  struct RProjectileBlueprint : public REntityBlueprint
  {
    msvc8::string DevStatus;             // +0x017C
    RProjectileBlueprintDisplay Display; // +0x0198
    RProjectileBlueprintEconomy Economy; // +0x01D0
    RProjectileBlueprintPhysics Physics; // +0x01DC
    static gpg::RType* sType;

    /**
     * Address: 0x0051B580 (FUN_0051B580)
     * Mangled: ?GetClass@RProjectileBlueprint@Moho@@UBEPAVRType@gpg@@XZ
     *
     * What it does:
     * Returns cached reflection descriptor for `RProjectileBlueprint`.
     */
    [[nodiscard]] gpg::RType* GetClass() const;

    /**
     * Address: 0x0051B5A0 (FUN_0051B5A0)
     * Mangled: ?GetDerivedObjectRef@RProjectileBlueprint@Moho@@UAE?AVRRef@gpg@@XZ
     *
     * What it does:
     * Packs `{this, GetClass()}` as a reflection reference handle.
     */
    gpg::RRef GetDerivedObjectRef();

    /**
     * Address: 0x0051B8B0 (FUN_0051B8B0)
     * Mangled: ?OnInitBlueprint@RProjectileBlueprint@Moho@@MAEXXZ
     *
     * What it does:
     * Runs base entity-blueprint init and canonicalizes `Display.MeshBlueprint`
     * to a completed, lowercase, slash-normalized resource path.
     */
    void OnInitBlueprint();

    /**
     * Address: 0x0051C8C0 (FUN_0051C8C0)
     * Mangled: ?GetAngularVelocity@RProjectileBlueprint@Moho@@QBE?AV?$Vector3@M@Wm3@@PAVCRandomStream@2@@Z
     *
     * What it does:
     * Samples one random normalized axis and returns launch angular velocity
     * in radians-per-second, using `Physics.RotationalVelocity` and symmetric
     * random spread from `Physics.RotationalVelocityRange`.
     */
    [[nodiscard]] Wm3::Vector3f GetAngularVelocity(CRandomStream* randomStream) const;
  };

  static_assert(sizeof(RProjectileBlueprintDisplay) == 0x38, "RProjectileBlueprintDisplay size must be 0x38");
  static_assert(sizeof(RProjectileBlueprintEconomy) == 0x0C, "RProjectileBlueprintEconomy size must be 0x0C");
  static_assert(sizeof(RProjectileBlueprintPhysics) == 0x8C, "RProjectileBlueprintPhysics size must be 0x8C");

  static_assert(
    offsetof(RProjectileBlueprintDisplay, MeshBlueprint) == 0x00,
    "RProjectileBlueprintDisplay::MeshBlueprint offset must be 0x00"
  );
  static_assert(
    offsetof(RProjectileBlueprintDisplay, UniformScale) == 0x1C,
    "RProjectileBlueprintDisplay::UniformScale offset must be 0x1C"
  );
  static_assert(
    offsetof(RProjectileBlueprintDisplay, MeshScaleRange) == 0x20,
    "RProjectileBlueprintDisplay::MeshScaleRange offset must be 0x20"
  );
  static_assert(
    offsetof(RProjectileBlueprintDisplay, MeshScaleVelocity) == 0x24,
    "RProjectileBlueprintDisplay::MeshScaleVelocity offset must be 0x24"
  );
  static_assert(
    offsetof(RProjectileBlueprintDisplay, MeshScaleVelocityRange) == 0x28,
    "RProjectileBlueprintDisplay::MeshScaleVelocityRange offset must be 0x28"
  );
  static_assert(
    offsetof(RProjectileBlueprintDisplay, CameraFollowsProjectile) == 0x2C,
    "RProjectileBlueprintDisplay::CameraFollowsProjectile offset must be 0x2C"
  );
  static_assert(
    offsetof(RProjectileBlueprintDisplay, CameraFollowTimeout) == 0x30,
    "RProjectileBlueprintDisplay::CameraFollowTimeout offset must be 0x30"
  );
  static_assert(
    offsetof(RProjectileBlueprintDisplay, StrategicIconSize) == 0x34,
    "RProjectileBlueprintDisplay::StrategicIconSize offset must be 0x34"
  );

  static_assert(
    offsetof(RProjectileBlueprintEconomy, BuildCostEnergy) == 0x00,
    "RProjectileBlueprintEconomy::BuildCostEnergy offset must be 0x00"
  );
  static_assert(
    offsetof(RProjectileBlueprintEconomy, BuildCostMass) == 0x04,
    "RProjectileBlueprintEconomy::BuildCostMass offset must be 0x04"
  );
  static_assert(
    offsetof(RProjectileBlueprintEconomy, BuildTime) == 0x08,
    "RProjectileBlueprintEconomy::BuildTime offset must be 0x08"
  );

  static_assert(
    offsetof(RProjectileBlueprintPhysics, CollideSurface) == 0x00,
    "RProjectileBlueprintPhysics::CollideSurface offset must be 0x00"
  );
  static_assert(
    offsetof(RProjectileBlueprintPhysics, CollideEntity) == 0x01,
    "RProjectileBlueprintPhysics::CollideEntity offset must be 0x01"
  );
  static_assert(
    offsetof(RProjectileBlueprintPhysics, TrackTarget) == 0x02,
    "RProjectileBlueprintPhysics::TrackTarget offset must be 0x02"
  );
  static_assert(
    offsetof(RProjectileBlueprintPhysics, VelocityAlign) == 0x03,
    "RProjectileBlueprintPhysics::VelocityAlign offset must be 0x03"
  );
  static_assert(
    offsetof(RProjectileBlueprintPhysics, StayUpright) == 0x04,
    "RProjectileBlueprintPhysics::StayUpright offset must be 0x04"
  );
  static_assert(
    offsetof(RProjectileBlueprintPhysics, LeadTarget) == 0x05,
    "RProjectileBlueprintPhysics::LeadTarget offset must be 0x05"
  );
  static_assert(
    offsetof(RProjectileBlueprintPhysics, StayUnderwater) == 0x06,
    "RProjectileBlueprintPhysics::StayUnderwater offset must be 0x06"
  );
  static_assert(
    offsetof(RProjectileBlueprintPhysics, UseGravity) == 0x07,
    "RProjectileBlueprintPhysics::UseGravity offset must be 0x07"
  );
  static_assert(
    offsetof(RProjectileBlueprintPhysics, DetonateAboveHeight) == 0x08,
    "RProjectileBlueprintPhysics::DetonateAboveHeight offset must be 0x08"
  );
  static_assert(
    offsetof(RProjectileBlueprintPhysics, DetonateBelowHeight) == 0x0C,
    "RProjectileBlueprintPhysics::DetonateBelowHeight offset must be 0x0C"
  );
  static_assert(
    offsetof(RProjectileBlueprintPhysics, TurnRate) == 0x10, "RProjectileBlueprintPhysics::TurnRate offset must be 0x10"
  );
  static_assert(
    offsetof(RProjectileBlueprintPhysics, TurnRateRange) == 0x14,
    "RProjectileBlueprintPhysics::TurnRateRange offset must be 0x14"
  );
  static_assert(
    offsetof(RProjectileBlueprintPhysics, Lifetime) == 0x18, "RProjectileBlueprintPhysics::Lifetime offset must be 0x18"
  );
  static_assert(
    offsetof(RProjectileBlueprintPhysics, LifetimeRange) == 0x1C,
    "RProjectileBlueprintPhysics::LifetimeRange offset must be 0x1C"
  );
  static_assert(
    offsetof(RProjectileBlueprintPhysics, InitialSpeed) == 0x20,
    "RProjectileBlueprintPhysics::InitialSpeed offset must be 0x20"
  );
  static_assert(
    offsetof(RProjectileBlueprintPhysics, InitialSpeedRange) == 0x24,
    "RProjectileBlueprintPhysics::InitialSpeedRange offset must be 0x24"
  );
  static_assert(
    offsetof(RProjectileBlueprintPhysics, MaxSpeed) == 0x28, "RProjectileBlueprintPhysics::MaxSpeed offset must be 0x28"
  );
  static_assert(
    offsetof(RProjectileBlueprintPhysics, MaxSpeedRange) == 0x2C,
    "RProjectileBlueprintPhysics::MaxSpeedRange offset must be 0x2C"
  );
  static_assert(
    offsetof(RProjectileBlueprintPhysics, Acceleration) == 0x30,
    "RProjectileBlueprintPhysics::Acceleration offset must be 0x30"
  );
  static_assert(
    offsetof(RProjectileBlueprintPhysics, AccelerationRange) == 0x34,
    "RProjectileBlueprintPhysics::AccelerationRange offset must be 0x34"
  );
  static_assert(
    offsetof(RProjectileBlueprintPhysics, PositionX) == 0x38,
    "RProjectileBlueprintPhysics::PositionX offset must be 0x38"
  );
  static_assert(
    offsetof(RProjectileBlueprintPhysics, PositionY) == 0x3C,
    "RProjectileBlueprintPhysics::PositionY offset must be 0x3C"
  );
  static_assert(
    offsetof(RProjectileBlueprintPhysics, PositionZ) == 0x40,
    "RProjectileBlueprintPhysics::PositionZ offset must be 0x40"
  );
  static_assert(
    offsetof(RProjectileBlueprintPhysics, PositionXRange) == 0x44,
    "RProjectileBlueprintPhysics::PositionXRange offset must be 0x44"
  );
  static_assert(
    offsetof(RProjectileBlueprintPhysics, PositionYRange) == 0x48,
    "RProjectileBlueprintPhysics::PositionYRange offset must be 0x48"
  );
  static_assert(
    offsetof(RProjectileBlueprintPhysics, PositionZRange) == 0x4C,
    "RProjectileBlueprintPhysics::PositionZRange offset must be 0x4C"
  );
  static_assert(
    offsetof(RProjectileBlueprintPhysics, DirectionX) == 0x50,
    "RProjectileBlueprintPhysics::DirectionX offset must be 0x50"
  );
  static_assert(
    offsetof(RProjectileBlueprintPhysics, DirectionY) == 0x54,
    "RProjectileBlueprintPhysics::DirectionY offset must be 0x54"
  );
  static_assert(
    offsetof(RProjectileBlueprintPhysics, DirectionZ) == 0x58,
    "RProjectileBlueprintPhysics::DirectionZ offset must be 0x58"
  );
  static_assert(
    offsetof(RProjectileBlueprintPhysics, DirectionXRange) == 0x5C,
    "RProjectileBlueprintPhysics::DirectionXRange offset must be 0x5C"
  );
  static_assert(
    offsetof(RProjectileBlueprintPhysics, DirectionYRange) == 0x60,
    "RProjectileBlueprintPhysics::DirectionYRange offset must be 0x60"
  );
  static_assert(
    offsetof(RProjectileBlueprintPhysics, DirectionZRange) == 0x64,
    "RProjectileBlueprintPhysics::DirectionZRange offset must be 0x64"
  );
  static_assert(
    offsetof(RProjectileBlueprintPhysics, RotationalVelocity) == 0x68,
    "RProjectileBlueprintPhysics::RotationalVelocity offset must be 0x68"
  );
  static_assert(
    offsetof(RProjectileBlueprintPhysics, RotationalVelocityRange) == 0x6C,
    "RProjectileBlueprintPhysics::RotationalVelocityRange offset must be 0x6C"
  );
  static_assert(
    offsetof(RProjectileBlueprintPhysics, MaxZigZag) == 0x70,
    "RProjectileBlueprintPhysics::MaxZigZag offset must be 0x70"
  );
  static_assert(
    offsetof(RProjectileBlueprintPhysics, ZigZagFrequency) == 0x74,
    "RProjectileBlueprintPhysics::ZigZagFrequency offset must be 0x74"
  );
  static_assert(
    offsetof(RProjectileBlueprintPhysics, DestroyOnWater) == 0x78,
    "RProjectileBlueprintPhysics::DestroyOnWater offset must be 0x78"
  );
  static_assert(
    offsetof(RProjectileBlueprintPhysics, MinBounceCount) == 0x7C,
    "RProjectileBlueprintPhysics::MinBounceCount offset must be 0x7C"
  );
  static_assert(
    offsetof(RProjectileBlueprintPhysics, MaxBounceCount) == 0x80,
    "RProjectileBlueprintPhysics::MaxBounceCount offset must be 0x80"
  );
  static_assert(
    offsetof(RProjectileBlueprintPhysics, BounceVelDamp) == 0x84,
    "RProjectileBlueprintPhysics::BounceVelDamp offset must be 0x84"
  );
  static_assert(
    offsetof(RProjectileBlueprintPhysics, RealisticOrdinance) == 0x88,
    "RProjectileBlueprintPhysics::RealisticOrdinance offset must be 0x88"
  );
  static_assert(
    offsetof(RProjectileBlueprintPhysics, StraightDownOrdinance) == 0x89,
    "RProjectileBlueprintPhysics::StraightDownOrdinance offset must be 0x89"
  );

  static_assert(
    offsetof(RProjectileBlueprint, DevStatus) == 0x17C, "RProjectileBlueprint::DevStatus offset must be 0x17C"
  );
  static_assert(offsetof(RProjectileBlueprint, Display) == 0x198, "RProjectileBlueprint::Display offset must be 0x198");
  static_assert(offsetof(RProjectileBlueprint, Economy) == 0x1D0, "RProjectileBlueprint::Economy offset must be 0x1D0");
  static_assert(offsetof(RProjectileBlueprint, Physics) == 0x1DC, "RProjectileBlueprint::Physics offset must be 0x1DC");
  static_assert(sizeof(RProjectileBlueprint) == 0x268, "RProjectileBlueprint size must be 0x268");
} // namespace moho
