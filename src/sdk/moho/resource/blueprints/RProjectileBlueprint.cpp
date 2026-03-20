#include "RProjectileBlueprint.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <filesystem>
#include <limits>
#include <new>
#include <string>
#include <string_view>
#include <typeinfo>

namespace moho
{
  namespace
  {
    void NormalizeFilenameLowerSlash(std::string& value)
    {
      for (char& ch : value) {
        ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        if (ch == '\\') {
          ch = '/';
        }
      }
    }

    [[nodiscard]] std::string
    CompleteResourcePath(const std::string_view sourceName, const std::string_view resourceName)
    {
      if (resourceName.empty()) {
        return {};
      }

      std::filesystem::path resourcePath{resourceName};
      if (!resourcePath.is_absolute() && !sourceName.empty()) {
        const std::filesystem::path sourcePath{sourceName};
        resourcePath = sourcePath.parent_path() / resourcePath;
      }

      return resourcePath.lexically_normal().generic_string();
    }

  } // namespace

  gpg::RType* RProjectileBlueprint::sType = nullptr;

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

    std::string completedMeshPath = CompleteResourcePath(mSource.view(), Display.MeshBlueprint.name.view());
    NormalizeFilenameLowerSlash(completedMeshPath);
    Display.MeshBlueprint.name.assign_owned(completedMeshPath);
  }
} // namespace moho
