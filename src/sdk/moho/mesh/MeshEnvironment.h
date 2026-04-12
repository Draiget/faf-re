#pragma once

#include <cstddef>
#include <cstring>

#include "legacy/containers/String.h"
#include "Wm3Vector3.h"

namespace moho
{
  class MeshEnvironment
  {
  public:
    /**
     * Address: 0x007DB0D0 (FUN_007DB0D0)
     *
     * What it does:
     * Initializes default cube-map path and fallback mesh-lighting shader parameters.
     */
    MeshEnvironment();

    /**
     * Address: 0x007DB1D0 (FUN_007DB1D0)
     *
     * What it does:
     * Resets cube-map path storage to an empty SSO string state.
     */
    virtual ~MeshEnvironment();

    /**
     * Address: 0x007DB190 (FUN_007DB190)
     *
     * What it does:
     * Clears and frees cube-map path storage while keeping the object alive.
     */
    void ResetCubeMapPathStorage();

  public:
    msvc8::string mCubeMapPath;               // +0x04
    float mFallbackLightMultiplier;           // +0x20
    Wm3::Vec3f mFallbackSunDiffuseColor;      // +0x24
    Wm3::Vec3f mFallbackSunAmbientColor;      // +0x30
    Wm3::Vec3f mFallbackShadowFillColor;      // +0x3C
    float mFallbackSunDirectionAngle0Radians; // +0x48 (constructor-seeded, used by external update paths)
    float mFallbackSunDirectionAngle1Radians; // +0x4C (constructor-seeded, used by external update paths)
    Wm3::Vec3f mFallbackSunDirection;         // +0x50
  };

  static_assert(offsetof(MeshEnvironment, mCubeMapPath) == 0x04, "MeshEnvironment::mCubeMapPath offset must be 0x04");
  static_assert(
    offsetof(MeshEnvironment, mFallbackLightMultiplier) == 0x20,
    "MeshEnvironment::mFallbackLightMultiplier offset must be 0x20"
  );
  static_assert(
    offsetof(MeshEnvironment, mFallbackSunDiffuseColor) == 0x24,
    "MeshEnvironment::mFallbackSunDiffuseColor offset must be 0x24"
  );
  static_assert(
    offsetof(MeshEnvironment, mFallbackSunAmbientColor) == 0x30,
    "MeshEnvironment::mFallbackSunAmbientColor offset must be 0x30"
  );
  static_assert(
    offsetof(MeshEnvironment, mFallbackShadowFillColor) == 0x3C,
    "MeshEnvironment::mFallbackShadowFillColor offset must be 0x3C"
  );
  static_assert(
    offsetof(MeshEnvironment, mFallbackSunDirectionAngle0Radians) == 0x48,
    "MeshEnvironment::mFallbackSunDirectionAngle0Radians offset must be 0x48"
  );
  static_assert(
    offsetof(MeshEnvironment, mFallbackSunDirectionAngle1Radians) == 0x4C,
    "MeshEnvironment::mFallbackSunDirectionAngle1Radians offset must be 0x4C"
  );
  static_assert(
    offsetof(MeshEnvironment, mFallbackSunDirection) == 0x50,
    "MeshEnvironment::mFallbackSunDirection offset must be 0x50"
  );
  static_assert(sizeof(MeshEnvironment) == 0x5C, "MeshEnvironment size must be 0x5C");
} // namespace moho
