#include "MeshEnvironment.h"

namespace moho
{
  namespace
  {
    constexpr const char* kDefaultEnvironmentCubeMapPath = "/textures/environment/defaultenvcube.dds";
  }

  /**
   * Address: 0x007DB0D0 (FUN_007DB0D0)
   *
   * What it does:
   * Initializes default cube-map path and fallback mesh-lighting shader parameters.
   */
  MeshEnvironment::MeshEnvironment()
    : mCubeMapPath()
    , mFallbackLightMultiplier(1.5f)
    , mFallbackSunDiffuseColor{1.0f, 1.0f, 1.0f}
    , mFallbackSunAmbientColor{0.1f, 0.1f, 0.1f}
    , mFallbackShadowFillColor{0.7f, 0.7f, 0.75f}
    , mFallbackSunDirectionAngle0Radians(0.78539816339f)
    , mFallbackSunDirectionAngle1Radians(1.57079632679f)
    , mFallbackSunDirection{0.70710676908f, 0.70710676908f, 0.0f}
  {
    mCubeMapPath.assign_owned(kDefaultEnvironmentCubeMapPath);
  }

  /**
   * Address: 0x007DB1D0 (FUN_007DB1D0)
   *
   * What it does:
   * Resets cube-map path storage to an empty SSO string state.
   */
  MeshEnvironment::~MeshEnvironment()
  {
    ResetCubeMapPathStorage();
  }

  /**
   * Address: 0x007DB190 (FUN_007DB190)
   *
   * What it does:
   * Clears and frees cube-map path storage while keeping the object alive.
   */
  void MeshEnvironment::ResetCubeMapPathStorage()
  {
    mCubeMapPath.tidy(true, 0U);
  }
} // namespace moho
