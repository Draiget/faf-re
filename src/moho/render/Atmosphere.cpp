#include "moho/render/Atmosphere.h"

#include "moho/render/BoundDepthSupport.h"
#include <algorithm>
#include <cmath>
#include <cstdint>
#include <vector>

#include "gpg/core/utils/Logging.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/DeviceContext.hpp"
#include "gpg/gal/GpuDriven.h"
#include "moho/console/CConCommand.h"
#include "moho/math/VMatrix4.h"
#include "moho/render/AtmosphereShader.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/STIMap.h"

namespace moho
{
  // Engine addition (ren_Atmosphere): see Atmosphere.h.
  int ren_Atmosphere = 0;
  float ren_AtmosphereDensity = 0.012f;
  float ren_AtmosphereFogHeight = 8.0f;
  float ren_AtmosphereShafts = 1.0f;
  float ren_AtmosphereMax = 0.3f;
  float ren_AtmosphereClear = 0.75f;
  float ren_AtmosphereReach = 600.0f;
  int ren_AtmosphereSteps = 16;

  namespace
  {
    TConVar<int> gTConVar_ren_Atmosphere(
      "ren_Atmosphere",
      "Direct3D 12 and Vulkan: height fog over the low ground, lit by the sun, with shafts of light and shadow where "
      "hills block it. 1 on, 0 off (default).",
      &ren_Atmosphere
    );
    TConVar<float> gTConVar_ren_AtmosphereDensity(
      "ren_AtmosphereDensity",
      "ren_Atmosphere: the fog's density per world unit at the low ground (0.012 the default).",
      &ren_AtmosphereDensity
    );
    TConVar<float> gTConVar_ren_AtmosphereFogHeight(
      "ren_AtmosphereFogHeight",
      "ren_Atmosphere: the height in world units over which the fog thins to a third (8 the default).",
      &ren_AtmosphereFogHeight
    );
    TConVar<float> gTConVar_ren_AtmosphereShafts(
      "ren_AtmosphereShafts",
      "ren_Atmosphere: how much sunlight the fog scatters, so hills' shadows show in it (0 none, 1 the default).",
      &ren_AtmosphereShafts
    );
    TConVar<float> gTConVar_ren_AtmosphereMax(
      "ren_AtmosphereMax",
      "ren_Atmosphere: the most of a pixel's colour the fog takes, 0 to 1 (0.3 the default), so units stay visible.",
      &ren_AtmosphereMax
    );
    TConVar<float> gTConVar_ren_AtmosphereClear(
      "ren_AtmosphereClear",
      "ren_Atmosphere: the fog starts this far from the camera, times its distance to its focus (0.75 the default), "
      "and "
      "comes in over one focus distance, so the ground being looked at stays clear.",
      &ren_AtmosphereClear
    );
    TConVar<float> gTConVar_ren_AtmosphereReach(
      "ren_AtmosphereReach",
      "ren_Atmosphere: how far towards the sky the fog is marched, world units (600 the default).",
      &ren_AtmosphereReach
    );
    TConVar<int> gTConVar_ren_AtmosphereSteps(
      "ren_AtmosphereSteps",
      "ren_Atmosphere: samples per pixel along the view (4-64, 16 the default).",
      &ren_AtmosphereSteps
    );

    struct AtmosphereConstants
    {
      VMatrix4 inverseViewProjection;
      float viewRect[4];
      float bufferSize[4];
      float eye[4];
      float sun[4];
      float sunColor[4];
      float ambient[4];
      float fog[4];
      float grid[4];
      float gridSize[4];
      float range[4];
    };
    static_assert(sizeof(AtmosphereConstants) == 224, "AtmosphereConstants matches the shader's cbuffer");

    /** Sun-height cells across the larger side of the map at most. */
    constexpr std::int32_t kSunHeightCells = 1024;

    /** The fog's light is the scene's: this much of the sun's and the ambient light reaches the camera from it. */
    constexpr float kLightScale = 0.55f;

  } // namespace

  // Defined in moho/app/WxRuntimeTypes.cpp (0x007FA170).
  [[nodiscard]] IWldTerrainRes* REN_GetTerrainRes();

  Atmosphere& Atmosphere::Get()
  {
    static Atmosphere sAtmosphere;
    return sAtmosphere;
  }

  bool Atmosphere::IsActive()
  {
    if (ren_Atmosphere <= 0) {
      return false;
    }
    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    if (device == nullptr) {
      return false;
    }
    if (device != mDevice) {
      *this = Atmosphere();
      mDevice = device;
      constexpr std::uint32_t kNeeded = gpg::gal::kGpuFeatureVertexPulling | gpg::gal::kGpuFeatureCompute;
      if (BackendReadsBoundDepth(*device) && (device->GetGpuDrivenFeatures() & kNeeded) == kNeeded) {
        gpg::gal::GpuProgramDesc compute{};
        compute.name = "Atmosphere";
        compute.source = kAtmosphereShaderSource;
        compute.sourceBytes = sizeof(kAtmosphereShaderSource) - 1U;
        compute.computeEntry = "AtmosphereCS";
        mCompute = device->CreateGpuProgram(compute);

        gpg::gal::GpuProgramDesc bake = compute;
        bake.name = "AtmosphereSunHeights";
        bake.computeEntry = "SunHeightCS";
        mBake = device->CreateGpuProgram(bake);

        gpg::gal::GpuProgramDesc composite{};
        composite.name = "AtmosphereComposite";
        composite.source = kAtmosphereShaderSource;
        composite.sourceBytes = sizeof(kAtmosphereShaderSource) - 1U;
        composite.vertexEntry = "AtmosphereCompositeVS";
        composite.pixelEntry = "AtmosphereCompositePS";
        composite.blend = gpg::gal::GpuBlend::AlphaBlend; // colour * (1 - opacity) + light
        composite.colorWriteMask = 0x07U;                 // alpha is the glow amount and the water mask
        composite.depthTest = false;
        composite.depthWrite = false;
        composite.cullBackFaces = false;
        mComposite = device->CreateGpuProgram(composite);
      }
      mSupported = mCompute != nullptr && mBake != nullptr && mComposite != nullptr;
      if (mSupported) {
        gpg::Logf("Atmosphere: on this renderer (ren_Atmosphere)");
      }
    }
    return mSupported;
  }

  bool Atmosphere::PrepareSunHeights(
    const float sun[3]
  )
  {
    IWldTerrainRes* const terrain = REN_GetTerrainRes();
    if (terrain == nullptr || terrain->mMap == nullptr) {
      return false;
    }
    CHeightField* const field = terrain->mMap->mHeightField.get();
    if (field == nullptr || field->Width() < 2 || field->Height() < 2) {
      return false;
    }
    // The revision moves on every terrain edit and map load (RayScene.cpp uses it the same way).
    const std::uint64_t revision = HeightFieldRevision();
    const bool sameField = field == mBakedField && field->Width() == mFieldWidth && field->Height() == mFieldHeight &&
      revision == mBakedRevision && mHeights != nullptr;
    if (sameField && sun[0] == mBakedSun[0] && sun[1] == mBakedSun[1] && sun[2] == mBakedSun[2]) {
      return mBaked;
    }
    mBakedRevision = revision;
    mBakedField = field;
    mFieldWidth = field->Width();
    mFieldHeight = field->Height();
    std::copy(sun, sun + 3, mBakedSun);
    mBaked = false;

    if (!sameField) {
      // The heights, two 16-bit samples per element, and the low ground: a fifth of the samples lie under it.
      const std::size_t samples = static_cast<std::size_t>(mFieldWidth) * static_cast<std::size_t>(mFieldHeight);
      std::vector<std::uint32_t> packed((samples + 1U) / 2U, 0U);
      std::vector<std::uint32_t> histogram(65536U, 0U);
      const std::uint16_t* const heights = field->GetArrayAt(0, 0);
      for (std::size_t index = 0; index < samples; ++index) {
        packed[index >> 1U] |= static_cast<std::uint32_t>(heights[index]) << ((index & 1U) * 16U);
        ++histogram[heights[index]];
      }
      std::size_t seen = 0U;
      std::uint32_t low = 0U;
      std::uint32_t lowest = 65535U;
      std::uint32_t highest = 0U;
      for (std::uint32_t value = 0U; value < 65536U; ++value) {
        if (histogram[value] == 0U) {
          continue;
        }
        lowest = std::min(lowest, value);
        highest = value;
        if (seen * 5U < samples) {
          low = value;
        }
        seen += histogram[value];
      }
      mLowGround = static_cast<float>(low) * 0.0078125f;
      mHeightRange = static_cast<float>(highest - std::min(lowest, highest)) * 0.0078125f;

      gpg::gal::GpuBufferDesc heightDesc{};
      heightDesc.name = "AtmosphereHeights";
      heightDesc.stride = sizeof(std::uint32_t);
      heightDesc.capacity = static_cast<std::uint32_t>(packed.size());
      mHeights = mDevice->CreateGpuBuffer(heightDesc);
      if (mHeights == nullptr) {
        return false;
      }
      mDevice->UpdateGpuBuffer(*mHeights, 0U, static_cast<std::uint32_t>(packed.size()), packed.data());

      const std::int32_t larger = std::max(mFieldWidth, mFieldHeight);
      mCellSize = static_cast<std::uint32_t>((larger + kSunHeightCells - 1) / kSunHeightCells);
      mCellsAcross = (static_cast<std::uint32_t>(mFieldWidth) + mCellSize - 1U) / mCellSize;
      mCellsDown = (static_cast<std::uint32_t>(mFieldHeight) + mCellSize - 1U) / mCellSize;
      gpg::gal::GpuBufferDesc sunDesc{};
      sunDesc.name = "AtmosphereSunHeights";
      sunDesc.stride = sizeof(float);
      sunDesc.capacity = mCellsAcross * mCellsDown;
      sunDesc.shaderWrite = true;
      mSunHeights = mDevice->CreateGpuBuffer(sunDesc);
      if (mSunHeights == nullptr) {
        mHeights.reset();
        return false;
      }
    }

    AtmosphereConstants constants{};
    constants.sun[0] = sun[0];
    constants.sun[1] = sun[1];
    constants.sun[2] = sun[2];
    constants.grid[0] = static_cast<float>(mFieldWidth);
    constants.grid[1] = static_cast<float>(mFieldHeight);
    constants.grid[2] = static_cast<float>(mCellSize);
    constants.grid[3] = mHeightRange + 1.0f;
    constants.gridSize[0] = static_cast<float>(mCellsAcross);
    constants.gridSize[1] = static_cast<float>(mCellsDown);
    gpg::gal::GpuDispatch bake{};
    bake.program = mBake.get();
    bake.bindings.constants = &constants;
    bake.bindings.constantBytes = sizeof(constants);
    bake.bindings.readBuffers[1] = mHeights.get();
    bake.bindings.writeBuffers[1] = mSunHeights.get();
    bake.groupsX = (mCellsAcross + 7U) / 8U;
    bake.groupsY = (mCellsDown + 7U) / 8U;
    mDevice->DispatchGpuProgram(bake);
    gpg::Logf(
      "Atmosphere: sun heights baked, %ux%u cells over a %dx%d heightfield, low ground %.1f, height range %.1f "
      "(ren_Atmosphere)",
      mCellsAcross,
      mCellsDown,
      mFieldWidth,
      mFieldHeight,
      mLowGround,
      mHeightRange
    );
    mBaked = true;
    return true;
  }

  void Atmosphere::Render(
    const GeomCamera3& camera,
    const float focus,
    const int x,
    const int y,
    const int width,
    const int height
  )
  {
    if (!mSupported || width < 8 || height < 8 || ren_AtmosphereDensity <= 0.0f || ren_AtmosphereMax <= 0.0f) {
      return;
    }
    IWldTerrainRes* const terrain = REN_GetTerrainRes();
    if (terrain == nullptr) {
      return;
    }
    Wm3::Vector3f sun = terrain->GetSunDirection();
    sun.Normalize();
    const float sunDirection[3] = {sun.X(), sun.Y(), sun.Z()};
    if (!PrepareSunHeights(sunDirection)) {
      return;
    }

    const auto samplesAcross = static_cast<std::uint32_t>(width + 1) / 2U;
    const auto samplesDown = static_cast<std::uint32_t>(height + 1) / 2U;
    const std::uint32_t needed = samplesAcross * samplesDown;
    if (mTerms == nullptr || needed > mTermCapacity) {
      gpg::gal::GpuBufferDesc desc{};
      desc.name = "AtmosphereTerms";
      desc.stride = 4U * sizeof(float);
      desc.capacity = needed * 2U;
      desc.shaderWrite = true;
      mTerms = mDevice->CreateGpuBuffer(desc);
      mTermCapacity = (mTerms != nullptr) ? needed : 0U;
      if (mTerms == nullptr) {
        return;
      }
    }

    const bool water = terrain->IsWaterEnabled();
    const float waterLevel = terrain->GetWaterElevation();
    const float fogHeight = std::max(ren_AtmosphereFogHeight, 0.5f);
    const float base = water ? std::max(mLowGround, waterLevel) : mLowGround;
    const float multiplier = std::max(terrain->GetLightingMultiplier(), 0.0f);
    const Wm3::Vector3f sunColor = terrain->GetSunColor();
    const Wm3::Vector3f ambience = terrain->GetSunAmbience();

    AtmosphereConstants constants{};
    constants.inverseViewProjection = camera.inverseViewProjection;
    constants.viewRect[0] = static_cast<float>(x);
    constants.viewRect[1] = static_cast<float>(y);
    constants.viewRect[2] = static_cast<float>(width);
    constants.viewRect[3] = static_cast<float>(height);
    constants.bufferSize[0] = static_cast<float>(samplesAcross);
    constants.bufferSize[1] = static_cast<float>(samplesDown);
    constants.bufferSize[2] = 1.0f / static_cast<float>(samplesAcross);
    constants.bufferSize[3] = 1.0f / static_cast<float>(samplesDown);
    constants.eye[0] = camera.inverseView.r[3].x;
    constants.eye[1] = camera.inverseView.r[3].y;
    constants.eye[2] = camera.inverseView.r[3].z;
    constants.eye[3] = std::max(ren_AtmosphereReach, 1.0f);
    constants.sun[0] = sunDirection[0];
    constants.sun[1] = sunDirection[1];
    constants.sun[2] = sunDirection[2];
    constants.sun[3] = std::max(ren_AtmosphereShafts, 0.0f);
    constants.sunColor[0] = sunColor.X() * multiplier * kLightScale;
    constants.sunColor[1] = sunColor.Y() * multiplier * kLightScale;
    constants.sunColor[2] = sunColor.Z() * multiplier * kLightScale;
    constants.sunColor[3] = 0.4f; // Henyey-Greenstein g: mostly forward, so looking towards the sun the haze glows
    constants.ambient[0] = std::max(ambience.X(), 0.0f) + 0.25f * sunColor.X() * multiplier * kLightScale;
    constants.ambient[1] = std::max(ambience.Y(), 0.0f) + 0.25f * sunColor.Y() * multiplier * kLightScale;
    constants.ambient[2] = std::max(ambience.Z(), 0.0f) + 0.25f * sunColor.Z() * multiplier * kLightScale;
    constants.ambient[3] = std::clamp(ren_AtmosphereMax, 0.0f, 1.0f);
    constants.fog[0] = ren_AtmosphereDensity;
    constants.fog[1] = base;
    constants.fog[2] = fogHeight;
    constants.fog[3] = base + fogHeight * 6.0f; // the density is under 1/400 of the base's above it
    constants.grid[0] = static_cast<float>(mFieldWidth);
    constants.grid[1] = static_cast<float>(mFieldHeight);
    constants.grid[2] = static_cast<float>(mCellSize);
    constants.grid[3] = mHeightRange + 1.0f;
    constants.gridSize[0] = static_cast<float>(mCellsAcross);
    constants.gridSize[1] = static_cast<float>(mCellsDown);
    constants.gridSize[2] = water ? waterLevel : -1.0e9f;
    constants.gridSize[3] = static_cast<float>(std::clamp(ren_AtmosphereSteps, 4, 64));
    // Clear up to three quarters of the way to the camera's focus, then in over one focus distance.
    constants.range[0] = std::max(focus, 1.0f) * std::max(ren_AtmosphereClear, 0.0f);
    constants.range[1] = std::max(focus, 1.0f);

    gpg::gal::GpuDispatch dispatch{};
    dispatch.program = mCompute.get();
    dispatch.bindings.constants = &constants;
    dispatch.bindings.constantBytes = sizeof(constants);
    dispatch.bindings.writeBuffers[0] = mTerms.get();
    dispatch.bindings.readBuffers[1] = mHeights.get();
    dispatch.bindings.readBuffers[2] = mSunHeights.get();
    dispatch.bindings.readBoundDepth = true;
    dispatch.groupsX = (samplesAcross + 7U) / 8U;
    dispatch.groupsY = (samplesDown + 7U) / 8U;
    mDevice->DispatchGpuProgram(dispatch);

    gpg::gal::GpuDrawCall draw{};
    draw.program = mComposite.get();
    draw.bindings.constants = &constants;
    draw.bindings.constantBytes = sizeof(constants);
    draw.bindings.readBuffers[0] = mTerms.get();
    draw.vertexCountPerInstance = 3U;
    draw.instanceCount = 1U;
    mDevice->DrawGpuProgram(draw);
  }
} // namespace moho
