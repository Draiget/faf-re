#include "moho/render/AmbientOcclusionRenderer.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

#include "gpg/core/utils/Logging.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/DeviceContext.hpp"
#include "gpg/gal/GpuDriven.h"
#include "gpg/gal/effects/ShadowCascades.h"
#include "moho/console/CConCommand.h"
#include "moho/math/VMatrix4.h"
#include "moho/render/AmbientOcclusionShader.h"
#include "moho/render/ID3DRenderTarget.h"
#include "moho/render/Shadow.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/render/d3d/CD3DRenderTarget.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/STIMap.h"
#include "moho/terrain/StratumMaterial.h"

namespace moho
{
  int ren_Ao = -1;
  float ren_AoRadius = 2.0f;
  float ren_AoIntensity = 1.0f;
  float ren_AoBias = 0.25f;
  float ren_AoFadeStart = 120.0f;
  float ren_AoFadeEnd = 260.0f;

  TConVar<int> gTConVar_ren_Ao(
    "ren_Ao",
    "Ambient occlusion from scene depth: 1 on, 0 off, -1 (the default) on Direct3D 12 and Vulkan. "
    "Direct3D 9 and 11 can't read the depth target and keep the original look.",
    &ren_Ao
  );
  TConVar<float> gTConVar_ren_AoRadius("ren_AoRadius", "Ambient occlusion reach in world units.", &ren_AoRadius);
  TConVar<float> gTConVar_ren_AoIntensity("ren_AoIntensity", "Ambient occlusion strength.", &ren_AoIntensity);
  TConVar<float> gTConVar_ren_AoBias(
    "ren_AoBias",
    "How steeply (as a cosine, 0..1) a neighbour must rise above a surface before it occludes it; "
    "keeps the creases between terrain triangles clean.",
    &ren_AoBias
  );
  TConVar<float> gTConVar_ren_AoFadeStart(
    "ren_AoFadeStart", "Camera distance where ambient occlusion starts to fade out.", &ren_AoFadeStart
  );
  TConVar<float> gTConVar_ren_AoFadeEnd("ren_AoFadeEnd", "Camera distance where ambient occlusion is gone.", &ren_AoFadeEnd);

  float ren_AoContact = 0.35f;
  float ren_AoContactLength = 1.5f;
  TConVar<float> gTConVar_ren_AoContact(
    "ren_AoContact",
    "Contact shadow strength, 0 to 1: how much a short ray towards the sun that hits nearby depth darkens "
    "(part of ren_Ao; 0 turns contact shadows off).",
    &ren_AoContact
  );
  TConVar<float> gTConVar_ren_AoContactLength(
    "ren_AoContactLength", "Contact shadow ray length in world units.", &ren_AoContactLength
  );

  float ren_TerrainShadows = 0.45f;
  TConVar<float> gTConVar_ren_TerrainShadows(
    "ren_TerrainShadows",
    "Terrain shadows from the heightfield beyond the shadow map's reach (part of ren_Ao): how much of the sun's "
    "direct light they take, 0 to 1 (0 off). Off on maps that bake their own (stratum 7 terrain info) and when "
    "shadows are off.",
    &ren_TerrainShadows
  );

  // Defined in moho/app/WxRuntimeTypes.cpp (0x007FA170).
  [[nodiscard]] IWldTerrainRes* REN_GetTerrainRes();

  namespace
  {
    struct AoConstants
    {
      VMatrix4 inverseViewProjection;
      float viewRect[4];
      float bufferSize[4];
      float eye[4];
      float radius;
      float intensity;
      float projScale;
      float bias;
      float fadeStart;
      float fadeEnd;
      float unused[2];
      VMatrix4 viewProjection;
      float sun[4];
      float contact[4];
      float terrainGrid[4];
      float terrainShadowSize[4];
      VMatrix4 shadowMatrix;
      float shadowParams[4];
      float shadowCascades[gpg::gal::effects::kShadowCascadeVectors][4];
    };
    static_assert(sizeof(AoConstants) == 496, "AoConstants matches the shader's cbuffer");

    /** Terrain-shadow cells across the larger side of the map at most. */
    constexpr std::int32_t kTerrainShadowCells = 1024;

    [[nodiscard]] bool BackendReadsBoundDepth(gpg::gal::Device& device)
    {
      const gpg::gal::DeviceContext* const context = device.GetDeviceContext();
      return context != nullptr
        && (context->mDeviceType == gpg::gal::DeviceApi::Direct3D12 || context->mDeviceType == gpg::gal::DeviceApi::Vulkan);
    }
  } // namespace

  AmbientOcclusionRenderer& AmbientOcclusionRenderer::Get()
  {
    static AmbientOcclusionRenderer sRenderer;
    return sRenderer;
  }

  bool AmbientOcclusionRenderer::IsActive()
  {
    if (ren_Ao == 0) {
      return false;
    }
    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    if (device == nullptr) {
      return false;
    }
    if (device != mDevice) {
      *this = AmbientOcclusionRenderer();
      mDevice = device;
      constexpr std::uint32_t kNeeded = gpg::gal::kGpuFeatureVertexPulling | gpg::gal::kGpuFeatureCompute;
      if (BackendReadsBoundDepth(*device) && (device->GetGpuDrivenFeatures() & kNeeded) == kNeeded) {
        gpg::gal::GpuProgramDesc compute{};
        compute.name = "AmbientOcclusion";
        compute.source = kAmbientOcclusionShaderSource;
        compute.sourceBytes = sizeof(kAmbientOcclusionShaderSource) - 1U;
        compute.computeEntry = "AoCS";
        mCompute = device->CreateGpuProgram(compute);

        gpg::gal::GpuProgramDesc bake = compute;
        bake.name = "TerrainShadowBake";
        bake.computeEntry = "TerrainShadowCS";
        mBake = device->CreateGpuProgram(bake);

        gpg::gal::GpuProgramDesc composite{};
        composite.name = "AmbientOcclusionComposite";
        composite.source = kAmbientOcclusionShaderSource;
        composite.sourceBytes = sizeof(kAmbientOcclusionShaderSource) - 1U;
        composite.vertexEntry = "AoCompositeVS";
        composite.pixelEntry = "AoCompositePS";
        composite.blend = gpg::gal::GpuBlend::Multiply;
        composite.colorWriteMask = 0x07U; // alpha is the glow amount and the water mask
        composite.depthTest = false;
        composite.depthWrite = false;
        composite.cullBackFaces = false;
        mComposite = device->CreateGpuProgram(composite);
      }
      mSupported = mCompute != nullptr && mComposite != nullptr;
      if (mSupported) {
        gpg::Logf("Ambient occlusion: on this renderer (ren_Ao)");
      }
    }
    return mSupported;
  }

  bool AmbientOcclusionRenderer::PrepareTerrainShadows(const float sun[3])
  {
    IWldTerrainRes* const terrain = REN_GetTerrainRes();
    if (terrain == nullptr || mBake == nullptr || terrain->mMap == nullptr) {
      return false;
    }
    // A map with a terrain info texture (stratum 7 albedo tile under 1, terrain.fx
    // ShaderUsesTerrainInfoTexture) already darkens its terrain with baked shadows.
    if (terrain->GetStratumMaterial().mStratum7AlbedoTexture.mScaleX < 1.0f) {
      return false;
    }
    CHeightField* const field = terrain->mMap->mHeightField.get();
    if (field == nullptr || field->Width() < 2 || field->Height() < 2) {
      return false;
    }
    if (field == mBakedField && field->Width() == mFieldWidth && field->Height() == mFieldHeight
        && sun[0] == mBakedSun[0] && sun[1] == mBakedSun[1] && sun[2] == mBakedSun[2]) {
      return mTerrainShadow != nullptr;
    }

    mBakedField = field;
    mFieldWidth = field->Width();
    mFieldHeight = field->Height();
    std::copy(sun, sun + 3, mBakedSun);
    mTerrainShadow.reset();

    const std::size_t samples = static_cast<std::size_t>(mFieldWidth) * static_cast<std::size_t>(mFieldHeight);
    std::vector<std::uint32_t> packed((samples + 1U) / 2U, 0U);
    const std::uint16_t* const heights = field->GetArrayAt(0, 0);
    for (std::size_t index = 0; index < samples; ++index) {
      packed[index >> 1U] |= static_cast<std::uint32_t>(heights[index]) << ((index & 1U) * 16U);
    }
    gpg::gal::GpuBufferDesc heightDesc{};
    heightDesc.name = "TerrainShadowHeights";
    heightDesc.stride = sizeof(std::uint32_t);
    heightDesc.capacity = static_cast<std::uint32_t>(packed.size());
    mHeights = mDevice->CreateGpuBuffer(heightDesc);
    if (mHeights == nullptr) {
      return false;
    }
    mDevice->UpdateGpuBuffer(*mHeights, 0U, static_cast<std::uint32_t>(packed.size()), packed.data());

    const std::int32_t larger = std::max(mFieldWidth, mFieldHeight);
    mShadowCellSize = static_cast<std::uint32_t>((larger + kTerrainShadowCells - 1) / kTerrainShadowCells);
    mShadowAcross = (static_cast<std::uint32_t>(mFieldWidth) + mShadowCellSize - 1U) / mShadowCellSize;
    mShadowDown = (static_cast<std::uint32_t>(mFieldHeight) + mShadowCellSize - 1U) / mShadowCellSize;
    gpg::gal::GpuBufferDesc shadowDesc{};
    shadowDesc.name = "TerrainShadow";
    shadowDesc.stride = sizeof(float);
    shadowDesc.capacity = mShadowAcross * mShadowDown;
    shadowDesc.shaderWrite = true;
    mTerrainShadow = mDevice->CreateGpuBuffer(shadowDesc);
    if (mTerrainShadow == nullptr) {
      return false;
    }

    AoConstants constants{};
    constants.sun[0] = sun[0];
    constants.sun[1] = sun[1];
    constants.sun[2] = sun[2];
    constants.terrainGrid[0] = static_cast<float>(mFieldWidth);
    constants.terrainGrid[1] = static_cast<float>(mFieldHeight);
    constants.terrainGrid[2] = static_cast<float>(mShadowCellSize);
    constants.terrainShadowSize[0] = static_cast<float>(mShadowAcross);
    constants.terrainShadowSize[1] = static_cast<float>(mShadowDown);
    gpg::gal::GpuDispatch bake{};
    bake.program = mBake.get();
    bake.bindings.constants = &constants;
    bake.bindings.constantBytes = sizeof(constants);
    bake.bindings.readBuffers[1] = mHeights.get();
    bake.bindings.writeBuffers[1] = mTerrainShadow.get();
    bake.groupsX = (mShadowAcross + 7U) / 8U;
    bake.groupsY = (mShadowDown + 7U) / 8U;
    mDevice->DispatchGpuProgram(bake);
    gpg::Logf("Terrain shadows: baked %ux%u cells over a %dx%d heightfield, sun (%.3f, %.3f, %.3f) (ren_TerrainShadows)",
              mShadowAcross, mShadowDown, mFieldWidth, mFieldHeight, sun[0], sun[1], sun[2]);

    // Diagnostics: FAF_TERRAIN_SHADOW_DUMP=<folder> writes the heightfield, the baked visibility and the sun
    // there, so a CPU march can check the bake cell by cell.
    std::size_t length = 0;
    char folder[512] = {};
    if (::getenv_s(&length, folder, sizeof(folder), "FAF_TERRAIN_SHADOW_DUMP") == 0 && length > 1U) {
      std::vector<float> visibility(static_cast<std::size_t>(mShadowAcross) * mShadowDown);
      if (mDevice->ReadGpuBuffer(*mTerrainShadow, 0U, static_cast<std::uint32_t>(visibility.size()), visibility.data())) {
        const std::string base(folder);
        if (std::FILE* const out = std::fopen((base + "/terrain_shadow.bin").c_str(), "wb")) {
          std::fwrite(visibility.data(), sizeof(float), visibility.size(), out);
          std::fclose(out);
        }
        if (std::FILE* const out = std::fopen((base + "/terrain_heights.bin").c_str(), "wb")) {
          std::fwrite(heights, sizeof(std::uint16_t), samples, out);
          std::fclose(out);
        }
        if (std::FILE* const out = std::fopen((base + "/terrain_meta.txt").c_str(), "w")) {
          std::fprintf(out, "%d %d %u %u %u %.9g %.9g %.9g\n", mFieldWidth, mFieldHeight, mShadowCellSize, mShadowAcross,
                       mShadowDown, sun[0], sun[1], sun[2]);
          std::fclose(out);
        }
        gpg::Logf("Terrain shadows: dumped to %s", folder);
      }
    }
    return true;
  }

  void AmbientOcclusionRenderer::Render(
    const GeomCamera3& camera, const int x, const int y, const int width, const int height, const float shadowReach,
    const Shadow* const shadow
  )
  {
    if (!mSupported || width < 8 || height < 8 || ren_AoRadius <= 0.0f || ren_AoIntensity <= 0.0f) {
      return;
    }
    const auto samplesAcross = static_cast<std::uint32_t>(width + 1) / 2U;
    const auto samplesDown = static_cast<std::uint32_t>(height + 1) / 2U;
    const std::uint32_t needed = samplesAcross * samplesDown;
    if (mTerms == nullptr || needed > mTermCapacity) {
      gpg::gal::GpuBufferDesc desc{};
      desc.name = "AmbientOcclusionTerms";
      desc.stride = 2U * sizeof(float);
      desc.capacity = needed;
      desc.shaderWrite = true;
      mTerms = mDevice->CreateGpuBuffer(desc);
      mTermCapacity = (mTerms != nullptr) ? needed : 0U;
      if (mTerms == nullptr) {
        return;
      }
    }

    AoConstants constants{};
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
    constants.radius = ren_AoRadius;
    constants.intensity = ren_AoIntensity;
    // Half the view's height spans one unit of the projection's y scale; samples are every second pixel.
    constants.projScale = camera.projection.r[1].y * static_cast<float>(height) * 0.25f;
    constants.bias = ren_AoBias;
    constants.fadeStart = ren_AoFadeStart;
    constants.fadeEnd = std::max(ren_AoFadeEnd, ren_AoFadeStart + 1.0f);
    constants.viewProjection = camera.viewProjection;
    if (IWldTerrainRes* const terrain = REN_GetTerrainRes(); terrain != nullptr) {
      Wm3::Vector3f sun = terrain->GetSunDirection();
      sun.Normalize();
      constants.sun[0] = sun.X();
      constants.sun[1] = sun.Y();
      constants.sun[2] = sun.Z();
      if (ren_AoContact > 0.0f) {
        constants.sun[3] = std::min(ren_AoContact, 1.0f);
        constants.contact[0] = std::max(ren_AoContactLength, 0.1f);
        constants.contact[1] = std::max(ren_AoContactLength, 0.1f);
      }
      if (ren_TerrainShadows > 0.0f && shadowReach >= 0.0f && PrepareTerrainShadows(constants.sun)) {
        constants.terrainGrid[0] = static_cast<float>(mFieldWidth);
        constants.terrainGrid[1] = static_cast<float>(mFieldHeight);
        constants.terrainGrid[2] = static_cast<float>(mShadowCellSize);
        constants.terrainGrid[3] = std::min(ren_TerrainShadows, 1.0f);
        constants.terrainShadowSize[0] = static_cast<float>(mShadowAcross);
        constants.terrainShadowSize[1] = static_cast<float>(mShadowDown);
        constants.terrainShadowSize[2] = shadowReach;
      }
    }

    // The sun's shadow texture, so contact shadows leave the points it shades alone.
    ID3DRenderTarget::SurfaceHandle shadowSurface{};
    if (constants.sun[3] > 0.0f && shadow != nullptr && shadow->mShadowCameraValid) {
      if (const boost::shared_ptr<CD3DRenderTarget> shadowTexture = shadow->GetShadowTexture(); shadowTexture) {
        (void)shadowTexture->GetSurface(shadowSurface);
      }
      if (shadowSurface) {
        constants.shadowMatrix = shadow->mCamera.viewProjection;
        constants.shadowParams[0] = 1.0f;
        std::memcpy(constants.shadowCascades, gpg::gal::effects::gShadowCascades.vectors, sizeof(constants.shadowCascades));
      }
    }

    gpg::gal::GpuDispatch dispatch{};
    dispatch.program = mCompute.get();
    dispatch.bindings.constants = &constants;
    dispatch.bindings.constantBytes = sizeof(constants);
    dispatch.bindings.writeBuffers[0] = mTerms.get();
    if (shadowSurface) {
      dispatch.bindings.targets[0] = shadowSurface.get();
    }
    if (constants.terrainGrid[3] > 0.0f) {
      dispatch.bindings.readBuffers[1] = mHeights.get();
      dispatch.bindings.readBuffers[2] = mTerrainShadow.get();
    }
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
