#include "moho/terrain/water/HighFidelityWater.h"
#include "moho/render/WRenViewport.h"

#include <algorithm>
#include <cmath>
#include <cstdint>

#include "gpg/core/utils/Global.h"
#include "gpg/gal/EffectVariable.hpp"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DIndexSheet.h"
#include "moho/render/d3d/CD3DVertexSheet.h"
#include "moho/render/ID3DVertexStream.h"
#include "moho/render/textures/CD3DDynamicTextureSheet.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/CWldSession.h"
#include "moho/terrain/water/CWaterShaderProperties.h"
#include "moho/terrain/water/RiverFlowBind.h"
#include "moho/terrain/water/WaterBanksBind.h"
#include "moho/terrain/water/WaterBodySurfaces.h"
#include "moho/terrain/water/WaterQuality.h"
#include "moho/terrain/water/WaterShaderVars.h"
#include "moho/terrain/water/WaterSimulation.h"

namespace
{
  template <typename T>
  void DeleteOwned(
    T*& lane
  ) noexcept
  {
    if (lane == nullptr) {
      return;
    }

    delete lane;
    lane = nullptr;
  }
} // namespace

namespace moho
{
  namespace
  {
    constexpr float kDisabledWaterElevation = -10000.0f;
    constexpr std::uint32_t kVertexSheetUsageToken = 0;
    constexpr int kHighFidelityWaterVertexFormatToken = 3;
    constexpr int kHighFidelityWaterVertexCount = 4;
    constexpr int kHighFidelityWaterIndexCount = 6;
    constexpr std::int32_t kTriangleListPrimitiveToken = 4;
    constexpr int kFresnelLookupTextureSize = 128;
    constexpr int kFresnelLookupTextureFormatToken = 17;
    constexpr float kFresnelLookupInvDimensionMinusOne = 1.0f / 127.0f;

    // The projected grid of the wave simulation (WaterSimulation.h): vertices that only carry their screen position (u,
    // v), 255 x 255 of them, the most the 16-bit indices reach (65,025 of 65,536).
    constexpr int kGridSide = 255;
    CD3DVertexSheet* gGridVertexSheet = nullptr;
    CD3DIndexSheet* gGridIndexSheet = nullptr;

    struct HighFidelityWaterVertex
    {
      float x;
      float y;
      float z;
      float u;
      float v;
    };

    static_assert(sizeof(HighFidelityWaterVertex) == 0x14, "HighFidelityWaterVertex size must be 0x14");

    struct WaterExtents2D
    {
      float x;
      float z;
    };

    [[nodiscard]] WaterExtents2D GetWaterMapExtents(
      const IWldTerrainRes& terrainResource
    )
    {
      const CHeightField* const field = terrainResource.mMap->mHeightField.get();
      const float halfWidth = static_cast<float>((field->width - 1) >> 1);
      const float halfHeight = static_cast<float>((field->height - 1) >> 1);
      return {halfWidth * 2.0f, halfHeight * 2.0f};
    }

    // Builds the projected grid once (and again after a device reset released it). A vertex's position is (u, 0, v) and
    // its uv (u, v): the water vertex shader reads the uv as the place on the screen.
    bool EnsureWaterGrid()
    {
      if (gGridVertexSheet != nullptr && gGridIndexSheet != nullptr) {
        return true;
      }
      ID3DDeviceResources* const resources = D3D_GetDevice()->GetResources();
      CD3DVertexFormat* const vertexFormat = resources->GetVertexFormat(kHighFidelityWaterVertexFormatToken);
      if (vertexFormat == nullptr) {
        return false;
      }
      DeleteOwned(gGridVertexSheet);
      DeleteOwned(gGridIndexSheet);
      gGridVertexSheet = resources->NewVertexSheet(kVertexSheetUsageToken, kGridSide * kGridSide, vertexFormat);
      gGridIndexSheet = resources->CreateIndexSheet(false, (kGridSide - 1) * (kGridSide - 1) * 6);
      if (gGridVertexSheet == nullptr || gGridIndexSheet == nullptr) {
        DeleteOwned(gGridVertexSheet);
        DeleteOwned(gGridIndexSheet);
        return false;
      }
      ID3DVertexStream* const stream = gGridVertexSheet->GetVertStream(0U);
      auto* const vertices =
        static_cast<HighFidelityWaterVertex*>(stream->Lock(0, kGridSide * kGridSide, false, false));
      for (int z = 0; z < kGridSide; ++z) {
        for (int x = 0; x < kGridSide; ++x) {
          const float u = static_cast<float>(x) / static_cast<float>(kGridSide - 1);
          const float v = static_cast<float>(z) / static_cast<float>(kGridSide - 1);
          vertices[z * kGridSide + x] = {u, 0.0f, v, u, v};
        }
      }
      stream->Unlock();
      std::int16_t* const indices = gGridIndexSheet->Lock(0U, gGridIndexSheet->GetSize(), true, false);
      int at = 0;
      for (int z = 0; z + 1 < kGridSide; ++z) {
        for (int x = 0; x + 1 < kGridSide; ++x) {
          const auto i0 = static_cast<std::int16_t>(z * kGridSide + x);
          const auto i1 = static_cast<std::int16_t>(z * kGridSide + x + 1);
          const auto i2 = static_cast<std::int16_t>((z + 1) * kGridSide + x);
          const auto i3 = static_cast<std::int16_t>((z + 1) * kGridSide + x + 1);
          indices[at++] = i0;
          indices[at++] = i2;
          indices[at++] = i1;
          indices[at++] = i1;
          indices[at++] = i2;
          indices[at++] = i3;
        }
      }
      gGridIndexSheet->Unlock();
      return true;
    }

    void SetShaderVarMem(
      ShaderVar& shaderVar,
      const std::uint32_t floatCount,
      const float* const values
    )
    {
      if (shaderVar.Exists()) {
        shaderVar.mEffectVariable->SetFloatArray(floatCount, values);
      }
    }

    void BindTextureShaderVar(
      ShaderVar& shaderVar,
      const std::shared_ptr<ID3DTextureSheet>& texture
    )
    {
      shaderVar.GetTexture(std::static_pointer_cast<CD3DDynamicTextureSheet>(texture));
    }

    /**
     * Address: 0x00810EF0 (sub_810EF0)
     *
     * What it does:
     * Builds one 128x128 two-lane Fresnel lookup texture from the supplied
     * water shader scalars and returns one retained sheet handle.
     */
    [[nodiscard]] std::shared_ptr<CD3DDynamicTextureSheet> BuildFresnelLookupTexture(
      const float fresnelBias,
      const float fresnelPower,
      const float sunShininess,
      const float sunReflectionAmount
    )
    {
      ID3DDeviceResources::DynamicTextureSheetHandle lookupTexture{};
      ID3DDeviceResources* const resources = D3D_GetDevice()->GetResources();
      (void)resources->CreateDynamicTextureSheet2(
        lookupTexture, kFresnelLookupTextureSize, kFresnelLookupTextureSize, kFresnelLookupTextureFormatToken
      );

      std::uint32_t pitchBytes = 0U;
      void* lockBits = nullptr;
      if (!lookupTexture || !lookupTexture->Lock(&pitchBytes, &lockBits)) {
        gpg::Die("Warning, Couldn't lock fresnel lookup texture.  Make sure your video drivers are up to date");
      }

      const std::uint32_t rowAdvanceBytes = 8U * (pitchBytes >> 3U);
      auto* row = static_cast<float*>(lockBits);
      for (int rowIndex = 0; rowIndex < kFresnelLookupTextureSize; ++rowIndex) {
        const float incidence = static_cast<float>(rowIndex) * kFresnelLookupInvDimensionMinusOne;
        float* write = row;

        for (int columnIndex = 0; columnIndex < kFresnelLookupTextureSize; ++columnIndex) {
          const float reflectionBlend =
            (static_cast<float>(columnIndex) * kFresnelLookupInvDimensionMinusOne) * fresnelBias;
          const float fresnelTerm =
            reflectionBlend + ((1.0f - reflectionBlend) * static_cast<float>(std::pow(1.0f - incidence, fresnelPower)));
          const float reflectionFactor = std::clamp(fresnelTerm, 0.0f, 1.0f);
          const float highlightFactor = static_cast<float>(std::pow(incidence, sunShininess));

          write[0] = reflectionFactor;
          write[1] = (reflectionFactor * highlightFactor) * sunReflectionAmount;
          write += 2;
        }

        row = reinterpret_cast<float*>(reinterpret_cast<std::uint8_t*>(row) + rowAdvanceBytes);
      }

      lookupTexture->Unlock();
      return lookupTexture;
    }

    // Engine addition (ren_WaterDetail): water_hd.fx's noise texture (`WaterHdNoise`), 256x256 8-bit RGBA, the
    // format the terrain's noise fill uses. One per process, released with the Fresnel lookup texture in Destroy().
    constexpr int kWaterHdNoiseTextureSize = 256;
    constexpr int kWaterHdNoiseTextureFormat = 2;
    std::shared_ptr<ID3DTextureSheet> sWaterHdNoiseTexture{};

    /** A 32-bit integer hash (Chris Wellons' lowbias32): every input bit changes about half the output bits. */
    [[nodiscard]] constexpr std::uint32_t WaterHdNoiseHash(
      std::uint32_t value
    ) noexcept
    {
      value ^= value >> 16U;
      value *= 0x7FEB352DU;
      value ^= value >> 15U;
      value *= 0x846CA68BU;
      value ^= value >> 16U;
      return value;
    }

    /**
     * Engine addition (ren_WaterDetail): fills the tiling noise texture water_hd.fx reads for its caustics,
     * sparkles and foam, four independent random bytes per texel from a fixed hash of the texel's index (the same
     * pattern on every machine). The shader reads it with filtering at a smoothstep-remapped position, which gives
     * the smooth value noise that hashing four lattice corners per pixel gave, for one texture read.
     */
    [[nodiscard]] std::shared_ptr<ID3DTextureSheet> BuildWaterHdNoiseTexture()
    {
      ID3DDeviceResources::DynamicTextureSheetHandle noiseTexture{};
      ID3DDeviceResources* const resources = D3D_GetDevice()->GetResources();
      (void)resources->CreateDynamicTextureSheet2(
        noiseTexture, kWaterHdNoiseTextureSize, kWaterHdNoiseTextureSize, kWaterHdNoiseTextureFormat
      );

      std::uint32_t pitchBytes = 0U;
      void* lockBits = nullptr;
      if (!noiseTexture || !noiseTexture->Lock(&pitchBytes, &lockBits)) {
        return {};
      }

      auto* row = static_cast<std::uint8_t*>(lockBits);
      for (int rowIndex = 0; rowIndex < kWaterHdNoiseTextureSize; ++rowIndex) {
        for (int columnIndex = 0; columnIndex < kWaterHdNoiseTextureSize; ++columnIndex) {
          const auto texel = static_cast<std::uint32_t>(rowIndex * kWaterHdNoiseTextureSize + columnIndex);
          const std::uint32_t random = WaterHdNoiseHash(texel * 0x9E3779B9U + 0x5BD1E995U);
          std::uint8_t* const write = row + static_cast<std::size_t>(columnIndex) * 4U;
          write[0] = static_cast<std::uint8_t>(random);
          write[1] = static_cast<std::uint8_t>(random >> 8U);
          write[2] = static_cast<std::uint8_t>(random >> 16U);
          write[3] = static_cast<std::uint8_t>(random >> 24U);
        }
        row += pitchBytes;
      }

      noiseTexture->Unlock();
      return std::static_pointer_cast<ID3DTextureSheet>(noiseTexture);
    }

    /**
     * Address: 0x00810EA0 (sub_810EA0)
     *
     * What it does:
     * Updates the shared `water2` world-to-view and projection matrix lanes
     * from the active camera.
     */
    void ApplyWater2CameraMatrices(
      const GeomCamera3& camera
    )
    {
      GetWater2WorldToViewShaderVar().SetMatrix4x4(&camera.view);
      GetWater2ProjectionShaderVar().SetMatrix4x4(&camera.projection);
    }
  } // namespace

  /**
   * Address: 0x008101E0 (??0HighFidelityWater@Moho@@QAE@@Z)
   * Mangled: ??0HighFidelityWater@Moho@@QAE@@Z
   *
   * What it does:
   * Initializes high-fidelity water runtime lanes to an empty state.
   */
  HighFidelityWater::HighFidelityWater() = default;

  /**
   * Address: 0x00810300 (FUN_00810300, Moho::HighFidelityWater::InitVerts)
   *
   * What it does:
   * Builds one high-fidelity water quad vertex/index-sheet pair from the
   * current terrain map extents and water elevation.
   */
  bool HighFidelityWater::InitVerts(
    IWldTerrainRes* const terrainResource
  )
  {
    mTerrainRes = terrainResource;
    STIMap* const terrainMap = terrainResource->mMap;
    mWaterElevation = terrainMap->mWaterEnabled != 0 ? terrainMap->mWaterElevation : kDisabledWaterElevation;

    ID3DDeviceResources* const resources = D3D_GetDevice()->GetResources();

    CD3DVertexFormat* const vertexFormat = resources->GetVertexFormat(kHighFidelityWaterVertexFormatToken);
    if (vertexFormat == nullptr) {
      gpg::Die("CRenWater::InitVerts: Unable to create vertex format");
    }

    CD3DVertexSheet* const nextVertexSheet =
      resources->NewVertexSheet(kVertexSheetUsageToken, kHighFidelityWaterVertexCount, vertexFormat);
    if (nextVertexSheet != mVertexSheet) {
      DeleteOwned(mVertexSheet);
      mVertexSheet = nextVertexSheet;
    }
    if (mVertexSheet == nullptr) {
      gpg::Die("CRenWater::InitVerts: Unable to create vertex sheet");
    }

    const WaterExtents2D mapExtents = GetWaterMapExtents(*terrainResource);
    ID3DVertexStream* const vertexStream = mVertexSheet->GetVertStream(0U);
    const int vertexCount = mVertexSheet->Func5();
    auto* const vertices = static_cast<HighFidelityWaterVertex*>(vertexStream->Lock(0, vertexCount, false, false));

    vertices[0] = {0.0f, mWaterElevation, 0.0f, 0.0f, 0.0f};
    vertices[1] = {mapExtents.x, mWaterElevation, 0.0f, 1.0f, 0.0f};
    vertices[2] = {0.0f, mWaterElevation, mapExtents.z, 0.0f, 1.0f};
    vertices[3] = {mapExtents.x, mWaterElevation, mapExtents.z, 1.0f, 1.0f};

    vertexStream->Unlock();

    CD3DIndexSheet* const nextIndexSheet = resources->CreateIndexSheet(false, kHighFidelityWaterIndexCount);
    if (nextIndexSheet != mIndexSheet) {
      DeleteOwned(mIndexSheet);
      mIndexSheet = nextIndexSheet;
    }
    if (mIndexSheet == nullptr) {
      gpg::Die("CRenWater::InitVerts: Unable to create index sheet");
    }

    const std::uint32_t indexCount = mIndexSheet->GetSize();
    std::int16_t* const indices = mIndexSheet->Lock(0U, indexCount, true, false);
    indices[0] = 0;
    indices[1] = 2;
    indices[2] = 1;
    indices[3] = 1;
    indices[4] = 2;
    indices[5] = 3;
    mIndexSheet->Unlock();

    return true;
  }

  /**
   * Address: 0x00810540 (FUN_00810540, Moho::HighFidelityWater::Func1)
   * Mangled: ?Func1@HighFidelityWater@Moho@@QAEXXZ
   *
   * What it does:
   * Clears the cached runtime state used by the high-fidelity water render
   * path, including both shared texture handles and owned render sheets.
   */
  void HighFidelityWater::Destroy()
  {
    mFresnelLookupTexture.reset();
    // Engine addition (ren_WaterDetail): rebuilt on the next detailed-water draw.
    sWaterHdNoiseTexture.reset();
    DeleteOwned(gGridVertexSheet);
    DeleteOwned(gGridIndexSheet);
    DeleteOwned(mVertexSheet);
    DeleteOwned(mIndexSheet);
    mWaterMapTexture.reset();
    mTerrainRes = nullptr;
  }

  /**
   * Address: 0x008105E0 (FUN_008105E0, Moho::HighFidelityWater::Func2)
   *
   * What it does:
   * Binds `water2/TWaterLayAlphaMask`, updates camera matrices, binds utility
   * texture C from the terrain resource, and renders the cached water quad.
   */
  bool HighFidelityWater::RenderWaterLayerAlphaMask(
    const GeomCamera3* const camera
  )
  {
    ApplyWater2CameraMatrices(*camera);

    CD3DDevice* const device = D3D_GetDevice();
    device->SelectFxFile("water2");
    device->SelectTechnique("TWaterLayAlphaMask");

    IWldTerrainRes* const terrainRes = mTerrainRes;
    std::shared_ptr<CD3DDynamicTextureSheet> utilityTexture =
      std::static_pointer_cast<CD3DDynamicTextureSheet>(terrainRes->GetWaterMap());
    GetWater2UtilityTextureCShaderVar().GetTexture(utilityTexture);

    std::int32_t primitiveType = kTriangleListPrimitiveToken;
    // Engine addition (water bodies): the mask is laid at each water's own level. FAF (banks): the mask of a lake or
    // a river is the depth test alone, so its edge is where the surface meets the ground (docs/WATER_SIMULATION.md,
    // "Banks"); the sea's is the shipped one.
    if (const auto* const levels = WaterBodySurfaces::For(terrainRes); levels != nullptr) {
      bool drawn = true;
      for (const WaterBodySurfaces::Level& level : *levels) {
        GetWater2WaterElevationShaderVar().SetFloat(level.elevation);
        water::BindBankMask(!level.sea);
        for (const WaterBodySurfaces::Chunk& chunk : level.chunks) {
          drawn = device->DrawIndexedSheetPrimitive(chunk.vertices, chunk.indices, &primitiveType) && drawn;
        }
      }
      water::BindBankMask(false);
      return drawn;
    }
    return device->DrawIndexedSheetPrimitive(mVertexSheet, mIndexSheet, &primitiveType);
  }

  /**
   * Address: 0x008106D0 (FUN_008106D0, Moho::HighFidelityWater::Func3)
   *
   * What it does:
   * Binds `water2/TWater`, updates water uniforms/textures from camera and
   * runtime shader properties, refreshes cached Fresnel lookup state when the
   * controlling lanes change, and draws the high-fidelity water sheet.
   */
  bool HighFidelityWater::RenderWaterSurface(
    const std::int32_t tick,
    const float tickLerp,
    const GeomCamera3* const camera,
    const CWaterShaderProperties* const shaderProperties,
    const std::shared_ptr<ID3DRenderTarget>& refractionTexture,
    const std::shared_ptr<ID3DRenderTarget>& reflectionTexture
  )
  {
    CD3DDevice* const device = D3D_GetDevice();
    device->SelectFxFile("water2");
    device->SelectTechnique("TWater");

    ApplyWater2CameraMatrices(*camera);

    const float viewPosition[3] = {
      camera->inverseView.r[3].x,
      camera->inverseView.r[3].y,
      camera->inverseView.r[3].z,
    };
    SetShaderVarMem(GetWater2ViewPositionShaderVar(), 3U, viewPosition);
    GetWater2WaterElevationShaderVar().SetFloat(mWaterElevation);

    BindTextureShaderVar(GetWater2SkyMapShaderVar(), shaderProperties->GetCubeMap());
    BindTextureShaderVar(GetWater2NormalMap0ShaderVar(), shaderProperties->GetNormalMap(0));
    BindTextureShaderVar(GetWater2NormalMap1ShaderVar(), shaderProperties->GetNormalMap(1));
    BindTextureShaderVar(GetWater2NormalMap2ShaderVar(), shaderProperties->GetNormalMap(2));
    BindTextureShaderVar(GetWater2NormalMap3ShaderVar(), shaderProperties->GetNormalMap(3));
    BindTextureShaderVar(GetWater2WaterRampShaderVar(), shaderProperties->GetWaterRamp());

    GetWater2RefractionMapShaderVar().SetRenderTargetTexture(refractionTexture);
    GetWater2ReflectionMapShaderVar().SetRenderTargetTexture(reflectionTexture);
    GetWater2TimeShaderVar().SetFloat(static_cast<float>(tick) + tickLerp);
    water::BindShaderParams(); // FAF: the filter tap counts of the patched effect (docs/WATER_SIMULATION.md)

    const WaterShaderNumericState& shaderState = shaderProperties->mNumericState;
    if (
      mCachedFresnelBias != shaderState.mFresnelBias || mCachedFresnelPower != shaderState.mFresnelPower ||
      mCachedSunShininess != shaderState.mSunShininess ||
      mCachedSunReflectionAmount != shaderState.mSunReflectionAmount || mFresnelLookupTexture.get() == nullptr
    ) {
      const auto fresnelLookupTexture = BuildFresnelLookupTexture(
        shaderState.mFresnelBias, shaderState.mFresnelPower, shaderState.mSunShininess, shaderState.mSunReflectionAmount
      );
      mFresnelLookupTexture = std::static_pointer_cast<ID3DTextureSheet>(fresnelLookupTexture);

      mCachedFresnelBias = shaderState.mFresnelBias;
      mCachedFresnelPower = shaderState.mFresnelPower;
      mCachedSunShininess = shaderState.mSunShininess;
      mCachedSunReflectionAmount = shaderState.mSunReflectionAmount;
    }

    BindTextureShaderVar(GetWater2FresnelLookupShaderVar(), mFresnelLookupTexture);

    SetShaderVarMem(GetWater2WaterColorShaderVar(), 3U, shaderState.mWaterColor);
    SetShaderVarMem(GetWater2WaterLerpShaderVar(), 2U, shaderState.mWaterLerp);
    GetWater2RefractionScaleShaderVar().SetFloat(shaderState.mRefractionScale);
    GetWater2FresnelBiasShaderVar().SetFloat(shaderState.mFresnelBias);
    GetWater2FresnelPowerShaderVar().SetFloat(shaderState.mFresnelPower);
    GetWater2UnitReflectionAmountShaderVar().SetFloat(shaderState.mUnitReflectionAmount);
    GetWater2SkyReflectionAmountShaderVar().SetFloat(shaderState.mSkyReflectionAmount);
    SetShaderVarMem(GetWater2NormalRepeatRateShaderVar(), 4U, shaderState.mNormalRepeatRate);
    SetShaderVarMem(GetWater2Normal1MovementShaderVar(), 2U, shaderState.mNormal1Movement);
    SetShaderVarMem(GetWater2Normal2MovementShaderVar(), 2U, shaderState.mNormal2Movement);
    SetShaderVarMem(GetWater2Normal3MovementShaderVar(), 2U, shaderState.mNormal3Movement);
    SetShaderVarMem(GetWater2Normal4MovementShaderVar(), 2U, shaderState.mNormal4Movement);
    GetWater2SunShininessShaderVar().SetFloat(shaderState.mSunShininess);
    GetWater2SunReflectionAmountShaderVar().SetFloat(shaderState.mSunReflectionAmount);
    SetShaderVarMem(GetWater2SunDirectionShaderVar(), 3U, shaderState.mSunDirection);

    const float sunColor[3] = {
      shaderState.mSunColor[0] * shaderState.mSunReflectionAmount,
      shaderState.mSunColor[1] * shaderState.mSunReflectionAmount,
      shaderState.mSunColor[2] * shaderState.mSunReflectionAmount,
    };
    SetShaderVarMem(GetWater2SunColorShaderVar(), 3U, sunColor);
    GetWater2SunGlowShaderVar().SetFloat(shaderState.mSunGlow);
    // Engine addition (ren_WaterDetail): which water the pass draws; the effect has the switch only where
    // water_hd.fx is appended (Direct3D 12 and Vulkan), elsewhere this does nothing.
    GetWater2WaterHdEnabledShaderVar().SetFloat(ren_WaterDetail ? 1.0f : 0.0f);
    if (ren_WaterDetail && GetWater2WaterHdNoiseShaderVar().Exists()) {
      if (!sWaterHdNoiseTexture) {
        sWaterHdNoiseTexture = BuildWaterHdNoiseTexture();
      }
      BindTextureShaderVar(GetWater2WaterHdNoiseShaderVar(), sWaterHdNoiseTexture);
    }

    // 0x00810D6C: `mov eax, [sWldMap]`, the map the renderer draws (a session's, or the map editor's).
    IWldTerrainRes* const terrainRes = REN_GetTerrainRes();
    const CHeightField* const heightField = terrainRes->mMap->mHeightField.get();
    const float terrainScale[4] = {
      1.0f / static_cast<float>(heightField->width - 1),
      -1.0f / static_cast<float>(heightField->height - 1),
      0.0f,
      1.0f,
    };
    (void)SetWater2TerrainScaleShaderVarData(terrainScale);

    std::int32_t primitiveType = kTriangleListPrimitiveToken;
    // FAF: with the wave simulation the surface of a map without water bodies is the projected grid (the waves lift its
    // vertices). The call also switches the grid off for the draws below when there is none (it keeps the last value
    // otherwise); a map with water bodies draws one water at a time (below): the projected grid of the water where it
    // is near enough, else the meshes of WaterBodySurfaces, and the ripples bend the normals of both
    // (docs/WATER_SIMULATION.md, "Water bodies").
    const WaterExtents2D gridExtents = GetWaterMapExtents(*mTerrainRes);
    const bool projectedGrid = water::BindWaterGrid(*camera, gridExtents.x, gridExtents.z) && EnsureWaterGrid();
    // Engine addition (water bodies): each water at its own level. Only the sea samples the
    // planar reflection, which is mirrored at the sea; a body samples its own (see ReflectionFor).
    if (const auto* const levels = WaterBodySurfaces::For(mTerrainRes); levels != nullptr) {
      bool drawn = true;
      // FAF: the projected grid of each water (the waves lift it), clipped to the blocks the water owns, in the part of
      // the screen that holds the water; the meshes where there is no grid (switched off, off the screen, further
      // waters than the cap of a frame)
      const std::shared_ptr<ID3DTextureSheet> owner =
        std::static_pointer_cast<ID3DTextureSheet>(WaterBodySurfaces::OwnerTexture(mTerrainRes));
      const bool gridSheet = owner != nullptr && EnsureWaterGrid();
      // FAF (rivers): the flow of the map's rivers; a river is drawn as its own mesh (the sloped surface, the vertices
      // keep their heights), never as a grid, and never mirrors at a plane (docs/projects/RIVERS.md)
      water::BindRiverFlow(mTerrainRes);
      for (const WaterBodySurfaces::Level& level : *levels) {
        GetWater2WaterElevationShaderVar().SetFloat(level.elevation);
        GetWater2ReflectionMapShaderVar().SetRenderTargetTexture(
          level.sea
            ? reflectionTexture
            : (level.river ? WaterBodySurfaces::EmptyReflection() : WaterBodySurfaces::ReflectionFor(level.elevation))
        );
        if (level.river) {
          water::BindWaterGridLevelOff();
          water::BindRiverMesh(true);
          for (const WaterBodySurfaces::Chunk& chunk : level.chunks) {
            drawn = device->DrawIndexedSheetPrimitive(chunk.vertices, chunk.indices, &primitiveType) && drawn;
          }
          water::BindRiverMesh(false);
          continue;
        }
        water::GridLevel grid;
        grid.elevation = level.elevation;
        grid.body = level.body;
        grid.x0 = level.x0;
        grid.z0 = level.z0;
        grid.x1 = level.x1;
        grid.z1 = level.z1;
        grid.extentX = gridExtents.x;
        grid.extentZ = gridExtents.z;
        grid.sheetReady = gridSheet;
        if (water::BindWaterGridLevel(*camera, grid, owner)) {
          drawn = device->DrawIndexedSheetPrimitive(gGridVertexSheet, gGridIndexSheet, &primitiveType) && drawn;
          continue;
        }
        for (const WaterBodySurfaces::Chunk& chunk : level.chunks) {
          drawn = device->DrawIndexedSheetPrimitive(chunk.vertices, chunk.indices, &primitiveType) && drawn;
        }
      }
      water::EndWaterGridLevels();
      return drawn;
    }
    if (projectedGrid) {
      return device->DrawIndexedSheetPrimitive(gGridVertexSheet, gGridIndexSheet, &primitiveType);
    }
    return device->DrawIndexedSheetPrimitive(mVertexSheet, mIndexSheet, &primitiveType);
  }

  /**
   * Address: 0x00810220 (??1HighFidelityWater@Moho@@QAE@@Z)
   * Address: 0x00811100 (FUN_00811100, vtable-slot-2 scalar deleting
   * destructor: tail-calls the body below then conditionally frees the
   * object -- ordinary C++ `delete` semantics, not modeled as a separate
   * function here)
   * Mangled: ??1HighFidelityWater@Moho@@QAE@@Z
   *
   * What it does:
   * Releases retained shared-owner lanes, destroys owned render sheets, and
   * clears the bound terrain-resource lane.
   */
  HighFidelityWater::~HighFidelityWater()
  {
    HighFidelityWater::Destroy();
  }
} // namespace moho
