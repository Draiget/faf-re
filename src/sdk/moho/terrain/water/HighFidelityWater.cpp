#include "moho/terrain/water/HighFidelityWater.h"

#include <algorithm>
#include <cmath>
#include <cstdint>

#include "gpg/gal/backends/d3d9/EffectVariableD3D9.hpp"
#include "gpg/core/utils/Global.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/ID3DVertexStream.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DIndexSheet.h"
#include "moho/render/d3d/CD3DVertexSheet.h"
#include "moho/render/textures/CD3DDynamicTextureSheet.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/CWldSession.h"
#include "moho/terrain/water/CWaterShaderProperties.h"
#include "moho/terrain/water/WaterShaderRuntimeView.h"
#include "moho/terrain/water/WaterShaderVars.h"

namespace
{
  template <typename T>
  void DeleteOwned(T*& lane) noexcept
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

    [[nodiscard]] WaterExtents2D GetWaterMapExtents(const TerrainWaterResourceView& terrainResource)
    {
      const TerrainHeightFieldRuntimeView* const field = terrainResource.mMap->mHeightFieldObject;
      const float halfWidth = static_cast<float>((field->width - 1) >> 1);
      const float halfHeight = static_cast<float>((field->height - 1) >> 1);
      return {halfWidth * 2.0f, halfHeight * 2.0f};
    }

    void SetShaderVarMem(ShaderVar& shaderVar, const std::uint32_t floatCount, const float* const values)
    {
      if (shaderVar.Exists()) {
        shaderVar.mEffectVariable->SetMem(floatCount, values);
      }
    }

    void SetShaderVarRawData(ShaderVar& shaderVar, const void* const data, const std::uint32_t byteCount)
    {
      if (shaderVar.Exists()) {
        shaderVar.mEffectVariable->SetPtr(data, byteCount);
      }
    }

    void BindTextureShaderVar(ShaderVar& shaderVar, const boost::shared_ptr<ID3DTextureSheet>& texture)
    {
      shaderVar.GetTexture(boost::static_pointer_cast<CD3DDynamicTextureSheet>(texture));
    }

    /**
     * Address: 0x00810EF0 (sub_810EF0)
     *
     * What it does:
     * Builds one 128x128 two-lane Fresnel lookup texture from the supplied
     * water shader scalars and returns one retained sheet handle.
     */
    [[nodiscard]] boost::shared_ptr<CD3DDynamicTextureSheet> BuildFresnelLookupTexture(
      const float fresnelBias,
      const float fresnelPower,
      const float sunShininess,
      const float sunReflectionAmount
    )
    {
      ID3DDeviceResources::DynamicTextureSheetHandle lookupTexture{};
      ID3DDeviceResources* const resources = D3D_GetDevice()->GetResources();
      (void)resources->CreateDynamicTextureSheet2(
        lookupTexture,
        kFresnelLookupTextureSize,
        kFresnelLookupTextureSize,
        kFresnelLookupTextureFormatToken
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

    /**
     * Address: 0x00810EA0 (sub_810EA0)
     *
     * What it does:
     * Updates the shared `water2` world-to-view and projection matrix lanes
     * from the active camera.
     */
    void ApplyWater2CameraMatrices(const GeomCamera3& camera)
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
  bool HighFidelityWater::InitVerts(TerrainWaterResourceView* const terrainResource)
  {
    mTerrainRes = terrainResource;
    TerrainMapRuntimeView* const terrainMap = terrainResource->mMap;
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
  void HighFidelityWater::ReleaseRenderState()
  {
    mFresnelLookupTexture.release();
    DeleteOwned(mVertexSheet);
    DeleteOwned(mIndexSheet);
    mWaterMapTexture.release();
    mTerrainRes = nullptr;
  }

  /**
   * Address: 0x008105E0 (FUN_008105E0, Moho::HighFidelityWater::Func2)
   *
   * What it does:
   * Binds `water2/TWaterLayAlphaMask`, updates camera matrices, binds utility
   * texture C from the terrain resource, and renders the cached water quad.
   */
  bool HighFidelityWater::RenderWaterLayerAlphaMask(const GeomCamera3* const camera)
  {
    ApplyWater2CameraMatrices(*camera);

    CD3DDevice* const device = D3D_GetDevice();
    device->SelectFxFile("water2");
    device->SelectTechnique("TWaterLayAlphaMask");

    IWldTerrainRes* const terrainRes = reinterpret_cast<IWldTerrainRes*>(mTerrainRes);
    boost::shared_ptr<CD3DDynamicTextureSheet> utilityTexture =
      boost::static_pointer_cast<CD3DDynamicTextureSheet>(terrainRes->GetWaterMap());
    GetWater2UtilityTextureCShaderVar().GetTexture(utilityTexture);

    std::int32_t primitiveType = kTriangleListPrimitiveToken;
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
    boost::weak_ptr<gpg::gal::TextureD3D9> refractionTexture,
    boost::weak_ptr<gpg::gal::TextureD3D9> reflectionTexture
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

    GetWater2RefractionMapShaderVar().GetTexture(refractionTexture);
    GetWater2ReflectionMapShaderVar().GetTexture(reflectionTexture);
    GetWater2TimeShaderVar().SetFloat(static_cast<float>(tick) + tickLerp);

    const WaterShaderRuntimeView& shaderState = AsWaterShaderRuntimeView(*shaderProperties);
    if (mCachedFresnelBias != shaderState.mFresnelBias || mCachedFresnelPower != shaderState.mFresnelPower ||
        mCachedSunShininess != shaderState.mSunShininess ||
        mCachedSunReflectionAmount != shaderState.mSunReflectionAmount || mFresnelLookupTexture.px == nullptr) {
      const auto fresnelLookupTexture = BuildFresnelLookupTexture(
        shaderState.mFresnelBias,
        shaderState.mFresnelPower,
        shaderState.mSunShininess,
        shaderState.mSunReflectionAmount
      );
      const boost::shared_ptr<ID3DTextureSheet> fresnelBaseTexture =
        boost::static_pointer_cast<ID3DTextureSheet>(fresnelLookupTexture);
      mFresnelLookupTexture.assign_retain(boost::SharedPtrRawFromSharedBorrow(fresnelBaseTexture));

      mCachedFresnelBias = shaderState.mFresnelBias;
      mCachedFresnelPower = shaderState.mFresnelPower;
      mCachedSunShininess = shaderState.mSunShininess;
      mCachedSunReflectionAmount = shaderState.mSunReflectionAmount;
    }

    BindTextureShaderVar(
      GetWater2FresnelLookupShaderVar(),
      boost::SharedPtrFromRawRetained(mFresnelLookupTexture)
    );

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

    CWldSession* const activeSession = WLD_GetActiveSession();
    IWldTerrainRes* const terrainRes = activeSession->mWldMap->mTerrainRes;
    const auto* const terrainView = reinterpret_cast<const TerrainWaterResourceView*>(terrainRes);
    const TerrainHeightFieldRuntimeView* const heightField = terrainView->mMap->mHeightFieldObject;
    const float terrainScale[4] = {
      1.0f / static_cast<float>(heightField->width - 1),
      -1.0f / static_cast<float>(heightField->height - 1),
      0.0f,
      1.0f,
    };
    (void)SetWater2TerrainScaleShaderVarData(terrainScale);

    std::int32_t primitiveType = kTriangleListPrimitiveToken;
    return device->DrawIndexedSheetPrimitive(mVertexSheet, mIndexSheet, &primitiveType);
  }

  /**
   * Address: 0x00810220 (??1HighFidelityWater@Moho@@QAE@@Z)
   * Mangled: ??1HighFidelityWater@Moho@@QAE@@Z
   *
   * What it does:
   * Releases retained shared-owner lanes, destroys owned render sheets, and
   * clears the bound terrain-resource lane.
   */
  HighFidelityWater::~HighFidelityWater()
  {
    ReleaseRenderState();
  }
} // namespace moho
