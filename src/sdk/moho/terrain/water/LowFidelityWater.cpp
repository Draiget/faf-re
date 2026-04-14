#include "moho/terrain/water/LowFidelityWater.h"

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
#include "moho/terrain/water/CWaterShaderProperties.h"
#include "moho/terrain/water/WaterShaderRuntimeView.h"
#include "moho/terrain/water/WaterShaderVars.h"

namespace moho
{
  namespace
  {
    constexpr float kDisabledWaterElevation = -10000.0f;
    constexpr int kLowFidelityWaterVertexFormatToken = 3;
    constexpr int kLowFidelityWaterVertexCount = 4;
    constexpr int kLowFidelityWaterIndexCount = 6;

    struct LowFidelityWaterVertex
    {
      float x;
      float y;
      float z;
      float u;
      float v;
    };

    static_assert(sizeof(LowFidelityWaterVertex) == 0x14, "LowFidelityWaterVertex size must be 0x14");

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

    void BindTextureShaderVar(ShaderVar& shaderVar, const boost::shared_ptr<ID3DTextureSheet>& texture)
    {
      shaderVar.GetTexture(boost::static_pointer_cast<CD3DDynamicTextureSheet>(texture));
    }
  } // namespace

  /**
   * Address: 0x0080F970 (??1LowFidelityWater@Moho@@QAE@@Z)
   * Mangled: ??1LowFidelityWater@Moho@@QAE@@Z
   *
   * What it does:
   * Releases retained low-fidelity render sheets and clears the bound
   * terrain-resource lane.
   */
  LowFidelityWater::~LowFidelityWater()
  {
    ReleaseRenderSheets();
  }

  /**
   * Address: 0x0080FA10 (FUN_0080FA10)
   *
   * TerrainWaterResourceView *
   *
   * IDA signature:
   * char __thiscall Moho::LowFidelityWater::InitVerts(float *this, int terrainRes);
   *
   * What it does:
   * Rebuilds one low-fidelity water quad vertex/index-sheet pair from the
   * current terrain map dimensions and water elevation.
   */
  bool LowFidelityWater::InitVerts(TerrainWaterResourceView* const terrainRes)
  {
    CD3DDevice* const device = D3D_GetDevice();
    ID3DDeviceResources* const resources = device->GetResources();

    mTerrainRes = terrainRes;
    TerrainMapRuntimeView* const terrainMap = terrainRes->mMap;
    mWaterElevation = terrainMap->mWaterEnabled != 0 ? terrainMap->mWaterElevation : kDisabledWaterElevation;

    CD3DVertexFormat* const vertexFormat = resources->GetVertexFormat(kLowFidelityWaterVertexFormatToken);
    if (vertexFormat == nullptr) {
      gpg::Die("unable to create vertex format for low fidelity water");
    }

    CD3DVertexSheet* const nextVertexSheet = resources->NewVertexSheet(0U, kLowFidelityWaterVertexCount, vertexFormat);
    if (nextVertexSheet != mVertexSheet && mVertexSheet != nullptr) {
      delete mVertexSheet;
    }
    mVertexSheet = nextVertexSheet;
    if (mVertexSheet == nullptr) {
      gpg::Die("unable to create vertex sheet for low fidelity water");
    }

    const WaterExtents2D mapExtents = GetWaterMapExtents(*terrainRes);
    ID3DVertexStream* const vertexStream = mVertexSheet->GetVertStream(0U);
    const int vertexCount = mVertexSheet->Func5();
    auto* const vertices = static_cast<LowFidelityWaterVertex*>(vertexStream->Lock(0, vertexCount, false, false));

    vertices[0] = {0.0f, mWaterElevation, 0.0f, 0.0f, 0.0f};
    vertices[1] = {mapExtents.x, mWaterElevation, 0.0f, 1.0f, 0.0f};
    vertices[2] = {0.0f, mWaterElevation, mapExtents.z, 0.0f, 1.0f};
    vertices[3] = {mapExtents.x, mWaterElevation, mapExtents.z, 1.0f, 1.0f};

    vertexStream->Unlock();

    CD3DIndexSheet* const nextIndexSheet = resources->CreateIndexSheet(false, kLowFidelityWaterIndexCount);
    if (nextIndexSheet != mIndexSheet && mIndexSheet != nullptr) {
      delete mIndexSheet;
    }
    mIndexSheet = nextIndexSheet;
    if (mIndexSheet == nullptr) {
      gpg::Die("unable to index sheet for low fidelity water");
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
   * Address: 0x0080FC40 (FUN_0080FC40)
   *
   * What it does:
   * Releases retained low-fidelity water vertex/index sheet ownership and
   * clears the bound terrain-resource lane.
   */
  std::int32_t LowFidelityWater::ReleaseRenderSheets()
  {
    std::int32_t releaseResult = 0;

    if (mVertexSheet != nullptr) {
      delete mVertexSheet;
      releaseResult = 1;
    }
    mVertexSheet = nullptr;

    if (mIndexSheet != nullptr) {
      delete mIndexSheet;
      releaseResult = 1;
    }
    mIndexSheet = nullptr;

    mTerrainRes = nullptr;
    return releaseResult;
  }

  /**
   * Address: 0x0080FC70 (FUN_0080FC70)
   *
   * What it does:
   * No-op water alpha-mask lane retained for low-fidelity slot parity.
   */
  bool LowFidelityWater::RenderWaterLayerAlphaMask(const GeomCamera3* const /*camera*/)
  {
    return true;
  }

  /**
   * Address: 0x0080FC80 (FUN_0080FC80, Moho::LowFidelityWater::Func3)
   *
   * What it does:
   * Binds `water2/TWater`, updates water shader uniforms from camera/properties,
   * binds normal and water-map textures, and draws the retained water sheet.
   */
  bool LowFidelityWater::RenderWaterSurface(
    const std::int32_t tick,
    const float tickLerp,
    const GeomCamera3* const camera,
    const CWaterShaderProperties* const shaderProperties,
    boost::weak_ptr<gpg::gal::TextureD3D9> refractionTexture,
    boost::weak_ptr<gpg::gal::TextureD3D9> reflectionTexture
  )
  {
    (void)refractionTexture;
    (void)reflectionTexture;

    CD3DDevice* const device = D3D_GetDevice();
    device->SelectFxFile("water2");
    device->SelectTechnique("TWater");

    const float viewPosition[3] = {
      camera->inverseView.r[3].x,
      camera->inverseView.r[3].y,
      camera->inverseView.r[3].z,
    };
    SetShaderVarMem(GetWater2ViewPositionShaderVar(), 3U, viewPosition);
    GetWater2WaterElevationShaderVar().SetFloat(mWaterElevation);
    GetWater2TimeShaderVar().SetFloat(static_cast<float>(tick) + tickLerp);

    const WaterShaderRuntimeView& shaderState = AsWaterShaderRuntimeView(*shaderProperties);

    SetShaderVarMem(GetWater2WaterColorShaderVar(), 3U, shaderState.mWaterColor);
    SetShaderVarMem(GetWater2WaterLerpShaderVar(), 2U, shaderState.mWaterLerp);
    GetWater2SunShininessShaderVar().SetFloat(shaderState.mSunShininess);
    GetWater2SunReflectionAmountShaderVar().SetFloat(shaderState.mSunReflectionAmount);
    SetShaderVarMem(GetWater2SunDirectionShaderVar(), 3U, shaderState.mSunDirection);

    const float sunColor[3] = {
      shaderState.mSunColor[0] * shaderState.mSunReflectionAmount,
      shaderState.mSunColor[1] * shaderState.mSunReflectionAmount,
      shaderState.mSunColor[2] * shaderState.mSunReflectionAmount,
    };
    SetShaderVarMem(GetWater2SunColorShaderVar(), 3U, sunColor);

    GetWater2WorldToViewShaderVar().SetMatrix4x4(&camera->view);
    GetWater2ProjectionShaderVar().SetMatrix4x4(&camera->projection);

    SetShaderVarMem(GetWater2NormalRepeatRateShaderVar(), 4U, shaderState.mNormalRepeatRate);
    SetShaderVarMem(GetWater2Normal1MovementShaderVar(), 2U, shaderState.mNormal1Movement);
    SetShaderVarMem(GetWater2Normal2MovementShaderVar(), 2U, shaderState.mNormal2Movement);
    SetShaderVarMem(GetWater2Normal3MovementShaderVar(), 2U, shaderState.mNormal3Movement);
    SetShaderVarMem(GetWater2Normal4MovementShaderVar(), 2U, shaderState.mNormal4Movement);

    BindTextureShaderVar(GetWater2NormalMap0ShaderVar(), shaderProperties->GetNormalMap(0));
    BindTextureShaderVar(GetWater2NormalMap1ShaderVar(), shaderProperties->GetNormalMap(1));
    BindTextureShaderVar(GetWater2NormalMap2ShaderVar(), shaderProperties->GetNormalMap(2));
    BindTextureShaderVar(GetWater2NormalMap3ShaderVar(), shaderProperties->GetNormalMap(3));

    IWldTerrainRes* const terrainRes = reinterpret_cast<IWldTerrainRes*>(mTerrainRes);
    BindTextureShaderVar(GetWater2FresnelLookupShaderVar(), terrainRes->GetWaterMap());

    std::int32_t primitiveType = 4;
    return device->DrawIndexedSheetPrimitive(mVertexSheet, mIndexSheet, &primitiveType);
  }
} // namespace moho
