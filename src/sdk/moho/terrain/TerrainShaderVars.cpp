#include "moho/terrain/TerrainShaderVars.h"

#include "gpg/gal/backends/d3d9/EffectVariableD3D9.hpp"
#include "moho/render/ID3DTextureSheet.h"
#include "moho/render/d3d/RD3DTextureResource.h"

namespace moho
{
  TerrainShaderVarSet::TerrainShaderVarSet()
  {
    RegisterShaderVar("SkirtTexture", &skirtTexture, "terrain");
    RegisterShaderVar("UtilityTextureA", &utilityTextureA, "terrain");
    RegisterShaderVar("UtilityTextureB", &utilityTextureB, "terrain");
    RegisterShaderVar("UtilityTextureC", &utilityTextureC, "terrain");

    RegisterShaderVar("LowerAlbedoTexture", &lowerAlbedoTexture, "terrain");
    RegisterShaderVar("Stratum0AlbedoTexture", &stratum0AlbedoTexture, "terrain");
    RegisterShaderVar("Stratum1AlbedoTexture", &stratum1AlbedoTexture, "terrain");
    RegisterShaderVar("Stratum2AlbedoTexture", &stratum2AlbedoTexture, "terrain");
    RegisterShaderVar("Stratum3AlbedoTexture", &stratum3AlbedoTexture, "terrain");
    RegisterShaderVar("Stratum4AlbedoTexture", &stratum4AlbedoTexture, "terrain");
    RegisterShaderVar("Stratum5AlbedoTexture", &stratum5AlbedoTexture, "terrain");
    RegisterShaderVar("Stratum6AlbedoTexture", &stratum6AlbedoTexture, "terrain");
    RegisterShaderVar("Stratum7AlbedoTexture", &stratum7AlbedoTexture, "terrain");
    RegisterShaderVar("UpperAlbedoTexture", &upperAlbedoTexture, "terrain");

    RegisterShaderVar("LowerNormalTexture", &lowerNormalTexture, "terrain");
    RegisterShaderVar("Stratum0NormalTexture", &stratum0NormalTexture, "terrain");
    RegisterShaderVar("Stratum1NormalTexture", &stratum1NormalTexture, "terrain");
    RegisterShaderVar("Stratum2NormalTexture", &stratum2NormalTexture, "terrain");
    RegisterShaderVar("Stratum3NormalTexture", &stratum3NormalTexture, "terrain");
    RegisterShaderVar("Stratum4NormalTexture", &stratum4NormalTexture, "terrain");
    RegisterShaderVar("Stratum5NormalTexture", &stratum5NormalTexture, "terrain");
    RegisterShaderVar("Stratum6NormalTexture", &stratum6NormalTexture, "terrain");
    RegisterShaderVar("Stratum7NormalTexture", &stratum7NormalTexture, "terrain");

    RegisterShaderVar("LowerAlbedoTile", &lowerAlbedoTile, "terrain");
    RegisterShaderVar("Stratum0AlbedoTile", &stratum0AlbedoTile, "terrain");
    RegisterShaderVar("Stratum1AlbedoTile", &stratum1AlbedoTile, "terrain");
    RegisterShaderVar("Stratum2AlbedoTile", &stratum2AlbedoTile, "terrain");
    RegisterShaderVar("Stratum3AlbedoTile", &stratum3AlbedoTile, "terrain");
    RegisterShaderVar("Stratum4AlbedoTile", &stratum4AlbedoTile, "terrain");
    RegisterShaderVar("Stratum5AlbedoTile", &stratum5AlbedoTile, "terrain");
    RegisterShaderVar("Stratum6AlbedoTile", &stratum6AlbedoTile, "terrain");
    RegisterShaderVar("Stratum7AlbedoTile", &stratum7AlbedoTile, "terrain");
    RegisterShaderVar("UpperAlbedoTile", &upperAlbedoTile, "terrain");

    RegisterShaderVar("LowerNormalTile", &lowerNormalTile, "terrain");
    RegisterShaderVar("Stratum0NormalTile", &stratum0NormalTile, "terrain");
    RegisterShaderVar("Stratum1NormalTile", &stratum1NormalTile, "terrain");
    RegisterShaderVar("Stratum2NormalTile", &stratum2NormalTile, "terrain");
    RegisterShaderVar("Stratum3NormalTile", &stratum3NormalTile, "terrain");
    RegisterShaderVar("Stratum4NormalTile", &stratum4NormalTile, "terrain");
    RegisterShaderVar("Stratum5NormalTile", &stratum5NormalTile, "terrain");
    RegisterShaderVar("Stratum6NormalTile", &stratum6NormalTile, "terrain");
    RegisterShaderVar("Stratum7NormalTile", &stratum7NormalTile, "terrain");

    RegisterShaderVar("NormalTexture", &normalTexture, "terrain");
    RegisterShaderVar("TerrainScale", &terrainScale, "terrain");
    RegisterShaderVar("ViewportScale", &viewportScale, "terrain");
    RegisterShaderVar("ViewportOffset", &viewportOffset, "terrain");

    RegisterShaderVar("ViewMatrix", &viewMatrix, "terrain");
    RegisterShaderVar("ProjMatrix", &projMatrix, "terrain");
    RegisterShaderVar("LightingMultiplier", &lightingMultiplier, "terrain");
    RegisterShaderVar("SunDirection", &sunDirection, "terrain");
    RegisterShaderVar("SunAmbience", &sunAmbience, "terrain");
    RegisterShaderVar("SunColor", &sunColor, "terrain");
    RegisterShaderVar("HalfAngle", &halfAngle, "terrain");
    RegisterShaderVar("CameraDirection", &cameraDirection, "terrain");
    RegisterShaderVar("CameraPosition", &cameraPosition, "terrain");
    RegisterShaderVar("SpecularColor", &specularColor, "terrain");
    RegisterShaderVar("ShadowFillColor", &shadowFillColor, "terrain");
    RegisterShaderVar("ShadowsEnabled", &shadowsEnabled, "terrain");
    RegisterShaderVar("ShadowMatrix", &shadowMatrix, "terrain");
    RegisterShaderVar("ShadowTexture", &shadowTexture, "terrain");
    RegisterShaderVar("NoiseTexture", &noiseTexture, "terrain");
    RegisterShaderVar("DecalMaskTexture", &decalMaskTexture, "terrain");
    RegisterShaderVar("BiCubicLookup", &biCubicLookup, "terrain");
    RegisterShaderVar("OverlayTexture", &overlayTexture, "terrain");
  }

  TerrainShaderVarSet& GetTerrainShaderVars()
  {
    static TerrainShaderVarSet shaderVars{};
    return shaderVars;
  }

  void BindTextureShaderVar(ShaderVar& shaderVar, const boost::shared_ptr<ID3DTextureSheet>& textureSheet)
  {
    ID3DTextureSheet::TextureHandle textureHandle{};
    if (textureSheet != nullptr) {
      textureSheet->GetTexture(textureHandle);
    }
    shaderVar.GetTexture(boost::weak_ptr<gpg::gal::TextureD3D9>(textureHandle));
  }

  void BindTextureShaderVar(
    ShaderVar& shaderVar,
    const boost::SharedPtrRaw<RD3DTextureResource>& textureResource
  )
  {
    const boost::shared_ptr<RD3DTextureResource> retainedTexture = boost::SharedPtrFromRawRetained(textureResource);
    BindTextureShaderVar(shaderVar, boost::static_pointer_cast<ID3DTextureSheet>(retainedTexture));
  }

  void SetShaderVarMem(ShaderVar& shaderVar, const std::uint32_t floatCount, const float* const values)
  {
    if (shaderVar.Exists()) {
      shaderVar.mEffectVariable->SetMem(floatCount, values);
    }
  }

  void SetShaderVarPtr(ShaderVar& shaderVar, const void* const data, const std::uint32_t byteCount)
  {
    if (shaderVar.Exists()) {
      shaderVar.mEffectVariable->SetPtr(data, byteCount);
    }
  }
} // namespace moho
