#pragma once

#include <cstdint>

#include "boost/shared_ptr.h"
#include "gpg/core/utils/BoostWrappers.h"
#include "moho/render/d3d/ShaderVar.h"

namespace moho
{
  class ID3DTextureSheet;
  class RD3DTextureResource;

  struct TerrainShaderVarSet
  {
    ShaderVar skirtTexture;
    ShaderVar utilityTextureA;
    ShaderVar utilityTextureB;
    ShaderVar utilityTextureC;

    ShaderVar lowerAlbedoTexture;
    ShaderVar stratum0AlbedoTexture;
    ShaderVar stratum1AlbedoTexture;
    ShaderVar stratum2AlbedoTexture;
    ShaderVar stratum3AlbedoTexture;
    ShaderVar stratum4AlbedoTexture;
    ShaderVar stratum5AlbedoTexture;
    ShaderVar stratum6AlbedoTexture;
    ShaderVar stratum7AlbedoTexture;
    ShaderVar upperAlbedoTexture;

    ShaderVar lowerNormalTexture;
    ShaderVar stratum0NormalTexture;
    ShaderVar stratum1NormalTexture;
    ShaderVar stratum2NormalTexture;
    ShaderVar stratum3NormalTexture;
    ShaderVar stratum4NormalTexture;
    ShaderVar stratum5NormalTexture;
    ShaderVar stratum6NormalTexture;
    ShaderVar stratum7NormalTexture;

    ShaderVar lowerAlbedoTile;
    ShaderVar stratum0AlbedoTile;
    ShaderVar stratum1AlbedoTile;
    ShaderVar stratum2AlbedoTile;
    ShaderVar stratum3AlbedoTile;
    ShaderVar stratum4AlbedoTile;
    ShaderVar stratum5AlbedoTile;
    ShaderVar stratum6AlbedoTile;
    ShaderVar stratum7AlbedoTile;
    ShaderVar upperAlbedoTile;

    ShaderVar lowerNormalTile;
    ShaderVar stratum0NormalTile;
    ShaderVar stratum1NormalTile;
    ShaderVar stratum2NormalTile;
    ShaderVar stratum3NormalTile;
    ShaderVar stratum4NormalTile;
    ShaderVar stratum5NormalTile;
    ShaderVar stratum6NormalTile;
    ShaderVar stratum7NormalTile;

    ShaderVar normalTexture;
    ShaderVar terrainScale;
    ShaderVar viewportScale;
    ShaderVar viewportOffset;

    TerrainShaderVarSet();
  };

  [[nodiscard]] TerrainShaderVarSet& GetTerrainShaderVars();

  void BindTextureShaderVar(ShaderVar& shaderVar, const boost::shared_ptr<ID3DTextureSheet>& textureSheet);
  void BindTextureShaderVar(ShaderVar& shaderVar, const boost::SharedPtrRaw<RD3DTextureResource>& textureResource);
  void SetShaderVarMem(ShaderVar& shaderVar, std::uint32_t floatCount, const float* values);
} // namespace moho
