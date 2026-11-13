#include "moho/terrain/water/TerrainWaterLevels.h"

#include <cstdlib>
#include <memory>
#include "gpg/core/utils/Logging.h"
#include "gpg/gal/EffectVariable.hpp"
#include "moho/console/CConCommand.h"
#include "moho/render/ID3DTextureSheet.h"
#include "moho/render/WRenViewport.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DDeviceResources.h"
#include "moho/render/d3d/ShaderVar.h"
#include "moho/render/textures/CD3DDynamicTextureSheet.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/CWldMap.h"
#include "moho/terrain/TerrainShaderVars.h"
#include "moho/terrain/water/WaterBodySurfaces.h"

namespace moho::water
{
  static int ren_TerrainWaterLevels = 1;

  static TConVar<int> gTConVar_ren_TerrainWaterLevels(
    "ren_TerrainWaterLevels",
    "A map with water bodies: 1 (the default) the terrain's tint under the water is computed per pixel from the level "
    "and "
    "the abyss of the water of each block; 0 it is the water map's baked depth (block steps, a line of tint on the "
    "bank). "
    "Needs the patched terrain effect. No effect on a map without water bodies. docs/WATER_SIMULATION.md.",
    &ren_TerrainWaterLevels
  );

  namespace
  {
    bool gPatched = false;

    // never destroyed: the effect unlinks its shader-vars when it goes
    ShaderVar& ParamsVar()
    {
      static ShaderVar* const var = [] {
        auto* const created = new ShaderVar();
        RegisterShaderVar("fafWaterLevelParams", created, "terrain");
        return created;
      }();
      return *var;
    }
  } // namespace

  namespace
  {
    bool gWanted = false;         // what the effect loader is told
    bool gBuiltForWanted = false; // what the loaded effect was built for
  } // namespace

  bool TerrainWaterLevelsAdditionsDisabled()
  {
    static const bool disabled = [] {
      std::size_t length = 0U;
      char value[8] = {};
      return ::getenv_s(&length, value, sizeof(value), "FAF_NO_RENDER_ADDITIONS") == 0 && length != 0U &&
        value[0] == '1';
    }();
    return disabled;
  }

  bool TerrainWaterLevelsWanted()
  {
    return gWanted;
  }

  bool ApplyTerrainWaterLevelsLive()
  {
    const IWldTerrainRes* const terrainRes = REN_GetTerrainRes();
    const bool wanted = ren_TerrainWaterLevels != 0 && terrainRes != nullptr && terrainRes->mMap != nullptr &&
      terrainRes->mMap->HasWaterBodies();
    if (wanted == gBuiltForWanted) {
      return false;
    }
    CD3DDevice* const device = D3D_GetDevice();
    ID3DDeviceResources* const resources = device != nullptr ? device->GetResources() : nullptr;
    if (resources == nullptr) {
      return false;
    }
    // set first: a failed rebuild must not repeat every frame
    gBuiltForWanted = wanted;
    gWanted = wanted;
    const bool rebuilt = static_cast<CD3DDeviceResources*>(resources)->ReloadEffectNamed("terrain");
    gpg::Logf(
      "Water: terrain.fx rebuilt %s the water level patch (%s)",
      wanted ? "with" : "without",
      rebuilt ? "ok" : "the effect could not be rebuilt"
    );
    return rebuilt;
  }

  void SetTerrainWaterLevelsPatched(
    const bool patched
  )
  {
    gPatched = patched;
  }

  bool TerrainWaterLevelsPatched()
  {
    return gPatched;
  }

  void BindTerrainWaterMap(
    IWldTerrainRes& terrainRes,
    ShaderVar& utilityTextureC
  )
  {
    ShaderVar& params = ParamsVar();
    std::shared_ptr<CD3DDynamicTextureSheet> levels;
    if (gPatched && ren_TerrainWaterLevels != 0 && terrainRes.mMap != nullptr && terrainRes.mMap->HasWaterBodies()) {
      levels = WaterBodySurfaces::LevelTexture(&terrainRes);
    }
    if (levels != nullptr) {
      BindTextureShaderVar(utilityTextureC, std::static_pointer_cast<ID3DTextureSheet>(levels));
      if (params.Exists()) {
        const CHeightField* const field = terrainRes.mMap->mHeightField.get();
        const float values[4] = {
          1.0f,
          static_cast<float>((field->width - 1) >> 1),
          static_cast<float>((field->height - 1) >> 1),
          0.0f,
        };
        params.mEffectVariable->SetVector(values);
      }
      return;
    }
    BindTextureShaderVar(utilityTextureC, terrainRes.GetWaterMap());
    if (params.Exists()) {
      const float off[4] = {0.0f, 0.0f, 0.0f, 0.0f};
      params.mEffectVariable->SetVector(off);
    }
  }
} // namespace moho::water
