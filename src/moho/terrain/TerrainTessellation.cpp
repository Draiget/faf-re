// Engine addition, not in the shipped binary: see TerrainTessellation.h.

#include "moho/terrain/TerrainTessellation.h"

#include <array>
#include <cctype>
#include <cstdio>
#include <string>
#include <string_view>

#include "gpg/core/utils/Logging.h"
#include "moho/render/d3d/ShaderVar.h"
#include "moho/terrain/StratumMaterial.h"
#include "moho/terrain/TerrainShaderVars.h"

namespace moho
{
  namespace
  {
    struct TessellationShaderVars
    {
      TessellationShaderVars()
      {
        RegisterShaderVar("TerrainTessLayers0", &layers[0], "terrain");
        RegisterShaderVar("TerrainTessLayers1", &layers[1], "terrain");
        RegisterShaderVar("TerrainTessLayers2", &layers[2], "terrain");
      }

      ShaderVar layers[3];
    };

    [[nodiscard]] TessellationShaderVars& Vars()
    {
      static TessellationShaderVars vars;
      return vars;
    }

    [[nodiscard]] bool Mentions(const std::string& name, const std::initializer_list<std::string_view> words)
    {
      for (const std::string_view word : words) {
        if (name.find(word) != std::string::npos) {
          return true;
        }
      }
      return false;
    }

    /** 1 for rock, sand, dirt and the like, 0 for plant layers, 0.5 when the name says neither or both. */
    [[nodiscard]] float LayerRelief(const fa::string& path)
    {
      std::string name(path.c_str());
      const std::size_t slash = name.find_last_of("/\\");
      if (slash != std::string::npos) {
        name.erase(0U, slash + 1U);
      }
      if (name.empty()) {
        return 0.0f;
      }
      for (char& character : name) {
        character = static_cast<char>(std::tolower(static_cast<unsigned char>(character)));
      }
      const bool plant = Mentions(name, {"grass", "moss", "leaf", "leaves", "flower", "foliage", "fern", "clover", "lawn", "vine"});
      const bool hard = Mentions(name, {"rock", "cliff", "stone", "gravel", "pebble", "sand", "dirt", "mud", "soil", "crack",
                                        "crater", "lava", "rubble", "boulder", "dune", "desert", "ash", "slate", "granite",
                                        "basalt", "scorch", "earth", "ground", "road", "path", "concrete", "debris"});
      if (hard && !plant) {
        return 1.0f;
      }
      if (plant && !hard) {
        return 0.0f;
      }
      return 0.5f;
    }
  } // namespace

  void TERRAIN_SetTessellationLayers(const StratumMaterial& strata)
  {
    TessellationShaderVars& vars = Vars();
    if (!vars.layers[0].Exists()) {
      return; // terrain.fx without terrain_tess.fx
    }
    const std::array<const CStratumMaterial*, 9> layers = {
      &strata.mLowerAlbedoTexture,    &strata.mStratum0AlbedoTexture, &strata.mStratum1AlbedoTexture,
      &strata.mStratum2AlbedoTexture, &strata.mStratum3AlbedoTexture, &strata.mStratum4AlbedoTexture,
      &strata.mStratum5AlbedoTexture, &strata.mStratum6AlbedoTexture, &strata.mStratum7AlbedoTexture,
    };
    float values[12]{};
    for (std::size_t index = 0U; index < layers.size(); ++index) {
      values[index] = LayerRelief(layers[index]->mPath);
    }
    SetShaderVarMem(vars.layers[0], 4U, values);
    SetShaderVarMem(vars.layers[1], 4U, values + 4);
    SetShaderVarMem(vars.layers[2], 4U, values + 8);

    // Once per map: which layers got relief.
    static std::string logged;
    std::string summary;
    for (std::size_t index = 0U; index < layers.size(); ++index) {
      if (!layers[index]->mPath.empty()) {
        char item[32]{};
        std::snprintf(item, sizeof(item), " %s=%.1f", index == 0U ? "lower" : ("s" + std::to_string(index - 1U)).c_str(), values[index]);
        summary += item;
        summary += " (";
        summary += layers[index]->mPath.c_str();
        summary += ")";
      }
    }
    if (summary != logged) {
      logged = summary;
      gpg::Logf("terrain: tessellation relief per layer:%s", summary.c_str());
    }
  }
} // namespace moho
