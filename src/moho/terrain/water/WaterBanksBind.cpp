// Engine addition, not in the binary: the console variables and the shader variable of the banks of water bodies, see
// WaterBanks.h and WaterBanksBind.h.
#include "moho/terrain/water/WaterBanksBind.h"

#include <algorithm>
#include <cstdlib>

#include "gpg/gal/EffectVariable.hpp"
#include "moho/console/CConCommand.h"
#include "moho/render/d3d/ShaderVar.h"
#include "moho/terrain/water/WaterBanks.h"

namespace moho::water
{
  static int ren_WaterBanks = 2;
  static int ren_WaterBankReach = kBankReachDefault;

  static TConVar<int> gTConVar_ren_WaterBanks(
    "ren_WaterBanks",
    "The edge of a river or a lake where it meets the ground (docs/WATER_SIMULATION.md, \"Banks\"): 0 the water "
    "map's block "
    "outline and shore polygons (a staircase), 1 the shoreline cut-out of a water body is the depth test alone, so the "
    "edge is "
    "where the surface meets the terrain (live), 2 (the default) also the mesh of a river reaches the ground below "
    "its level "
    "beside the water (the sim's wet outline stops at the river's half width; read when a map's bodies are first "
    "drawn). "
    "The sea and maps without water bodies are not affected. Render only.",
    &ren_WaterBanks
  );
  static TConVar<int> gTConVar_ren_WaterBankReach(
    "ren_WaterBankReach",
    "How far in world units past its half width a river's mesh reaches over the ground below its level beside the "
    "water "
    "(ren_WaterBanks 2); default 8, 0 to 32. Read when a map's bodies are first drawn. Render only.",
    &ren_WaterBankReach
  );

  namespace
  {
    // FAF_NO_RENDER_ADDITIONS=1 (the same switch as the post passes): the shipped edge
    [[nodiscard]] bool AdditionsDisabled()
    {
      static const bool disabled = [] {
        std::size_t length = 0u;
        char value[8] = {};
        return ::getenv_s(&length, value, sizeof(value), "FAF_NO_RENDER_ADDITIONS") == 0 && length != 0u &&
          value[0] == '1';
      }();
      return disabled;
    }

    // never destroyed: the effect unlinks its shader-vars when it goes
    ShaderVar& ParamsVar()
    {
      static ShaderVar* const var = [] {
        auto* const created = new ShaderVar();
        RegisterShaderVar("waterBankParams", created, "water2");
        return created;
      }();
      return *var;
    }
  } // namespace

  bool BankPatchWanted()
  {
    return ren_WaterBanks != 0;
  }

  bool BankMaskWanted()
  {
    return ren_WaterBanks >= 1 && !AdditionsDisabled();
  }

  bool BankGrowthWanted()
  {
    return ren_WaterBanks >= 2 && !AdditionsDisabled();
  }

  int BankReach()
  {
    return std::clamp(ren_WaterBankReach, 0, kBankReachMax);
  }

  void BindBankMask(
    const bool body
  )
  {
    ShaderVar& var = ParamsVar();
    if (!var.Exists()) {
      return;
    }
    const float params[4] = {body && BankMaskWanted() ? 1.0f : 0.0f, 0.0f, 0.0f, 0.0f};
    var.mEffectVariable->SetVector(params);
  }
} // namespace moho::water
