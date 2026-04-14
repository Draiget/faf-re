#include "moho/terrain/water/WaterFactory.h"

#include "gpg/core/utils/Logging.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/terrain/water/HighFidelityWater.h"
#include "moho/terrain/water/LowFidelityWater.h"

namespace moho
{
  /**
   * Address: 0x00811120 (FUN_00811120, func_CreateWaterFidelity)
   *
   * What it does:
   * Allocates one low/high-fidelity water surface by `graphics_Fidelity`,
   * logs the selected path, and initializes water render sheets.
   */
  WaterSurface* CreateWaterFidelity(TerrainWaterResourceView* const terrainResource)
  {
    WaterSurface* result = nullptr;
    if (graphics_Fidelity < 0) {
      return nullptr;
    }

    if (graphics_Fidelity <= 1) {
      result = new LowFidelityWater();
      gpg::Logf("creating low fidelity water");
    } else {
      if (graphics_Fidelity != 2) {
        return nullptr;
      }

      result = new HighFidelityWater();
      gpg::Logf("creating high fidelity water");
    }

    if (result != nullptr) {
      result->InitVerts(terrainResource);
    }
    return result;
  }
} // namespace moho
