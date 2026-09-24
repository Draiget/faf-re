#include "moho/terrain/water/WaterFactory.h"

#include "gpg/core/utils/Logging.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/terrain/water/HighFidelityWater.h"
#include "moho/terrain/water/LowFidelityWater.h"

namespace moho
{
  /**
   * Address: 0x0080F920 (FUN_0080F920, ??0WaterSurface@Moho@@QAE@XZ)
   *
   * IDA signature:
   * mov dword ptr [ecx], offset ??_7WaterSurface@Moho@@6B@ ; retn
   *
   * What it does:
   * Initializes one water-surface base interface object -- which for an
   * abstract base with no data members is just the vptr store the compiler
   * emits.
   */
  WaterSurface::WaterSurface() = default;

  /**
   * Address: 0x0080F930 (FUN_0080F930)
   *
   * IDA signature:
   * mov dword ptr [eax], offset ??_7WaterSurface@Moho@@6B@ ; retn
   *
   * What it does:
   * The base half of the water-surface teardown: the same seven bytes as the
   * constructor above, re-seating the vptr as the derived destructor unwinds
   * into its base.
   *
   * This is defined out of line rather than left `= default` in the header so
   * the emission has one home, matching the single body in the shipped image.
   * It previously had a hand-written stand-in -- an abstract-class "probe"
   * instantiated only to read its vptr, which was then `reinterpret_cast` into
   * a `WaterSurface` -- that nothing called and that the compiler emits by
   * itself.
   */
  WaterSurface::~WaterSurface() = default;

  /**
   * Address: 0x00811120 (FUN_00811120, func_CreateWaterFidelity)
   *
   * What it does:
   * Allocates one low/high-fidelity water surface by `graphics_Fidelity`,
   * logs the selected path, and initializes water render sheets.
   */
  WaterSurface* CreateWaterFidelity(IWldTerrainRes* const terrainResource)
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
