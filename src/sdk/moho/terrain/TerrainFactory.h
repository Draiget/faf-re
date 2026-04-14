#pragma once

#include "moho/terrain/TerrainCommon.h"

namespace moho
{
  /**
   * Terrain factory entrypoint used by world-view render paths.
   */
  class IRenTerrain
  {
  public:
    /**
     * Address: 0x00809DA0 (?Create@IRenTerrain@Moho@@SAPAV12@XZ)
     * Mangled: ?Create@IRenTerrain@Moho@@SAPAV12@XZ
     *
     * What it does:
     * Allocates one terrain renderer variant from `graphics_Fidelity`,
     * logs the selected fidelity path, and returns the constructed base pointer.
     */
    [[nodiscard]] static TerrainCommon* Create();

    /**
     * Address: 0x007FF8B0 (FUN_007FF8B0, ??3IRenTerrain@Moho@@QAE@@Z)
     *
     * What it does:
     * Runs the IRenTerrain destructor lane and conditionally frees the object
     * storage when the delete flag requests heap release.
     */
    static IRenTerrain* DeleteWithFlag(IRenTerrain* object, std::uint8_t deleteFlags) noexcept;
  };
} // namespace moho
