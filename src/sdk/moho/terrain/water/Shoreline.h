#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "legacy/containers/Vector.h"
#include "moho/mesh/Mesh.h"

namespace moho
{
  class ID3DVertexSheet;
  class ShoreCell;
  struct TerrainWaterResourceView;

  /**
   * Address: 0x010A6442 (?ren_Shoreline@Moho@@3_NA)
   *
   * What it does:
   * Global shoreline render enable lane toggled by shoreline generation.
   */
  extern bool ren_Shoreline;

  /**
   * Address: 0x00F57D64 (?ren_ShorelineCutoff@Moho@@3MA)
   *
   * What it does:
   * Dissolve-cutoff value propagated into generated shoreline spatial-db cells.
   */
  extern float ren_ShorelineCutoff;

  /**
   * Terrain-water shoreline runtime owner.
   */
  class Shoreline
  {
  public:
    /**
     * Address: 0x00812840 (FUN_00812840, Moho::Shoreline::Shoreline)
     *
     * What it does:
     * Initializes shoreline runtime lanes, including spatial-db entry wrapper,
     * shoreline-cell vector storage, vertex-sheet shared owner, and triangle count.
     */
    Shoreline();

    /**
     * Address: 0x008128D0 (FUN_008128D0, Moho::Shoreline::~Shoreline)
     *
     * What it does:
     * Destroys shoreline runtime state by calling `Destroy`, releasing shoreline
     * cell storage, and tearing down the spatial-db entry wrapper subobject.
     */
    virtual ~Shoreline();

    /**
     * Address: 0x008128B0 (FUN_008128B0, Moho::Shoreline::dtr)
     *
     * What it does:
     * Runs the non-deleting destructor and conditionally frees `this` when the
     * low delete-flag bit is set.
     */
    Shoreline* DeleteWithFlag(std::uint8_t deleteFlags);

    /**
     * Address: 0x00812E00 (FUN_00812E00, Moho::Shoreline::Destroy)
     *
     * What it does:
     * Releases vertex-sheet ownership, erases shoreline-cell shared-pointer lanes,
     * and clears shoreline triangle-count state.
     */
    void Destroy();

    /**
     * Address: 0x008129B0 (FUN_008129B0, Moho::Shoreline::Generate)
     *
     * What it does:
     * Rebuilds shoreline cells from terrain-water heightfield masks, recreates
     * shoreline vertex-sheet ownership, and updates shoreline-cell stats.
     */
    void Generate(TerrainWaterResourceView* terrainResource);

  public:
    SpatialDB_MeshInstance mSpatialDbEntry;                      // +0x04
    std::uint8_t mUnknown0C_93[0x88]{};                          // +0x0C..+0x93
    msvc8::vector<boost::shared_ptr<ShoreCell>> mCells;          // +0x94
    boost::shared_ptr<ID3DVertexSheet> mVertexSheet;             // +0xA4
    std::int32_t mShorelineTris;                                 // +0xAC
  };

  static_assert(offsetof(Shoreline, mSpatialDbEntry) == 0x04, "Shoreline::mSpatialDbEntry offset must be 0x04");
  static_assert(offsetof(Shoreline, mCells) == 0x94, "Shoreline::mCells offset must be 0x94");
  static_assert(offsetof(Shoreline, mVertexSheet) == 0xA4, "Shoreline::mVertexSheet offset must be 0xA4");
  static_assert(offsetof(Shoreline, mShorelineTris) == 0xAC, "Shoreline::mShorelineTris offset must be 0xAC");
  static_assert(sizeof(Shoreline) == 0xB0, "Shoreline size must be 0xB0");
} // namespace moho
