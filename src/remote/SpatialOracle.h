#pragma once

#include <cstdint>
#include <vector>

// Engine addition, server mode (plan WPR.44): the spatial visibility oracle. It answers, for one
// view, the set of entities `CanViewSee` (VisibilityOracle.h) admits, without testing every
// entity once per view: one pass per beat sorts the entities into lists, then each view tests
// only its own units, the blips it has to flush, the entities some view sees without a grid
// test, and the entities in or next to the cells its grids (or its allies') see. Every
// candidate then gets the exact test, `CanViewSee`, so the result is the brute-force result.
//
// Why its own index and not the sim's:
//   - `SpatialDB<T>` indexes the client's `UserEntity` and `MeshInstance`, not sim entities.
//   - The sim's `COGrid` buckets (`EntityOccupationManager`) hold an entity only while it has a
//     collision primitive, at its collision bounds (blueprint collision offset, unit skirt), in
//     4-unit cells rather than intel cells; and its gathers write the shapes' `mMarked` flag.
//   - No sim structure lists entities by visibility mode, and an entity in mode Always or
//     MapPlayableRect is sent wherever it is: finding those needs every entity looked at once.
// So each beat walks the entity DB once for all views (brute force walks it once per view),
// and the cells are the view's own: `GridPos` at the view's vision-grid size, the mapping
// `ViewCanSeePoint` uses, so the candidate cells cover every point the exact test can admit.
//
// The index holds raw entity pointers: build it after the beat's sync and query it before the
// sim runs again. Reads only, like the brute-force oracle.

namespace moho
{
  class Entity;
  class Sim;
}

namespace faf::remote
{
  /**
   * The reference for WPR.54: the id (`Entity::id_`) of every entity `CanViewSee` admits for
   * `viewArmy`, testing every entity of the entity DB, ascending. Clears `outIds` first.
   */
  void CollectViewEntitiesBruteForce(const moho::Sim& sim, std::int32_t viewArmy, std::vector<std::uint32_t>& outIds);

  /** One beat's entity lists for the spatial view query. */
  class SpatialOracle
  {
  public:
    /** Sorts every live entity of the sim's current beat into the lists below. Reads only. */
    void Build(const moho::Sim& sim);

    /**
     * The id of every entity `CanViewSee` admits for `viewArmy`, ascending: the same set as
     * `CollectViewEntitiesBruteForce` on the sim state `Build` saw. A view without its own
     * army or vision grid (an observer, -1) sees through any grid, so it takes the brute-force
     * path. Clears `outIds` first.
     */
    void CollectViewEntities(const moho::Sim& sim, std::int32_t viewArmy, std::vector<std::uint32_t>& outIds) const;

  private:
    /** One entity in one intel cell, at one vision-grid size. */
    struct SCellEntity
    {
      std::int32_t mX = 0;
      std::int32_t mZ = 0;
      bool mUnderwater = false; // tested against the water grids (`UsesUnderwaterReconGrid`)
      moho::Entity* mEntity = nullptr;
    };

    /** The grid-tested entities by cell for one vision-grid size, sorted by layer, z, x. */
    struct SCellIndex
    {
      std::uint32_t mGridSize = 0;
      std::vector<SCellEntity> mEntries;
    };

    [[nodiscard]] const SCellIndex* FindCellIndex(std::uint32_t gridSize) const noexcept;

    std::vector<std::vector<moho::Entity*>> mUnitsByArmy;       // units, by their army's index
    std::vector<std::vector<moho::Entity*>> mFlushedBlipsByArmy; // blips whose record for that army needs a flush
    std::vector<moho::Entity*> mGridFree; // some view admits it without a grid test: tested for every view
    std::vector<SCellIndex> mCellIndices; // one per distinct vision-grid size among the armies
  };
} // namespace faf::remote
