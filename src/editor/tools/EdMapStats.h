#pragma once

#include <string>
#include <vector>

namespace faf::editor
{
  /**
   * The Statistics panel's per-start fairness (FAF Studio's mapstats.lua): each mass and hydrocarbon point and each
   * prop's reclaim goes to the start nearest to it, and the spread says how far apart the starts are.
   */
  struct StatStart
  {
    std::string name;
    float x = 0.0f;
    float z = 0.0f;
    int mass = 0;
    int hydro = 0;
    int props = 0;
    double reclaimMass = 0.0;
    double reclaimEnergy = 0.0;
  };
  struct StatThing
  {
    enum class Kind
    {
      Mass,
      Hydro,
      Prop,
    } kind = Kind::Mass;
    float x = 0.0f;
    float z = 0.0f;
    double mass = 0.0;
    double energy = 0.0;
  };
  /** Each thing counted for the start nearest to it (ties to the first). */
  [[nodiscard]] std::vector<StatStart> PerStart(std::vector<StatStart> starts, const std::vector<StatThing>& things);
  /** Highest minus lowest over the starts: mass points, and reclaim mass. */
  struct StatSpread
  {
    int mass = 0;
    int hydro = 0;
    double reclaimMass = 0.0;
  };
  [[nodiscard]] StatSpread SpreadOf(const std::vector<StatStart>& starts);

  /**
   * A structure's footprint snapping (FAF Studio's unitfit Snap): an odd size sits on a cell's middle (x.5), an even
   * size on a cell corner (a whole number), so its cells line up with the game's grid.
   */
  [[nodiscard]] float SnapFootprint(float value, int size) noexcept;

  /** Why a unit wouldn't fit where it is placed (empty: it fits), from what the view measured there. */
  struct FitFacts
  {
    bool structure = false;
    float groundVaries = 0.0f;    // the slope rule's rating under it
    float maxVariation = 0.0f;    // the blueprint's MaxGroundVariation (0: none)
    float waterDepth = 0.0f;      // water over the ground there (0: dry)
    bool landOnly = true;         // its footprint can't stand in water
    bool outsidePlayable = false; // the playable area doesn't hold it
    bool overlaps = false;        // another unit's footprint takes the same cells
  };
  [[nodiscard]] std::string FitProblem(const FitFacts& facts);
} // namespace faf::editor
