#include "editor/tools/EdMapStats.h"

#include <algorithm>
#include <cmath>
#include <cstdio>

namespace faf::editor
{
  std::vector<StatStart> PerStart(
    std::vector<StatStart> starts,
    const std::vector<StatThing>& things
  )
  {
    if (starts.empty()) {
      return starts;
    }
    for (const StatThing& thing : things) {
      std::size_t nearest = 0;
      float best = -1.0f;
      for (std::size_t i = 0; i < starts.size(); ++i) {
        const float d = std::hypot(starts[i].x - thing.x, starts[i].z - thing.z);
        if (best < 0.0f || d < best) {
          best = d;
          nearest = i;
        }
      }
      StatStart& start = starts[nearest];
      switch (thing.kind) {
      case StatThing::Kind::Mass:
        ++start.mass;
        break;
      case StatThing::Kind::Hydro:
        ++start.hydro;
        break;
      case StatThing::Kind::Prop:
        ++start.props;
        start.reclaimMass += thing.mass;
        start.reclaimEnergy += thing.energy;
        break;
      }
    }
    return starts;
  }

  StatSpread SpreadOf(
    const std::vector<StatStart>& starts
  )
  {
    StatSpread spread;
    if (starts.empty()) {
      return spread;
    }
    const auto [lowMass, highMass] =
      std::minmax_element(starts.begin(), starts.end(), [](const StatStart& a, const StatStart& b) {
      return a.mass < b.mass;
    });
    const auto [lowHydro, highHydro] =
      std::minmax_element(starts.begin(), starts.end(), [](const StatStart& a, const StatStart& b) {
      return a.hydro < b.hydro;
    });
    const auto [lowReclaim, highReclaim] =
      std::minmax_element(starts.begin(), starts.end(), [](const StatStart& a, const StatStart& b) {
      return a.reclaimMass < b.reclaimMass;
    });
    spread.mass = highMass->mass - lowMass->mass;
    spread.hydro = highHydro->hydro - lowHydro->hydro;
    spread.reclaimMass = highReclaim->reclaimMass - lowReclaim->reclaimMass;
    return spread;
  }

  float SnapFootprint(
    const float value,
    const int size
  ) noexcept
  {
    return size % 2 != 0 ? std::floor(value) + 0.5f : std::round(value);
  }

  std::string FitProblem(
    const FitFacts& facts
  )
  {
    char text[160];
    if (facts.outsidePlayable) {
      return "outside the playable area";
    }
    if (facts.landOnly && facts.waterDepth > 0.05f) {
      (void)std::snprintf(text, sizeof(text), "under %.1f of water", static_cast<double>(facts.waterDepth));
      return text;
    }
    if (facts.structure && facts.maxVariation > 0.0f && facts.groundVaries > facts.maxVariation + 1e-3f) {
      (void)std::snprintf(
        text,
        sizeof(text),
        "too steep: the ground varies %.2f, it is built where it varies %.2f at most",
        static_cast<double>(facts.groundVaries),
        static_cast<double>(facts.maxVariation)
      );
      return text;
    }
    if (facts.overlaps) {
      return "on another unit's cells";
    }
    return {};
  }
} // namespace faf::editor
