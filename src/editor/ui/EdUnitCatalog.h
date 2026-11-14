#pragma once

#include <array>
#include <cstddef>
#include <string>
#include <string_view>
#include <vector>

namespace faf::editor
{
  /** The Units tool's browser groups (design §7 Units: like the build menu). */
  constexpr std::array<const char*, 5> kUnitFactions = {"UEF", "Aeon", "Cybran", "Seraphim", "Other"};
  constexpr std::array<const char*, 5> kUnitKinds = {"Land", "Air", "Naval", "Buildings", "Other"};
  constexpr std::array<const char*, 5> kUnitTechs = {"Tech 1", "Tech 2", "Tech 3", "Experimental", "Other"};

  /** One unit blueprint as the browser sorts it: its faction, kind and tech by its categories (indices above). */
  struct EdUnitInfo
  {
    std::string id;
    std::string name;
    int faction = 4;
    int kind = 4;
    int tech = 4;
  };

  /** A unit's groups from its blueprint's categories (UEF, AIR, TECH2, STRUCTURE, EXPERIMENTAL...). */
  [[nodiscard]] EdUnitInfo UnitInfoFrom(std::string id, std::string name, const std::vector<std::string>& categories);

  /** The browser's filter: a faction and a kind (-1: any), and words in the id or name. */
  struct EdUnitFilter
  {
    int faction = -1;
    int kind = -1;
    std::string text;
  };

  /** The units passing the filter, by their index, sorted by tech then id (the build menu's order). */
  [[nodiscard]] std::vector<std::size_t> FilterUnits(const std::vector<EdUnitInfo>& units, const EdUnitFilter& filter);

  /**
   * The chips' counts: how many units each faction would show with the filter's kind and text, and each kind with
   * its faction and text (a chip's count is what clicking it gives).
   */
  [[nodiscard]] std::array<int, 5> FactionCounts(const std::vector<EdUnitInfo>& units, const EdUnitFilter& filter);
  [[nodiscard]] std::array<int, 5> KindCounts(const std::vector<EdUnitInfo>& units, const EdUnitFilter& filter);
} // namespace faf::editor
