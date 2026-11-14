#include "editor/ui/EdUnitCatalog.h"

#include <algorithm>
#include <cctype>

namespace faf::editor
{
  namespace
  {
    [[nodiscard]] std::string Upper(
      std::string_view text
    )
    {
      std::string out(text);
      std::transform(out.begin(), out.end(), out.begin(), [](const unsigned char c) {
        return static_cast<char>(std::toupper(c));
      });
      return out;
    }

    [[nodiscard]] std::string Lower(
      std::string_view text
    )
    {
      std::string out(text);
      std::transform(out.begin(), out.end(), out.begin(), [](const unsigned char c) {
        return static_cast<char>(std::tolower(c));
      });
      return out;
    }

    [[nodiscard]] bool Matches(
      const EdUnitInfo& unit,
      const EdUnitFilter& filter,
      const bool faction,
      const bool kind
    )
    {
      if (faction && filter.faction >= 0 && unit.faction != filter.faction) {
        return false;
      }
      if (kind && filter.kind >= 0 && unit.kind != filter.kind) {
        return false;
      }
      if (!filter.text.empty()) {
        const std::string haystack = Lower(unit.id + " " + unit.name);
        std::string word;
        for (const char c : Lower(filter.text) + " ") {
          if (c == ' ') {
            if (!word.empty() && haystack.find(word) == std::string::npos) {
              return false;
            }
            word.clear();
          } else {
            word += c;
          }
        }
      }
      return true;
    }
  } // namespace

  EdUnitInfo UnitInfoFrom(
    std::string id,
    std::string name,
    const std::vector<std::string>& categories
  )
  {
    EdUnitInfo info;
    info.id = std::move(id);
    info.name = std::move(name);
    bool structure = false;
    bool land = false;
    bool air = false;
    bool naval = false;
    for (const std::string& raw : categories) {
      const std::string category = Upper(raw);
      if (category == "UEF") {
        info.faction = 0;
      } else if (category == "AEON") {
        info.faction = 1;
      } else if (category == "CYBRAN") {
        info.faction = 2;
      } else if (category == "SERAPHIM") {
        info.faction = 3;
      } else if (category == "TECH1") {
        info.tech = std::min(info.tech, 0);
      } else if (category == "TECH2") {
        info.tech = std::min(info.tech, 1);
      } else if (category == "TECH3") {
        info.tech = std::min(info.tech, 2);
      } else if (category == "EXPERIMENTAL") {
        info.tech = 3;
      } else if (category == "STRUCTURE") {
        structure = true;
      } else if (category == "LAND") {
        land = true;
      } else if (category == "AIR") {
        air = true;
      } else if (category == "NAVAL") {
        naval = true;
      }
    }
    // A building first (an air factory is a building), then what it moves on; experimentals keep their tech.
    info.kind = structure ? 3 : air ? 1 : naval ? 2 : land ? 0 : 4;
    return info;
  }

  std::vector<std::size_t> FilterUnits(
    const std::vector<EdUnitInfo>& units,
    const EdUnitFilter& filter
  )
  {
    std::vector<std::size_t> out;
    for (std::size_t i = 0; i < units.size(); ++i) {
      if (Matches(units[i], filter, true, true)) {
        out.push_back(i);
      }
    }
    std::stable_sort(out.begin(), out.end(), [&units](const std::size_t a, const std::size_t b) {
      if (units[a].tech != units[b].tech) {
        return units[a].tech < units[b].tech;
      }
      return units[a].id < units[b].id;
    });
    return out;
  }

  std::array<int, 5> FactionCounts(
    const std::vector<EdUnitInfo>& units,
    const EdUnitFilter& filter
  )
  {
    std::array<int, 5> counts{};
    for (const EdUnitInfo& unit : units) {
      if (Matches(unit, filter, false, true)) {
        ++counts[static_cast<std::size_t>(std::clamp(unit.faction, 0, 4))];
      }
    }
    return counts;
  }

  std::array<int, 5> KindCounts(
    const std::vector<EdUnitInfo>& units,
    const EdUnitFilter& filter
  )
  {
    std::array<int, 5> counts{};
    for (const EdUnitInfo& unit : units) {
      if (Matches(unit, filter, true, false)) {
        ++counts[static_cast<std::size_t>(std::clamp(unit.kind, 0, 4))];
      }
    }
    return counts;
  }
} // namespace faf::editor
