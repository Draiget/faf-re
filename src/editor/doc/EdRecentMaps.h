#pragma once

#include <cstddef>
#include <string>
#include <vector>

namespace faf::editor
{
  /** The maps opened last, newest first, as their scenario paths (`/maps/x/x_scenario.lua`); kept in a text file, one a line. */
  constexpr std::size_t kRecentMapsKept = 10;

  /** The list in `file`; empty when there is none. */
  std::vector<std::string> ReadRecentMaps(const std::string& file);

  /** The list with `scenario` first: taken from where it was (case aside), the oldest dropped past `kept`. */
  std::vector<std::string> WithRecentMap(std::vector<std::string> list, const std::string& scenario, std::size_t kept = kRecentMapsKept);

  bool WriteRecentMaps(const std::string& file, const std::vector<std::string>& list);
} // namespace faf::editor
