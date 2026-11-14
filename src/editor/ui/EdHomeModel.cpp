#include "editor/ui/EdHomeModel.h"

#include "editor/ui/EdIconFont.h"

#include <algorithm>
#include <cmath>

#include "editor/ui/EdCommands.h"

namespace faf::editor
{
  EdCardGrid CardGrid(
    const float available,
    const float minWidth,
    const float gap,
    const int maxColumns
  )
  {
    EdCardGrid grid;
    if (available <= 0.0f || minWidth <= 0.0f) {
      return grid;
    }
    grid.columns =
      std::clamp(static_cast<int>(std::floor((available + gap) / (minWidth + gap))), 1, std::max(1, maxColumns));
    grid.cardWidth = (available - gap * static_cast<float>(grid.columns - 1)) / static_cast<float>(grid.columns);
    return grid;
  }

  std::vector<int> LocalMatches(
    const std::vector<std::string>& titles,
    const std::vector<std::string>& paths,
    std::string_view query,
    const std::size_t max
  )
  {
    std::vector<std::pair<int, int>> scored; // score, index
    if (query.empty()) {
      return {};
    }
    for (std::size_t i = 0; i < titles.size() && i < paths.size(); ++i) {
      const int score = std::max(FuzzyScore(query, titles[i]), FuzzyScore(query, paths[i]));
      if (score > 0) {
        scored.emplace_back(score, static_cast<int>(i));
      }
    }
    std::stable_sort(scored.begin(), scored.end(), [](const auto& a, const auto& b) {
      return a.first > b.first;
    });
    std::vector<int> out;
    for (std::size_t i = 0; i < scored.size() && out.size() < max; ++i) {
      out.push_back(scored[i].second);
    }
    return out;
  }

  VaultQuery UploadsQuery(
    const std::string& user
  )
  {
    VaultQuery query;
    query.author = user;
    query.sortProperty = "latestVersion.updateTime";
    query.descending = true;
    return query;
  }

  VaultQuery MostPlayedQuery()
  {
    VaultQuery query;
    query.sortProperty = "gamesPlayed";
    query.descending = true;
    return query;
  }

  VaultQuery TypedQuery(
    const std::string& text
  )
  {
    VaultQuery query;
    query.text = text;
    return query;
  }

  std::string WhenText(
    const double secondsAgo
  )
  {
    if (secondsAgo < 60.0) {
      return "Just now";
    }
    if (secondsAgo < 3600.0) {
      const int minutes = static_cast<int>(secondsAgo / 60.0);
      return minutes == 1 ? "1 minute ago" : std::to_string(minutes) + " minutes ago";
    }
    const double days = secondsAgo / 86400.0;
    if (days < 1.0) {
      const int hours = static_cast<int>(secondsAgo / 3600.0);
      return hours == 1 ? "1 hour ago" : std::to_string(hours) + " hours ago";
    }
    if (days < 2.0) {
      return "yesterday";
    }
    if (days < 14.0) {
      return std::to_string(static_cast<int>(days)) + " days ago";
    }
    if (days < 61.0) {
      return std::to_string(static_cast<int>(days / 7.0)) + " weeks ago";
    }
    if (days < 730.0) {
      return std::to_string(static_cast<int>(days / 30.4)) + " months ago";
    }
    return std::to_string(static_cast<int>(days / 365.25)) + " years ago";
  }

  const std::vector<EdNewKind>& NewKinds()
  {
    static const std::vector<EdNewKind> kKinds = {
      // The mockup's kinds: their icons and colours.
      {"file.new", "Map", "Skirmish, any size", ICON_TERRAIN, 0x4EA1FFU},
      {"new.mission", "Mission", "Campaign or coop", ICON_MISSION, 0xE3A33BU},
      {"new.mod", "Mod", "Units and balance", ICON_MOD, 0xA77BFFU},
      {"new.effect", "Effect", "Particles, beams, trails", ICON_PARTICLES, 0xFF7A59U},
      {"new.material", "Material", "Layer textures from nodes", ICON_MATERIAL, 0x35C39BU},
    };
    return kKinds;
  }
} // namespace faf::editor
