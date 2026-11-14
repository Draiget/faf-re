#include "editor/tools/EdChecks.h"

#include <algorithm>
#include <set>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <unordered_map>

#include "editor/tools/EdMarkers.h"

namespace faf::editor
{
  const char* CheckLevelName(
    const CheckIssue::Level level
  )
  {
    switch (level) {
    case CheckIssue::Level::Error:
      return "error";
    case CheckIssue::Level::Warning:
      return "warning";
    case CheckIssue::Level::Note:
      break;
    }
    return "note";
  }

  bool ParseLuaError(
    const std::string& error,
    int& line,
    std::string& message
  )
  {
    // This engine's Lua writes `name(12): message`.
    for (std::size_t open = error.find('('); open != std::string::npos; open = error.find('(', open + 1)) {
      std::size_t digits = open + 1;
      while (digits < error.size() && error[digits] >= '0' && error[digits] <= '9') {
        ++digits;
      }
      if (digits > open + 1 && error.compare(digits, 2, "):") == 0) {
        line = std::atoi(error.c_str() + open + 1);
        message = error.substr(digits + 2);
        while (!message.empty() && message.front() == ' ') {
          message.erase(0, 1);
        }
        return true;
      }
    }
    // The line is the number between the last two colons before the message.
    std::size_t at = error.find("]:");
    at = at == std::string::npos ? error.find(':') : at + 1;
    while (at != std::string::npos) {
      std::size_t digits = at + 1;
      while (digits < error.size() && error[digits] >= '0' && error[digits] <= '9') {
        ++digits;
      }
      if (digits > at + 1 && digits < error.size() && error[digits] == ':') {
        line = std::atoi(error.c_str() + at + 1);
        message = error.substr(digits + 1);
        while (!message.empty() && message.front() == ' ') {
          message.erase(0, 1);
        }
        return true;
      }
      at = error.find(':', at + 1);
    }
    return false;
  }

  std::vector<CheckIssue> CheckMarkers(
    const MarkerCheckInput& input
  )
  {
    std::vector<CheckIssue> issues;
    if (input.markers == nullptr) {
      return issues;
    }
    struct Point
    {
      const SaveEntry* marker;
      std::string type;
      float x;
      float y;
      float z;
    };
    std::vector<Point> points;
    for (const SaveEntry& marker : *input.markers) {
      const std::string type = MarkerTypeOf(marker);
      if (type != "Blank Marker" && type != "Mass" && type != "Hydrocarbon") {
        continue;
      }
      float x = 0.0f, y = 0.0f, z = 0.0f;
      if (MarkerPosition(marker, x, y, z)) {
        points.push_back({&marker, type, x, y, z});
      }
    }
    const auto add = [&](const CheckIssue::Level level, const Point& p, const std::string& text) {
      issues.push_back({level, p.marker->name, text, p.x, p.z, std::string(), 0});
    };
    const auto what = [](const Point& p) {
      return std::string(
        p.type == "Blank Marker" ? "start position"
          : p.type == "Mass"     ? "mass point"
                                 : "hydrocarbon point"
      );
    };

    for (const Point& p : points) {
      // On the map, and inside the playable area.
      if (
        input.width > 0 &&
        (p.x < 0.0f || p.z < 0.0f || p.x > static_cast<float>(input.width - 1) ||
         p.z > static_cast<float>(input.height - 1))
      ) {
        add(CheckIssue::Level::Error, p, what(p) + " is off the map");
        // Pulled a unit in from the edge; a resource keeps the middle of its cell.
        const bool resource = p.type != "Blank Marker";
        float fx = std::clamp(p.x, 1.0f, static_cast<float>(input.width - 2));
        float fz = std::clamp(p.z, 1.0f, static_cast<float>(input.height - 2));
        if (resource) {
          fx = std::floor(fx) + 0.5f;
          fz = std::floor(fz) + 0.5f;
        }
        issues.back().fix = CheckIssue::Fix::PullInside;
        issues.back().fixX = fx;
        issues.back().fixZ = fz;
        continue;
      }
      if (input.playable) {
        const auto& a = *input.playable;
        if (
          p.x < static_cast<float>(a[0]) || p.z < static_cast<float>(a[1]) || p.x > static_cast<float>(a[2]) ||
          p.z > static_cast<float>(a[3])
        ) {
          add(CheckIssue::Level::Error, p, what(p) + " is outside the playable area");
          const bool resource = p.type != "Blank Marker";
          float fx = std::clamp(p.x, static_cast<float>(a[0]) + 1.0f, static_cast<float>(a[2]) - 1.0f);
          float fz = std::clamp(p.z, static_cast<float>(a[1]) + 1.0f, static_cast<float>(a[3]) - 1.0f);
          if (resource) {
            fx = std::floor(fx) + 0.5f;
            fz = std::floor(fz) + 0.5f;
          }
          issues.back().fix = CheckIssue::Fix::PullInside;
          issues.back().fixX = fx;
          issues.back().fixZ = fz;
        }
      }
      // Under the sea.
      if (input.water && input.groundAt != nullptr) {
        const float ground = input.groundAt(input.groundContext, p.x, p.z);
        if (ground < input.waterLevel) {
          char text[160];
          (void)std::snprintf(
            text,
            sizeof(text),
            "%s is under water (ground %.1f, sea %.1f)",
            what(p).c_str(),
            static_cast<double>(ground),
            static_cast<double>(input.waterLevel)
          );
          add(p.type == "Blank Marker" ? CheckIssue::Level::Warning : CheckIssue::Level::Note, p, text);
        }
      }
      // A partner of its type at each symmetric copy.
      if (input.symmetry != Symmetry::None && input.width > 0) {
        float copyX[kMaxSymmetryCopies], copyZ[kMaxSymmetryCopies];
        const int copies =
          HeightBrushCentres(input.width, input.height, p.x, p.z, input.symmetry, input.turns, copyX, copyZ);
        for (int c = 1; c < copies; ++c) {
          float nearest = 1e30f;
          for (const Point& q : points) {
            if (q.type == p.type) {
              nearest = std::min(nearest, std::hypot(q.x - copyX[c], q.z - copyZ[c]));
            }
          }
          if (nearest > 2.0f) {
            char text[200];
            (void)std::snprintf(
              text,
              sizeof(text),
              "%s has no partner at its symmetric copy (%.1f, %.1f); the nearest is %.1f away",
              what(p).c_str(),
              static_cast<double>(copyX[c]),
              static_cast<double>(copyZ[c]),
              static_cast<double>(nearest)
            );
            add(CheckIssue::Level::Warning, p, text);
            break;
          }
        }
      }
    }
    // Resources whose extractors (2 x 2) would overlap.
    for (std::size_t i = 0; i < points.size(); ++i) {
      for (std::size_t j = i + 1; j < points.size(); ++j) {
        const Point& a = points[i];
        const Point& b = points[j];
        if (a.type == "Blank Marker" || b.type == "Blank Marker") {
          continue;
        }
        if (std::fabs(a.x - b.x) < 2.0f && std::fabs(a.z - b.z) < 2.0f) {
          add(
            CheckIssue::Level::Error,
            a,
            what(a) + " overlaps " + b.marker->name + " (their extractors would share ground)"
          );
        }
      }
    }
    return issues;
  }
  std::vector<CheckIssue> CheckMapBasics(
    const MapBasicsInput& in
  )
  {
    std::vector<CheckIssue> issues;
    const auto add =
      [&](
        const CheckIssue::Level level, const std::string& marker, const std::string& text, const float x, const float z
      ) {
      issues.push_back({level, marker, text, x, z, std::string(), 0});
    };
    std::vector<std::pair<std::string, std::array<float, 2>>> starts;
    std::set<std::string> names;
    int masses = 0;
    if (in.markers != nullptr) {
      for (const SaveEntry& marker : *in.markers) {
        names.insert(marker.name);
        const std::string type = MarkerTypeOf(marker);
        float x = 0.0f, y = 0.0f, z = 0.0f;
        const bool placed = MarkerPosition(marker, x, y, z);
        if (!placed || !std::isfinite(x) || !std::isfinite(z) || std::fabs(x) > 1.0e6f || std::fabs(z) > 1.0e6f) {
          add(CheckIssue::Level::Error, marker.name, "has a broken position (none, not a number or huge)", 0.0f, 0.0f);
          continue;
        }
        if (type == "Blank Marker" && marker.name.rfind("ARMY_", 0) == 0) {
          starts.push_back({marker.name, {x, z}});
        }
        if (type == "Mass") {
          ++masses;
        }
        // Resources sit in the middle of their extractor's cell (1 x 1 mass, 3 x 3 hydrocarbon: x.5).
        if (type == "Mass" || type == "Hydrocarbon") {
          const float sx = std::floor(x) + 0.5f;
          const float sz = std::floor(z) + 0.5f;
          if (std::fabs(sx - x) > 0.02f || std::fabs(sz - z) > 0.02f) {
            char text[200];
            (void)std::snprintf(
              text,
              sizeof(text),
              "is off the build grid (%.2f, %.2f; the cell's middle is %.1f, %.1f)",
              static_cast<double>(x),
              static_cast<double>(z),
              static_cast<double>(sx),
              static_cast<double>(sz)
            );
            add(CheckIssue::Level::Warning, marker.name, text, x, z);
            issues.back().fix = CheckIssue::Fix::SnapToGrid;
            issues.back().fixX = sx;
            issues.back().fixZ = sz;
          }
        }
      }
    }
    // The starts and the scenario's armies, both ways.
    if (starts.empty()) {
      add(
        CheckIssue::Level::Error, "", "the map has no start positions (place them with the Markers tool)", 0.0f, 0.0f
      );
    } else if (starts.size() == 1) {
      add(
        CheckIssue::Level::Warning,
        starts[0].first,
        "is the map's only start position",
        starts[0].second[0],
        starts[0].second[1]
      );
    }
    for (const auto& [name, at] : starts) {
      if (!in.armies.empty() && std::find(in.armies.begin(), in.armies.end(), name) == in.armies.end()) {
        add(
          CheckIssue::Level::Warning,
          name,
          "is a start position the scenario's army list hasn't got (Armies panel)",
          at[0],
          at[1]
        );
      }
    }
    for (const std::string& army : in.armies) {
      if (std::none_of(starts.begin(), starts.end(), [&](const auto& s) {
        return s.first == army;
      })) {
        add(
          CheckIssue::Level::Error, army, "is in the scenario's army list but has no start position marker", 0.0f, 0.0f
        );
      }
    }
    if (masses == 0) {
      add(CheckIssue::Level::Warning, "", "the map has no mass points", 0.0f, 0.0f);
    } else if (!starts.empty() && masses < 4 * static_cast<int>(starts.size())) {
      add(
        CheckIssue::Level::Note,
        "",
        std::to_string(masses) + " mass points for " + std::to_string(starts.size()) +
          " start positions (usually at least 4 each)",
        0.0f,
        0.0f
      );
    }
    // Chains naming markers the map hasn't got.
    if (in.chains != nullptr) {
      for (const MarkerChain& chain : *in.chains) {
        std::vector<std::string> missing;
        for (const std::string& name : chain.markers) {
          if (names.count(name) == 0) {
            missing.push_back(name);
          }
        }
        if (!missing.empty()) {
          add(
            CheckIssue::Level::Warning,
            chain.name,
            "chain names " + std::to_string(missing.size()) +
              " marker(s) the map hasn't got (first: " + missing.front() + ")",
            0.0f,
            0.0f
          );
        }
      }
    }
    for (const auto& [blueprint, at] : in.missingProps) {
      add(CheckIssue::Level::Warning, "", "prop blueprint the game hasn't got: " + blueprint, at[0], at[1]);
    }
    if (in.name.empty()) {
      add(CheckIssue::Level::Warning, "", "the map has no name (Map panel)", 0.0f, 0.0f);
    }
    if (in.description.empty()) {
      add(CheckIssue::Level::Note, "", "the map has no description (Map panel)", 0.0f, 0.0f);
    }
    return issues;
  }

  std::vector<CheckIssue> CheckPropSymmetry(
    const std::vector<PropPoint>& props,
    const Symmetry symmetry,
    const int turns,
    const int width,
    const int height,
    const float reach,
    const std::size_t listed
  )
  {
    std::vector<CheckIssue> issues;
    if (symmetry == Symmetry::None || width <= 0 || props.empty()) {
      return issues;
    }
    // Props in cells of `reach` units, by blueprint: a copy's partners are in its cell or the eight around it.
    const float cell = std::max(reach, 0.5f);
    const auto key = [&](const std::string& blueprint, const int cx, const int cz) {
      return blueprint + "#" + std::to_string(cx) + "," + std::to_string(cz);
    };
    std::unordered_map<std::string, std::vector<std::size_t>> grid;
    grid.reserve(props.size());
    for (std::size_t i = 0; i < props.size(); ++i) {
      grid[key(
             props[i].blueprint,
             static_cast<int>(std::floor(props[i].x / cell)),
             static_cast<int>(std::floor(props[i].z / cell))
           )]
        .push_back(i);
    }
    const auto partnerNear = [&](const std::string& blueprint, const float x, const float z) {
      const int cx = static_cast<int>(std::floor(x / cell));
      const int cz = static_cast<int>(std::floor(z / cell));
      for (int dz = -1; dz <= 1; ++dz) {
        for (int dx = -1; dx <= 1; ++dx) {
          const auto found = grid.find(key(blueprint, cx + dx, cz + dz));
          if (found == grid.end()) {
            continue;
          }
          for (const std::size_t j : found->second) {
            if (std::hypot(props[j].x - x, props[j].z - z) <= reach) {
              return true;
            }
          }
        }
      }
      return false;
    };
    std::size_t unmatched = 0;
    double unmatchedMass = 0.0;
    double totalMass = 0.0;
    std::vector<CheckIssue> examples;
    for (const PropPoint& prop : props) {
      totalMass += prop.mass;
      float copyX[kMaxSymmetryCopies], copyZ[kMaxSymmetryCopies];
      const int copies = HeightBrushCentres(width, height, prop.x, prop.z, symmetry, turns, copyX, copyZ);
      for (int c = 1; c < copies; ++c) {
        if (partnerNear(prop.blueprint, copyX[c], copyZ[c])) {
          continue;
        }
        ++unmatched;
        unmatchedMass += prop.mass;
        if (examples.size() < listed) {
          const std::string name = prop.blueprint.substr(prop.blueprint.find_last_of('/') + 1);
          char text[240];
          (void)std::snprintf(
            text,
            sizeof(text),
            "%s at (%.1f, %.1f) has no partner at its symmetric copy (%.1f, %.1f)%s",
            name.c_str(),
            static_cast<double>(prop.x),
            static_cast<double>(prop.z),
            static_cast<double>(copyX[c]),
            static_cast<double>(copyZ[c]),
            prop.mass > 0.0f ? "" : " (no reclaim)"
          );
          CheckIssue issue;
          issue.level = CheckIssue::Level::Note;
          issue.marker = "Prop " + name;
          issue.text = text;
          issue.x = prop.x;
          issue.z = prop.z;
          examples.push_back(std::move(issue));
        }
        break;
      }
    }
    if (unmatched == 0) {
      return issues;
    }
    CheckIssue summary;
    summary.level = unmatchedMass > 0.0 ? CheckIssue::Level::Warning : CheckIssue::Level::Note;
    summary.marker = "Props";
    char text[240];
    (void)std::snprintf(
      text,
      sizeof(text),
      "%zu of %zu props have no partner at a symmetric copy: %.0f of %.0f reclaim mass isn't mirrored%s",
      unmatched,
      props.size(),
      unmatchedMass,
      totalMass,
      unmatched > examples.size() ? " (the first ones listed)" : ""
    );
    summary.text = text;
    if (!examples.empty()) {
      summary.x = examples.front().x;
      summary.z = examples.front().z;
    }
    issues.push_back(std::move(summary));
    issues.insert(issues.end(), examples.begin(), examples.end());
    return issues;
  }

  const char* CheckFixName(
    const CheckIssue::Fix fix
  )
  {
    switch (fix) {
    case CheckIssue::Fix::PullInside:
      return "Pull inside";
    case CheckIssue::Fix::SnapToGrid:
      return "Snap to grid";
    default:
      return "";
    }
  }
} // namespace faf::editor
