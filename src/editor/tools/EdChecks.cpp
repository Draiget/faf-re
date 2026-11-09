#include "editor/tools/EdChecks.h"

#include <algorithm>
#include <cmath>
#include <cstdio>

#include "editor/tools/EdMarkers.h"

namespace faf::editor
{
  const char* CheckLevelName(const CheckIssue::Level level)
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

  std::vector<CheckIssue> CheckMarkers(const MarkerCheckInput& input)
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
      issues.push_back({level, p.marker->name, text, p.x, p.z});
    };
    const auto what = [](const Point& p) { return std::string(p.type == "Blank Marker" ? "start position" : p.type == "Mass" ? "mass point" : "hydrocarbon point"); };

    for (const Point& p : points) {
      // On the map, and inside the playable area.
      if (input.width > 0 && (p.x < 0.0f || p.z < 0.0f || p.x > static_cast<float>(input.width - 1) || p.z > static_cast<float>(input.height - 1))) {
        add(CheckIssue::Level::Error, p, what(p) + " is off the map");
        continue;
      }
      if (input.playable) {
        const auto& a = *input.playable;
        if (p.x < static_cast<float>(a[0]) || p.z < static_cast<float>(a[1]) || p.x > static_cast<float>(a[2]) || p.z > static_cast<float>(a[3])) {
          add(CheckIssue::Level::Error, p, what(p) + " is outside the playable area");
        }
      }
      // Under the sea.
      if (input.water && input.groundAt != nullptr) {
        const float ground = input.groundAt(input.groundContext, p.x, p.z);
        if (ground < input.waterLevel) {
          char text[160];
          (void)std::snprintf(text, sizeof(text), "%s is under water (ground %.1f, sea %.1f)", what(p).c_str(), static_cast<double>(ground),
                              static_cast<double>(input.waterLevel));
          add(p.type == "Blank Marker" ? CheckIssue::Level::Warning : CheckIssue::Level::Note, p, text);
        }
      }
      // A partner of its type at each symmetric copy.
      if (input.symmetry != Symmetry::None && input.width > 0) {
        float copyX[kMaxSymmetryCopies], copyZ[kMaxSymmetryCopies];
        const int copies = HeightBrushCentres(input.width, input.height, p.x, p.z, input.symmetry, input.turns, copyX, copyZ);
        for (int c = 1; c < copies; ++c) {
          float nearest = 1e30f;
          for (const Point& q : points) {
            if (q.type == p.type) {
              nearest = std::min(nearest, std::hypot(q.x - copyX[c], q.z - copyZ[c]));
            }
          }
          if (nearest > 2.0f) {
            char text[200];
            (void)std::snprintf(text, sizeof(text), "%s has no partner at its symmetric copy (%.1f, %.1f); the nearest is %.1f away",
                                what(p).c_str(), static_cast<double>(copyX[c]), static_cast<double>(copyZ[c]), static_cast<double>(nearest));
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
          add(CheckIssue::Level::Error, a, what(a) + " overlaps " + b.marker->name + " (their extractors would share ground)");
        }
      }
    }
    return issues;
  }
} // namespace faf::editor
