#include "editor/doc/EdViewState.h"

#include <cctype>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <sstream>

namespace faf::editor
{
  std::string WriteViewState(const ViewState& s)
  {
    std::ostringstream out;
    const auto flag = [&](const char* const key, const bool on) { out << key << '=' << (on ? 1 : 0) << '\n'; };
    out << "tool=" << s.tool << '\n';
    flag("grid", s.grid);
    flag("snap", s.snap);
    char step[32];
    (void)std::snprintf(step, sizeof(step), "%g", static_cast<double>(s.gridStep));
    out << "gridStep=" << step << '\n';
    flag("keepOnGround", s.keepOnGround);
    flag("slope", s.slope);
    flag("kmGrid", s.kmGrid);
    flag("terrainTypes", s.terrainTypes);
    flag("pathing", s.pathing);
    out << "pathingLayer=" << s.pathingLayer << '\n';
    flag("layerWeight", s.layerWeight);
    flag("differences", s.differences);
    flag("props", s.props);
    flag("units", s.units);
    flag("gameUnits", s.gameUnits);
    for (const std::string& type : s.hiddenMarkerTypes) {
      out << "hideMarkers=" << type << '\n';
    }
    return out.str();
  }

  ViewState ReadViewState(const std::string& text, ViewState s)
  {
    std::istringstream lines(text);
    std::string line;
    bool hiddenSeen = false;
    while (std::getline(lines, line)) {
      if (!line.empty() && line.back() == '\r') {
        line.pop_back();
      }
      const std::size_t eq = line.find('=');
      if (eq == std::string::npos) {
        continue;
      }
      const std::string key = line.substr(0, eq);
      const std::string value = line.substr(eq + 1);
      const bool on = value == "1";
      if (key == "tool") {
        s.tool = std::atoi(value.c_str());
      } else if (key == "grid") {
        s.grid = on;
      } else if (key == "snap") {
        s.snap = on;
      } else if (key == "gridStep") {
        s.gridStep = static_cast<float>(std::atof(value.c_str()));
      } else if (key == "keepOnGround") {
        s.keepOnGround = on;
      } else if (key == "slope") {
        s.slope = on;
      } else if (key == "kmGrid") {
        s.kmGrid = on;
      } else if (key == "terrainTypes") {
        s.terrainTypes = on;
      } else if (key == "pathing") {
        s.pathing = on;
      } else if (key == "pathingLayer") {
        s.pathingLayer = std::atoi(value.c_str());
      } else if (key == "layerWeight") {
        s.layerWeight = on;
      } else if (key == "differences") {
        s.differences = on;
      } else if (key == "props") {
        s.props = on;
      } else if (key == "units") {
        s.units = on;
      } else if (key == "gameUnits") {
        s.gameUnits = on;
      } else if (key == "hideMarkers") {
        if (!hiddenSeen) {
          s.hiddenMarkerTypes.clear(); // the file's list replaces the one before
          hiddenSeen = true;
        }
        s.hiddenMarkerTypes.insert(value);
      }
    }
    // A file that names no hidden types hides none.
    if (!hiddenSeen && text.find("tool=") != std::string::npos) {
      s.hiddenMarkerTypes.clear();
    }
    if (s.gridStep <= 0.0f) {
      s.gridStep = 1.0f;
    }
    return s;
  }

  std::string ViewStateFileName(const std::string& scenarioPath)
  {
    // `/maps/scmp_009/scmp_009_scenario.lua` -> `scmp_009-<hash>.txt`.
    std::string folder = scenarioPath;
    if (const std::size_t slash = folder.find_last_of("/\\"); slash != std::string::npos) {
      folder.erase(slash);
    }
    if (const std::size_t slash = folder.find_last_of("/\\"); slash != std::string::npos) {
      folder.erase(0, slash + 1);
    }
    std::string name;
    for (const char c : folder) {
      const char lower = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
      name += std::isalnum(static_cast<unsigned char>(lower)) != 0 || lower == '.' || lower == '_' || lower == '-' ? lower : '_';
    }
    // FNV-1a of the lower-cased path: the same map opened again finds its file.
    std::uint32_t hash = 2166136261u;
    for (const char c : scenarioPath) {
      hash = (hash ^ static_cast<unsigned char>(std::tolower(static_cast<unsigned char>(c)))) * 16777619u;
    }
    char tail[16];
    (void)std::snprintf(tail, sizeof(tail), "-%08x.txt", hash);
    return (name.empty() ? std::string("map") : name) + tail;
  }
} // namespace faf::editor
