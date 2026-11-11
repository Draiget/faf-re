#pragma once

#include <set>
#include <string>

namespace faf::editor
{
  /**
   * The editor's view switches and tool, kept per map across restarts (user ask 2026-11-11: "all toggles for visibility
   * of markers, nav stuff, models and so on, including the selected tool, saved over restarts, for each map"). One file
   * a map under `%LOCALAPPDATA%\FAForever\Editor\views`, `key=value` lines; a key the file lacks keeps its value.
   */
  struct ViewState
  {
    int tool = 1;
    bool grid = false;
    bool snap = false;
    float gridStep = 1.0f;
    bool keepOnGround = true;
    bool slope = false;
    bool kmGrid = false;
    bool terrainTypes = true;
    bool pathing = false;
    int pathingLayer = 0;
    bool layerWeight = false;
    bool differences = true;
    bool props = true;
    bool units = true;
    bool gameUnits = true;
    std::set<std::string> hiddenMarkerTypes;

    bool operator==(const ViewState& other) const
    {
      return tool == other.tool && grid == other.grid && snap == other.snap && gridStep == other.gridStep && keepOnGround == other.keepOnGround &&
             slope == other.slope && kmGrid == other.kmGrid && terrainTypes == other.terrainTypes && pathing == other.pathing &&
             pathingLayer == other.pathingLayer && layerWeight == other.layerWeight && differences == other.differences &&
             props == other.props && units == other.units && gameUnits == other.gameUnits && hiddenMarkerTypes == other.hiddenMarkerTypes;
    }
    bool operator!=(const ViewState& other) const { return !(*this == other); }
  };

  std::string WriteViewState(const ViewState& state);
  /** `state` with what `text` sets (the keys it has; unknown lines left out). */
  ViewState ReadViewState(const std::string& text, ViewState state);

  /** The file's name for a map (its folder's name and a hash of its scenario's path, so two copies don't share one). */
  std::string ViewStateFileName(const std::string& scenarioPath);
} // namespace faf::editor
