#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "editor/doc/EdSaveFile.h"

namespace faf::editor
{
  /** A marker type the Markers tool places: its `type`, name and the properties the game's own saves give it. */
  struct MarkerType
  {
    /** The `type` string (`Mass`, `Land Path Node`). */
    const char* type;
    /** The palette's group (Resources, Starts, AI, Path nodes, Other). */
    const char* group;
    /** New names: this prefix and a two-digit number (`Mass 00`); start positions are `ARMY_<n>`. */
    const char* prefix;
    /** The `color` string (ARGB hex). */
    const char* color;
    /** The marker's prop blueprint. */
    const char* prop;
    /** Further properties, `key = value text`, in the order the saves write them. */
    std::vector<std::pair<std::string, std::string>> extra;
  };

  /** Every type the palette offers, from the retail maps' saves (SCMP_009's markers, one of each). */
  const std::vector<MarkerType>& MarkerTypes();
  /** The palette entry of a `type` string, or null. */
  const MarkerType* FindMarkerType(const std::string& type);

  /** The next free name for a type among `markers` (`Mass 07`, or `ARMY_9` for a start position). */
  std::string NextMarkerName(const std::vector<SaveEntry>& markers, const MarkerType& type);

  /** A new marker of `type` named `name` at (x, y, z), its properties in the saves' order. */
  SaveEntry NewMarker(const MarkerType& type, const std::string& name, float x, float y, float z);

  /** A marker's position (from `position`); false when it has none. */
  bool MarkerPosition(const SaveEntry& marker, float& x, float& y, float& z);
  /** A marker's colour as ARGB (from `color`, else grey). */
  std::uint32_t MarkerColor(const SaveEntry& marker);
  /** A marker's `type` string. */
  std::string MarkerTypeOf(const SaveEntry& marker);
  /** A path node's neighbours (`adjacentTo`, names split on spaces). */
  std::vector<std::string> MarkerLinks(const SaveEntry& marker);

  /** Whether a marker is a path node (it has a `graph`). */
  bool IsPathNode(const SaveEntry& marker);
  /** Whether path nodes `a` and `b` are linked (either one names the other). */
  bool MarkersLinked(const std::vector<SaveEntry>& markers, const std::string& a, const std::string& b);
  /**
   * Links or unlinks path nodes `a` and `b`, both ways, as the game's saves keep them. Nodes of different graphs
   * (land and water) aren't linked. Returns whether anything changed.
   */
  bool SetMarkerLink(std::vector<SaveEntry>& markers, const std::string& a, const std::string& b, bool linked);
  /** Drops every link naming `name` (the marker is being deleted); returns how many markers changed. */
  int RemoveLinksTo(std::vector<SaveEntry>& markers, const std::string& name);
  /** The marker tree's groups, in the order the panel lists them. */
  enum class MarkerGroup
  {
    Starts,
    Resources,
    Ai,
    PathNodes,
    Other,
  };
  constexpr int kMarkerGroupCount = 5;
  /** A marker's group: start positions, mass and hydrocarbon, AI markers, path nodes, everything else. */
  MarkerGroup MarkerGroupOf(const SaveEntry& marker);
  const char* MarkerGroupName(MarkerGroup group);

  /** The nearest marker of `type` within `reach` of (x, z), or -1. */
  int MarkerNear(const std::vector<SaveEntry>& markers, const std::string& type, float x, float z, float reach);
} // namespace faf::editor
