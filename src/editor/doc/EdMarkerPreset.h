#pragma once

#include <string>
#include <vector>

#include "editor/doc/EdSaveFile.h"

namespace faf::editor
{
  /** What an import of a `.fafmapmarkers` file did. */
  struct MarkerImport
  {
    /** The new markers' names, in the file's order. */
    std::vector<std::string> names;
    /** Markers of a type the editor doesn't place (weather, effect, objective, auto path node), left out. */
    int skipped = 0;
    /** Path-node links made between the new markers. */
    int links = 0;
  };

  /**
   * FAForeverMapEditor's marker file (`.fafmapmarkers`, JsonUtility's dump of its ExportMarkers): each marker's type
   * as FAFME's MarkerTypes number, its position in FAFME's world units (x / 10, y / 10, -z / 10), its rotation as a
   * Unity quaternion, and its links as indices into the file. Writes the markers named in `names` (all when empty);
   * links to markers outside them are left out, as FAFME's export does.
   */
  std::string MarkersToFafmapmarkers(const std::vector<SaveEntry>& markers, const std::vector<std::string>& names, int mapWidth,
                                     int mapHeight);
  /**
   * Adds a `.fafmapmarkers` file's markers to `markers` under new names (the type's next free one, also clear of
   * `reserved`: the scenario's armies, which a start position is named after), with their links; false with `error`
   * when the text isn't such a file.
   */
  bool MarkersFromFafmapmarkers(const std::string& text, std::vector<SaveEntry>& markers, MarkerImport& result, std::string& error,
                                const std::vector<std::string>& reserved = {});

  /** Unity's Quaternion.Euler (degrees; z, then x, then y) and its eulerAngles back (degrees in [0, 360)). */
  void UnityEulerToQuaternion(const float (&degrees)[3], float (&quaternion)[4]);
  void UnityQuaternionToEuler(const float (&quaternion)[4], float (&degrees)[3]);
} // namespace faf::editor
