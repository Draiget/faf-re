#pragma once

#include <string>
#include <vector>

namespace faf::editor
{
  /** One prop of the Props tool's paint list: what Scatter places, how often, turned and scaled how. */
  struct PropPaintEntry
  {
    /** The prop blueprint's path (`/env/evergreen/props/trees/pine06_s1_prop.bp`). */
    std::string blueprint;
    /** The turn about the vertical, in whole degrees, picked between these. */
    int rotationMin = 0;
    int rotationMax = 360;
    /** The scale written to the map for it (the game reads it and ignores it: CWldProps::Load, 0x008918E0). */
    float scaleMin = 1.0f;
    float scaleMax = 1.0f;
    /** Its weight among the list's: picked with chance / sum of chances. */
    int chance = 100;

    bool operator==(
      const PropPaintEntry& other
    ) const
    {
      return blueprint == other.blueprint && rotationMin == other.rotationMin && rotationMax == other.rotationMax &&
        scaleMin == other.scaleMin && scaleMax == other.scaleMax && chance == other.chance;
    }
  };

  /**
   * FAForeverMapEditor's paint set (`.proppaintset`, JsonUtility's dump of its PaintButtonsSet): each prop's blueprint,
   * scale and rotation ranges and chance. Written with each entry's own values (FAFME's export writes one entry's
   * values for all, and its scale minimum as the maximum).
   */
  std::string PaintSetToProppaintset(const std::vector<PropPaintEntry>& entries);
  bool PaintSetFromProppaintset(const std::string& text, std::vector<PropPaintEntry>& entries, std::string& error);

  /** FAFME's GetRandomProp: the entry `roll` (0 to 1) falls on, each as wide as its chance; -1 when none has one. */
  int PickPaintEntry(const std::vector<PropPaintEntry>& entries, float roll);
} // namespace faf::editor
