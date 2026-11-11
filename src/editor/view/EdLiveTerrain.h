#pragma once

#include <vector>

namespace moho
{
  class CHeightField;
  class CWldMap;
} // namespace moho

namespace faf::editor
{
  /** A rectangle of height samples (inclusive), as the height tools change them. */
  struct HeightRect
  {
    int x0 = 0;
    int z0 = 0;
    int x1 = 0;
    int z1 = 0;
  };

  /**
   * Height edits made in the editor's view while a solo play runs behind it, put into the play (WPE.40): the session's
   * rendered terrain at once (the rectangles copied in and their normals redrawn, whatever its camera sees), and the
   * sim's own copy of the heights at the start of its next beat (`moho::gSimBeforeBeat`, on the sim's thread). The two
   * maps are the same size (the play was loaded from this map's files); anything else is left alone.
   */
  void LiveHeights(moho::CWldMap& sessionMap, const moho::CHeightField& edited, const std::vector<HeightRect>& rects);
  /** No play: what is still queued is dropped and the sim hook taken away (a next play starts from its own files). */
  void DropLiveHeights();
  /**
   * Water levels changed in the editor's view in front of a play: the sim's copy of them set at the start of its next
   * beat (WPE.41; the play's drawn water is set by the caller). What floats and what is under water follows them.
   */
  void LiveWaterLevels(bool enabled, float elevation, float deep, float abyss);
  /** Test runs (`/playnoreseat`): the play's units left where they were on changed ground, to compare against. */
  void SetLiveHeightsNoReseat(bool off) noexcept;
  /** Test runs (`/playnopathdirty`): the play's path clusters left as they were over changed ground, to compare
   * against. */
  void SetLiveHeightsNoPathDirty(bool off) noexcept;
} // namespace faf::editor
