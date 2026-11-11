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
} // namespace faf::editor
