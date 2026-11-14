#pragma once

// What the Paths panel and the view share: the path being edited, its selected points, and the panel's asks the view
// carries out on its next frame (Preview, Apply, Unapply, Bake, the skeleton generator's Apply all).

#include "editor/tools/EdSkeleton.h"

#include <string>
#include <vector>

namespace faf::editor
{
  struct PathEditState
  {
    /** The view's clicks edit paths (a click adds a point, a drag moves one, Shift+click inserts, Del deletes). */
    bool editing = false;
    /** The path that clicks edit; empty: the next click starts a new one with `newMode` / `newBezier`. */
    std::string current;
    int newMode = 0;
    bool newBezier = false;
    /** Selected control points of the current path (0-based). */
    std::vector<int> selected;
    /** Grid snap of new and moved points (0: none). */
    float snap = 0.0f;

    enum class Ask
    {
      None,
      Preview,
      RevertPreview,
      Apply,
      Unapply,
      Bake,
      /** Several paths applied in order as one undo step. */
      ApplyMany,
      /** The map skeleton (`skeleton` settings): new skeleton paths, Apply all, Clear. */
      SkeletonGenerate,
      SkeletonApply,
      SkeletonClear,
    };
    SkeletonSettings skeleton;
    Ask ask = Ask::None;
    std::vector<std::string> askIds;
    /** Live preview: the view previews the current path again after each change (when it isn't busy). */
    bool livePreview = false;

    /** What the view said about the last ask. */
    std::string status;
    bool previewShown = false;
  };
} // namespace faf::editor
