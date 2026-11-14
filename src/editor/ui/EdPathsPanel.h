#pragma once

// The Paths panel (FAF Studio's panels_paths.lua and the skeleton part of panels_sctools.lua): the map's kept paths,
// the current path's settings and its selected points, the profile, texture, props and decals along it, Preview / Apply
// / Unapply / Bake, the grade report, and the map skeleton generator. The view does the work (EdMapScenePaths.cpp).

#include "editor/doc/EdDocument.h"
#include "editor/tools/EdPathEdit.h"

#include <functional>
#include <memory>
#include <string>

namespace faf::editor
{
  class EdPathsPanel
  {
  public:
    explicit EdPathsPanel(EdDocument& document);
    void Draw(bool& open, bool mapOpen);
    [[nodiscard]] PathEditState& State() noexcept
    {
      return mState;
    }
    /** The ground's height at a point (the view's); used to pin points and switch modes. */
    std::function<float(float, float)> ground;

  private:
    void DrawList();
    void DrawPath(KeptPath& path);
    void DrawPoints(KeptPath& path);
    void DrawProfile(KeptPath& path);
    void DrawAlong(KeptPath& path);
    void DrawActions(const KeptPath& path);
    void DrawSkeleton();
    /** After a control: a change of a dragged control is recorded when it ends, others at once (one undo step each). */
    void Track(bool changed);
    float Ground(float x, float z) const;

    EdDocument& mDocument;
    PathEditState mState;
    EdDocument::PathsState mFrameStart;
    std::unique_ptr<EdDocument::PathsState> mDragBefore;
    int mReportRevision = -1;
    std::string mReportFor;
    KeptPathReport mReport;
  };
} // namespace faf::editor
