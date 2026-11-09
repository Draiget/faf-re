#pragma once

#include "editor/tools/EdHeightBrush.h"

#include <utility>

namespace faf::editor
{
  /**
   * The tool box, as the mockup lays it out (tmp/claude/map-editor/editor-mockup.html): a strip of tool icons
   * and, beside it, the chosen tool's settings (brush modes, size, strength, falloff, the symmetry modes with
   * their diagrams, limits). The settings are kept here; the tools act on a map from stages 3 to 6 of the plan.
   */
  class EdTools
  {
  public:
    /** Draws the panel's contents into the current ImGui window. */
    void Draw();

    /** Whether the Terrain tool is the chosen one (the viewport's left button paints heights). */
    [[nodiscard]] bool TerrainToolActive() const noexcept { return mTool == 1; }

    /** The terrain brush as the panel sets it (Flatten's height is the stroke's, set by the viewport). */
    [[nodiscard]] HeightBrush CurrentHeightBrush() const noexcept
    {
      HeightBrush brush;
      brush.mode = static_cast<HeightBrushMode>(mBrushMode);
      brush.symmetry = static_cast<Symmetry>(mSymmetry);
      brush.radius = mRadius;
      brush.strength = mStrength;
      brush.falloff = mFalloff;
      brush.turns = mNWay;
      return brush;
    }

    /** Test runs (`/symcheck`): the Terrain tool with this symmetry (the panel's index), then Check or Copy. */
    void SetSymmetry(const int index, const int turns) noexcept
    {
      mTool = 1;
      mSymmetry = index;
      mNWay = turns;
    }
    void RequestCheck() noexcept { mCheckRequested = true; }
    void RequestRepair() noexcept { mRepairRequested = true; }

    /** The symmetry check's buttons, taken by the view each frame. */
    [[nodiscard]] bool TakeCheckRequest() noexcept { return std::exchange(mCheckRequested, false); }
    [[nodiscard]] bool TakeRepairRequest() noexcept { return std::exchange(mRepairRequested, false); }
    /** Whether the view marks the vertices whose copies differ. */
    [[nodiscard]] bool ShowDifferences() const noexcept { return mShowDifferences; }

    /** The check's result for the panel, for the symmetry it checked (`checked` 0: nothing to show). */
    void SetCheckResult(const int checked, const int differing, const int largestWords, const HeightBrush& checkedWith) noexcept
    {
      mChecked = checked;
      mDiffering = differing;
      mLargest = largestWords;
      mCheckedSymmetry = static_cast<int>(checkedWith.symmetry);
      mCheckedTurns = checkedWith.turns;
    }

    /** True if the last check was made with the panel's current symmetry. */
    [[nodiscard]] bool CheckIsCurrent() const noexcept
    {
      return mChecked > 0 && mCheckedSymmetry == mSymmetry && (mSymmetry != 9 || mCheckedTurns == mNWay);
    }

  private:
    void DrawStrip();
    void DrawTerrain();
    void DrawTexture();
    void DrawWater();
    void DrawProps();
    void DrawDecals();
    void DrawMarkers();
    void DrawSelect();
    void DrawBrush(bool withModes);
    void DrawSymmetry();

    int mTool = 1;
    int mBrushMode = 0;
    float mRadius = 14.0f;
    float mStrength = 0.5f;
    float mFalloff = 0.6f;
    int mSymmetry = 6; // both axes
    int mNWay = 3;
    bool mLimitHeight = false;
    bool mLimitSlope = false;
    int mMarkerType = 0;
    int mDecalMode = 1; // spline
    float mWaterLevel = 20.0f;
    bool mSea = true;

    bool mCheckRequested = false;
    bool mRepairRequested = false;
    bool mShowDifferences = true;
    int mChecked = 0;
    int mDiffering = 0;
    int mLargest = 0;
    int mCheckedSymmetry = -1;
    int mCheckedTurns = 0;
  };
} // namespace faf::editor
