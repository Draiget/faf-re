#pragma once

#include "editor/tools/EdHeightBrush.h"
#include "editor/tools/EdMaskBrush.h"

#include <cmath>
#include <memory>
#include <string>
#include <utility>
#include <vector>

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
    /** Whether the Texture tool is the chosen one (the viewport's left button paints a layer's mask). */
    [[nodiscard]] bool TextureToolActive() const noexcept { return mTool == 2; }

    /** The texture brush as the panel sets it: the brush's shape, the layer, the mode. */
    [[nodiscard]] MaskBrush CurrentMaskBrush() const noexcept
    {
      MaskBrush brush;
      brush.shape = CurrentHeightBrush();
      brush.mode = static_cast<MaskBrushMode>(mMaskMode);
      brush.layer = mMaskLayer;
      brush.lowerAbove = mLowerAbove;
      return brush;
    }
    /** The open map's layer texture paths (lower, strata 1-8, upper), for the layer list. */
    void SetLayerNames(std::vector<std::string> names) { mLayerNames = std::move(names); }
    /** Apply rules to whole map was pressed; the rules. */
    [[nodiscard]] bool TakeRulesRequest() noexcept { return std::exchange(mRulesRequested, false); }
    [[nodiscard]] const std::vector<MaskRule>& Rules() const noexcept { return mRules; }
    /** Test runs (`/maskrule`): one more rule, then Apply. */
    void AddRule(const MaskRule& rule)
    {
      mTool = 2;
      mRules.push_back(rule);
    }
    void RequestRules() noexcept { mRulesRequested = true; }
    /** Test runs (`/masklayer`): the Texture tool on this layer. */
    void SetMaskLayer(const int layer) noexcept
    {
      mTool = 2;
      mMaskLayer = layer;
    }

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
      brush.setTo = mSetHeight * 128.0f;
      brush.terraceStep = mTerraceStep * 128.0f;
      brush.planeSet = mPlaneSet;
      brush.planeX = mPlaneX;
      brush.planeZ = mPlaneZ;
      brush.planeC = mPlaneC;
      brush.stamp = mStamp.get();
      brush.stampHeight = mStampHeight * 128.0f;
      brush.limitHeight = mLimitHeight;
      brush.limitLow = mLimitLow * 128.0f;
      brush.limitHigh = mLimitHigh * 128.0f;
      brush.limitSlope = mLimitSlope;
      brush.limitMaxSlope = std::tan(mLimitSlopeDegrees * 0.0174532925f);
      return brush;
    }

    /** Plane mode: a picked point (game units: x, height, z); the plane goes through the last three. */
    void AddPlanePoint(float x, float height, float z) noexcept;
    void ClearPlanePoints() noexcept
    {
      mPlanePoints = 0;
      mPlaneSet = false;
    }
    /** The picked points, oldest first, for the view to mark. */
    [[nodiscard]] int PlanePoints(float (&x)[3], float (&height)[3], float (&z)[3]) const noexcept;

    /** Stamp mode: the image the Stamp image button loaded. */
    [[nodiscard]] bool TakeStampRequest() noexcept { return std::exchange(mStampRequested, false); }
    void SetStamp(HeightStamp stamp, std::string name)
    {
      mStamp = std::make_shared<HeightStamp>(std::move(stamp));
      mStampName = std::move(name);
    }

    /** Test runs (`/symcheck`): the Terrain tool with this symmetry (the panel's index), then Check or Copy. */
    void SetSymmetry(const int index, const int turns) noexcept
    {
      mTool = 1;
      mSymmetry = index;
      mNWay = turns;
    }
    void RequestCheck() noexcept { mCheckRequested = true; }
    void RequestImport() noexcept { mImportRequested = true; }
    /** Test runs (`/brush`): the Terrain tool with this brush mode (a HeightBrushMode). */
    void SetBrushMode(const int mode) noexcept
    {
      mTool = 1;
      mBrushMode = mode;
    }
    void RequestRepair() noexcept { mRepairRequested = true; }

    /** The height field's Import and Export buttons, taken by the app each frame (it asks for the file). */
    [[nodiscard]] bool TakeImportRequest() noexcept { return std::exchange(mImportRequested, false); }
    [[nodiscard]] bool TakeExportRequest() noexcept { return std::exchange(mExportRequested, false); }
    /** Heights times this on import and export. */
    [[nodiscard]] float HeightScale() const noexcept { return mHeightScale; }
    /** The exported image's width in samples, 0 for the map's own. */
    [[nodiscard]] int ExportWidth() const noexcept { return kExportWidths[mExportSize]; }

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
    void DrawSymmetry(bool withCheck = true);
    void DrawLimits();

    int mTool = 1;
    int mBrushMode = 0;
    float mRadius = 14.0f;
    float mStrength = 0.5f;
    float mFalloff = 0.6f;
    int mSymmetry = 6; // both axes
    int mNWay = 3;
    bool mLimitHeight = false;
    float mLimitLow = 0.0f;
    float mLimitHigh = 100.0f;
    bool mLimitSlope = false;
    float mLimitSlopeDegrees = 30.0f;
    float mSetHeight = 20.0f;
    float mTerraceStep = 5.0f;
    float mPlanePointX[3]{};
    float mPlanePointH[3]{};
    float mPlanePointZ[3]{};
    int mPlanePoints = 0;
    bool mPlaneSet = false;
    double mPlaneX = 0.0;
    double mPlaneZ = 0.0;
    double mPlaneC = 0.0;
    std::shared_ptr<HeightStamp> mStamp;
    std::string mStampName;
    float mStampHeight = 20.0f;
    bool mStampRequested = false;
    int mMarkerType = 0;
    int mDecalMode = 1; // spline
    float mWaterLevel = 20.0f;
    bool mSea = true;

    static constexpr int kExportWidths[] = {0, 257, 513, 1025, 2049, 4097};
    bool mImportRequested = false;
    bool mExportRequested = false;
    float mHeightScale = 1.0f;
    int mExportSize = 0;

    int mMaskLayer = 0;
    int mMaskMode = 0;
    bool mLowerAbove = true;
    std::vector<std::string> mLayerNames;
    std::vector<MaskRule> mRules;
    bool mRulesRequested = false;

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
