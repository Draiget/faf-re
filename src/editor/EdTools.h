#pragma once

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
  };
} // namespace faf::editor
