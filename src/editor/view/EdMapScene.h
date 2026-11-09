#pragma once

#include <memory>
#include <vector>

#include <Windows.h>

#include "editor/tools/EdHeightBrush.h"

namespace moho
{
  class CameraImpl;
  class CWldMap;
  class MeshInstance;
  class SimpleRenderWorldView;
} // namespace moho

namespace faf::editor
{
  class EdDocument;
  class EdTools;

  /**
   * The opened map in the game's viewport between plays (board task WPE.3). The renderer draws the map in
   * `moho::sWldMap` through its world views, as the original editor did (`REN_SetWldMap`, 0x007FA150).
   * While a map is open and no play runs, the scene puts the document's map there and registers one world
   * view with its own camera (made the way the strategic preview render makes one). It leaves before a
   * play's session takes the map over, and before the document drops its map.
   *
   * Camera: middle mouse button drag orbits (turns and tilts around the point looked at), Shift + middle
   * drag or right drag pans (the ground follows the cursor), WASD or the arrows move (Shift faster), the
   * wheel zooms toward the point under the cursor without changing the camera's tilt or turn; Home frames
   * the whole map.
   *
   * With the Terrain tool, the left button paints the height brush (EdHeightBrush.cpp) under the cursor
   * while it is held, with the Tools panel's mode, size, strength, falloff and symmetry; Flatten flattens to
   * the height under the stroke's first point.
   */
  class EdMapScene
  {
  public:
    explicit EdMapScene(EdDocument& document);
    ~EdMapScene();
    EdMapScene(const EdMapScene&) = delete;
    EdMapScene& operator=(const EdMapScene&) = delete;

    /** Each frame, after the play's frame logic: attaches, follows the window's size, or leaves. */
    void Update(float frameSeconds, bool playIdle);

    /** Leaves the viewport (the document is about to drop its map). */
    void Detach();

    /** The tool settings the left mouse button acts with (the Tools panel's). */
    void SetTools(EdTools* tools) noexcept { mTools = tools; }

    /** Undoes or redoes the newest height stroke (Ctrl+Z, Ctrl+Y); false when there is none. */
    bool Undo();
    bool Redo();

    [[nodiscard]] bool Attached() const noexcept { return mMap != nullptr; }

    /** The game viewport window's messages while attached; true when the scene used one. */
    bool OnWindowMessage(HWND window, UINT message, WPARAM wParam, LPARAM lParam);

  private:
    void Attach(moho::CWldMap& map);
    void FrameWholeMap();
    void ApplyCamera();
    /** The ground (terrain or water) under a point of the viewport, in its pixels; false off the map. */
    bool GroundAt(float x, float y, float& outX, float& outZ) const;
    void MoveWithKeys(float frameSeconds);
    /** The map's props as mesh instances, from the kept rules' blueprints once they are ready. */
    void CreateProps();
    void DeleteProps();

    std::vector<moho::MeshInstance*> mProps;
    bool mPropsDone = false;

    /** A terrain stroke in progress: the brush under the cursor each frame while the left button is held. */
    void PaintStroke(float frameSeconds);
    void EndStroke();
    /** Hands written samples back to the height field (its tiers and revision) and redraws their terrain. */
    void RefreshHeights(const std::vector<SampleRect>& rects);
    EdTools* mTools = nullptr;

    /** The symmetry check (EdSymmetryCheck.cpp) on the map's heights, its result to the Tools panel. */
    void RunSymmetryCheck();
    /** Copies the source part to the other copies, as one undo step. */
    void RepairSymmetry();
    /** The blocks of samples the last check found differing, drawn red while the panel shows differences. */
    std::vector<SampleRect> mDifferences;
    HeightBrush mCheckedWith;
    bool mCheckDone = false;
    bool mPainting = false;

    /** Draws the brush rings on the terrain from the renderer's editor hook (`ED_SetHook`). */
    void DrawBrushRings();
    class RingHook;
    std::unique_ptr<RingHook> mRingHook;
    float mFlattenTo = 0.0f;
    POINT mCursor{};

    // Held movement keys (WASD and the arrows), and Shift for speed.
    bool mForward = false;
    bool mBack = false;
    bool mLeft = false;
    bool mRight = false;
    bool mFast = false;

    EdDocument& mDocument;
    moho::CWldMap* mMap = nullptr;
    moho::CameraImpl* mCamera = nullptr;
    std::unique_ptr<moho::SimpleRenderWorldView> mWorldView;

    // The orbit camera: the point it looks at, its heading and pitch (radians) and its distance from it.
    float mTargetX = 0.0f;
    float mTargetY = 0.0f;
    float mTargetZ = 0.0f;
    float mHeading = 3.14159265f;
    float mPitch = 1.0f;
    float mDistance = 500.0f;
    float mMapExtent = 512.0f;
    int mWidth = 0;
    int mHeight = 0;

    enum class Drag
    {
      None,
      Orbit,
      Pan,
    };
    Drag mDrag = Drag::None;
    POINT mDragFrom{};
  };
} // namespace faf::editor
