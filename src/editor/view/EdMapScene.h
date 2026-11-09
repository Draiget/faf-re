#pragma once

#include <memory>

#include <Windows.h>

namespace moho
{
  class CameraImpl;
  class CWldMap;
  class SimpleRenderWorldView;
} // namespace moho

namespace faf::editor
{
  class EdDocument;

  /**
   * The opened map in the game's viewport between plays (board task WPE.3). The renderer draws the map in
   * `moho::sWldMap` through its world views, as the original editor did (`REN_SetWldMap`, 0x007FA150).
   * While a map is open and no play runs, the scene puts the document's map there and registers one world
   * view with its own camera (made the way the strategic preview render makes one). It leaves before a
   * play's session takes the map over, and before the document drops its map.
   *
   * Camera: middle mouse button drag orbits (turns and tilts around the point looked at), Shift + middle
   * drag or right drag pans, the wheel zooms; Home frames the whole map.
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

    [[nodiscard]] bool Attached() const noexcept { return mMap != nullptr; }

    /** The game viewport window's messages while attached; true when the scene used one. */
    bool OnWindowMessage(HWND window, UINT message, WPARAM wParam, LPARAM lParam);

  private:
    void Attach(moho::CWldMap& map);
    void FrameWholeMap();
    void ApplyCamera();

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
