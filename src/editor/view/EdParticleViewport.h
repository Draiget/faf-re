#pragma once

#include "moho/misc/ID3DDeviceResources.h"

#include <cstdint>

namespace faf::editor
{
  /**
   * The particle editor's own 3D view: the effect alone, in empty space or over a plain ground with a grid, seen from
   * an orbit camera, rendered into a target of its own (not the map, none of its markers or helpers). The effect's
   * particles are emitted far off the map (kPlace) and drawn by the game's world particle renderer with this view's
   * camera, so the map's view never shows them and this one shows nothing else. Rendered at the start of each frame
   * through the engine's hook (moho::gViewportBeforeFrame), shown as an image by the panels.
   */
  class EdParticleViewport
  {
  public:
    /**
     * Where the effect plays: far outside any map (maps are at most 4096 across), one of eight spots 3000 apart. The
     * particles the renderer already has can't be taken back, so a new effect (or a restart) plays at the next spot and
     * the last one's particles live out their lives beyond this view's far plane (2000 past the effect).
     */
    static constexpr float kPlaceY = 0.0f;
    [[nodiscard]] float PlaceX() const noexcept
    {
      return -6000.0f - 3000.0f * static_cast<float>(mSpot);
    }
    [[nodiscard]] float PlaceZ() const noexcept
    {
      return -6000.0f;
    }
    void NextSpot() noexcept
    {
      mSpot = (mSpot + 1) % 8;
    }

    struct Options
    {
      int background = 0; // 0 night, 1 grey, 2 sky, 3 black
      bool ground = true;
      bool grid = true;
      float height = 0.0f; // the emitter above the ground
      bool turn = false;   // the camera turns slowly round the effect
    };
    [[nodiscard]] Options& Opts() noexcept
    {
      return mOptions;
    }

    /** The size the panels show it at; the target follows it. */
    void SetSize(int width, int height);
    /** Orbit: a drag turns (pixels), the wheel moves closer or farther, a preset looks from the front, side or top. */
    void Turn(float dx, float dy);
    void Zoom(float steps);
    void Look(float heading, float pitch);
    /** Back to the default angle and distance (`size`: about how big the effect is). */
    void Reset(float size = 12.0f);

    /** Renders it (the engine's frame hook, head 0 only; the caller restores the head's target). */
    void Render(int headWidth, int headHeight, float frameSeconds);
    /** The image for ImGui::Image (0 before the first render). */
    [[nodiscard]] std::uint64_t Image() const noexcept
    {
      return mImage;
    }
    /** Shown this frame: rendered only while some panel draws it. */
    void MarkShown() noexcept
    {
      mShown = true;
    }

  private:
    Options mOptions;
    int mWidth = 512;
    int mHeight = 512;
    int mTargetWidth = 0;
    int mTargetHeight = 0;
    float mHeading = 2.4f;
    float mPitch = 0.45f;
    float mDistance = 30.0f;
    bool mShown = false;
    int mSpot = 0;
    std::uint64_t mImage = 0;
    moho::ID3DDeviceResources::RenderTargetHandle mTarget;
    moho::ID3DDeviceResources::DepthStencilHandle mDepth;
  };
} // namespace faf::editor
