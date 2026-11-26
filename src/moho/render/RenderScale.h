#pragma once

#include <cstdint>
#include <vector>

#include <memory>
#include "gpg/gal/backends/common/RenderScale.h"

namespace gpg::gal
{
  class Device;
}

namespace moho
{
  class CD3DDevice;
  class ID3DRenderTarget;
  class ID3DDepthStencil;
  class CD3DRenderTarget;
  class CD3DDepthStencil;
} // namespace moho

// FAF addition, not in the shipped binary: engine side of the render scale (docs/RENDERER_BACKENDS.md, "Render scale").
// The 3D world of a frame is drawn into targets that are a fraction of the window, then upscaled into the back buffer
// before the control tree. Seen from the world pass the engine simply runs in a smaller window: the head's colour and
// depth targets, the viewport's frame-copy and normal targets and the view rectangles are all replaced by scaled ones
// for the duration of the world loop; the camera and the simulation are untouched, so mouse picking and every
// projection stay what they were. Render only.
namespace moho
{
  // The one setting is upstream's ren_RenderScale (TemporalAA.h): the share of the view's width and height the world is
  // drawn at, 0.5 to 1 (1, the default, full size). With temporal anti-aliasing running (ren_Taa) its resolve rebuilds
  // the full view from the smaller picture; without it (ren_Taa off, or a renderer that cannot, Direct3D 11) this
  // module draws into smaller targets and upscales them spatially. /renderscale 100|85|75|67|50 on the command line
  // sets it at start. The Options > Video item comes from the render feature registry (key "render_scale").
  // ren_RenderScaleSharpness (0..1, default 0.6) is the strength of the sharpening after the spatial upscale.
  extern float ren_RenderScaleSharpness;

  // One frame of scaled world drawing: what the engine's own lanes held before, and the views drawn.
  struct ScaledWorldFrame
  {
    bool active = false;  ///< a scaled frame is in progress (between Begin and the end of the world loop)
    bool swapped = false; ///< the engine's lanes currently hold the scaled targets
    float factor = 1.0f;
    int head = 0;
    int width = 0; ///< scaled target size
    int height = 0;
    int windowWidth = 0;
    int windowHeight = 0;
    std::shared_ptr<ID3DRenderTarget> savedHeadColor;
    std::shared_ptr<ID3DDepthStencil> savedHeadDepth;
    std::shared_ptr<CD3DRenderTarget> savedPrimary;
    std::shared_ptr<CD3DRenderTarget> savedSecondary;
    std::shared_ptr<CD3DDepthStencil> savedViewportDepth;
    struct View
    {
      gpg::gal::RenderScaleRect source; ///< texels of the scaled colour target
      gpg::gal::RenderScaleRect dest;   ///< pixels of the back buffer
    };
    std::vector<View> views;
  };

  // The scale factor the next frame uses: 1 when ren_RenderScale is 1, when temporal anti-aliasing is running (it
  // scales the world itself), or when the backend cannot (no GPU programs).
  [[nodiscard]] float REN_GetRenderScaleFactor();

  // The scale of the target the world is being drawn into right now: the frame's factor while the scaled targets are in
  // the engine's lanes (REN_BeginScaledWorld / REN_ResumeScaledWorld .. REN_EndScaledWorld), 1 otherwise. Thin geometry
  // sized in pixels (range rings) divides its thickness by it so a line keeps its width in source texels and does not
  // break up into dots.
  [[nodiscard]] float REN_GetWorldDrawScale();

  // Starts scaled drawing of head `head`: swaps the head's colour and depth lanes of `device` and the viewport's three
  // frame lanes
  // (`primary`, `secondary`, `viewportDepth`, the references stay the caller's) for scaled ones, clears them, and
  // returns true. False (nothing changed) when the level is 100 % or the backend cannot.
  bool REN_BeginScaledWorld(
    ScaledWorldFrame& frame,
    CD3DDevice& device,
    int head,
    std::shared_ptr<CD3DRenderTarget>& primary,
    std::shared_ptr<CD3DRenderTarget>& secondary,
    std::shared_ptr<CD3DDepthStencil>& viewportDepth
  );

  // Turns a view's rectangle in the window (x, y, width, height) into the rectangle of the scaled targets the world is
  // drawn into, and remembers the pair for the upscale. Idempotent for a rectangle already seen.
  [[nodiscard]] gpg::gal::RenderScaleRect
  REN_ScaledViewRect(ScaledWorldFrame& frame, int x, int y, int width, int height);

  // Puts the scaled targets back into the engine's lanes after REN_SuspendScaledWorld, without clearing them (the next
  // view of the frame).
  void REN_ResumeScaledWorld(
    ScaledWorldFrame& frame,
    CD3DDevice& device,
    std::shared_ptr<CD3DRenderTarget>& primary,
    std::shared_ptr<CD3DRenderTarget>& secondary,
    std::shared_ptr<CD3DDepthStencil>& viewportDepth
  );

  // Puts the engine's lanes back (the scaled targets stay alive for the next frame); the frame stays active so it can
  // be resumed.
  void REN_EndScaledWorld(
    ScaledWorldFrame& frame,
    CD3DDevice& device,
    std::shared_ptr<CD3DRenderTarget>& primary,
    std::shared_ptr<CD3DRenderTarget>& secondary,
    std::shared_ptr<CD3DDepthStencil>& viewportDepth
  );

  // Draws every view recorded since the last call (scaled rectangle -> back buffer: upscale and, when `sharpness` > 0,
  // sharpen) and forgets them. Run after REN_EndScaledWorld. The caller passes 0 when the post effects sharpen the
  // upscaled view anyway (ren_Sharpen > 0).
  void REN_ResolveScaledWorld(ScaledWorldFrame& frame, gpg::gal::Device& device, float sharpness);

  // Frees every scaled target (a device reset or exit).
  void REN_ReleaseRenderScale();
} // namespace moho
