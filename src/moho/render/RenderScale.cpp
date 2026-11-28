#include "moho/render/RenderScale.h"

#include <cctype>
#include <string>

#include "gpg/core/utils/Logging.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/RenderScalePass.h"
#include "moho/app/FrameDumpCommands.h"
#include "moho/console/CConCommand.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/render/ID3DDepthStencil.h"
#include "moho/render/ID3DRenderTarget.h"
#include "moho/render/TemporalAA.h"
#include "moho/render/d3d/CD3DDepthStencil.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DDeviceResources.h"
#include "moho/render/d3d/CD3DRenderTarget.h"

namespace moho
{
  float ren_RenderScaleSharpness = 0.6f;

  namespace
  {
    // gal / engine format codes of the head's targets (WRenViewport: kViewportHeadTargetFormat 2,
    // kViewportHeadDepthStencilFormat 3).
    constexpr int kColorFormat = 2;
    constexpr int kDepthFormat = 3;

    TConVar<float> gTConVar_ren_RenderScaleSharpness(
      "ren_RenderScaleSharpness",
      "Render scale: strength of the sharpening after the upscale, 0 (none) to 1. Default 0.6. Taken as 0 while "
      "ren_Sharpen is above 0, whose post pass sharpens the upscaled view.",
      &ren_RenderScaleSharpness
    );

    void ApplyCommandLine()
    {
      static bool applied = false;
      if (applied) {
        return;
      }
      applied = true;
      fa::vector<fa::string> args;
      if (!CFG_GetArgOption("/renderscale", 1U, &args) || args.empty()) {
        return;
      }
      std::string value = args[0].c_str();
      for (char& c : value) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
      }
      if (!value.empty() && value.back() == '%') {
        value.pop_back();
      }
      if (value == "100" || value == "0" || value == "off") {
        ren_RenderScale = 1.0f;
      } else if (value == "85") {
        ren_RenderScale = 0.85f;
      } else if (value == "75") {
        ren_RenderScale = 0.75f;
      } else if (value == "67") {
        ren_RenderScale = 2.0f / 3.0f;
      } else if (value == "50") {
        ren_RenderScale = 0.5f;
      } else {
        gpg::Warnf(
          "/renderscale %s is not 100, 85, 75, 67 or 50; the render scale stays at %.2f", value.c_str(), ren_RenderScale
        );
      }
    }

    // What the scaled drawing keeps between frames, per head.
    struct HeadState
    {
      std::shared_ptr<gpg::gal::RenderTarget> galColor; ///< the pass's targets the wrappers were made for
      std::shared_ptr<gpg::gal::DepthStencilTarget> galDepth;
      std::shared_ptr<ID3DRenderTarget> colorLock;
      std::shared_ptr<ID3DDepthStencil> depthLock;
      std::shared_ptr<CD3DRenderTarget> primary;
      std::shared_ptr<CD3DRenderTarget> secondary;
      std::shared_ptr<CD3DDepthStencil> viewportDepth;
      int width = 0;
      int height = 0;
    };
    HeadState gHeads[2];
  } // namespace

  float REN_GetRenderScaleFactor()
  {
    ApplyCommandLine();
    // Temporal anti-aliasing draws the world at this scale itself and rebuilds the full view in its resolve.
    if (TemporalAA::Get().IsActive()) {
      return 1.0f;
    }
    return gpg::gal::RenderScaleFactorFor(ren_RenderScale);
  }

  namespace
  {
    float gWorldDrawScale = 1.0f;
  }

  float REN_GetWorldDrawScale()
  {
    return gWorldDrawScale;
  }

  bool REN_BeginScaledWorld(
    ScaledWorldFrame& frame,
    CD3DDevice& device,
    const int head,
    std::shared_ptr<CD3DRenderTarget>& primary,
    std::shared_ptr<CD3DRenderTarget>& secondary,
    std::shared_ptr<CD3DDepthStencil>& viewportDepth
  )
  {
    frame = ScaledWorldFrame();
    const float factor = REN_GetRenderScaleFactor();
    gpg::gal::Device* const galDevice = device.GetGalDevice();
    // The frame dump (dump_Frame / dump_Frames) accumulates the viewport's own frame-sized target: it is drawn at full
    // size while it runs.
    if (factor >= 0.999f || galDevice == nullptr || head < 0 || head > 1 || dump_frameRate != 0) {
      return false;
    }
    const int windowWidth = device.GetHeadWidth(static_cast<unsigned int>(head));
    const int windowHeight = device.GetHeadHeight(static_cast<unsigned int>(head));
    if (windowWidth < 16 || windowHeight < 16) {
      return false;
    }

    gpg::gal::RenderScalePass& pass = gpg::gal::RenderScalePass::Instance();
    if (!pass.Prepare(
          *galDevice, static_cast<std::uint32_t>(windowWidth), static_cast<std::uint32_t>(windowHeight), factor
        )) {
      return false;
    }
    HeadState& state = gHeads[head];
    const int width = static_cast<int>(pass.Width());
    const int height = static_cast<int>(pass.Height());

    // Engine wrappers around the pass's targets (the same kind of wrapper CD3DDevice::InitContext makes for the back
    // buffer).
    if (state.galColor != pass.Color() || state.galDepth != pass.Depth() || !state.colorLock || !state.depthLock) {
      state.galColor = pass.Color();
      state.galDepth = pass.Depth();
      state.colorLock.reset(new CD3DRenderTarget(&device, state.galColor));
      state.depthLock.reset(new CD3DDepthStencil(&device, state.galDepth));
    }
    // The viewport's own frame-sized targets (terrain normals / frame copy for refraction, reflection, and their depth)
    // follow the same size, so the shaders' viewport scale and offset (view rectangle over target size) stay what they
    // were.
    if (!state.primary || !state.secondary || !state.viewportDepth || state.width != width || state.height != height) {
      ID3DDeviceResources* const resources = device.GetResources();
      state.primary.reset();
      state.secondary.reset();
      state.viewportDepth.reset();
      resources->CreateRenderTarget(state.primary, width, height, kColorFormat);
      resources->CreateRenderTarget(state.secondary, width, height, kColorFormat);
      resources->CreateDepthStencil(state.viewportDepth, width, height, kDepthFormat);
      state.width = width;
      state.height = height;
      if (!state.primary || !state.secondary || !state.viewportDepth) {
        gpg::Warnf(
          "Render scale: the %dx%d helper targets could not be created; the world is drawn at full size", width, height
        );
        state = HeadState();
        return false;
      }
    }

    frame.active = true;
    frame.factor = factor;
    frame.head = head;
    frame.width = width;
    frame.height = height;
    frame.windowWidth = windowWidth;
    frame.windowHeight = windowHeight;
    REN_ResumeScaledWorld(frame, device, primary, secondary, viewportDepth);

    // The scaled targets start every frame cleared (the native back buffer was cleared by the caller before the frames
    // were drawn).
    device.SetRenderTarget2(head, true, 0, 1.0f, 0);
    return true;
  }

  void REN_ResumeScaledWorld(
    ScaledWorldFrame& frame,
    CD3DDevice& device,
    std::shared_ptr<CD3DRenderTarget>& primary,
    std::shared_ptr<CD3DRenderTarget>& secondary,
    std::shared_ptr<CD3DDepthStencil>& viewportDepth
  )
  {
    if (!frame.active || frame.swapped) {
      return;
    }
    HeadState& state = gHeads[frame.head];
    frame.savedHeadColor = device.mRenderTargetLocks[frame.head];
    frame.savedHeadDepth = device.mDepthStencilLocks[frame.head];
    frame.savedPrimary = primary;
    frame.savedSecondary = secondary;
    frame.savedViewportDepth = viewportDepth;

    device.mRenderTargetLocks[frame.head] = state.colorLock;
    device.mDepthStencilLocks[frame.head] = state.depthLock;
    primary = state.primary;
    secondary = state.secondary;
    viewportDepth = state.viewportDepth;
    frame.swapped = true;
    gWorldDrawScale = frame.factor;
    // Bind the scaled head again; the first caller after a resume sets its own viewport.
    device.SetRenderTarget2(frame.head, false, 0, 1.0f, 0);
  }

  gpg::gal::RenderScaleRect REN_ScaledViewRect(
    ScaledWorldFrame& frame,
    const int x,
    const int y,
    const int width,
    const int height
  )
  {
    const gpg::gal::RenderScaleRect window{x, y, width, height};
    for (const ScaledWorldFrame::View& view : frame.views) {
      if (view.dest.x == x && view.dest.y == y && view.dest.width == width && view.dest.height == height) {
        return view.source;
      }
    }
    ScaledWorldFrame::View view;
    view.dest = window;
    view.source = gpg::gal::RenderScaleSourceRect(
      window, frame.factor, static_cast<std::uint32_t>(frame.width), static_cast<std::uint32_t>(frame.height)
    );
    frame.views.push_back(view);
    return view.source;
  }

  void REN_EndScaledWorld(
    ScaledWorldFrame& frame,
    CD3DDevice& device,
    std::shared_ptr<CD3DRenderTarget>& primary,
    std::shared_ptr<CD3DRenderTarget>& secondary,
    std::shared_ptr<CD3DDepthStencil>& viewportDepth
  )
  {
    if (!frame.active || !frame.swapped) {
      return;
    }
    frame.swapped = false;
    gWorldDrawScale = 1.0f;
    device.mRenderTargetLocks[frame.head] = frame.savedHeadColor;
    device.mDepthStencilLocks[frame.head] = frame.savedHeadDepth;
    primary = frame.savedPrimary;
    secondary = frame.savedSecondary;
    viewportDepth = frame.savedViewportDepth;
    frame.savedHeadColor.reset();
    frame.savedHeadDepth.reset();
    frame.savedPrimary.reset();
    frame.savedSecondary.reset();
    frame.savedViewportDepth.reset();
    // Draw what comes next (the resolve, the cartographic view, the interface) into the native head again.
    device.SetRenderTarget2(frame.head, false, 0, 1.0f, 0);
  }

  void REN_ResolveScaledWorld(
    ScaledWorldFrame& frame,
    gpg::gal::Device& device,
    const float sharpness
  )
  {
    if (!frame.active) {
      return;
    }
    gpg::gal::RenderScalePass& pass = gpg::gal::RenderScalePass::Instance();
    for (const ScaledWorldFrame::View& view : frame.views) {
      (void)pass.Resolve(device, static_cast<std::uint32_t>(frame.head), view.source, view.dest, sharpness);
    }
    frame.views.clear();
  }

  void REN_ReleaseRenderScale()
  {
    for (HeadState& state : gHeads) {
      state = HeadState();
    }
    gpg::gal::RenderScalePass::Instance().Release();
  }
} // namespace moho
