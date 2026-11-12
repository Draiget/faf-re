#include "editor/view/EdParticleViewport.h"

#include "editor/ui/EdImGuiRenderer.h"
#include "moho/entity/Entity.h"
#include "moho/math/QuaternionMath.h"
#include "moho/particles/CWorldParticles.h"
#include "moho/render/WRenViewport.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/render/camera/VTransform.h"
#include "moho/render/d3d/CD3DDepthStencil.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DPrimBatcher.h"
#include "moho/render/d3d/CD3DRenderTarget.h"
#include "moho/render/textures/CD3DBatchTexture.h"

#include <algorithm>
#include <cmath>

namespace faf::editor
{
  namespace
  {
    /** COORDS_Orient's look turned into a view orientation, as CameraImpl::UpdateCoords does (ViewOrientFromLook). */
    Wm3::Quaternionf ViewOrient(
      const Wm3::Quaternionf& look
    )
    {
      Wm3::Quaternionf orient{};
      orient.w = -look.y;
      orient.x = -look.z;
      orient.y = look.w;
      orient.z = look.x;
      return orient;
    }

    std::uint32_t Background(
      const int kind
    )
    {
      switch (kind) {
      case 1:
        return 0xFF5A5F66u;
      case 2:
        return 0xFF86A9CCu;
      case 3:
        return 0xFF000000u;
      default:
        return 0xFF14171Du;
      }
    }
  } // namespace

  void EdParticleViewport::SetSize(
    const int width,
    const int height
  )
  {
    // In steps of 32, so a slowly resized panel doesn't make a new target every frame.
    mWidth = std::clamp((width + 31) / 32 * 32, 64, 2048);
    mHeight = std::clamp((height + 31) / 32 * 32, 64, 2048);
  }

  void EdParticleViewport::Turn(
    const float dx,
    const float dy
  )
  {
    mHeading += dx * 0.01f;
    mPitch = std::clamp(mPitch + dy * 0.01f, -0.2f, 1.55f);
  }

  void EdParticleViewport::Zoom(
    const float steps
  )
  {
    mDistance = std::clamp(mDistance * std::pow(0.87f, steps), 2.0f, 400.0f);
  }

  void EdParticleViewport::Look(
    const float heading,
    const float pitch
  )
  {
    mHeading = heading;
    mPitch = pitch;
  }

  void EdParticleViewport::Reset(
    const float size
  )
  {
    mHeading = 2.4f;
    mPitch = 0.45f;
    mDistance = std::clamp(size * 2.5f, 6.0f, 200.0f);
  }

  void EdParticleViewport::Render(
    const int headWidth,
    const int headHeight,
    const float frameSeconds
  )
  {
    if (!std::exchange(mShown, false)) {
      return; // no panel showed it last frame
    }
    moho::CD3DDevice* const device = moho::D3D_GetDevice();
    if (device == nullptr || device->GetResources() == nullptr || moho::ren_Viewport == nullptr) {
      return;
    }
    if (!mTarget || !mDepth || mTargetWidth != mWidth || mTargetHeight != mHeight) {
      mTarget.reset();
      mDepth.reset();
      (void)device->GetResources()->CreateRenderTarget(mTarget, mWidth, mHeight, 2);
      (void)device->GetResources()->CreateDepthStencil(mDepth, mWidth, mHeight, 3);
      mTargetWidth = mWidth;
      mTargetHeight = mHeight;
    }
    if (!mTarget || !mDepth) {
      return;
    }
    if (mOptions.turn) {
      mHeading += frameSeconds * 0.35f;
    }

    // The orbit camera round the effect, built as CameraImpl::UpdateCoords builds the game's (0x007AA330).
    const float kPlaceX = PlaceX();
    const float kPlaceZ = PlaceZ();
    const Wm3::Vec3f target{kPlaceX, kPlaceY + mOptions.height + 1.0f, kPlaceZ};
    moho::VTransform view{};
    view.orient_ = ViewOrient(moho::COORDS_Orient(mHeading, mPitch));
    const Wm3::Vector3f eye = moho::QuatForwardAxis(view.orient_);
    view.pos_ = Wm3::Vec3f{target.x + eye.x * mDistance, target.y + eye.y * mDistance, target.z + eye.z * mDistance};
    const float fov = 0.9f;
    const float nearClip = -std::max(mDistance * 0.01f, 0.05f);
    const float farClip = -(mDistance + 2000.0f); // short of the next spot (3000 away)
    const moho::VMatrix4 projection = moho::VEC_D3DProjectionMatrixFOV(
      fov, fov, nearClip, farClip, static_cast<float>(mHeight) / static_cast<float>(mWidth)
    );
    moho::GeomCamera3 camera(view, projection);

    device->SetRenderTarget1(
      mTarget.get(), mDepth.get(), true, static_cast<int>(Background(mOptions.background)), 1.0f, 0
    );
    Wm3::Vector2i origin{0, 0};
    Wm3::Vector2i size{mWidth, mHeight};
    device->SetViewport(&origin, &size, 0.0f, 1.0f);

    // The ground under the effect and its grid: a metre line every unit near it, stronger every five.
    moho::CD3DPrimBatcher* const batcher = moho::ren_Viewport->GetPrimBatcher();
    if (batcher != nullptr && (mOptions.ground || mOptions.grid)) {
      (void)batcher->Setup("TAlphaBlendLinearSample");
      batcher->SetViewProjMatrix(camera);
      batcher->SetTexture(moho::CD3DBatchTexture::FromSolidColor(0xFFFFFFFFu));
      const auto vertex = [](const float x, const float y, const float z, const std::uint32_t color) {
        moho::CD3DPrimBatcher::Vertex v{};
        v.mX = x;
        v.mY = y;
        v.mZ = z;
        v.mColor = color;
        return v;
      };
      constexpr float kHalf = 60.0f;
      if (mOptions.ground) {
        const std::uint32_t ground = mOptions.background == 2 ? 0xFF5F6B52u : 0xFF2E3238u;
        const moho::CD3DPrimBatcher::Vertex quad[4] = {
          vertex(kPlaceX - kHalf, kPlaceY, kPlaceZ - kHalf, ground),
          vertex(kPlaceX + kHalf, kPlaceY, kPlaceZ - kHalf, ground),
          vertex(kPlaceX + kHalf, kPlaceY, kPlaceZ + kHalf, ground),
          vertex(kPlaceX - kHalf, kPlaceY, kPlaceZ + kHalf, ground)
        };
        batcher->DrawQuads(quad, 1);
      }
      if (mOptions.grid) {
        const float y = kPlaceY + 0.02f;
        for (int i = -static_cast<int>(kHalf); i <= static_cast<int>(kHalf); ++i) {
          const std::uint32_t color = i == 0 ? 0xC0D0D0D0u : (i % 5 == 0 ? 0x80A0A0A0u : 0x40808080u);
          const float o = static_cast<float>(i);
          batcher->DrawLine(
            vertex(kPlaceX + o, y, kPlaceZ - kHalf, color), vertex(kPlaceX + o, y, kPlaceZ + kHalf, color)
          );
          batcher->DrawLine(
            vertex(kPlaceX - kHalf, y, kPlaceZ + o, color), vertex(kPlaceX + kHalf, y, kPlaceZ + o, color)
          );
        }
        // The emitter's spot, and its height above the ground when raised.
        const float h = kPlaceY + mOptions.height;
        batcher->DrawLine(
          vertex(kPlaceX, kPlaceY, kPlaceZ, 0xFFF0B040u), vertex(kPlaceX, h + 0.01f, kPlaceZ, 0xFFF0B040u)
        );
        batcher->DrawLine(
          vertex(kPlaceX - 0.5f, h, kPlaceZ, 0xFFF0B040u), vertex(kPlaceX + 0.5f, h, kPlaceZ, 0xFFF0B040u)
        );
        batcher->DrawLine(
          vertex(kPlaceX, h, kPlaceZ - 0.5f, 0xFFF0B040u), vertex(kPlaceX, h, kPlaceZ + 0.5f, 0xFFF0B040u)
        );
      }
      batcher->Flush();
    }

    // The effect: the world's particles through this camera (as WRenViewport::RenderEffects draws them), both sides of
    // the water surface; the map's view sees none of them, they are far off its map.
    device->SetColorWriteState(true, false);
    (void)moho::sWorldParticles.RenderEffects(&camera, 0, 0, moho::REN_GetGameTick(), moho::REN_GetSimDeltaSeconds());
    (void)moho::sWorldParticles.RenderEffects(&camera, 1, 0, moho::REN_GetGameTick(), moho::REN_GetSimDeltaSeconds());

    // The head's own viewport back (its target is bound again by the caller).
    Wm3::Vector2i headSize{std::max(headWidth, 1), std::max(headHeight, 1)};
    device->SetViewport(&origin, &headSize, 0.0f, 1.0f);

    moho::ID3DRenderTarget::SurfaceHandle surface;
    (void)mTarget->GetSurface(surface);
    mImage = EdImGuiRenderer::TargetImage(surface.get());
  }
} // namespace faf::editor
