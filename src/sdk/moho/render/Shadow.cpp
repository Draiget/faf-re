#include "moho/render/Shadow.h"

#include <Windows.h>

#include <cstring>
#include <new>

#include "gpg/core/utils/Logging.h"
#include "gpg/gal/Device.hpp"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/ID3DVertexSheet.h"
#include "moho/render/ScreenQuadVertexSheet.h"
#include "moho/render/d3d/CD3DDepthStencil.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DRenderTarget.h"
#include "moho/collision/CGeomSolid3.h"
#include "moho/sim/CWldMap.h"
#include "moho/sim/STIMap.h"
#include "moho/terrain/water/WaterSurface.h"
#include "moho/terrain/TerrainCommon.h"
#include "moho/terrain/TerrainShaderVars.h"
#include "moho/mesh/Mesh.h"
#include "gpg/gal/RenderTargetContext.hpp"
#include "gpg/gal/backends/d3d9/RenderTargetD3D9.hpp"

// Declared the way gpg/gal/Matrix.cpp declares its D3DX entry points, rather
// than pulling in the D3DX headers - moho::VMatrix4 is layout-identical to
// D3DXMATRIX and Wm3::Vector3f to D3DXVECTOR3.
extern "C"
{
  moho::VMatrix4* WINAPI D3DXMatrixLookAtRH(
    moho::VMatrix4* outMatrix,
    const Wm3::Vector3f* eye,
    const Wm3::Vector3f* target,
    const Wm3::Vector3f* up
  );
}
#include <algorithm>
#include <cmath>
#include "moho/render/d3d/CD3DVertexSheet.h"

namespace
{
  // Depth-stencil format the shadow map's companion buffer is created with.
  constexpr int kShadowDepthStencilFormat = 3;

  struct BlinkyBoxListNode
  {
    BlinkyBoxListNode* next;
    BlinkyBoxListNode* prev;
  };

  BlinkyBoxListNode gBlinkyBoxesListHead{&gBlinkyBoxesListHead, &gBlinkyBoxesListHead};

  /**
   * Address: 0x007FE040 (FUN_007FE040)
   *
   * What it does:
   * Unlinks one blinky-box node from its current intrusive list and reinserts
   * it at the head of the global blinky-box list.
   */
  [[maybe_unused]] [[nodiscard]] BlinkyBoxListNode* RelinkBlinkyBoxNodeToGlobalHead(BlinkyBoxListNode* const node)
  {
    if (node == nullptr || node->next == nullptr || node->prev == nullptr) {
      return node;
    }

    node->next->prev = node->prev;
    node->prev->next = node->next;
    node->next = node;
    node->prev = node;

    node->next = gBlinkyBoxesListHead.next;
    node->prev = &gBlinkyBoxesListHead;
    gBlinkyBoxesListHead.next = node;
    node->next->prev = node;
    return node;
  }
} // namespace

namespace moho
{
  extern int ren_ShadowSize;
  extern bool ren_ShadowBlur;
  extern float ren_ShadowCoeff;
  extern float ren_ShadowLOD;
  extern bool ren_Shadows;
  extern int shadow_Fidelity;
  extern int shadow_FidelitySupported;

  class IWldTerrainRes;

  // Defined in moho/app/WxRuntimeTypes.cpp (0x007FA170); folds in both the
  // map and terrain null checks.
  [[nodiscard]] IWldTerrainRes* REN_GetTerrainRes();

  /**
   * Address: 0x009407D0 (FUN_009407D0, sub_9407D0)
   *
   * What it does:
   * Builds a right-handed look-at matrix. A thin forward to D3DX that the
   * binary keeps as its own symbol, so it is recovered under its own name
   * rather than inlined at the call site.
   */
  gpg::gal::Matrix* MatrixLookAtRH(
    gpg::gal::Matrix* const outMatrix,
    const Wm3::Vector3f* const eye,
    const Wm3::Vector3f* const target,
    const Wm3::Vector3f* const up
  )
  {
    return ::D3DXMatrixLookAtRH(outMatrix, eye, target, up);
  }

  /**
   * Address: 0x007FE120 (FUN_007FE120, ??0Shadow@Moho@@QAE@@Z)
   *
   * What it does:
   * Initializes shadow-renderer fidelity/size flags, constructs the light-space
   * camera at `+0x18`, and null-clears every resource handle.
   */
  Shadow::Shadow()
    : mUnusedHeaderWord(0)
    , mShadowFidelity(0)
    , mShadowBlurEnabled(false)
    , mPadding0D_0F{}
    , mShadowSize(0)
    , mShadowCameraValid(false)
    , mPadding15_17{}
    , mCamera()
    , mShadowMap()
    , mBlurTargetA()
    , mBlurTargetB()
    , mDepthStencil()
    , mQuadVertexSheet()
    , mUnreferencedResources{}
  {}

  /**
   * Address: 0x007FE760 (FUN_007FE760)
   *
   * IDA signature:
   * int __usercall sub_7FE760@<eax>(Moho::Shadow *this@<esi>);
   *
   * What it does:
   * Clears the cached fidelity/blur/size settings and releases every render
   * resource the shadow renderer holds. Called from the destructor, from
   * `Init` (on entry and again on either failure path), and from
   * `WRenViewport::D3DWindowOnDeviceExit` when the device drops its
   * default-pool resources.
   */
  int Shadow::ReleaseRenderResources() noexcept
  {
    mShadowFidelity = 0;
    mShadowBlurEnabled = false;

    mShadowMap.reset();
    mBlurTargetA.reset();
    mBlurTargetB.reset();
    mDepthStencil.reset();
    mQuadVertexSheet.reset();
    for (boost::shared_ptr<void>& resource : mUnreferencedResources) {
      resource.reset();
    }

    mShadowSize = 0;
    return 0;
  }

  /**
   * Address: 0x007FE200 (FUN_007FE200, ??1Shadow@Moho@@UAE@XZ)
   *
   * What it does:
   * Runs non-deleting teardown for one shadow runtime object.
   */
  Shadow::~Shadow()
  {
    (void)ReleaseRenderResources();
  }

  /**
   * Address: 0x007DB350 (FUN_007DB350)
   *
   * What it does:
   * Returns a retained copy of the shadow-map render target for shader binding.
   */
  boost::shared_ptr<CD3DRenderTarget>& Shadow::GetShadowMap(
    boost::shared_ptr<CD3DRenderTarget>& outShadowMap
  ) const
  {
    outShadowMap = mShadowMap;
    return outShadowMap;
  }

  /**
   * Address: 0x007FE3E0 (FUN_007FE3E0, Moho::Shadow::Init)
   *
   * IDA signature:
   * int __usercall Moho::Shadow::Init@<eax>(int fidelity, Moho::Shadow *this);
   *
   * What it does:
   * Rebuilds every shadow render resource for the requested fidelity. Latches
   * the current shadow-size/blur tuning, drops what was held before, and for a
   * non-zero fidelity allocates the shadow-map target (plus the two blur
   * ping-pong targets when blur is enabled), the depth stencil, and the
   * fullscreen quad the blur passes draw - scaled to the shadow resolution.
   */
  int Shadow::Init(const int fidelity)
  {
    // Both tuning values are sampled before the reset below, which zeroes the
    // cached copies.
    const int shadowSize = ren_ShadowSize;
    const bool shadowBlur = ren_ShadowBlur;

    (void)ReleaseRenderResources();

    mShadowFidelity = fidelity;
    mShadowBlurEnabled = shadowBlur;
    mShadowSize = shadowSize;

    if (fidelity == 0) {
      return 1;
    }

    // Fidelity 1 uses the cheaper target format; every higher level uses the
    // wider one.
    const int targetFormat = (fidelity != 1) ? 7 : 2;

    // The binary pulls the GAL device singleton here and discards it; the call
    // is kept because it is what forces the backend to be resolved before the
    // resource factory below is used.
    (void)gpg::gal::Device::GetInstance();

    ID3DDeviceResources* const resources = D3D_GetDevice()->GetResources();

    resources->CreateRenderTarget(mShadowMap, shadowSize, shadowSize, targetFormat);
    if (mShadowBlurEnabled) {
      resources->CreateRenderTarget(mBlurTargetA, shadowSize, shadowSize, targetFormat);
      resources->CreateRenderTarget(mBlurTargetB, shadowSize, shadowSize, targetFormat);
    }

    resources->CreateDepthStencil(mDepthStencil, shadowSize, shadowSize, kShadowDepthStencilFormat);
    if (!mDepthStencil) {
      gpg::Warnf("unable to create depth sheet used by the shadow map");
      (void)ReleaseRenderResources();
      return 0;
    }

    CD3DVertexFormat* const vertexFormat = resources->GetVertexFormat(kScreenQuadVertexFormatToken);
    mQuadVertexSheet.reset(
      resources->NewVertexSheet(kScreenQuadStreamUsage, kScreenQuadVertexCount, vertexFormat)
    );
    if (!mQuadVertexSheet) {
      gpg::Warnf("unable to create the main vertex sheet used by the shadow map");
      (void)ReleaseRenderResources();
      return 0;
    }

    // The template is a unit quad; scale it out to the shadow-map resolution.
    // The binary leaves the texture coordinates alone, which is what passing
    // 1.0f for both texture scales does here.
    const float shadowSizeF = static_cast<float>(shadowSize);
    FillScreenQuadVertexSheet(*mQuadVertexSheet, shadowSizeF, shadowSizeF, 1.0f, 1.0f);
    return 1;
  }

  /**
   * Address: 0x007FE1A0 (FUN_007FE1A0)
   *
   * What it does:
   * Runs one deleting-destructor thunk for `Shadow`, forwarding through
   * `Shadow::~Shadow` and optional storage release.
   */
  [[nodiscard]] Shadow* DestroyShadowDeleting(Shadow* const shadow, const unsigned char deleteFlag)
  {
    shadow->~Shadow();
    if ((deleteFlag & 1u) != 0u) {
      ::operator delete(static_cast<void*>(shadow));
    }
    return shadow;
  }
  /**
   * Address: 0x007FE940 (FUN_007FE940, sub_7FE940)
   *
   * What it does:
   * Builds the light-space camera the shadow map is rendered with.
   *
   * The light basis is built around the sun direction, using the camera's
   * forward axis as the reference up - unless the two are nearly parallel
   * (dot >= 0.99), where the cross products would collapse and a fixed
   * (0, 0, -1) is used instead.
   *
   * The view frustum's far plane is pulled in to `ren_ShadowCoeff * zoom`
   * before the terrain clip, which is what keeps the shadow volume tight
   * as the camera zooms rather than covering the whole visible distance.
   *
   * The eye sits 10000 units back along the light direction - far enough
   * that the projection is effectively directional - and the near plane is
   * pushed a further 25 units out so casters just behind the clipped volume
   * still reach it. The 8-unit lift on the box top is the same idea for
   * casters standing above the terrain.
   */
  bool Shadow::PrepareLightCamera(
    const GeomCamera3& viewCamera,
    const Wm3::Vector3f& sunDirection,
    const float zoom
  )
  {
    mShadowCameraValid = false;
    if (mShadowFidelity == 0 || zoom > ren_ShadowLOD) {
      return false;
    }

    IWldTerrainRes* const terrainRes = REN_GetTerrainRes();
    if (terrainRes == nullptr) {
      return false;
    }
    // Same route the terrain passes use: the resource view carries the map,
    // and the map's height-field lane is the collision surface.
    auto* const terrainView = reinterpret_cast<TerrainWaterResourceView*>(terrainRes);
    auto* const heightField =
      reinterpret_cast<CHeightField*>(terrainView->mMap->mHeightFieldObject);
    if (heightField == nullptr) {
      return false;
    }

    // The light travels along -sunDirection; the camera forward axis is
    // inverseView.r[2], also negated.
    const Wm3::Vector3f lightDirection(-sunDirection.X(), -sunDirection.Y(), -sunDirection.Z());
    const Vector4f& cameraBasisZ = viewCamera.inverseView.r[2];
    const Wm3::Vector3f cameraForward(-cameraBasisZ.x, -cameraBasisZ.y, -cameraBasisZ.z);

    Wm3::Vector3f lightUp(0.0f, 0.0f, -1.0f);
    const float alignment = (cameraForward.X() * lightDirection.X())
      + (cameraForward.Y() * lightDirection.Y())
      + (cameraForward.Z() * lightDirection.Z());
    if (alignment < 0.99f) {
      Wm3::Vector3f lightRight(
        (cameraForward.Z() * lightDirection.Y()) - (cameraForward.Y() * lightDirection.Z()),
        (cameraForward.X() * lightDirection.Z()) - (cameraForward.Z() * lightDirection.X()),
        (cameraForward.Y() * lightDirection.X()) - (cameraForward.X() * lightDirection.Y())
      );
      lightRight.Normalize();

      lightUp = Wm3::Vector3f(
        (lightRight.Y() * lightDirection.Z()) - (lightRight.Z() * lightDirection.Y()),
        (lightRight.Z() * lightDirection.X()) - (lightRight.X() * lightDirection.Z()),
        (lightRight.X() * lightDirection.Y()) - (lightRight.Y() * lightDirection.X())
      );
      lightUp.Normalize();
    }

    // Clip the view frustum to the shadow distance, then to the terrain.
    CGeomSolid3 shadowFrustum{viewCamera.solid2};
    shadowFrustum.planes_[5].Constant =
      (ren_ShadowCoeff * zoom) - shadowFrustum.planes_[4].Constant;

    Wm3::AxisAlignedBox3f volume = heightField->ConvexIntersection(shadowFrustum);
    if (volume.Max.X() <= volume.Min.X()) {
      return false;
    }

    // Lift the top so casters standing above the terrain still fit.
    volume.Max.Y() = volume.Max.Y() + 8.0f;

    const Wm3::Vector3f center(
      (volume.Min.X() + volume.Max.X()) * 0.5f,
      (volume.Min.Y() + volume.Max.Y()) * 0.5f,
      (volume.Min.Z() + volume.Max.Z()) * 0.5f
    );
    const Wm3::Vector3f eye(
      center.X() - (lightDirection.X() * 10000.0f),
      center.Y() - (lightDirection.Y() * 10000.0f),
      center.Z() - (lightDirection.Z() * 10000.0f)
    );

    gpg::gal::Matrix lightView{};
    (void)MatrixLookAtRH(&lightView, &eye, &center, &lightUp);

    Wm3::AxisAlignedBox3f lightSpaceVolume{};
    (void)ProjectBoxByMatrix(
      &lightView, &volume, &lightSpaceVolume);

    const float nearMagnitude = std::fabs(lightSpaceVolume.Max.Z());
    const float farMagnitude = std::fabs(lightSpaceVolume.Min.Z());
    const float nearDepth = std::min(nearMagnitude, farMagnitude) - 25.0f;
    const float farDepth = std::max(nearMagnitude, farMagnitude);

    // Orthographic projection fitted to the light-space volume, built by
    // hand rather than through a helper - the binary writes these seven
    // elements and zeroes the rest.
    gpg::gal::Matrix lightProjection{};
    lightProjection.r[0].x = 2.0f / (lightSpaceVolume.Max.X() - lightSpaceVolume.Min.X());
    lightProjection.r[1].y = 2.0f / (lightSpaceVolume.Max.Y() - lightSpaceVolume.Min.Y());
    lightProjection.r[2].z = 1.0f / (nearDepth - farDepth);
    lightProjection.r[3].x = (lightSpaceVolume.Max.X() + lightSpaceVolume.Min.X())
      / (lightSpaceVolume.Min.X() - lightSpaceVolume.Max.X());
    lightProjection.r[3].y = (lightSpaceVolume.Min.Y() + lightSpaceVolume.Max.Y())
      / (lightSpaceVolume.Min.Y() - lightSpaceVolume.Max.Y());
    lightProjection.r[3].z = lightProjection.r[2].z * nearDepth;
    lightProjection.r[3].w = 1.0f;

    gpg::gal::Matrix lightViewProjection{};
    (void)gpg::gal::Math::mul(&lightViewProjection, &lightView, &lightProjection);

    const VTransform identityTransform{VMatrix4::Identity()};
    mCamera.Init(identityTransform, lightViewProjection);

    mShadowCameraValid = true;
    return mShadowCameraValid;
  }

  /**
   * Address: 0x007FEEA0 (FUN_007FEEA0, sub_7FEEA0)
   *
   * What it does:
   * Draws the shadow map for this frame: terrain depth first, then every
   * mesh, both from the light camera PrepareLightCamera built.
   *
   * With no valid light camera it only rebinds the targets and returns, so
   * the map is left cleared rather than holding the previous frame.
   *
   * Every pass insets its viewport by one pixel on each side. That border
   * is what stops the blur taps and the shadow lookup from sampling past
   * the edge of the map.
   *
   * When blur is on the depth map is turned into a variance map by two
   * separable passes, shadow map -> A -> B, each drawing the unit quad.
   */
  void Shadow::RenderShadowMap(TerrainCommon* const terrain, const GeomCamera3& viewCamera)
  {
    if (mShadowFidelity == 0) {
      return;
    }

    CD3DDevice* const device = D3D_GetDevice();
    (void)device->GetResources();

    if (!mShadowCameraValid) {
      // Nothing to draw - just leave the targets bound and cleared.
      device->SetRenderTarget1(mShadowMap.get(), mDepthStencil.get(), true, -1, 1.0f, 0);
      if (mShadowBlurEnabled) {
        device->SetRenderTarget1(mBlurTargetA.get(), mDepthStencil.get(), true, -1, 1.0f, 0);
        device->SetRenderTarget1(mBlurTargetB.get(), mDepthStencil.get(), true, -1, 1.0f, 0);
      }
      return;
    }

    gpg::gal::RenderTargetContext targetContext{};

    Wm3::Vector2i savedPos{};
    Wm3::Vector2i savedSize{};
    float savedMinDepth = 0.0f;
    float savedMaxDepth = 1.0f;

    // Binds one target and gives it a viewport inset by a one-pixel border.
    const auto bindTargetWithBorder =
      [&](const boost::shared_ptr<CD3DRenderTarget>& target) {
        device->GetView(&savedPos, &savedSize, &savedMinDepth, &savedMaxDepth);

        // The target's real extent, via its surface's context.
        ID3DRenderTarget::SurfaceHandle surface{};
        (void)target->GetSurface(surface);
        const gpg::gal::RenderTargetContext* const context =
          (surface != nullptr) ? surface->GetContext() : nullptr;
        if (context == nullptr) {
          return;
        }

        Wm3::Vector2i borderPos{1, 1};
        Wm3::Vector2i borderSize{
          static_cast<std::int32_t>(context->width_) - 2,
          static_cast<std::int32_t>(context->height_) - 2
        };
        device->SetViewport(&borderPos, &borderSize, savedMinDepth, savedMaxDepth);
      };

    const auto restoreViewport = [&]() {
      device->SetViewport(&savedPos, &savedSize, savedMinDepth, savedMaxDepth);
    };

    // Depth pass into the shadow map.
    device->SetRenderTarget1(mShadowMap.get(), mDepthStencil.get(), true, -1, 1.0f, 0);
    bindTargetWithBorder(mShadowMap);

    terrain->DrawTerrainDepth(mCamera);

    MeshRenderer* const meshRenderer = MeshRenderer::GetInstance();
    meshRenderer->Batch(REN_GetGameTick(), REN_GetSimDeltaSeconds(), mCamera, viewCamera.viewport.r[1]);
    meshRenderer->RenderDepth(mCamera, meshRenderer->meshes);

    restoreViewport();

    if (!mShadowBlurEnabled) {
      return;
    }

    auto& shaderVars = GetTerrainShaderVars();

    // Separable variance blur: shadow map -> A (horizontal) -> B (vertical).
    const auto blurPass = [&](
      const boost::shared_ptr<CD3DRenderTarget>& target,
      const boost::shared_ptr<CD3DRenderTarget>& source,
      const char* const technique
    ) {
      device->SetRenderTarget1(target.get(), mDepthStencil.get(), true, -1, 1.0f, 0);
      bindTargetWithBorder(target);

      device->SelectFxFile("terrain");
      device->SelectTechnique(technique);
      (void)shaderVars.shadowSize.SetFloat(static_cast<float>(mShadowSize));
      (void)shaderVars.shadowTexture.SetRenderTargetTexture(source);

      CD3DVertexSheetViewRuntime quadView{};
      quadView.sheet = mQuadVertexSheet.get();
      quadView.startVertex = 0;
      quadView.baseVertex = 0;
      quadView.endVertex = 3;
      std::int32_t primitiveType = 5;
      (void)device->DrawPrimitiveList(&quadView, &primitiveType);

      restoreViewport();
    };

    blurPass(mBlurTargetA, mShadowMap, "THorizontalBlurDepthToVariance");
    blurPass(mBlurTargetB, mBlurTargetA, "TVerticalBlurDepthToVariance");
  }

  /**
   * Address: 0x007F7D10 (FUN_007F7D10,
   *          ?RenderShadows@WRenViewport@Moho@@AAEXPAVIRenTerrain@2@M@Z)
   *
   * What it does:
   * The frame's shadow pass. Re-initialises the shadow renderer when any of
   * the three tuning lanes has moved since it was last built, derives the
   * light camera from the sun direction, and draws the map.
   *
   * The fidelity is clamped to what the device reports it can do, and the
   * clamped value is written back to the global - so a request for more than
   * the hardware supports is remembered as the value actually used, not the
   * value asked for.
   */
  void Shadow::RenderFrameShadows(TerrainCommon* const terrain, const GeomCamera3& viewCamera, const float zoom)
  {
    if (!ren_Shadows) {
      return;
    }

    std::int32_t fidelity = std::min(shadow_Fidelity, shadow_FidelitySupported);
    if (fidelity < 0) {
      fidelity = 0;
    }
    shadow_Fidelity = fidelity;

    if (fidelity != mShadowFidelity
      || ren_ShadowSize != mShadowSize
      || ren_ShadowBlur != mShadowBlurEnabled) {
      (void)Init(fidelity);

      // Init settles what could actually be allocated; publish that back.
      shadow_Fidelity = mShadowFidelity;
      ren_ShadowSize = mShadowSize;
      ren_ShadowBlur = mShadowBlurEnabled;
    }

    IWldTerrainRes* const terrainRes = REN_GetTerrainRes();
    if (terrainRes == nullptr) {
      return;
    }

    const Wm3::Vector3f sunDirection = terrainRes->GetSunDirection();
    (void)PrepareLightCamera(viewCamera, sunDirection, zoom);
    RenderShadowMap(terrain, viewCamera);
  }

} // namespace moho
