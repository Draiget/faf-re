#pragma once

#include <cstddef>
#include <cstdint>

#include <boost/shared_ptr.hpp>

#include "moho/render/camera/GeomCamera3.h"

namespace moho
{
  class TerrainCommon;

  class CD3DDepthStencil;
  class CD3DRenderTarget;
  class ID3DVertexSheet;

  /**
   * VFTABLE: 0x00E40D34 (??_7Shadow@Moho@@6B@)
   *
   * One viewport's shadow-map renderer: the render targets the shadow depth is
   * drawn into, the light-space camera it is drawn with, and the fullscreen
   * quad used by the blur passes.
   *
   * Field ownership was recovered from every function in the binary that
   * touches this object: the constructor (0x007FE120), Init (0x007FE3E0), the
   * reset helper (0x007FE760), the shadow-map accessor (0x007DB350), the
   * light/camera setup (0x007FE940), the render pass (0x007FEEA0),
   * WRenViewport::RenderShadows (0x007F7D10) and MeshRenderer::ConfigureShader
   * (0x007E19D0).
   */
  class Shadow
  {
  public:
    /**
     * Address: 0x007FE120 (FUN_007FE120, ??0Shadow@Moho@@QAE@@Z)
     *
     * What it does:
     * Seats the vftable, zeroes the fidelity/size/blur settings and the
     * camera-valid flag, constructs the light-space camera, and null-clears all
     * seven reference-counted resource handles.
     */
    Shadow();

    /**
     * Address: 0x007FE200 (FUN_007FE200, ??1Shadow@Moho@@UAE@XZ)
     *
     * What it does:
     * Releases every held render resource through the shared reset path.
     */
    virtual ~Shadow();

    /**
     * Address: 0x007FE3E0 (FUN_007FE3E0, Moho::Shadow::Init)
     *
     * IDA signature:
     * int __usercall Moho::Shadow::Init@<eax>(int fidelity, Moho::Shadow *this);
     *
     * What it does:
     * Rebuilds the shadow render resources for one fidelity level. Latches the
     * current `ren_ShadowSize`/`ren_ShadowBlur` tuning, releases whatever was
     * held before, and - when fidelity is non-zero - allocates the shadow-map
     * target (plus two more when blur is on), the depth stencil, and the
     * fullscreen quad the blur passes draw. Returns 0 if a resource could not
     * be created (after warning), 1 otherwise.
     */
    int Init(int fidelity);

    /**
     * Address: 0x007FE940 (FUN_007FE940, sub_7FE940)
     *
     * IDA signature:
     * int __usercall sub_7FE940(float *this, Shadow *a2,
     *     Wm3::Vector3f *a3, float arg8);
     *
     * What it does:
     * Builds the light-space camera the shadow map is rendered with, and
     * reports whether there is anything to render.
     *
     * Clips the view frustum against the terrain, fits an orthographic
     * light volume to whatever survives, and leaves mShadowCameraValid set
     * when that volume is non-empty. Answers false without touching the
     * camera when shadows are off for this fidelity or the view is zoomed
     * out past ren_ShadowLOD.
     */
    bool PrepareLightCamera(const GeomCamera3& viewCamera, const Wm3::Vector3f& sunDirection, float zoom);

    /**
     * Address: 0x007FEEA0 (FUN_007FEEA0, sub_7FEEA0)
     *
     * What it does:
     * Draws the shadow map: terrain depth then meshes, from the light
     * camera, followed by the separable variance blur when it is enabled.
     */
    void RenderShadowMap(TerrainCommon* terrain, const GeomCamera3& viewCamera);

    /**
     * Address: 0x007F7D10 (FUN_007F7D10,
     *          ?RenderShadows@WRenViewport@Moho@@AAEXPAVIRenTerrain@2@M@Z)
     *
     * What it does:
     * The frame's shadow pass: rebuild on a tuning change, derive the light
     * camera, draw the map.
     */
    void RenderFrameShadows(TerrainCommon* terrain, const GeomCamera3& viewCamera, float zoom);

    /**
     * Address: 0x007FE760 (FUN_007FE760)
     *
     * IDA signature:
     * int __usercall sub_7FE760@<eax>(Moho::Shadow *this@<esi>);
     *
     * What it does:
     * Clears the cached fidelity/blur/size settings and releases every render
     * resource the shadow renderer holds. Reached from the destructor, from
     * `Init`, and from `WRenViewport::D3DWindowOnDeviceExit` - the last one is
     * why this is public: the D3D device must not still own default-pool
     * surfaces when `IDirect3DDevice9::Reset` runs.
     */
    int ReleaseRenderResources() noexcept;

    /**
     * Address: 0x007DB350 (FUN_007DB350)
     *
     * IDA signature:
     * boost::shared_ptr *__usercall sub_7DB350@<eax>(
     *     boost::shared_ptr *result@<eax>, Moho::Shadow *this@<ecx>);
     *
     * What it does:
     * Returns a retained copy of the shadow-map render target so a shader
     * variable can sample it. The binary increments `use_count_` (control
     * block +0x04), i.e. a strong reference, not a weak one.
     */
    boost::shared_ptr<CD3DRenderTarget>& GetShadowMap(
      boost::shared_ptr<CD3DRenderTarget>& outShadowMap
    ) const;

  public:
    // Never written by the constructor and no reader was found in any of the
    // functions listed above; kept as an explicit hole so the offsets below
    // stay exact.
    std::uint32_t mUnusedHeaderWord;                      // +0x04

    std::int32_t mShadowFidelity;                         // +0x08
    bool mShadowBlurEnabled;                              // +0x0C
    std::uint8_t mPadding0D_0F[0x03];                     // +0x0D
    std::int32_t mShadowSize;                             // +0x10

    // Set to 1 by the light/camera setup (0x007FE940) immediately after
    // GeomCamera3::Init succeeds, and cleared at its entry. The render pass
    // (0x007FEEA0) branches on it: set means draw the shadow map, clear means
    // only clear the targets for this frame.
    bool mShadowCameraValid;                              // +0x14
    std::uint8_t mPadding15_17[0x03];                     // +0x15

    GeomCamera3 mCamera;                                  // +0x18

    // Drawn into by the render pass and sampled by the mesh/terrain shaders
    // through GetShadowMap.
    boost::shared_ptr<CD3DRenderTarget> mShadowMap;       // +0x2E0

    // Blur ping-pong targets; only allocated when mShadowBlurEnabled.
    boost::shared_ptr<CD3DRenderTarget> mBlurTargetA;     // +0x2E8
    boost::shared_ptr<CD3DRenderTarget> mBlurTargetB;     // +0x2F0

    boost::shared_ptr<CD3DDepthStencil> mDepthStencil;    // +0x2F8

    // Unit quad the blur passes draw; built once by Init.
    boost::shared_ptr<ID3DVertexSheet> mQuadVertexSheet;  // +0x300

    // Two further reference-counted slots. The constructor null-clears them and
    // the reset helper releases them exactly like the five above, so they are
    // handles of the same shape - but no function in this binary reads or
    // writes either one, so their pointee type cannot be named yet.
    boost::shared_ptr<void> mUnreferencedResources[2];    // +0x308, +0x310
  };

  static_assert(offsetof(Shadow, mShadowFidelity) == 0x08, "Shadow::mShadowFidelity offset must be 0x08");
  static_assert(offsetof(Shadow, mShadowBlurEnabled) == 0x0C, "Shadow::mShadowBlurEnabled offset must be 0x0C");
  static_assert(offsetof(Shadow, mShadowSize) == 0x10, "Shadow::mShadowSize offset must be 0x10");
  static_assert(offsetof(Shadow, mShadowCameraValid) == 0x14, "Shadow::mShadowCameraValid offset must be 0x14");
  static_assert(offsetof(Shadow, mCamera) == 0x18, "Shadow::mCamera offset must be 0x18");
  static_assert(offsetof(Shadow, mShadowMap) == 0x2E0, "Shadow::mShadowMap offset must be 0x2E0");
  static_assert(offsetof(Shadow, mBlurTargetA) == 0x2E8, "Shadow::mBlurTargetA offset must be 0x2E8");
  static_assert(offsetof(Shadow, mBlurTargetB) == 0x2F0, "Shadow::mBlurTargetB offset must be 0x2F0");
  static_assert(offsetof(Shadow, mDepthStencil) == 0x2F8, "Shadow::mDepthStencil offset must be 0x2F8");
  static_assert(offsetof(Shadow, mQuadVertexSheet) == 0x300, "Shadow::mQuadVertexSheet offset must be 0x300");
  static_assert(
    offsetof(Shadow, mUnreferencedResources) == 0x308,
    "Shadow::mUnreferencedResources offset must be 0x308"
  );
  static_assert(sizeof(Shadow) == 0x318, "Shadow size must be 0x318");
} // namespace moho
