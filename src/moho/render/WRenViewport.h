#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "legacy/containers/Vector.h"
#include "moho/mesh/MeshThumbnailRenderer.h"
#include "moho/misc/CountedObject.h"
#include "moho/render/BoundaryRenderer.h"
#include "moho/render/CRenFrame.h"
#include "moho/render/Clutter.h"
#include "moho/render/MapImager.h"
#include "moho/render/RangeRenderer.h"
#include "moho/render/Shadow.h"
#include "moho/render/Silhouette.h"
#include "moho/render/VisionRenderer.h"
#include "moho/render/d3d/CD3DFont.h"
#include "moho/render/d3d/WD3DViewport.h"
#include "moho/sim/CDebugCanvas.h"
#include "Wm3Vector2.h"

class wxMouseEvent;

namespace moho
{
  class CD3DDepthStencil;
  class CD3DDynamicTextureSheet;
  class CD3DPrimBatcher;
  class CD3DRenderTarget;
  class CD3DTextureBatcher;
  class CWldSession;
  class ID3DRenderTarget;
  class ID3DTextureSheet;
  class IRenderWorldView;
  class IWldTerrainRes;
  class TerrainCommon;
  struct GeomCamera3;

  /**
   * One head's bloom post-process: two half-size targets the blur ping-pongs
   * between and the two frame quads that draw into them.
   *
   * Constructed and destroyed as the `WRenViewport::mBloomRenderers[2]` array
   * (the eh vector iterators at 0x007F66F2 / 0x007F6B32, stride 0xAC).
   */
  class CBloomRenderer
  {
  public:
    /**
     * Address: 0x007F6420 (FUN_007F6420)
     * Mangled: ??0CBloomRenderer@Moho@@QAE@XZ
     *
     * What it does:
     * Default-constructs the targets and frames, then zeroes the extent and
     * head - in the body, after the members, as the stores at 0x007F6477 run.
     */
    CBloomRenderer();

    /**
     * Address: 0x007F64A0 (FUN_007F64A0)
     * Mangled: ??1CBloomRenderer@Moho@@QAE@XZ
     *
     * What it does:
     * `ResetRenderTargets()`, then the members go in reverse order.
     */
    ~CBloomRenderer();

    /**
     * Address: 0x007F4D00 (FUN_007F4D00)
     *
     * What it does:
     * Binds this renderer to `head`: caches half the head's extent, creates the
     * two half-size targets, and lays out both frame quads - the composite pass
     * at half size, the extract pass at the full head size.
     */
    int Init(int head);

    /**
     * Address: 0x007F4F10 (FUN_007F4F10)
     *
     * What it does:
     * Destroys both frames' vertex sheets and drops both targets.
     */
    void ResetRenderTargets() noexcept;

    /**
     * Address: 0x007F5160 (FUN_007F5160)
     * Mangled: ?DoBloom@CBloomRenderer@Moho@@QAEXM@Z
     *
     * What it does:
     * Copies the glowing part of the head's back buffer into the extract
     * target, blurs it `ren_BloomBlurCount` times between the two targets, and
     * adds the result back onto the back buffer. `amount` is the glow-copy
     * bias (shaderVarFrameGlowCopyAdd).
     */
    void DoBloom(float amount);

  private:
    /**
     * Address: 0x007F4FB0 (FUN_007F4FB0)
     * Mangled: ?RenderToBlur@CBloomRenderer@Moho@@AAEXPBDV?$shared_ptr@VID3DRenderTarget@Moho@@@boost@@@Z
     *
     * What it does:
     * Draws the composite quad at half size with `technique`, sampling `texture`.
     */
    void RenderToBlur(const char* technique, boost::shared_ptr<ID3DRenderTarget> texture);

    /**
     * Address: 0x007F5070 (FUN_007F5070)
     * Mangled: ?RenderToBackBuffer@CBloomRenderer@Moho@@AAEXPBDV?$shared_ptr@VID3DRenderTarget@Moho@@@boost@@@Z
     *
     * What it does:
     * Draws the extract quad over the whole head with "TFrameAdd", sampling
     * `texture`. The mangled name carries a technique argument the body never
     * reads; DoBloom does not pass one.
     */
    void RenderToBackBuffer(boost::shared_ptr<ID3DRenderTarget> texture);

  public:
    // Half the head's extent (0x007F4D2E..0x007F4D49 shift the head size by 1).
    std::uint32_t mWidth;                                    // +0x00
    std::uint32_t mHeight;                                   // +0x04
    boost::shared_ptr<ID3DRenderTarget> mRenderTargets[2];  // +0x08
    CRenFrame mExtractFrame;                                 // +0x18
    CRenFrame mCompositeFrame;                               // +0x60
    std::uint32_t mHead;                                     // +0xA8
  };

  static_assert(offsetof(CBloomRenderer, mRenderTargets) == 0x08, "moho::CBloomRenderer::mRenderTargets offset must be 0x08");
  static_assert(offsetof(CBloomRenderer, mExtractFrame) == 0x18, "moho::CBloomRenderer::mExtractFrame offset must be 0x18");
  static_assert(offsetof(CBloomRenderer, mCompositeFrame) == 0x60, "moho::CBloomRenderer::mCompositeFrame offset must be 0x60");
  static_assert(offsetof(CBloomRenderer, mHead) == 0xA8, "moho::CBloomRenderer::mHead offset must be 0xA8");
  static_assert(sizeof(CBloomRenderer) == 0xAC, "moho::CBloomRenderer size must be 0xAC");

  /**
   * One world view the game viewport draws: the view, the head it draws on,
   * its draw order, and the terrain renderer AddWorldView made for it.
   * `WRenViewport::Render`'s mangled name spells the element type
   * (`std::vector<Moho::SWorldViewInfo>`).
   */
  struct SWorldViewInfo
  {
    IRenderWorldView* mView;                  // +0x00
    std::int32_t mHead;                       // +0x04
    std::int32_t mDepth;                      // +0x08
    boost::shared_ptr<TerrainCommon> mTerrain; // +0x0C
  };

  static_assert(offsetof(SWorldViewInfo, mDepth) == 0x08, "moho::SWorldViewInfo::mDepth offset must be 0x08");
  static_assert(offsetof(SWorldViewInfo, mTerrain) == 0x0C, "moho::SWorldViewInfo::mTerrain offset must be 0x0C");
  static_assert(sizeof(SWorldViewInfo) == 0x14, "moho::SWorldViewInfo size must be 0x14");

  /**
   * The game viewport: the D3D window the world is rendered into, with every
   * renderer the world pass uses.
   *
   * vftable 0x00E405BC. It overrides slot 1 (the deleting destructor), slot 6
   * (GetEventTable 0x007F6690, table 0x00DFE950 = {&WD3DViewport::sm_eventTable,
   * rows 0x00F5AB58}) and the six device hooks 131-136; slot 124 stays
   * WD3DViewport's MSWWindowProc. Allocated by REN_CreateGameViewport as
   * `operator new(0x21A8)`.
   *
   * The member order is the constructor's (0x007F66A0), which runs them in
   * this sequence and leaves the screen/head block uninitialised, and the
   * destructor's (0x007F6900), which undoes them in reverse and has no body of
   * its own.
   */
  class WRenViewport : public WD3DViewport
  {
  public:
    /**
     * Address: 0x007F66A0 (FUN_007F66A0)
     * Mangled: ??0WRenViewport@Moho@@QAE@PAVwxWindow@@VStrArg@gpg@@ABVwxSize@@_N@Z
     *
     * What it does:
     * Builds the D3D window, default-constructs every renderer, and sets the
     * head count from `hasSecondHead`.
     */
    WRenViewport(wxWindow* parent, gpg::StrArg title, const wxSize& size, bool hasSecondHead);

    /**
     * Address: 0x007F6900 (FUN_007F6900)
     * Mangled: ??1WRenViewport@Moho@@UAE@XZ
     *
     * What it does:
     * Nothing beyond the member destructors and ~WD3DViewport.
     */
    ~WRenViewport() override;

    /**
     * Address: 0x007F6B60 (FUN_007F6B60)
     * Mangled: ?D3DWindowOnDeviceInit@WRenViewport@Moho@@UAEX_N@Z
     *
     * What it does:
     * Builds every device-dependent resource the viewport renders through: the
     * texture and primitive batchers (only when `createBatchers` - the first
     * bind, from CD3DDevice::SetRenViewport 0x0042DC10), the debug font, each
     * renderer's resources, the dynamic texture sheet, and per head the bloom
     * renderer, the two colour targets and the depth stencil. A rebind from
     * CD3DDevice::InitContext (0x0042E1E0) passes false and keeps the
     * batchers; the per-head resources are each guarded, so a rebind only
     * refills what D3DWindowOnDeviceExit released.
     */
    void D3DWindowOnDeviceInit(bool createBatchers) override;

    /**
     * Address: 0x007F7B30 (FUN_007F7B30)
     * Mangled: ?D3DWindowOnDeviceRender@WRenViewport@Moho@@UAEXXZ
     *
     * What it does:
     * One engine frame: resets the frame's render stats, ticks each world view,
     * advances the mesh interpolant, then renders each head. A paint that
     * arrives while one is already in progress is dropped.
     */
    void D3DWindowOnDeviceRender() override;

    /**
     * Address: 0x007F70F0 (FUN_007F70F0)
     * Mangled: ?D3DWindowOnDeviceExit@WRenViewport@Moho@@UAEX_N@Z
     *
     * What it does:
     * The inverse of D3DWindowOnDeviceInit: drops every device-dependent
     * resource so none of them survives into IDirect3DDevice9::Reset, which
     * fails outright while a default-pool surface is still referenced.
     * `fullShutdown` (CD3DDevice::Destroy 0x0042E750) also drops the batchers,
     * clears the map-imager border and shuts the mesh renderer down; a rebind
     * (CD3DDevice::InitContext) only resets it.
     */
    void D3DWindowOnDeviceExit(bool fullShutdown) override;

    /**
     * Address: 0x007F7400 (FUN_007F7400)
     * Mangled: ?RenderPreviewImage@WRenViewport@Moho@@UAEX_N@Z
     *
     * What it does:
     * Renders a top-down strategic snapshot of the loaded map into the preview
     * sheet GetPreviewImage returns: one Render against a throwaway camera
     * framed on the map, with every non-terrain pass and the editor hook off
     * for its duration. `forceRegenerate` is not read.
     */
    void RenderPreviewImage(bool forceRegenerate) override;

    /**
     * Address: 0x007F65D0 (FUN_007F65D0)
     * Mangled: ?GetPreviewImage@WRenViewport@Moho@@UAE?AV?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@XZ
     *
     * What it does:
     * Returns the dynamic texture sheet the preview is rendered into.
     */
    boost::shared_ptr<ID3DTextureSheet> GetPreviewImage() override;

    /**
     * Address: 0x007F6600 (FUN_007F6600)
     * Mangled: ?GetPrimBatcher@WRenViewport@Moho@@UBEPAVCD3DPrimBatcher@2@XZ
     *
     * What it does:
     * Returns the primitive batcher.
     */
    CD3DPrimBatcher* GetPrimBatcher() const override;

    /**
     * Address: 0x007F6610 (FUN_007F6610)
     * Mangled: ?OnMouseEnter@WRenViewport@Moho@@QAEXAAVwxMouseEvent@@@Z
     *
     * What it does:
     * Once the GAL device is ready, gives keyboard focus to the first head's
     * window.
     */
    void OnMouseEnter(wxMouseEvent& event);

    /**
     * Address: 0x007F6640 (FUN_007F6640)
     * Mangled: ?OnMouseLeave@WRenViewport@Moho@@QAEXAAVwxMouseEvent@@@Z
     *
     * What it does:
     * Once the GAL device is ready and there is a second head, gives keyboard
     * focus to that head's window.
     */
    void OnMouseLeave(wxMouseEvent& event);

    /**
     * Address: 0x007F9E60 (FUN_007F9E60)
     * Mangled: ?AddWorldView@WRenViewport@Moho@@QAEXPAVIRenderWorldView@2@HH@Z
     *
     * What it does:
     * Re-adds `view` in depth order with a new terrain renderer bound to the
     * loaded map's terrain.
     */
    void AddWorldView(IRenderWorldView* view, int head, int depth);

    /**
     * Address: 0x007FA090 (FUN_007FA090)
     * Mangled: ?RemoveWorldView@WRenViewport@Moho@@QAEXPAVIRenderWorldView@2@@Z
     *
     * What it does:
     * Erases the first entry for `view`.
     */
    void RemoveWorldView(IRenderWorldView* view);

  private:
    /**
     * Address: 0x007F90D0 (FUN_007F90D0)
     * Mangled: ?Render@WRenViewport@Moho@@AAEXHAAV?$vector@USWorldViewInfo@Moho@@V?$allocator@USWorldViewInfo@Moho@@@std@@@std@@@Z
     *
     * What it does:
     * Renders one head: binds its targets, then runs the terrain, mesh,
     * effects, water, shadow, bloom and UI passes for each world view in
     * `worldViews` that draws on it.
     */
    void Render(int head, msvc8::vector<SWorldViewInfo>& worldViews);

    /**
     * Address: 0x007F88B0 (FUN_007F88B0)
     * Mangled: ?RenderUI@WRenViewport@Moho@@AAEXABV?$vector@USWorldViewInfo@Moho@@V?$allocator@USWorldViewInfo@Moho@@@std@@@std@@@Z
     *
     * What it does:
     * Draws the UI and the debug overlays over the head's full extent.
     */
    void RenderUI(const msvc8::vector<SWorldViewInfo>& worldViews);

    /**
     * Address: 0x007F98A0 (FUN_007F98A0)
     * Mangled: ?RenderCameraOutline@WRenViewport@Moho@@AAEXPBVGeomCamera3@2@M_N@Z
     *
     * What it does:
     * Draws where `camera` meets the ground as an outline.
     */
    void RenderCameraOutline(const GeomCamera3* camera, float groundY, bool useFocusedColor);

    /**
     * Address: 0x007F8BA0 (FUN_007F8BA0)
     * Mangled: ?RenderCartographic@WRenViewport@Moho@@AAEIHAAV?$vector@USWorldViewInfo@Moho@@V?$allocator@USWorldViewInfo@Moho@@@std@@@std@@@Z
     *
     * What it does:
     * Renders the cartographic (map-mode) views of `head`; returns how many it
     * drew.
     */
    unsigned int RenderCartographic(int head, msvc8::vector<SWorldViewInfo>& worldViews);

    /**
     * Address: 0x007F7FC0 (FUN_007F7FC0)
     * Mangled: ?TransformTerrainNormals@WRenViewport@Moho@@AAEXXZ
     */
    void TransformTerrainNormals();

    /**
     * Address: 0x007F81C0 (FUN_007F81C0)
     * Mangled: ?RenderCompositeTerrain@WRenViewport@Moho@@AAEXPAVIRenTerrain@2@@Z
     */
    void RenderCompositeTerrain(TerrainCommon* terrain);

    /**
     * Address: 0x007F80C0 (FUN_007F80C0)
     *
     * What it does:
     * Binds the sky target for the head and draws the terrain's sky dome. The
     * symbol names SkyDome::Render, but `this` is the viewport: it reads
     * mHead, mScreenPos, mScreenSize and mCam.
     */
    void RenderSkyDome();

    /**
     * Address: 0x007F8350 (FUN_007F8350)
     * Mangled: ?RenderWaterMask@WRenViewport@Moho@@AAEXPAVIRenTerrain@2@@Z
     */
    void RenderWaterMask(TerrainCommon* terrain);

    /**
     * Address: 0x007F83F0 (FUN_007F83F0)
     * Mangled: ?RenderCopyForRefraction@WRenViewport@Moho@@AAEXXZ
     *
     * What it does:
     * At medium fidelity and above, copies the head's primary target into the
     * refraction sheet; `clampToViewportRect` limits the copy to the local
     * viewport rect.
     *
     * The mangled name lists no parameter, but both call sites pass one:
     * Render clears cl at 0x007F94AF and RenderRefractingEffects sets it at
     * 0x007F8623, each with `this` in edx, and the body starts
     * `mov bl, cl; mov esi, edx`. Link-time code generation moved the private
     * member off __thiscall; the bool is real.
     */
    void RenderCopyForRefraction(bool clampToViewportRect);

    /**
     * Address: 0x007F8290 (FUN_007F8290)
     */
    void RenderMeshes(int meshFlags, bool mirrored);

    /**
     * Address: 0x007F8560 (FUN_007F8560)
     */
    void RenderEffects(bool renderWaterSurface);

    /**
     * Address: 0x007F8600 (FUN_007F8600)
     * Mangled: ?RenderRefractingEffects@WRenViewport@Moho@@AAEXXZ
     */
    void RenderRefractingEffects();

    /**
     * Address: 0x007F86F0 (FUN_007F86F0)
     * Mangled: ?RenderWater@WRenViewport@Moho@@AAEXPAVIRenTerrain@2@@Z
     */
    void RenderWater(TerrainCommon* terrain);

    /**
     * Address: 0x007F7DF0 (FUN_007F7DF0)
     * Mangled: ?RenderReflections@WRenViewport@Moho@@AAEXXZ
     */
    void RenderReflections();

    /**
     * Address: 0x007F7ED0 (FUN_007F7ED0)
     * Mangled: ?SetViewportToFullScreen@WRenViewport@Moho@@AAEXXZ
     */
    void SetViewportToFullScreen();

    /**
     * Address: 0x007F7EA0 (FUN_007F7EA0)
     * Mangled: ?SetViewportToLocalScreen@WRenViewport@Moho@@AAEXXZ
     */
    void SetViewportToLocalScreen();

    /**
     * Address: 0x007F87F0 (FUN_007F87F0)
     * Mangled: ?UpdateRenderViewportCoordinates@WRenViewport@Moho@@AAEXXZ
     */
    void UpdateRenderViewportCoordinates();

    /**
     * Address: 0x007F8A30 (FUN_007F8A30)
     * Mangled: ?FogOn@WRenViewport@Moho@@AAEXM@Z
     */
    void FogOn(float offsetMultiplier);

    /**
     * Address: 0x007F8B70 (FUN_007F8B70)
     * Mangled: ?FogOff@WRenViewport@Moho@@AAEXXZ
     */
    void FogOff();

    /**
     * Address: 0x007F7F10 (FUN_007F7F10)
     * Mangled: ?RenderTerrainNormals@WRenViewport@Moho@@AAEXPAVIRenTerrain@2@@Z
     */
    void RenderTerrainNormals(TerrainCommon* terrain);

  public:
    CBloomRenderer mBloomRenderers[2];                                // +0x0128
    CRenFrame mFrame;                                                 // +0x0280
    CDebugCanvas mDebugCanvas;                                        // +0x02C8
    Wm3::Vector2i mScreenPos;                                         // +0x0308
    Wm3::Vector2i mScreenSize;                                        // +0x0310
    Wm3::Vector2i mFullScreen;                                        // +0x0318
    std::int32_t mHead;                                               // +0x0320
    bool mHasSecondaryHead;                                           // +0x0324
    std::int32_t mNumHeads;                                           // +0x0328
    MapImager mMapImager;                                             // +0x032C
    MeshThumbnailRenderer mThumbnailRenderer;                         // +0x0340
    RangeRenderer mRangeRenderer;                                     // +0x037C
    VisionRenderer mVisionRenderer;                                   // +0x0410
    BoundaryRenderer mBoundaryRenderer;                               // +0x0488
    Shadow mShadowRenderer;                                           // +0x04F0
    Clutter mClutter;                                                 // +0x0808
    Silhouette mSilhouetteRenderer;                                   // +0x2134
    // The session Render is drawing: stored at 0x007F9379, read at 0x007F95CE
    // and cleared at 0x007F9709. The fog-of-war guard reads [ebx+488h] from
    // the same register, CWldSession::FocusArmy, which pins the type.
    CWldSession* mSession;                                            // +0x2140
    msvc8::vector<SWorldViewInfo> mWorldViews;                        // +0x2144
    boost::shared_ptr<CD3DTextureBatcher> mTexBatcher;                // +0x2154
    boost::shared_ptr<CD3DPrimBatcher> mPrimBatcher;                  // +0x215C
    // Concrete types, not the interfaces: D3DWindowOnDeviceInit fills them
    // from ID3DDeviceResources::CreateRenderTarget / CreateDepthStencil.
    boost::shared_ptr<CD3DRenderTarget> mPrimaryTargetLocks[2];       // +0x2164
    boost::shared_ptr<CD3DRenderTarget> mSecondaryTargetLocks[2];     // +0x2174
    boost::shared_ptr<CD3DDepthStencil> mDepthStencilLocks[2];        // +0x2184
    boost::shared_ptr<CD3DDynamicTextureSheet> mDynamicTextureSheet;  // +0x2194
    GeomCamera3* mCam;                                                // +0x219C
    CountedPtr<CD3DFont> mFont;                                       // +0x21A0

    DECLARE_EVENT_TABLE()
  };

  static_assert(offsetof(WRenViewport, mBloomRenderers) == 0x128, "moho::WRenViewport::mBloomRenderers offset must be 0x128");
  static_assert(offsetof(WRenViewport, mFrame) == 0x280, "moho::WRenViewport::mFrame offset must be 0x280");
  static_assert(offsetof(WRenViewport, mDebugCanvas) == 0x2C8, "moho::WRenViewport::mDebugCanvas offset must be 0x2C8");
  static_assert(offsetof(WRenViewport, mScreenPos) == 0x308, "moho::WRenViewport::mScreenPos offset must be 0x308");
  static_assert(offsetof(WRenViewport, mFullScreen) == 0x318, "moho::WRenViewport::mFullScreen offset must be 0x318");
  static_assert(offsetof(WRenViewport, mHead) == 0x320, "moho::WRenViewport::mHead offset must be 0x320");
  static_assert(offsetof(WRenViewport, mHasSecondaryHead) == 0x324, "moho::WRenViewport::mHasSecondaryHead offset must be 0x324");
  static_assert(offsetof(WRenViewport, mNumHeads) == 0x328, "moho::WRenViewport::mNumHeads offset must be 0x328");
  static_assert(offsetof(WRenViewport, mMapImager) == 0x32C, "moho::WRenViewport::mMapImager offset must be 0x32C");
  static_assert(offsetof(WRenViewport, mThumbnailRenderer) == 0x340, "moho::WRenViewport::mThumbnailRenderer offset must be 0x340");
  static_assert(offsetof(WRenViewport, mRangeRenderer) == 0x37C, "moho::WRenViewport::mRangeRenderer offset must be 0x37C");
  static_assert(offsetof(WRenViewport, mVisionRenderer) == 0x410, "moho::WRenViewport::mVisionRenderer offset must be 0x410");
  static_assert(offsetof(WRenViewport, mBoundaryRenderer) == 0x488, "moho::WRenViewport::mBoundaryRenderer offset must be 0x488");
  static_assert(offsetof(WRenViewport, mShadowRenderer) == 0x4F0, "moho::WRenViewport::mShadowRenderer offset must be 0x4F0");
  static_assert(offsetof(WRenViewport, mClutter) == 0x808, "moho::WRenViewport::mClutter offset must be 0x808");
  static_assert(offsetof(WRenViewport, mSilhouetteRenderer) == 0x2134, "moho::WRenViewport::mSilhouetteRenderer offset must be 0x2134");
  static_assert(offsetof(WRenViewport, mSession) == 0x2140, "moho::WRenViewport::mSession offset must be 0x2140");
  static_assert(offsetof(WRenViewport, mWorldViews) == 0x2144, "moho::WRenViewport::mWorldViews offset must be 0x2144");
  static_assert(offsetof(WRenViewport, mTexBatcher) == 0x2154, "moho::WRenViewport::mTexBatcher offset must be 0x2154");
  static_assert(offsetof(WRenViewport, mPrimBatcher) == 0x215C, "moho::WRenViewport::mPrimBatcher offset must be 0x215C");
  static_assert(offsetof(WRenViewport, mPrimaryTargetLocks) == 0x2164, "moho::WRenViewport::mPrimaryTargetLocks offset must be 0x2164");
  static_assert(offsetof(WRenViewport, mSecondaryTargetLocks) == 0x2174, "moho::WRenViewport::mSecondaryTargetLocks offset must be 0x2174");
  static_assert(offsetof(WRenViewport, mDepthStencilLocks) == 0x2184, "moho::WRenViewport::mDepthStencilLocks offset must be 0x2184");
  static_assert(offsetof(WRenViewport, mDynamicTextureSheet) == 0x2194, "moho::WRenViewport::mDynamicTextureSheet offset must be 0x2194");
  static_assert(offsetof(WRenViewport, mCam) == 0x219C, "moho::WRenViewport::mCam offset must be 0x219C");
  static_assert(offsetof(WRenViewport, mFont) == 0x21A0, "moho::WRenViewport::mFont offset must be 0x21A0");
  // mFont ends at +0x21A4; the last four bytes are tail padding (nothing in the
  // binary touches +0x21A4). Shadow makes the class 8-byte aligned.
  static_assert(sizeof(WRenViewport) == 0x21A8, "moho::WRenViewport size must be 0x21A8");

  // 0x010A6428 in FA.
  extern WRenViewport* ren_Viewport;

  /**
   * Address: 0x007FA230 (FUN_007FA230)
   * Mangled: ?REN_CreateGameViewport@Moho@@YAPAVWD3DViewport@1@PAVwxWindow@@VStrArg@gpg@@ABV?$IVector2@H@Wm3@@_N@Z
   *
   * What it does:
   * `new WRenViewport(parent, title, wxSize(size.x, size.y), hasSecondHead)`.
   * The mangled size type is Wm3::IVector2<int>, which this tree spells
   * Wm3::Vector2i.
   */
  [[nodiscard]] WD3DViewport* REN_CreateGameViewport(
    wxWindow* parent, gpg::StrArg title, const Wm3::Vector2i& size, bool hasSecondHead
  );

  /**
   * Address: 0x007F6530 (FUN_007F6530)
   *
   * What it does:
   * Toggles skeleton display and forwards the new value to the sim driver's
   * sync filter, when there is one.
   */
  void REN_ShowSkeletons();

  /**
   * Address: 0x007FA170 (FUN_007FA170)
   * Mangled: ?REN_GetTerrainRes@Moho@@YAPAVIWldTerrainRes@1@XZ
   *
   * What it does:
   * Returns the loaded map's terrain resource, or null when no map is bound.
   */
  [[nodiscard]] IWldTerrainRes* REN_GetTerrainRes();
} // namespace moho
