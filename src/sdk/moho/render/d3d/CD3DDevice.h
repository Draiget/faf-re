#pragma once

#include <cstdint>

#include "boost/shared_ptr.h"
#include "moho/unit/Broadcaster.h"

struct tagRECT;
using RECT = tagRECT;

namespace boost::detail
{
  class sp_counted_base;
} // namespace boost::detail

namespace gpg::gal
{
  class CubeRenderTargetD3D9;
  class DeviceD3D9;
  class DeviceContext;
} // namespace gpg::gal

namespace Wm3
{
  template <class T>
  struct Vector2;
  using Vector2i = Vector2<int>;
} // namespace Wm3

namespace moho
{
  class CD3DDepthStencil;
  struct CD3DIndexSheetViewRuntime;
  struct CD3DVertexSheetViewRuntime;
  class CD3DDynamicTextureSheet;
  class CD3DEffect;
  class ID3DDeviceResources;
  class ID3DDepthStencil;
  class ID3DIndexSheet;
  class ID3DRenderTarget;
  class ID3DTextureSheet;
  class ID3DVertexSheet;
  struct WRenViewport;

  /**
   * What it does:
   * Carries one indexed draw view over a vertex-sheet source lane.
   */
  struct CD3DVertexSheetViewRuntime
  {
    ID3DVertexSheet* sheet = nullptr; // +0x00
    std::int32_t startVertex = 0;     // +0x04
    std::int32_t baseVertex = 0;      // +0x08
    std::int32_t endVertex = -1;      // +0x0C
  };

  static_assert(
    sizeof(CD3DVertexSheetViewRuntime) == 0x10,
    "CD3DVertexSheetViewRuntime size must be 0x10"
  );

  /**
   * What it does:
   * Carries one indexed draw view over an index-sheet source lane.
   */
  struct CD3DIndexSheetViewRuntime
  {
    ID3DIndexSheet* sheet = nullptr; // +0x00
    std::int32_t startIndex = 0;     // +0x04
    std::int32_t indexCount = 0;     // +0x08
  };

  static_assert(
    sizeof(CD3DIndexSheetViewRuntime) == 0x0C,
    "CD3DIndexSheetViewRuntime size must be 0x0C"
  );

  /**
   * VFTABLE: 0x00E02214
   * COL:     0x00E5E54C
   */
  class CD3DDevice : public Broadcaster
  {
  public:
    /**
     * Address: 0x0042DBE0 (FUN_0042DBE0)
     *
     * What it does:
     * Owns the deleting-destructor entrypoint for the D3D device wrapper.
     */
    virtual ~CD3DDevice();

    /**
     * Address: 0x0042DBF0
     * Slot: 1
     * Demangled: Moho::CD3DDevice::GetDeviceD3D9
     *
     * What it does:
     * Returns the active GAL D3D9 backend pointer when the global device is ready.
     */
    virtual gpg::gal::DeviceD3D9* GetDeviceD3D9();

    /**
     * Address: 0x0042DC10
     * Slot: 2
     * Demangled: Moho::CD3DDevice::SetRenViewport
     *
     * What it does:
     * Binds the active render viewport, rebuilds per-head writer locks and
     * default output wrappers from backend output contexts, refreshes
     * fidelity-support lanes, initializes device resources, and emits one
     * device-init event to registered listeners.
     */
    virtual void SetRenViewport(WRenViewport* viewport);

    /**
     * Address: 0x0042E9D0
     * Slot: 3
     * Demangled: Moho::CD3DDevice::GetViewport
     *
     * What it does:
     * Returns the active render viewport object.
     */
    virtual WRenViewport* GetViewport();

    /**
     * Address: 0x0042E9E0
     * Slot: 4
     * Demangled: Moho::CD3DDevice::Refresh
     *
     * What it does:
     * Refreshes device-facing state after viewport/effect changes.
     */
    virtual bool Refresh();

    /**
     * Address: 0x0042EA00 (FUN_0042EA00)
     * Slot: 5
     * Demangled: Moho::CD3DDevice::GetHeadWidth
     *
     * unsigned int
     *
     * What it does:
     * Returns one head width from the active GAL device context.
     */
    virtual int GetHeadWidth(unsigned int headIndex);

    /**
     * Address: 0x0042EA30 (FUN_0042EA30)
     * Slot: 6
     * Demangled: Moho::CD3DDevice::GetHeadHeight
     *
     * unsigned int
     *
     * What it does:
     * Returns one head height from the active GAL device context.
     */
    virtual int GetHeadHeight(unsigned int headIndex);

    /**
     * Address: 0x0042EA60 (FUN_0042EA60)
     * Slot: 7
     * Demangled: Moho::CD3DDevice::GetSize
     *
     * Wm3::Vector2i *,int
     *
     * What it does:
     * Writes one `(width,height)` pair into caller-provided output vector.
     */
    virtual Wm3::Vector2i* GetSize(Wm3::Vector2i* outSize, int headIndex);

    /**
     * Address: 0x0042EA90 (FUN_0042EA90)
     * Slot: 8
     * Demangled: Moho::CD3DDevice::GetAspectRatio
     *
     * int
     *
     * What it does:
     * Returns one head aspect ratio as `headWidth / headHeight`.
     */
    virtual double GetAspectRatio(int headIndex);

#define CD3DDEVICE_RESERVED_VFUNC(slot) virtual void VFunc##slot() = 0
    /**
     * Address: 0x0042EB40 (FUN_0042EB40)
     * Slot: 9
     * Demangled: Moho::CD3DDevice::SetCursor
     *
     * int,int,boost::shared_ptr<moho::ID3DTextureSheet>
     *
     * What it does:
     * Updates cursor hotspot/source state and forwards one cursor-context payload
     * to the active GAL backend.
     */
    virtual bool SetCursor(int hotspotX, int hotspotY, boost::shared_ptr<ID3DTextureSheet> cursorTexture);

    /**
     * Address: 0x0042EB00 (FUN_0042EB00)
     * Slot: 10
     * Demangled: Moho::CD3DDevice::ShowCursor
     *
     * bool
     *
     * What it does:
     * Shows or hides cursor through backend dispatch and updates local cursor state.
     */
    virtual int ShowCursor(bool show);
#undef CD3DDEVICE_RESERVED_VFUNC

    /**
     * Address: 0x0042ED50 (FUN_0042ED50)
     * Slot: 11
     * Demangled: Moho::CD3DDevice::GetView
     *
     * Wm3::Vector2i *,Wm3::Vector2i *,float *,float *
     *
     * What it does:
     * Reads current viewport position/size/depth range from the active GAL device.
     */
    virtual void GetView(Wm3::Vector2i* outPos, Wm3::Vector2i* outSize, float* outMinZ, float* outMaxZ);

    /**
     * Address: 0x0042EDE0 (FUN_0042EDE0)
     * Slot: 12
     * Demangled: Moho::CD3DDevice::SetViewport
     *
     * Wm3::Vector2i *,Wm3::Vector2i *,float,float
     *
     * What it does:
     * Applies one viewport payload to the active GAL device.
     */
    virtual void SetViewport(Wm3::Vector2i* pos, Wm3::Vector2i* size, float minZ, float maxZ);

    /**
     * Address: 0x0042EE70
     * Slot: 13
     * Demangled: Moho::CD3DDevice::GetResources
     */
    virtual ID3DDeviceResources* GetResources() = 0;

    /**
     * Address: 0x004310D0 (FUN_004310D0)
     * Slot: 14
     * Demangled: Moho::CD3DDevice::Func9
     *
     * boost::shared_ptr<moho::CD3DDynamicTextureSheet> &,moho::ID3DTextureSheet *,boost::detail::sp_counted_base *,int,bool
     *
     * What it does:
     * Creates one dynamic texture sheet from source texture dimensions, copies
     * source texture pixels into the destination sheet, and returns retained ownership.
     */
    virtual boost::shared_ptr<CD3DDynamicTextureSheet>& CreateDynamicTextureSheetFromSource(
      boost::shared_ptr<CD3DDynamicTextureSheet>& outSheet,
      ID3DTextureSheet* sourceTextureSheet,
      boost::detail::sp_counted_base* sourceSheetGuard,
      int format,
      bool archiveMode
    );

    /**
     * Address: 0x0042FB90 (FUN_0042FB90)
     * Slot: 15
     * Demangled: Moho::CD3DDevice::Func10
     *
     * moho::ID3DVertexSheet *,moho::ID3DIndexSheet *,D3DPRIMITIVETYPE *
     *
     * What it does:
     * Binds one vertex/index sheet pair, iterates active effect passes, and
     * submits one indexed draw context with zero start/base offsets.
     */
    virtual bool DrawIndexedSheetPrimitive(
      ID3DVertexSheet* vertexSheet, ID3DIndexSheet* indexSheet, std::int32_t* primitiveType
    );

    /**
     * Address: 0x0042FA10 (FUN_0042FA10)
     * Slot: 16
     * Demangled: Moho::CD3DDevice::Func11
     *
     * CD3DVertexSheet::View const *,CD3DIndexSheet::View const *,D3DPRIMITIVETYPE *
     *
     * What it does:
     * Submits one indexed triangle-list draw from caller-provided vertex/index
     * sheet views.
     */
    virtual bool DrawTriangleList(
      const CD3DVertexSheetViewRuntime* vertexSheetView,
      const CD3DIndexSheetViewRuntime* indexSheetView,
      std::int32_t* primitiveType
    );

    /**
     * Address: 0x0042F8D0 (FUN_0042F8D0)
     * Slot: 17
     * Demangled: Moho::CD3DDevice::Func12
     *
     * CD3DVertexSheet::View const *,D3DPRIMITIVETYPE *
     *
     * What it does:
     * Submits one non-indexed primitive draw from caller-provided vertex-sheet
     * view.
     */
    virtual bool DrawPrimitiveList(
      const CD3DVertexSheetViewRuntime* vertexSheetView, std::int32_t* primitiveType
    );

    /**
     * Address: 0x0042FCF0 (FUN_0042FCF0)
     * Slot: 18
     * Demangled: Moho::CD3DDevice::SetColorWriteState
     *
     * bool,bool
     *
     * What it does:
     * Forwards two color-write toggles into the active GAL backend lane.
     */
    virtual void SetColorWriteState(bool colorWrite0, bool colorWrite1);

    /**
     * Address: 0x0042FD40
     * Slot: 19
     * Demangled: Moho::CD3DDevice::SetCurEffect
     *
     * What it does:
     * Selects one active effect object for subsequent draw dispatch.
     */
    virtual bool SetCurEffect(CD3DEffect* effect);

    /**
     * Address: 0x0042FD10
     * Slot: 20
     * Demangled: Moho::CD3DDevice::SelectFxFile
     *
     * What it does:
     * Selects one effect file by symbolic name.
     */
    virtual bool SelectFxFile(const char* fxFileName);

    /**
     * Address: 0x0042FD60
     * Slot: 21
     * Demangled: Moho::CD3DDevice::SelectTechnique
     *
     * What it does:
     * Selects one technique from the active effect.
     */
    virtual bool SelectTechnique(const char* techniqueName);

    /**
     * Address: 0x0042FD80 (FUN_0042FD80)
     * Slot: 22
     * Demangled: Moho::CD3DDevice::GetCurEffect
     *
     * What it does:
     * Returns the currently selected effect pointer from runtime state.
     */
    virtual CD3DEffect* GetCurEffect();

    /**
     * Address: 0x0042EE80 (FUN_0042EE80)
     * Slot: 23
     * Demangled: Moho::CD3DDevice::GetWriterLock1
     *
     * boost::shared_ptr<moho::ID3DRenderTarget> &,int
     *
     * What it does:
     * Copies one retained render-target writer lock from indexed device storage.
     */
    virtual boost::shared_ptr<ID3DRenderTarget>&
      GetWriterLock1(boost::shared_ptr<ID3DRenderTarget>& outLock, int index);

    /**
     * Address: 0x0042EEB0 (FUN_0042EEB0)
     * Slot: 24
     * Demangled: Moho::CD3DDevice::GetWriterLock2
     *
     * boost::shared_ptr<moho::ID3DDepthStencil> &,int
     *
     * What it does:
     * Copies one retained depth-stencil writer lock from indexed device storage.
     */
    virtual boost::shared_ptr<ID3DDepthStencil>&
      GetWriterLock2(boost::shared_ptr<ID3DDepthStencil>& outLock, int index);

    /**
     * Address: 0x0042EEE0 (FUN_0042EEE0)
     * Slot: 25
     * Demangled: Moho::CD3DDevice::Func16
     *
     * boost::shared_ptr<void> &
     *
     * What it does:
     * Copies one retained generic shared handle from device runtime state lane #1.
     */
    virtual boost::shared_ptr<void>& Func16(boost::shared_ptr<void>& outHandle);

    /**
     * Address: 0x0042EF10 (FUN_0042EF10)
     * Slot: 26
     * Demangled: Moho::CD3DDevice::Func17
     *
     * boost::shared_ptr<void> &
     *
     * What it does:
     * Copies one retained generic shared handle from device runtime state lane #2.
     */
    virtual boost::shared_ptr<void>& Func17(boost::shared_ptr<void>& outHandle);

    /**
     * Address: 0x0042EF40 (FUN_0042EF40)
     * Slot: 27
     * Demangled: Moho::CD3DDevice::GetRenderTarget
     *
     * boost::shared_ptr<gpg::gal::CubeRenderTargetD3D9> &
     *
     * What it does:
     * Copies the active cube render-target shared handle from device state.
     */
    virtual boost::shared_ptr<gpg::gal::CubeRenderTargetD3D9>&
      GetRenderTarget(boost::shared_ptr<gpg::gal::CubeRenderTargetD3D9>& outTarget);

    /**
     * Address: 0x0042EF70 (FUN_0042EF70)
     * Slot: 28
     * Demangled: Moho::CD3DDevice::GetDepthStencil
     *
     * boost::shared_ptr<moho::CD3DDepthStencil> &
     *
     * What it does:
     * Copies the active depth-stencil shared handle from device state.
     */
    virtual boost::shared_ptr<CD3DDepthStencil>&
      GetDepthStencil(boost::shared_ptr<CD3DDepthStencil>& outDepthStencil);

    /**
     * Address: 0x0042F0C0 (FUN_0042F0C0)
     * Slot: 29
     * Demangled: Moho::CD3DDevice::BeginScene1
     *
     * moho::ID3DRenderTarget *,moho::ID3DDepthStencil *,bool,int,float,int
     *
     * What it does:
     * Binds output/depth targets, clears target lane, and begins one backend scene.
     */
    virtual void BeginScene1(
      ID3DRenderTarget* renderTarget,
      ID3DDepthStencil* depthStencil,
      bool clear,
      int color,
      float zValue,
      int stencil
    );

    /**
     * Address: 0x0042EFC0 (FUN_0042EFC0)
     * Slot: 30
     * Demangled: Moho::CD3DDevice::BeginScene2
     *
     * int,bool,int,float,int
     *
     * What it does:
     * Acquires indexed writer locks and dispatches `BeginScene1`.
     */
    virtual void BeginScene2(int index, bool clear, int color, float zValue, int stencil);

    /**
     * Address: 0x0042EFA0 (FUN_0042EFA0)
     * Slot: 31
     * Demangled: Moho::CD3DDevice::BeginScene
     *
     * What it does:
     * Begins one backend scene only when scene state is not active.
     */
    virtual void BeginScene();

    /**
     * Address: 0x0042F2A0 (FUN_0042F2A0)
     * Slot: 32
     * Demangled: Moho::CD3DDevice::SetRenderTarget1
     *
     * moho::ID3DRenderTarget *,moho::ID3DDepthStencil *,bool,int,float,int
     *
     * What it does:
     * Applies output/depth target bindings and clears backend state with one payload.
     */
    virtual void SetRenderTarget1(
      ID3DRenderTarget* renderTarget,
      ID3DDepthStencil* depthStencil,
      bool clear,
      int color,
      float zValue,
      int stencil
    );

    /**
     * Address: 0x0042F1A0 (FUN_0042F1A0)
     * Slot: 33
     * Demangled: Moho::CD3DDevice::SetRenderTarget2
     *
     * int,bool,int,float,int
     *
     * What it does:
     * Acquires indexed writer locks and dispatches `SetRenderTarget1`.
     */
    virtual void SetRenderTarget2(int index, bool clear, int color, float zValue, int stencil);

    /**
     * Address: 0x0042F360 (FUN_0042F360)
     * Slot: 34
     * Demangled: Moho::CD3DDevice::EndScene
     *
     * What it does:
     * Ends active backend scene and clears local scene-active state.
     */
    virtual void EndScene();
    /**
     * Address: 0x0042F380 (FUN_0042F380)
     * Slot: 35
     * Demangled: Moho::CD3DDevice::InitRenderEngineStats
     *
     * What it does:
     * Lazily binds render stat lanes and resets their counters.
     */
    virtual int InitRenderEngineStats();

    /**
     * Address: 0x0042F6A0 (FUN_0042F6A0)
     * Slot: 36
     * Demangled: Moho::CD3DDevice::AddPrimStats
     *
     * unsigned int,bool
     *
     * What it does:
     * Adds primitive-count stats, with optional unit-primitive lane update.
     */
    virtual int AddPrimStats(unsigned int amount, bool unitPrimitive);

    /**
     * Address: 0x0042F720 (FUN_0042F720)
     * Slot: 37
     * Demangled: Moho::CD3DDevice::AddVertexStats
     *
     * unsigned int,bool
     *
     * What it does:
     * Adds vertex-count stats, with optional unit-vertex lane update.
     */
    virtual int AddVertexStats(unsigned int amount, bool unitVertex);

    /**
     * Address: 0x0042F7A0 (FUN_0042F7A0)
     * Slot: 38
     * Demangled: Moho::CD3DDevice::AddQuadBatchCount
     *
     * unsigned int
     *
     * What it does:
     * Adds one quad-batch count delta to render stats.
     */
    virtual int AddQuadBatchCount(unsigned int amount);

    /**
     * Address: 0x0042F7E0 (FUN_0042F7E0)
     * Slot: 39
     * Demangled: Moho::CD3DDevice::AddTextBatchStats
     *
     * unsigned int
     *
     * What it does:
     * Adds one text-batch count delta to render stats.
     */
    virtual int AddTextBatchStats(unsigned int amount);

    /**
     * Address: <vslot dispatch observed in FUN_0042C3D0>
     * Slot: 40
     * Demangled: Moho::CD3DDevice::SetAntiAliasingSamples
     *
     * int sampleCount
     *
     * What it does:
     * Applies one anti-aliasing sample-count override to the active device path.
     */
    virtual void SetAntiAliasingSamples(int sampleCount);

    /**
     * Address: 0x0042E720 (FUN_0042E720)
     * Slot: 41
     * Demangled: Moho::CD3DDevice::Init
     *
     * What it does:
     * Initializes this device by forwarding the active GAL device context to
     * the virtual `InitContext` lane.
     */
    virtual void Init();

    /**
     * Address: 0x0042E1E0 (FUN_0042E1E0)
     * Slot: 42
     * Demangled: Moho::CD3DDevice::InitContext
     *
     * gpg::gal::DeviceContext *
     *
     * What it does:
     * Rebinds one GAL device-context payload and rebuilds head/render-target state.
     */
    virtual bool InitContext(gpg::gal::DeviceContext* context) = 0;

    /**
     * Address: 0x0042E750 (FUN_0042E750)
     * Slot: 43
     * Demangled: Moho::CD3DDevice::Destroy
     *
     * What it does:
     * Tears down current device-bound resources and cursor/output state.
     */
    virtual void Destroy() = 0;

    /**
     * Address: 0x0042FD90 (FUN_0042FD90)
     * Slot: 44
     * Demangled: Moho::CD3DDevice::GetCurThreadId
     *
     * What it does:
     * Returns the active backend render-thread identifier.
     */
    virtual int GetCurThreadId();

    /**
     * Address: 0x0042FE90 (FUN_0042FE90)
     * Slot: 45
     * Demangled: Moho::CD3DDevice::UpdateSurface2
     *
     * CD3DDynamicTextureSheet **,CD3DDynamicTextureSheet **
     *
     * What it does:
     * Forwards sheet handles to `UpdateSurface` with default whole-surface rectangles.
     */
    virtual void UpdateSurface2(
      CD3DDynamicTextureSheet** sourceSheet, CD3DDynamicTextureSheet** destinationSheet
    );

    /**
     * Address: 0x0042FDA0 (FUN_0042FDA0)
     * Slot: 46
     * Demangled: Moho::CD3DDevice::UpdateSurface
     *
     * CD3DDynamicTextureSheet *,CD3DDynamicTextureSheet *,RECT const *,RECT const *
     *
     * What it does:
     * Copies one source texture sheet surface region into destination texture sheet.
     */
    virtual void UpdateSurface(
      CD3DDynamicTextureSheet* sourceSheet,
      CD3DDynamicTextureSheet* destinationSheet,
      const RECT* sourceRect,
      const RECT* destinationRect
    );

    /**
     * Address: 0x0042FFA0 (FUN_0042FFA0)
     * Slot: 47
     * Demangled: Moho::CD3DDevice::SetViewRect2
     *
     * moho::ID3DRenderTarget **,moho::ID3DRenderTarget **
     *
     * What it does:
     * Dereferences render-target pointer lanes and forwards to `SetViewRect`
     * with default whole-surface rectangles.
     */
    virtual void SetViewRect2(
      ID3DRenderTarget** sourceRenderTarget, ID3DRenderTarget** destinationRenderTarget
    );

    /**
     * Address: 0x0042FEB0 (FUN_0042FEB0)
     * Slot: 48
     * Demangled: Moho::CD3DDevice::SetViewRect
     *
     * moho::ID3DRenderTarget *,moho::ID3DRenderTarget *,RECT const *,RECT const *
     *
     * What it does:
     * Copies one source render-target rectangle into one destination
     * render-target rectangle via backend `StretchRect`.
     */
    virtual void SetViewRect(
      ID3DRenderTarget* sourceRenderTarget,
      ID3DRenderTarget* destinationRenderTarget,
      const RECT* sourceRect,
      const RECT* destinationRect
    );

    /**
     * Address: 0x004300B0 (FUN_004300B0)
     * Slot: 49
     * Demangled: Moho::CD3DDevice::SetViewRenderTarget2
     *
     * moho::ID3DRenderTarget **,moho::ID3DTextureSheet **
     *
     * What it does:
     * Dereferences source/destination lanes and forwards to
     * `SetViewRenderTarget`.
     */
    virtual void SetViewRenderTarget2(
      ID3DRenderTarget** sourceRenderTarget, ID3DTextureSheet** destinationTextureSheet
    );

    /**
     * Address: 0x0042FFC0 (FUN_0042FFC0)
     * Slot: 50
     * Demangled: Moho::CD3DDevice::SetViewRenderTarget
     *
     * moho::ID3DRenderTarget *,moho::ID3DTextureSheet *
     *
     * What it does:
     * Copies one source render-target surface into one destination texture-sheet
     * via backend `CreateRenderTarget`.
     */
    virtual void SetViewRenderTarget(
      ID3DRenderTarget* sourceRenderTarget, ID3DTextureSheet* destinationTextureSheet
    );
#undef CD3DDEVICE_RESERVED_VFUNC

    /**
     * Address: 0x004300D0
     * Slot: 51
     * Demangled: Moho::CD3DDevice::Clear2
     */
    virtual bool Clear2(bool clear);

    /**
     * Address: 0x004300E0
     * Slot: 52
     * Demangled: Moho::CD3DDevice::Clear
     */
    virtual void Clear();

    /**
     * Address: 0x00430F90 (FUN_00430F90, ?Paint@CD3DDevice@Moho@@QAEXXZ)
     *
     * What it does:
     * Presents one frame and dispatches clear/render callback lanes for the
     * active viewport path.
     */
    void Paint();

    [[nodiscard]] bool IsCursorPixelSourceReady() const;
    [[nodiscard]] bool IsCursorShowing() const;
    [[nodiscard]] bool ShouldDrawViewportBackground() const;

  };

  /**
   * Address: 0x00430900 (FUN_00430900, ?D3D_Init@Moho@@YA_NXZ)
   *
   * What it does:
   * Runs render bootstrap initialization and reports success.
   */
  bool D3D_Init();

  /**
   * Address: 0x00430910 (FUN_00430910, ?D3D_Exit@Moho@@YAXXZ)
   *
   * What it does:
   * Tears down D3D singleton lanes (index sheets + world particles) and calls
   * device destroy on the global D3D device.
   */
  void D3D_Exit();

  /**
   * Address: 0x00430590 (D3D_GetDevice)
   *
   * What it does:
   * Returns the global D3D device owner used by startup/render paths.
   */
  CD3DDevice* D3D_GetDevice();

  /**
   * Address: 0x004305F0 (FUN_004305F0, ?REN_Init@Moho@@YAXXZ)
   *
   * What it does:
   * Enumerates and registers runtime font files for D3D text rendering.
   */
  void REN_Init();

  /**
   * Address: 0x007FA2C0 (FUN_007FA2C0, Moho::REN_Frame)
   *
   * int gameTick, float simDeltaSeconds, float frameSeconds
   *
   * What it does:
   * Updates render timing globals and publishes `Frame_Time` / `Frame_FPS`
   * stat counters.
   */
  void REN_Frame(int gameTick, float simDeltaSeconds, float frameSeconds);
} // namespace moho
