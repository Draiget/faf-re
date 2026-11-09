#include "moho/app/WxPrivate.h"
#include "moho/app/NetworkPanel.h"
#include "moho/render/AmbientOcclusionRenderer.h"
#include "moho/render/FxaaRenderer.h"
#include "moho/render/PostRenderer.h"
#include "moho/render/WideBloomRenderer.h"
#include "moho/sim/STIMap.h"
#include "moho/terrain/water/WaterBodySurfaces.h"

#include <array>
#include <cstdlib>

namespace
{
  /**
   * Address: 0x007FB7C0 (FUN_007FB7C0, boost::shared_ptr_IRenTerrain::operator=)
   * Address: 0x007FBA60 (FUN_007FBA60, boost::detail::shared_count_IRenTerrain::shared_count_IRenTerrain)
   *
   * What it does:
   * Rebinds one `shared_ptr<TerrainCommon>` from a raw pointer and releases
   * prior ownership. The real `boost::shared_ptr<TerrainCommon>::reset(T*)`
   * this delegates to internally constructs a fresh `shared_count(T*)`
   * control block (0x007FBA60) before releasing the old one; this single
   * call covers both.
   */
  boost::shared_ptr<moho::TerrainCommon>* AssignSharedTerrainFromRaw(
    boost::shared_ptr<moho::TerrainCommon>* const outTerrain,
    moho::TerrainCommon* const terrain
  )
  {
    outTerrain->reset(terrain);
    return outTerrain;
  }
}


// ---------------------------------------------------------------------------
// WRenViewport construction
// ---------------------------------------------------------------------------

// Table 0x00DFE950 = {&WD3DViewport::sm_eventTable (0x00DFFC84), rows
// 0x00F5AB58}; GetEventTable (0x007F6690) comes with it.
BEGIN_EVENT_TABLE(moho::WRenViewport, moho::WD3DViewport)
  EVT_ENTER_WINDOW(moho::WRenViewport::OnMouseEnter)
  EVT_LEAVE_WINDOW(moho::WRenViewport::OnMouseLeave)
END_EVENT_TABLE()

/**
 * Address: 0x007F66A0 (FUN_007F66A0)
 * Mangled: ??0WRenViewport@Moho@@QAE@PAVwxWindow@@VStrArg@gpg@@ABVwxSize@@_N@Z
 *
 * What it does:
 * The members construct in order - the bloom pair through the eh vector
 * iterator, MapImager and Silhouette inline - the screen/head block is left
 * as it is, and the head count comes from the second-head flag.
 */
moho::WRenViewport::WRenViewport(
  wxWindow* const parent,
  const gpg::StrArg title,
  const wxSize& size,
  const bool hasSecondHead
)
  : WD3DViewport(parent, title, wxDefaultPosition, size)
  , mHasSecondaryHead(hasSecondHead)
  , mSession(nullptr)
  , mCam(nullptr)
{
  mNumHeads = mHasSecondaryHead ? 2 : 1;
}

/**
 * Address: 0x007F6900 (FUN_007F6900)
 * Mangled: ??1WRenViewport@Moho@@UAE@XZ
 *
 * What it does:
 * Nothing of its own: the members go in reverse order (the font's counted
 * pointer first), then ~WD3DViewport. The deleting destructor (0x007F6890) is
 * the compiler's.
 */
moho::WRenViewport::~WRenViewport() = default;
namespace moho
{
  extern bool ren_Fx;
  extern bool ren_Terrain;
  extern bool ren_ShowSkeletons;
  extern bool ren_Water;
  extern bool ren_Reflection;
  extern bool ren_SkyDome;
  extern bool ren_Oblivion;
  extern bool ren_Bloom;
  extern bool ren_ShowNormals;
  extern bool fog_DistanceFog;
  extern float fog_OffsetMultiplier;
  extern bool ren_PlayableBoundary;
  extern bool ren_FogOfWar;

  // Save/restore triple read and cleared by WRenViewport::RenderPreviewImage
  // (0x007F7590-0x007F75FB) around the strategic-map preview render pass,
  // alongside ren_Ui/ren_Fx/fog_DistanceFog/ren_Shadows above. Defined (with
  // byte-verified defaults) in RuntimeTuningGlobals.cpp.
  extern bool ren_WorldBorder;  // 0x00F57E48 = 0x01
  extern bool ren_Select;       // 0x00F57E4C = 0x01
  extern bool ren_fog;          // 0x00F57E4D = 0x01
  extern bool ren_Shadows;      // 0x00F57E53 = 0x01
  extern float ren_ShadowCoeff;
  extern std::int32_t shadow_Fidelity;
}


/**
 * Address: 0x007F6530 (FUN_007F6530, Moho::REN_ShowSkeletons)
 *
 * What it does:
 * Toggles skeleton-debug rendering and mirrors that bool into the active
 * sim-driver sync option lane when a driver instance exists.
 */
void moho::REN_ShowSkeletons()
{
  const bool showSkeletons = !moho::ren_ShowSkeletons;
  moho::ren_ShowSkeletons = showSkeletons;

  if (ISTIDriver* const simDriver = moho::WLD_GetDriver(); simDriver != nullptr) {
    simDriver->SetSyncFilterOptionFlag(showSkeletons);
  }
}

/**
 * Address: 0x007FA170 (FUN_007FA170, ?REN_GetTerrainRes@Moho@@YAPAVIWldTerrainRes@1@XZ)
 *
 * What it does:
 * Returns the active world-map terrain resource when one is available.
 */
moho::IWldTerrainRes* moho::REN_GetTerrainRes()
{
  moho::CWldSession* const session = moho::WLD_GetActiveSession();
  if (session == nullptr || session->mWldMap == nullptr) {
    return nullptr;
  }

  return session->mWldMap->mTerrainRes;
}

/**
 * Address: 0x007FA230 (FUN_007FA230, Moho::REN_CreateGameViewport)
 * Mangled: ?REN_CreateGameViewport@Moho@@YAPAVWD3DViewport@1@PAVwxWindow@@VStrArg@gpg@@ABV?$IVector2@H@Wm3@@_N@Z
 *
 * What it does:
 * `new WRenViewport` (0x21A8 bytes) with the size copied into a wxSize.
 */
moho::WD3DViewport* moho::REN_CreateGameViewport(
  wxWindow* const parent,
  const gpg::StrArg title,
  const Wm3::Vector2i& size,
  const bool hasSecondHead
)
{
  return new WRenViewport(parent, title, wxSize(size.X(), size.Y()), hasSecondHead);
}

/**
 * Address: 0x007F65D0 (FUN_007F65D0)
 * Mangled: ?GetPreviewImage@WRenViewport@Moho@@UAE?AV?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@XZ
 *
 * What it does:
 * Returns the dynamic texture sheet RenderPreviewImage renders into (the
 * converting shared_ptr copy is the interlocked increment the binary shows).
 */
boost::shared_ptr<moho::ID3DTextureSheet> moho::WRenViewport::GetPreviewImage()
{
  return mDynamicTextureSheet;
}

/**
 * Address: 0x007F6600 (FUN_007F6600)
 * Mangled: ?GetPrimBatcher@WRenViewport@Moho@@UBEPAVCD3DPrimBatcher@2@XZ
 *
 * What it does:
 * Returns the primitive batcher.
 */
moho::CD3DPrimBatcher* moho::WRenViewport::GetPrimBatcher() const
{
  return mPrimBatcher.get();
}

/**
 * Address: 0x007F6610 (FUN_007F6610)
 * Mangled: ?OnMouseEnter@WRenViewport@Moho@@QAEXAAVwxMouseEvent@@@Z
 *
 * What it does:
 * Once the GAL device is ready, focuses the first head's window so keyboard
 * input follows the mouse into the viewport.
 */
void moho::WRenViewport::OnMouseEnter(wxMouseEvent& event)
{
  (void)event;

  if (!gpg::gal::Device::IsReady()) {
    return;
  }

  gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
  if (device == nullptr) {
    return;
  }

  gpg::gal::DeviceContext* const context = device->GetDeviceContext();
  if (context == nullptr || context->GetHeadCount() <= 0) {
    return;
  }

  const gpg::gal::Head& head = context->GetHead(0);
  if (head.mWindow != nullptr) {
    (void)::SetFocus(reinterpret_cast<HWND>(head.mWindow));
  }
}

/**
 * Address: 0x007F6640 (FUN_007F6640)
 * Mangled: ?OnMouseLeave@WRenViewport@Moho@@QAEXAAVwxMouseEvent@@@Z
 *
 * What it does:
 * Once the GAL device is ready and there is a second head, focuses that
 * head's window as the mouse leaves the viewport.
 */
void moho::WRenViewport::OnMouseLeave(wxMouseEvent& event)
{
  (void)event;

  if (!gpg::gal::Device::IsReady()) {
    return;
  }

  gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
  if (device == nullptr) {
    return;
  }

  gpg::gal::DeviceContext* const context = device->GetDeviceContext();
  if (context == nullptr || context->GetHeadCount() <= 1) {
    return;
  }

  const gpg::gal::Head& head = context->GetHead(1);
  if (head.mWindow != nullptr) {
    (void)::SetFocus(reinterpret_cast<HWND>(head.mWindow));
  }
}

/**
 * Address: 0x007F9E60 (FUN_007F9E60)
 * Mangled: ?AddWorldView@WRenViewport@Moho@@QAEXPAVIRenderWorldView@2@HH@Z
 *
 * What it does:
 * Re-adds `view` (on the active viewport, as the binary does through
 * ren_Viewport) before the first entry of greater depth, with a new terrain
 * renderer created over the loaded map's terrain.
 */
void moho::WRenViewport::AddWorldView(
  IRenderWorldView* const view,
  const int head,
  const int depth
)
{
  WRenViewport* const viewport = moho::ren_Viewport;
  viewport->RemoveWorldView(view);

  fa::vector<SWorldViewInfo>& worldViews = viewport->mWorldViews;
  SWorldViewInfo* insertPos = worldViews.begin();
  while (insertPos != worldViews.end() && depth >= insertPos->mDepth) {
    ++insertPos;
  }

  SWorldViewInfo entry{};
  entry.mView = view;
  entry.mHead = head;
  entry.mDepth = depth;
  (void)AssignSharedTerrainFromRaw(&entry.mTerrain, IRenTerrain::Create());
  if (entry.mTerrain) {
    (void)entry.mTerrain->Create(REN_GetTerrainRes());
  }

  worldViews.insert(insertPos, entry);
}

/**
 * Address: 0x007FA090 (FUN_007FA090)
 * Mangled: ?RemoveWorldView@WRenViewport@Moho@@QAEXPAVIRenderWorldView@2@@Z
 *
 * What it does:
 * Erases the first entry for `view`.
 */
void moho::WRenViewport::RemoveWorldView(IRenderWorldView* const view)
{
  for (SWorldViewInfo* it = mWorldViews.begin(); it != mWorldViews.end(); ++it) {
    if (it->mView == view) {
      mWorldViews.erase(it);
      return;
    }
  }
}
namespace
{
  /**
   * Process-static frame-dump accumulation lane.
   *
   * The binary keeps this as a raw px/pn pair at `dword_11043E8`/`dword_11043EC`
   * (VA 0x011043E8 / 0x011043EC), guarded by a one-time-init flag at
   * `dword_11043F0` that also registers an `atexit` cleanup (`sub_C042A0` =
   * FUN_00C042A0) which releases the shared count. That is exactly the
   * lifetime of a file-static `boost::shared_ptr<CD3DDynamicTextureSheet>`
   * whose destructor runs at process exit, so it is modeled as one here.
   *
   * `CD3DDevice::GetResources()->Func10(...)` (ID3DDeviceResources slot 18,
   * vtable +0x48) accumulates the current frame into this sheet, taking the
   * previous sheet as its `currentSheet` argument and returning the (possibly
   * recreated) destination that is stored back into the lane.
   */
  boost::shared_ptr<moho::CD3DDynamicTextureSheet>& RenDumpFrameSheetLane() noexcept
  {
    // Function-local static: constructed empty on first use and released once
    // at process exit, matching the binary's init-once + atexit semantics.
    static boost::shared_ptr<moho::CD3DDynamicTextureSheet> sDumpFrameSheet{};
    return sDumpFrameSheet;
  }

  // Frame-dump tuning/state globals owned by the render screenshot subsystem.
  //
  // These are the `Moho::dump_*` data globals the binary reads/writes from
  // REN_MaybeDumpFrame. No prior source declaration exists, so they are
  // modeled here at their proven types and byte-verified defaults:
  //   dump_frameRate         @ 0x010A6334 (?dump_frameRate@Moho@@3HA)          int, 0
  //   dump_outputFrameNumber @ 0x010A6418 (?dump_outputFrameNumber@Moho@@3HA)  int, 0
  //   dump_Timestamp         @ 0x00F5A8A4 (fa::string)                      empty
  //   dump_frameDumpName     @ 0x00F5A8C0 (fa::string)                      empty
  // The timestamp / base-name strings are populated by the frame-dump console
  // command elsewhere; here they are only consumed to build the output path.
}

namespace moho
{
  /**
   * Address: 0x010A6334 (?dump_frameRate@Moho@@3HA)
   *
   * Frame-dump countdown. Zero disables dumping; a positive value dumps one
   * frame per render and decrements toward zero; a negative value dumps
   * indefinitely (never decremented). Default 0 (byte-verified in .data).
   */
  int dump_frameRate = 0;

  /**
   * Address: 0x010A6418 (?dump_outputFrameNumber@Moho@@3HA)
   *
   * Monotonic index appended to each dumped frame's filename. Default 0.
   */
  int dump_outputFrameNumber = 0;

  /**
   * Address: 0x00F5A8A4 (?dump_Timestamp@Moho@@3V?$basic_string@...@std@@A)
   *
   * Timestamp token embedded in dumped frame filenames. Default empty.
   */
  fa::string dump_Timestamp{};

  /**
   * Address: 0x00F5A8C0 (?dump_frameDumpName@Moho@@3V?$basic_string@...@std@@A)
   *
   * Base directory / name prefix for dumped frame files. Default empty.
   */
  fa::string dump_frameDumpName{};

  void REN_MaybeDumpFrame(ID3DRenderTarget* renderTarget);
}


/**
 * Address: 0x007F5970 (FUN_007F5970)
 * Mangled: ?REN_MaybeDumpFrame@Moho@@YAXPAVID3DRenderTarget@1@@Z
 *
 * IDA signature:
 * void __thiscall Moho::REN_MaybeDumpFrame(Moho::CD3DRenderTarget *this);
 *   (the ecx-passed argument is the render target; the mangled symbol types it
 *    as ID3DRenderTarget*, which is used here. IDA's CD3DRenderTarget* label is
 *    a decompiler guess and the caller supplies a boost::shared_ptr
 *    <ID3DRenderTarget>::get().)
 *
 * What it does:
 * When frame dumping is armed (`dump_frameRate != 0`), decrements the positive
 * countdown, copies the current screen writer-lock surface into the supplied
 * render target, then accumulates that render target into a process-static
 * dump texture sheet via the device resources copy lane. Finally it reads the
 * accumulated sheet's texture back and saves it to a numbered `.bmp` file
 * built from the frame-dump name + timestamp, warning on save failure.
 */
void moho::REN_MaybeDumpFrame(moho::ID3DRenderTarget* const renderTarget)
{
  if (moho::dump_frameRate == 0) {
    return;
  }

  // Positive countdown consumes one frame; a negative value dumps forever.
  if (moho::dump_frameRate > 0) {
    --moho::dump_frameRate;
  }

  moho::CD3DDevice* const device = moho::D3D_GetDevice();
  gpg::gal::Device* const device9 = device->GetGalDevice();

  // Copy the current head's screen writer-lock surface into the caller's
  // render target (whole-surface StretchRect: null source/dest rectangles).
  boost::shared_ptr<moho::ID3DRenderTarget> screenLock{};
  device->GetWriterLock1(screenLock, 0);
  device->SetViewRect(screenLock.get(), renderTarget, nullptr, nullptr);

  // Accumulate the render target into the persistent dump sheet. Func10 takes
  // the previous sheet as `currentSheet` (reused/recreated as needed) and
  // returns the destination sheet, which we store back into the static lane.
  boost::shared_ptr<moho::CD3DDynamicTextureSheet>& dumpSheet = RenDumpFrameSheetLane();
  moho::ID3DDeviceResources* const resources = device->GetResources();
  resources->Func10(dumpSheet, renderTarget, dumpSheet);

  // Build the numbered output path: "<name>\SCFrame_<timestamp>_<NNNNN>.bmp".
  const int frameNumber = moho::dump_outputFrameNumber++;
  const fa::string dest = gpg::STR_Printf(
    "%s\\SCFrame_%s_%05d.bmp",
    moho::dump_frameDumpName.c_str(),
    moho::dump_Timestamp.c_str(),
    frameNumber
  );

  // Save the accumulated sheet's texture to file. The binary reads the sheet's
  // retained texture handle (ID3DTextureSheet::GetTexture) and forwards it to
  // the GAL backend's texture-save slot (Device::SaveTexture) with the default
  // image format and no in-memory output buffer. A GAL error is caught and
  // reported rather than propagated, matching the binary's inline EH funclet.
  if (device9 != nullptr) {
    boost::shared_ptr<gpg::gal::Texture> texture{};
    dumpSheet->GetTexture(texture);
    try {
      device9->SaveTexture(texture, dest, 0, nullptr);
    } catch (const std::exception& error) {
      gpg::Warnf("Error saving file %s: %s", dest.c_str(), error.what());
    }
  }
}
namespace moho
{
  // Console-tuning debug globals consumed by the render/debug HUD pass. All are
  // defined in the unrecovered console-vars TU; extern-declared here per the
  // established frontier pattern. Types byte-verified from the referencing .asm.
  extern bool ren_Ui;                        // ?ren_Ui@Moho@@3_NA (1-byte bool)
  extern bool ren_UnitSilhouette;            // ?ren_UnitSilhouette@Moho@@3_NA (1-byte bool)
  extern bool ren_ShowFrameTimes;            // ?ren_ShowFrameTimes@Moho@@3_NA
  extern bool ren_ShowNetworkStats;          // ?ren_ShowNetworkStats@Moho@@3_NA
  extern bool ren_ShowBandwidthUsage;        // ?ren_ShowBandwidthUsage@Moho@@3_NA
  extern bool UI_ShowControlUnderMouse;      // ?UI_ShowControlUnderMouse@Moho@@3_NA
  extern bool ed_EnableHook;                 // ?ed_EnableHook@Moho@@3_NA
  extern float ren_BandwidthDisplaySeconds;  // ?ren_BandwidthDisplaySeconds@Moho@@3MA
  extern float ren_BandwidthDisplayKernel;   // ?ren_BandwidthDisplayKernel@Moho@@3MA

  // ed_EnableHook (0x00F57E55) gates ED_Render at the end of RenderUI
  // (asm 0x007F89FB..0x007F8A13); RenderPreviewImage clears it while it draws.

  // Frame-driver tuning globals read by WRenViewport::D3DWindowOnDeviceRender /
  // WRenViewport::Render. Types byte-verified from the referencing .asm
  // (FUN_007F7B30 and FUN_007F90D0 all use `cmp <sym>, 0` on a 1-byte lane).
  extern bool ren_RenderNothing;   // ?ren_RenderNothing@Moho@@3_NA @0x010A6416
  extern bool ren_ShowWireframe;   // ?ren_ShowWireframe@Moho@@3_NA @0x010A641C
  extern bool ren_OnlyFirstView;   // ?ren_OnlyFirstView@Moho@@3_NA @0x010A641D

  // Sound-frame sequence counter bumped once per rendered frame by the
  // frame driver (asm 0x007F7CD7 `add snd_index, 1`). Defined in the audio TU.
  extern int snd_index;

  // Defined below, called from WRenViewport::RenderUI.
  void REN_DebugStuff(boost::shared_ptr<CD3DPrimBatcher> batcher, int head);
}

namespace
{
  // ---- func_ren_BandwidthUsage peak-scale hysteresis state ------------------
  // Power-of-two auto-range for the bandwidth graph's Y axis. The peak scale
  // only grows immediately; it decays by half at most once per second so the
  // graph does not flicker. Both live in engine .data in the shipped binary
  // (dword_F57E8C @0x00F57E8C, ren_bandwidth_time1 @0x010BF070, constructed via
  // CRT static-init) and persist across frames.
  int gRenBandwidthPeakScale = 1024;              // dword_F57E8C (shipped .data: 1024)
  gpg::time::Timer gRenBandwidthPeakScaleTimer;   // ren_bandwidth_time1

  // Round-toward-zero + carry helpers matching the binary's frndint/cmov idiom.
  // ceil form (cmova, +1 when x > trunc(x)); floor form (cmovb, -1 when
  // x < trunc(x)). Preserves the exact integer the .asm computes.
  [[nodiscard]] int RenCeilTowardZero(const float x) noexcept
  {
    const float truncated = std::trunc(x);
    return static_cast<int>(truncated) + (x > truncated ? 1 : 0);
  }
  [[nodiscard]] int RenFloorTowardZero(const float x) noexcept
  {
    const float truncated = std::trunc(x);
    return static_cast<int>(truncated) - (x < truncated ? 1 : 0);
  }

  /**
   * Address: 0x007F40D0 (FUN_007F40D0, func_ren_BandwidthUsage)
   *
   * IDA signature:
   * void __fastcall func_ren_BandwidthUsage(int@<ecx>, int@<edx>, CD3DPrimBatcher*,
   *                                         int, int);
   * (The Hex-Rays export mistypes the fourth argument as CD3DPrimBatcher*; the
   *  real batcher is the third argument, and the fourth/fifth are integer graph
   *  extents -- confirmed from the body's arg_4/arg_8/arg_C uses.)
   *
   * What it does:
   * Renders the network bandwidth-over-time debug graph for the active head:
   * a translucent backdrop quad, five Y-axis scale labels ("%5d") drawn with a
   * 10pt Courier New font, a framed grid, and two outbound/inbound line-pair
   * series (local client-manager send-stamps + connector send-stamps). The Y
   * axis auto-ranges to a power-of-two peak that grows immediately and decays by
   * half at most once per second.
   *
   * Callees invoked by name:
   *  - moho::NET_BuildBandwidthUsageSeries (x2, sub_47CC00) builds each smoothed
   *    byte-rate series from a send-stamp window.
   *  - moho::REN_DrawBandwidthUsageLinePair (x2, func_ren_BandwidthUsage_Line)
   *    strokes each series as connected outbound/inbound line strips.
   */
  void func_ren_BandwidthUsage(
    const int graphHeightBase,             // ecx0 (== headHeight/3 at the call site)
    const int graphLeftBase,               // edx0 (== headWidth - 3*headWidth/4 - 25)
    moho::CD3DPrimBatcher* const batcher,  // a3 (target of every Draw* call; `info`)
    const int graphRightExtent,            // a4  (== 3*headWidth/4)
    const int graphHalfHeight              // arg8 (== (headHeight - headHeight/3)/2)
  )
  {
    using moho::CD3DFont;
    using moho::CD3DBatchTexture;
    using moho::CD3DPrimBatcher;
    using moho::SBandwidthUsageSeries;
    using moho::SSendStampWindow;
    using moho::CClientManagerImpl;
    using moho::INetConnector;
    using moho::Vector3f;

    // 0x007F40F0: nothing to draw without an active sim driver.
    moho::ISTIDriver* const simDriver = moho::WLD_GetDriver();
    if (simDriver == nullptr) {
      return;
    }

    // 0x007F4101: client manager is the local send-stamp source.
    CClientManagerImpl* const clientMgr = simDriver->GetClientManager();

    // Three stack arguments follow the two register arguments. After the
    // prologue, +0x14C is the batcher, +0x150 is the graph width, and
    // +0x154 is its top coordinate. The coordinate adds read the latter two.
    const int rightEdgeX = graphRightExtent + graphLeftBase;
    const int graphBottomY = graphHalfHeight + graphHeightBase;

    // 0x007F411A..0x007F413C: retained 10pt Courier New font handle.
    boost::SharedPtrRaw<CD3DFont> rawFont = CD3DFont::Create(10, "Courier New");
    CD3DFont* const font = rawFont.px;

    // 0x007F414F..0x007F41B8: vertical extents from font metrics (ceil + 1).
    const int ascentCeil = RenCeilTowardZero(font->mAscent) + 1;   // v11
    const int descentCeil = RenCeilTowardZero(font->mDescent) + 1; // v14

    // 0x007F41C4..0x007F4213: horizontal room reserved for the "10000" labels.
    // GetAdvance's flags argument is the canonical whole-string form (-1).
    const int labelAdvanceCeil = RenCeilTowardZero(font->GetAdvance("10000", -1)) + 2; // v17

    // ---- Backdrop quad, asm 0x007F421B..0x007F4393. Color 0x80000000 --------
    {
      const boost::shared_ptr<CD3DBatchTexture> whiteTex = CD3DBatchTexture::FromSolidColor(0xFFFFFFFFu);
      batcher->SetTexture(whiteTex);

      constexpr std::uint32_t kBackdropColor = 0x80000000u; // 0x007F4297
      // Corner extents (cvtsi2ss lanes at 0x007F4282..0x007F42E4).
      const float xLeft = static_cast<float>(graphRightExtent); // arg_8 (a4) @0x007F42E4
      const float xRight = static_cast<float>(ascentCeil);      // var_128.y @0x007F4282
      const float yTop = static_cast<float>(graphHalfHeight);   // arg_C @0x007F4288
      const float yBottom = static_cast<float>(descentCeil);    // var_12C @0x007F4291
      const CD3DPrimBatcher::Vertex topLeft{xLeft, yTop, 0.0f, kBackdropColor, 0.0f, 0.0f};
      const CD3DPrimBatcher::Vertex topRight{xLeft, yBottom, 0.0f, kBackdropColor, 0.0f, 0.0f};
      const CD3DPrimBatcher::Vertex bottomRight{xRight, yBottom, 0.0f, kBackdropColor, 0.0f, 0.0f};
      const CD3DPrimBatcher::Vertex bottomLeft{xRight, yTop, 0.0f, kBackdropColor, 0.0f, 0.0f};
      batcher->DrawQuad(topLeft, topRight, bottomRight, bottomLeft); // 0x007F4393
    }

    // ---- Time-range parameters, asm 0x007F4398..0x007F443E. -----------------
    const int rangeSpanMs = RenFloorTowardZero(moho::ren_BandwidthDisplaySeconds * 1000.0f);    // v23
    const int windowUs = RenFloorTowardZero(moho::ren_BandwidthDisplayKernel * 1000000.0f);     // v27
    const int kernelMs = RenFloorTowardZero(moho::ren_BandwidthDisplayKernel * 1000.0f);        // v28-derived

    // 0x007F443E..0x007F4451: local send-stamp window (vtable GetBetween, slot 23).
    SSendStampWindow localStamps = clientMgr->GetBetween(rangeSpanMs + kernelMs);

    // 0x007F4453..0x007F44A1: connector send-stamp window (SnapshotSendStamps, slot 12).
    INetConnector* const connector = clientMgr->GetConnector();
    const int connectorSinceMs = rangeSpanMs + RenFloorTowardZero(moho::ren_BandwidthDisplayKernel * 1000.0f);
    SSendStampWindow connectorStamps = connector->SnapshotSendStamps(connectorSinceMs);

    // ---- Build the two smoothed byte-rate series, asm 0x007F44A3..0x007F4547.
    const int sampleCount = rangeSpanMs;                                     // v63
    const int64_t spanUs = 1000LL * static_cast<int64_t>(rangeSpanMs);       // v35

    SBandwidthUsageSeries localSeries;      // &a2
    SBandwidthUsageSeries connectorSeries;  // &v87

    const uint64_t localEndUs = localStamps.windowEndTimeUs;
    moho::NET_BuildBandwidthUsageSeries(
      localSeries, localStamps, sampleCount,
      localEndUs - static_cast<uint64_t>(spanUs), localEndUs, static_cast<uint64_t>(windowUs));

    const uint64_t connEndUs = connectorStamps.windowEndTimeUs;
    moho::NET_BuildBandwidthUsageSeries(
      connectorSeries, connectorStamps, sampleCount,
      connEndUs - static_cast<uint64_t>(spanUs), connEndUs, static_cast<uint64_t>(windowUs));

    // ---- Peak-scale auto-range (power of two), asm 0x007F454C..0x007F462C. --
    int peakScale = 128; // esi, seeded 0x80 (0x007F454C)
    if (sampleCount > 0) {
      const uint32_t columns = static_cast<uint32_t>(sampleCount);
      const uint32_t nLocal = localSeries.SampleCount();
      const uint32_t nConn = connectorSeries.SampleCount();
      for (uint32_t i = 0; i < columns; ++i) {
        // Per-column max across both series' outbound+inbound rates
        // (0x007F4572..0x007F45CD).
        float columnMax = 0.0f;
        if (i < nConn) {
          const moho::SBandwidthUsageSample& c = connectorSeries.samples[i];
          columnMax = std::max(c.outboundBytesPerSec, c.inboundBytesPerSec);
        }
        if (i < nLocal) {
          const moho::SBandwidthUsageSample& l = localSeries.samples[i];
          columnMax = std::max(columnMax, std::max(l.outboundBytesPerSec, l.inboundBytesPerSec));
        }
        const int need = RenCeilTowardZero(columnMax);
        while (peakScale < need) {
          peakScale *= 2; // 0x007F45D5
        }
      }
    }

    // Hysteresis: grow immediately; decay by half at most once per second.
    // asm 0x007F45E9..0x007F462C.
    if (peakScale >= gRenBandwidthPeakScale) {
      gRenBandwidthPeakScaleTimer.Reset();
      gRenBandwidthPeakScale = peakScale;
    } else {
      if (gRenBandwidthPeakScaleTimer.ElapsedSeconds() >= 1.0f) {
        gRenBandwidthPeakScale >>= 1; // sar dword_F57E8C, 1
        gRenBandwidthPeakScaleTimer.Reset();
      }
      peakScale = gRenBandwidthPeakScale;
    }

    // Y-axis label/grid step: peakScale / 4 (sar esi, 2 @0x007F463B).
    const int axisStep = peakScale >> 2;

    // Text glyph axes (asm 0x007F4633 flt_E4F6E8 = -1.0, 0x007F465B a7 = 1.0).
    const Vector3f textXAxis{1.0f, 0.0f, 0.0f};
    // UNRESOLVED: text yAxis lane values, asm 0x007F4633..0x007F4692. Retail
    // threads -1.0/1.0 scalars through registers into Render's axis args; the
    // exact yAxis argument lane is not provable from this frame. Using the
    // canonical down-screen row axis from the sibling DrawNetworkStats site.
    const Vector3f textYAxis{0.0f, 1.0f, 0.0f};
    // UNRESOLVED: Render glyphScale + maxAdvance scalars, asm 0x007F46EF/0x007F46F5
    // (NaN sentinels). Using quiet-NaN "natural size / no advance limit" to match
    // the sibling debug-HUD Render call sites.
    const float kNoGlyphScale = gpg::NaN;
    const float kNoMaxAdvance = gpg::NaN;

    // ---- Y-axis scale labels: 5 rows of "%5d", asm 0x007F469A..0x007F4775. --
    {
      int labelValue = 0;            // ebp (v50), steps by axisStep
      unsigned int rowYAccum = 0;    // esi (v49), steps by the row-height slot y_low
      for (int row = 0; row < 5; ++row) { // var_138 == 5
        const fa::string text = gpg::STR_Printf("%5d", labelValue); // 0x007F46B0
        // Baseline Y = (peakScale-derived base) - (rowYAccum >> 2), fild + the
        // MSVC unsigned->float fixup (0x007F46BC..0x007F46E1).
        const int rawY = static_cast<int>(gRenBandwidthPeakScale) - static_cast<int>(rowYAccum >> 2);
        const float labelY = static_cast<float>(static_cast<uint32_t>(rawY));
        // UNRESOLVED: label origin X lane, asm 0x007F4649/0x007F4732. The origin
        // X is threaded from the same register-aliased float lane as the row
        // index; not pinnable to Render's origin.x from this frame. Anchoring at
        // the reserved label gutter (graphLeftBase - labelAdvanceCeil).
        const Vector3f origin{static_cast<float>(graphLeftBase - labelAdvanceCeil), labelY, 0.0f};
        (void)font->Render(text.c_str(), batcher, origin, textXAxis, textYAxis,
                           0xFFFFFFFFu, kNoGlyphScale, kNoMaxAdvance);
        labelValue += axisStep;                               // 0x007F475F
        rowYAccum += static_cast<unsigned int>(graphHalfHeight);  // 0x007F4763 (y_low/var_D4)
      }
    }

    // ---- Grid frame + horizontal grid lines, asm 0x007F4775..0x007F4AC9. ----
    {
      const boost::shared_ptr<CD3DBatchTexture> whiteTex = CD3DBatchTexture::FromSolidColor(0xFFFFFFFFu);
      batcher->SetTexture(whiteTex); // 0x007F4799

      // UNRESOLVED: the four frame-rectangle corner scalars (v72.info,
      // v72.count.pi_, v73, v74; consumed at 0x007F47DC/0x4845/0x48B1/0x491A)
      // are read from a boost::shared_ptr storage slot reused as float scratch
      // after the label texture temp is torn down; their producing stores are the
      // heavily-aliased entry-block writes (~0x007F4410..0x007F447C) that could
      // not be pinned. Using the plainly derived plot bounds.
      const float rectLeftX = static_cast<float>(graphLeftBase - labelAdvanceCeil);  // v72.info
      const float rectRightX = static_cast<float>(rightEdgeX);                       // v72.count.pi_
      const float rectTopY = static_cast<float>(graphHeightBase - descentCeil - ascentCeil); // v73
      const float rectBottomY = static_cast<float>(graphHalfHeight);                 // v74

      constexpr std::uint32_t kLineColor = 0xFFFFFFFFu; // eax0 == -1 on every vertex
      const auto lineVertex = [](const float x, const float y) {
        return CD3DPrimBatcher::Vertex{x, y, 0.0f, kLineColor, 0.0f, 0.0f};
      };

      // Four frame edges (0x007F47DC..0x007F4981).
      batcher->DrawLine(lineVertex(rectLeftX, rectBottomY), lineVertex(rectLeftX, rectTopY));
      batcher->DrawLine(lineVertex(rectLeftX, rectTopY), lineVertex(rectRightX, rectTopY));
      batcher->DrawLine(lineVertex(rectRightX, rectTopY), lineVertex(rectRightX, rectBottomY));
      batcher->DrawLine(lineVertex(rectRightX, rectBottomY), lineVertex(rectLeftX, rectBottomY));

      // Right-inner vertical edge at graphBottomY-1 (0x007F4986..0x007F49F8).
      const float innerRightX = static_cast<float>(graphBottomY - 1);
      batcher->DrawLine(lineVertex(innerRightX, rectBottomY), lineVertex(innerRightX, rectTopY));

      // Five horizontal grid lines stepping down by the row-height slot
      // (0x007F49FD..0x007F4AC9).
      unsigned int gridYAccum = 0; // edi
      for (int g = 0; g < 5; ++g) {
        const int rawY = static_cast<int>(gRenBandwidthPeakScale) - static_cast<int>(gridYAccum >> 2);
        const float gridY = static_cast<float>(static_cast<uint32_t>(rawY));
        batcher->DrawLine(lineVertex(rectLeftX, gridY), lineVertex(innerRightX, gridY));
        gridYAccum += static_cast<unsigned int>(graphHalfHeight); // 0x007F4ABF (y_low/var_D4)
      }
    }

    // ---- The two bandwidth line-pair series, asm 0x007F4ACF..0x007F4B2A. ----
    // yScale = (row-height slot y_low) / peakScale (fild var_D4 @0x007F4ACF / fidiv var_13C
    // @0x007F4AE0). The per-sample color mapping is verified from the callee
    // (func_ren_BandwidthUsage_Line): x0 (ebx) colors the inbound lane, x1 the
    // outbound lane.
    const float yScale = static_cast<float>(graphHalfHeight) / static_cast<float>(peakScale);

    // xOffset (a4) = var_130 = graphRightExtent + graphHeightBase (asm 0x007F411B
    // / 0x007F4AD6), i.e. graphBottomY. yBase (a5) = var_100.mColor (asm
    // 0x007F4AE4).
    const std::int32_t seriesXOffset = graphBottomY; // var_130

    // UNRESOLVED: line-pair yBase (a5 = var_100.mColor, asm 0x007F42AE seeded as
    // the quad color 0x80000000 then reinterpreted as an int screen-Y baseline;
    // the producing store of its final value is aliased and could not be pinned).
    // Using the plot bottom baseline (graphHalfHeight) as the best-evidence screen Y.
    const std::int32_t seriesYBase = graphHalfHeight;

    // Local series: inbound 0xFF0000FF (x0/ebx @0x007F4AE8), outbound 0xFFFF0000
    // (x1 @0x007F4ADA).
    moho::REN_DrawBandwidthUsageLinePair(
      *batcher, localSeries,
      /*xOffset=*/ seriesXOffset,
      /*yBase=*/ seriesYBase,
      /*yScale=*/ yScale,
      /*inboundColor=*/ 0xFF0000FFu,
      /*outboundColor=*/ 0xFFFF0000u);

    // Connector series: inbound 0xFF8080FF (x0/ebx @0x007F4B1E), outbound
    // 0xFFFF8080 (x1 @0x007F4B0E).
    moho::REN_DrawBandwidthUsageLinePair(
      *batcher, connectorSeries,
      /*xOffset=*/ seriesXOffset,
      /*yBase=*/ seriesYBase,
      /*yScale=*/ yScale,
      /*inboundColor=*/ 0xFF8080FFu,
      /*outboundColor=*/ 0xFFFF8080u);

    // ---- Teardown, asm 0x007F4B2F..0x007F4BE9. localSeries/connectorSeries and
    // the two send-stamp views destruct here; release the retained font handle.
    rawFont.release();
  }
}


/**
 * Address: 0x007FA730 (FUN_007FA730, Moho::REN_DebugStuff)
 * Mangled: ?REN_DebugStuff@Moho@@YAXV?$shared_ptr@VCD3DPrimBatcher@Moho@@@boost@@H@Z
 *
 * IDA signature:
 * void __usercall Moho::REN_DebugStuff(boost::shared_ptr<CD3DPrimBatcher> batcher,
 *                                      int head@<ecx>);
 *
 * What it does:
 * Draws the per-frame debug overlays for one head, gated by console flags:
 * frame-time bars (ren_ShowFrameTimes), the network-stats HUD
 * (ren_ShowNetworkStats), the bandwidth graph (ren_ShowBandwidthUsage), and the
 * control-under-mouse highlight (UI_ShowControlUnderMouse). Sets up a
 * screen-space orthographic projection on the prim batcher, renders every armed
 * overlay, then flushes. A no-op when every flag is clear.
 */
void moho::REN_DebugStuff(boost::shared_ptr<CD3DPrimBatcher> batcher, const int head)
{
  // 0x007FA756..0x007FA778: bail (releasing the batcher) when nothing is armed.
  // Engine addition (issue #322): the network panel is one more overlay.
  if (!moho::ren_ShowFrameTimes && !moho::ren_ShowNetworkStats
      && !moho::ren_ShowBandwidthUsage && !moho::UI_ShowControlUnderMouse && !moho::net_ShowPanel) {
    return; // batcher shared_ptr destructs here (asm 0x007FA77A..0x007FA786)
  }

  CD3DPrimBatcher* const primBatcher = batcher.get();

  // 0x007FA79E..0x007FA7BF: select the primbatcher effect + alpha technique.
  CD3DDevice* device = moho::D3D_GetDevice();
  device->SelectFxFile("primbatcher");
  device->SelectTechnique("TAlphaBlendLinearSampleNoDepth");

  // 0x007FA7C1..0x007FA7C5: clear the batcher's composite-rebuild flag (+0x11D)
  // so the screen-space HUD pass reuses the freshly set projection/view.
  primBatcher->mRebuildComposite = 0;

  // 0x007FA7CC..0x007FA7EA: active head pixel dimensions.
  const int headWidth = moho::D3D_GetDevice()->GetHeadWidth(head);   // v6
  const int headHeight = moho::D3D_GetDevice()->GetHeadHeight(head); // v8
  const float widthF = static_cast<float>(headWidth);
  const float heightF = static_cast<float>(headHeight);

  // 0x007FA7EC..0x007FA8D2: screen-space orthographic projection (row-major).
  // Constants byte-verified from ForgedAlliance.exe: 2.0, -0.5, 0.5, 1.0.
  VMatrix4 projection{};
  projection.r[0] = {2.0f / widthF, 0.0f, 0.0f, 0.0f};
  projection.r[1] = {0.0f, 2.0f / (-0.0f - heightF), 0.0f, 0.0f};
  projection.r[2] = {0.0f, 0.0f, -0.5f, 0.0f};
  projection.r[3] = {
    (widthF / (-0.0f - widthF)) - (1.0f / widthF),
    (heightF / heightF) + (1.0f / heightF),
    0.5f,
    1.0f
  };
  primBatcher->SetProjectionMatrix(projection);      // 0x007FA8D2
  primBatcher->SetViewMatrix(VMatrix4::Identity());  // 0x007FA8DE (sIdentity)

  // 0x007FA8E3..0x007FA93E: frame-time bars over the top-left quadrant.
  if (moho::ren_ShowFrameTimes) {
    moho::TIME_RenderTimeBars(
      primBatcher, widthF * 0.25f, heightF * 0.25f, widthF * 0.5f, heightF * 0.5f);
  }

  // 0x007FA941..0x007FA982: network-stats HUD, right-anchored.
  if (moho::ren_ShowNetworkStats) {
    // Engine addition: only the lockstep driver has these stats; a server-mode game shows its bytes by lane
    // instead (plan WP10.10).
    if (CSimDriver* const simDriver = dynamic_cast<CSimDriver*>(moho::WLD_GetDriver())) {
      simDriver->DrawNetworkStats(primBatcher, static_cast<float>(headWidth - 25), 25.0f, 1.0f, 0.0f);
    } else {
      moho::NETPANEL_DrawServerLanes(primBatcher, static_cast<float>(headWidth - 25), 25.0f);
    }
  }

  // 0x007FA984..0x007FA9C1: bandwidth-over-time graph. Argument arithmetic
  // transcribed from 0x007FA98D..0x007FA9BC (__fastcall: ecx, edx, then stack
  // args pushed right-to-left ebx=batcher, edi, eax):
  //   graphHeightBase (ecx) = headHeight / 3
  //   graphLeftBase   (edx) = headWidth - 3*headWidth/4 - 25
  //   batcher         (a3)  = primBatcher (ebx)
  //   graphRightExtent (a4) = 3*headWidth/4 (edi)
  //   graphHalfHeight  (arg8) = (headHeight - headHeight/3) / 2 (eax)
  if (moho::ren_ShowBandwidthUsage) {
    const int threeQuarterWidth = 3 * headWidth / 4; // edi (sar 2 of esi+esi*2)
    func_ren_BandwidthUsage(
      /*graphHeightBase=*/  headHeight / 3,
      /*graphLeftBase=*/    headWidth - threeQuarterWidth - 25,
      /*batcher=*/          primBatcher,
      /*graphRightExtent=*/ threeQuarterWidth,
      /*graphHalfHeight=*/  (headHeight - headHeight / 3) / 2);
  }

  // 0x007FA9C4..0x007FA9EB: control-under-mouse debug highlight.
  if (moho::UI_ShowControlUnderMouse) {
    moho::IUIManager* const uiManager = moho::UI_GetManager();
    if (uiManager != nullptr && uiManager->HasFrames()) {
      uiManager->DebugMouseOverControl(primBatcher);
    }
  }

  // Engine addition (issue #322): the network panel, last so it is on top.
  moho::NETPANEL_Draw(primBatcher, widthF, heightF);

  // 0x007FA9ED..0x007FA9F3: flush the accumulated debug geometry.
  primBatcher->Flush();
  // batcher shared_ptr destructs here (asm 0x007FA9FB..0x007FAA2D).
}
namespace
{
  /// The current profile's ui_scale option, as SimDriverNetworkStats.cpp reads it;
  /// 1.0 when it is unset or not a number.
  [[nodiscard]] float BuildLabelUiScale()
  {
    moho::IUserPrefs* const prefs = moho::USER_GetPreferences();
    if (prefs == nullptr) {
      return 1.0f;
    }
    const std::lock_guard<std::recursive_mutex> lock(moho::USER_PreferencesLock()); // #247
    const LuaPlus::LuaObject value = prefs->LookupCurrentOption("ui_scale");
    if (!value.IsNumber()) {
      return 1.0f;
    }
    return std::clamp(static_cast<float>(value.GetNumber()), 0.5f, 4.0f);
  }

  /**
   * Engine addition (issue #215): gpg::diag::BuildLabel ("FAF-RE, Draiget & contributors,
   * build <version or commit> <arch>") in small gray text, centred at the bottom of the first head, while
   * the lobby screen is up (a CLobby exists and no game session runs). In a game the
   * same line heads the network-stats panel (F11) instead. The engine draws it after the UI, from
   * the commit compiled into the exe, so no Lua code can change or hide it; there is
   * deliberately no console variable for it either, since Lua can set those.
   */
  void DrawLobbyBuildLabel(moho::CD3DPrimBatcher* const primBatcher, const int head)
  {
    if (head != 0 || !moho::LOBBY_IsActive() || moho::WLD_GetActiveSession() != nullptr) {
      return;
    }

    const char* const label = gpg::diag::BuildLabel();
    const float uiScale = BuildLabelUiScale();
    const int fontPoints = std::max(1, static_cast<int>(std::lround(9.0f * uiScale)));
    boost::SharedPtrRaw<moho::CD3DFont> rawFont = moho::CD3DFont::Create(fontPoints, "Arial");
    moho::CD3DFont* const font = rawFont.px;
    if (font == nullptr) {
      return;
    }

    moho::CD3DDevice* const device = moho::D3D_GetDevice();
    device->SelectFxFile("primbatcher");
    device->SelectTechnique("TAlphaBlendLinearSampleNoDepth");
    primBatcher->mRebuildComposite = 0;

    // The screen-space projection REN_DebugStuff sets: pixels, origin top left.
    const float widthF = static_cast<float>(device->GetHeadWidth(head));
    const float heightF = static_cast<float>(device->GetHeadHeight(head));
    moho::VMatrix4 projection{};
    projection.r[0] = {2.0f / widthF, 0.0f, 0.0f, 0.0f};
    projection.r[1] = {0.0f, 2.0f / (-0.0f - heightF), 0.0f, 0.0f};
    projection.r[2] = {0.0f, 0.0f, -0.5f, 0.0f};
    projection.r[3] = {(widthF / (-0.0f - widthF)) - (1.0f / widthF), (heightF / heightF) + (1.0f / heightF), 0.5f, 1.0f};
    primBatcher->SetProjectionMatrix(projection);
    primBatcher->SetViewMatrix(moho::VMatrix4::Identity());

    // Baseline 4 px (scaled) above the bottom edge, below the descenders.
    const float advance = font->GetAdvance(label, -1);
    const float descent = font->mHeight - font->mAscent;
    const moho::Vector3f origin{
      std::floor((widthF - advance) * 0.5f), std::floor(heightF - descent - 4.0f * uiScale), 0.0f};
    const moho::Vector3f xAxis{1.0f, 0.0f, 0.0f};
    const moho::Vector3f yAxis{0.0f, -1.0f, 0.0f};
    constexpr std::uint32_t kGray = 0xB0A0A0A0u; // ARGB: light gray, partly transparent
    (void)font->Render(label, primBatcher, origin, xAxis, yAxis, kGray, 0.0f, gpg::NaN);

    primBatcher->Flush();
    rawFont.release();
  }
}


/**
 * Address: 0x007F88B0 (FUN_007F88B0)
 * Mangled: ?RenderUI@WRenViewport@Moho@@AAEXABV?$vector@USWorldViewInfo@Moho@@V?$allocator@USWorldViewInfo@Moho@@@std@@@std@@@Z
 *
 * What it does:
 * The UI and debug-HUD pass for the active head: binds the head's target,
 * lets each world view's terrain draw its dirty regions through the prim
 * batcher, resets the viewport to the full head, draws the UI head when
 * ren_Ui is set, then the debug overlays (REN_DebugStuff) and the editor
 * render hook.
 */
void moho::WRenViewport::RenderUI(const fa::vector<SWorldViewInfo>& worldViews)
{
  // 0x007F88CA..0x007F88FD: bind the head render target, disable secondary
  // color write.
  CD3DDevice* const device = D3D_GetDevice();
  device->SetRenderTarget2(mHead, false, 0, 1.0f, 0);
  device->SetColorWriteState(true, false);

  CD3DPrimBatcher* const primBatcher = mPrimBatcher.get();

  // 0x007F88FF..0x007F8927: TerrainCommon slot 14 (DrawDirtyTerrain) on each
  // view's terrain, through the shared prim batcher.
  for (const SWorldViewInfo& worldView : worldViews) {
    if (TerrainCommon* const terrain = worldView.mTerrain.get(); terrain != nullptr) {
      terrain->DrawDirtyTerrain(primBatcher);
    }
  }

  // 0x007F8929..0x007F898C: reset the viewport to the full-screen extent,
  // origin (0,0).
  Wm3::Vector2i viewportOrigin{0, 0};
  D3D_GetDevice()->SetViewport(&viewportOrigin, &mFullScreen, 0.0f, 1.0f);
  device->SetColorWriteState(true, false); // 0x007F898E..0x007F8999

  // 0x007F899B..0x007F89C1: draw the UI head when the UI is enabled.
  if (ren_Ui) {
    if (IUIManager* const uiManager = UI_GetManager()) {
      uiManager->DrawHead(mHead, primBatcher);
    }
  }

  // 0x007F89C3..0x007F89F8: debug overlays, handed a copy of the batcher.
  REN_DebugStuff(mPrimBatcher, mHead);

  // Engine addition (issue #215): the lobby's build label.
  DrawLobbyBuildLabel(primBatcher, mHead);

  // 0x007F89FB..0x007F8A13: editor render hook. ED_Render (0x007B6450) is
  // inlined here by LTCG: `mov ecx,[ed_Hook]; cmp ecx,esi; ...; call [vtbl+4]`.
  if (ed_EnableHook) {
    ED_Render();
  }
}
namespace
{
  /**
   * Intersects one camera ray with the horizontal cartographic ground plane
   * `y = groundY` and returns the world-space hit point, or a NaN sentinel
   * when the ray is parallel to the plane or the hit falls outside the ray's
   * valid `[closest, farthest]` extent.
   *
   * Inlined four times (once per NDC screen corner) into the shipped
   * `RenderCameraOutline` body (0x007F98A0..0x007F9E5E). The binary's own
   * denominator/numerator expressions carry dead `* 0.0` terms for the
   * plane's zero-valued x/z normal components - the cartographic ground
   * plane is always horizontal (normal = (0,1,0)) - which this helper folds
   * away rather than reproducing as decompiler-shaped arithmetic. The NaN
   * sentinel matches the binary's lazily-initialized `invalid_vec` (a
   * function-local `static const` here is equivalent and simpler than the
   * binary's explicit `invalid_vec_static_guard` byte).
   */
  [[nodiscard]] Wm3::Vec3f IntersectCameraRayWithGroundPlane(const moho::GeomLine3& ray, const float groundY) noexcept
  {
    static const Wm3::Vec3f kInvalidVec{
      std::numeric_limits<float>::quiet_NaN(),
      std::numeric_limits<float>::quiet_NaN(),
      std::numeric_limits<float>::quiet_NaN()
    };

    if (ray.dir.y == 0.0f) {
      return kInvalidVec;
    }

    const float t = (groundY - ray.pos.y) / ray.dir.y;
    if (t < ray.closest || t > ray.farthest) {
      return kInvalidVec;
    }

    return Wm3::Vec3f{
      ray.pos.x + (ray.dir.x * t),
      ray.pos.y + (ray.dir.y * t),
      ray.pos.z + (ray.dir.z * t)
    };
  }
}


/**
 * Address: 0x007F98A0 (FUN_007F98A0)
 * Mangled: ?RenderCameraOutline@WRenViewport@Moho@@AAEXPBVGeomCamera3@2@M_N@Z
 *
 * IDA signature:
 * void __thiscall Moho::WRenViewport::RenderCameraOutline(
 *     Moho::WRenViewport* this, const Moho::GeomCamera3* camera, float groundY, bool useFocusedColor);
 *
 * What it does:
 * Draws one four-line picture-in-picture frustum outline for `camera` onto
 * the cartographic terrain, at cartographic ground height `groundY`. Each of
 * the four NDC screen corners (0,0)/(1,0)/(1,1)/(0,1) is unprojected through
 * `camera` and intersected with the horizontal plane `y = groundY`; a corner
 * whose ray is parallel to the plane or whose hit falls outside the ray's
 * valid range degenerates to a NaN vertex. The outline uses the `"TYellow"`
 * technique when `useFocusedColor` is set, `"TRed"` otherwise, drawn as four
 * solid-red lines (`0xFFFF0000`) through the shared prim batcher. Its one
 * caller is RenderCartographic (0x007F8FE2).
 */
void moho::WRenViewport::RenderCameraOutline(
  const GeomCamera3* const camera,
  const float groundY,
  const bool useFocusedColor
)
{
  if (camera == nullptr) {
    return;
  }

  CD3DPrimBatcher* const primBatcher = mPrimBatcher.get();

  primBatcher->Setup(useFocusedColor ? "TYellow" : "TRed");
  primBatcher->SetTexture(CD3DBatchTexture::FromSolidColor(0xFFFF0000u));
  primBatcher->SetProjectionMatrix(mCam->projection);
  primBatcher->SetViewMatrix(mCam->view);

  const Wm3::Vector2f kNdcCorners[4] = {
    Wm3::Vector2f{0.0f, 0.0f},
    Wm3::Vector2f{1.0f, 0.0f},
    Wm3::Vector2f{1.0f, 1.0f},
    Wm3::Vector2f{0.0f, 1.0f}
  };

  CD3DPrimBatcher::Vertex corners[4];
  for (int cornerIndex = 0; cornerIndex < 4; ++cornerIndex) {
    // The unit rectangle, not the camera's own viewport: 0x007F99A5 zeroes
    // xmm1 (x0) and xmm4 (y0) and loads 1.0f into xmm2 (x1) and xmm5 (y1), so
    // the four corner literals above ARE normalised device coordinates. Going
    // through the camera-viewport wrapper instead mapped all four of them to
    // within one pixel of the view's top-left corner, collapsing the outline
    // to a point and leaving the minimap with no camera-frustum indicator.
    const GeomLine3 ray = camera->Unproject(kNdcCorners[cornerIndex], 0.0f, 1.0f, 0.0f, 1.0f);
    const Wm3::Vec3f hit = IntersectCameraRayWithGroundPlane(ray, groundY);
    corners[cornerIndex] = CD3DPrimBatcher::Vertex{hit.x, hit.y, hit.z, 0xFFFFFFFFu, 0.0f, 0.0f};
  }

  primBatcher->DrawLine(corners[0], corners[1]);
  primBatcher->DrawLine(corners[1], corners[2]);
  primBatcher->DrawLine(corners[2], corners[3]);
  primBatcher->DrawLine(corners[3], corners[0]);
  primBatcher->Flush();
}

/**
 * Address: 0x007F8BA0 (FUN_007F8BA0, 0x007F8BA0..0x007F90C4)
 * Mangled: ?RenderCartographic@WRenViewport@Moho@@AAEIHAAV?$vector@USWorldViewInfo@Moho@@V?$allocator@USWorldViewInfo@Moho@@@std@@@std@@@Z
 *
 * The shipped body is `retn 0Ch`: LTCG moved `this` onto the stack next to
 * `head` and the vector (the one call site, WRenViewport::Render
 * 0x007F97AF..0x007F97B2, pushes the three) and passes a dead DeviceD3D9* in
 * edi. The vector is read at +4/+8 only - its first and last element
 * pointers, past fa::vector's leading proxy word.
 *
 * What it does:
 * Renders the cartographic ("strategic"/top-down) view for every world-view
 * entry that targets `head`. Bails out early (returns 0) when there is no
 * active world map/terrain, or when none of the head's world-view entries
 * currently have the optional-feature flag off and shaking enabled
 * (`!Func2() && CanShake()`). Lazily initializes the terrain's
 * `Cartographic` runtime on first use, then for each qualifying world-view
 * entry: acquires this head's colour and depth-stencil render-target
 * surfaces and a copy of the viewport's shared prim batcher, and calls
 * `Cartographic::Render` to paint the terrain/mesh/decal/UI cartographic
 * pass into them. When the entry reports `IsMiniMap()`, additionally
 * restores the device viewport to the entry's own camera rect and overlays
 * every other same-head world-view's camera frustum outline
 * (`REN_RenderCameraOutline`) as a picture-in-picture indicator.
 *
 * Evidence for the ambiguous per-element loop (0x007F8BE7..0x007F8C38 and
 * 0x007F8CD0..0x007F8E94): Hex-Rays types the walked collection's element
 * pointer as `Moho::CD3DVertexSheet*`/`Moho::VisionRenderer*` purely from a
 * coincidental cast chain (`v12->__vftable` re-read as if `__vftable` were a
 * field of an object, rather than the object's own vtable pointer value).
 * That cannot be right: the calls dispatch at vtable offsets
 * +0x10/+0x24/+0x28/+0x30 (slots 4/9/10/12), one slot beyond
 * `ID3DVertexSheet`'s entire 10-slot vtable (max offset 0x24, `Func9`) -
 * `CD3DVertexSheet` has no slot 12 to call. Those four offsets instead match
 * `Moho::IRenderWorldView` exactly: slot 4 = `GetCameraView()` (its return
 * value is read at +0x2B4/+0x2B8/+0x2BC/+0x2C0, which is
 * `GeomCamera3::viewport.r[3]` = {X,Y,Width,Height} - confirmed by the
 * pre-existing `MakeViewportPixelProjection` helper in `GeomCamera3.h`
 * reading the same `viewport.r[3].z/.w` lanes), slot 9 = `Func2()`, slot 10 =
 * `IsMiniMap()`, slot 12 = `CanShake()`. The walked collection is therefore
 * SWorldViewInfo (`sizeof == 0x14`, the view at +0x00), the record RenderUI
 * walks too.
 *
 * The `_InterlockedExchangeAdd` pairs the decompiler shows around the
 * render-target/prim-batcher locals (0x007F8D62..0x007F8E7C) are the
 * compiler inlining `boost::shared_ptr` copy-construction/destruction for
 * the by-value `colorTarget`/`depthStencilTarget`/`primBatcher` parameters
 * of `Cartographic::Render` - ordinary `boost::shared_ptr` locals below
 * reproduce the same refcounting without hand-written atomics.
 *
 * Self-exclusion note (0x007F8FB6 `cmp esi, [var_58]`, inside the
 * `IsMiniMap()` outline-scan loop): `var_58`'s exact register provenance
 * could not be pinned down byte-for-byte across the large intervening
 * `Cartographic::Render` call and shared_ptr cleanup sequence. Excluding the
 * world-view currently being rendered from its own outline scan is the only
 * reading consistent with a picture-in-picture overlay - it must never draw
 * its own camera's outline into its own cartographic pass - so that is what
 * this recovery implements.
 */
unsigned int moho::WRenViewport::RenderCartographic(
  const int head,
  fa::vector<SWorldViewInfo>& worldViews
)
{
  IWldTerrainRes* const terrain = moho::REN_GetTerrainRes();
  if (terrain == nullptr) {
    return 0;
  }

  bool anyRenderable = false;
  for (const SWorldViewInfo* entry = worldViews.begin(); entry != worldViews.end(); ++entry) {
    if (!entry->mView->Func2() && entry->mView->CanShake()) {
      anyRenderable = true;
      break;
    }
  }
  if (!anyRenderable) {
    return 0;
  }

  moho::Cartographic& cartographic = terrain->GetCartographic();
  // Engine addition (water bodies): built again once the session has installed the map's bodies.
  if (!cartographic.IsInitialized() || (terrain->mMap != nullptr && moho::CartographicWaterBodiesStale(*terrain->mMap))) {
    // The five hypsometric-color lanes the mangled Initialize() declares are
    // never read by its shipped body (it re-reads them off the terrain
    // itself) - see Cartographic::Initialize's own doc comment.
    cartographic.Initialize(terrain, 0, 0, 0, 0, 0);
  }

  gpg::gal::Device* const galInstance = gpg::gal::Device::GetInstance();
  gpg::gal::DeviceContext* const deviceContext = galInstance->GetDeviceContext();
  (void)deviceContext->GetHead(static_cast<std::uint32_t>(head)); // result unused, matches the binary

  // 0x007F8C74 `mov eax,[edi+4]` is `IWldTerrainRes::mMap`, read only to gate
  // the playable-boundary renderer on the terrain having map data.
  BoundaryRenderer* const boundaryRenderer =
    (moho::ren_PlayableBoundary && terrain->mMap != nullptr) ? &mBoundaryRenderer : nullptr;

  moho::CWldSession* const activeSession = moho::WLD_GetActiveSession();
  VisionRenderer* const visionRenderer =
    (moho::ren_FogOfWar && activeSession != nullptr && activeSession->FocusArmy != -1)
      ? &mVisionRenderer
      : nullptr;

  unsigned int outlineDrawCount = 0;

  for (const SWorldViewInfo* entry = worldViews.begin(); entry != worldViews.end(); ++entry) {
    IRenderWorldView* const worldView = entry->mView;
    GeomCamera3* const cameraView = worldView->GetCameraView();

    if (entry->mHead != head || worldView->Func2() || !worldView->CanShake()) {
      continue;
    }

    ID3DRenderTarget::SurfaceHandle colorTarget;
    mPrimaryTargetLocks[head]->GetSurface(colorTarget);
    ID3DDepthStencil::SurfaceHandle depthStencilTarget;
    mDepthStencilLocks[head]->GetSurface(depthStencilTarget);

    cartographic.Render(
      static_cast<unsigned int>(head),
      moho::REN_GetGameTick(),
      moho::REN_GetSimDeltaSeconds(),
      worldView,
      &mRangeRenderer,
      visionRenderer,
      boundaryRenderer,
      colorTarget,
      depthStencilTarget,
      mPrimBatcher
    );

    if (!worldView->IsMiniMap()) {
      continue;
    }

    mCam = cameraView;

    D3DVIEWPORT9 restoredViewport{};
    restoredViewport.X = static_cast<DWORD>(cameraView->viewport.r[3].x);
    restoredViewport.Y = static_cast<DWORD>(cameraView->viewport.r[3].y);
    restoredViewport.Width = static_cast<DWORD>(cameraView->viewport.r[3].z);
    restoredViewport.Height = static_cast<DWORD>(cameraView->viewport.r[3].w);
    restoredViewport.MinZ = 0.0f;
    restoredViewport.MaxZ = 1.0f;
    galInstance->SetViewport(&restoredViewport);

    for (const SWorldViewInfo* other = worldViews.begin(); other != worldViews.end(); ++other) {
      if (other->mHead != head || other->mView->Func2() || other == entry) {
        continue;
      }

      const float groundY = other->mView->GetCameraOffset()->y;
      GeomCamera3* const otherCamera = other->mView->GetCameraView();
      RenderCameraOutline(otherCamera, groundY, head == 0);
      ++outlineDrawCount;
    }

    mCam = nullptr;
  }

  return outlineDrawCount;
}
namespace
{
  // ---- WRenViewport frame-driver state --------------------------------------
  // Both persist across frames in the shipped binary:
  //   render_lock                  @0x010C7768 (1-byte re-entrancy guard)
  //   sEngineStat_Render_UnitCount @0x010C776C (lazily-bound StatItem*)
  // The guard is a plain byte, not an interlocked flag - a paint that arrives
  // while a frame is already in flight is dropped, not queued.
  bool gRenderLock = false;
  moho::StatItem* gEngineStatRenderUnitCount = nullptr;

  /**
   * Lazily binds the `Render_UnitCount` engine stat and atomically zeroes its
   * counter. The binary emits this inline in D3DWindowOnDeviceRender as a
   * lazy GetItem("Render_UnitCount", true) + Release(0) followed by the
   * double-`lock cmpxchg` read-then-store idiom at 0x007F7BB0..0x007F7BC7.
   */
  void ResetRenderUnitCountStat()
  {
    if (gEngineStatRenderUnitCount == nullptr) {
      if (moho::EngineStats* const stats = moho::GetEngineStats(); stats != nullptr) {
        gEngineStatRenderUnitCount = stats->GetItem2("Render_UnitCount");
        if (gEngineStatRenderUnitCount != nullptr) {
          (void)gEngineStatRenderUnitCount->Release(0);
        }
      }
    }

    if (gEngineStatRenderUnitCount == nullptr) {
      return;
    }

    gEngineStatRenderUnitCount->StorePrimaryBits(0);
  }
  // Resource parameters WRenViewport::D3DWindowOnDeviceInit (0x007F6B60) builds
  // its device-dependent objects with.
  constexpr std::int32_t kViewportDebugFontPointSize = 12;
  constexpr const char* kViewportDebugFontFace = "Courier New";
  constexpr int kViewportDynamicSheetExtent = 256;
  constexpr int kViewportDynamicSheetFormat = 2;
  constexpr int kViewportHeadTargetFormat = 2;
  constexpr int kViewportHeadDepthStencilFormat = 3;
}


/**
 * Address: 0x007F6B60 (FUN_007F6B60, Moho::WRenViewport::D3DWindowOnDeviceInit)
 * Mangled: ?D3DWindowOnDeviceInit@WRenViewport@Moho@@UAEX_N@Z
 *
 * IDA signature:
 * int __thiscall Moho::WRenViewport::D3DWindowOnDeviceInit(
 *     Moho::WRenViewport *this, bool a2);
 *
 * What it does:
 * Creates every device-dependent resource the viewport renders through. See
 * the declaration for how `createBatchers` splits the first-bind path from the
 * device-rebind path.
 */
void moho::WRenViewport::D3DWindowOnDeviceInit(const bool createBatchers)
{
  moho::snd_index = 0;

  if (createBatchers) {
    mTexBatcher.reset(new moho::CD3DTextureBatcher());
    mPrimBatcher.reset(new moho::CD3DPrimBatcher(mTexBatcher.get()));

    // mFont = CD3DFont::Create(12, "Courier New"): the binary's Create returns
    // a CountedPtr that already owns one reference; the assignment takes
    // mFont's own and the temporary's destructor drops the returned one. This
    // tree's Create hands back a raw handle instead, so the returned reference
    // is adopted into a CountedPtr to give it the same lifetime. (An earlier
    // revision dropped it with CD3DFont::Release(1), which is the deleting
    // destructor, not a release - mFont was left dangling.)
    const boost::SharedPtrRaw<moho::CD3DFont> fontHandle =
      moho::CD3DFont::Create(kViewportDebugFontPointSize, kViewportDebugFontFace);
    CountedPtr<CD3DFont> createdFont;
    createdFont.tex = fontHandle.px;
    mFont = createdFont;
  }

  mRangeRenderer.Init();
  mVisionRenderer.Init();
  mBoundaryRenderer.Init();
  // Fidelity 0: the shadow renderer starts with its settings latched but no
  // targets allocated. WRenViewport::RenderShadows re-inits it at the real
  // fidelity once it knows what the frame needs.
  (void)mShadowRenderer.Init(0);
  mSilhouetteRenderer.Init();
  moho::MeshRenderer::GetInstance()->Reset();

  moho::CD3DDevice* const device = moho::D3D_GetDevice();
  moho::ID3DDeviceResources* const resources = device->GetResources();

  if (!mDynamicTextureSheet) {
    (void)resources->NewDynamicTextureSheet(
      mDynamicTextureSheet,
      kViewportDynamicSheetExtent,
      kViewportDynamicSheetExtent,
      kViewportDynamicSheetFormat
    );
  }

  for (int head = 0; head < mNumHeads; ++head) {
    (void)mBloomRenderers[head].Init(head);

    if (moho::IUIManager* const uiManager = moho::UI_GetManager(); uiManager != nullptr) {
      uiManager->OnResize(head, device->GetHeadWidth(head), device->GetHeadHeight(head));
    }

    const int headWidth = device->GetHeadWidth(head);
    const int headHeight = device->GetHeadHeight(head);
    const auto headSlot = static_cast<std::size_t>(head);

    // Each slot is filled only when empty, so a device rebind restores just
    // the targets that were released rather than reallocating all of them.
    if (!mPrimaryTargetLocks[headSlot]) {
      resources->CreateRenderTarget(
        mPrimaryTargetLocks[headSlot], headWidth, headHeight, kViewportHeadTargetFormat
      );
    }
    if (!mSecondaryTargetLocks[headSlot]) {
      resources->CreateRenderTarget(
        mSecondaryTargetLocks[headSlot], headWidth, headHeight, kViewportHeadTargetFormat
      );
    }
    if (!mDepthStencilLocks[headSlot]) {
      resources->CreateDepthStencil(
        mDepthStencilLocks[headSlot], headWidth, headHeight, kViewportHeadDepthStencilFormat
      );
    }
  }
}

/**
 * Address: 0x007F70F0 (FUN_007F70F0,
 * ?D3DWindowOnDeviceExit@WRenViewport@Moho@@UAEX_N@Z)
 *
 * IDA signature:
 * int __thiscall Moho::WRenViewport::D3DWindowOnDeviceExit(
 *     Moho::WRenViewport *this, bool a2);
 *
 * What it does:
 * Drops every device-dependent resource the viewport owns, in the exact
 * inverse of `D3DWindowOnDeviceInit`. See the declaration for how
 * `fullShutdown` splits the device-rebind path from the app-shutdown path.
 */
void moho::WRenViewport::D3DWindowOnDeviceExit(const bool fullShutdown)
{

  // The singleton is fetched before the branch in the binary, because both
  // sides use it.
  moho::MeshRenderer* const meshRenderer = moho::MeshRenderer::GetInstance();

  if (fullShutdown) {
    mPrimBatcher.reset();
    mTexBatcher.reset();
    mMapImager.ClearBorder();
    meshRenderer->Shutdown();

    // The binary follows this with `call sub_809E80` at 0x007F7130 - the
    // shared terrain teardown. It drops the per-fidelity terrain statics of
    // all three terrain TUs, three groups in this order, each group being
    // `delete batcher; delete waterSurface; <sheets>.reset()`:
    //
    //   high   0x00809E81 sHighFidelityTextureBatcher          @0x010BF738
    //          0x00809E9F sHighFidelityWaterSurface            @0x010C0ABC
    //          0x00809EB7 sHighFidelityNoiseFillTexture        @0x010BF704
    //          0x00809EFD sHighFidelityCubicBlendLookupTexture @0x010BF714
    //          0x00809F3D sHighFidelityGridTexture             @0x010BF73C
    //   medium 0x00809F7D sMediumFidelityTextureBatcher        @0x010BF724
    //          0x00809F97 sMediumFidelityWaterSurface          @0x010BF734
    //          0x00809FAF sMediumFidelityNoiseFillTexture      @0x010BF71C
    //          0x00809FF5 sMediumFidelityCubicBlendLookup...   @0x010C0AB0
    //          0x0080A035 sMediumFidelityGridTexture           @0x010BF728
    //   low    0x0080A075 texture_batcher                      @0x010C0AB8
    //          0x0080A08F sTerrainWaterSurface                 @0x010BF730
    //          0x0080A0A7 sTerrainGridTexture                  @0x010BF70C
    //
    // Ten of the thirteen have internal linkage (the anonymous namespaces at
    // the head of HighFidelityTerrain.cpp and MediumFidelityTerrain.cpp), so
    // each group is released by a named helper in its own translation unit and
    // REN_ReleaseTerrainSharedResources walks the three in the binary's order.
    moho::REN_ReleaseTerrainSharedResources();
    moho::WaterBodySurfaces::Release();
  } else {
    meshRenderer->Reset();
  }
  ReleaseWaterBodyReflections();

  mFrame.ResetTransientResources();

  // `if (sWldMap && sWldMap->mTerrainRes)` in the binary - which is exactly
  // what REN_GetTerrainRes (0x007FA170) returns a non-null pointer for.
  if (moho::IWldTerrainRes* const terrainRes = moho::REN_GetTerrainRes(); terrainRes != nullptr) {
    terrainRes->GetCartographic().Shutdown();
    terrainRes->GetSkyDome().Reset();
  }

  mSilhouetteRenderer.mQuadVertexSheet.reset();
  mClutter.Shutdown();
  (void)mShadowRenderer.ReleaseRenderResources();
  mRangeRenderer.ResetRenderResources();

  mBoundaryRenderer.mFrame.ResetTransientResources();
  mBoundaryRenderer.mBoundaryRendererBody.ResetRenderResources();

  mVisionRenderer.ResetRenderResources();
  mThumbnailRenderer.ReleaseTargets();

  mBloomRenderers[0].ResetRenderTargets();
  mBloomRenderers[1].ResetRenderTargets();

  // Release order is the binary's: the shared dynamic sheet first, then the
  // six per-head locks. These are the default-pool surfaces that make
  // `IDirect3DDevice9::Reset` fail if any of them outlives this call.
  mDynamicTextureSheet.reset();
  mPrimaryTargetLocks[0].reset();
  mPrimaryTargetLocks[1].reset();
  mSecondaryTargetLocks[0].reset();
  mSecondaryTargetLocks[1].reset();
  mDepthStencilLocks[0].reset();
  mDepthStencilLocks[1].reset();
}

/**
 * Address: 0x007F7B30 (FUN_007F7B30)
 * Mangled: ?D3DWindowOnDeviceRender@WRenViewport@Moho@@UAEXXZ
 *
 * What it does:
 * Drives one engine frame. Resets the per-frame unit stat and every render
 * counter, ticks each registered world view's terrain, advances the global mesh
 * frame counter/interpolant, then runs `Render` once per configured head. A
 * re-entrant paint while a frame is in flight is dropped by the guard byte.
 * CD3DDevice::Paint reaches it through WD3DViewport's slot 132.
 */
void moho::WRenViewport::D3DWindowOnDeviceRender()
{
  FAF_PROFILE_ZONE_NAMED("Render");
  moho::CTimeBarSection renderSection("Render");
  if (gRenderLock) {
    return;
  }
  const gpg::gal::RenderProfileScope profileFrame("Frame"); // FAF instrumentation (gpg/gal/RenderProfiler.h)
  gRenderLock = true;

  ResetRenderUnitCountStat();
  (void)moho::D3D_GetDevice()->InitRenderEngineStats();
  // FAF instrumentation, not in the binary: refill the draw stats just zeroed
  // with the previous frame's submissions (CD3DDevice::PublishDrawStatistics).
  moho::D3D_GetDevice()->PublishDrawStatistics();

  for (SWorldViewInfo& worldView : mWorldViews) {
    worldView.mView->Func1();
  }

  // ++sFrameCounter; sCurrentInterpolant = REN_GetSimDeltaSeconds(); - the
  // binary open-codes both stores here; the recovered helper is byte-identical.
  moho::MeshInstance::SetCurrentInterpolant();

  for (int head = 0; head < mNumHeads; ++head) {
    if (moho::ren_OnlyFirstView && !mWorldViews.empty()) {
      // Debug mode: render only the first registered world view. The binary
      // copy-constructs a fresh one-element vector from the first entry for
      // the duration of the call rather than passing the live vector.
      fa::vector<SWorldViewInfo> firstViewOnly{};
      firstViewOnly.push_back(mWorldViews.front());
      Render(head, firstViewOnly);
    } else {
      Render(head, mWorldViews);
    }
  }

  ++moho::snd_index;
  gRenderLock = false;
}

/**
 * Address: 0x007F7400 (FUN_007F7400, ?RenderPreviewImage@WRenViewport@Moho@@UAEX_N@Z)
 * Mangled: ?RenderPreviewImage@WRenViewport@Moho@@UAEX_N@Z
 *
 * IDA signature:
 * int __thiscall Moho::WRenViewport::RenderPreviewImage(
 *     Moho::WRenViewport *this, bool forceRegenerate);
 *
 * What it does:
 * Renders one top-down "strategic map" snapshot of the active world into
 * this viewport's retained 256x256 preview texture (the sheet
 * `GetPreviewImage()` returns, allocated once by `D3DWindowOnDeviceInit` via
 * `NewDynamicTextureSheet`). Builds a throwaway camera framed on the loaded
 * map's bounds, disables every non-terrain render pass and the editor input
 * hook for the duration of one `Render` call against a one-element
 * world-view list wrapping that camera, then composites the primary render
 * target through a full-screen "TOpaque" frame pass, accumulates it into a
 * fresh dynamic texture sheet via the device-resources copy lane, and blits
 * that into the retained preview sheet with `UpdateSurface`. Every disabled
 * toggle and the editor hook are restored before return, and the throwaway
 * camera is deleted (which forgets itself from `RCamManager::mCams` as part
 * of its own destructor chain - see `CameraImpl::~CameraImpl`).
 *
 * Notes:
 * - `forceRegenerate` is not read anywhere in the recovered body; every path
 *   below runs unconditionally, matching the binary.
 * - The raw decompile shows this as manual `boost::detail::shared_count` /
 *   `_InterlockedExchangeAdd` refcount bookkeeping and a `dtr_sp_counted_base`
 *   virtual call on the camera pointer. Both are decompiler artifacts: the
 *   shared_count calls are boost's own `shared_ptr<TerrainCommon>` machinery
 *   (mirrored below through `AssignSharedTerrainFromRaw`, exactly as
 *   `WRenViewport::AddWorldView` already uses it for the identical
 *   `IRenTerrain::Create()` + `Create(terrainRes)` pair), and
 *   `dtr_sp_counted_base(camera, 1)` is CameraImpl's own scalar-deleting
 *   destructor (vtable slot 0) - i.e. a plain `delete camera;`.
 * - The `1132462080` / `1132462080` pair the raw decompile assigns into the
 *   viewport-size local is the bit pattern of `256.0f` twice over (a
 *   `Wm3::Vector2f{256.0f, 256.0f}` written through adjacent stack slots),
 *   not a pointer or a stack-reuse token.
 * - `GetResources()->Func10(...)` is ID3DDeviceResources slot 18
 *   (vtable +0x48 / decompiled offset 72), the same lane
 *   `REN_MaybeDumpFrame` above uses to accumulate a render target into a
 *   dynamic texture sheet. Unlike that persistent-lane caller, this pass
 *   always hands Func10 an empty `currentSheet` (the binary's literal `0, 0`
 *   pair), so it recreates the destination sheet fresh on every call instead
 *   of reusing one across frames.
 * - `GetPreviewImage()`'s real declared signature takes no arguments and
 *   returns `boost::shared_ptr<moho::ID3DTextureSheet>`
 *   by value through a hidden return pointer; the raw decompile's apparent
 *   second argument is that hidden pointer, not a real parameter.
 */
void moho::WRenViewport::RenderPreviewImage([[maybe_unused]] const bool forceRegenerate)
{
  moho::ed_EnableHook = false;

  moho::CD3DDevice* const device = moho::D3D_GetDevice();
  const int headWidth = device->GetHeadWidth(0);
  const int headHeight = device->GetHeadHeight(0);

  // `if (sWldMap) mTerrainRes = sWldMap->mTerrainRes;` in the binary, followed
  // by an unconditional `mTerrainRes->mMap` deref. REN_GetTerrainRes folds in
  // the same session/map null check this file already substitutes for that
  // exact expression elsewhere (see WRenViewport::D3DWindowOnDeviceExit); the
  // extra null guard below only matters if this is ever reached without a
  // loaded world, which does not happen on any real call path.
  moho::IWldTerrainRes* const terrainRes = moho::REN_GetTerrainRes();
  if (terrainRes == nullptr) {
    moho::ed_EnableHook = true;
    return;
  }
  moho::STIMap* const map = terrainRes->mMap;

  moho::RCamManager* const camManager = moho::CAM_GetManager();
  moho::CameraImpl* const camera = camManager->CreateCamera("Strategic map render camera", *map, nullptr);
  camera->CameraSetViewport(Wm3::Vector2f(0.0f, 0.0f), Wm3::Vector2f(256.0f, 256.0f));

  const Wm3::AxisAlignedBox3f mapBounds = map->GetBounds3D();
  float mapExtent = mapBounds.Max.x - mapBounds.Min.x;
  if ((mapBounds.Max.z - mapBounds.Min.z) > mapExtent) {
    mapExtent = mapBounds.Max.z - mapBounds.Min.z;
  }
  const Wm3::Vec3f mapCenter{
    (mapBounds.Min.x + mapBounds.Max.x) * 0.5f,
    (mapBounds.Max.y + mapBounds.Min.y) * 0.5f,
    (mapBounds.Min.z + mapBounds.Max.z) * 0.5f
  };
  camera->TargetManual(mapCenter, 3.1415925f, 1.5707963f, mapExtent, 0.0f);

  camManager->Frame(0.0f, 0.0f);

  const bool savedUi = moho::ren_Ui;
  const bool savedFx = moho::ren_Fx;
  const bool savedWorldBorder = moho::ren_WorldBorder;
  const bool savedDistanceFog = moho::fog_DistanceFog;
  const bool savedSelect = moho::ren_Select;
  const bool savedShadows = moho::ren_Shadows;
  const bool savedFog = moho::ren_fog;

  moho::ren_Shadows = false;
  moho::fog_DistanceFog = false;
  moho::ren_fog = false;
  moho::ren_Select = false;
  moho::ren_Fx = false;
  moho::ren_WorldBorder = false;
  moho::ren_Ui = false;

  moho::SimpleRenderWorldView previewView(const_cast<moho::GeomCamera3*>(&camera->CameraGetView()));

  SWorldViewInfo worldViewEntry{};
  worldViewEntry.mView = &previewView;
  (void)AssignSharedTerrainFromRaw(&worldViewEntry.mTerrain, moho::IRenTerrain::Create());
  if (worldViewEntry.mTerrain) {
    (void)worldViewEntry.mTerrain->Create(terrainRes);
  }

  fa::vector<SWorldViewInfo> previewWorldViews{};
  previewWorldViews.push_back(worldViewEntry);
  Render(0, previewWorldViews);

  moho::ren_Ui = savedUi;
  moho::ren_WorldBorder = savedWorldBorder;
  moho::ren_Fx = savedFx;
  moho::ren_Select = savedSelect;
  moho::fog_DistanceFog = savedDistanceFog;
  moho::ren_fog = savedFog;
  moho::ren_Shadows = savedShadows;

  device->SetRenderTarget2(0, false, 0, 1.0f, 0);
  device->SetColorWriteState(false, true);

  mFrame.mName = "TOpaque";
  mFrame.InitTransformedVerts(static_cast<float>(headWidth), static_cast<float>(headHeight));
  mFrame.SetTexture(0, mPrimaryTargetLocks[0]);
  mFrame.Render(headWidth, headHeight);

  boost::shared_ptr<moho::ID3DRenderTarget> screenLock{};
  device->GetWriterLock1(screenLock, 0);
  device->SetViewRect(screenLock.get(), mPrimaryTargetLocks[0].get(), nullptr, nullptr);

  moho::ID3DDeviceResources* const resources = device->GetResources();
  boost::shared_ptr<moho::CD3DDynamicTextureSheet> previewSheet{};
  resources->Func10(
    previewSheet, mPrimaryTargetLocks[0].get(), moho::ID3DDeviceResources::DynamicTextureSheetHandle{}
  );
  moho::CD3DDynamicTextureSheet* const resolvedSheet = previewSheet.get();

  const RECT sourceRect{0, 0, 256, 256};
  const boost::shared_ptr<moho::ID3DTextureSheet> previewImage = GetPreviewImage();
  device->UpdateSurface(
    resolvedSheet, static_cast<moho::CD3DDynamicTextureSheet*>(previewImage.get()), &sourceRect, nullptr
  );

  moho::ed_EnableHook = true;

  // Forgets itself from RCamManager::mCams as part of ~CameraImpl chaining
  // into ~RCamCamera (see CameraImpl.h); no ForgetCamera call is needed here.
  delete camera;
}
namespace
{
  // TEMPORARY BISECT SWITCH -- delete once the commander-spawn heap corruption
  // is attributed. Three blocks in `WRenViewport::Render` were restored on
  // 2026-09-03 (range-category refresh, lazy terrain finalize, clutter
  // refresh). All three had never executed in any prior session, so all three
  // are newly-live recovered code running on the render thread during the
  // loading screen. Setting FAF_NO_RENDER_ADDITIONS=1 skips exactly those
  // three and nothing else, which separates "one of today's blocks corrupts
  // the heap" from "the corruption predates them" in a single run.
  // TEMPORARY: FAF_NO_SHADOWS=1 drops the shadow context and the shadow pass
  // (black-wedge triage).
  [[nodiscard]] bool ShadowsDisabledByEnv() noexcept
  {
    static const bool disabled = [] {
      std::size_t length = 0u;
      char value[8] = {};
      return ::getenv_s(&length, value, sizeof(value), "FAF_NO_SHADOWS") == 0 && length != 0u && value[0] == '1';
    }();
    // Runtime toggle: "<FAF_TOGGLE_DIR>\noshadow.on" while it exists.
    static char sToggleDir[512] = {};
    static bool sToggleDirResolved = false;
    if (!sToggleDirResolved) {
      sToggleDirResolved = true;
      std::size_t length = 0u;
      if (::getenv_s(&length, sToggleDir, sizeof(sToggleDir), "FAF_TOGGLE_DIR") != 0 || length == 0u) {
        sToggleDir[0] = 0;
      }
    }
    static unsigned sPollCounter = 0u;
    static bool sToggled = false;
    if (sToggleDir[0] != 0 && (sPollCounter++ % 30u) == 0u) {
      char path[640];
      (void)std::snprintf(path, sizeof(path), "%s\\noshadow.on", sToggleDir);
      sToggled = ::GetFileAttributesA(path) != INVALID_FILE_ATTRIBUTES;
    }
    return disabled || sToggled;
  }

  [[nodiscard]] bool RenderAdditionsDisabled() noexcept
  {
    static const bool disabled = [] {
      std::size_t length = 0u;
      char value[8] = {};
      return ::getenv_s(&length, value, sizeof(value), "FAF_NO_RENDER_ADDITIONS") == 0
             && length != 0u && value[0] == '1';
    }();
    return disabled;
  }
}


/**
 * Engine addition: one world view of `Render`'s per-view loop (0x007F9253..0x007F9779), in the
 * binary's order. A view it skips returns, where the binary jumps to the next entry.
 */
void moho::WRenViewport::RenderWorldView(
  const SWorldViewInfo* const worldView, const int head, const SWorldViewInfo* const begin, const bool regenerateShoreline
)
{
  if (worldView->mView == nullptr) {
    return;
  }

  // 0x007F92A0..0x007F92FB: a view is skipped when its slot-9 query answers
  // true, when slot 12 does (CUIWorldView::CanShake 0x0086DC60 returns the
  // orthographic flag, so every minimap is left to the cartographic pass and
  // never gets the 3D world/fog pass), when it belongs to another head, and,
  // under `ren_HideSecondary` (0x010A6421), when it is not the first view.
  if (worldView->mView->Func2() || worldView->mView->CanShake() || worldView->mHead != head
      || (moho::ren_HideSecondary && worldView != begin)) {
    return;
  }

  // `IRenderWorldView::GetCamera()` returns a `CameraImpl*` (see
  // IRenderWorldView.h slot 3) - a whole camera-control object, not the
  // embedded GeomCamera3 transform/projection state itself. The prior
  // reinterpret_cast straight to `GeomCamera3*` treated CameraImpl's own
  // layout (RCamCamera broadcaster fields, the CScriptEvent sub-object,
  // mName, mTerrainMap, ...) as if it were GeomCamera3, so every read
  // through `mCam` below (view/projection matrices, transform) pulled
  // unrelated CameraImpl bytes instead - confirmed live via dbgrun: the
  // resulting "position" was nonsense (~31219 on two axes) even though
  // CameraImpl's own CameraGetView()/UpdateCoords() computed a perfectly
  // sane transform. CameraGetView() is the real, correctly-offset
  // accessor for the embedded GeomCamera3 (CameraImpl.cpp:2007-2010:
  // `return As(this)->mCam;`).
  moho::CameraImpl* const cameraImpl = worldView->mView->GetCamera();
  mCam = cameraImpl != nullptr
    ? const_cast<moho::GeomCamera3*>(&cameraImpl->CameraGetView())
    : nullptr;
  if (mCam == nullptr) {
    return;
  }

  // Ground clutter, refreshed once per frame off the primary world view.
  // Binary 0x007F9301..0x007F9330: gated on `ren_Clutter` and on this entry
  // being the first in the world-view list (the same `== begin` comparison
  // `ren_HideSecondary` uses two instructions earlier -- IDA types the list's
  // begin/end pair as `mVertexSheets[0]`/`[1]`, which is what makes that test
  // read like a sheet comparison). `UpdateCurrent` retires regions the camera
  // has left, `GenerateNew` fills in the ones it has entered; both take the
  // view camera and both live at `viewport + 0x808`.
  // TEMPORARY: FAF_NO_CLUTTER=1 skips only this block (black-sliver triage).
  static const bool sClutterDisabled = [] {
    std::size_t length = 0u;
    char value[8] = {};
    return ::getenv_s(&length, value, sizeof(value), "FAF_NO_CLUTTER") == 0 && length != 0u && value[0] == '1';
  }();
  if (moho::ren_Clutter && worldView == begin && !RenderAdditionsDisabled() && !sClutterDisabled) {
    mClutter.UpdateCurrent(mCam);
    mClutter.GenerateNew(mCam);
  }

  // Refresh mScreenPos/mScreenSize/mFullScreen from THIS view's camera
  // before drawing it. The binary calls UpdateRenderViewportCoordinates
  // twice (confirmed via its two code xrefs): once per-iteration right
  // here (0x007F9385, with mCam freshly bound to the current view), and
  // once more after the loop as a shared tail (0x007F97A4, by which point
  // the loop has reset mCam to null - see `mCam = nullptr;`
  // below). This per-iteration call was missing from the recovery, so
  // mScreenPos/mScreenSize never advanced past whatever the PREVIOUS
  // frame's post-loop null-camera fallback wrote (the full head rect at
  // origin) - every view, main and minimap alike, rendered its
  // terrain/mesh/water passes through that full-screen rect instead of
  // this view's own CameraSetViewport-pushed one.
  UpdateRenderViewportCoordinates();


  // Render the atmosphere/cloud sky dome for this world view before the
  // terrain composite pass (binary order: WRenViewport::Render @0x007F90D0
  // dispatches the sky dome pass right after the per-view camera bind,
  // guarded by the ren_SkyDome tuning flag).
  if (moho::ren_SkyDome) {
    const gpg::gal::RenderProfileScope profileSky("SkyDome");
    RenderSkyDome();
  }

  moho::TerrainCommon* const terrain = worldView->mTerrain.get();


  if (moho::ren_Terrain && terrain != nullptr) {
    // Per-frame render-context update (TerrainCommon slot 5), dispatched
    // immediately before RenderTerrainNormals in the binary
    // (0x007F93A6-0x007F93C7). The viewport block is the 3 contiguous
    // Vector2i fields at +0x308 (mScreenPos/mScreenSize/mFullScreen). minimapPass is always false from this call site;
    // forceRegenerate is the `ren_RegenShore` latch taken on entry (the
    // push at 0x007F939A reads that stack byte). Passing 1 here rebuilt the
    // whole shoreline every frame.
    {
      const gpg::gal::RenderProfileScope profileTerrainContext("TerrainContext");
      terrain->UpdateRenderContext(
        moho::REN_GetGameTick(),
        moho::REN_GetSimDeltaSeconds(),
        mCam,
        reinterpret_cast<const std::int32_t*>(&mScreenPos),
        false,
        regenerateShoreline ? 1 : 0
      );
    }

    {
      const gpg::gal::RenderProfileScope profileTerrainNormals("TerrainNormals");
      RenderTerrainNormals(terrain);
      TransformTerrainNormals();
    }

    // The shadow pass, between the normal transform and the composite
    // (0x007F93DF slot 6 CameraGetTargetZoom, then 0x007F93F1).
    {
      const gpg::gal::RenderProfileScope profileShadows("Shadows");
      mShadowRenderer.RenderFrameShadows(
        terrain, *mCam, worldView->mView->CameraGetTargetZoom());
    }

    FogOn(worldView->mView->CameraGetZoom());
    {
      const gpg::gal::RenderProfileScope profileTerrain("Terrain");
      RenderCompositeTerrain(terrain);
    }
  }

  // Range-ring pass for the normal (non-cartographic) world view, between the
  // terrain composite and the mesh batch. Binary 0x007F940E..0x007F944D:
  //
  //   0x007F940E  call [worldView + 0Ch]      ; IRenderWorldView slot 3, GetCamera
  //   0x007F9417  mov  ecx, [esp+1Ch]         ; the cached sWldSession local
  //   0x007F941D  test ecx, ecx / jz          ; no session -> skip
  //   0x007F9421  test eax, eax / jz          ; no camera  -> skip
  //   0x007F9423  cmp  ren_Ranges, 0 / jz     ; 0x00F57E4F
  //   0x007F942C  cmp  ren_Ui, 0 / jz         ; 0x00F57DE7
  //   0x007F9435  fld  sDeltaFrame            ; 0x010A6338
  //   0x007F9444  lea  edx, [ebp+37Ch]        ; &WRenViewport::mRangeRenderer
  //   0x007F944D  call RangeRenderer::Render
  //
  // Without this the range renderer only ever ran from `Cartographic::Render`,
  // so every range overlay - build range, weapon ranges, intel - was visible
  // in the minimap and in cartographic mode but never in the ordinary 3D view.
  // The call target is FAF's `.exxt` replacement of `RangeRenderer::Render`
  // (0x012910B7), which re-implements the build-ring and visible-profile
  // passes and then jumps back into the shipped body at 0x007EEB55 for the
  // selected/highlighted passes; the recovered `RangeRenderer::Render` already
  // covers all of that, so it is called directly here.
  if (moho::CWldSession* const rangeSession = moho::WLD_GetActiveSession(); rangeSession != nullptr) {
    moho::CameraImpl* const rangeCamera = worldView->mView->GetCamera();
    if (rangeCamera != nullptr && moho::ren_Ranges && moho::ren_Ui) {
      const gpg::gal::RenderProfileScope profileRanges("Ranges");
      mRangeRenderer.Render(
        rangeSession, rangeCamera, static_cast<unsigned int>(head), moho::REN_GetSimDeltaSeconds()
      );
    }
  }

  // Rebuild the global mesh-renderer batch map for this frame/view before the
  // mesh draw passes below. Binary (WRenViewport::Render @0x007F90D0, the
  // GetInstance+Batch pair at 0x007F9452..0x007F9478) invokes it as
  //   MeshRenderer::Batch(instance, sCurGameTick, sDeltaFrame,
  //                       *viewport->mCam, viewport->mCam->viewport.r[1]);
  // The Vector4f fade-plane arg is the second row of the camera viewport
  // matrix (mCam + 0x294 = viewport @0x284 + 0x10 = r[1]).
  moho::MeshRenderer* const meshRenderer = moho::MeshRenderer::GetInstance();
  {
    const gpg::gal::RenderProfileScope profileMeshBatch("MeshBatch");
    meshRenderer->Batch(
      moho::REN_GetGameTick(),
      moho::REN_GetSimDeltaSeconds(),
      *mCam,
      mCam->viewport.r[1]
    );
  }

  {
    const gpg::gal::RenderProfileScope profileReflections("Reflections");
    RenderReflections();
  }
  {
    const gpg::gal::RenderProfileScope profileMeshes("Meshes");
    RenderMeshes(0x14, false);
  }
  // Engine addition (ren_Ao): ambient occlusion from the depth of terrain and the opaque meshes,
  // before effects and water draw over it.
  if (moho::AmbientOcclusionRenderer& occlusion = moho::AmbientOcclusionRenderer::Get(); occlusion.IsActive()) {
    const gpg::gal::RenderProfileScope profileOcclusion("AmbientOcclusion");
    // How far the shadow map reaches: terrain shadows take over beyond it, and stay off with shadows off.
    const float shadowReach = (!moho::ren_Shadows || moho::shadow_Fidelity == 0) ? -1.0f
      : mShadowRenderer.mShadowCameraValid                                      ? moho::ren_ShadowCoeff * worldView->mView->CameraGetTargetZoom()
                                                                                 : 0.0f;
    occlusion.Render(*mCam, mScreenPos.x, mScreenPos.y, mScreenSize.x, mScreenSize.y, shadowReach,
                     shadowReach > 0.0f ? &mShadowRenderer : nullptr);
  }
  {
    const gpg::gal::RenderProfileScope profileEffects("Effects");
    RenderEffects(true);
  }
  {
    const gpg::gal::RenderProfileScope profileMeshes("Meshes");
    RenderMeshes(0x18, false);
  }
  FogOff();

  if (terrain != nullptr) {
    const gpg::gal::RenderProfileScope profileWater("Water");
    RenderWaterMask(terrain);
    RenderCopyForRefraction(false);
    // Fog density tracks the camera zoom - the binary dispatches
    // IRenderWorldView slot 8 (CameraGetZoom) straight into FogOn at
    // 0x007F94B8..0x007F94C8, it is not a constant.
    FogOn(worldView->mView->CameraGetZoom());
    RenderWater(terrain);
  }

  // The playable-boundary pass and the UI selection pass, in that order,
  // between RenderWater and the 0x24 mesh bucket.
  //
  //   0x007F94D2  cmp  ren_PlayableBoundary, 0   ; jz 0x007F9500
  //   0x007F94DF  test ebx, ebx                  ; jz 0x007F9500  (mSession)
  //   0x007F94E3  cmp  [worldView->mView], 0      ; jz 0x007F9500
  //   0x007F94FB  call func_RenBoundary          ; 0x007D01C0, __thiscall
  //               ecx = head; args (&mBoundaryRenderer, mSession, <local>)
  //   0x007F9500  cmp  ren_Ui, 0                 ; jz 0x007F9536
  //   0x007F952E  call func_RenUI                ; 0x007FD490, __cdecl/0x14
  //               (mSession, mCam, mPrimBatcher.px, sDeltaFrame,
  //                sWeightedFrameRate)  <- IDA's 4-arg signature is wrong,
  //               it drops the 5th float; the push sequence at
  //               0x007F9509..0x007F952D has five dwords and the callee
  //               cleanup is `add esp, 14h` at 0x007F9533. `moho::RenUI`
  //               takes all five; do not trim it back to four.
  //
  // The fifth argument is the smoothed frame time (`fld sWeightedFrameRate`
  // at 0x007F9509), not the sim delta - the blinky-box cycle advances on
  // wall-clock frame time while the bracket geometry interpolates on
  // `sDeltaFrame`.
  // The `ebx` these three gates test is NOT the `+0x2140` lane this file
  // models as `mSession`. `+0x2140` is written once per loop iteration at
  // 0x007F9379, alongside `mCam` at `+0x219C`, and both are cleared together
  // at 0x007F9709 - it is the per-iteration current world view, and slot 0 is
  // dispatched off it at 0x007F95EA. Nothing ever writes it as a session, so
  // reading it here handed all three passes a permanent nullptr and the
  // playable boundary, the UI selection pass and the fog of war never ran.
  // The session the binary tests is the plain `sWldSession` global, cached
  // into a stack local ahead of the loop (`v79 = Moho::sWldSession`).
  moho::CWldSession* const renderSession = moho::WLD_GetActiveSession();
  if (moho::ren_PlayableBoundary && renderSession != nullptr && worldView->mView != nullptr) {
    moho::RenderPlayableBoundary(
      static_cast<unsigned int>(head), mBoundaryRenderer, *renderSession,
      *mCam
    );
  }

  if (moho::ren_Ui) {
    const gpg::gal::RenderProfileScope profileRenUi("WorldUi");
    moho::RenUI(
      renderSession,
      mCam,
      mPrimBatcher.get(),
      moho::REN_GetSimDeltaSeconds(),
      moho::REN_GetWeightedFrameSeconds()
    );
  }

  {
    const gpg::gal::RenderProfileScope profileMeshes("Meshes");
    RenderMeshes(0x24, false);
  }
  {
    const gpg::gal::RenderProfileScope profileEffects("Effects");
    RenderEffects(false);
  }
  {
    const gpg::gal::RenderProfileScope profileMeshes("Meshes");
    RenderMeshes(0x28, false);
  }

  // Fog is dropped *before* the refracting-effects pass, not after it. The
  // binary runs FogOff at 0x007F9551, then the fog-of-war block, and only
  // reaches RenderRefractingEffects at 0x007F95AE - so the refraction pass
  // draws unfogged. Emitting RenderRefractingEffects first (as this did)
  // rendered it with the terrain fog state still bound.
  FogOff();

  // Not yet wired: the fog-of-war overlay, between FogOff and the
  // refracting-effects pass.
  //
  //   0x007F9556  cmp  ren_FogOfWar, 0           ; jz 0x007F95AC
  //   0x007F955F  test ebx, ebx                  ; jz 0x007F95AC  (mSession)
  //   0x007F9563  cmp  [mSession + 0x488], -1    ; jz 0x007F95AC
  //               (focus army unset -> no fog of war to draw)
  //   0x007F9589  call func_ren_FogOfWar         ; 0x0081C660, __thiscall
  //               ecx = mSession; args (&mVisionRenderer, head, <local>,
  //               sDeltaFrame)
  //   0x007F958E  Clear(false, false, true, 0xFFFFFFFF, 1.0f, 0) through
  //               device slot +0x98: wipe the vision stencil again so it
  //               does not mask anything drawn after the fog pass.
  if (moho::ren_FogOfWar && renderSession != nullptr &&
      renderSession->FocusArmy != -1) {
    const gpg::gal::RenderProfileScope profileFog("FogOfWar");
    moho::RenderFogOfWar(
      *renderSession, mVisionRenderer, static_cast<unsigned int>(head),
      *mCam, moho::REN_GetSimDeltaSeconds()
    );
    gpg::gal::Device::GetInstance()->Clear(false, false, true, 0xFFFFFFFFu, 1.0f, 0);
  }

  {
    const gpg::gal::RenderProfileScope profileRefraction("Refraction");
    RenderRefractingEffects();
  }

  // 0x007F95B3..0x007F95EA: the world view's own overlay pass, dispatched
  // through `IRenderWorldView` slot 0 on the `+0x2140` lane this loop seeded
  // at 0x007F9379. The four arguments are laid down at 0x007F95BC..0x007F95E7:
  // the raw `CD3DPrimBatcher*` from `mPrimBatcher` at `+0x215C`,
  // `sCurGameTick`, then `sDeltaFrame` (the sub-tick interpolation fraction)
  // and `sWeightedFrameRate`, both through the x87 stack. This is the
  // dispatch that draws the overlays for an ordinary perspective view; the
  // one in `Cartographic::Render` only ever runs for a view whose
  // orthographic flag is set, which is the minimap and whichever view the
  // player has toggled into cartographic mode.
  if (moho::ren_Ui && worldView->mView != nullptr) {
    const gpg::gal::RenderProfileScope profileViewOverlay("ViewOverlay");
    worldView->mView->Render(
      mPrimBatcher.get(),
      static_cast<int>(moho::REN_GetGameTick()),
      moho::REN_GetSimDeltaSeconds(),
      moho::REN_GetWeightedFrameSeconds()
    );
  }

  // Per-view debug-canvas overlay pass. Binary (WRenViewport::Render
  // @0x007F90D0, 0x007F9639..0x007F96D3): resets the 2D draw origin to
  // local screen space unconditionally, then - only while a world session
  // is active - renders and releases the session's tick and beat debug
  // canvases in turn.
  //
  // Not yet modelled: the unconditional tail at 0x007F96D8 that follows
  // this (reached whether or not a session was active) additionally
  // renders and clears the viewport's OWN debug canvas
  // (`mDebugCanvas`, +0x2C8) and runs cleanup this pass does not
  // cover (`[ebp+2140h]` zero, `sub_7F7AC0`). Left out rather than guessed.
  SetViewportToLocalScreen();
  if (moho::CWldSession* const activeSession = moho::WLD_GetActiveSession(); activeSession != nullptr) {
    if (boost::SharedPtrRaw<moho::CDebugCanvas> tickCanvas = activeSession->GetTickDebugCanvas();
        tickCanvas.px != nullptr) {
      tickCanvas.px->Render(
        mPrimBatcher.get(), *mCam, mScreenSize.x, mScreenSize.y
      );
      tickCanvas.release();
    }

    if (boost::SharedPtrRaw<moho::CDebugCanvas> beatCanvas = activeSession->GetBeatDebugCanvas();
        beatCanvas.px != nullptr) {
      beatCanvas.px->Render(
        mPrimBatcher.get(), *mCam, mScreenSize.x, mScreenSize.y
      );
      beatCanvas.release();
    }
  }

  mCam = nullptr;
}

/**
 * Address: 0x007F90D0 (FUN_007F90D0)
 * Mangled: ?Render@WRenViewport@Moho@@AAEXHAAV?$vector@USWorldViewInfo@Moho@@V?$allocator@USWorldViewInfo@Moho@@@std@@@std@@@Z
 *
 * What it does:
 * Makes `head` current and runs the world pass - terrain, reflections, meshes,
 * effects, water, shadows - for each view in `worldViews` that draws on it,
 * then the cartographic views, the silhouettes, bloom and the UI.
 *
 * It walks the vector it is given ([esp+0x64] at 0x007F924C), not
 * mWorldViews: RenderPreviewImage hands it a one-view list and
 * ren_OnlyFirstView a copy of the first view. An earlier revision walked
 * mWorldViews here, so both drew every registered view.
 */
void moho::WRenViewport::Render(const int head, fa::vector<SWorldViewInfo>& worldViews)
{
  moho::CD3DDevice* const device = moho::D3D_GetDevice();
  if (device == nullptr) {
    return;
  }

  gpg::gal::Device* const galDevice = device->GetGalDevice();

  // `ren_RegenShore` is a one-shot request (0x007F910C-0x007F9120): latched
  // and cleared here, then handed to the terrain's render-context update as
  // its regenerate flag. The shoreline is otherwise built once, when the
  // terrain is created.
  const bool regenerateShoreline = moho::ren_RegenShore;
  moho::ren_RegenShore = false;

  // Clamp the requested fidelity into the range this adapter actually supports.
  if (moho::graphics_Fidelity >= moho::graphics_FidelitySupported) {
    moho::graphics_Fidelity = moho::graphics_FidelitySupported;
  }
  if (moho::graphics_Fidelity < 0) {
    moho::graphics_Fidelity = 0;
  }

  mHead = head;

  if (moho::ren_RenderNothing) {
    return;
  }

  // ---- Per-head device setup -----------------------------------------------
  // This block runs before any world-view work and unconditionally, which is
  // what makes a frame renderable at all: `SetRenderTarget2` is the only thing
  // on the D3D9 path that binds a depth-stencil surface (it reaches
  // `CD3DDevice::SetRenderTarget1` -> `DeviceD3D9::ClearTarget` ->
  // `SetDepthStencilSurface`). The device is created with
  // `EnableAutoDepthStencil = 0`, so until this runs once, any clear that asks
  // for Z or stencil - such as the one `CD3DDevice::Paint` issues while the
  // window is being resized - fails with D3DERR_INVALIDCALL and the GAL throws.
  //
  // Binary order (FUN_007F90D0.asm 0x007F914D..0x007F91D9):
  //   ValidateFrame -> SetWireframeState -> BeginScene -> RenderThumbnails
  //   -> SetRenderTarget2(mHead, clear=1, color=0, z=1.0f, stencil=0)
  //   -> RenderFrames
  // The SetRenderTarget2 arguments are read straight off the push sequence at
  // 0x007F919E..0x007F91B1 (stencil, z via fld1/fstp, color, clear, index).
  moho::IUIManager* const uiManager = moho::ren_Ui ? moho::UI_GetManager() : nullptr;
  if (uiManager != nullptr) {
    uiManager->ValidateFrame(head);
  }

  if (galDevice != nullptr) {
    (void)galDevice->SetWireframeState(moho::ren_ShowWireframe);
  }

  device->BeginScene();

  mThumbnailRenderer.ProcessPendingRequests();

  device->SetRenderTarget2(mHead, true, 0, 1.0f, 0);

  if (uiManager != nullptr) {
    // Batcher read straight out of the viewport at +0x215C, matching the
    // binary's direct field load at 0x007F91C4 (same lane `GetPrimBatcher`
    // returns).
    const gpg::gal::RenderProfileScope profileUiFrames("UiFrames");
    uiManager->RenderFrames(mHead, mPrimBatcher.get());
  }

  // Range-ring category filter, refreshed from the session's overlay filters
  // before any world view draws. Binary 0x007F91DB..0x007F91FE: loads
  // `sWldSession`, gates on it and on `ren_Ranges`, then passes
  // `session + 0x4D8` (`mOverlayFilters`) to the viewport's own RangeRenderer
  // at `+0x37C`.
  if (moho::CWldSession* const session = moho::WLD_GetActiveSession();
      session != nullptr && moho::ren_Ranges && !RenderAdditionsDisabled()) {
    mRangeRenderer.MoveCategories(session->mOverlayFilters);
  }

  // Lazy terrain finalize. Binary 0x007F9203..0x007F9231:
  //
  //     mov  eax, sWldMap        ; jz skip
  //     mov  esi, [eax+4]        ; mTerrainRes; jz skip
  //     mov  eax, [esi]
  //     mov  edx, [eax+4]        ; vtable slot 1  -> GetBool (0x008A1030)
  //     call edx
  //     test al, al
  //     jnz  skip
  //     mov  edx, [eax+12Ch]     ; vtable slot 75 -> Finalize (0x008A2DD0)
  //     call edx
  //
  // `Finalize` is where the terrain's D3D-side runtime is built: the two
  // stratum-mask sheets, the water-map sheet, and -- via `InitNormalMap` --
  // the normal-map tile sheets. It cannot run on the loader thread, so the
  // render thread does it once, the first frame after a map load, gated on the
  // ready flag `Finalize` itself sets.
  //
  // `MapLoad` deliberately does not call it (FUN_00890DA0 ends after
  // `CWldProps::Load`), and this was the only dispatch site, so with the block
  // missing `Finalize` never ran at all: `GetNormalMapCount()` stayed 0, the
  // `TTerrainBasis` tile loop in every fidelity's `DrawTerrainNormals` never
  // executed, the normals target's B/A channels stayed zero, and frame.fx's
  // `BasisPS` reconstructed `baseNormal.y = sqrt(1 - x*x - z*z)` from them --
  // which is why lit terrain came out near-black while meshes shaded normally.
  if (moho::IWldTerrainRes* const terrainRes = moho::REN_GetTerrainRes();
      terrainRes != nullptr && !RenderAdditionsDisabled()) {
    if (!terrainRes->GetBool()) {
      ::OutputDebugStringA("[TERRDIAG] Finalize: entering\n");
      const bool finalized = terrainRes->Finalize();
      char probe[64];
      (void)std::snprintf(probe, sizeof(probe), "[TERRDIAG] Finalize: returned %d\n", finalized ? 1 : 0);
      ::OutputDebugStringA(probe);
    }
  }

  // Re-center border mesh stances over the active terrain every frame.
  mMapImager.UpdateMeshStances();

  // An empty world-view list skips only the per-view loop - it is not a return.
  // The binary tests the list at 0x007F9253 (`cmp ecx, [ebx+8]` / `jz
  // loc_7F9779`) and loc_7F9779 lands *inside* the shared tail, ahead of
  // UpdateRenderViewportCoordinates. Of the 61 jumps in this function exactly
  // one leaves before the tail: `ren_RenderNothing` at 0x007F9147, and that one
  // is taken before the scene is ever opened. Returning here instead would
  // strand the scene BeginScene opened above, and the Present that
  // CD3DDevice::Paint issues at the head of the next frame would fail with
  // D3DERR_INVALIDCALL.
  const SWorldViewInfo* const begin = worldViews.begin();
  const SWorldViewInfo* const end = worldViews.end();

  for (const SWorldViewInfo* worldView = begin; worldView != end; ++worldView) {
    RenderWorldView(worldView, head, begin, regenerateShoreline);
  }

  // Every world view has consumed this frame's decal set, so drop the decal
  // manager's pending-changes flag. Binary 0x007F9779..0x007F979C: inside the
  // non-empty-list branch, after the loop - `sWldMap`, its `mTerrainRes`
  // (which is what REN_GetTerrainRes checks), `GetDecalManager` (slot +0x130),
  // then slot +0x74 on the manager. Without it HasPendingChanges stays set
  // and every view re-tessellates the terrain each frame.
  if (moho::IWldTerrainRes* const decalTerrainRes = moho::REN_GetTerrainRes(); decalTerrainRes != nullptr) {
    static_cast<moho::CDecalManager*>(decalTerrainRes->GetDecalManager())->ClearPendingChanges();
  }

  // Engine addition (ren_Fxaa): anti-aliasing for the world views on Direct3D 12 and Vulkan, which
  // have no multisampled back buffer. The head is copied into the refraction target (free again
  // once the views are drawn) and drawn back through FXAA over the whole head, colour only, before
  // the cartographic views and the interface. Sharpening and grading (ren_Sharpen, ren_Grade) follow
  // the same way, over FXAA's result.
  if (begin != end && mPrimaryTargetLocks[mHead] && !RenderAdditionsDisabled()) {
    const auto overHeadCopy = [&](const char* const profileName, auto&& render) {
      const gpg::gal::RenderProfileScope profile(profileName);
      boost::shared_ptr<moho::ID3DRenderTarget> headTarget{};
      device->GetWriterLock1(headTarget, mHead);
      device->SetViewRect(headTarget.get(), mPrimaryTargetLocks[mHead].get(), nullptr, nullptr);
      moho::ID3DRenderTarget::SurfaceHandle copy{};
      (void)mPrimaryTargetLocks[mHead]->GetSurface(copy);
      if (!copy) {
        return;
      }
      Wm3::Vector2i savedPos{};
      Wm3::Vector2i savedSize{};
      float savedMinZ = 0.0f;
      float savedMaxZ = 1.0f;
      device->GetView(&savedPos, &savedSize, &savedMinZ, &savedMaxZ);
      const int width = device->GetHeadWidth(static_cast<unsigned int>(mHead));
      const int height = device->GetHeadHeight(static_cast<unsigned int>(mHead));
      Wm3::Vector2i headPos{0, 0};
      Wm3::Vector2i headSize{width, height};
      device->SetViewport(&headPos, &headSize, savedMinZ, savedMaxZ);
      render(*copy, width, height);
      device->SetViewport(&savedPos, &savedSize, savedMinZ, savedMaxZ);
    };
    if (moho::FxaaRenderer& fxaa = moho::FxaaRenderer::Get(); fxaa.IsActive()) {
      overHeadCopy("Fxaa", [&](gpg::gal::RenderTarget& copy, const int width, const int height) {
        fxaa.Render(copy, width, height);
      });
    }
    if (moho::PostRenderer& post = moho::PostRenderer::Get(); post.IsActive()) {
      overHeadCopy("Post", [&](gpg::gal::RenderTarget& copy, const int width, const int height) {
        post.Render(copy, width, height);
      });
    }
  }

  // Shared tail, reached from the per-view loop, from the empty-list jump
  // (loc_7F9779) and from the ren_Oblivion jump (loc_7F979E) alike. The binary
  // has exactly one call to this at 0x007F97A4, after the loop rather than
  // before it.
  UpdateRenderViewportCoordinates();

  // Cartographic ("strategic"/top-down) pass. The binary calls this
  // immediately after the coordinate update and before the UI pass
  // (0x007F97AF..0x007F97B2: `push ebx; push ecx(mHead); push ebp(this);
  // call RenderCartographic`) - this call was missing from the recovered
  // body, which orphaned `Moho::Cartographic::Render` (its sole caller).
  // The return value (outline-overlay draw count) is unused by this caller,
  // matching the binary (the pushed result is never read after the call).
  {
    const gpg::gal::RenderProfileScope profileCartographic("Cartographic");
    (void)RenderCartographic(head, worldViews);
  }

  // Draw the UI control tree over the rendered viewport. The binary does this
  // at 0x007F97B7..0x007F97DD, immediately after the coordinate update and
  // before the bloom pass:
  //   cmp  ren_Ui, 0                 ; skip entirely when the UI is off
  //   mov  ecx, Moho__UI_Manager     ; and when no manager exists yet
  //   mov  eax, [ebp+215Ch]          ; mPrimBatcher.px
  //   mov  edx, [edx+40h]            ; vtable slot 16
  //   mov  eax, [ebp+320h]           ; mHead
  //   call edx                       ; CUIManager::DrawUI(head, primBatcher)
  // Slot 16 is DrawUI on the concrete CUIManager vtable at 0x00E462CC
  // (+0x40 -> 0x0084D5D0); IUIManager's own vtable is all _purecall, so the
  // slot has to be read off the derived table.
  //
  // This call was missing, and it is the whole reason the window rendered
  // black: CUIManager::RenderFrames/DrawUI were never reached, so the control
  // tree - the entire front end - was never drawn.
  if (moho::ren_Ui) {
    if (moho::IUIManager* const uiManager = moho::UI_GetManager(); uiManager != nullptr) {
      FAF_PROFILE_ZONE_NAMED("UI");
      const gpg::gal::RenderProfileScope profileDrawUi("DrawUi");
      uiManager->DrawUI(mHead, mPrimBatcher.get());
    }
  }

  // Unit-silhouette overlay. Binary (WRenViewport::Render @0x007F90D0,
  // 0x007F95EC..0x007F9614) calls it right after the UI prim-batcher pass:
  //   lea ecx, [ebp+2134h]   -> &mSilhouetteRenderer
  //   mov edi, [ebp+219Ch]   -> the camera
  //   push eax               -> the render-target index
  //
  // The binary additionally requires `var_80 == [anonymous_4 + 4]` - a
  // session-identity check between the world view being drawn and its STI map
  // (the decompiler spells it `v72 == v74->mSTImap`). Both operands are
  // per-iteration locals of the binary's world-view loop, and this pass sits
  // at outer scope here, so that half of the guard is NOT modelled yet: the
  // overlay currently draws whenever the tuning flag is on, which is a
  // superset of the binary's condition. Resolve the two locals and tighten
  // this before relying on the pass for anything but bring-up.
  if (moho::ren_UnitSilhouette) {
    mSilhouetteRenderer.Render(*mCam, mHead);
  }

  // Bloom post-process pass. Binary (the DoBloom call at 0x007F983A) gates it
  // on `!ren_Oblivion && ren_Bloom && !ren_ShowNormals` and runs it on the
  // active head's bloom renderer. The amount is the map's bloom:
  // 0x007F97DF..0x007F97FE loads sWldMap, then its terrain res, and calls
  // vtable slot 53 (+0xD4, `GetBloom`, 0x008A6BF0), falling back to 0.0f when
  // either is null. It becomes the glow-copy bias inside DoBloom.
  if (!moho::ren_Oblivion && moho::ren_Bloom && !moho::ren_ShowNormals) {
    moho::IWldTerrainRes* const bloomTerrainRes = moho::REN_GetTerrainRes();
    const float bloomAmount = bloomTerrainRes != nullptr ? bloomTerrainRes->GetBloom() : 0.0f;
    {
      const gpg::gal::RenderProfileScope profileBloom("Bloom");
      mBloomRenderers[mHead].DoBloom(bloomAmount);
    }
    // Engine addition (ren_BloomWide): a wide, soft glow from the bloom's own result, on
    // Direct3D 12 and Vulkan.
    if (moho::WideBloomRenderer& wide = moho::WideBloomRenderer::Get(mHead); !RenderAdditionsDisabled() && wide.IsActive()) {
      const gpg::gal::RenderProfileScope profileBloomWide("BloomWide");
      const moho::CBloomRenderer& bloom = mBloomRenderers[mHead];
      wide.Render(mHead, bloom.mRenderTargets[0], static_cast<int>(bloom.mWidth), static_cast<int>(bloom.mHeight));
    }
  }

  // UI-overlay + debug-HUD pass (0x007F9845), handed the same world views.
  {
    const gpg::gal::RenderProfileScope profileRenderUi("RenderUi");
    RenderUI(worldViews);
  }

  // Close the scene opened before the thumbnail pass. The binary dispatches
  // this through CD3DDevice vtable slot 34 (+0x88) right after RenderUI and
  // before the frame dump:
  //   0x007F984A  mov ecx, [esp+104h+var_E0]   ; the same device local
  //   0x007F984E  mov edx, [ecx]
  //   0x007F9850  mov eax, [edx+88h]           ; CD3DDevice::EndScene
  //   0x007F9856  call eax
  // Without it the device keeps an open scene across frames and the Present
  // that CD3DDevice::Paint issues at the head of the next paint fails with
  // D3DERR_INVALIDCALL - Present is illegal between BeginScene and EndScene.
  device->EndScene();

  // Conditionally dump the just-rendered frame to a numbered screenshot file.
  // In the binary this is the tail call of WRenViewport::Render @0x007F90D0
  // (line 375): Moho::REN_MaybeDumpFrame((ID3DRenderTarget *)viewport->mLocks1[0]),
  // where mLocks1[0] is the primary render-target writer-lock slot at +0x2164.
  // It is a no-op unless frame dumping has been armed via `dump_frameRate`.
  moho::REN_MaybeDumpFrame(mPrimaryTargetLocks[0].get());
}

/**
 * Address: 0x007F80C0 (FUN_007F80C0)
 * Mangled: ?Render@SkyDome@Moho@@QAEXHMABVGeomCamera3@2@ABV?$vector@UCumulusVertex@SkyDome@Moho@@V?$allocator@UCumulusVertex@SkyDome@Moho@@@std@@@std@@@Z
 *
 * IDA signature:
 * void __thiscall Moho::SkyDome::Render(WRenViewport *this);
 *
 * What it does:
 * Binds the active head's sky render target and viewport rectangle, resolves
 * the active terrain's SkyDome, ensures its render resources exist, then runs
 * the atmosphere, decal, cirrus, and cumulus passes for this viewport's camera.
 *
 * The PDB attributes this body to ?Render@SkyDome@Moho@@..., but the compiled
 * `this` is a WRenViewport (the body reads WRenViewport fields mHead@+0x320,
 * mScreenPos@+0x308, mScreenSize@+0x310, mCam@+0x219C, all beyond SkyDome's
 * 0x224 size). The symbol is a genuine misattribution, so the body is modeled
 * here as a WRenViewport member that drives the SkyDome render passes.
 */
void moho::WRenViewport::RenderSkyDome()
{

  moho::CD3DDevice* device = moho::D3D_GetDevice();
  device->SetRenderTarget2(mHead, false, 0, 1.0f, 0);

  device = moho::D3D_GetDevice();
  device->SetViewport(&mScreenPos, &mScreenSize, 0.0f, 1.0f);

  moho::SkyDome& skyDome = moho::REN_GetTerrainRes()->GetSkyDome();

  // The dispatcher hands the cumulus pass an empty per-cloud instance stream;
  // the producer that fills it is a separate (unrecovered) upload path.
  const fa::vector<moho::SkyDome::CumulusVertex> cumulusVertices{};

  const moho::GeomCamera3& cam = *mCam;
  const float simDeltaSeconds = moho::REN_GetSimDeltaSeconds();
  const int gameTick = moho::REN_GetGameTick();

  // loop) fires 787x per run while a probe placed immediately AFTER this call
  // fires 0x, so RenderSkyDome throws every frame and aborts the whole world
  // pass before terrain/mesh/water ever draw -- which is why the HUD renders
  // but the 3D viewport is empty. Step markers to find which call throws.

  skyDome.CreateRenderAbility();
  skyDome.RenderAtmosphere(cam);
  skyDome.RenderDecals(cam);
  skyDome.RenderCirrus(gameTick, simDeltaSeconds, cam);
  skyDome.RenderCumulus(mHead, simDeltaSeconds, cam, cumulusVertices);
}

/**
 * Address: 0x007F81C0 (FUN_007F81C0, ?RenderCompositeTerrain@WRenViewport@Moho@@AAEXPAVIRenTerrain@2@@Z)
 * Mangled: ?RenderCompositeTerrain@WRenViewport@Moho@@AAEXPAVIRenTerrain@2@@Z
 *
 * What it does:
 * Binds the active viewport render target and viewport lanes, renders terrain
 * normal-composite data with optional shadow lane, then emits terrain skirt
 * geometry for the same frame.
 */
void moho::WRenViewport::RenderCompositeTerrain(TerrainCommon* const terrain)
{
  moho::CD3DDevice* const device = moho::D3D_GetDevice();
  device->SetRenderTarget2(mHead, false, 0, 1.0f, 0);
  device->SetColorWriteState(true, false);
  SetViewportToLocalScreen();

  // The binary finishes with two virtual dispatches on the terrain:
  //   0x007F8277  mov edx, [edx+20h] / call edx   -> slot  8 DrawNormals
  //   0x007F8285  mov edx, [eax+30h] / jmp edx    -> slot 12 DrawTerrainSkirt
  // The shadow renderer is passed only when a fidelity is selected
  // (0x007F8221: cmp [esi+4F8h], 0), and the normal target is
  // mPrimaryTargetLocks[mHead], retained across the call.
  moho::Shadow* const shadowContext =
    mShadowRenderer.mShadowFidelity != 0 && !ShadowsDisabledByEnv()
      ? &mShadowRenderer
      : nullptr;

  const auto drewNormals = terrain->DrawNormals(
    moho::REN_GetGameTick(),
    moho::REN_GetSimDeltaSeconds(),
    mPrimaryTargetLocks[mHead],
    shadowContext
  );
  terrain->DrawTerrainSkirt();

  // (rectCacheCount=122..128) and the vertex upload runs, yet the viewport is
  // flat -- so the failure is at or after this composite dispatch. Report
  // whether this is even reached, what DrawNormals returned, and whether the
  // primary target lock it draws into is bound.
  {
    static int sCompositeBudget = 0;
    if (sCompositeBudget < 5) {
      ++sCompositeBudget;
      gpg::Warnf(
        "[COMPDIAG] RenderCompositeTerrain head=%d drewNormals=%d target=%p shadowCtx=%p",
        mHead, static_cast<int>(drewNormals),
        static_cast<const void*>(
          mPrimaryTargetLocks[mHead].get()),
        static_cast<const void*>(shadowContext));
    }
  }
}

/**
 * Address: 0x007F8350 (FUN_007F8350, ?RenderWaterMask@WRenViewport@Moho@@AAEXPAVIRenTerrain@2@@Z)
 * Mangled: ?RenderWaterMask@WRenViewport@Moho@@AAEXPAVIRenTerrain@2@@Z
 *
 * What it does:
 * Binds active-head water-mask render state (target + viewport), dispatches
 * terrain water-mask rendering for `(gameTick, simDeltaSeconds)`, then
 * restores full color-write state.
 */
void moho::WRenViewport::RenderWaterMask(TerrainCommon* const terrain)
{
  if (!moho::ren_Water || moho::graphics_Fidelity < 2) {
    return;
  }

  CD3DDevice* const device = moho::D3D_GetDevice();
  device->SetRenderTarget2(mHead, false, 0, 1.0f, 0);
  device->SetViewport(&mScreenPos, &mScreenSize, 0.0f, 1.0f);

  // Slot 10, dispatched straight off the terrain vptr: `mov eax, [ebx]` /
  // `mov edx, [eax+28h]` / `call edx` at 0x007F83C1-0x007F83D3, with
  // `sCurGameTick` pushed last and `sDeltaFrame` stored as a float in the
  // slot above it. There is no fidelity test here in the binary -- this used
  // to be a three-way `dynamic_cast` chain only because `DrawWaterLine` was
  // not declared on the base, so it had no slot to dispatch through.
  terrain->DrawWaterLine(moho::REN_GetGameTick(), moho::REN_GetSimDeltaSeconds());

  device->SetColorWriteState(true, true);
}

/**
 * Address: 0x007F83F0 (FUN_007F83F0, ?RenderCopyForRefraction@WRenViewport@Moho@@AAEXXZ)
 * Mangled: ?RenderCopyForRefraction@WRenViewport@Moho@@AAEXXZ
 *
 * What it does:
 * Copies the active writer-lock render target into the retained refraction
 * background slot, optionally clamped to the viewport's local-screen rect.
 */
void moho::WRenViewport::RenderCopyForRefraction(const bool clampToViewportRect)
{
  if (moho::graphics_Fidelity < 2) {
    return;
  }

  moho::CD3DDevice* const device = moho::D3D_GetDevice();

  boost::shared_ptr<moho::ID3DRenderTarget> sourceLock{};
  device->GetWriterLock1(sourceLock, mHead);

  boost::shared_ptr<moho::ID3DRenderTarget> destinationLock =
    mPrimaryTargetLocks[mHead];

  RECT sourceRect{};
  sourceRect.left = mScreenPos.x;
  sourceRect.top = mScreenPos.y;
  sourceRect.right = mScreenPos.x + mScreenSize.x;
  sourceRect.bottom = mScreenPos.y + mScreenSize.y;

  device->SetViewRect(
    sourceLock.get(),
    destinationLock.get(),
    clampToViewportRect ? &sourceRect : nullptr,
    nullptr
  );
}

/**
 * Address: 0x007F8290 (FUN_007F8290, Moho::WRenViewport::RenderMeshes)
 *
 * What it does:
 * Sets the render target, viewport, and color-write state for one viewport
 * mesh pass, then dispatches either skeleton-debug rendering or the normal
 * mesh batch renderer depending on `ren_ShowSkeletons`.
 */
void moho::WRenViewport::RenderMeshes(const int meshFlags, const bool mirrored)
{
  moho::GeomCamera3* const cam = mCam;
  moho::CD3DDevice* const device = moho::D3D_GetDevice();
  device->SetRenderTarget2(mHead, false, 0, 1.0f, 0);
  SetViewportToLocalScreen();
  device->SetColorWriteState(true, true);

  moho::Shadow* const shadowRenderer = mShadowRenderer.mShadowFidelity != 0 && !ShadowsDisabledByEnv()
    ? &mShadowRenderer
    : nullptr;

  moho::MeshRenderer* const instance = moho::MeshRenderer::GetInstance();
  if (moho::ren_ShowSkeletons) {
    instance->RenderSkeletons(
      mPrimBatcher.get(),
      &mDebugCanvas,
      *cam,
      true
    );
    return;
  }

  instance->Render(meshFlags, *cam, shadowRenderer, instance->meshes);
  (void)mirrored;
}

/**
 * Address: 0x007F8600 (FUN_007F8600, ?RenderRefractingEffects@WRenViewport@Moho@@AAEXXZ)
 * Mangled: ?RenderRefractingEffects@WRenViewport@Moho@@AAEXXZ
 *
 * IDA signature:
 * void __thiscall Moho::WRenViewport::RenderRefractingEffects(Moho::WRenViewport *this);
 *
 * What it does:
 * When FX are enabled and graphics fidelity is medium or higher, copies the
 * current writer-lock into the refraction background slot, rebinds the
 * active head's render target + local viewport, switches to color-only
 * writes, then dispatches `CWorldParticles::RenderRefractingEffects` with
 * the retained refraction-background texture pointer and the current game
 * tick/sim delta.
 */
void moho::WRenViewport::RenderRefractingEffects()
{
  if (!moho::ren_Fx || moho::graphics_Fidelity < 2) {
    return;
  }

  RenderCopyForRefraction(true);

  moho::CD3DDevice* const device = moho::D3D_GetDevice();
  device->SetRenderTarget2(mHead, false, 0, 1.0f, 0);
  device->SetViewport(&mScreenPos, &mScreenSize, 0.0f, 1.0f);
  device->SetColorWriteState(true, false);

  // The refraction background is the head's primary render target, passed
  // straight through. CWorldParticles::RenderRefractingEffects binds it with
  // the render-target binder at 0x00491280, so no cast is involved - the
  // decompiler's {px, pn.pi_} copy is just a shared_ptr copy.
  moho::sWorldParticles.RenderRefractingEffects(
    mCam,
    moho::REN_GetGameTick(),
    moho::REN_GetSimDeltaSeconds(),
    mPrimaryTargetLocks[mHead]
  );
}

/**
 * Address: 0x007F8560 (FUN_007F8560, Moho::WRenViewport::RenderEffects)
 *
 * What it does:
 * Binds the viewport render target and viewport lanes for the active head,
 * configures color writes for FX, then renders world-particle effects.
 */
void moho::WRenViewport::RenderEffects(const bool renderWaterSurface)
{
  if (!moho::ren_Fx) {
    return;
  }

  moho::CD3DDevice* const device = moho::D3D_GetDevice();
  device->SetRenderTarget2(mHead, false, 0, 1.0f, 0);
  SetViewportToLocalScreen();
  device->SetColorWriteState(true, false);

  (void)moho::sWorldParticles.RenderEffects(
    mCam,
    static_cast<char>(renderWaterSurface ? 1 : 0),
    0,
    moho::REN_GetGameTick(),
    moho::REN_GetSimDeltaSeconds()
  );
}

/**
 * Address: 0x007F86F0 (FUN_007F86F0, ?RenderWater@WRenViewport@Moho@@AAEXPAVIRenTerrain@2@@Z)
 * Mangled: ?RenderWater@WRenViewport@Moho@@AAEXPAVIRenTerrain@2@@Z
 *
 * What it does:
 * Binds the active viewport head to the water render target, restores the
 * viewport rectangle, and forwards the current frame lanes to terrain water
 * rendering.
 */
void moho::WRenViewport::RenderWater(TerrainCommon* const terrain)
{
  if (!moho::ren_Water) {
    return;
  }

  moho::CD3DDevice* const device = moho::D3D_GetDevice();
  device->SetRenderTarget2(mHead, false, 0, 1.0f, 0);
  SetViewportToLocalScreen();
  device->SetColorWriteState(true, true);

  // Slot 11. The two render targets are retained by value across the call
  // (0x007F86F0 builds both shared_ptr temporaries before the dispatch):
  // refraction from mPrimaryTargetLocks[head], reflection from
  // mSecondaryTargetLocks[head].
  const std::int32_t head = mHead;
  terrain->DrawWaterTerrain(
    moho::REN_GetGameTick(),
    moho::REN_GetSimDeltaSeconds(),
    mPrimaryTargetLocks[head],
    mSecondaryTargetLocks[head]
  );
}

/**
 * Address: 0x007F7DF0 (FUN_007F7DF0, ?RenderReflections@WRenViewport@Moho@@AAEXXZ)
 *
 * What it does:
 * Binds reflection render-target/depth lanes for the active head slot and,
 * when enabled, renders reflection meshes through `MeshRenderer`.
 */
void moho::WRenViewport::RenderReflections()
{
  if (!moho::ren_Water) {
    return;
  }

  moho::CD3DDevice* const colorDevice = moho::D3D_GetDevice();
  moho::CD3DDevice* const targetDevice = moho::D3D_GetDevice();
  const std::size_t reflectionIndex = static_cast<std::size_t>(mHead);
  targetDevice->SetRenderTarget1(
    mSecondaryTargetLocks[reflectionIndex].get(),
    mDepthStencilLocks[reflectionIndex].get(),
    true,
    0,
    1.0f,
    0
  );

  // TEMPORARY: FAF_NO_REFLECTION=1 skips the mirrored mesh pass (black-wedge
  // triage). Also report, once, whether the reflection target actually exists:
  // a null target here would leave the back buffer bound and paint the
  // mirrored meshes straight onto the scene.
  static const bool sReflectionDisabled = [] {
    std::size_t length = 0u;
    char value[8] = {};
    return ::getenv_s(&length, value, sizeof(value), "FAF_NO_REFLECTION") == 0 && length != 0u && value[0] == '1';
  }();
  {
    static int sReflBudget = 0;
    if (sReflBudget < 2) {
      ++sReflBudget;
      char probe[160];
      (void)std::snprintf(probe, sizeof(probe), "[REFLDIAG] head=%d rt=%p ds=%p ren_Reflection=%d\n",
                          static_cast<int>(reflectionIndex),
                          static_cast<const void*>(mSecondaryTargetLocks[reflectionIndex].get()),
                          static_cast<const void*>(mDepthStencilLocks[reflectionIndex].get()),
                          moho::ren_Reflection ? 1 : 0);
      ::OutputDebugStringA(probe);
    }
  }
  if (!moho::ren_Reflection || sReflectionDisabled) {
    RenderWaterBodyReflection(false);
    return;
  }
  SetViewportToLocalScreen();
  colorDevice->SetColorWriteState(true, true);

  moho::MeshRenderer* const renderer = moho::MeshRenderer::GetInstance();
  renderer->Render(2, *mCam, nullptr, renderer->meshes);

  RenderWaterBodyReflection(true);
}

namespace
{
  /// Engine addition (water bodies): a head's lake reflection and the cleared target other lakes sample.
  struct SWaterBodyReflection
  {
    boost::shared_ptr<moho::CD3DRenderTarget> body;
    boost::shared_ptr<moho::CD3DRenderTarget> empty;
    boost::shared_ptr<moho::CD3DDepthStencil> emptyDepth;
    int width = 0;
    int height = 0;
  };
  std::array<SWaterBodyReflection, 2> sWaterBodyReflections;

  /**
   * The wet body most seen through a 5 x 5 grid of view rays, ties to the one nearer the
   * centre; 0 when the rays see none.
   */
  [[nodiscard]] std::uint8_t MostVisibleWaterBody(const moho::GeomCamera3& camera, const moho::STIMap& map)
  {
    const moho::CWaterBodies& bodies = *map.mWaterBodies;
    std::array<std::int32_t, 256> score{};
    for (std::int32_t row = 0; row < 5; ++row) {
      for (std::int32_t column = 0; column < 5; ++column) {
        const Wm3::Vector2f point{0.1f + 0.2f * static_cast<float>(column), 0.1f + 0.2f * static_cast<float>(row)};
        const moho::GeomLine3 ray = camera.Unproject(point, 0.0f, 1.0f, 0.0f, 1.0f);
        const Wm3::Vec3f hit = map.SurfaceIntersection(ray, nullptr);
        if (!Wm3::Vec3f::IsntNaN(hit)) {
          continue;
        }
        const std::uint8_t number = bodies.BodyOfCell(static_cast<std::int32_t>(hit.x), static_cast<std::int32_t>(hit.z));
        if (number != 0u && bodies.Body(number).elevation != moho::kWaterBodyNoWater) {
          // 4 for each hit, plus 1 more the nearer the ray is to the centre (at most 2 away).
          score[number] += 4 + (2 - std::max(std::abs(row - 2), std::abs(column - 2)));
        }
      }
    }
    std::uint8_t best = 0u;
    for (std::size_t number = 1; number < score.size(); ++number) {
      if (score[number] > score[best]) {
        best = static_cast<std::uint8_t>(number);
      }
    }
    return score[best] > 0 ? best : 0u;
  }
} // namespace

/**
 * Engine addition (water bodies, .plans/water-levels/PLAN.md). The planar reflection is mirrored
 * at the sea, so a lake at another level would show units mirrored at the sea. When the map has
 * bodies this renders the meshes once more, mirrored at the level of the lake the view sees most,
 * into a target of its own, and clears a small target for every other lake to sample (so they
 * reflect the sky). `WaterBodySurfaces::ReflectionFor` hands each lake its target. Without bodies
 * it does nothing.
 */
void moho::WRenViewport::RenderWaterBodyReflection(const bool meshes)
{
  const std::size_t head = static_cast<std::size_t>(mHead);
  moho::IWldTerrainRes* const terrainRes = moho::REN_GetTerrainRes();
  const moho::STIMap* const map = terrainRes != nullptr ? terrainRes->mMap : nullptr;
  if (map == nullptr || !map->HasWaterBodies() || head >= sWaterBodyReflections.size()) {
    moho::WaterBodySurfaces::SetBodyReflection(false, 0.0f, {}, {});
    return;
  }

  moho::CD3DDevice* const device = moho::D3D_GetDevice();
  SWaterBodyReflection& targets = sWaterBodyReflections[head];
  const int width = device->GetHeadWidth(mHead);
  const int height = device->GetHeadHeight(mHead);
  moho::ID3DDeviceResources* const resources = device->GetResources();
  if (!targets.empty || !targets.emptyDepth) {
    resources->CreateRenderTarget(targets.empty, 4, 4, kViewportHeadTargetFormat);
    resources->CreateDepthStencil(targets.emptyDepth, 4, 4, kViewportHeadDepthStencilFormat);
  }
  if (!targets.body || targets.width != width || targets.height != height) {
    targets.body.reset();
    resources->CreateRenderTarget(targets.body, width, height, kViewportHeadTargetFormat);
    targets.width = width;
    targets.height = height;
  }

  if (!targets.empty || !targets.emptyDepth || !mDepthStencilLocks[head]) {
    moho::WaterBodySurfaces::SetBodyReflection(false, 0.0f, {}, {});
    return;
  }
  device->SetRenderTarget1(targets.empty.get(), targets.emptyDepth.get(), true, 0, 1.0f, 0);

  const std::uint8_t body = meshes ? MostVisibleWaterBody(*mCam, *map) : 0u;
  if (body == 0u || !targets.body) {
    moho::WaterBodySurfaces::SetBodyReflection(false, 0.0f, targets.body, targets.empty);
    return;
  }
  const float level = map->mWaterBodies->Body(body).elevation;
  device->SetRenderTarget1(targets.body.get(), mDepthStencilLocks[head].get(), true, 0, 1.0f, 0);
  SetViewportToLocalScreen();
  device->SetColorWriteState(true, true);
  moho::MESH_SetMirrorElevation(true, level);
  moho::MeshRenderer* const renderer = moho::MeshRenderer::GetInstance();
  renderer->Render(2, *mCam, nullptr, renderer->meshes);
  moho::MESH_SetMirrorElevation(false, 0.0f);
  moho::WaterBodySurfaces::SetBodyReflection(true, level, targets.body, targets.empty);
}

void moho::WRenViewport::ReleaseWaterBodyReflections()
{
  for (SWaterBodyReflection& targets : sWaterBodyReflections) {
    targets = SWaterBodyReflection{};
  }
  moho::WaterBodySurfaces::SetBodyReflection(false, 0.0f, {}, {});
}

/**
 * Address: 0x007F7ED0 (FUN_007F7ED0, ?SetViewportToFullScreen@WRenViewport@Moho@@AAEXXZ)
 *
 * What it does:
 * Applies a full-head viewport rectangle (`(0,0)` to `mFullScreen`) to the
 * active D3D device viewport state.
 */
void moho::WRenViewport::SetViewportToFullScreen()
{
  moho::CD3DDevice* const device = moho::D3D_GetDevice();
  Wm3::Vector2i screenOrigin{0, 0};
  device->SetViewport(&screenOrigin, &mFullScreen, 0.0f, 1.0f);
}

/**
 * Address: 0x007F7EA0 (FUN_007F7EA0, ?SetViewportToLocalScreen@WRenViewport@Moho@@AAEXXZ)
 *
 * What it does:
 * Applies this viewport's cached local-screen rectangle to the active D3D
 * device viewport state.
 */
void moho::WRenViewport::SetViewportToLocalScreen()
{
  moho::CD3DDevice* const device = moho::D3D_GetDevice();
  device->SetViewport(&mScreenPos, &mScreenSize, 0.0f, 1.0f);
}

/**
 * Address: 0x007F87F0 (FUN_007F87F0, ?UpdateRenderViewportCoordinates@WRenViewport@Moho@@AAEXXZ)
 * Mangled: ?UpdateRenderViewportCoordinates@WRenViewport@Moho@@AAEXXZ
 *
 * What it does:
 * Refreshes full-head dimensions and local viewport lanes from the active
 * camera's viewport matrix row when a camera is present, else falls back to
 * the full-head rectangle.
 */
void moho::WRenViewport::UpdateRenderViewportCoordinates()
{

  moho::CD3DDevice* const widthDevice = moho::D3D_GetDevice();
  const int headWidth = widthDevice->GetHeadWidth(static_cast<unsigned int>(mHead));
  moho::CD3DDevice* const heightDevice = moho::D3D_GetDevice();
  const int headHeight = heightDevice->GetHeadHeight(static_cast<unsigned int>(mHead));
  mFullScreen.x = headWidth;
  mFullScreen.y = headHeight;

  moho::GeomCamera3* const camera = mCam;
  if (camera != nullptr) {
    mScreenPos.x = static_cast<int>(camera->viewport.r[3].x);
    mScreenPos.y = static_cast<int>(camera->viewport.r[3].y);
    mScreenSize.x = static_cast<int>(camera->viewport.r[3].z);
    mScreenSize.y = static_cast<int>(camera->viewport.r[3].w);
    return;
  }

  mScreenSize.x = headWidth;
  mScreenSize.y = mFullScreen.y;
  mScreenPos.x = 0;
  mScreenPos.y = 0;
}
namespace
{
  [[nodiscard]] std::uint8_t ClampFogColorChannel(const float value) noexcept
  {
    const int scaled = static_cast<int>(value * 255.0f);
    if (scaled <= 0) {
      return 0u;
    }
    if (scaled >= 255) {
      return 255u;
    }
    return static_cast<std::uint8_t>(scaled);
  }

  [[nodiscard]] std::uint32_t PackFogColorArgb255(const moho::SFogInfo& fogInfo) noexcept
  {
    const std::uint32_t red = ClampFogColorChannel(fogInfo.mStartDistance);
    const std::uint32_t green = ClampFogColorChannel(fogInfo.mCutoffDistance);
    const std::uint32_t blue = ClampFogColorChannel(fogInfo.mMinClamp);
    return 0xFF000000u | (red << 16u) | (green << 8u) | blue;
  }
}


/**
 * Address: 0x007F8A30 (FUN_007F8A30, ?FogOn@WRenViewport@Moho@@AAEXM@Z)
 * Mangled: ?FogOn@WRenViewport@Moho@@AAEXM@Z
 *
 * What it does:
 * Enables fog using active terrain fog lanes and one caller-provided distance
 * offset multiplier.
 */
void moho::WRenViewport::FogOn(const float offsetMultiplier)
{
  const moho::SFogInfo& fogInfo = moho::REN_GetTerrainRes()->GetFogInfo();
  const float fogOffset = moho::fog_OffsetMultiplier * offsetMultiplier;
  gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
  if (!moho::fog_DistanceFog) {
    device->SetFogState(false, nullptr, 0.0f, 1.0f, 0);
    // FAF: see below.
    moho::MeshRenderer::SetDistanceFog(false, nullptr, 0.0f, 1.0f, 0u);
    return;
  }

  const float fogStart = fogInfo.mMaxClamp + fogOffset;
  const float fogEnd = fogInfo.mCurveExponent + fogOffset;
  const std::uint32_t fogColor = PackFogColorArgb255(fogInfo);
  device->SetFogState(true, &mCam->projection, fogStart, fogEnd, static_cast<int>(fogColor));

  // FAF: a mesh effect compiled with FAF_BONE_TEXTURE runs shader model 3
  // pixel shaders, which this fixed-function fog does not reach, so they fog
  // themselves with the same values.
  moho::MeshRenderer::SetDistanceFog(true, &mCam->projection, fogStart, fogEnd, fogColor);
}

/**
 * Address: 0x007F8B70 (FUN_007F8B70, ?FogOff@WRenViewport@Moho@@AAEXXZ)
 * Mangled: ?FogOff@WRenViewport@Moho@@AAEXXZ
 *
 * What it does:
 * Disables fog on the active GAL D3D9 device with default depth range
 * (`0.0f..1.0f`) and zero fog color lanes.
 */
void moho::WRenViewport::FogOff()
{
  gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
  device->SetFogState(false, nullptr, 0.0f, 1.0f, 0);

  // FAF: the shader model 3 mesh pixel shaders stop fogging too (see FogOn).
  moho::MeshRenderer::SetDistanceFog(false, nullptr, 0.0f, 1.0f, 0u);
}

/**
 * Address: 0x007F7F10 (FUN_007F7F10, ?RenderTerrainNormals@WRenViewport@Moho@@AAEXPAVIRenTerrain@2@@Z)
 * Mangled: ?RenderTerrainNormals@WRenViewport@Moho@@AAEXPAVIRenTerrain@2@@Z
 *
 * What it does:
 * Binds the viewport's terrain-normal render target and viewport lanes, then
 * dispatches terrain-normal rendering when terrain debug rendering is enabled.
 */
void moho::WRenViewport::RenderTerrainNormals(TerrainCommon* const terrain)
{
  // Guard is ren_Terrain, not a null-terrain test: 0x007F7F11
  // `cmp ren_Terrain, 0 / jz loc_7F7FB5`. The caller checks both.
  if (!moho::ren_Terrain) {
    return;
  }

  moho::CD3DDevice* const device = moho::D3D_GetDevice();
  gpg::gal::Device* const d3dDevice = device->GetGalDevice();
  if (d3dDevice != nullptr) {
    (void)d3dDevice->ClearTextures();
  }

  // This pass fills the off-screen terrain-normal buffer, which
  // TransformTerrainNormals then samples as mSecondaryTargetLocks[head]
  // for its TCreateBasis pass - it must not draw into the head's
  // backbuffer. The binary loads the pair through one scaled base:
  //   0x007F7F42  mov ecx, [esi+320h]        ; mHead
  //   0x007F7F58  lea eax, [esi+ecx*8]       ; 8-byte shared_ptr stride
  //   0x007F7F5B  mov ecx, [eax+2184h]       ; mDepthStencilLocks[head]
  //   0x007F7F61  mov eax, [eax+2174h]       ; mSecondaryTargetLocks[head]
  // and dispatches SetRenderTarget1 through vtable slot 32 ([edx+80h]).
  const std::int32_t head = mHead;
  device->SetRenderTarget1(
    mSecondaryTargetLocks[head].get(),
    mDepthStencilLocks[head].get(),
    true,
    0,
    1.0f,
    0
  );
  SetViewportToLocalScreen();

  // Slot 9 fills the buffer bound above (0x007F7FA5, call through the
  // terrain vtable). Low fidelity keeps it an empty hook; medium and high
  // walk the normal-map tiles.
  terrain->DrawTerrainNormal(moho::REN_GetGameTick(), moho::REN_GetSimDeltaSeconds());
}

/**
 * Address: 0x007F7FC0 (FUN_007F7FC0, ?TransformTerrainNormals@WRenViewport@Moho@@AAEXXZ)
 * Mangled: ?TransformTerrainNormals@WRenViewport@Moho@@AAEXXZ
 *
 * What it does:
 * Builds and renders the terrain-normal basis frame (`TCreateBasis`) for the
 * active head when terrain rendering is enabled.
 *
 * Uses the viewport's one scratch frame, `mFrame` (+0x280) - the same object
 * `Render`'s opaque pass relabels "TOpaque". An earlier revision used a
 * fabricated frame at +0x2280, 0x2000 bytes past the real one and past the
 * end of the 0x21A8-byte viewport. Nothing constructed it, so its
 * mVertexSheet held heap garbage and CRenFrame::InitTransformedVerts faulted
 * on the first painted frame (main.exe /map SCMP_009 under dbgrun).
 */
void moho::WRenViewport::TransformTerrainNormals()
{
  if (!moho::ren_Terrain) {
    return;
  }

  moho::CD3DDevice* const device = moho::D3D_GetDevice();
  if (gpg::gal::Device* const d3dDevice = device->GetGalDevice(); d3dDevice != nullptr) {
    (void)d3dDevice->ClearTextures();
  }

  const std::int32_t head = mHead;
  device->SetRenderTarget1(
    mPrimaryTargetLocks[head].get(),
    mDepthStencilLocks[head].get(),
    false,
    0,
    1.0f,
    0
  );

  const int headWidth = device->GetHeadWidth(static_cast<unsigned int>(head));
  const int headHeight = device->GetHeadHeight(static_cast<unsigned int>(head));
  mFrame.mName = "TCreateBasis";
  mFrame.InitTransformedVerts(static_cast<float>(headWidth), static_cast<float>(headHeight));
  mFrame.SetTexture(0u, mSecondaryTargetLocks[head]);
  mFrame.Render(headWidth, headHeight);
}

/**
 * Address: 0x007F3F20 (FUN_007F3F20, func_ren_BandwidthUsage_Line)
 *
 * What it does:
 * Draws outbound/inbound bandwidth samples as two connected line strips.
 */
void moho::REN_DrawBandwidthUsageLinePair(
  CD3DPrimBatcher& primBatcher,
  const SBandwidthUsageSeries& series,
  const std::int32_t xOffset,
  const std::int32_t yBase,
  const float yScale,
  const std::uint32_t inboundColor,
  const std::uint32_t outboundColor
)
{
  const std::uint32_t sampleCount = series.SampleCount();
  if (sampleCount == 0u) {
    return;
  }

  CD3DPrimBatcher::Vertex previousOutbound{};
  CD3DPrimBatcher::Vertex previousInbound{};
  bool hasPrevious = false;

  for (std::uint32_t sampleIndex = 0; sampleIndex < sampleCount; ++sampleIndex) {
    const SBandwidthUsageSample& sample = series.samples[sampleIndex];
    const float x = static_cast<float>(xOffset + static_cast<std::int32_t>(sampleIndex));

    CD3DPrimBatcher::Vertex currentOutbound{};
    currentOutbound.mX = x;
    currentOutbound.mY = static_cast<float>(yBase) - (sample.outboundBytesPerSec * yScale);
    currentOutbound.mZ = 0.0f;
    currentOutbound.mColor = outboundColor;
    currentOutbound.mU = 0.0f;
    currentOutbound.mV = 0.0f;

    CD3DPrimBatcher::Vertex currentInbound{};
    currentInbound.mX = x;
    currentInbound.mY = static_cast<float>(yBase) - (sample.inboundBytesPerSec * yScale);
    currentInbound.mZ = 0.0f;
    currentInbound.mColor = inboundColor;
    currentInbound.mU = 0.0f;
    currentInbound.mV = 0.0f;

    if (hasPrevious) {
      primBatcher.DrawLine(previousOutbound, currentOutbound);
      primBatcher.DrawLine(previousInbound, currentInbound);
    }

    previousOutbound = currentOutbound;
    previousInbound = currentInbound;
    hasPrevious = true;
  }
}
