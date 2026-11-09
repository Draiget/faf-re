#include "moho/ui/CUIManager.h"
#include "gpg/core/profiling/Profiler.h"

#include <Windows.h>

#include <algorithm>
#include <cstdint>
#include <new>
#include <vector>

#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "lua/LuaObject.h"
#include "lua/LuaIncrementalGc.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/Stats.h"
#include "moho/render/d3d/CD3DPrimBatcher.h"
#include "moho/console/TConVarbool.h"
#include "moho/app/UserWorkerPool.h"

namespace moho
{
  bool ui_ParallelMark = true;
  TConVar<bool> gTConVar_ui_ParallelMark(
    "ui_ParallelMark",
    "Mark UI Lua objects on CUserWorkerPool worker threads during garbage collection.",
    &ui_ParallelMark
  );

  bool ui_ParallelSweep = true;
  TConVar<bool> gTConVar_ui_ParallelSweep(
    "ui_ParallelSweep",
    "Sweep UI Lua objects on CUserWorkerPool worker threads during garbage collection.",
    &ui_ParallelSweep
  );

  bool ui_IdleGC = true;
  TConVar<bool> gTConVar_ui_IdleGC(
    "ui_IdleGC",
    "Defer periodic UI Lua GC to the post-present frame idle window.",
    &ui_IdleGC
  );

  static bool sPendingUiGc = false;
  static bool sIncrementalCycleDue = false;

  struct UserGcDispatcherRegistrar
  {
    UserGcDispatcherRegistrar()
    {
      RegisterUserGcDispatcher({
        [](std::size_t count, std::size_t grain, void (*fn)(void*, std::size_t, std::size_t), void* context) {
          CUserWorkerPool::Get().Run(count, grain, fn, context);
        },
        // Off the main thread (the scenario loader's blueprint state) the collection runs
        // serially: it would share the pool and the GC's user-side scratch with the UI's.
        []() { return CUserWorkerPool::IsDispatcherThread() ? CUserWorkerPool::ConfiguredWorkerCount() : 0u; },
        &ui_ParallelMark,
        &ui_ParallelSweep
      });
    }
  } gUserGcDispatcherRegistrar;
}

namespace
{

  /**
   * Frames whose owning reference was dropped while a MAUI event was being
   * dispatched. Released by `ReleaseRetiredFrames` on the next UI tick.
   */
  std::vector<boost::shared_ptr<moho::CMauiFrame>> gRetiredFrames;

  /**
   * Pacing state for the incremental (5.1-style) Lua collector that the UI VM
   * drives once per frame. `sGcWindowFrames` / `sGcWindowSeconds` measure the
   * real frame rate over the current five-second window; `sGcSecondsPerFrame`
   * keeps the last completed measurement (a conservative 30 FPS default until
   * the first window closes).
   */
  int sGcWindowFrames = 0;
  float sGcWindowSeconds = 0.0f;
  float sGcSecondsPerFrame = 1.0f / 30.0f;

  /**
   * Work budget for one incremental-GC slice, in 5.1 singlestep work units.
   *
   * Units. The collector's work unit is one byte of object payload touched by
   * the mark phase (`IncrPropagateMark` returns `sizeof(Table) + payload`, so a
   * full mark phase of a heap costs about as many units as the heap has bytes)
   * plus a small sweep overhead (10 units per swept object) and 100 units per
   * finalizer. `global_State::nblocks` is the number of bytes the VM has
   * allocated, so it is the natural scale for "how much work is one cycle".
   *
   * Formula. A cycle must fit into the five-second window in which the shipped
   * collector would have run (the UI forces a cycle every five seconds), so the
   * per-cycle work is spread over the frames of that window:
   *
   *   cycleWork = (heapBytes + debtBytes) * 2
   *   budget    = cycleWork * (secondsPerFrame / 5 s)
   *
   * The factor 2 covers the sweep and finalizer overhead on top of the mark
   * phase (mark ~= heapBytes). `debtBytes` is the allocation debt past the
   * pause threshold (`nblocks - GCthreshold`, or the collector's own
   * `gcdebt` when it is larger): a heap that grew a lot since the last cycle
   * gets proportionally more work per frame, so the debt is paid down at the
   * same rate as it accumulates.
   *
   * Because the budget is derived from the measured frame time, the total work
   * per five-second window is frame-rate independent: `budget * frames =
   * cycleWork`, and `frames = 5 s / secondsPerFrame`. A cycle therefore
   * completes inside one five-second window at any frame rate, while a single
   * frame never does more than its proportional share of it.
   *
   * Bounds. The minimum keeps the previous fixed 512 units for small heaps
   * (a heap of a few hundred KB needs far less than 512 units per frame to
   * keep up), and the maximum caps a single frame at 65536 units (~64 KB of
   * mark traversal, tens of microseconds) so a huge heap cannot stall a frame;
   * a heap too large for the cap simply finishes its cycle over more than one
   * five-second window instead of hitching the frame.
   */
  int ComputeIncrementalGcWorkBudget(global_State* const g)
  {
    constexpr int kMinWork = 512;
    constexpr int kMaxWork = 65536;
    constexpr double kCycleSeconds = 5.0;
    constexpr double kWorkPerHeapByte = 2.0;

    if (g == nullptr) {
      return kMinWork;
    }

    const lu_mem heapBytes = g->nblocks;
    const lu_mem thresholdBytes = g->GCthreshold;
    const lu_mem thresholdDebt =
      (heapBytes > thresholdBytes) ? (heapBytes - thresholdBytes) : static_cast<lu_mem>(0);

    // The collector's own debt (bytes allocated past the pause threshold) is
    // only maintained by the allocation-driven path; take the larger of the two
    // so a burst of allocations is paid down faster.
    lu_mem debtBytes = thresholdDebt;
    if (const moho::lua_incremental::SState* const incremental =
          moho::lua_incremental::Find(g);
        incremental != nullptr && incremental->gcdebt > debtBytes) {
      debtBytes = incremental->gcdebt;
    }

    const double effectiveBytes =
      static_cast<double>(heapBytes) + static_cast<double>(debtBytes);
    const double cycleWork = effectiveBytes * kWorkPerHeapByte;
    const double perFrameWork =
      cycleWork * (static_cast<double>(sGcSecondsPerFrame) / kCycleSeconds);

    int budget = static_cast<int>(perFrameWork);
    if (budget < kMinWork) {
      budget = kMinWork;
    } else if (budget > kMaxWork) {
      budget = kMaxWork;
    }
    return budget;
  }

  /**
   * Address: 0x0084E6F0 (FUN_0084E6F0, funcReleaseRange_WeakPtrFrame)
   *
   * What it does:
   * Releases one half-open range of `boost::shared_ptr<CMauiFrame>` elements.
   */
  void ReleaseFrameSharedPtrRange(
    boost::shared_ptr<moho::CMauiFrame>* begin,
    boost::shared_ptr<moho::CMauiFrame>* end
  )
  {
    // Dropping the last owner here runs ~CMauiFrame inline. That is safe on a
    // tick, but not from script: `SetNewLuaState` is reached from Lua - the
    // splash calls EngineStartFrontEndUI from a control's HandleEvent - and the
    // event dispatch that got us there still holds raw pointers into this
    // frame. `CMauiControl::PostEvent` reads a control's parent *before* running
    // the handler and dispatches to it *after*, so freeing the frame here makes
    // that dispatch a virtual call through a released object. ~CMauiFrame would
    // also delete the wx event mapper whose method is currently on the stack.
    //
    // The engine already defers control deletes for exactly this reason
    // (`Destroy` queues, `PurgeDeleted` frees on the tick); frames are the one
    // owner that escaped it, because they are held by shared_ptr rather than the
    // deleted-control list. Park the owning reference and drop it on the next
    // tick. The frames are already destroyed and unhooked by then - only the
    // `operator delete` moves.
    const bool deferDelete = moho::MAUI_EventDispatchInProgress();
    for (boost::shared_ptr<moho::CMauiFrame>* it = begin; it != end; ++it) {
      if (deferDelete && *it) {
        gRetiredFrames.push_back(*it);
      }
      it->reset();
    }
  }

  /**
   * Drops every frame parked by `ReleaseFrameSharedPtrRange`. Called at the top
   * of the UI tick, where no event dispatch is on the stack.
   */
  void ReleaseRetiredFrames()
  {
    // Swap first: ~CMauiFrame runs script (`OnDestroy` on any control still
    // queued) and must not mutate the container being iterated.
    std::vector<boost::shared_ptr<moho::CMauiFrame>> retired;
    retired.swap(gRetiredFrames);
  }

  /**
   * Address: 0x00796F30 (FUN_00796F30, boost::shared_ptr<Moho::CMauiFrame>::shared_ptr(CMauiFrame*))
   *
   * What it does:
   * Constructs one `boost::shared_ptr<CMauiFrame>` from one raw frame pointer
   * in caller-provided storage.
   */
  [[maybe_unused]] boost::shared_ptr<moho::CMauiFrame>* ConstructSharedFrameFromRaw(
    boost::shared_ptr<moho::CMauiFrame>* const outSharedFrame,
    moho::CMauiFrame* const rawFrame
  )
  {
    if (outSharedFrame == nullptr) {
      return nullptr;
    }

    return ::new (outSharedFrame) boost::shared_ptr<moho::CMauiFrame>(rawFrame);
  }

  [[nodiscard]] bool IsValidFrameIndex(const moho::CUIManager& manager, const int frameIdx)
  {
    return frameIdx >= 0 && static_cast<std::size_t>(frameIdx) < manager.mFrames.Size();
  }

  /**
   * Republishes the whole engine-statistics tree as the `__EngineStats` global.
   *
   * `STAT_GetLuaTable` is the recursive serializer: it assigns the node's own
   * table, fills in `Name`/`Value` through `StatItem::ToLua`, and then emits a
   * `Children` array holding one such table per child. Calling `ToLua` directly
   * here instead produced a root node with no `Children` at all, which is what
   * `/lua/system/performance.lua:711` walks - `for k, stat in
   * engineStats.Children do` raised "attempt to loop over field `Children' (a
   * nil value)" on every UI tick.
   */
  void PublishEngineStatsToLua(LuaPlus::LuaState* const state)
  {
    if (state == nullptr) {
      return;
    }

    // Built before the globals lookup, as the binary does: the serializer takes
    // the stat tree's lock and can run script-visible allocation.
    LuaPlus::LuaObject engineStatsTable{};
    moho::STAT_GetLuaTable(state, moho::GetEngineStats()->mItem.get(), engineStatsTable);

    LuaPlus::LuaObject globals = state->GetGlobals();
    globals.SetObject("__EngineStats", engineStatsTable);
  }
} // namespace

/**
 * Address: 0x0084C9C0 (FUN_0084C9C0)
 *
 * What it does:
 * Initializes inline-storage vectors, cursor-link state, and defaults.
 */
moho::CUIManager::CUIManager()
  : mUnknown04(0)
  , mFrames()
  , mCursor()
  , mLuaState(nullptr)
  , mUnknown34(0)
  , mInputWindows()
  , mHostWindows()
  , mUIControlsAlpha(1.0f)
  , mUnknown6C(0.0f)
  , mGCTime(0.0f)
  , mUnknown74(0)
{
}

/**
 * Address: 0x0084CA30 (FUN_0084CA30)
 *
 * What it does:
 * Core UI-manager teardown for cursor-link and frame shared-ownership lanes.
 */
void moho::CUIManager::DestroyCore()
{
  mCursor.ResetFromObject(nullptr);

  if (!mFrames.Empty()) {
    ReleaseFrameSharedPtrRange(mFrames.begin(), mFrames.end());
  }

  mFrames.ResetStorageToInline();

  // Teardown is the last safe point; nothing may stay parked past it.
  ReleaseRetiredFrames();
}

/**
 * Address: 0x0084CA90 (FUN_0084CA90)
 *
 * What it does:
 * Full deleting-destructor behavior before object deallocation.
 */
void moho::CUIManager::DeleteDtor()
{
  ClearFrames();
  mHostWindows.ResetStorageToInline();
  mInputWindows.ResetStorageToInline();
  DestroyCore();
}

/**
 * Address: 0x0084CB30 (FUN_0084CB30)
 */
bool moho::CUIManager::Init()
{
  if (!mFrames.Empty()) {
    gpg::Warnf("CUIManager::Init - attempt to initialize before UI manager cleaned up.");
    return false;
  }

  mLuaState = USER_GetLuaState();
  if (!UI_InitKeyHandler()) {
    gpg::Die("CUIManager::Init - unable to initialize key handler.");
  }

  return true;
}

/**
 * Address: 0x0084CB70 (FUN_0084CB70)
 */
int moho::CUIManager::AddFrame(wxWindow* const inputWindow, wxWindow* const eventHostWindow)
{
  if (inputWindow == nullptr) {
    return -1;
  }

  mInputWindows.PushBack(inputWindow);
  mHostWindows.PushBack(eventHostWindow);
  const int head = static_cast<int>(mInputWindows.Size() - 1);

  inputWindow->PushEventHandler(new CUIKeyHandler());
  return head;
}

/**
 * Address: 0x0084CC50 (FUN_0084CC50)
 */
bool moho::CUIManager::SetNewLuaState(LuaPlus::LuaState* const state)
{
  UI_ClearInputCapture();
  UI_ClearCurrentDragger();

  if (!mFrames.Empty()) {
    const std::size_t sharedCount = std::min(mFrames.Size(), mInputWindows.Size());
    for (std::size_t index = 0; index < sharedCount; ++index) {
      if (mFrames[index] && mInputWindows[index] != nullptr) {
        (void)mInputWindows[index]->PopEventHandler(false);
      }
    }

    for (std::size_t index = 0; index < mFrames.Size(); ++index) {
      if (mFrames[index]) {
        mFrames[index]->Destroy();
      }
    }

    ReleaseFrameSharedPtrRange(mFrames.begin(), mFrames.end());
    mFrames.ResetStorageToInline();
  }

  // 0x0084CD5D-0x0084CD72: the old state's cursor is deleted (`[mCursor - 4]`, vtable +0x08, the
  // deleting destructor, with 1); the new state's `SetupUI` makes its own. Its weak link clears itself.
  delete GetCursor();
  mLuaState = state;

  if (mLuaState == nullptr) {
    return true;
  }

  // A fresh state only gets the empty placeholder; the tree itself is published
  // per tick from `UpdateFrameRate`. Doing the full serialize here would walk
  // the stat tree before any frame exists.
  LuaPlus::LuaObject globals = mLuaState->GetGlobals();
  (void)globals.CreateTable("__EngineStats", 0, 0);

  for (std::size_t head = 0; head < mInputWindows.Size(); ++head) {
    boost::shared_ptr<CMauiFrame> frame = CMauiFrame::Create(mLuaState);
    if (!frame) {
      gpg::Die("CUIManager::Init - unable to create root frame for head %d.", static_cast<int>(head));
    }

    mFrames.PushBack(frame);

    moho::CMauiFrame* const frameView = frame.get();
    frameView->mRenderPass = 8;

    // Sized from the input window, not the host: both GetClientSize calls
    // (0x0084CEAE / 0x0084CED7) go through `mInputWindows` (+0x38).
    const int width = mInputWindows[head]->GetClientSize().x;
    const int height = mInputWindows[head]->GetClientSize().y;

    CScriptLazyVar_float::SetValue(&frameView->mLeftLV, 0.0f);
    CScriptLazyVar_float::SetValue(&frameView->mTopLV, 0.0f);
    CScriptLazyVar_float::SetValue(&frameView->mWidthLV, static_cast<float>(width));
    CScriptLazyVar_float::SetValue(&frameView->mHeightLV, static_cast<float>(height));

    if (frameView->mEventHandler != nullptr) {
      // Pushed, then told which window it is on (0x0084CF66, 0x0084CF7C):
      // wheel events arrive in screen coordinates and are converted to client
      // space through that window.
      mInputWindows[head]->PushEventHandler(frameView->mEventHandler);
      frameView->mEventHandler->mWindow = mInputWindows[head];
    }

    frameView->mTargetHead = static_cast<std::int32_t>(head);
  }

  if (!MAUI_StartMainScript()) {
    gpg::Die("CUIManager::Init - unable to start main UI script.");
  }

  return true;
}

/**
 * Address: 0x0084D150 (FUN_0084D150)
 */
bool moho::CUIManager::HasFrames() const
{
  return !mFrames.Empty();
}

/**
 * Address: 0x0084D010 (FUN_0084D010)
 */
void moho::CUIManager::ClearFrames()
{
  if (!mFrames.Empty()) {
    const std::size_t sharedCount = std::min(mFrames.Size(), mInputWindows.Size());
    for (std::size_t index = 0; index < sharedCount; ++index) {
      if (mFrames[index] && mInputWindows[index] != nullptr) {
        (void)mInputWindows[index]->PopEventHandler(false);
      }
    }

    for (std::size_t index = 0; index < mFrames.Size(); ++index) {
      if (mFrames[index]) {
        mFrames[index]->Destroy();
      }
    }

    ReleaseFrameSharedPtrRange(mFrames.begin(), mFrames.end());
    mFrames.ResetStorageToInline();
  }

  for (std::size_t index = 0; index < mInputWindows.Size(); ++index) {
    wxWindow* const inputWindow = mInputWindows[index];
    if (inputWindow == nullptr) {
      continue;
    }

    delete inputWindow->PopEventHandler(false);
  }

  mInputWindows.ResetStorageToInline();
  mHostWindows.ResetStorageToInline();
  mLuaState = nullptr;
}

/**
 * Address: 0x0084D160 (FUN_0084D160)
 */
void moho::CUIManager::UpdateFrameRate(const float deltaSeconds)
{
  FAF_PROFILE_ZONE_NAMED("UI");
  ReleaseRetiredFrames();

  {
    FAF_PROFILE_ZONE_NAMED("UI::FrameWindows");
    for (std::size_t index = 0; index < mFrames.Size(); ++index) {
      if (mFrames[index]) {
        mFrames[index]->Frame(deltaSeconds);
      }
    }
  }

  if (CMauiCursor* const cursor = GetCursor()) {
    MAUI_UpdateCursor(cursor);
  }

  if (mLuaState != nullptr) {
    PublishEngineStatsToLua(mLuaState);

    mGCTime += deltaSeconds;

    // Measure the real frame rate over the five-second GC window so the
    // incremental slice budget can be spread over the frames that follow.
    sGcWindowFrames += 1;
    sGcWindowSeconds += deltaSeconds;

    if (mGCTime > 5.0f) {
      mGCTime -= 5.0f;
      if (sGcWindowFrames > 0) {
        float secondsPerFrame = sGcWindowSeconds / static_cast<float>(sGcWindowFrames);
        // Keep the measurement sane: a hitch must not shrink the budget for
        // the next window, and a very fast frame must not inflate it.
        if (secondsPerFrame < 1.0f / 240.0f) {
          secondsPerFrame = 1.0f / 240.0f;
        } else if (secondsPerFrame > 1.0f / 10.0f) {
          secondsPerFrame = 1.0f / 10.0f;
        }
        sGcSecondsPerFrame = secondsPerFrame;
      }
      sGcWindowFrames = 0;
      sGcWindowSeconds = 0.0f;
      if (moho::lua_IncrementalGC) {
        // Keep the five-second cadence of the shipped collector, but spread the
        // cycle over frames in UI_ProcessIdleGC instead of stopping the world.
        sIncrementalCycleDue = true;
      } else if (ui_IdleGC) {
        sPendingUiGc = true;
      } else if (mLuaState->m_state != nullptr) {
        lua_setgcthreshold(mLuaState->m_state, 0);
      }
    }
  }

  STAT_Frame();
  UI_UpdateCommandFeedbackBlips(deltaSeconds);
}

void moho::UI_ProcessIdleGC()
{
  if (moho::lua_IncrementalGC) {
    if (CUIManager* const uiMgr = static_cast<CUIManager*>(UI_GetManager())) {
      if (uiMgr->mLuaState != nullptr && uiMgr->mLuaState->m_state != nullptr) {
        FAF_PROFILE_ZONE_NAMED("UI::LuaGCStep");
        // Work units are 5.1 singlestep costs (bytes of mark traversal), not
        // milliseconds. The budget scales with the current heap size and the
        // allocation debt so that one cycle fits into the five-second window
        // the shipped collector used, while a single frame stays bounded.
        const bool forceStart = sIncrementalCycleDue;
        if (forceStart) {
          // The due request is consumed by this call. Clear it here, when the
          // cycle is started, instead of when it finishes: a flag that stays
          // set for the whole cycle would restart the collector as soon as the
          // cycle reaches Pause again.
          sIncrementalCycleDue = false;
        }
        const int workBudget =
          ComputeIncrementalGcWorkBudget(uiMgr->mLuaState->m_state->l_G);
        [[maybe_unused]] const bool done =
            faf_lua51_gc_slice(uiMgr->mLuaState->m_state, workBudget, forceStart);
      }
    }
    return;
  }

  if (!sPendingUiGc) {
    return;
  }
  sPendingUiGc = false;
  if (CUIManager* const uiMgr = static_cast<CUIManager*>(UI_GetManager())) {
    if (uiMgr->mLuaState != nullptr && uiMgr->mLuaState->m_state != nullptr) {
      lua_setgcthreshold(uiMgr->mLuaState->m_state, 0);
    }
  }
}

/**
 * Address: 0x0084D310 (FUN_0084D310)
 */
bool moho::CUIManager::DoBeat()
{
  FAF_PROFILE_ZONE_NAMED("UI::Beat");
  UI_FactoryCommandQueueHandlerBeat();
  return UI_LuaBeat();
}

/**
 * Address: 0x0084D320 (FUN_0084D320)
 */
void moho::CUIManager::SetMinimized(const bool minimized)
{
  for (std::size_t index = 0; index < mFrames.Size(); ++index) {
    if (mFrames[index]) {
      mFrames[index]->OnMinimized(minimized);
    }
  }
}

/**
 * Address: 0x0084D360 (FUN_0084D360)
 */
void moho::CUIManager::ClearChildren(const int frameIdx)
{
  if (frameIdx == -1) {
    for (std::size_t index = 0; index < mFrames.Size(); ++index) {
      if (mFrames[index]) {
        mFrames[index]->ClearChildren();
      }
    }
    return;
  }

  if (!IsValidFrameIndex(*this, frameIdx) || !mFrames[static_cast<std::size_t>(frameIdx)]) {
    return;
  }

  mFrames[static_cast<std::size_t>(frameIdx)]->ClearChildren();
}

/**
 * Address: 0x0084CFC0 (FUN_0084CFC0)
 */
void moho::CUIManager::OnResize(const int frameIdx, const int width, const int height)
{
  if (!IsValidFrameIndex(*this, frameIdx)) {
    return;
  }

  boost::shared_ptr<CMauiFrame>& frame = mFrames[static_cast<std::size_t>(frameIdx)];
  if (!frame) {
    return;
  }

  frame->SetBounds(width, height);
  MAUI_OnApplicationResize(frameIdx, width, height);
}

/**
 * Address: 0x0084D3C0 (FUN_0084D3C0)
 */
void moho::CUIManager::SetUIControlsAlpha(const float alpha)
{
  mUIControlsAlpha = alpha;
}

/**
 * Address: 0x0084D3D0 (FUN_0084D3D0)
 */
float moho::CUIManager::GetUIControlsAlpha() const
{
  return mUIControlsAlpha;
}

/**
 * Address: 0x0084D000 (FUN_0084D000)
 */
void moho::CUIManager::SetCursor(CMauiCursor* const cursor)
{
  mCursor.ResetFromObject(cursor);
}

/**
 * Address: 0x0084C920 (FUN_0084C920)
 */
moho::CMauiCursor* moho::CUIManager::GetCursor() const
{
  return mCursor.GetObjectPtr();
}

/**
 * Address: 0x0084D520 (FUN_0084D520)
 */
void moho::CUIManager::ValidateFrame(const int frameIdx)
{
  if (!IsValidFrameIndex(*this, frameIdx)) {
    return;
  }

  boost::shared_ptr<CMauiFrame>& frame = mFrames[static_cast<std::size_t>(frameIdx)];
  if (frame) {
    frame->Render();
  }
}

/**
 * Address: 0x0084D550 (FUN_0084D550)
 */
void moho::CUIManager::RenderFrames(const int head, CD3DPrimBatcher* const primBatcher)
{
  primBatcher->SetToViewport(head, *this);

  CD3DDevice* const device = D3D_GetDevice();
  device->SelectFxFile("primbatcher");
  device->SelectTechnique("TAlphaBlendLinearSampleNoDepth");

  primBatcher->mRebuildComposite = 0;

  if (IsValidFrameIndex(*this, head) && mFrames[static_cast<std::size_t>(head)]) {
    mFrames[static_cast<std::size_t>(head)]->RenderChildControls(primBatcher, 1);
  }

  primBatcher->Flush();
}

/**
 * Address: 0x0084D5D0 (FUN_0084D5D0)
 */
void moho::CUIManager::DrawUI(const int head, CD3DPrimBatcher* const primBatcher)
{
  FAF_PROFILE_ZONE_NAMED("UI");
  primBatcher->SetToViewport(head, *this);

  CD3DDevice* const device = D3D_GetDevice();
  device->SelectFxFile("primbatcher");
  device->SelectTechnique("TAlphaBlendLinearSampleNoDepth");

  primBatcher->mRebuildComposite = 0;

  if (IsValidFrameIndex(*this, head) && mFrames[static_cast<std::size_t>(head)]) {
    mFrames[static_cast<std::size_t>(head)]->RenderChildControls(primBatcher, 4);
  }

  primBatcher->Flush();
}

/**
 * Address: 0x0084D650 (FUN_0084D650)
 */
void moho::CUIManager::DrawHead(const int head, CD3DPrimBatcher* const primBatcher)
{
  primBatcher->SetToViewport(head, *this);

  CD3DDevice* const device = D3D_GetDevice();
  device->SelectFxFile("primbatcher");
  device->SelectTechnique("TAlphaBlendLinearSampleNoDepth");

  primBatcher->mRebuildComposite = 0;

  if (IsValidFrameIndex(*this, head) && mFrames[static_cast<std::size_t>(head)]) {
    mFrames[static_cast<std::size_t>(head)]->RenderChildControls(primBatcher, 8);
  }

  primBatcher->Flush();
}

/**
 * Address: 0x0084D6D0 (FUN_0084D6D0)
 */
void moho::CUIManager::GetControlAtCursor(
  int* const outViewport, float* const outX, float* const outY, CMauiControl** const outControl
)
{
  // The out-parameters are written only on a hit; the callers initialise
  // them (DebugMouseOverControl does).
  const wxPoint mouse = wxGetMousePosition();
  for (std::size_t head = 0; head < mInputWindows.Size(); ++head) {
    int x = mouse.x;
    int y = mouse.y;
    mInputWindows[head]->ScreenToClient(&x, &y);

    int width = 0;
    int height = 0;
    mInputWindows[head]->GetClientSize(&width, &height);

    if (wxRect(wxPoint(0, 0), wxSize(width, height)).Inside(x, y)) {
      *outControl =
        CMauiControl::GetTopmostControl(mFrames[head].get(), static_cast<float>(x), static_cast<float>(y));
      *outX = static_cast<float>(x);
      *outY = static_cast<float>(y);
      *outViewport = static_cast<int>(head);
      return;
    }
  }
}

/**
 * Address: 0x0084D810 (FUN_0084D810)
 */
void moho::CUIManager::DumpControlsUnderMouse()
{
  const wxPoint mouse = wxGetMousePosition();
  for (std::size_t head = 0; head < mInputWindows.Size(); ++head) {
    int localX = mouse.x;
    int localY = mouse.y;
    mInputWindows[head]->ScreenToClient(&localX, &localY);

    gpg::Logf(
      "\n\n--- Dumping controls for head #%d at cursor position %d, %d",
      static_cast<int>(head),
      localX,
      localY
    );

    if (head < mFrames.Size() && mFrames[head]) {
      CMauiFrame::DumpControlsUnder(mFrames[head].get(), static_cast<float>(localX), static_cast<float>(localY));
    }
  }

  gpg::Logf("\n**** Mouse input is going to:");
  UI_DumpCurrentInputCapture();
}

/**
 * Address: 0x0084D8E0 (FUN_0084D8E0)
 */
void moho::CUIManager::DebugMouseOverControl(CD3DPrimBatcher* const primBatcher)
{
  int viewport = 0;
  float mouseX = 0.0f;
  float mouseY = 0.0f;
  CMauiControl* control = nullptr;
  GetControlAtCursor(&viewport, &mouseX, &mouseY, &control);

  (void)viewport;
  (void)mouseX;
  (void)mouseY;

  if (control == nullptr) {
    return;
  }

  const boost::shared_ptr<CD3DBatchTexture> texture = CD3DBatchTexture::FromSolidColor(0xFFFF00FFu);
  primBatcher->SetTexture(texture);

  const float left = CScriptLazyVar_float::GetValue(&control->mLeftLV);
  const float right = CScriptLazyVar_float::GetValue(&control->mRightLV);
  const float top = CScriptLazyVar_float::GetValue(&control->mTopLV);
  const float bottom = CScriptLazyVar_float::GetValue(&control->mBottomLV);

  const Vector3f topLeft{left, top, 0.0f};
  const Vector3f widthAxis{right - left, 0.0f, 0.0f};
  const Vector3f heightAxis{0.0f, bottom - top, 0.0f};
  DRAW_Rect(primBatcher, 5.0f, heightAxis, widthAxis, topLeft, 0xFFFF00FFu, nullptr, -1000.0f);
}
