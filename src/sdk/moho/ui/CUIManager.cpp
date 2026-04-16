#include "moho/ui/CUIManager.h"

#include <Windows.h>

#include <algorithm>
#include <cstdint>
#include <new>

#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "lua/LuaObject.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/Stats.h"
#include "moho/render/d3d/CD3DPrimBatcher.h"

namespace
{
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
    for (boost::shared_ptr<moho::CMauiFrame>* it = begin; it != end; ++it) {
      it->reset();
    }
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

  void PublishEngineStatsToLua(LuaPlus::LuaState* const state)
  {
    if (state == nullptr) {
      return;
    }

    LuaPlus::LuaObject globals = state->GetGlobals();
    LuaPlus::LuaObject engineStatsTable(state);
    engineStatsTable.AssignNewTable(state, 0, 0);

    moho::EngineStats* const engineStats = moho::GetEngineStats();
    if (engineStats != nullptr && engineStats->mItem != nullptr) {
      engineStats->mItem->ToLua(state, &engineStatsTable);
    }

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
  , mCursorLink{}
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
  mCursorLink.Unlink();

  if (!mFrames.Empty()) {
    ReleaseFrameSharedPtrRange(mFrames.begin(), mFrames.end());
  }

  mFrames.ResetStorageToInline();
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
int moho::CUIManager::AddFrame(wxWindowBase* const inputWindow, wxWindowBase* const eventHostWindow)
{
  if (inputWindow == nullptr) {
    return -1;
  }

  mInputWindows.PushBack(inputWindow);
  mHostWindows.PushBack(eventHostWindow);

  wxEvtHandlerRuntime* const keyHandler = UI_CreateKeyHandler();
  if (keyHandler != nullptr) {
    WX_PushEventHandler(inputWindow, keyHandler);
  }

  return static_cast<int>(mInputWindows.Size() - 1);
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
        (void)WX_PopEventHandler(mInputWindows[index], false);
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

  MAUI_ReleaseCursor(GetCursor());
  mLuaState = state;

  if (mLuaState == nullptr) {
    return true;
  }

  PublishEngineStatsToLua(mLuaState);

  const std::size_t headCount = std::min(mInputWindows.Size(), mHostWindows.Size());
  for (std::size_t head = 0; head < headCount; ++head) {
    boost::shared_ptr<CMauiFrame> frame = CMauiFrame::Create(mLuaState);
    if (!frame) {
      gpg::Die("CUIManager::Init - unable to create root frame for head %d.", static_cast<int>(head));
    }

    mFrames.PushBack(frame);

    CMauiFrameRuntimeView* const frameView = CMauiFrameRuntimeView::FromFrame(frame.get());
    frameView->mRenderPass = 8;

    std::int32_t width = 0;
    std::int32_t height = 0;
    WX_GetClientSize(mHostWindows[head], width, height);

    CScriptLazyVar_float::SetValue(&frameView->mLeftLV, 0.0f);
    CScriptLazyVar_float::SetValue(&frameView->mTopLV, 0.0f);
    CScriptLazyVar_float::SetValue(&frameView->mWidthLV, static_cast<float>(width));
    CScriptLazyVar_float::SetValue(&frameView->mHeightLV, static_cast<float>(height));

    if (frameView->mEventHandler != nullptr && mInputWindows[head] != nullptr) {
      WX_PushEventHandler(mInputWindows[head], frameView->mEventHandler);
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
        (void)WX_PopEventHandler(mInputWindows[index], false);
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
    wxWindowBase* const inputWindow = mInputWindows[index];
    if (inputWindow == nullptr) {
      continue;
    }

    wxEvtHandlerRuntime* const popped = WX_PopEventHandler(inputWindow, false);
    if (popped != nullptr) {
      delete popped;
    }
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
  for (std::size_t index = 0; index < mFrames.Size(); ++index) {
    if (mFrames[index]) {
      mFrames[index]->Frame(deltaSeconds);
    }
  }

  if (CMauiCursor* const cursor = GetCursor()) {
    MAUI_UpdateCursor(cursor);
  }

  if (mLuaState != nullptr) {
    PublishEngineStatsToLua(mLuaState);

    mGCTime += deltaSeconds;
    if (mGCTime > 5.0f) {
      mGCTime -= 5.0f;
      if (mLuaState->m_state != nullptr) {
        lua_setgcthreshold(mLuaState->m_state, 0);
      }
    }
  }

  STAT_Frame();
  UI_UpdateCommandFeedbackBlips(deltaSeconds);
}

/**
 * Address: 0x0084D310 (FUN_0084D310)
 */
bool moho::CUIManager::DoBeat()
{
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
  mCursorLink.AssignCursor(cursor);
}

/**
 * Address: 0x0084C920 (FUN_0084C920)
 */
moho::CMauiCursor* moho::CUIManager::GetCursor() const
{
  return mCursorLink.GetCursor();
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

  CD3DPrimBatcherRuntimeView::FromBatcher(primBatcher)->mRebuildComposite = 0;

  if (IsValidFrameIndex(*this, head) && mFrames[static_cast<std::size_t>(head)]) {
    mFrames[static_cast<std::size_t>(head)]->DoRender(primBatcher, 1);
  }

  primBatcher->Flush();
}

/**
 * Address: 0x0084D5D0 (FUN_0084D5D0)
 */
void moho::CUIManager::DrawUI(const int head, CD3DPrimBatcher* const primBatcher)
{
  primBatcher->SetToViewport(head, *this);

  CD3DDevice* const device = D3D_GetDevice();
  device->SelectFxFile("primbatcher");
  device->SelectTechnique("TAlphaBlendLinearSampleNoDepth");

  CD3DPrimBatcherRuntimeView::FromBatcher(primBatcher)->mRebuildComposite = 0;

  if (IsValidFrameIndex(*this, head) && mFrames[static_cast<std::size_t>(head)]) {
    mFrames[static_cast<std::size_t>(head)]->DoRender(primBatcher, 4);
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

  CD3DPrimBatcherRuntimeView::FromBatcher(primBatcher)->mRebuildComposite = 0;

  if (IsValidFrameIndex(*this, head) && mFrames[static_cast<std::size_t>(head)]) {
    mFrames[static_cast<std::size_t>(head)]->DoRender(primBatcher, 8);
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
  if (outViewport != nullptr) {
    *outViewport = 0;
  }
  if (outX != nullptr) {
    *outX = 0.0f;
  }
  if (outY != nullptr) {
    *outY = 0.0f;
  }
  if (outControl != nullptr) {
    *outControl = nullptr;
  }

  std::int32_t mouseX = 0;
  std::int32_t mouseY = 0;
  if (!WX_GetCursorPosition(mouseX, mouseY)) {
    return;
  }

  for (std::size_t head = 0; head < mInputWindows.Size(); ++head) {
    wxWindowBase* const inputWindow = mInputWindows[head];
    if (inputWindow == nullptr) {
      continue;
    }

    std::int32_t localX = mouseX;
    std::int32_t localY = mouseY;
    WX_ScreenToClient(inputWindow, localX, localY);

    std::int32_t clientWidth = 0;
    std::int32_t clientHeight = 0;
    WX_GetClientSize(inputWindow, clientWidth, clientHeight);

    if (localX < 0 || localY < 0 || localX >= clientWidth || localY >= clientHeight) {
      continue;
    }

    if (head < mFrames.Size() && mFrames[head]) {
      CMauiControl* const control = CMauiControl::GetTopmostControl(
        mFrames[head].get(),
        static_cast<float>(localX),
        static_cast<float>(localY)
      );

      if (outControl != nullptr) {
        *outControl = control;
      }
      if (outX != nullptr) {
        *outX = static_cast<float>(localX);
      }
      if (outY != nullptr) {
        *outY = static_cast<float>(localY);
      }
      if (outViewport != nullptr) {
        *outViewport = static_cast<int>(head);
      }
    }

    return;
  }
}

/**
 * Address: 0x0084D810 (FUN_0084D810)
 */
void moho::CUIManager::DumpControlsUnderMouse()
{
  std::int32_t mouseX = 0;
  std::int32_t mouseY = 0;
  (void)WX_GetCursorPosition(mouseX, mouseY);

  for (std::size_t head = 0; head < mInputWindows.Size(); ++head) {
    wxWindowBase* const inputWindow = mInputWindows[head];
    if (inputWindow == nullptr) {
      continue;
    }

    std::int32_t localX = mouseX;
    std::int32_t localY = mouseY;
    WX_ScreenToClient(inputWindow, localX, localY);

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

  CMauiControlRuntimeView* const controlView = CMauiControlRuntimeView::FromControl(control);
  const float left = CScriptLazyVar_float::GetValue(&controlView->mLeftLV);
  const float right = CScriptLazyVar_float::GetValue(&controlView->mRightLV);
  const float top = CScriptLazyVar_float::GetValue(&controlView->mTopLV);
  const float bottom = CScriptLazyVar_float::GetValue(&controlView->mBottomLV);

  const Vector3f topLeft{left, top, 0.0f};
  const Vector3f widthAxis{right - left, 0.0f, 0.0f};
  const Vector3f heightAxis{0.0f, bottom - top, 0.0f};
  DRAW_Rect(primBatcher, 5.0f, heightAxis, widthAxis, topLeft, 0xFFFF00FFu, nullptr, -1000.0f);
}
