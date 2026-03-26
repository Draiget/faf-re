#include "moho/ui/UiRuntimeTypes.h"

#include <Windows.h>

#include <algorithm>
#include <cstdint>
#include <vector>

namespace
{
  LuaPlus::LuaState* gUserLuaState = nullptr;

  struct WindowEventHandlerChain
  {
    wxWindowBase* window = nullptr;
    std::vector<moho::wxEvtHandlerRuntime*> handlers{};
  };

  std::vector<WindowEventHandlerChain> gWindowEventHandlerChains;

  [[nodiscard]]
  std::vector<WindowEventHandlerChain>::iterator FindWindowEventHandlerChain(const wxWindowBase* const window)
  {
    return std::find_if(
      gWindowEventHandlerChains.begin(),
      gWindowEventHandlerChains.end(),
      [window](const WindowEventHandlerChain& chain) { return chain.window == window; }
    );
  }
} // namespace

moho::EUIState moho::sUIState = moho::UIS_none;

float moho::CScriptLazyVar_float::GetValue(const CScriptLazyVar_float* const value) noexcept
{
  return value != nullptr ? value->mCachedValue : 0.0f;
}

void moho::CScriptLazyVar_float::SetValue(CScriptLazyVar_float* const value, const float next) noexcept
{
  if (value == nullptr) {
    return;
  }

  value->mCachedValue = next;
}

void moho::CMauiCursorLink::AssignCursor(CMauiCursor* const cursor) noexcept
{
  CMauiCursorLink** const nextOwnerHead =
    cursor != nullptr ? &CMauiCursorRuntimeView::FromCursor(cursor)->ownerChainHead : nullptr;
  if (nextOwnerHead == ownerHeadLink) {
    return;
  }

  if (ownerHeadLink != nullptr) {
    CMauiCursorLink** link = ownerHeadLink;
    while (*link != nullptr && *link != this) {
      link = &(*link)->nextInOwnerChain;
    }

    if (*link == this) {
      *link = nextInOwnerChain;
    }
  }

  ownerHeadLink = nextOwnerHead;
  if (ownerHeadLink != nullptr) {
    nextInOwnerChain = *ownerHeadLink;
    *ownerHeadLink = this;
  } else {
    nextInOwnerChain = nullptr;
  }
}

void moho::CMauiCursorLink::Unlink() noexcept
{
  AssignCursor(nullptr);
}

moho::CMauiCursor* moho::CMauiCursorLink::GetCursor() const noexcept
{
  if (ownerHeadLink == nullptr || ownerHeadLink == reinterpret_cast<CMauiCursorLink**>(0x4)) {
    return nullptr;
  }

  const std::uintptr_t rawAddress = reinterpret_cast<std::uintptr_t>(ownerHeadLink);
  const std::uintptr_t cursorAddress = rawAddress - offsetof(CMauiCursorRuntimeView, ownerChainHead);
  return reinterpret_cast<CMauiCursor*>(cursorAddress);
}

moho::CMauiControl* moho::CMauiControl::GetTopmostControl(CMauiControl* const root, const float x, const float y)
{
  (void)x;
  (void)y;
  return root;
}

boost::shared_ptr<moho::CMauiFrame> moho::CMauiFrame::Create(LuaPlus::LuaState* const state)
{
  (void)state;
  return boost::shared_ptr<CMauiFrame>{};
}

void moho::CMauiFrame::DumpControlsUnder(CMauiFrame* const frame, const float x, const float y)
{
  (void)frame;
  (void)x;
  (void)y;
}

LuaPlus::LuaState* moho::USER_GetLuaState()
{
  return gUserLuaState;
}

bool moho::MAUI_StartMainScript()
{
  return true;
}

void moho::MAUI_UpdateCursor(CMauiCursor* const cursor)
{
  (void)cursor;
}

void moho::MAUI_ReleaseCursor(CMauiCursor* const cursor)
{
  (void)cursor;
}

void moho::MAUI_OnApplicationResize(const std::int32_t frameIdx, const std::int32_t width, const std::int32_t height)
{
  (void)frameIdx;
  (void)width;
  (void)height;
}

bool moho::UI_InitKeyHandler()
{
  return true;
}

void moho::UI_ClearInputCapture()
{
}

void moho::UI_ClearCurrentDragger()
{
}

void moho::UI_FactoryCommandQueueHandlerBeat()
{
}

bool moho::UI_LuaBeat()
{
  return true;
}

void moho::UI_UpdateCommandFeedbackBlips(const float deltaSeconds)
{
  (void)deltaSeconds;
}

void moho::UI_DumpCurrentInputCapture()
{
}

moho::wxEvtHandlerRuntime* moho::UI_CreateKeyHandler()
{
  return new CUIKeyHandlerRuntime{};
}

void moho::WX_PushEventHandler(wxWindowBase* const window, wxEvtHandlerRuntime* const handler)
{
  if (window == nullptr || handler == nullptr) {
    return;
  }

  auto chainIt = FindWindowEventHandlerChain(window);
  if (chainIt == gWindowEventHandlerChains.end()) {
    gWindowEventHandlerChains.push_back(WindowEventHandlerChain{window, {}});
    chainIt = gWindowEventHandlerChains.end() - 1;
  }

  chainIt->handlers.push_back(handler);
}

moho::wxEvtHandlerRuntime* moho::WX_PopEventHandler(wxWindowBase* const window, const bool deleteHandler)
{
  if (window == nullptr) {
    return nullptr;
  }

  const auto chainIt = FindWindowEventHandlerChain(window);
  if (chainIt == gWindowEventHandlerChains.end() || chainIt->handlers.empty()) {
    return nullptr;
  }

  wxEvtHandlerRuntime* const popped = chainIt->handlers.back();
  chainIt->handlers.pop_back();

  if (chainIt->handlers.empty()) {
    gWindowEventHandlerChains.erase(chainIt);
  }

  if (deleteHandler && popped != nullptr) {
    delete popped;
    return nullptr;
  }

  return popped;
}

void moho::WX_GetClientSize(wxWindowBase* const window, std::int32_t& outWidth, std::int32_t& outHeight)
{
  if (window == nullptr) {
    outWidth = 0;
    outHeight = 0;
    return;
  }

  window->DoGetClientSize(&outWidth, &outHeight);
}

void moho::WX_ScreenToClient(wxWindowBase* const window, std::int32_t& inOutX, std::int32_t& inOutY)
{
  if (window == nullptr) {
    return;
  }

  const HWND handle = reinterpret_cast<HWND>(static_cast<std::uintptr_t>(window->GetHandle()));
  if (handle == nullptr) {
    return;
  }

  POINT point{};
  point.x = inOutX;
  point.y = inOutY;
  if (::ScreenToClient(handle, &point) == FALSE) {
    return;
  }

  inOutX = point.x;
  inOutY = point.y;
}

bool moho::WX_GetCursorPosition(std::int32_t& outX, std::int32_t& outY)
{
  POINT cursorPosition{};
  if (::GetCursorPos(&cursorPosition) == FALSE) {
    outX = 0;
    outY = 0;
    return false;
  }

  outX = cursorPosition.x;
  outY = cursorPosition.y;
  return true;
}

const moho::VMatrix4& moho::UI_IdentityMatrix()
{
  static const VMatrix4 kIdentity = VMatrix4::Identity();
  return kIdentity;
}
