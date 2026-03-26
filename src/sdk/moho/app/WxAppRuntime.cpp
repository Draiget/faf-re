#include "WxAppRuntime.h"

#include <cstddef>
#include <cstdint>

namespace
{
  [[nodiscard]]
  wxApp* GetWxApp()
  {
    return wxTheApp;
  }
} // namespace

bool moho::WxAppRuntime::IsAvailable()
{
  return GetWxApp() != nullptr;
}

void moho::WxAppRuntime::EnableLoopFlags()
{
  wxApp* const wxApp = GetWxApp();
  if (wxApp == nullptr) {
    return;
  }

  wxApp->m_exitOnFrameDelete = wxApp::kExitOnFrameDeleteYes;
  wxApp->m_keepGoing = 1;
}

bool moho::WxAppRuntime::Pending()
{
  wxApp* const wxApp = GetWxApp();
  return wxApp != nullptr && wxApp->Pending();
}

void moho::WxAppRuntime::Dispatch()
{
  wxApp* const wxApp = GetWxApp();
  if (wxApp == nullptr) {
    return;
  }

  wxApp->Dispatch();
}

bool moho::WxAppRuntime::ProcessIdle()
{
  wxApp* const wxApp = GetWxApp();
  return wxApp != nullptr && wxApp->ProcessIdle();
}

bool moho::WxAppRuntime::KeepGoing()
{
  const wxApp* const wxApp = GetWxApp();
  return wxApp != nullptr && wxApp->m_keepGoing != 0;
}

void moho::WxAppRuntime::OnExit()
{
  wxApp* const wxApp = GetWxApp();
  if (wxApp == nullptr) {
    return;
  }

  (void)wxApp->OnExit();
}

bool moho::WxAppRuntime::DestroyWindow(wxWindowBase* const window)
{
  return window != nullptr && window->Destroy();
}

bool moho::WxAppRuntime::DestroyWindow(WSupComFrame* const window)
{
  return DestroyWindow(reinterpret_cast<wxWindowBase*>(window));
}

bool moho::WxAppRuntime::IsSupComFrameWindowActive(const WSupComFrame* const frame)
{
  return frame != nullptr && frame->mIsApplicationActive != 0;
}
