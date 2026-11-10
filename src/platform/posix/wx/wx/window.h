#pragma once

// Engine addition (issue #255): the part of wx 2.4.2's wxWindow (wx/window.h) the Linux
// client's game code uses: the event handler chain and the client area. See wx/defs.h in this
// folder. The window system (issue #256) keeps the size and screen position current.

#include <wx/event.h>
#include <wx/gdicmn.h>

#include <cstdint>

// The native window behind a wxWindow: the window system's handle (issue #256), 0 until then. An
// integer, as wx 2.4.2's WXWidget (WXHWND) is: the engine casts it with static_cast<uintptr_t>.
typedef std::uintptr_t WXWidget;

class wxWindow : public wxEvtHandler
{
public:
  wxWindow() = default;
  wxWindow(
    wxWindow* parent,
    wxWindowID id,
    const wxPoint& pos = wxDefaultPosition,
    const wxSize& size = wxDefaultSize,
    long style = 0,
    const wchar_t* name = L"panel"
  );
  ~wxWindow() override;

  wxWindow* GetParent() const { return m_parent; }
  WXWidget GetHandle() const { return m_handle; }
  WXWidget GetHWND() const { return m_handle; }
  // Set by the window system (issue #256) when it creates the native window.
  void SetHandle(WXWidget const handle) { m_handle = handle; }

  virtual bool Show(bool show = true);
  // wx 2.4.2 deletes a window at once unless it is a top-level one; nothing here defers.
  virtual bool Destroy();
  bool IsShown() const { return m_shown; }
  virtual void SetFocus() {}
  virtual void Refresh(bool eraseBackground = true) { (void)eraseBackground; }
  virtual void Update() {}
  void SetSize(int width, int height);
  wxSize GetSize() const { return GetClientSize(); }

  wxEvtHandler* GetEventHandler() const { return m_eventHandler; }
  void SetEventHandler(wxEvtHandler* const handler) { m_eventHandler = handler; }

  // src/common/wincmn.cpp 2.4.2: the new handler sees events first, then passes them on.
  void PushEventHandler(wxEvtHandler* handler);
  wxEvtHandler* PopEventHandler(bool deleteHandler = false);

  void GetClientSize(int* width, int* height) const;
  wxSize GetClientSize() const;
  void ScreenToClient(int* x, int* y) const;
  wxPoint ScreenToClient(const wxPoint& point) const;

  // Set by the window system (issue #256).
  void SetClientArea(int screenX, int screenY, int width, int height);

private:
  wxWindow* m_parent = nullptr;
  WXWidget m_handle = 0;
  bool m_shown = false;
  wxEvtHandler* m_eventHandler = this;
  int m_screenX = 0;
  int m_screenY = 0;
  int m_clientWidth = 0;
  int m_clientHeight = 0;
};
