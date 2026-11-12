#pragma once

// Engine addition (issue #255): the part of wx 2.4.2's wxWindow (wx/window.h) the Linux
// client's game code uses: the event handler chain and the client area. See wx/defs.h in this
// folder. The window system (issue #256) keeps the size and screen position current.

#include <wx/event.h>
#include <wx/gdicmn.h>

#include <cstdint>
#include <vector>

// The native window behind a wxWindow, as the renderers and the system's own window calls take
// it (platform::window::NativeHandle: the HWND on Windows, the SDL_Window* elsewhere). A top-level
// window has its own; a child window shares its top-level window's, which it fills. An integer, as
// wx 2.4.2's WXWidget (WXHWND) is: the engine casts it with static_cast<uintptr_t>.
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

  wxWindow* GetParent() const
  {
    return m_parent;
  }
  WXWidget GetHandle() const
  {
    return m_handle;
  }
  WXWidget GetHWND() const
  {
    return m_handle;
  }
  // The window system's window (platform::window::Handle), null for none.
  void* GetPlatformWindow() const
  {
    return m_platformWindow;
  }

  virtual bool Show(bool show = true);
  // wx 2.4.2 deletes a window at once unless it is a top-level one; nothing here defers.
  virtual bool Destroy();
  bool IsShown() const
  {
    return m_shown;
  }
  // The window that gets the keyboard and mouse events of its top-level window.
  virtual void SetFocus();
  static wxWindow* FindFocus();
  const std::vector<wxWindow*>& GetChildren() const
  {
    return m_children;
  }
  bool IsTopLevel() const
  {
    return m_topLevel;
  }
  // A child with a native window of its own (platform::window::CreateChild; Windows), as wx made
  // child windows. Elsewhere a child fills its parent's window and shares it.
  bool IsNativeChild() const
  {
    return m_nativeChild;
  }
  virtual void Refresh(
    bool eraseBackground = true,
    const wxRect* rect = nullptr
  )
  {
    (void)eraseBackground;
    (void)rect;
  }
  virtual void Update() {}
  void SetSize(int width, int height);
  // wx 2.4.2: -1 keeps a coordinate or dimension as it is (with wxSIZE_USE_EXISTING).
  void SetSize(int x, int y, int width, int height, int sizeFlags = 0);
  void Move(
    int x,
    int y
  )
  {
    SetSize(x, y, -1, -1);
  }
  wxSize GetSize() const
  {
    return GetClientSize();
  }
  wxPoint GetPosition() const
  {
    return wxPoint(m_screenX, m_screenY);
  }

  wxEvtHandler* GetEventHandler() const
  {
    return m_eventHandler;
  }
  void SetEventHandler(
    wxEvtHandler* const handler
  )
  {
    m_eventHandler = handler;
  }

  // src/common/wincmn.cpp 2.4.2: the new handler sees events first, then passes them on.
  void PushEventHandler(wxEvtHandler* handler);
  wxEvtHandler* PopEventHandler(bool deleteHandler = false);

  void GetClientSize(int* width, int* height) const;
  wxSize GetClientSize() const;
  void ScreenToClient(int* x, int* y) const;
  wxPoint ScreenToClient(const wxPoint& point) const;

  // Set by the window system (issue #256).
  void SetClientArea(int screenX, int screenY, int width, int height);

protected:
  // A top-level window with its own native window (wxTopLevelWindow's constructor).
  void SetTopLevel(void* platformWindow);

private:
  wxWindow* m_parent = nullptr;
  std::vector<wxWindow*> m_children;
  bool m_topLevel = false;
  bool m_nativeChild = false;
  WXWidget m_handle = 0;
  void* m_platformWindow = nullptr;
  bool m_shown = false;
  wxEvtHandler* m_eventHandler = this;
  int m_screenX = 0;
  int m_screenY = 0;
  int m_clientWidth = 0;
  int m_clientHeight = 0;
};
