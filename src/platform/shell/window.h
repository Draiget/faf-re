#pragma once

// Engine addition (issues #255, #407): the shell's window: the event handler chain and the client
// area. The window system (platform/Window.h) keeps the size and screen position current. See
// defs.h.

#include "platform/shell/event.h"
#include "platform/shell/gdicmn.h"

#include <cstdint>
#include <vector>

// The native window behind a Window, as the renderers and the system's own window calls take
// it (platform::window::NativeHandle: the HWND on Windows, the SDL_Window* elsewhere). A top-level
// window has its own; a child window shares its top-level window's, which it fills. An integer, as
// The 2.4.2 window library's native handle is: the engine casts it with static_cast<uintptr_t>.
typedef std::uintptr_t ShellNativeHandle;

class ShellWindow : public ShellEvtHandler
{
public:
  ShellWindow() = default;
  ShellWindow(
    ShellWindow* parent,
    ShellWindowID id,
    const ShellPoint& pos = kShellDefaultPosition,
    const ShellSize& size = kShellDefaultSize,
    long style = 0,
    const wchar_t* name = L"panel"
  );
  ~ShellWindow() override;

  ShellWindow* GetParent() const
  {
    return m_parent;
  }
  ShellNativeHandle GetHandle() const
  {
    return m_handle;
  }
  ShellNativeHandle GetHWND() const
  {
    return m_handle;
  }
  // The window system's window (platform::window::Handle), null for none.
  void* GetPlatformWindow() const
  {
    return m_platformWindow;
  }

  virtual bool Show(bool show = true);
  // The 2.4.2 window library deletes a window at once unless it is a top-level one; nothing here defers.
  virtual bool Destroy();
  bool IsShown() const
  {
    return m_shown;
  }
  // The window that gets the keyboard and mouse events of its top-level window.
  virtual void SetFocus();
  static ShellWindow* FindFocus();
  const std::vector<ShellWindow*>& GetChildren() const
  {
    return m_children;
  }
  bool IsTopLevel() const
  {
    return m_topLevel;
  }
  // A child with a native window of its own (platform::window::CreateChild; Windows), as the window library made
  // child windows. Elsewhere a child fills its parent's window and shares it.
  bool IsNativeChild() const
  {
    return m_nativeChild;
  }
  virtual void Refresh(
    bool eraseBackground = true,
    const ShellRect* rect = nullptr
  )
  {
    (void)eraseBackground;
    (void)rect;
  }
  virtual void Update() {}
  void SetSize(int width, int height);
  // The 2.4.2 window library: -1 keeps a coordinate or dimension as it is (with SIZE_USE_EXISTING).
  void SetSize(int x, int y, int width, int height, int sizeFlags = 0);
  void Move(
    int x,
    int y
  )
  {
    SetSize(x, y, -1, -1);
  }
  ShellSize GetSize() const
  {
    return GetClientSize();
  }
  // A top-level window's frame position (borders and caption included), as the retail window
  // library answered; a child's client origin on the screen.
  ShellPoint GetPosition() const;

  ShellEvtHandler* GetEventHandler() const
  {
    return m_eventHandler;
  }
  void SetEventHandler(
    ShellEvtHandler* const handler
  )
  {
    m_eventHandler = handler;
  }

  // src/common/wincmn.cpp 2.4.2: the new handler sees events first, then passes them on.
  void PushEventHandler(ShellEvtHandler* handler);
  ShellEvtHandler* PopEventHandler(bool deleteHandler = false);

  void GetClientSize(int* width, int* height) const;
  ShellSize GetClientSize() const;
  void ScreenToClient(int* x, int* y) const;
  ShellPoint ScreenToClient(const ShellPoint& point) const;

  // Set by the window system (issue #256).
  void SetClientArea(int screenX, int screenY, int width, int height);

protected:
  // A top-level window with its own native window (TopLevelWindow's constructor).
  void SetTopLevel(void* platformWindow);

private:
  ShellWindow* m_parent = nullptr;
  std::vector<ShellWindow*> m_children;
  bool m_topLevel = false;
  bool m_nativeChild = false;
  ShellNativeHandle m_handle = 0;
  void* m_platformWindow = nullptr;
  bool m_shown = false;
  ShellEvtHandler* m_eventHandler = this;
  int m_screenX = 0;
  int m_screenY = 0;
  int m_clientWidth = 0;
  int m_clientHeight = 0;
};
