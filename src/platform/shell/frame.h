#pragma once

// Engine addition (issues #255, #407): the shell's top-level window and frame: the main frame's
// size, state and style. The window system (platform/Window.h) creates the native window and
// reports its size and state back. See defs.h.

#include "platform/shell/bitmap.h"
#include "platform/shell/string.h"
#include "platform/shell/window.h"

// The 2.4.2 window library defs.h: frame styles and size flags.
#define SHELL_MINIMIZE_BOX 0x0400
#define SHELL_MAXIMIZE_BOX 0x0200
#define SHELL_THICK_FRAME 0x0040
#define SHELL_SYSTEM_MENU 0x0800
#define SHELL_CAPTION 0x20000000
#define SHELL_RESIZE_BORDER 0x00000040
#define SHELL_CLOSE_BOX 0x1000
#define SHELL_CLIP_CHILDREN 0x00400000
#define SHELL_DEFAULT_FRAME_STYLE                                                                                      \
  (SHELL_SYSTEM_MENU | SHELL_RESIZE_BORDER | SHELL_MINIMIZE_BOX | SHELL_MAXIMIZE_BOX | SHELL_CAPTION |                 \
   SHELL_CLIP_CHILDREN)
#define SHELL_SIZE_USE_EXISTING 0x0000
#define SHELL_BITMAP_TYPE_ICO_RESOURCE 4

extern const wchar_t* kShellFrameName;

class ShellIcon : public ShellBitmap
{
public:
  ShellIcon() = default;
  ShellIcon(
    const wchar_t* const name,
    const long type
  )
  {
    (void)name;
    (void)type;
  }
};

// A window of its own on the desktop: the window system (platform/Window.h) makes its native
// window, hidden until Show, and reports its moves, sizes and state back.
class ShellTopLevelWindow : public ShellWindow
{
public:
  ShellTopLevelWindow() = default;
  ShellTopLevelWindow(
    ShellWindow* parent,
    ShellWindowID id,
    const ShellString& title,
    const ShellPoint& pos = kShellDefaultPosition,
    const ShellSize& size = kShellDefaultSize,
    long style = SHELL_DEFAULT_FRAME_STYLE,
    const wchar_t* name = kShellFrameName
  );

  virtual void Maximize(bool maximize = true);
  virtual bool IsMaximized() const
  {
    return m_maximized;
  }
  virtual void Iconize(bool iconize = true);
  virtual bool IsIconized() const
  {
    return m_iconized;
  }
  virtual bool ShowFullScreen(bool show, long style = 0);
  virtual bool IsFullScreen() const
  {
    return m_fullScreen;
  }
  virtual void SetIcon(
    const ShellIcon& icon
  )
  {
    (void)icon;
  }
  virtual void SetTitle(const ShellString& title);
  virtual ShellString GetTitle() const
  {
    return m_title;
  }

  // An item the engine added to the window's system menu was chosen
  // (platform::window::AddSystemMenuItem), as WM_SYSCOMMAND reached the window library's frames.
  virtual void OnSystemCommand(
    const int command
  )
  {
    (void)command;
  }

  // What the window system reports (Shell.cpp's event delivery).
  void NoteMaximized(
    const bool maximized
  )
  {
    m_maximized = maximized;
  }
  void NoteIconized(
    const bool iconized
  )
  {
    m_iconized = iconized;
  }

  void SetSizeHints(
    const int minWidth,
    const int minHeight,
    const int maxWidth = -1,
    const int maxHeight = -1
  )
  {
    m_minWidth = minWidth;
    m_minHeight = minHeight;
    (void)maxWidth;
    (void)maxHeight;
  }
  void SetClientSize(
    const int width,
    const int height
  )
  {
    SetSize(width, height);
  }
  void SetWindowStyleFlag(
    const long style
  )
  {
    m_windowStyle = style;
  }
  long GetWindowStyleFlag() const
  {
    return m_windowStyle;
  }

private:
  ShellString m_title;
  long m_windowStyle = 0;
  int m_minWidth = -1;
  int m_minHeight = -1;
  bool m_maximized = false;
  bool m_iconized = false;
  bool m_fullScreen = false;
};

class ShellFrame : public ShellTopLevelWindow
{
public:
  ShellFrame() = default;
  ShellFrame(
    ShellWindow* const parent,
    const ShellWindowID id,
    const ShellString& title,
    const ShellPoint& pos = kShellDefaultPosition,
    const ShellSize& size = kShellDefaultSize,
    const long style = SHELL_DEFAULT_FRAME_STYLE,
    const wchar_t* const name = kShellFrameName
  )
    : ShellTopLevelWindow(parent, id, title, pos, size, style, name)
  {}
  // The name as a String, as WWinManagedFrame passes it (the window keeps no name).
  ShellFrame(
    ShellWindow* const parent,
    const ShellWindowID id,
    const ShellString& title,
    const ShellPoint& pos,
    const ShellSize& size,
    const long style,
    const ShellString& name
  )
    : ShellTopLevelWindow(parent, id, title, pos, size, style, name.c_str())
  {}
};
