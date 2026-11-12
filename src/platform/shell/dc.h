#pragma once

// Engine addition (issues #255, #407): the shell's device context and brushes. The viewport
// painted only a black background before the renderer presented; the renderer owns the whole
// window surface, so drawing through a DC does nothing. See defs.h.

#include "platform/shell/window.h"

class ShellBrush
{
public:
  ShellBrush() = default;
};

extern ShellBrush* gShellBlackBrush;
extern ShellBrush gShellNullBrush;

class SHELL_DC : public ShellObject
{
public:
  SHELL_DC() = default;
  explicit SHELL_DC(
    ShellWindow* const window
  )
    : m_window(window)
  {}

  void SetBrush(
    const ShellBrush& brush
  )
  {
    (void)brush;
  }
  void GetSize(
    int* const width,
    int* const height
  ) const
  {
    if (m_window != nullptr) {
      m_window->GetClientSize(width, height);
      return;
    }
    if (width != nullptr) {
      *width = 0;
    }
    if (height != nullptr) {
      *height = 0;
    }
  }
  void DrawRectangle(
    const int x,
    const int y,
    const int width,
    const int height
  )
  {
    (void)x;
    (void)y;
    (void)width;
    (void)height;
  }

private:
  ShellWindow* m_window = nullptr;
};

class ShellPaintDC : public SHELL_DC
{
public:
  explicit ShellPaintDC(
    ShellWindow* const window
  )
    : SHELL_DC(window)
  {}
};

class ShellClientDC : public SHELL_DC
{
public:
  explicit ShellClientDC(
    ShellWindow* const window
  )
    : SHELL_DC(window)
  {}
};
