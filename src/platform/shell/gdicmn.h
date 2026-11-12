#pragma once

// Engine addition (issues #255, #407): the shell's point, size and rectangle. See defs.h.

#include "platform/shell/defs.h"

class ShellSize
{
public:
  int x = 0;
  int y = 0;

  ShellSize() = default;
  ShellSize(
    const int width,
    const int height
  )
    : x(width)
    , y(height)
  {}

  int GetWidth() const
  {
    return x;
  }
  int GetHeight() const
  {
    return y;
  }
};

class ShellPoint
{
public:
  int x = 0;
  int y = 0;

  ShellPoint() = default;
  ShellPoint(
    const int px,
    const int py
  )
    : x(px)
    , y(py)
  {}
};

class ShellRect
{
public:
  int x = 0;
  int y = 0;
  int width = 0;
  int height = 0;

  ShellRect() = default;
  ShellRect(
    const ShellPoint& pos,
    const ShellSize& size
  )
    : x(pos.x)
    , y(pos.y)
    , width(size.x)
    , height(size.y)
  {}

  // The 2.4.2 window library src/common/gdicmn.cpp: the right and bottom edges are outside.
  bool Inside(
    const int cx,
    const int cy
  ) const
  {
    return cx >= x && cy >= y && cy < y + height && cx < x + width;
  }
};

extern const ShellPoint kShellDefaultPosition;
extern const ShellSize kShellDefaultSize;

/**
 * The mouse position in screen coordinates. The window system (issue #256) keeps it current;
 * until then it is (0, 0).
 */
ShellPoint ShellGetMousePosition();
