#pragma once

// Engine addition (issue #255): wx 2.4.2's point, size and rectangle (wx/gdicmn.h), for the
// Linux client. See wx/defs.h in this folder.

#include <wx/defs.h>

class wxSize
{
public:
  int x = 0;
  int y = 0;

  wxSize() = default;
  wxSize(
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

class wxPoint
{
public:
  int x = 0;
  int y = 0;

  wxPoint() = default;
  wxPoint(
    const int px,
    const int py
  )
    : x(px)
    , y(py)
  {}
};

class wxRect
{
public:
  int x = 0;
  int y = 0;
  int width = 0;
  int height = 0;

  wxRect() = default;
  wxRect(
    const wxPoint& pos,
    const wxSize& size
  )
    : x(pos.x)
    , y(pos.y)
    , width(size.x)
    , height(size.y)
  {}

  // wx 2.4.2 src/common/gdicmn.cpp: the right and bottom edges are outside.
  bool Inside(
    const int cx,
    const int cy
  ) const
  {
    return cx >= x && cy >= y && cy < y + height && cx < x + width;
  }
};

extern const wxPoint wxDefaultPosition;
extern const wxSize wxDefaultSize;

/**
 * The mouse position in screen coordinates. The window system (issue #256) keeps it current;
 * until then it is (0, 0).
 */
wxPoint wxGetMousePosition();
