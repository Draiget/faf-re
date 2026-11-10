#pragma once

// Engine addition (issue #255): wx 2.4.2's device context and brushes (wx/dc.h, wx/dcclient.h,
// wx/brush.h), for the Linux client. See wx/defs.h in this folder. The application shell paints
// only a black background before the renderer presents; on Linux the renderer owns the whole
// window surface, so drawing through a DC does nothing.

#include <wx/window.h>

class wxBrush
{
public:
  wxBrush() = default;
};

extern wxBrush* wxBLACK_BRUSH;
extern wxBrush wxNullBrush;

class wxDC : public wxObject
{
public:
  wxDC() = default;
  explicit wxDC(wxWindow* const window)
    : m_window(window)
  {}

  void SetBrush(const wxBrush& brush) { (void)brush; }
  void GetSize(int* const width, int* const height) const
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
  void DrawRectangle(const int x, const int y, const int width, const int height)
  {
    (void)x;
    (void)y;
    (void)width;
    (void)height;
  }

private:
  wxWindow* m_window = nullptr;
};

class wxPaintDC : public wxDC
{
public:
  explicit wxPaintDC(wxWindow* const window)
    : wxDC(window)
  {}
};

class wxClientDC : public wxDC
{
public:
  explicit wxClientDC(wxWindow* const window)
    : wxDC(window)
  {}
};
