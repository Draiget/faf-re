#pragma once

// Engine addition (issue #255): wx 2.4.2's top-level window and frame (wx/toplevel.h,
// wx/frame.h) as the Linux client's shell uses them: the main frame's size, state and style. See
// wx/defs.h in this folder. The window system (issue #256) creates the native window and reports
// its size and state back.

#include <wx/bitmap.h>
#include <wx/string.h>
#include <wx/window.h>

// wx 2.4.2 wx/defs.h: frame styles and size flags.
#define wxMINIMIZE_BOX 0x0400
#define wxMAXIMIZE_BOX 0x0200
#define wxTHICK_FRAME 0x0040
#define wxSYSTEM_MENU 0x0800
#define wxCAPTION 0x20000000
#define wxRESIZE_BORDER 0x00000040
#define wxCLOSE_BOX 0x1000
#define wxCLIP_CHILDREN 0x00400000
#define wxDEFAULT_FRAME_STYLE                                                                                          \
  (wxSYSTEM_MENU | wxRESIZE_BORDER | wxMINIMIZE_BOX | wxMAXIMIZE_BOX | wxCAPTION | wxCLIP_CHILDREN)
#define wxSIZE_USE_EXISTING 0x0000
#define wxBITMAP_TYPE_ICO_RESOURCE 4

extern const wchar_t* wxFrameNameStr;

class wxIcon : public wxBitmap
{
public:
  wxIcon() = default;
  wxIcon(
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
class wxTopLevelWindow : public wxWindow
{
public:
  wxTopLevelWindow() = default;
  wxTopLevelWindow(
    wxWindow* parent,
    wxWindowID id,
    const wxString& title,
    const wxPoint& pos = wxDefaultPosition,
    const wxSize& size = wxDefaultSize,
    long style = wxDEFAULT_FRAME_STYLE,
    const wchar_t* name = wxFrameNameStr
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
    const wxIcon& icon
  )
  {
    (void)icon;
  }
  virtual void SetTitle(const wxString& title);
  virtual wxString GetTitle() const
  {
    return m_title;
  }

  // What the window system reports (WxStandIn.cpp's event delivery).
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
  wxString m_title;
  long m_windowStyle = 0;
  int m_minWidth = -1;
  int m_minHeight = -1;
  bool m_maximized = false;
  bool m_iconized = false;
  bool m_fullScreen = false;
};

class wxFrame : public wxTopLevelWindow
{
public:
  wxFrame() = default;
  wxFrame(
    wxWindow* const parent,
    const wxWindowID id,
    const wxString& title,
    const wxPoint& pos = wxDefaultPosition,
    const wxSize& size = wxDefaultSize,
    const long style = wxDEFAULT_FRAME_STYLE,
    const wchar_t* const name = wxFrameNameStr
  )
    : wxTopLevelWindow(parent, id, title, pos, size, style, name)
  {}
  // The name as a wxString, as WWinManagedFrame passes it (the window keeps no name).
  wxFrame(
    wxWindow* const parent,
    const wxWindowID id,
    const wxString& title,
    const wxPoint& pos,
    const wxSize& size,
    const long style,
    const wxString& name
  )
    : wxTopLevelWindow(parent, id, title, pos, size, style, name.c_str())
  {}
};
