#pragma once

// Engine addition (issue #255): the part of wx 2.4.2's wxWindow (wx/window.h) the Linux
// client's game code uses: the event handler chain and the client area. See wx/defs.h in this
// folder. The window system (issue #256) keeps the size and screen position current.

#include <wx/event.h>
#include <wx/gdicmn.h>

class wxWindow : public wxEvtHandler
{
public:
  wxWindow() = default;
  ~wxWindow() override;

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
  wxEvtHandler* m_eventHandler = this;
  int m_screenX = 0;
  int m_screenY = 0;
  int m_clientWidth = 0;
  int m_clientHeight = 0;
};
