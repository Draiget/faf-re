#pragma once

// Engine addition (issue #255): the part of wx 2.4.2's wxApp (wx/app.h) the Linux client's game
// code uses: the global application, its pending-event pump and the request to leave the main
// loop. See wx/defs.h in this folder. The window system (issue #256) supplies the events.

#include <wx/event.h>

class wxApp : public wxEvtHandler
{
public:
  wxApp();
  ~wxApp() override;

  // True while the window system has events queued.
  virtual bool Pending();
  // Delivers one queued event.
  virtual void Dispatch();
  // Asks the main loop to return.
  virtual void ExitMainLoop();

  bool IsMainLoopRunning() const { return !m_exitRequested; }

protected:
  bool m_exitRequested = false;
};

extern wxApp* wxTheApp;

// wx 2.4.2: `wxGetApp()` returning the application's own class.
#define DECLARE_APP(appname) extern appname& wxGetApp();
#define IMPLEMENT_APP_NO_MAIN(appname) \
  appname& wxGetApp() { return *static_cast<appname*>(wxTheApp); }
