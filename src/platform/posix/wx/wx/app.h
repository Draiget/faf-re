#pragma once

// Engine addition (issue #255): the part of wx 2.4.2's wxApp (wx/app.h) the Linux client uses:
// the global application, its start hook, its pending-event pump and the keep-going flag the
// main loop reads. See wx/defs.h in this folder. The window system (issue #256) supplies the
// events.

#include <wx/event.h>

class wxApp : public wxEvtHandler
{
public:
  wxApp();
  ~wxApp() override;

  // Called once the application object exists, before the engine's own loop starts.
  virtual bool OnInit() { return true; }
  // True while the window system has events queued.
  virtual bool Pending();
  // Delivers one queued event.
  virtual void Dispatch();
  // Asks the main loop to return: clears m_keepGoing, as wx 2.4.2 does.
  virtual void ExitMainLoop();

protected:
  // wx 2.4.2 wxApp::m_keepGoing: the main loop runs while it is set.
  int m_keepGoing = TRUE;
};

extern wxApp* wxTheApp;

// wx 2.4.2: `wxGetApp()` returning the application's own class.
#define DECLARE_APP(appname) extern appname& wxGetApp();
#define IMPLEMENT_APP_NO_MAIN(appname) \
  appname& wxGetApp() { return *static_cast<appname*>(wxTheApp); }
