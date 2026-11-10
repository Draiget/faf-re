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
  // wx's idle pass: true while more idle work is wanted. Nothing here waits for idle time (the
  // stand-in's windows are deleted by Destroy at once), so it returns false.
  virtual bool ProcessIdle() { return false; }
  // Asks the main loop to return: clears m_keepGoing, as wx 2.4.2 does.
  virtual void ExitMainLoop();
  // Called by the main loop once it has ended.
  virtual int OnExit() { return 0; }
  // wx 2.4.2: closing the last frame ends the loop. The window system's close event does that here.
  void SetExitOnFrameDelete(const bool exitOnFrameDelete) { m_exitOnFrameDelete = exitOnFrameDelete; }
  bool GetExitOnFrameDelete() const { return m_exitOnFrameDelete; }
  // wx 2.4.2 frees its global state here; the stand-in deletes the application object.
  static void CleanUp();

  // The function IMPLEMENT_APP_NO_MAIN registers to create the application (wxCreateApp).
  using InitializerFunction = wxApp* (*)();
  static void SetInitializerFunction(InitializerFunction function) { sInitializer = function; }
  static InitializerFunction GetInitializerFunction() { return sInitializer; }

protected:
  // wx 2.4.2 wxApp::m_keepGoing: the main loop runs while it is set.
  int m_keepGoing = TRUE;
  bool m_exitOnFrameDelete = true;

private:
  static inline InitializerFunction sInitializer = nullptr;
};

extern wxApp* wxTheApp;

// wx 2.4.2's start for programs with their own main loop: creates the application through the
// registered initializer and calls OnInit. The instance and command-line arguments are Windows';
// `enterLoop` false is what the engine passes (WIN_AppExecute pumps events itself).
using WXHINSTANCE = void*;
int wxEntry(WXHINSTANCE instance, WXHINSTANCE previousInstance, char* commandLine, int showCommand, bool enterLoop = true);

// wx 2.4.2: registers the application's creator, as wxAppInitializer does.
class wxAppInitializer
{
public:
  explicit wxAppInitializer(const wxApp::InitializerFunction function) { wxApp::SetInitializerFunction(function); }
};

// wx 2.4.2: `wxGetApp()` returning the application's own class, and the creator wxEntry calls.
#define DECLARE_APP(appname) extern appname& wxGetApp();
#define IMPLEMENT_APP_NO_MAIN(appname) \
  wxApp* wxCreateApp() { return new appname; } \
  wxAppInitializer wxTheAppInitializer(&wxCreateApp); \
  appname& wxGetApp() { return *static_cast<appname*>(wxTheApp); }
