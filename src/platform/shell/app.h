#pragma once

// Engine addition (issues #255, #407): the shell's application: the global application object,
// its start hook, its event pump (the window system's events, platform/Window.h) and the
// keep-going flag the main loop reads. See defs.h.

#include "platform/shell/event.h"

class ShellApp : public ShellEvtHandler
{
public:
  ShellApp();
  ~ShellApp() override;

  // Called once the application object exists, before the engine's own loop starts.
  virtual bool OnInit()
  {
    return true;
  }
  // True while the window system has events queued.
  virtual bool Pending();
  // Delivers one queued event.
  virtual void Dispatch();
  // The window library's idle pass: true while more idle work is wanted. Nothing here waits for idle time (the
  // stand-in's windows are deleted by Destroy at once), so it returns false.
  virtual bool ProcessIdle()
  {
    return false;
  }
  // Asks the main loop to return: clears m_keepGoing, as the 2.4.2 window library does.
  virtual void ExitMainLoop();
  // Called by the main loop once it has ended.
  virtual int OnExit()
  {
    return 0;
  }
  // The 2.4.2 window library: closing the last frame ends the loop. The window system's close event does that here.
  void SetExitOnFrameDelete(
    const bool exitOnFrameDelete
  )
  {
    m_exitOnFrameDelete = exitOnFrameDelete;
  }
  bool GetExitOnFrameDelete() const
  {
    return m_exitOnFrameDelete;
  }
  // The 2.4.2 window library frees its global state here; the shell deletes the application object.
  static void CleanUp();

  // The function IMPLEMENT_APP_NO_MAIN registers to create the application (CreateApp).
  using InitializerFunction = ShellApp* (*)();
  static void SetInitializerFunction(
    InitializerFunction function
  )
  {
    sInitializer = function;
  }
  static InitializerFunction GetInitializerFunction()
  {
    return sInitializer;
  }

protected:
  // The 2.4.2 window library App::m_keepGoing: the main loop runs while it is set.
  int m_keepGoing = TRUE;
  bool m_exitOnFrameDelete = true;

private:
  static inline InitializerFunction sInitializer = nullptr;
};

extern ShellApp* gShellApp;

// The 2.4.2 window library's start for programs with their own main loop: creates the application through the
// registered initializer and calls OnInit. The instance and command-line arguments are Windows';
// `enterLoop` false is what the engine passes (WIN_AppExecute pumps events itself).
using ShellInstanceHandle = void*;
int ShellEntry(
  ShellInstanceHandle instance,
  ShellInstanceHandle previousInstance,
  char* commandLine,
  int showCommand,
  bool enterLoop = true
);

// The 2.4.2 window library: registers the application's creator, as AppInitializer does.
class ShellAppInitializer
{
public:
  explicit ShellAppInitializer(
    const ShellApp::InitializerFunction function
  )
  {
    ShellApp::SetInitializerFunction(function);
  }
};

// The 2.4.2 window library: `GetApp()` returning the application's own class, and the creator Entry calls.
#define DECLARE_APP(appname) extern appname& ShellGetApp();
#define IMPLEMENT_APP_NO_MAIN(appname)                                                                                 \
  ShellApp* ShellCreateApp()                                                                                           \
  {                                                                                                                    \
    return new appname;                                                                                                \
  }                                                                                                                    \
  ShellAppInitializer gShellAppInitializer(&ShellCreateApp);                                                           \
  appname& ShellGetApp()                                                                                               \
  {                                                                                                                    \
    return *static_cast<appname*>(gShellApp);                                                                          \
  }
