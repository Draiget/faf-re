// Engine addition (issues #255, #256): the Linux client's entry point, in WinMain's place
// (moho/app/WinMain.cpp, Windows only). It keeps what WinMain does around the game itself: the
// main thread's name, the application object run by WIN_AppExecute, its exit value, and the
// fatal-error report for an exception nothing caught. WinMain's Windows-only switches (the
// crash tests, hardware watches, accessibility keys, Media Center) have no Linux counterpart yet.

#include <exception>

#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "gpg/gal/Error.hpp"
#include "moho/app/CScApp.h"
#include "moho/app/WinApp.h"

int main()
{
  gpg::SetThreadName(0xFFFFFFFFu, "Main");

  int exitCode = 0;
  try {
    CScApp app;
    moho::WIN_AppExecute(&app);
    exitCode = app.GetExitValue();
  } catch (const gpg::gal::Error& galError) {
    gpg::Die("GAL Exception: %s (%s:%d)", galError.what(), galError.GetFile(), galError.GetLine());
  } catch (const std::exception& exception) {
    gpg::Die("Unhandled exception:\n\n%s", exception.what());
  }
  return exitCode;
}
