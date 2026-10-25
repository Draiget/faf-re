// Engine addition (dedicated-server plan WPL.4, WPR.11): the folder prompt of
// CArmyStats::DumpStats (the wxDirDialog at 0x0070C438), moved out of the sim's
// CArmyStats.cpp and installed through moho::sSnapshotDirectoryPrompt before
// main. The dialog code is the original's; CArmyStats.cpp restores the sim's
// 24-bit x87 precision after it returns, as before.
//
// wx is included first: it owns the windows.h inclusion so that
// wx/msw/winundef.h can drop the CreateDialog/GetClassInfo macros before the
// wx class declarations are parsed.
#include "platform/WxWidgets.h"
#include <wx/dirdlg.h>

#include "gpg/core/containers/String.h"
#include "legacy/containers/String.h"
#include "moho/sim/CArmyStats.h"

namespace
{
  void PromptSnapshotDirectory(msvc8::string& directory)
  {
    wxDirDialog directoryDialog(
      nullptr,
      wxT("Dump snap shot data to"),
      gpg::STR_Utf8ToWide(directory.c_str()).c_str(),
      wxDD_NEW_DIR_BUTTON
    );
    if (directoryDialog.ShowModal() == wxID_OK) {
      directory.assign(gpg::STR_WideToUtf8(directoryDialog.GetPath().c_str()), 0, msvc8::string::npos);
    }
  }

  [[maybe_unused]] const bool gSnapshotDirectoryPromptSet =
    (moho::sSnapshotDirectoryPrompt = &PromptSnapshotDirectory, true);
} // namespace
