// Engine addition (dedicated-server plan WPL.4, WPR.11): the folder prompt of
// CArmyStats::DumpStats (the wxDirDialog at 0x0070C438 in the binary), moved out
// of the sim's CArmyStats.cpp and installed through moho::sSnapshotDirectoryPrompt
// before main. CArmyStats.cpp restores the sim's 24-bit x87 precision after it
// returns, as before. The picker is the system's through the window system since
// issue #411 (platform::window::PickFolder); without one nothing is asked.

#include <string>

#include "legacy/containers/String.h"
#include "moho/sim/CArmyStats.h"
#include "platform/Window.h"

namespace
{
  void PromptSnapshotDirectory(
    fa::string& directory
  )
  {
    std::string folder = directory.c_str();
    if (platform::window::PickFolder("Dump snap shot data to", folder)) {
      directory.assign(folder.c_str(), 0, fa::string::npos);
    }
  }

  [[maybe_unused]] const bool gSnapshotDirectoryPromptSet =
    (moho::sSnapshotDirectoryPrompt = &PromptSnapshotDirectory, true);
} // namespace
