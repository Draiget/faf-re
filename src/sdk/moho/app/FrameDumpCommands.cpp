// `DUMP_PromptFilename` (0x007F5500) opens a `wxDirDialog`, so this translation
// unit pulls in the wx dialog family. wx has to be included first: it needs to
// own the `windows.h` inclusion so that `wx/msw/winundef.h` can drop the
// `CreateDialog`/`GetClassInfo` macros before the wx class declarations are
// parsed.
#include <wx/defs.h>
#include <wx/dirdlg.h>

#include "moho/app/FrameDumpCommands.h"

#include <cstdlib>
#include <cstring>
#include <float.h>

#include "gpg/core/containers/String.h"
#include "moho/console/CConCommand.h"
#include "moho/console/CConFunc.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/misc/StatItem.h"

namespace
{
  /// 0x00E3FB5C, the `.data` initializer of `Moho::CConFunc_dump_Frames` (+0x08).
  constexpr const char* kConsoleStartupConDumpFramesDescription = "Toggle dumping of video frames.";

  /// 0x00E3FBB8, the `.data` initializer of `Moho::CConFunc_dump_Frame` (+0x08).
  constexpr const char* kConsoleStartupConDumpFrameDescription =
    "Dump a single video frame. A directory can be specified, otherwise it will prompt for one.";

  // 0x00F5A8F8 and 0x00F5A908. The registrars below only patch the vftable and
  // the `mFunc` slot at +0x0C; the name and description lanes are `.data`
  // initializers, which is where the two strings above come from.
  moho::CConFunc gCConFunc_dump_Frames{};
  moho::CConFunc gCConFunc_dump_Frame{};
} // namespace

namespace moho
{
  /**
   * Address: 0x007F5450 (FUN_007F5450, Moho::DUMP_UpdateTimestamp)
   *
   * What it does:
   * Captures the current wall clock through `CTimeStamp` - the binary inlines
   * that constructor's `_time64`/`_ftime64` pair at 0x007F5456/0x007F546B -
   * formats it, and stores it in `dump_Timestamp` with spaces turned into
   * underscores and colons removed so the result is filename-safe
   * (0x007F54D0 / 0x007F54F1).
   *
   * The binary re-runs the string constructor in place on the global at
   * 0x007F54B2; `assign` is the same store without leaking the previous buffer.
   */
  void DUMP_UpdateTimestamp()
  {
    const CTimeStamp now{};
    const char* const text = now.GetString();

    dump_Timestamp.assign(text, std::strlen(text));
    (void)gpg::STR_Replace(dump_Timestamp, " ", "_", 1u);
    (void)gpg::STR_Replace(dump_Timestamp, ":", "", 1u);
  }

  /**
   * Address: 0x007F5500 (FUN_007F5500, Moho::DUMP_PromptFilename)
   *
   * What it does:
   * Seeds a directory picker with the current `dump_frameDumpName`, or with
   * `%USERPROFILE%/Desktop/SC_CAPTURE` when nothing has been chosen yet
   * (0x007F5530..0x007F5563). On acceptance the picked path is converted back
   * to UTF-8 and stored (0x007F56D9..0x007F5705).
   *
   * wx leaves the x87 control word on its own setting, so the 24-bit precision
   * the sim runs at is restored right after the dialog closes
   * (`_controlfp(_PC_24, _MCW_PC)` at 0x007F5745).
   */
  bool DUMP_PromptFilename()
  {
    msvc8::string defaultDirectory;
    defaultDirectory.assign(dump_frameDumpName, 0, msvc8::string::npos);

    if (defaultDirectory.empty()) {
      defaultDirectory.assign(
        gpg::STR_Printf("%s/Desktop/SC_CAPTURE", std::getenv("USERPROFILE")), 0, msvc8::string::npos
      );
    }

    bool accepted = false;

    wxDirDialog directoryDialog(
      nullptr,
      wxT("Dump frames to"),
      gpg::STR_Utf8ToWide(defaultDirectory.c_str()).c_str(),
      wxDD_NEW_DIR_BUTTON
    );
    if (directoryDialog.ShowModal() == wxID_OK) {
      dump_frameDumpName.assign(
        gpg::STR_WideToUtf8(directoryDialog.GetPath().c_str()), 0, msvc8::string::npos
      );
      accepted = true;
    }

    (void)_controlfp(_PC_24, _MCW_PC);

    return accepted;
  }

  /**
   * Address: 0x007F57F0 (FUN_007F57F0, Moho::DUMP_Frames)
   *
   * What it does:
   * The `dump_Frames` console toggle. While dumping is armed it disarms and
   * reports the frame it stopped at; otherwise it prompts for a directory and
   * arms an unbounded dump (`dump_frameRate = -1`, the sentinel
   * `REN_MaybeDumpFrame` never counts down), then refreshes the timestamp.
   *
   * The binary reads no command arguments here.
   */
  void DUMP_Frames(void* const /*commandArgs*/)
  {
    if (dump_frameRate != 0) {
      dump_frameRate = 0;
      CON_Printf(
        "Frame dumping to '%s' stopped at frame %d", dump_frameDumpName.c_str(), dump_outputFrameNumber
      );
      return;
    }

    // `neg`/`sbb`/`neg` at 0x007F5820: the accepted flag becomes -1, the
    // unbounded-dump sentinel, and a refused prompt leaves dumping off.
    dump_frameRate = DUMP_PromptFilename() ? -1 : 0;
    DUMP_UpdateTimestamp();
  }

  /**
   * Address: 0x007F5840 (FUN_007F5840, Moho::DUMP_Frame)
   *
   * What it does:
   * The `dump_Frame` console command: arms a single-frame dump
   * (`dump_frameRate = 1`) and refreshes the timestamp.
   *
   * With exactly one argument, `.` means "keep the directory already chosen" -
   * and if none has been chosen yet it falls back to the picker, in which case
   * a refusal leaves dumping disarmed. Any other argument is taken as the
   * output directory verbatim. With no argument (or more than one) the user's
   * screenshot directory is used.
   *
   * The `.` test is the binary's `compare(0, size, ".", 1)` at 0x007F589F,
   * which is simply "this token is not exactly a dot".
   */
  void DUMP_Frame(void* const commandArgs)
  {
    const ConCommandArgsView args = GetConCommandArgsView(commandArgs);

    if (args.Count() == 2u) {
      const msvc8::string& directoryToken = *args.At(1);

      if (directoryToken.view() != ".") {
        dump_frameDumpName.assign(directoryToken, 0, msvc8::string::npos);
      } else if (dump_frameDumpName.empty()) {
        dump_frameRate = DUMP_PromptFilename() ? 1 : 0;
        if (dump_frameRate == 0) {
          return;
        }

        DUMP_UpdateTimestamp();
        return;
      }

      dump_frameRate = 1;
    } else {
      dump_frameDumpName.assign(USER_GetScreenshotDir(), 0, msvc8::string::npos);
      dump_frameRate = 1;
    }

    DUMP_UpdateTimestamp();
  }

  /**
   * Address: 0x00C04240 (FUN_00C04240, ??1CConFunc_dump_Frames@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `dump_Frames`.
   */
  void cleanup_CConFunc_dump_Frames()
  {
    CleanupStartupConCommand(gCConFunc_dump_Frames);
  }

  /**
   * Address: 0x00C04270 (FUN_00C04270, ??1CConFunc_dump_Frame@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup command storage for `dump_Frame`.
   */
  void cleanup_CConFunc_dump_Frame()
  {
    CleanupStartupConCommand(gCConFunc_dump_Frame);
  }

  /**
   * Address: 0x00BE0F50 (FUN_00BE0F50, register_CConFunc_dump_Frames)
   *
   * What it does:
   * Registers the startup console callback for `dump_Frames`. The store
   * `Moho__CConFunc_dump_Frames.mFunc = offset Moho__DUMP_Frames` at
   * 0x00BE0F70 is the only reference to `Moho::DUMP_Frames` in the image.
   */
  void register_CConFunc_dump_Frames()
  {
    gCConFunc_dump_Frames.InitializeRecovered(
      kConsoleStartupConDumpFramesDescription, "dump_Frames", &moho::DUMP_Frames
    );
    (void)std::atexit(&cleanup_CConFunc_dump_Frames);
  }

  /**
   * Address: 0x00BE0F90 (FUN_00BE0F90, register_CConFunc_dump_Frame)
   *
   * What it does:
   * Registers the startup console callback for `dump_Frame`. The store
   * `Moho__CConFunc_dump_Frame.mFunc = offset Moho__DUMP_Frame` at 0x00BE0FB0
   * is the only reference to `Moho::DUMP_Frame` in the image.
   */
  void register_CConFunc_dump_Frame()
  {
    gCConFunc_dump_Frame.InitializeRecovered(
      kConsoleStartupConDumpFrameDescription, "dump_Frame", &moho::DUMP_Frame
    );
    (void)std::atexit(&cleanup_CConFunc_dump_Frame);
  }
} // namespace moho

namespace
{
  // The binary runs both registrars from the CRT static-initializer array; a
  // file-scope bootstrap object reproduces that.
  struct FrameDumpConsoleRegistrations
  {
    FrameDumpConsoleRegistrations()
    {
      moho::register_CConFunc_dump_Frames();
      moho::register_CConFunc_dump_Frame();
    }
  };

  [[maybe_unused]] FrameDumpConsoleRegistrations gFrameDumpConsoleRegistrations;
} // namespace
