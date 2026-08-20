#pragma once

#include "legacy/containers/String.h"

namespace moho
{
  // Frame-dump state. Defined in `moho/app/WxRuntimeTypes.cpp` next to its
  // consumer `REN_MaybeDumpFrame` (0x007F5970); the two console commands below
  // are the only writers. The declarations live here rather than in
  // `WxRuntimeTypes.h` because that header re-declares the wx class hierarchy
  // and cannot be combined with the real `<wx/dirdlg.h>` this command family
  // needs.

  /// 0x010A6334 (?dump_frameRate@Moho@@3HA). Zero disables dumping, a positive
  /// value dumps one frame per render and counts down, a negative value dumps
  /// indefinitely.
  extern int dump_frameRate;

  /// 0x010A6418 (?dump_outputFrameNumber@Moho@@3HA). Monotonic index appended
  /// to each dumped frame's filename.
  extern int dump_outputFrameNumber;

  /// 0x00F5A8A4. Timestamp token embedded in dumped frame filenames.
  extern msvc8::string dump_Timestamp;

  /// 0x00F5A8C0. Base directory / name prefix for dumped frame files.
  extern msvc8::string dump_frameDumpName;

  /**
   * Address: 0x007F5450 (FUN_007F5450, Moho::DUMP_UpdateTimestamp)
   *
   * IDA signature:
   * void __cdecl Moho::DUMP_UpdateTimestamp();
   *
   * What it does:
   * Refreshes `dump_Timestamp` from the wall clock and sanitizes it for use in
   * a filename: spaces become underscores and colons are dropped.
   */
  void DUMP_UpdateTimestamp();

  /**
   * Address: 0x007F5500 (FUN_007F5500, Moho::DUMP_PromptFilename)
   *
   * IDA signature:
   * char __cdecl Moho::DUMP_PromptFilename();
   *
   * What it does:
   * Offers a directory picker seeded with the current `dump_frameDumpName`,
   * falling back to `%USERPROFILE%/Desktop/SC_CAPTURE` when none is set yet.
   * Returns true and stores the chosen directory when the user accepts.
   */
  [[nodiscard]] bool DUMP_PromptFilename();

  /**
   * Address: 0x007F57F0 (FUN_007F57F0, Moho::DUMP_Frames)
   *
   * IDA signature:
   * void __cdecl Moho::DUMP_Frames();
   *
   * What it does:
   * `dump_Frames` console command. Toggles continuous frame dumping: running
   * means stop and report the frame reached, stopped means prompt for a
   * directory and arm an unbounded dump.
   */
  void DUMP_Frames(void* commandArgs);

  /**
   * Address: 0x007F5840 (FUN_007F5840, Moho::DUMP_Frame)
   *
   * IDA signature:
   * int __cdecl sub_7F5840(int commandArgs);
   *
   * What it does:
   * `dump_Frame` console command. Arms a single-frame dump, taking the output
   * directory from the one optional argument, from the previous directory when
   * that argument is `.`, or from the user's screenshot directory otherwise.
   */
  void DUMP_Frame(void* commandArgs);

  /**
   * Address: 0x00BE0F50 (FUN_00BE0F50, register_CConFunc_dump_Frames)
   *
   * What it does:
   * Registers the `dump_Frames` startup console command and installs its
   * process-exit teardown.
   */
  void register_CConFunc_dump_Frames();

  /**
   * Address: 0x00BE0F90 (FUN_00BE0F90, register_CConFunc_dump_Frame)
   *
   * What it does:
   * Registers the `dump_Frame` startup console command and installs its
   * process-exit teardown.
   */
  void register_CConFunc_dump_Frame();
} // namespace moho
