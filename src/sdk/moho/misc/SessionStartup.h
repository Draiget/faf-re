#pragma once

#include <cstddef>

#include "gpg/core/containers/String.h"
#include "legacy/containers/AutoPtr.h"
#include "legacy/containers/String.h"
#include "moho/serialization/SSavedGameHeader.h"

namespace gpg
{
  class ReadArchive;
} // namespace gpg

namespace moho
{
  struct SWldSessionInfo;

  /**
   * Address: 0x00880330 (FUN_00880330, `Moho::CSavedGame::CSavedGame`)
   * Address: 0x00880770 (FUN_00880770, `Moho::CSavedGame::~CSavedGame`)
   *
   * What it does:
   * Opens and validates one saved-game file, then loads the serialized
   * `SSavedGameHeader` payload and owning read-archive state.
   */
  class CSavedGame
  {
  public:
    /**
     * Address: 0x00880330 (FUN_00880330)
     *
     * What it does:
     * Opens and validates one saved-game file and loads its header archive lane.
     */
    explicit CSavedGame(gpg::StrArg filename);

    /**
     * Address: 0x00880770 (FUN_00880770)
     *
     * What it does:
     * Releases the loaded read-archive lane and header-owned fields.
     */
    ~CSavedGame();

    /**
     * Address: 0x008807F0 (FUN_008807F0)
     *
     * What it does:
     * Builds one single-player `SWldSessionInfo` from loaded save payload.
     */
    [[nodiscard]] msvc8::auto_ptr<SWldSessionInfo> CreateSinglePlayerSessionInfo();

  private:
    msvc8::string mFilename;      // +0x00
    gpg::ReadArchive* mReader;    // +0x1C
    SSavedGameHeader mHeader;     // +0x20
  };

  static_assert(sizeof(CSavedGame) == 0x78, "CSavedGame size must be 0x78");

  /**
   * Address: 0x008765E0 (FUN_008765E0)
   * Mangled:
   * ?VCR_SetupReplaySession@Moho@@YA?AV?$auto_ptr@USWldSessionInfo@Moho@@@std@@VStrArg@gpg@@@Z
   *
   * What it does:
   * Loads replay file payload, reconstructs `LaunchInfoNew`, and creates
   * one replay `SWldSessionInfo` bootstrap object.
   */
  [[nodiscard]] msvc8::auto_ptr<SWldSessionInfo> VCR_SetupReplaySession(gpg::StrArg filename);
} // namespace moho
