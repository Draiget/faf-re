#pragma once

#include <cstdint>
#include <string>

// Engine addition, server mode (docs/SWITCHES.md, "headless"): the headless replay runner.
// It plays one `.scfareplay` through the same sim, driver and replay client the game uses,
// with no world session, window, render device or audio engine.

namespace faf::headless
{
  struct SReplayOptions
  {
    std::string replayPath;     // `.scfareplay`
    std::string label;          // prefix of every line headless prints
    int focusArmy = -1;         // the army whose view `Sim::Sync` builds; -1 = observer
    std::string digestPath;     // when set: one "beat digest" line per checksummed beat
    std::string syncKeysPath;   // when set: every top-level Lua `Sync` key seen, with beat counts
    std::string wireStatsPath;  // when set: the entities lane of the wire format, per beat (CSV)
    std::string syncWritersPath; // when set: every Sync write's Lua call site (ReplaySyncWriters.h)
    bool loopback = false;      // every packet through the wire and the client's rebuild (CLoopbackLink)
    int loopbackDeadReckoning = 0; // with `loopback`: dead-reckoning tolerance in 1/64-unit steps
    int loopbackTurnTolerance = 0; // with dead reckoning: orientation tolerance in 1/65536 turns (0: off)
    bool commandCheck = false;  // every command decoded and marshalled again, compared (ReplayCommandCheck.h)
    bool oracleCheck = false;   // the visibility oracle against the sim's own publication (ReplayOracleCheck.h)
    std::string oracleDigestsPath; // with `oracleCheck`: per beat and army, the oracle's answers as a digest
    bool changeSetCheck = false; // the sync walk's change set against its packet (ReplayChangeSetCheck.h)
    std::string stateDigestPath; // when set: "beat digest" of what the sim published, every beat
    bool fpuReport = false;     // at beat 1: every thread's x87 control word and MXCSR
    std::string boneStatsPath;  // when set: changed bones per unit and beat (CSV), per blueprint at the end
    std::string laneSizesPath;  // when set: per-beat element counts and bytes of every sync lane (CSV)
    std::string blueprintOrderPath; // when set: every blueprint by ordinal, in load order (plan WPL.16)
    std::string luaPairsPath;   // when set: the sim Lua state's pairs() order before BeginSession (plan WPL.18)
    int checksumPeriod = 0;     // when > 0: `sim_ChecksumPeriod` for this run (0 = the default)
    int replayLead = -1;        // when >= 0: `sim_ReplayLead` for this run
    int timeoutMinutes = 180;   // wall-clock limit for the whole run
  };

  struct SReplayResult
  {
    bool started = false;       // the session loaded and the sim produced its first beat
    bool gameOver = false;      // a packet carried `mGameOver` (victory or end of the replay)
    bool gameEnded = false;     // the sim's Lua `Sync` table carried `GameEnded`
    bool timedOut = false;
    bool crashed = false;
    int beats = 0;              // packets taken off the queue
    int lastBeat = -1;
    int mismatches = 0;         // "Checksum for beat N mismatched" warnings
    int desyncReports = 0;      // entries in the packets' desync runs
    std::uint64_t digestsWritten = 0;
    double loadSeconds = 0.0;
    double playSeconds = 0.0;
    std::string error;          // why the run could not start or finish
    std::string wireSummary;    // with `wireStatsPath`: one summary line
    std::string loopbackSummary; // with `loopback`: two lines
    std::string syncWritersSummary; // with `syncWritersPath`: one line
    std::uint64_t loopbackFailures = 0;
    std::string commandSummary; // with `commandCheck`: one line
    std::uint64_t commandFailures = 0;
    std::string oracleSummary;  // with `oracleCheck`: a few lines
    std::uint64_t oracleFailures = 0;
    std::string changeSetSummary; // with `changeSetCheck`: two lines and the first differences
    std::uint64_t changeSetFailures = 0;
    std::string boneSummary;    // with `boneStatsPath`: one summary line
    std::string fpuReport;      // with `fpuReport`: one line per thread
  };

  /**
   * Plays the replay to its end (a game-over packet), or until the time limit. The engine's
   * process-wide services (VFS, preferences, user Lua state) must be up already.
   */
  [[nodiscard]] SReplayResult RunReplay(const SReplayOptions& options);

  /** Counts the checksum warnings the sim logs; installed for the whole process. */
  void InstallChecksumWatch(const std::string& label);
  [[nodiscard]] int ChecksumMismatchCount() noexcept;
} // namespace faf::headless
