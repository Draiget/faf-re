// Engine addition, server mode (docs/SWITCHES.md, "headless"): the entry point of
// `headless`, a console program that plays one replay with no window, render device or
// audio engine and reports whether every checksum the players recorded matches.
//
// It brings up the parts of the game's startup the sim depends on, in the game's order
// (`WinMain`, `WIN_AppExecute`, `CScApp::Init`, `InitializeSessionFromCommandLine`), and leaves
// out every window, device, audio and UI step.

#include <Windows.h>
#if defined(_WIN32)
#include <objbase.h>
#else
#include <csignal>
#include <execinfo.h>
#endif

#include <algorithm>
#include <cfloat>
#include <cstdio>
#include <cstdlib>
#include <string>

#include "gpg/core/utils/Global.h"
#include "moho/app/IWinApp.h"
#include "moho/app/WinApp.h"
#include "moho/console/CConCommand.h"
#include "moho/core/ThreadPlacement.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/math/MathReflection.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/StartupHelpers.h"
#include "platform/X87Precision.h"
#include "headless/ReplayLaunchCheck.h"
#include "headless/ReplayRunner.h"

namespace
{
  // Exit codes: 0 every recorded checksum matched and the replay reached its end; 1 at least
  // one mismatch; 2 the replay did not reach its end in time; 3 a crash or fatal error;
  // 4 bad arguments or the replay could not be loaded.
  constexpr int kExitMatched = 0;
  constexpr int kExitMismatch = 1;
  constexpr int kExitIncomplete = 2;
  constexpr int kExitCrash = 3;
  constexpr int kExitBadInput = 4;

  /// `sim_ChecksumPeriod` of the players' games, the period the recorded checksums were taken at.
  constexpr int kRecordedChecksumPeriod = 50;

  std::string gLabel = "headless";

  [[noreturn]] void EndProcess(const int exitCode)
  {
    // Every output stream: stdout, stderr and the --disk-trace file.
    std::fflush(nullptr);
    // The sim and loader threads are still running; nothing after the verdict is observed,
    // so the process ends here instead of tearing them down.
#if defined(_WIN32)
    ::TerminateProcess(::GetCurrentProcess(), static_cast<UINT>(exitCode));
#endif
    std::_Exit(exitCode);
  }

  void ReplayDieHandler(const char* const message)
  {
    std::printf("[%s] FATAL %s\n", gLabel.c_str(), message != nullptr ? message : "engine Die()");
    std::printf("[%s] VERDICT ended=False mismatches=%d crash=True\n", gLabel.c_str(), faf::headless::ChecksumMismatchCount());
    EndProcess(kExitCrash);
  }

#if defined(_WIN32)
  LONG WINAPI ReplayCrashFilter(EXCEPTION_POINTERS* const info)
  {
    const EXCEPTION_RECORD* const record = info != nullptr ? info->ExceptionRecord : nullptr;
    std::printf(
      "[%s] CRASH exception 0x%08lX at %p\n",
      gLabel.c_str(),
      record != nullptr ? record->ExceptionCode : 0ul,
      record != nullptr ? record->ExceptionAddress : nullptr
    );
    std::printf("[%s] VERDICT ended=False mismatches=%d crash=True\n", gLabel.c_str(), faf::headless::ChecksumMismatchCount());
    EndProcess(kExitCrash);
  }
#else
  /// The POSIX counterpart of the crash filter: a fatal signal is reported as a crash.
  void ReplayCrashSignal(const int signalNumber, siginfo_t* const info, void*)
  {
    std::printf(
      "[%s] CRASH signal %d at %p\n", gLabel.c_str(), signalNumber, info != nullptr ? info->si_addr : nullptr
    );
    std::fflush(stdout);
    void* frames[64];
    ::backtrace_symbols_fd(frames, ::backtrace(frames, 64), 1);
    std::printf("[%s] VERDICT ended=False mismatches=%d crash=True\n", gLabel.c_str(), faf::headless::ChecksumMismatchCount());
    EndProcess(kExitCrash);
  }
#endif

  /** The common services every engine app sets up (`IWinApp::AppInitCommonServices`). */
  class ReplayApp final : public moho::IWinApp
  {
  public:
    ReplayApp()
      : moho::IWinApp("SupCom", "SupremeCommander")
    {}

    bool Init() override { return AppInitCommonServices(); }
    void Main() override {}
    void Destroy() override {}
  };

  [[nodiscard]] bool ReadOption(const char* const name, std::string& value)
  {
    msvc8::vector<msvc8::string> args;
    if (!moho::CFG_GetArgOption(name, 1, &args) || args.empty()) {
      return false;
    }
    value = args[0].c_str();
    return true;
  }

  [[nodiscard]] bool ReadIntOption(const char* const name, int& value, bool& bad)
  {
    std::string text;
    if (!ReadOption(name, text)) {
      return false;
    }
    char* end = nullptr;
    const long parsed = std::strtol(text.c_str(), &end, 10);
    if (end == text.c_str() || *end != '\0') {
      bad = true;
      return false;
    }
    value = static_cast<int>(parsed);
    return true;
  }

  void PrintUsage()
  {
    std::printf(
      "usage: headless --replay <file.scfareplay> /init <init.lua> [options]\n"
      "  --focus <army|-1>         army whose view the sim builds (0-based; -1 observer, default)\n"
      "  --digests <file>          write \"beat md5\" for every checksummed beat\n"
      "  --sync-keys <file>        write every top-level Lua Sync key seen, with beat counts\n"
      "  --state-digests <file>    write \"beat digest\" of what the sim published, every beat\n"
      "  --fpu-report              at beat 1, every thread's x87 control word and MXCSR (sampled)\n"
      "  --bone-stats <file>      write changed bones per beat (CSV) and per blueprint (<file>.blueprints.csv)\n"
      "  --lane-sizes <file>      write per-beat element counts and bytes of every sync lane (CSV)\n"
      "  --blueprint-order <file> write every blueprint by ordinal, in the rules' load order\n"
      "  --lua-pairs <file>       write the sim Lua globals' and moho class tables' pairs() order, before BeginSession\n"
      "  --wire-stats <file>      run the wire format's entities lane on every beat (CSV; server-mode build)\n"
      "  --loopback [--loopback-dr <steps> [--loopback-turns <units>]]  every packet through the wire format and the\n"
      "                            client's rebuild; dead reckoning in 1/64-unit steps, turns in 1/65536 turns\n"
      "                            (server-mode build)\n"
      "  --command-check           every command decoded and marshalled again as a client sends it, compared\n"
      "                            (server-mode build)\n"
      "  --oracle-check            the visibility oracle for the --focus army against what the sim publishes,\n"
      "                            every entity and beat (server-mode build)\n"
      "  --launch-check            rebuild the header's launch with BuildLaunchInfo and compare (plays nothing)\n"
      "  --disk-trace <file>       write every file the engine finds, reads or maps and every directory listing\n"
      "  --checksum-period <n>     sim_ChecksumPeriod for this run (default: the game's, 50)\n"
      "  --lead <n>                beats the sim may run ahead (sim_ReplayLead, default 10)\n"
      "  --timeout <minutes>       give up after this long (default 180)\n"
      "  --label <text>            prefix for every printed line\n"
      "  engine flags as in the game: /log <file>, /synclog <dir>, /simworkers <n>,\n"
      "  /con <name=value;...>, /prefs <file>, /sse2, /noversioncheck\n"
    );
  }

  /** `/con name=value;name2=value2`, as `InitializeSessionFromCommandLine` runs it. */
  void RunStartupConsoleCommands()
  {
    msvc8::vector<msvc8::string> args;
    if (!moho::CFG_GetArgOption("/con", 1, &args) || args.empty()) {
      return;
    }
    std::string commands = args[0].c_str();
    std::replace(commands.begin(), commands.end(), '=', ' ');
    std::size_t begin = 0;
    while (begin <= commands.size()) {
      const std::size_t end = std::min(commands.find(';', begin), commands.size());
      if (end > begin) {
        moho::CON_Execute(commands.substr(begin, end - begin).c_str());
      }
      begin = end + 1;
    }
  }
} // namespace

int main(int argc, char** argv)
{
  (void)argc;
  (void)argv;
#if defined(_WIN32)
  ::SetErrorMode(SEM_FAILCRITICALERRORS | SEM_NOGPFAULTERRORBOX | SEM_NOOPENFILEERRORBOX);
  ::SetUnhandledExceptionFilter(&ReplayCrashFilter);
#else
  {
    struct sigaction action{};
    action.sa_sigaction = &ReplayCrashSignal;
    action.sa_flags = SA_SIGINFO;
    sigemptyset(&action.sa_mask);
    for (const int signalNumber : {SIGSEGV, SIGBUS, SIGFPE, SIGILL, SIGABRT}) {
      (void)::sigaction(signalNumber, &action, nullptr);
    }
  }
#endif
  gpg::SetDieHandler(&ReplayDieHandler);

  faf::headless::SReplayOptions options{};
  bool bad = false;
  (void)ReadOption("--label", gLabel);
  options.label = gLabel;
  if (!ReadOption("--replay", options.replayPath) || !moho::CFG_GetArgOption("/init", 1, nullptr)) {
    PrintUsage();
    return kExitBadInput;
  }
  (void)ReadIntOption("--focus", options.focusArmy, bad);
  (void)ReadOption("--digests", options.digestPath);
  (void)ReadOption("--sync-keys", options.syncKeysPath);
  (void)ReadOption("--sync-writers", options.syncWritersPath);
  (void)ReadOption("--wire-stats", options.wireStatsPath);
  (void)ReadOption("--state-digests", options.stateDigestPath);
  (void)ReadOption("--lane-sizes", options.laneSizesPath);
  (void)ReadOption("--blueprint-order", options.blueprintOrderPath);
  (void)ReadOption("--lua-pairs", options.luaPairsPath);
  (void)ReadOption("--bone-stats", options.boneStatsPath);
  options.fpuReport = moho::CFG_GetArgOption("--fpu-report", 0, nullptr);
  options.loopback = moho::CFG_GetArgOption("--loopback", 0, nullptr);
  options.commandCheck = moho::CFG_GetArgOption("--command-check", 0, nullptr);
  options.oracleCheck = moho::CFG_GetArgOption("--oracle-check", 0, nullptr);
  (void)ReadIntOption("--loopback-dr", options.loopbackDeadReckoning, bad);
  (void)ReadIntOption("--loopback-turns", options.loopbackTurnTolerance, bad);
  (void)ReadIntOption("--checksum-period", options.checksumPeriod, bad);
  (void)ReadIntOption("--lead", options.replayLead, bad);
  (void)ReadIntOption("--timeout", options.timeoutMinutes, bad);
  if (bad) {
    PrintUsage();
    return kExitBadInput;
  }
#if !FAF_SERVER_MODE
  // The wire format and the remote client (src/remote) are built only with FAF_SERVER_MODE.
  if (!options.wireStatsPath.empty() || options.loopback || options.commandCheck || options.oracleCheck) {
    std::printf(
      "[%s] --wire-stats, --loopback, --command-check and --oracle-check need a server-mode build "
      "(FAF_SERVER_MODE, the *-server presets)\n",
      gLabel.c_str()
    );
    return kExitBadInput;
  }
#endif
  std::printf("[%s] replay %s\n", gLabel.c_str(), options.replayPath.c_str());
  std::fflush(stdout);

  // From the first mount on, so the trace holds everything the run needs.
  std::string diskTracePath;
  if (ReadOption("--disk-trace", diskTracePath)) {
    std::FILE* const diskTrace = std::fopen(diskTracePath.c_str(), "w");
    if (diskTrace == nullptr) {
      std::printf("[%s] --disk-trace: cannot write %s\n", gLabel.c_str(), diskTracePath.c_str());
      return kExitBadInput;
    }
    moho::DISK_SetAccessTrace(diskTrace);
  }

  // `WinMain` / `CScApp::CScApp`.
  moho::APP_InitializeIdentity();

  // `WIN_AppExecute` builds wx's application object here; headless links only the
  // simulation and has no wx.
#if defined(_WIN32)
  (void)::CoInitialize(nullptr);
#endif
  moho::PLAT_Init();

  // `CScApp::Init`, without the splash, fonts, UI manager and device.
  (void)SetSse2Mode(moho::CFG_GetArgOption("/sse2", 0, nullptr) ? 1 : 0);
  ReplayApp app;
  if (!app.Init()) {
    std::printf("[%s] VERDICT ended=False mismatches=0 crash=True\n", gLabel.c_str());
    EndProcess(kExitCrash);
  }
  msvc8::vector<msvc8::string> preferenceArgs;
  if (moho::CFG_GetArgOption("/prefs", 1, &preferenceArgs) && !preferenceArgs.empty()) {
    moho::USER_LoadPreferences(preferenceArgs[0]);
  } else {
    moho::USER_LoadPreferences(msvc8::string("Game.prefs"));
  }
  // The game runs /lua/userInit.lua in the user Lua state here; headless has no user state
  // (headless/ReplayLuaState.h).

  // `WIN_AppExecute`, before its frame loop.
  platform::SetX87PrecisionControl(_PC_24);

  // `InitializeSessionFromCommandLine`, up to the `/replay` path.
  RunStartupConsoleCommands();
  moho::PlaceCurrentThread(moho::EThreadRole::Main);

  if (moho::CFG_GetArgOption("--launch-check", 0, nullptr)) {
    // Plan WP2.10: the header against `BuildLaunchInfo`; plays nothing.
    std::string expectPath;
    (void)ReadOption("--launch-expect", expectPath);
    const faf::headless::SLaunchCheckResult check = faf::headless::RunLaunchCheck(options.replayPath, expectPath);
    if (!check.ran) {
      std::printf("[%s] LAUNCHCHECK error: %s\n", gLabel.c_str(), check.error.c_str());
      std::fflush(stdout);
      EndProcess(kExitBadInput);
    }
    std::printf("[%s] %s\n", gLabel.c_str(), check.report.c_str());
    std::fflush(stdout);
    EndProcess(check.differences == 0 ? 0 : 1);
  }

  faf::headless::InstallChecksumWatch(gLabel);
  const faf::headless::SReplayResult result = faf::headless::RunReplay(options);

  const char* const label = gLabel.c_str();
  if (!result.error.empty()) {
    std::printf("[%s] ERROR %s\n", label, result.error.c_str());
  }
  if (!result.wireSummary.empty()) {
    std::printf("[%s] %s\n", label, result.wireSummary.c_str());
  }
  if (!result.syncWritersSummary.empty()) {
    std::printf("[%s] %s\n", label, result.syncWritersSummary.c_str());
  }
  if (!result.loopbackSummary.empty()) {
    std::string summary = result.loopbackSummary;
    for (std::size_t at = 0; (at = summary.find('\n', at)) != std::string::npos; at += 2 + gLabel.size() + 1) {
      summary.replace(at, 1, "\n[" + gLabel + "] ");
    }
    std::printf("[%s] %s\n", label, summary.c_str());
  }
  if (!result.commandSummary.empty()) {
    std::printf("[%s] %s\n", label, result.commandSummary.c_str());
  }
  if (!result.oracleSummary.empty()) {
    std::printf("[%s] %s\n", label, result.oracleSummary.c_str());
  }
  if (!result.boneSummary.empty()) {
    std::printf("[%s] %s\n", label, result.boneSummary.c_str());
  }
  if (!result.fpuReport.empty()) {
    std::printf("[%s] floating-point state at beat 1, busiest thread first:\n%s", label, result.fpuReport.c_str());
  }
  std::printf(
    "[%s] beats=%d last-beat=%d game-over=%s desync-reports=%d digests=%llu load=%.1fs play=%.1fs\n",
    label,
    result.beats,
    result.lastBeat,
    result.gameOver ? "True" : "False",
    result.desyncReports,
    static_cast<unsigned long long>(result.digestsWritten),
    result.loadSeconds,
    result.playSeconds
  );
  // The players' clients recorded their checksums at the game's period; any other period
  // digests different spans of hashed data, so those comparisons say nothing.
  const bool recordedChecksumsComparable =
    options.checksumPeriod <= 0 || options.checksumPeriod == kRecordedChecksumPeriod;
  if (recordedChecksumsComparable) {
    std::printf(
      "[%s] VERDICT ended=%s mismatches=%d crash=%s%s\n",
      label,
      result.gameEnded ? "True" : "False",
      result.mismatches,
      result.crashed ? "True" : "False",
      result.timedOut ? " timeout=True" : ""
    );
  } else {
    std::printf(
      "[%s] VERDICT ended=%s recorded-checksum check skipped (checksum period %d, recorded at %d) crash=%s%s\n",
      label,
      result.gameEnded ? "True" : "False",
      options.checksumPeriod,
      kRecordedChecksumPeriod,
      result.crashed ? "True" : "False",
      result.timedOut ? " timeout=True" : ""
    );
  }

  int exitCode = kExitMatched;
  if (!result.started && !result.crashed) {
    exitCode = kExitBadInput;
  } else if (result.crashed) {
    exitCode = kExitCrash;
  } else if ((recordedChecksumsComparable && result.mismatches > 0) || result.loopbackFailures > 0
             || result.commandFailures > 0 || result.oracleFailures > 0) {
    exitCode = kExitMismatch;
  } else if (!result.gameOver) {
    exitCode = kExitIncomplete;
  }
  EndProcess(exitCode);
}
