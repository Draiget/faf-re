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
#include "moho/effects/rendering/CEffectManagerImpl.h"
#include "moho/misc/CZipFile.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/resource/RScmResource.h"
#include "moho/sim/CWldSessionLoaderImpl.h"
#include "platform/X87Precision.h"
#include "headless/ReplayLaunchCheck.h"
#include "headless/HeadlessMain.h"
#include "headless/ReplayRunner.h"
#include "moho/animation/CAniActor.h"

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

#if defined(FAF_COVERAGE_PROFILE)
  extern "C" int __llvm_profile_write_file(void);
#endif

  [[noreturn]] void EndProcess(const int exitCode)
  {
    // Every output stream: stdout, stderr and the --disk-trace file.
    std::fflush(nullptr);
#if defined(FAF_COVERAGE_PROFILE)
    // A build with -fprofile-instr-generate writes its counters from an atexit
    // handler, which TerminateProcess skips.
    (void)__llvm_profile_write_file();
#endif
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
    fa::vector<fa::string> args;
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
      "  --sync-dump <file>        write each beat's Lua Sync bytes (tools/sync-routing/compare.py)\n"
      "  --lua-routing-dump <pre>  with --lua-routing: each view's Sync bytes, to <pre>_<view>.bin\n"
      "  --lua-move-view <b:v:a>   with --lua-routing: at beat b, view v moves to army a\n"
      "  --lua-resync <b:v>        with --lua-routing: at beat b, view v gets a reconnect's resync\n"
      "  --focus-switch <b:a>      at beat b, the sim's focus moves to army a, as a lockstep client's does\n"
      "  --state-digests <file>    write \"beat digest\" of what the sim published, every beat\n"
      "  --fpu-report              at beat 1, every thread's x87 control word and MXCSR (sampled)\n"
      "  --keyframe-every <beats>  save the sim between beats every <beats>, as a saved game; size, zlib size, md5, time\n"
      "  --keyframe-first <beat>   with --keyframe-every: the first save at this beat instead of at <beats>\n"
      "  --keyframe-dir <dir>      where the keyframe files go (default: keyframes)\n"
      "  --keyframe-keep           keep the keyframe files after measuring them\n"
      "  --keyframe-prepare        for the replay viewer: files get their names when complete, nothing is measured\n"
      "  --keyframe-quiet          with --keyframe-prepare: compressed as they are saved, named by their tick; the init file can't raise the priority\n"
      "  --resume-from <file>      continue the replay from one of its keyframes instead of its start\n"
      "  --seek <beat,beat,...>    with --keyframe-every: move to each beat in turn inside this process, by ending\n"
      "                            the session and restoring the newest keyframe before it, then play to the end;\n"
      "                            --digests, --state-digests and --lane-sizes get one numbered file per session\n"
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
      "  --seats                   the commands through the game server's seats, one per command source\n"
      "                            (server-mode build)\n"
      "  --seats-listen <ip:port>  with --seats, Linux: and each seat's view over UDP to whoever joins as it, uid\n"
      "                            the source's index, token seat-<uid> (--view-pipeline: its threads)\n"
      "  --target-audit            with --seats-listen: how many recorded targets a server's view wouldn't have held\n"
      "  --oracle-check            the visibility oracle for the --focus army against what the sim publishes,\n"
      "                            every entity and beat (server-mode build)\n"
      "  --oracle-digests <file>  with --oracle-check: per beat, the oracle's answers for every army (unfocused)\n"
      "                            or for the focus army, one digest line each\n"
      "  --changeset-check         the sync walk's change set against its packet, every beat (server-mode build;\n"
      "                            not with --oracle-check)\n"
      "  --view-packets <army> <file>  per beat, a digest of each entity lane of that army's packet: rebuilt\n"
      "                            from the change set when unfocused, the sim's own when focused on the army\n"
      "                            (server-mode build; not with the other two checks)\n"
      "  --view-packets-entries <file>  with --view-packets: one line per record (beat, lane, id, digest),\n"
      "                            so two runs can be compared entry by entry\n"
      "  --view-packets-entries-every <n>  with --view-packets-entries: the records of every nth beat only\n"
      "  --view-frames <file>      unfocused: every army's frame per beat (CSV: entities, withheld, delta bytes),\n"
      "                            each decoded again and compared (server-mode build; not with the checks above)\n"
      "  --view-ids                with --view-frames: blips, foreign projectiles and foreign command ids renumbered\n"
      "                            per view, and every renumbered id checked to map back to its sim id\n"
      "  --view-loss <percent> [--view-ack-delay <beats>]  with --view-frames: every view's frames also go over a\n"
      "                            simulated channel that loses that share of frames and acknowledges late; each\n"
      "                            frame is encoded against the newest acknowledged one and must decode exactly\n"
      "  --view-bench <file>       unfocused: only the server's view work per beat (views with their own ids, every\n"
      "                            lane encoded for every client), timed (CSV: build, send and beat ms, entities,\n"
      "                            bytes; server-mode build; not with the checks above)\n"
      "  --keep-client-data        keep what only a client reads: model vertices and indices, the session's and the rules' blueprint tables, files read from archives, what effects draw, the pose handles kept for a client\n"
      "  --view-bench-check        with --view-bench: every view's kept frame is compared with one built whole\n"
      "  --lua-routing             with --view-bench: the Lua lane too: each player's Sync routed (remote/SyncRouting.h)\n"
      "  --view-pipeline <n>       with --view-bench: n threads finish the views while the sim goes on (default 0: it waits)\n"
      "  --view-teams              with --view-pipeline: one view per team and each player's own units\n"
      "  --view-tables             with --view-bench: the session tables as a server keeps them (sounds, names, unit\n"
      "                            stats, deposits and terrain edits), each beat's record written\n"
      "  --stats-every <beats>     with --view-tables: each unit's stats read every <beats> beats (default 4)\n"
      "  --view-poses              with --view-bench: each view's pose lane (the units' bones) as a server sends it\n"
      "  --view-dump <file>        with --view-bench: what each player's client holds every 2000 beats, to compare two runs\n"
      "  --parallel-views          with --view-frames or --view-bench: the views are built on the sim's workers\n"
      "  --cpus <list>             run on these CPUs only, for example 8-15 or 0,2,4,6; a CPU set from taskset or a\n"
      "                            container counts too, and FAF's init scripts cannot change it\n"
      "  --spy                     with --view-bench --lua-routing: every Lua key each view receives checked;\n"
      "                            with --view-frames: every view's decoded frame checked against the oracle and\n"
      "                            for names of entities its client does not hold\n"
      "  --inbound-check           with --view-ids: every command sent again in its army's view ids and translated\n"
      "                            back as the server would; it must marshal to the same bytes\n"
      "  --launch-check           rebuild the header's launch with BuildLaunchInfo and compare (plays nothing)\n"
      "  --disk-trace <file>       write every file the engine finds, reads or maps and every directory listing\n"
      "  --path-spelling <file>    Linux: write each path found on disk only by ignoring case, as asked and as on disk\n"
      "  --rejoin-source <n>       play as this command source of a live game, every other client fed from the\n"
      "                            replay (needs --focus on its army); the rehearsal of a rejoin\n"
      "  --rejoin-beat <n>         with --rejoin-source: the driver issues this client's beats after this one\n"
      "  --rejoin-peers <list>     no replay: take seat --rejoin-source back in a running game from these peers,\n"
      "                            written address:port=source,...; needs the seat's key (/rejoinkeyfile)\n"
      "  --rejoin-port <n>         with --rejoin-peers: this client's game port\n"
      "  --checksum-period <n>     sim_ChecksumPeriod for this run (default: the game's, 50)\n"
      "  --lead <n>                beats the sim may run ahead (sim_ReplayLead, default 10)\n"
      "  --pace <ms>               one beat per this many ms, as a live game plays (100 is speed 0); time a late\n"
      "                            beat loses is not made up, and the run prints how much was lost\n"
      "  --timeout <minutes>       give up after this long (default 180)\n"
      "  --label <text>            prefix for every printed line\n"
      "  engine flags as in the game: /log <file>, /synclog <dir>, /simworkers <n>,\n"
      "  /con <name=value;...>, /prefs <file>, /sse2, /noversioncheck\n"
    );
  }

  /** `/con name=value;name2=value2`, as `InitializeSessionFromCommandLine` runs it. */
  void RunStartupConsoleCommands()
  {
    fa::vector<fa::string> args;
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

int HEADLESS_Main(int argc, char** argv)
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
  const bool liveRejoin = ReadOption("--rejoin-peers", options.rejoinPeers);
  if ((!ReadOption("--replay", options.replayPath) && !liveRejoin) || !moho::CFG_GetArgOption("/init", 1, nullptr)) {
    PrintUsage();
    return kExitBadInput;
  }
  (void)ReadIntOption("--focus", options.focusArmy, bad);
  (void)ReadIntOption("--rejoin-source", options.rejoinSource, bad);
  (void)ReadIntOption("--rejoin-port", options.rejoinPort, bad);
  (void)ReadIntOption("--rejoin-beat", options.rejoinBeat, bad);
  (void)ReadOption("--digests", options.digestPath);
  (void)ReadOption("--sync-keys", options.syncKeysPath);
  (void)ReadOption("--sync-dump", options.syncDumpPath);
  (void)ReadOption("--lua-routing-dump", options.luaRoutingDump);
  std::string beatStep;
  if (ReadOption("--lua-move-view", beatStep)
      && std::sscanf(beatStep.c_str(), "%d:%d:%d", &options.luaMoveBeat, &options.luaMoveView, &options.luaMoveArmy) != 3) {
    bad = true;
  }
  if (ReadOption("--lua-resync", beatStep)
      && std::sscanf(beatStep.c_str(), "%d:%d", &options.luaResyncBeat, &options.luaResyncView) != 2) {
    bad = true;
  }
  if (ReadOption("--focus-switch", beatStep)
      && std::sscanf(beatStep.c_str(), "%d:%d", &options.focusSwitchBeat, &options.focusSwitchArmy) != 2) {
    bad = true;
  }
  (void)ReadOption("--sync-writers", options.syncWritersPath);
  (void)ReadOption("--wire-stats", options.wireStatsPath);
  (void)ReadOption("--state-digests", options.stateDigestPath);
  (void)ReadOption("--lane-sizes", options.laneSizesPath);
  (void)ReadOption("--blueprint-order", options.blueprintOrderPath);
  (void)ReadOption("--lua-pairs", options.luaPairsPath);
  (void)ReadOption("--bone-stats", options.boneStatsPath);
  options.fpuReport = moho::CFG_GetArgOption("--fpu-report", 0, nullptr);
  (void)ReadIntOption("--keyframe-every", options.keyframeEvery, bad);
  (void)ReadIntOption("--keyframe-first", options.keyframeFirst, bad);
  if (!ReadOption("--keyframe-dir", options.keyframeDir)) {
    options.keyframeDir = "keyframes";
  }
  options.keyframeKeep = moho::CFG_GetArgOption("--keyframe-keep", 0, nullptr);
  options.keyframePrepare = moho::CFG_GetArgOption("--keyframe-prepare", 0, nullptr);
  (void)ReadOption("--resume-from", options.resumeFrom);
  std::vector<int> seekPlan;
  {
    std::string seekText;
    if (ReadOption("--seek", seekText)) {
      for (std::size_t begin = 0; begin < seekText.size();) {
        const std::size_t end = std::min(seekText.find(',', begin), seekText.size());
        seekPlan.push_back(std::atoi(seekText.substr(begin, end - begin).c_str()));
        begin = end + 1;
      }
      bad = bad || seekPlan.empty() || options.keyframeEvery <= 0 || !options.resumeFrom.empty();
    }
  }
  options.loopback = moho::CFG_GetArgOption("--loopback", 0, nullptr);
  options.commandCheck = moho::CFG_GetArgOption("--command-check", 0, nullptr);
  options.seats = moho::CFG_GetArgOption("--seats", 0, nullptr);
  (void)ReadOption("--seats-listen", options.seatsListen);
  options.targetAudit = moho::CFG_GetArgOption("--target-audit", 0, nullptr);
  options.oracleCheck = moho::CFG_GetArgOption("--oracle-check", 0, nullptr);
  if (ReadOption("--oracle-digests", options.oracleDigestsPath)) {
    options.oracleCheck = true;
  }
  options.changeSetCheck = moho::CFG_GetArgOption("--changeset-check", 0, nullptr);
  {
    fa::vector<fa::string> viewArgs;
    if (moho::CFG_GetArgOption("--view-packets", 2, &viewArgs) && viewArgs.size() == 2) {
      options.viewPacketsArmy = std::atoi(viewArgs[0].c_str());
      options.viewPacketsPath = viewArgs[1].c_str();
    }
  }
  (void)ReadOption("--view-packets-entries", options.viewPacketsEntriesPath);
  (void)ReadOption("--view-frames", options.viewFramesPath);
  (void)ReadOption("--view-bench", options.viewBenchPath);
  options.viewIds = moho::CFG_GetArgOption("--view-ids", 0, nullptr);
  if (ReadIntOption("--view-loss", options.viewLossPercent, bad)
      && (options.viewLossPercent < 0 || options.viewLossPercent > 100)) {
    bad = true;
  }
  if (ReadIntOption("--view-ack-delay", options.viewAckDelay, bad) && options.viewAckDelay < 0) {
    bad = true;
  }
  options.luaRouting = moho::CFG_GetArgOption("--lua-routing", 0, nullptr);
  options.parallelViews = moho::CFG_GetArgOption("--parallel-views", 0, nullptr);
  options.viewTeams = moho::CFG_GetArgOption("--view-teams", 0, nullptr);
  options.viewTables = moho::CFG_GetArgOption("--view-tables", 0, nullptr);
  options.viewPoses = moho::CFG_GetArgOption("--view-poses", 0, nullptr);
  if (std::string statsEvery; ReadOption("--stats-every", statsEvery)) {
    options.statsEvery = std::atoi(statsEvery.c_str());
  }
  (void)ReadOption("--view-dump", options.viewDumpPath);
  if (ReadIntOption("--view-pipeline", options.viewPipelineThreads, bad) && options.viewPipelineThreads < 0) {
    bad = true;
  }
  {
    std::string cpuList;
    if (ReadOption("--cpus", cpuList) && !moho::AssignProcessCpus(cpuList.c_str())) {
      bad = true;
    }
    moho::LockAssignedProcessCpus();
    if (moho::ProcessCpusAreLocked()) {
      DWORD_PTR processMask = 0;
      DWORD_PTR systemMask = 0;
      (void)::GetProcessAffinityMask(::GetCurrentProcess(), &processMask, &systemMask);
      std::printf("[%s] assigned CPU mask %llx of %llx; scripts cannot change it\n", gLabel.c_str(),
        static_cast<unsigned long long>(processMask), static_cast<unsigned long long>(systemMask));
    }
  }
  options.viewBenchCheck = moho::CFG_GetArgOption("--view-bench-check", 0, nullptr);
  options.keepClientData = moho::CFG_GetArgOption("--keep-client-data", 0, nullptr);
  options.spy = moho::CFG_GetArgOption("--spy", 0, nullptr);
  options.inboundCheck = moho::CFG_GetArgOption("--inbound-check", 0, nullptr);
  if (options.inboundCheck && (!options.viewIds || options.commandCheck)) {
    std::printf("[%s] --inbound-check needs --view-frames and --view-ids, and not --command-check\n", gLabel.c_str());
    bad = true;
  }
  if ((options.oracleCheck ? 1 : 0) + (options.changeSetCheck ? 1 : 0) + (options.viewPacketsPath.empty() ? 0 : 1)
        + (options.viewFramesPath.empty() ? 0 : 1) + (options.viewBenchPath.empty() ? 0 : 1) + (options.loopback ? 1 : 0)
      > 1) {
    std::printf(
      "[%s] --oracle-check, --changeset-check, --view-packets, --view-frames, --view-bench and --loopback (its grid copies) all "
      "observe the sync walk: one at a time\n",
      gLabel.c_str()
    );
    return kExitBadInput;
  }
  (void)ReadIntOption("--loopback-dr", options.loopbackDeadReckoning, bad);
  (void)ReadIntOption("--loopback-turns", options.loopbackTurnTolerance, bad);
  (void)ReadIntOption("--checksum-period", options.checksumPeriod, bad);
  (void)ReadIntOption("--lead", options.replayLead, bad);
  (void)ReadIntOption("--pace", options.paceMs, bad);
  (void)ReadIntOption("--timeout", options.timeoutMinutes, bad);
  if (ReadIntOption("--view-packets-entries-every", options.viewPacketsEntriesEvery, bad)
      && options.viewPacketsEntriesEvery < 1) {
    bad = true;
  }
  if (bad) {
    PrintUsage();
    return kExitBadInput;
  }
#if !FAF_SERVER_MODE
  // The wire format and the remote client (src/remote) are built only with FAF_SERVER_MODE.
  if (!options.wireStatsPath.empty() || options.loopback || options.commandCheck || options.seats || options.oracleCheck
      || options.changeSetCheck || !options.viewPacketsPath.empty() || !options.viewFramesPath.empty()
      || !options.viewBenchPath.empty()) {
    std::printf(
      "[%s] --wire-stats, --loopback, --command-check, --seats, --oracle-check, --changeset-check, --view-packets, --view-frames and "
      "--view-bench need a "
      "server-mode build "
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
#if !defined(_WIN32)
  std::string pathSpellingPath;
  if (ReadOption("--path-spelling", pathSpellingPath)) {
    std::FILE* const pathSpelling = std::fopen(pathSpellingPath.c_str(), "w");
    if (pathSpelling == nullptr) {
      std::printf("[%s] --path-spelling: cannot write %s\n", gLabel.c_str(), pathSpellingPath.c_str());
      return kExitBadInput;
    }
    FAF_SetPathSpellingTrace(pathSpelling);
  }
#endif

  // Nothing here draws or runs a UI: models keep what the sim reads (`RScmResource::DropGeometry`),
  // and the session's Lua state gets no copy of the blueprints.
  const bool keepClientData = moho::CFG_GetArgOption("--keep-client-data", 0, nullptr);
  moho::RScmResource::SetKeepGeometry(keepClientData);
  moho::WLD_SetSessionKeepsBlueprints(keepClientData);
  moho::CZipFile::SetKeepEntryData(keepClientData);
  moho::EFFECT_SetLifetimeOnly(!keepClientData);
  // `--bone-stats` reads the poses in the sim's packets.
  moho::POSE_SetKeepClientHandles(keepClientData || moho::CFG_GetArgOption("--bone-stats", 0, nullptr));

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
  fa::vector<fa::string> preferenceArgs;
  if (moho::CFG_GetArgOption("/prefs", 1, &preferenceArgs) && !preferenceArgs.empty()) {
    moho::USER_LoadPreferences(preferenceArgs[0]);
  } else {
    moho::USER_LoadPreferences(fa::string("Game.prefs"));
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
  const faf::headless::SReplayResult result =
    seekPlan.empty() ? faf::headless::RunReplay(options) : faf::headless::RunSeekPlan(options, seekPlan);

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
  if (!result.inboundSummary.empty()) {
    std::printf("[%s] %s\n", label, result.inboundSummary.c_str());
  }
  if (!result.commandSummary.empty()) {
    std::printf("[%s] %s\n", label, result.commandSummary.c_str());
  }
  if (!result.oracleSummary.empty()) {
    std::printf("[%s] %s\n", label, result.oracleSummary.c_str());
  }
  if (!result.changeSetSummary.empty()) {
    std::printf("[%s] %s\n", label, result.changeSetSummary.c_str());
  }
  if (!result.viewPacketsSummary.empty()) {
    std::printf("[%s] %s\n", label, result.viewPacketsSummary.c_str());
  }
  if (!result.viewFramesSummary.empty()) {
    std::printf("[%s] %s\n", label, result.viewFramesSummary.c_str());
  }
  if (!result.viewBenchSummary.empty()) {
    std::printf("[%s] %s\n", label, result.viewBenchSummary.c_str());
  }
  if (!result.boneSummary.empty()) {
    std::printf("[%s] %s\n", label, result.boneSummary.c_str());
  }
  if (!result.keyframeSummary.empty()) {
    std::printf("[%s] %s\n", label, result.keyframeSummary.c_str());
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
             || result.commandFailures > 0 || result.oracleFailures > 0 || result.inboundFailures > 0
             || result.changeSetFailures > 0 || result.viewFramesFailures > 0 || result.viewBenchFailures > 0
             || result.keyframeFailures > 0) {
    exitCode = kExitMismatch;
  } else if (!result.gameOver) {
    exitCode = kExitIncomplete;
  }
  EndProcess(exitCode);
}
