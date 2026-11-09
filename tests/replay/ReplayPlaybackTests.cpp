// Recorded games played back by headless, every recorded checksum compared (docs/PR_REPLAY_CHECK.md):
// the simulation as a whole under test. Needs the game data, so it is skipped without it:
//
//   FAF_REPLAY_DATA   folder with replays/vault_<id>.scfareplay and faf/bin/<init>
//   FAF_REPLAY_INIT   the init file under faf/bin (default init_replay.lua)
//   FAF_REPLAY_IDS    replays to play, separated by commas (default 26930624, a 2-player core replay);
//                     `id:init` plays one with its own init file under faf/bin (M28AI replays need one)
//   FAF_REPLAY_SEEK   the beats the keyframe test moves to on the first replay (default 3000,900,6000)
//   FAF_REPLAY_REJOIN the rejoin rehearsal on the first replay, `source:army:beat` (default 0:0:1500)
//
// A FAF_COVERAGE build's headless writes its own counters (LLVM_PROFILE_FILE), so these games count in
// tools/coverage/report.sh.

#include <gtest/gtest.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <map>
#include <sstream>
#include <string>
#include <utility>
#include <vector>

#if defined(_WIN32)
#define FAF_POPEN _popen
#define FAF_PCLOSE _pclose
#else
#include <sys/wait.h>
#define FAF_POPEN popen
#define FAF_PCLOSE pclose
#endif

namespace
{
  std::string Environment(const char* const name, const char* const fallback)
  {
    const char* const value = std::getenv(name);
    return value != nullptr && value[0] != '\0' ? std::string(value) : std::string(fallback);
  }

  std::vector<std::string> Split(const std::string& text)
  {
    std::vector<std::string> items;
    std::stringstream stream(text);
    std::string item;
    while (std::getline(stream, item, ',')) {
      if (!item.empty()) {
        items.push_back(item);
      }
    }
    return items;
  }

  std::string Quoted(const std::filesystem::path& path)
  {
    return "\"" + path.string() + "\"";
  }

  struct SRun
  {
    int exitCode = -1;
    std::string beats;   // the beats= line: how far the playback got
    std::string verdict; // the VERDICT line
    std::string tail;    // the last lines, for a failure message
    std::string output;  // everything printed, for the checks' summaries
    std::vector<std::string> keyframes; // "keyframes: N taken, M failed, ..." lines, one per session
    int seeks = 0;                      // "seek N: at beat" lines: moves that arrived
  };

  SRun Play(const std::string& commandLine)
  {
    SRun run;
#if defined(_WIN32)
    // cmd /c drops the outer quotes of a line that starts with one.
    const std::string line = "\"" + commandLine + " 2>&1\"";
#else
    const std::string line = commandLine + " 2>&1";
#endif
    FILE* const pipe = FAF_POPEN(line.c_str(), "r");
    if (pipe == nullptr) {
      return run;
    }
    std::vector<std::string> lines;
    char buffer[4096];
    while (std::fgets(buffer, sizeof(buffer), pipe) != nullptr) {
      std::string text(buffer);
      if (text.find("VERDICT") != std::string::npos) {
        run.verdict = text;
      } else if (text.find("] beats=") != std::string::npos) {
        run.beats = text;
      } else if (text.find("] keyframes: ") != std::string::npos) {
        run.keyframes.push_back(text);
      } else if (text.find("] seek ") != std::string::npos && text.find(": at beat ") != std::string::npos) {
        ++run.seeks;
      }
      run.output += text;
      lines.push_back(std::move(text));
      if (lines.size() > 40) {
        lines.erase(lines.begin());
      }
    }
    const int status = FAF_PCLOSE(pipe);
#if defined(_WIN32)
    run.exitCode = status;
#else
    run.exitCode = WIFEXITED(status) ? WEXITSTATUS(status) : -1;
#endif
    for (const std::string& text : lines) {
      run.tail += text;
    }
    return run;
  }
} // namespace

namespace
{
  struct SReplay
  {
    std::string id;
    std::filesystem::path replay;
    std::filesystem::path init;
  };

  /** The replays FAF_REPLAY_IDS names, with their init files; empty without FAF_REPLAY_DATA. */
  std::vector<SReplay> Replays()
  {
    std::vector<SReplay> replays;
    const std::string data = Environment("FAF_REPLAY_DATA", "");
    if (data.empty()) {
      return replays;
    }
    const std::filesystem::path root(data);
    const std::string defaultInit = Environment("FAF_REPLAY_INIT", "init_replay.lua");
    for (const std::string& item : Split(Environment("FAF_REPLAY_IDS", "26930624"))) {
      const std::size_t colon = item.find(':');
      SReplay replay;
      replay.id = item.substr(0, colon);
      replay.replay = root / "replays" / ("vault_" + replay.id + ".scfareplay");
      replay.init = root / "faf" / "bin" / (colon == std::string::npos ? defaultInit : item.substr(colon + 1));
      replays.push_back(std::move(replay));
    }
    return replays;
  }

  std::filesystem::path LogFolder()
  {
    const std::filesystem::path logs = std::filesystem::temp_directory_path() / "faf_replay_playback";
    std::filesystem::create_directories(logs);
    return logs;
  }

  SRun PlayReplay(const SReplay& replay, const std::string& label, const std::string& extraArguments)
  {
    EXPECT_TRUE(std::filesystem::exists(replay.init)) << replay.init.string();
    EXPECT_TRUE(std::filesystem::exists(replay.replay)) << replay.replay.string();
    const std::string command = Quoted(FAF_HEADLESS_EXE) + " --label " + label + " --replay " + Quoted(replay.replay) +
                                " /init " + Quoted(replay.init) + " /nobugreport /nosound /log " +
                                Quoted(LogFolder() / (label + ".log")) + extraArguments;
    const SRun run = Play(command);
    std::printf("%s%s", run.beats.c_str(), run.verdict.c_str());
    return run;
  }

  /** Every recorded checksum matched, nothing crashed, and the playback reached the game-over beat. */
  void ExpectMatchedToTheEnd(const SRun& run)
  {
    EXPECT_EQ(run.exitCode, 0) << "headless exit code (1 mismatch, 2 incomplete, 3 crash, 4 bad input)\n" << run.tail;
    // VERDICT's `ended` is the game's own Lua GameEnded, which a game without a victory never sets
    // (docs/SWITCHES.md); `game-over` on the beats line is the sim's last beat.
    EXPECT_NE(run.beats.find("game-over=True"), std::string::npos) << run.beats;
    EXPECT_NE(run.verdict.find("mismatches=0"), std::string::npos) << run.verdict;
    EXPECT_NE(run.verdict.find("crash=False"), std::string::npos) << run.verdict;
  }
} // namespace

TEST(ReplayPlayback, RecordedChecksumsMatch)
{
  const std::vector<SReplay> replays = Replays();
  if (replays.empty()) {
    GTEST_SKIP() << "set FAF_REPLAY_DATA to a folder with replays/ and faf/bin/ (see the file's header)";
  }
  for (const SReplay& replay : replays) {
    SCOPED_TRACE("replay " + replay.id);
    ExpectMatchedToTheEnd(PlayReplay(replay, "ctest_" + replay.id, ""));
  }
}

// The replay viewer's rewind (docs/REPLAY_VIEWER.md): the first replay played with a keyframe every 300 beats and
// moved through FAF_REPLAY_SEEK (default 3000,900,6000: a jump back, then forward past several keyframes). Each
// move restarts from a keyframe, and the recorded checksums after it still have to match.
TEST(ReplayPlayback, KeyframeSeeksKeepTheChecksums)
{
  const std::vector<SReplay> replays = Replays();
  if (replays.empty()) {
    GTEST_SKIP() << "set FAF_REPLAY_DATA to a folder with replays/ and faf/bin/ (see the file's header)";
  }
  const SReplay& replay = replays.front();
  SCOPED_TRACE("replay " + replay.id);
  const std::filesystem::path keyframes = LogFolder() / ("keyframes_" + replay.id);
  std::filesystem::create_directories(keyframes);
  const SRun run = PlayReplay(
    replay, "ctest_seek_" + replay.id,
    " --keyframe-every 300 --keyframe-dir " + Quoted(keyframes) + " --seek " +
      Environment("FAF_REPLAY_SEEK", "3000,900,6000")
  );
  ExpectMatchedToTheEnd(run);
  ASSERT_FALSE(run.keyframes.empty()) << "no keyframe summary\n" << run.tail;
  for (const std::string& line : run.keyframes) {
    EXPECT_NE(line.find(" 0 failed"), std::string::npos) << line;
  }
  EXPECT_GE(run.seeks, 3) << run.tail;
  std::error_code ignored;
  std::filesystem::remove_all(keyframes, ignored);
}

// The rehearsal of a rejoin (issue #275, CRejoinFeed): the first replay played as one command source of a live game,
// every other client fed from the recording, and this client's own driver issuing its beats after the handover beat.
// The recorded checksums have to match through the handover to the end.
TEST(ReplayPlayback, RejoinRehearsalKeepsTheChecksums)
{
  const std::vector<SReplay> replays = Replays();
  if (replays.empty()) {
    GTEST_SKIP() << "set FAF_REPLAY_DATA to a folder with replays/ and faf/bin/ (see the file's header)";
  }
  const SReplay& replay = replays.front();
  SCOPED_TRACE("replay " + replay.id);
  std::vector<std::string> plan;
  std::stringstream stream(Environment("FAF_REPLAY_REJOIN", "0:0:1500"));
  for (std::string item; std::getline(stream, item, ':');) {
    plan.push_back(item);
  }
  ASSERT_EQ(plan.size(), 3u) << "FAF_REPLAY_REJOIN is source:army:beat";
  const SRun run = PlayReplay(
    replay, "ctest_rejoin_" + replay.id,
    " --rejoin-source " + plan[0] + " --focus " + plan[1] + " --rejoin-beat " + plan[2]
  );
  ExpectMatchedToTheEnd(run);
}

// The unit zoo (tests/replay/zoo/lua/simInit.lua): a hook folder appended to FAF's /lua/simInit.lua that, on top of
// the first replay, spawns every unit blueprint for the first two armies wave by wave, calls every getter of the
// sim's Lua objects, and drives building, factories, upgrades, transports, missiles, reclaim, repair, capture and an
// AI platoon. The zoo changes the game, so the recorded checksums no longer apply (headless exits 1 for them); the
// run has to reach the zoo's last step without a crash and play to the end.
TEST(ReplayPlayback, UnitZooRunsEveryUnitAndCall)
{
  const std::vector<SReplay> replays = Replays();
  if (replays.empty()) {
    GTEST_SKIP() << "set FAF_REPLAY_DATA to a folder with replays/ and faf/bin/ (see the file's header)";
  }
  SReplay zoo = replays.front();
  SCOPED_TRACE("replay " + zoo.id);
  // The replay's own init file, then the zoo folder mounted at /zoo and named a hook folder.
  const std::filesystem::path init = LogFolder() / ("zoo_init_" + zoo.id + ".lua");
  {
    std::ofstream out(init);
    out << "InitFileDir = [[" << zoo.init.parent_path().generic_string() << "]]\n"
        << "dofile([[" << zoo.init.generic_string() << "]])\n"
        << "table.insert(path, { dir = [[" << std::filesystem::path(FAF_REPLAY_ZOO_DIR).generic_string()
        << "]], mountpoint = '/zoo' })\n"
        << "table.insert(hook, '/zoo')\n";
  }
  zoo.init = init;
  const std::string label = "ctest_zoo_" + zoo.id;
  const SRun run = PlayReplay(zoo, label, "");
  EXPECT_TRUE(run.exitCode == 0 || run.exitCode == 1) << "headless exit code " << run.exitCode << "\n" << run.tail;
  EXPECT_NE(run.verdict.find("crash=False"), std::string::npos) << run.verdict;
  EXPECT_NE(run.beats.find("game-over=True"), std::string::npos) << run.beats;

  std::ifstream logFile(LogFolder() / (label + ".log"));
  const std::string log((std::istreambuf_iterator<char>(logFile)), std::istreambuf_iterator<char>());
  EXPECT_NE(log.find("ZOO: waves done"), std::string::npos) << "the zoo's waves didn't finish";
  EXPECT_NE(log.find("ZOO: scenarios done"), std::string::npos) << "the zoo's scenarios didn't finish";
  EXPECT_NE(log.find("ZOO: sweeps done"), std::string::npos) << "the zoo's getter sweeps didn't finish";

  // The sim's checksum at each recorded beat, from "Checksum for beat N mismatched: <md5> (sim) != ...".
  std::map<int, std::string> sums;
  const std::string marker = "Checksum for beat ";
  for (std::size_t at = run.output.find(marker); at != std::string::npos; at = run.output.find(marker, at + 1)) {
    std::istringstream line(run.output.substr(at + marker.size(), 80));
    int beat = 0;
    std::string word;
    std::string md5;
    if (line >> beat >> word >> md5 && word == "mismatched:") {
      sums[beat] = md5;
    }
  }
  // The golden file holds them for 26930624, the original game's up to the beat its header names.
  const std::filesystem::path golden = std::filesystem::path(FAF_REPLAY_ZOO_DIR) / ("golden_" + zoo.id + ".txt");
  if (!std::filesystem::exists(golden)) {
    std::string pairs;
    for (const auto& [beat, md5] : sums) {
      pairs += std::to_string(beat) + " " + md5 + "\n";
    }
    GTEST_SKIP() << "no " << golden.string() << " for this replay; its pairs:\n" << pairs;
  }
  std::ifstream goldenFile(golden);
  int compared = 0;
  for (std::string text; std::getline(goldenFile, text);) {
    if (text.empty() || text[0] == '#') {
      continue;
    }
    std::istringstream line(text);
    int beat = 0;
    std::string md5;
    ASSERT_TRUE(static_cast<bool>(line >> beat >> md5)) << text;
    const auto found = sums.find(beat);
    ASSERT_NE(found, sums.end()) << "no checksum for beat " << beat;
    EXPECT_EQ(found->second, md5) << "beat " << beat;
    ++compared;
  }
  EXPECT_GT(compared, 100) << golden.string();
}

// A rejoin from a save (issue #275: a client that lost a heavy game loads one instead of running from beat 0): the
// first replay saved every 3000 beats, then played again from the beat-3000 save as command source 0, its own
// driver issuing beats after 4500. The recorded checksums after the save have to match.
TEST(ReplayPlayback, RejoinFromAKeyframeKeepsTheChecksums)
{
  const std::vector<SReplay> replays = Replays();
  if (replays.empty()) {
    GTEST_SKIP() << "set FAF_REPLAY_DATA to a folder with replays/ and faf/bin/ (see the file's header)";
  }
  const SReplay& replay = replays.front();
  SCOPED_TRACE("replay " + replay.id);
  const std::filesystem::path keyframes = LogFolder() / ("rejoin_keyframes_" + replay.id);
  std::error_code ignored;
  std::filesystem::remove_all(keyframes, ignored);
  std::filesystem::create_directories(keyframes);
  const std::string saver = "ctest_kfsave_" + replay.id;
  const SRun saved =
    PlayReplay(replay, saver, " --keyframe-every 3000 --keyframe-keep --keyframe-dir " + Quoted(keyframes));
  ExpectMatchedToTheEnd(saved);
  const std::filesystem::path save = keyframes / (saver + "_keyframe_3000.bin");
  ASSERT_TRUE(std::filesystem::exists(save)) << "no " << save.string();

  const SRun run = PlayReplay(
    replay, "ctest_rejoinkf_" + replay.id,
    " --resume-from " + Quoted(save) + " --rejoin-source 0 --focus 0 --rejoin-beat 4500"
  );
  ExpectMatchedToTheEnd(run);
  EXPECT_NE(run.output.find("resuming from beat"), std::string::npos) << run.output;
  std::filesystem::remove_all(keyframes, ignored);
}

// The analysis modes (docs/SWITCHES.md, headless --help) on the first replay, all in one run: the sim builds army 0's
// view and moves it to army 1 at beat 3000, as a player's client does, keeps what only a client reads, and writes
// the checksum digests, the published state, the Sync keys, the sync lanes, the bones, the blueprint order, the Lua
// pairs order and every file it touched. None of that may change the recorded checksums, and every file is written.
TEST(ReplayPlayback, AnalysisModesWriteTheirFilesAndKeepTheChecksums)
{
  const std::vector<SReplay> replays = Replays();
  if (replays.empty()) {
    GTEST_SKIP() << "set FAF_REPLAY_DATA to a folder with replays/ and faf/bin/ (see the file's header)";
  }
  const SReplay& replay = replays.front();
  SCOPED_TRACE("replay " + replay.id);
  const std::filesystem::path out = LogFolder() / ("modes_" + replay.id);
  std::error_code ignored;
  std::filesystem::remove_all(out, ignored); // files from an earlier run would hide a missing one
  std::filesystem::create_directories(out);
  const std::vector<std::pair<std::string, std::string>> files = {
    {"--digests", "digests.txt"},     {"--state-digests", "state.txt"}, {"--sync-keys", "keys.txt"},
    {"--lane-sizes", "lanes.csv"},    {"--bone-stats", "bones.csv"},    {"--blueprint-order", "blueprints.txt"},
    {"--lua-pairs", "pairs.txt"},     {"--disk-trace", "disk.txt"},     {"--sync-dump", "sync.bin"},
  };
  std::string arguments = " --focus 0 --focus-switch 3000:1 --keep-client-data --fpu-report";
  for (const auto& [option, name] : files) {
    arguments += " " + option + " " + Quoted(out / name);
  }
  const SRun run = PlayReplay(replay, "ctest_modes_" + replay.id, arguments);
  ExpectMatchedToTheEnd(run);

  for (const auto& [option, name] : files) {
    EXPECT_GT(std::filesystem::file_size(out / name, ignored), 0u) << option << " wrote nothing to " << name;
  }
  // One "beat md5" line per checksummed beat, as many as the beats line counts.
  const std::size_t at = run.beats.find("digests=");
  ASSERT_NE(at, std::string::npos) << run.beats;
  const int counted = std::atoi(run.beats.c_str() + at + 8);
  EXPECT_GT(counted, 0) << run.beats;
  std::ifstream digests(out / "digests.txt");
  int lines = 0;
  for (std::string line; std::getline(digests, line);) {
    lines += line.empty() ? 0 : 1;
  }
  EXPECT_EQ(lines, counted);
  std::filesystem::remove_all(out, ignored);
}

#if defined(FAF_HEADLESS_SERVER_MODE)
namespace
{
  /** The first replay played once with one server check; its summary must hold every `expected` text. */
  void ExpectServerCheck(const std::string& tag, const std::string& arguments, const std::vector<std::string>& expected)
  {
    const std::vector<SReplay> replays = Replays();
    if (replays.empty()) {
      GTEST_SKIP() << "set FAF_REPLAY_DATA to a folder with replays/ and faf/bin/ (see the file's header)";
    }
    const SReplay& replay = replays.front();
    SCOPED_TRACE("replay " + replay.id);
    const SRun run = PlayReplay(replay, "ctest_" + tag + "_" + replay.id, arguments);
    ExpectMatchedToTheEnd(run);
    for (const std::string& text : expected) {
      EXPECT_NE(run.output.find(text), std::string::npos) << "no \"" << text << "\" in\n" << run.output;
    }
  }

  std::string OutputFile(const std::string& name)
  {
    return Quoted(LogFolder() / name);
  }
} // namespace

// The replay's launch rebuilt from its header as the server builds it (BuildLaunchInfo) and compared; nothing played.
TEST(ReplayPlaybackServer, LaunchRebuildsFromTheHeader)
{
  const std::vector<SReplay> replays = Replays();
  if (replays.empty()) {
    GTEST_SKIP() << "set FAF_REPLAY_DATA to a folder with replays/ and faf/bin/ (see the file's header)";
  }
  const SReplay& replay = replays.front();
  const SRun run = Play(
    Quoted(FAF_HEADLESS_EXE) + " --launch-check --replay " + Quoted(replay.replay) + " /init " + Quoted(replay.init)
  );
  EXPECT_EQ(run.exitCode, 0) << run.output;
  EXPECT_NE(run.output.find("LAUNCHCHECK"), std::string::npos) << run.output;
  EXPECT_NE(run.output.find("differences=0"), std::string::npos) << run.output;
}

// Every command through the game server's seats, one per command source, each decoded and marshalled again as a
// client sends it.
TEST(ReplayPlaybackServer, SeatsCarryEveryCommandUnchanged)
{
  ExpectServerCheck("seats", " --seats --command-check", {"command check:", " 0 differing, 0 not marshalled again"});
}

// The visibility oracle for army 0 against what the sim publishes, every entity and beat, and the spatial oracle
// against brute force.
TEST(ReplayPlaybackServer, VisibilityOracleAgreesWithTheSim)
{
  ExpectServerCheck(
    "oracle", " --focus 0 --oracle-check", {"oracle check:", " 0 entity-beats differ", " 0 differ from brute force"}
  );
}

// The sync walk's change set against its packet, every beat.
TEST(ReplayPlaybackServer, ChangeSetCoversEveryPacketEntry)
{
  ExpectServerCheck("changeset", " --changeset-check", {"change-set check:", "(0 failures)"});
}

// Every army's view frame encoded and decoded again, with per-view ids, every command sent back through the view ids,
// and the spy checking that no frame names what its client does not hold.
TEST(ReplayPlaybackServer, ViewFramesRoundTrip)
{
  ExpectServerCheck(
    "frames", " --view-frames " + OutputFile("ctest_frames.csv") + " --view-ids --inbound-check --spy",
    {"view frames:", " 0 encode failures, 0 round-trip failures", "inbound check:", " 0 differing",
     "not mapping back to their family and source: 0"}
  );
}

// The view frames over a simulated channel that loses 5 % of them and acknowledges 3 beats late, as a real link does:
// each frame is encoded against the newest acknowledged one and must decode exactly (CClientFrameWindow).
TEST(ReplayPlaybackServer, ViewFramesSurviveALossyLateAckChannel)
{
  ExpectServerCheck(
    "lossy", " --view-frames " + OutputFile("ctest_lossy.csv") + " --view-loss 5 --view-ack-delay 3",
    {"view frames:", " 0 encode failures, 0 round-trip failures", "channel: 0 frames arrived and did not decode"}
  );
}

// Every packet through the wire format and the game client's rebuild of it (remote/client), with dead reckoning in
// 1/64-unit steps: what the client builds must be what the sim published.
TEST(ReplayPlaybackServer, LoopbackClientRebuildsEveryPacket)
{
  ExpectServerCheck(
    "loopback", " --loopback --loopback-dr 4 --loopback-turns 64",
    {"loopback end:", "encode failures 0, decode failures 0, rebuild failures 0", "packet creations not rebuilt 0",
     "erase mismatches 0, delete mismatches 0", "army lane", "(failures 0, records other than sent 0)"}
  );
}

// The server's view work as a bench: every view's kept frame against one built whole, the Lua lane routed (view 0
// moved to army 1 at beat 2000, view 1 resynced as after a reconnect at 3000, each view's Sync written), the session
// tables and pose lane, two pipeline threads and team views.
TEST(ReplayPlaybackServer, ViewBenchFramesMatchWholeFrames)
{
  ExpectServerCheck(
    "bench",
    " --view-bench " + OutputFile("ctest_bench.csv") +
      " --view-bench-check --lua-routing --lua-routing-dump " + OutputFile("ctest_routing") +
      " --lua-move-view 2000:0:1 --lua-resync 3000:1 --view-tables --view-poses --view-pipeline 2 --view-teams --spy",
    {"view bench:", " 0 encode failures, 0 check differences"}
  );
}

// Army 0's packet digests twice: rebuilt from the sync walk's change set (unfocused) and the sim's own packet (focused
// on army 0). The server's rebuild must be byte for byte what the sim sends.
TEST(ReplayPlaybackServer, ChangeSetRebuildsTheSimsOwnPacket)
{
  const std::vector<SReplay> replays = Replays();
  if (replays.empty()) {
    GTEST_SKIP() << "set FAF_REPLAY_DATA to a folder with replays/ and faf/bin/ (see the file's header)";
  }
  const SReplay& replay = replays.front();
  SCOPED_TRACE("replay " + replay.id);
  const std::filesystem::path rebuilt = LogFolder() / "ctest_packets_rebuilt.txt";
  const std::filesystem::path own = LogFolder() / "ctest_packets_own.txt";
  const std::filesystem::path entries = LogFolder() / "ctest_packets_entries.txt";
  std::error_code ignored;
  for (const auto& path : {rebuilt, own, entries}) {
    std::filesystem::remove(path, ignored);
  }
  const SRun unfocused = PlayReplay(
    replay, "ctest_packets_" + replay.id,
    " --view-packets 0 " + Quoted(rebuilt) + " --view-packets-entries " + Quoted(entries) +
      " --view-packets-entries-every 50"
  );
  ExpectMatchedToTheEnd(unfocused);
  EXPECT_NE(unfocused.output.find("rebuilt from the change set"), std::string::npos) << unfocused.output;
  const SRun focused = PlayReplay(replay, "ctest_packetsf_" + replay.id, " --focus 0 --view-packets 0 " + Quoted(own));
  ExpectMatchedToTheEnd(focused);
  EXPECT_NE(focused.output.find("the sim's own packet"), std::string::npos) << focused.output;

  // The beats up to the run's last one: the sim runs on past it while headless finishes (ReplayRunner.cpp), so a beat
  // after it may or may not reach either file.
  const std::size_t at = unfocused.beats.find("last-beat=");
  ASSERT_NE(at, std::string::npos) << unfocused.beats;
  const long lastBeat = std::atol(unfocused.beats.c_str() + at + 10);
  const auto beatsUpToLast = [lastBeat](const std::filesystem::path& path) {
    std::vector<std::string> lines;
    std::ifstream file(path);
    for (std::string line; std::getline(file, line);) {
      if (!line.empty() && std::atol(line.c_str()) <= lastBeat) {
        lines.push_back(line);
      }
    }
    return lines;
  };
  const std::vector<std::string> rebuiltLines = beatsUpToLast(rebuilt);
  const std::vector<std::string> ownLines = beatsUpToLast(own);
  EXPECT_EQ(rebuiltLines.size(), static_cast<std::size_t>(lastBeat + 1));
  EXPECT_EQ(ownLines.size(), static_cast<std::size_t>(lastBeat + 1));
  std::size_t differing = 0;
  for (std::size_t i = 0; i < rebuiltLines.size() && i < ownLines.size(); ++i) {
    if (rebuiltLines[i] != ownLines[i] && differing++ == 0) {
      ADD_FAILURE() << "the change set's packet differs from the sim's first at\n  " << rebuiltLines[i] << "\n  "
                    << ownLines[i] << "\n(" << rebuilt.string() << " against " << own.string() << ")";
    }
  }
  EXPECT_EQ(differing, 0u);
  EXPECT_GT(std::filesystem::file_size(entries, ignored), 0u);
}

// The wire format's entities lane run on every beat beside the sim.
TEST(ReplayPlaybackServer, WireStatsRunOnEveryBeat)
{
  const std::filesystem::path stats = LogFolder() / "ctest_wire.csv";
  std::error_code ignored;
  std::filesystem::remove(stats, ignored);
  ExpectServerCheck("wire", " --wire-stats " + Quoted(stats), {});
  EXPECT_GT(std::filesystem::file_size(stats, ignored), 0u);
}
#endif

// The checks above can fail: with /desynctestbeat this client alone nudges one unit's health at beat 1500
// (sim_DesyncTestNudgeBeat, docs/SWITCHES.md "Desync recorder"), so the recorded checksums stop matching from
// there. Headless must report the mismatch with exit code 1, and /desyncdump must write the desync dump for
// beat 1500 next to the log.
TEST(ReplayPlayback, DeliberateDesyncIsCaughtAndDumped)
{
  const std::vector<SReplay> replays = Replays();
  if (replays.empty()) {
    GTEST_SKIP() << "set FAF_REPLAY_DATA to a folder with replays/ and faf/bin/ (see the file's header)";
  }
  const SReplay& replay = replays.front();
  SCOPED_TRACE("replay " + replay.id);
  std::error_code ignored;
  for (const auto& entry : std::filesystem::directory_iterator(LogFolder(), ignored)) {
    if (entry.path().filename().string().rfind("desync_", 0) == 0) {
      std::filesystem::remove(entry.path(), ignored); // a dump from an earlier run would hide a missing one
    }
  }

  const SRun run = PlayReplay(replay, "ctest_desync_" + replay.id, " /desynctestbeat 1500 /desyncdump");
  EXPECT_EQ(run.exitCode, 1) << "headless exit code 1 is a checksum mismatch\n" << run.tail;
  EXPECT_EQ(run.verdict.find("mismatches=0"), std::string::npos) << run.verdict;
  EXPECT_NE(run.verdict.find("crash=False"), std::string::npos) << run.verdict;

  bool dumped = false;
  for (const auto& entry : std::filesystem::directory_iterator(LogFolder(), ignored)) {
    const std::string name = entry.path().filename().string();
    if (name.rfind("desync_", 0) == 0 && name.find("_beat1500_") != std::string::npos && entry.file_size(ignored) > 0) {
      dumped = true;
      std::filesystem::remove(entry.path(), ignored);
    }
  }
  EXPECT_TRUE(dumped) << "no desync_*_beat1500_*.zip in " << LogFolder().string();
}
