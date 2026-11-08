// Recorded games played back by headless, every recorded checksum compared (docs/PR_REPLAY_CHECK.md):
// the simulation as a whole under test. Needs the game data, so it is skipped without it:
//
//   FAF_REPLAY_DATA   folder with replays/vault_<id>.scfareplay and faf/bin/<init>
//   FAF_REPLAY_INIT   the init file under faf/bin (default init_replay.lua)
//   FAF_REPLAY_IDS    replays to play, separated by commas (default 26930624, a 2-player core replay);
//                     `id:init` plays one with its own init file under faf/bin (M28AI replays need one)
//   FAF_REPLAY_SEEK   the beats the keyframe test moves to on the first replay (default 3000,900,6000)
//
// A FAF_COVERAGE build's headless writes its own counters (LLVM_PROFILE_FILE), so these games count in
// tools/coverage/report.sh.

#include <gtest/gtest.h>

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <sstream>
#include <string>
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
