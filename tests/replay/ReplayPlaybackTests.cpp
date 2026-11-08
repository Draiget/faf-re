// Recorded games played back by headless, every recorded checksum compared (docs/PR_REPLAY_CHECK.md):
// the simulation as a whole under test. Needs the game data, so it is skipped without it:
//
//   FAF_REPLAY_DATA   folder with replays/vault_<id>.scfareplay and faf/bin/<init>
//   FAF_REPLAY_INIT   the init file under faf/bin (default init_replay.lua)
//   FAF_REPLAY_IDS    replays to play, separated by commas (default 26930624, a 2-player core replay)
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

TEST(ReplayPlayback, RecordedChecksumsMatch)
{
  const std::string data = Environment("FAF_REPLAY_DATA", "");
  if (data.empty()) {
    GTEST_SKIP() << "set FAF_REPLAY_DATA to a folder with replays/ and faf/bin/ (see the file's header)";
  }
  const std::filesystem::path root(data);
  const std::filesystem::path init = root / "faf" / "bin" / Environment("FAF_REPLAY_INIT", "init_replay.lua");
  ASSERT_TRUE(std::filesystem::exists(init)) << init.string();
  const std::filesystem::path logs = std::filesystem::temp_directory_path() / "faf_replay_playback";
  std::filesystem::create_directories(logs);

  const std::vector<std::string> ids = Split(Environment("FAF_REPLAY_IDS", "26930624"));
  ASSERT_FALSE(ids.empty());
  for (const std::string& id : ids) {
    SCOPED_TRACE("replay " + id);
    const std::filesystem::path replay = root / "replays" / ("vault_" + id + ".scfareplay");
    ASSERT_TRUE(std::filesystem::exists(replay)) << replay.string();

    const std::string command = Quoted(FAF_HEADLESS_EXE) + " --label ctest_" + id + " --replay " + Quoted(replay) +
                                " /init " + Quoted(init) + " /nobugreport /nosound /log " +
                                Quoted(logs / (id + ".log"));
    const SRun run = Play(command);
    std::printf("%s%s", run.beats.c_str(), run.verdict.c_str());
    EXPECT_EQ(run.exitCode, 0) << "headless exit code (1 mismatch, 2 incomplete, 3 crash, 4 bad input)\n" << run.tail;
    // The playback reached the sim's game-over beat. (VERDICT's `ended` is the game's own Lua GameEnded,
    // which a game without a victory never sets; docs/SWITCHES.md.)
    EXPECT_NE(run.beats.find("game-over=True"), std::string::npos) << run.beats;
    EXPECT_NE(run.verdict.find("mismatches=0"), std::string::npos) << run.verdict;
    EXPECT_NE(run.verdict.find("crash=False"), std::string::npos) << run.verdict;
  }
}
