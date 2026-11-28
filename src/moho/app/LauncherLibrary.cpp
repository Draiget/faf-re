// Engine addition (in-game launcher plan, WP5/WP6): the launcher's Replays and Mods pages, engine side. Replays on this
// computer (the game's own replay folder, FAF's client's, and the launcher's downloads) and what their heads say,
// FAF's replays readied to play, and searches and downloads in FAF's replay and mod vaults on threads of their own,
// which the pages ask after each frame (FafLibrary_Job). Nothing here runs until the launcher's Lua calls it.

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <expected>
#include <filesystem>
#include <fstream>
#include <functional>
#include <iterator>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <system_error>
#include <thread>
#include <vector>

#include "gpg/core/diagnostics/BuildInfo.h"
#include "gpg/core/utils/Logging.h"
#include "lua/LuaObject.h"
#include "moho/app/OnlineLauncher.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/StartupHelpers.h"
#include "online/FafReplay.h"
#include "online/FafVault.h"
#include "online/Zip.h"
#include "platform/Http.h"
#include "platform/PlatformDefines.h"

namespace
{
  using namespace faf::online;

  void LogLine(
    const std::string& line
  )
  {
    gpg::Logf("LIBRARY: %s", line.c_str());
  }

  std::string Lower(
    std::string text
  )
  {
    for (char& c : text) {
      if (c >= 'A' && c <= 'Z') {
        c = static_cast<char>(c - 'A' + 'a');
      }
    }
    return text;
  }

  /** Where FAF's replays download from: the replay host, which sends the request on to the file (no sign-in). */
  std::string ReplayBase()
  {
    const char* const test = std::getenv("FAF_ONLINE_REPLAY"); // a test hook, unset for players
    return test != nullptr && test[0] != '\0' ? test : moho::ONLINE_ReplayBase();
  }

  std::string UserAgent()
  {
    return std::string("faf-re-client/") + gpg::diag::BuildVersion();
  }

  std::filesystem::path DownloadsFolder()
  {
    return moho::ONLINE_DataFolder() / "replays";
  }

  /** A file's last change in seconds since 1970. */
  double FileSeconds(
    const std::filesystem::path& path
  )
  {
    std::error_code error;
    const auto written = std::filesystem::last_write_time(path, error);
    if (error) {
      return 0;
    }
    const auto system = written - std::filesystem::file_time_type::clock::now() + std::chrono::system_clock::now();
    return std::chrono::duration<double>(system.time_since_epoch()).count();
  }

  std::string ReadFile(
    const std::filesystem::path& path,
    const std::size_t limit
  )
  {
    std::ifstream in(path, std::ios::binary);
    std::string bytes;
    bytes.resize(limit);
    in.read(bytes.data(), static_cast<std::streamsize>(limit));
    bytes.resize(static_cast<std::size_t>(in.gcount()));
    return bytes;
  }

  /** Writes `bytes` beside `path` and renames it there, so a half-written file is never seen under its name. */
  std::expected<void, std::string> WriteWhole(
    const std::filesystem::path& path,
    const std::string& bytes
  )
  {
    std::error_code error;
    std::filesystem::create_directories(path.parent_path(), error);
    const std::filesystem::path part = path.string() + ".part";
    {
      std::ofstream out(part, std::ios::binary | std::ios::trunc);
      out.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
      if (!out) {
        return std::unexpected("can't write " + part.string());
      }
    }
    std::filesystem::rename(part, path, error);
    if (error) {
      std::filesystem::remove(part, error);
      return std::unexpected("can't write " + path.string());
    }
    return {};
  }

  // ---------------------------------------------------------------------------------------------------------------
  // Lua tables.

  void SetField(
    lua_State* const L,
    const char* const key,
    const std::string& value
  )
  {
    lua_pushstring(L, key);
    lua_pushstring(L, value.c_str());
    lua_rawset(L, -3);
  }

  void SetField(
    lua_State* const L,
    const char* const key,
    const double value
  )
  {
    lua_pushstring(L, key);
    lua_pushnumber(L, static_cast<lua_Number>(value));
    lua_rawset(L, -3);
  }

  void SetBool(
    lua_State* const L,
    const char* const key,
    const bool value
  )
  {
    lua_pushstring(L, key);
    lua_pushboolean(L, value ? 1 : 0);
    lua_rawset(L, -3);
  }

  std::string TableString(
    lua_State* const L,
    const int table,
    const char* const key
  )
  {
    lua_pushstring(L, key);
    lua_gettable(L, table);
    std::string value = lua_isstring(L, -1) ? lua_tostring(L, -1) : "";
    lua_pop(L, 1);
    return value;
  }

  double TableNumber(
    lua_State* const L,
    const int table,
    const char* const key,
    const double fallback
  )
  {
    lua_pushstring(L, key);
    lua_gettable(L, table);
    const double value = lua_isnumber(L, -1) ? lua_tonumber(L, -1) : fallback;
    lua_pop(L, 1);
    return value;
  }

  bool TableBool(
    lua_State* const L,
    const int table,
    const char* const key
  )
  {
    lua_pushstring(L, key);
    lua_gettable(L, table);
    const bool value = lua_toboolean(L, -1) != 0;
    lua_pop(L, 1);
    return value;
  }

  void PushStrings(
    lua_State* const L,
    const char* const key,
    const std::vector<std::string>& values
  )
  {
    lua_pushstring(L, key);
    lua_newtable(L);
    int index = 1;
    for (const std::string& value : values) {
      lua_pushstring(L, value.c_str());
      lua_rawseti(L, -2, index++);
    }
    lua_rawset(L, -3);
  }

  // ---------------------------------------------------------------------------------------------------------------
  // Background jobs: one search or download each, on a thread of its own.

  struct Job
  {
    int id = 0;
    std::string kind; ///< "replays", "replay", "mods", "mod", "map", "api", "thumbnail"
    std::thread thread;
    std::atomic<bool> done{false};
    std::atomic<std::uint64_t> received{0};
    std::atomic<std::uint64_t> total{0};
    std::mutex lock;
    bool failed = false;
    std::string message;
    std::string path;     ///< a download's file (a mod's folder)
    bool mounted = false; ///< a mod's folder is in the game's file system
    VaultPage page;
    std::vector<VaultReplay> replays;
    std::vector<VaultMod> mods;
    JsonNode answer; ///< a plain API read's answer

    void Fail(
      std::string why
    )
    {
      std::lock_guard<std::mutex> guard(lock);
      failed = true;
      message = std::move(why);
    }
  };

  std::mutex gJobsLock;
  std::map<int, std::shared_ptr<Job>> gJobs;
  int gNextJob = 1;

  int StartJob(
    const std::string& kind,
    std::function<void(Job&)> work
  )
  {
    auto job = std::make_shared<Job>();
    job->kind = kind;
    {
      std::lock_guard<std::mutex> guard(gJobsLock);
      job->id = gNextJob++;
      gJobs[job->id] = job;
    }
    Job* const raw = job.get();
    job->thread = std::thread([raw, work = std::move(work)] {
      try {
        work(*raw);
      } catch (const std::exception& exception) {
        raw->Fail(std::string("failed: ") + exception.what());
      }
      raw->done = true;
    });
    return job->id;
  }

  /** An API GET with the player's token: the answer's body, or why there is none. */
  std::expected<std::string, std::string> ApiGet(
    const std::string& url
  )
  {
    const auto token = moho::ONLINE_AccessToken();
    if (!token) {
      return std::unexpected("sign in to FAF first (" + token.error() + ")");
    }
    platform::http::Call call;
    call.url = url;
    call.userAgent = UserAgent();
    call.headers = "Accept: application/vnd.api+json\r\nAuthorization: Bearer " + *token + "\r\n";
    long status = 0;
    std::string body;
    if (const auto sent = platform::http::Request(call, status, body); !sent) {
      return std::unexpected("FAF's API didn't answer: " + sent.error());
    }
    if (status == 401 || status == 403) {
      return std::unexpected("FAF's API refused this sign-in (HTTP " + std::to_string(status) + ")");
    }
    if (status != 200) {
      return std::unexpected("FAF's API answered HTTP " + std::to_string(status));
    }
    return body;
  }

  /** number FafLibrary_UtcNow(): seconds since 1970 (UTC), for calendars that count from it. */
  int UtcNowBody(
    lua_State* const L
  )
  {
    lua_pushnumber(L, static_cast<lua_Number>(std::time(nullptr)));
    return 1;
  }

  /** text FafLibrary_UtcDate(daysAgo): the UTC date that many days back as FAF's API compares times. */
  int UtcDateBody(
    lua_State* const L
  )
  {
    const int back = lua_type(L, 1) == LUA_TNUMBER ? static_cast<int>(lua_tonumber(L, 1)) : 0;
    const auto today = std::chrono::floor<std::chrono::days>(std::chrono::system_clock::now());
    const std::chrono::year_month_day day{today - std::chrono::days(back)};
    char text[32];
    std::snprintf(
      text,
      sizeof(text),
      "%04d-%02u-%02uT00:00:00Z",
      static_cast<int>(day.year()),
      static_cast<unsigned>(day.month()),
      static_cast<unsigned>(day.day())
    );
    lua_pushstring(L, text);
    return 1;
  }

  /**
   * text FafLibrary_LocalTime(when): a moment in this computer's time zone, "2026-11-27 14:05". `when` is seconds
   * since 1970 or an ISO 8601 UTC time as FAF's API writes it ("2026-11-27T10:05:00Z"); empty when it is neither.
   */
  int LocalTimeBody(
    lua_State* const L
  )
  {
    std::time_t when = 0;
    if (lua_type(L, 1) == LUA_TNUMBER) {
      when = static_cast<std::time_t>(lua_tonumber(L, 1));
    } else if (lua_isstring(L, 1)) {
      int year = 0;
      int month = 0;
      int day = 0;
      int hour = 0;
      int minute = 0;
      int second = 0;
      if (std::sscanf(lua_tostring(L, 1), "%d-%d-%dT%d:%d:%d", &year, &month, &day, &hour, &minute, &second) < 3) {
        lua_pushstring(L, "");
        return 1;
      }
      const std::chrono::sys_days date = std::chrono::year(year) / std::chrono::month(static_cast<unsigned>(month)) /
        std::chrono::day(static_cast<unsigned>(day));
      when = static_cast<std::time_t>(date.time_since_epoch().count()) * 86400 + hour * 3600 + minute * 60 + second;
    }
    if (when <= 0) {
      lua_pushstring(L, "");
      return 1;
    }
    std::tm local{};
#if FAFRE_PLATFORM_WINDOWS
    const bool converted = localtime_s(&local, &when) == 0;
#else
    const bool converted = localtime_r(&when, &local) != nullptr;
#endif
    char text[32] = {};
    if (converted) {
      std::strftime(text, sizeof(text), "%Y-%m-%d %H:%M", &local);
    }
    lua_pushstring(L, text);
    return 1;
  }

  // ---------------------------------------------------------------------------------------------------------------
  // Replays on this computer.

  struct LocalReplay
  {
    std::filesystem::path path;
    std::string source; ///< "game", "faf", "downloads"
  };

  void ListFolder(
    const std::filesystem::path& folder,
    const std::string& source,
    const int depth,
    std::vector<LocalReplay>& out
  )
  {
    std::error_code error;
    if (folder.empty() || !std::filesystem::is_directory(folder, error)) {
      return;
    }
    for (std::filesystem::directory_iterator it(folder, error), end; !error && it != end; it.increment(error)) {
      const std::filesystem::path& path = it->path();
      if (it->is_directory(error)) {
        if (depth > 0 && path.filename() != "play") {
          ListFolder(path, source, depth - 1, out);
        }
        continue;
      }
      const std::string extension = Lower(path.extension().string());
      if (extension == ".fafreplay" || extension == ".scfareplay") {
        out.push_back({path, source});
      }
    }
  }

  /**
   * table FafLibrary_LocalReplays(): the replays on this computer, each {path, file, source, size, time}: the game's
   * own replay folder and its profiles' (source "game"), FAF's client's replay folder beside its bin folder ("faf"),
   * and what the launcher downloaded ("downloads").
   */
  int LocalReplaysBody(
    lua_State* const L
  )
  {
    std::vector<LocalReplay> found;
    ListFolder(std::filesystem::path(moho::USER_GetReplayDir().c_str()), "game", 1, found);
    // FAF's client keeps its replays in its data folder: beside the bin folder the init file is in, which is
    // %ProgramData%\FAForever on Windows (the client's default); each folder once.
    std::vector<std::filesystem::path> fafFolders;
    if (const std::filesystem::path init = moho::ONLINE_InitFile(); !init.empty()) {
      std::error_code error;
      fafFolders.push_back(std::filesystem::absolute(init, error).parent_path().parent_path() / "replays");
    }
    if (const char* const programData = std::getenv("ProgramData"); programData != nullptr && programData[0] != '\0') {
      fafFolders.push_back(std::filesystem::path(programData) / "FAForever" / "replays");
    }
    std::vector<std::filesystem::path> listed;
    for (const std::filesystem::path& folder : fafFolders) {
      std::error_code error;
      const std::filesystem::path canonical = std::filesystem::weakly_canonical(folder, error);
      bool seen = false;
      for (const std::filesystem::path& before : listed) {
        seen = seen || before == canonical;
      }
      if (!seen) {
        listed.push_back(canonical);
        ListFolder(folder, "faf", 0, found);
      }
    }
    ListFolder(DownloadsFolder(), "downloads", 0, found);
    lua_newtable(L);
    int index = 1;
    for (const LocalReplay& replay : found) {
      std::error_code error;
      lua_newtable(L);
      SetField(L, "path", replay.path.string());
      SetField(L, "file", replay.path.filename().string());
      SetField(L, "source", replay.source);
      SetField(L, "size", static_cast<double>(std::filesystem::file_size(replay.path, error)));
      SetField(L, "time", FileSeconds(replay.path));
      lua_rawseti(L, -2, index++);
    }
    return 1;
  }

  /** The map folder of a scenario path (/maps/<folder>/...), or the text as it is. */
  std::string MapFolderOf(
    const std::string& path
  )
  {
    const std::string lower = Lower(path);
    if (lower.rfind("/maps/", 0) == 0) {
      const std::size_t end = lower.find('/', 6);
      return lower.substr(6, end == std::string::npos ? std::string::npos : end - 6);
    }
    return lower;
  }

  /**
   * table|nil, why = FafLibrary_ReplayInfo(path): what a replay's head says: kind ("faf" or "game"), title, map (its
   * folder), featuredMod, uid, launchedAt and gameEnd (seconds since 1970), complete, version, mods (names), and
   * players, each {name, team} (team 0 when the file doesn't say).
   */
  int ReplayInfoBody(
    lua_State* const L
  )
  {
    const std::filesystem::path path = lua_isstring(L, 1) ? lua_tostring(L, 1) : "";
    if (Lower(path.extension().string()) == ".fafreplay") {
      auto header = ReadFafReplayHeader(ReadFile(path, 16 * 1024));
      if (!header) {
        header = ReadFafReplayHeader(ReadFile(path, 1024 * 1024)); // a head with many mods or players
      }
      if (!header) {
        lua_pushnil(L);
        lua_pushstring(L, header.error().c_str());
        return 2;
      }
      lua_newtable(L);
      SetField(L, "kind", "faf");
      SetField(L, "title", header->String("title"));
      SetField(L, "map", Lower(header->String("mapname")));
      SetField(L, "featuredMod", header->String("featured_mod"));
      SetField(L, "uid", header->String("uid"));
      SetField(L, "host", header->String("host"));
      SetField(L, "launchedAt", header->Number("launched_at"));
      SetField(L, "gameEnd", header->Number("game_end"));
      SetBool(L, "complete", header->Bool("complete"));
      std::vector<std::string> mods;
      if (
        const JsonNode* const simMods = header->Get("sim_mods");
        simMods != nullptr && simMods->kind == JsonNode::Kind::Object
      ) {
        for (const auto& [uid, name] : simMods->members) {
          mods.push_back(name.kind == JsonNode::Kind::String ? name.text : uid);
        }
      }
      PushStrings(L, "mods", mods);
      lua_pushstring(L, "players");
      lua_newtable(L);
      int index = 1;
      if (
        const JsonNode* const teams = header->Get("teams"); teams != nullptr && teams->kind == JsonNode::Kind::Object
      ) {
        for (const auto& [team, logins] : teams->members) {
          if (logins.kind != JsonNode::Kind::Array) {
            continue;
          }
          for (const JsonNode& login : logins.items) {
            lua_newtable(L);
            SetField(L, "name", login.text);
            SetField(L, "team", std::atof(team.c_str()));
            lua_rawseti(L, -2, index++);
          }
        }
      }
      lua_rawset(L, -3);
      return 1;
    }
    const auto summary = ReadGameReplaySummary(ReadFile(path, 4 * 1024 * 1024));
    if (!summary) {
      lua_pushnil(L);
      lua_pushstring(L, summary.error().c_str());
      return 2;
    }
    lua_newtable(L);
    SetField(L, "kind", "game");
    SetField(L, "title", path.stem().string());
    SetField(L, "map", MapFolderOf(summary->map));
    SetField(L, "version", summary->version);
    SetField(L, "launchedAt", FileSeconds(path));
    PushStrings(L, "mods", summary->mods);
    lua_pushstring(L, "players");
    lua_newtable(L);
    int index = 1;
    for (const std::string& name : summary->players) {
      lua_newtable(L);
      SetField(L, "name", name);
      SetField(L, "team", 0.0);
      lua_rawseti(L, -2, index++);
    }
    lua_rawset(L, -3);
    return 1;
  }

  /**
   * ok, path|why = FafLibrary_PrepareReplay(path): a file LaunchReplaySession can play. The game's own replays as
   * they are; a FAF replay decoded into the launcher's play folder first.
   */
  int PrepareReplayBody(
    lua_State* const L
  )
  {
    const std::filesystem::path path = lua_isstring(L, 1) ? lua_tostring(L, 1) : "";
    if (Lower(path.extension().string()) != ".fafreplay") {
      lua_pushboolean(L, 1);
      lua_pushstring(L, path.string().c_str());
      return 2;
    }
    std::error_code error;
    const auto size = std::filesystem::file_size(path, error);
    if (error || size > 512u * 1024u * 1024u) {
      lua_pushboolean(L, 0);
      lua_pushstring(L, ("can't read " + path.filename().string()).c_str());
      return 2;
    }
    const auto file = DecodeFafReplay(ReadFile(path, static_cast<std::size_t>(size)));
    if (!file) {
      lua_pushboolean(L, 0);
      lua_pushstring(L, file.error().c_str());
      return 2;
    }
    const std::filesystem::path play = DownloadsFolder() / "play" / (path.stem().string() + ".SCFAReplay");
    if (const auto written = WriteWhole(play, file->stream); !written) {
      lua_pushboolean(L, 0);
      lua_pushstring(L, written.error().c_str());
      return 2;
    }
    LogLine("ready to play " + path.filename().string() + " as " + play.string());
    lua_pushboolean(L, 1);
    lua_pushstring(L, play.string().c_str());
    return 2;
  }

  /**
   * seconds|nil, why = FafLibrary_ReplayLength(path): how long the game in a replay ran in game time (its beats, 10 a
   * second), read from the whole file (a FAF replay decoded first). For the selected replay, not for a list.
   */
  int ReplayLengthBody(
    lua_State* const L
  )
  {
    const std::filesystem::path path = lua_isstring(L, 1) ? lua_tostring(L, 1) : "";
    std::error_code error;
    const auto size = std::filesystem::file_size(path, error);
    if (error || size > 512u * 1024u * 1024u) {
      lua_pushnil(L);
      lua_pushstring(L, "can't read the replay");
      return 2;
    }
    std::string stream = ReadFile(path, static_cast<std::size_t>(size));
    if (Lower(path.extension().string()) == ".fafreplay") {
      auto file = DecodeFafReplay(stream);
      if (!file) {
        lua_pushnil(L);
        lua_pushstring(L, file.error().c_str());
        return 2;
      }
      stream = std::move(file->stream);
    }
    const auto summary = ReadGameReplaySummary(stream, true);
    if (!summary || summary->beats < 0) {
      lua_pushnil(L);
      lua_pushstring(L, summary ? "its commands can't be read" : summary.error().c_str());
      return 2;
    }
    lua_pushnumber(L, static_cast<lua_Number>(static_cast<double>(summary->beats) / 10.0));
    return 1;
  }

  // ---------------------------------------------------------------------------------------------------------------
  // The vaults.

  /** id = FafLibrary_SearchReplays{player=, map=, title=, mod=, rated=, page=, pageSize=}. */
  int SearchReplaysBody(
    lua_State* const L
  )
  {
    ReplayQuery query;
    if (lua_istable(L, 1)) {
      query.player = TableString(L, 1, "player");
      query.map = TableString(L, 1, "map");
      query.title = TableString(L, 1, "title");
      query.featuredMod = TableString(L, 1, "mod");
      query.id = TableString(L, 1, "id");
      query.ratedOnly = TableBool(L, 1, "rated");
      query.page = static_cast<int>(TableNumber(L, 1, "page", 1));
      query.pageSize = static_cast<int>(TableNumber(L, 1, "pageSize", 30));
    }
    const std::string url = ReplaySearchUrl(moho::ONLINE_ApiBase(), query);
    lua_pushnumber(L, static_cast<lua_Number>(StartJob("replays", [url](Job& job) {
      const auto body = ApiGet(url);
      if (!body) {
        job.Fail(body.error());
        return;
      }
      VaultPage page;
      auto rows = ReadReplayPage(*body, &page);
      if (!rows) {
        job.Fail(rows.error());
        return;
      }
      std::lock_guard<std::mutex> guard(job.lock);
      job.page = page;
      job.replays = std::move(*rows);
    })));
    return 1;
  }

  /** id = FafLibrary_DownloadReplay(gameId): the game's replay into the launcher's replay folder. */
  int DownloadReplayBody(
    lua_State* const L
  )
  {
    std::string id = lua_isstring(L, 1) ? lua_tostring(L, 1) : "";
    if (id.empty() || id.find_first_not_of("0123456789") != std::string::npos) {
      lua_pushnil(L);
      return 1;
    }
    const std::string url = ReplayDownloadUrl(ReplayBase(), id);
    const std::filesystem::path target = DownloadsFolder() / (id + ".fafreplay");
    lua_pushnumber(L, static_cast<lua_Number>(StartJob("replay", [url, target](Job& job) {
      platform::http::Call call;
      call.url = url;
      call.userAgent = UserAgent();
      long status = 0;
      std::string body;
      if (const auto sent = platform::http::Request(call, status, body, &job.received, &job.total); !sent) {
        job.Fail("the replay didn't download: " + sent.error());
        return;
      }
      if (status != 200) {
        job.Fail(
          status == 404 ? std::string("FAF has no replay of this game")
                        : "the replay host answered HTTP " + std::to_string(status)
        );
        return;
      }
      if (const auto header = ReadFafReplayHeader(body); !header) {
        job.Fail("what downloaded isn't a FAF replay");
        return;
      }
      if (const auto written = WriteWhole(target, body); !written) {
        job.Fail(written.error());
        return;
      }
      LogLine("downloaded " + target.string() + " (" + std::to_string(body.size()) + " bytes)");
      std::lock_guard<std::mutex> guard(job.lock);
      job.path = target.string();
    })));
    return 1;
  }

  // ---------------------------------------------------------------------------------------------------------------
  // Mods.

  /**
   * The vault folder FAF's game files use (maps, mods): `custom_vault_path` in FAF's fa_path.lua beside the bin folder
   * the game runs from, as its init file reads it; else the folder the game's replay folder is in (Documents\My
   * Games\Gas Powered Games\Supreme Commander Forged Alliance).
   */
  std::filesystem::path VaultFolder()
  {
    if (const char* const test = std::getenv("FAF_ONLINE_VAULT"); test != nullptr && test[0] != '\0') {
      return test; // a test hook, unset for players
    }
    if (const std::filesystem::path init = moho::ONLINE_InitFile(); !init.empty()) {
      std::error_code error;
      const std::filesystem::path paths =
        std::filesystem::absolute(init, error).parent_path().parent_path() / "fa_path.lua";
      const std::string text = ReadFile(paths, 64 * 1024);
      const std::size_t key = text.find("custom_vault_path");
      const std::size_t open = key == std::string::npos ? std::string::npos : text.find('"', key);
      const std::size_t close = open == std::string::npos ? std::string::npos : text.find('"', open + 1);
      if (close != std::string::npos && close > open + 1) {
        return std::filesystem::path(text.substr(open + 1, close - open - 1));
      }
    }
    std::string replays = moho::USER_GetReplayDir().c_str();
    while (!replays.empty() && (replays.back() == '/' || replays.back() == '\\')) {
      replays.pop_back();
    }
    return std::filesystem::path(replays).parent_path();
  }

  std::filesystem::path ModsFolder()
  {
    return VaultFolder() / "mods";
  }

  /** Where mods may download from: the FAF server's content server (the FAF clients' rule), or a test stack's. */
  bool AllowedModUrl(
    const std::string& url
  )
  {
    if (url.rfind(moho::ONLINE_ContentBase() + "/", 0) == 0) {
      return true;
    }
    const char* const test = std::getenv("FAF_ONLINE_CONTENT"); // a test hook, unset for players
    return test != nullptr && test[0] != '\0' && url.rfind(test, 0) == 0;
  }

  /** FAF's website for its news: the chosen server's, or FAF_ONLINE_NEWS (a test hook, unset for players). */
  std::string NewsBase()
  {
    const char* const test = std::getenv("FAF_ONLINE_NEWS");
    return test != nullptr && test[0] != '\0' ? std::string(test) : moho::ONLINE_WebsiteBase();
  }

  /** A picture the launcher may download and keep: from FAF's content server, or a news post's from FAF's website. */
  bool AllowedPictureUrl(
    const std::string& url
  )
  {
    return AllowedModUrl(url) || url.rfind(NewsBase() + "/wp-content/uploads/", 0) == 0;
  }

  /**
   * id = FafLibrary_News{page=}: one page of FAF's news posts (the website's WordPress API, with their authors,
   * categories and pictures), as the job's data. No sign-in needed.
   */
  int NewsBody(
    lua_State* const L
  )
  {
    int page = 1;
    if (lua_istable(L, 1)) {
      lua_pushstring(L, "page");
      lua_gettable(L, 1);
      if (lua_isnumber(L, -1)) {
        page = std::max(1, std::min(100, static_cast<int>(lua_tonumber(L, -1))));
      }
      lua_pop(L, 1);
    }
    const std::string url = NewsBase() + "/wp-json/wp/v2/posts?_embed=1&per_page=12&page=" + std::to_string(page);
    lua_pushnumber(L, static_cast<lua_Number>(StartJob("api", [url](Job& job) {
      platform::http::Call call;
      call.url = url;
      call.userAgent = UserAgent();
      call.headers = "Accept: application/json\r\n";
      long status = 0;
      std::string body;
      if (const auto sent = platform::http::Request(call, status, body); !sent) {
        job.Fail("FAF's website didn't answer: " + sent.error());
        return;
      }
      if (status == 400) { // WordPress answers a page past the last with 400
        body = "[]";
      } else if (status != 200) {
        job.Fail("FAF's website answered HTTP " + std::to_string(status));
        return;
      }
      auto parsed = ParseJson(body);
      if (!parsed) {
        job.Fail("FAF's website answered with something that isn't JSON");
        return;
      }
      std::lock_guard<std::mutex> guard(job.lock);
      job.answer = std::move(*parsed);
    })));
    return 1;
  }

  // ---------------------------------------------------------------------------------------------------------------
  // Reviews: the player's own review of a map, mod or game written to FAF's API (JSON:API, as the FAF client writes
  // them: POST to the version's reviews, PATCH and DELETE on the review). Only these: the requests are built here from
  // a score and a text, never from a path or a body the Lua gives.

  struct ReviewKind
  {
    const char* kind;    ///< what the Lua names: "map", "mod", "game"
    const char* subject; ///< the reviewed resource: mapVersion, modVersion, game
    const char* review;  ///< the review resource
  };

  constexpr ReviewKind kReviewKinds[] = {
    {"map", "mapVersion", "mapVersionReview"},
    {"mod", "modVersion", "modVersionReview"},
    {"game", "game", "gameReview"},
  };

  const ReviewKind* FindReviewKind(
    const std::string& kind
  )
  {
    for (const ReviewKind& known : kReviewKinds) {
      if (kind == known.kind) {
        return &known;
      }
    }
    return nullptr;
  }

  bool AllDigits(
    const std::string& text
  )
  {
    return !text.empty() && text.size() < 20 && text.find_first_not_of("0123456789") == std::string::npos;
  }

  /** An authorised write to FAF's API: the answer's body ("" for 204), or why it failed (FAF's own words when given).
   */
  std::expected<std::string, std::string> ApiSend(
    const std::string& method,
    const std::string& url,
    const std::string& body
  )
  {
    const auto token = moho::ONLINE_AccessToken();
    if (!token) {
      return std::unexpected("sign in to FAF first (" + token.error() + ")");
    }
    platform::http::Call call;
    call.method = method;
    call.url = url;
    call.body = body;
    call.userAgent = UserAgent();
    call.headers = "Accept: application/vnd.api+json\r\nAuthorization: Bearer " + *token + "\r\n";
    if (!body.empty()) {
      call.headers += "Content-Type: application/vnd.api+json\r\n";
    }
    long status = 0;
    std::string answer;
    if (const auto sent = platform::http::Request(call, status, answer); !sent) {
      return std::unexpected("FAF's API didn't answer: " + sent.error());
    }
    if (status >= 200 && status < 300) {
      return answer;
    }
    std::string why = "FAF's API answered HTTP " + std::to_string(status);
    if (const auto parsed = ParseJson(answer); parsed) {
      if (
        const JsonNode* const errors = parsed->Get("errors");
        errors != nullptr && errors->kind == JsonNode::Kind::Array && !errors->items.empty()
      ) {
        const std::string detail = errors->items[0].String("detail");
        const std::string title = errors->items[0].String("title");
        if (!detail.empty() || !title.empty()) {
          why += ": " + (detail.empty() ? title : detail);
        }
      }
    }
    return std::unexpected(why);
  }

  /** The job of a review write: its answer as the job's data (an empty object for 204). */
  int ReviewJob(
    lua_State* const L,
    std::string method,
    std::string url,
    std::string body
  )
  {
    lua_pushnumber(L, static_cast<lua_Number>(StartJob("api", [method, url, body](Job& job) {
      const auto answer = ApiSend(method, url, body);
      if (!answer) {
        job.Fail(answer.error());
        return;
      }
      auto parsed =
        answer->empty() ? std::expected<JsonNode, std::string>(faf::online::JsonObject({})) : ParseJson(*answer);
      if (!parsed) {
        parsed = faf::online::JsonObject({});
      }
      LogLine(method + " " + url.substr(url.find("/data/")) + ": done");
      std::lock_guard<std::mutex> guard(job.lock);
      job.answer = std::move(*parsed);
    })));
    return 1;
  }

  /**
   * id, why = FafLibrary_SaveReview{kind=, subject=, review=, player=, score=, text=}: the player's review of a map,
   * mod or game ("map", "mod", "game"): a new one on version or game `subject` by `player` (their FAF id), or review
   * `review` changed. Score 1 to 5, text at most 2000 bytes.
   */
  int SaveReviewBody(
    lua_State* const L
  )
  {
    if (!lua_istable(L, 1)) {
      lua_pushnil(L);
      lua_pushstring(L, "FafLibrary_SaveReview takes a table");
      return 2;
    }
    const ReviewKind* const kind = FindReviewKind(TableString(L, 1, "kind"));
    const std::string subject = TableString(L, 1, "subject");
    const std::string review = TableString(L, 1, "review");
    const std::string player = TableString(L, 1, "player");
    const std::string text = TableString(L, 1, "text");
    lua_pushstring(L, "score");
    lua_gettable(L, 1);
    const int score = lua_isnumber(L, -1) ? static_cast<int>(lua_tonumber(L, -1)) : 0;
    lua_pop(L, 1);
    const char* why = nullptr;
    if (kind == nullptr) {
      why = "not a kind of review (map, mod, game)";
    } else if (score < 1 || score > 5) {
      why = "a review's score is 1 to 5";
    } else if (text.size() > 2000) {
      why = "the review's text is too long";
    } else if (review.empty() ? (!AllDigits(subject) || !AllDigits(player)) : !AllDigits(review)) {
      why = "the review names no version and player, or no review";
    }
    if (why != nullptr) {
      lua_pushnil(L);
      lua_pushstring(L, why);
      return 2;
    }
    using faf::online::JsonDigits;
    using faf::online::JsonNumber;
    using faf::online::JsonObject;
    using faf::online::JsonString;
    const auto attributes = JsonObject({{"score", JsonNumber(score)}, {"text", JsonString(text)}});
    if (review.empty()) {
      const std::string body = faf::online::ToJson(JsonObject(
        {{"data",
          JsonObject({
            {"type", JsonString(kind->review)},
            {"attributes", attributes},
            {"relationships",
             JsonObject(
               {{"player",
                 JsonObject({{"data", JsonObject({{"type", JsonString("player")}, {"id", JsonString(player)}})}})}}
             )},
          })}}
      ));
      return ReviewJob(L, "POST", moho::ONLINE_ApiBase() + "/data/" + kind->subject + "/" + subject + "/reviews", body);
    }
    const std::string body = faf::online::ToJson(JsonObject(
      {{"data",
        JsonObject({{"type", JsonString(kind->review)}, {"id", JsonString(review)}, {"attributes", attributes}})}}
    ));
    return ReviewJob(L, "PATCH", moho::ONLINE_ApiBase() + "/data/" + kind->review + "/" + review, body);
  }

  /** id, why = FafLibrary_DeleteReview{kind=, review=}: the player's review taken off FAF. */
  int DeleteReviewBody(
    lua_State* const L
  )
  {
    const ReviewKind* const kind = lua_istable(L, 1) ? FindReviewKind(TableString(L, 1, "kind")) : nullptr;
    const std::string review = lua_istable(L, 1) ? TableString(L, 1, "review") : "";
    if (kind == nullptr || !AllDigits(review)) {
      lua_pushnil(L);
      lua_pushstring(L, "FafLibrary_DeleteReview takes the kind and the review's id");
      return 2;
    }
    return ReviewJob(L, "DELETE", moho::ONLINE_ApiBase() + "/data/" + kind->review + "/" + review, "");
  }

  // ---------------------------------------------------------------------------------------------------------------
  // Reports: the player's report of another player to FAF's moderators (JSON:API moderationReport, as the FAF clients
  // write it: the reporter, the reported player, the description, and a game with the time in it when it was one).
  // Built here from those values only.

  /**
   * id, why = FafLibrary_Report{reporter=, player=, text=, game=, time=}: a report on FAF player `player` by
   * `reporter` (both FAF ids); text 10 to 4000 bytes; game (a replay id) optional, and then time ("12:30", the
   * incident's time in the game) is needed.
   */
  int ReportBody(
    lua_State* const L
  )
  {
    if (!lua_istable(L, 1)) {
      lua_pushnil(L);
      lua_pushstring(L, "FafLibrary_Report takes a table");
      return 2;
    }
    const std::string reporter = TableString(L, 1, "reporter");
    const std::string player = TableString(L, 1, "player");
    const std::string text = TableString(L, 1, "text");
    const std::string game = TableString(L, 1, "game");
    const std::string time = TableString(L, 1, "time");
    const char* why = nullptr;
    if (!AllDigits(reporter) || !AllDigits(player)) {
      why = "the report names no reporter or player";
    } else if (reporter == player) {
      why = "a player can't report themselves";
    } else if (text.size() < 10) {
      why = "describe what happened in 10 characters at least";
    } else if (text.size() > 4000) {
      why = "the description is longer than 4000 characters";
    } else if (!game.empty() && !AllDigits(game)) {
      why = "a replay id is a whole number";
    } else if (!game.empty() && time.empty()) {
      why = "give the time in the game it happened at";
    } else if (time.size() > 40) {
      why = "the time in the game is too long";
    }
    if (why != nullptr) {
      lua_pushnil(L);
      lua_pushstring(L, why);
      return 2;
    }
    using faf::online::JsonArray;
    using faf::online::JsonNode;
    using faf::online::JsonObject;
    using faf::online::JsonString;
    const auto Ref = [](const char* type, const std::string& id) {
      return JsonObject({{"type", JsonString(type)}, {"id", JsonString(id)}});
    };
    std::vector<std::pair<std::string, JsonNode>> relationships = {
      {"reporter", JsonObject({{"data", Ref("player", reporter)}})},
      {"reportedUsers", JsonObject({{"data", JsonArray({Ref("player", player)})}})},
    };
    if (!game.empty()) {
      relationships.push_back({"game", JsonObject({{"data", Ref("game", game)}})});
    }
    std::vector<std::pair<std::string, JsonNode>> attributes = {{"reportDescription", JsonString(text)}};
    if (!time.empty()) {
      // The attribute's own spelling, with a lower-case c.
      attributes.push_back({"gameIncidentTimecode", JsonString(time)});
    }
    const std::string body = faf::online::ToJson(JsonObject(
      {{"data",
        JsonObject({
          {"type", JsonString("moderationReport")},
          {"attributes", JsonObject(std::move(attributes))},
          {"relationships", JsonObject(std::move(relationships))},
        })}}
    ));
    return ReviewJob(L, "POST", moho::ONLINE_ApiBase() + "/data/moderationReport", body);
  }

  /** A JSON document anyone may read (no sign-in) as a job's data: `what` names the source in a failure. */
  int PublicJsonJob(
    lua_State* const L,
    std::string url,
    std::string what
  )
  {
    lua_pushnumber(L, static_cast<lua_Number>(StartJob("api", [url, what](Job& job) {
      platform::http::Call call;
      call.url = url;
      call.userAgent = UserAgent();
      call.headers = "Accept: application/json\r\n";
      long status = 0;
      std::string body;
      if (const auto sent = platform::http::Request(call, status, body); !sent) {
        job.Fail(what + " didn't answer: " + sent.error());
        return;
      }
      if (status != 200) {
        job.Fail(what + " answered HTTP " + std::to_string(status));
        return;
      }
      if (body.size() > 4u * 1024u * 1024u) {
        job.Fail(what + " sent more than 4 MB");
        return;
      }
      auto parsed = ParseJson(body);
      if (!parsed) {
        job.Fail(what + " answered with something that isn't JSON");
        return;
      }
      std::lock_guard<std::mutex> guard(job.lock);
      job.answer = std::move(*parsed);
    })));
    return 1;
  }

  /** An address from the environment (tests point it at a stand-in), else the given one. */
  std::string UrlOr(
    const char* const variable,
    const char* const fallback
  )
  {
    const char* const value = std::getenv(variable);
    return value != nullptr && value[0] != '\0' ? std::string(value) : std::string(fallback);
  }

  /**
   * id = FafLibrary_Releases(): this engine's releases on GitHub, newest first (GitHub's release list: tag_name,
   * name, body, html_url, prerelease, published_at), as the job's data. FAF_RELEASES_URL replaces the address.
   */
  int ReleasesBody(
    lua_State* const L
  )
  {
    return PublicJsonJob(
      L,
      UrlOr("FAF_RELEASES_URL", "https://api.github.com/repos/Draiget/scfa-re/releases?per_page=20"),
      "GitHub's release list"
    );
  }

  /**
   * id = FafLibrary_Events(): FAF's community events catalogue (the FAF Rust client's published calendar.json:
   * events = {{id, title, summary, category, origin, host, startsAt, endsAt, allDay, recurrence, recursUntil, links}},
   * submitUrl), as the job's data. FAF_EVENTS_CATALOGUE_URL replaces the address, as in that client.
   */
  int EventsBody(
    lua_State* const L
  )
  {
    std::string url = UrlOr(
      "FAF_EVENTS_CATALOGUE_URL", "https://raw.githubusercontent.com/FAForeverRustClient/events/main/calendar.json"
    );
    // The CDN keeps a copy for minutes; a changing query asks for the current one, as that client does.
    url += (url.find('?') == std::string::npos ? "?t=" : "&t=") + std::to_string(std::time(nullptr));
    return PublicJsonJob(L, url, "FAF's events catalogue");
  }

  /** A mod_info.lua's `uid = "..."`, or empty. */
  std::string ModInfoUid(
    const std::string& text
  )
  {
    for (std::size_t at = text.find("uid"); at != std::string::npos; at = text.find("uid", at + 3)) {
      if (at > 0 && (std::isalnum(static_cast<unsigned char>(text[at - 1])) != 0 || text[at - 1] == '_')) {
        continue; // part of another name
      }
      std::size_t next = text.find_first_not_of(" \t", at + 3);
      if (next == std::string::npos || text[next] != '=') {
        continue;
      }
      next = text.find_first_not_of(" \t", next + 1);
      if (next == std::string::npos || (text[next] != '"' && text[next] != '\'')) {
        continue;
      }
      const std::size_t end = text.find(text[next], next + 1);
      if (end != std::string::npos) {
        return text.substr(next + 1, end - next - 1);
      }
    }
    return {};
  }

  /** A folder name a mod may have: no path parts, no dots alone. */
  bool SafeFolderName(
    const std::string& name
  )
  {
    return !name.empty() && name != "." && name != ".." && name.find_first_of("/\\:") == std::string::npos;
  }

  /**
   * The mod archive's files written into `modsFolder/<its one top folder>`, replacing what an older version left
   * there; the folder's name, or why not: not exactly one top folder, a path that would leave it, no mod_info.lua, or
   * another uid than `uid` (when given).
   */
  std::expected<std::string, std::string> InstallModZip(
    const std::string& zip,
    const std::string& uid,
    const std::filesystem::path& modsFolder
  )
  {
    auto entries = ReadZip(zip);
    if (!entries) {
      return std::unexpected(entries.error());
    }
    std::string root;
    for (const ZipEntry& entry : *entries) {
      std::string name = entry.name;
      for (char& c : name) {
        c = c == '\\' ? '/' : c;
      }
      const std::string top = name.substr(0, name.find('/'));
      if (top.empty() || top == name) {
        return std::unexpected("the archive's files aren't in one folder (" + entry.name + ")");
      }
      if (root.empty()) {
        root = top;
      } else if (Lower(top) != Lower(root)) {
        return std::unexpected("the archive holds more than one folder (" + root + ", " + top + ")");
      }
      if (name.find("/../") != std::string::npos || name.ends_with("/..") || name.find(':') != std::string::npos) {
        return std::unexpected("the archive's entry " + entry.name + " would leave the mod's folder");
      }
    }
    if (!SafeFolderName(root)) {
      return std::unexpected(std::string("the archive's folder has no usable name"));
    }
    const ZipEntry* info = nullptr;
    for (const ZipEntry& entry : *entries) {
      if (Lower(entry.name) == Lower(root + "/mod_info.lua")) {
        info = &entry;
      }
    }
    if (info == nullptr) {
      return std::unexpected("the archive has no " + root + "/mod_info.lua");
    }
    if (const std::string found = ModInfoUid(info->data); !uid.empty() && found != uid) {
      return std::unexpected("the archive is another version of the mod (uid " + found + ", wanted " + uid + ")");
    }
    std::error_code error;
    std::filesystem::create_directories(modsFolder, error);
    const std::filesystem::path part = modsFolder / (root + ".part");
    std::filesystem::remove_all(part, error);
    for (const ZipEntry& entry : *entries) {
      std::string name = entry.name;
      for (char& c : name) {
        c = c == '\\' ? '/' : c;
      }
      if (name.ends_with("/")) {
        continue; // a folder
      }
      const std::filesystem::path file = part / std::filesystem::path(name.substr(root.size() + 1));
      std::filesystem::create_directories(file.parent_path(), error);
      std::ofstream out(file, std::ios::binary | std::ios::trunc);
      out.write(entry.data.data(), static_cast<std::streamsize>(entry.data.size()));
      if (!out) {
        std::filesystem::remove_all(part, error);
        return std::unexpected("can't write " + file.string());
      }
    }
    const std::filesystem::path target = modsFolder / root;
    std::filesystem::remove_all(target, error); // an older version
    std::filesystem::rename(part, target, error);
    if (error) {
      std::filesystem::remove_all(part, error);
      return std::unexpected("can't write " + target.string());
    }
    return root;
  }

  /** id = FafLibrary_InstallMod{url=, uid=}: the mod into the vault's mods folder, usable at once (mounted). */
  int InstallModBody(
    lua_State* const L
  )
  {
    const std::string url = lua_istable(L, 1) ? TableString(L, 1, "url") : "";
    const std::string uid = lua_istable(L, 1) ? TableString(L, 1, "uid") : "";
    if (!AllowedModUrl(url)) {
      lua_pushnil(L);
      lua_pushstring(L, "mods download only from FAF's content server");
      return 2;
    }
    const std::filesystem::path mods = ModsFolder();
    lua_pushnumber(L, static_cast<lua_Number>(StartJob("mod", [url, uid, mods](Job& job) {
      platform::http::Call call;
      call.url = url;
      call.userAgent = UserAgent();
      long status = 0;
      std::string body;
      if (const auto sent = platform::http::Request(call, status, body, &job.received, &job.total); !sent) {
        job.Fail("the mod didn't download: " + sent.error());
        return;
      }
      if (status != 200) {
        job.Fail("FAF's content server answered HTTP " + std::to_string(status));
        return;
      }
      const auto installed = InstallModZip(body, uid, mods);
      if (!installed) {
        job.Fail(installed.error());
        return;
      }
      LogLine("installed the mod " + *installed + " into " + mods.string());
      std::lock_guard<std::mutex> guard(job.lock);
      job.path = (mods / *installed).string();
      job.message = *installed;
    })));
    return 1;
  }

  /**
   * FAF's userInit.lua keeps every DiskGetFileInfo answer for the session, "no such file" included, so a folder mounted
   * or removed later would keep its old answer. The engine's hook on that file (fafengine/lua/userInit.lua) keeps the
   * same cache with DiskForgetFileInfo() to empty it; called after every mount change made here.
   */
  void ForgetFileInfo(
    lua_State* const L
  )
  {
    lua_pushstring(L, "DiskForgetFileInfo");
    lua_rawget(L, LUA_GLOBALSINDEX);
    if (!lua_isfunction(L, -1)) {
      lua_pop(L, 1);
      return;
    }
    lua_call(L, 0, 0); // it only empties a table (this Lua has no lua_pcall: errors throw)
  }

  /**
   * ok, why = FafLibrary_RemoveMod(folder): the mod's folder (its name under the vault's mods folder) out of the file
   * system and off the disk.
   */
  int RemoveModBody(
    lua_State* const L
  )
  {
    const std::string folder = lua_isstring(L, 1) ? lua_tostring(L, 1) : "";
    if (!SafeFolderName(folder)) {
      lua_pushboolean(L, 0);
      lua_pushstring(L, "not a mod's folder");
      return 2;
    }
    const std::filesystem::path path = ModsFolder() / folder;
    std::error_code error;
    if (!std::filesystem::is_directory(path, error)) {
      lua_pushboolean(L, 0);
      lua_pushstring(L, ("no mod folder " + path.string()).c_str());
      return 2;
    }
    (void)moho::DISK_UnmountNow(("/mods/" + folder).c_str());
    ForgetFileInfo(L);
    std::filesystem::remove_all(path, error);
    if (error) {
      lua_pushboolean(L, 0);
      lua_pushstring(L, ("can't delete " + path.string() + ": " + error.message()).c_str());
      return 2;
    }
    LogLine("removed the mod " + path.string());
    lua_pushboolean(L, 1);
    lua_pushnil(L);
    return 2;
  }

  // ---------------------------------------------------------------------------------------------------------------
  // Maps from FAF's vault: the same archive rules as mods (one folder, nothing leaving it), a map's folder holding its
  // <name>_scenario.lua; installed into the vault's maps folder and mounted at /maps/<folder>.

  std::filesystem::path MapsFolder()
  {
    return VaultFolder() / "maps";
  }

  /** The map archive `zip` unpacked into `mapsFolder` (an older copy replaced): its folder's name, or why not. */
  std::expected<std::string, std::string> InstallMapZip(
    const std::string& zip,
    const std::filesystem::path& mapsFolder
  )
  {
    auto entries = ReadZip(zip);
    if (!entries) {
      return std::unexpected(entries.error());
    }
    std::string root;
    bool scenario = false;
    for (const ZipEntry& entry : *entries) {
      std::string name = entry.name;
      for (char& c : name) {
        c = c == '\\' ? '/' : c;
      }
      const std::string top = name.substr(0, name.find('/'));
      if (top.empty() || top == name) {
        return std::unexpected("the archive's files aren't in one folder (" + entry.name + ")");
      }
      if (root.empty()) {
        root = top;
      } else if (Lower(top) != Lower(root)) {
        return std::unexpected("the archive holds more than one folder (" + root + ", " + top + ")");
      }
      if (name.find("/../") != std::string::npos || name.ends_with("/..") || name.find(':') != std::string::npos) {
        return std::unexpected("the archive's entry " + entry.name + " would leave the map's folder");
      }
      scenario = scenario || (Lower(name).ends_with("_scenario.lua") && name.rfind('/') == root.size());
    }
    if (!SafeFolderName(root)) {
      return std::unexpected(std::string("the archive's folder has no usable name"));
    }
    if (!scenario) {
      return std::unexpected("the archive has no " + root + "/<name>_scenario.lua");
    }
    std::error_code error;
    std::filesystem::create_directories(mapsFolder, error);
    const std::filesystem::path part = mapsFolder / (root + ".part");
    std::filesystem::remove_all(part, error);
    for (const ZipEntry& entry : *entries) {
      std::string name = entry.name;
      for (char& c : name) {
        c = c == '\\' ? '/' : c;
      }
      if (name.ends_with("/")) {
        continue;
      }
      const std::filesystem::path file = part / std::filesystem::path(name.substr(root.size() + 1));
      std::filesystem::create_directories(file.parent_path(), error);
      std::ofstream out(file, std::ios::binary | std::ios::trunc);
      out.write(entry.data.data(), static_cast<std::streamsize>(entry.data.size()));
      if (!out) {
        std::filesystem::remove_all(part, error);
        return std::unexpected("can't write " + file.string());
      }
    }
    const std::filesystem::path target = mapsFolder / root;
    std::filesystem::remove_all(target, error);
    std::filesystem::rename(part, target, error);
    if (error) {
      std::filesystem::remove_all(part, error);
      return std::unexpected("can't write " + target.string());
    }
    return root;
  }

  /** id = FafLibrary_InstallMap{url=}: a map from FAF's content server into the vault's maps folder, usable at once. */
  int InstallMapBody(
    lua_State* const L
  )
  {
    const std::string url = lua_istable(L, 1) ? TableString(L, 1, "url") : "";
    if (!AllowedModUrl(url)) {
      lua_pushnil(L);
      lua_pushstring(L, "maps download only from FAF's content server");
      return 2;
    }
    const std::filesystem::path maps = MapsFolder();
    lua_pushnumber(L, static_cast<lua_Number>(StartJob("map", [url, maps](Job& job) {
      platform::http::Call call;
      call.url = url;
      call.userAgent = UserAgent();
      long status = 0;
      std::string body;
      if (const auto sent = platform::http::Request(call, status, body, &job.received, &job.total); !sent) {
        job.Fail("the map didn't download: " + sent.error());
        return;
      }
      if (status != 200) {
        job.Fail("FAF's content server answered HTTP " + std::to_string(status));
        return;
      }
      const auto installed = InstallMapZip(body, maps);
      if (!installed) {
        job.Fail(installed.error());
        return;
      }
      LogLine("installed the map " + *installed + " into " + maps.string());
      std::lock_guard<std::mutex> guard(job.lock);
      job.path = (maps / *installed).string();
      job.message = *installed;
    })));
    return 1;
  }

  /** ok, why = FafLibrary_RemoveMap(folder): a vault map out of the file system and off the disk. */
  int RemoveMapBody(
    lua_State* const L
  )
  {
    const std::string folder = lua_isstring(L, 1) ? lua_tostring(L, 1) : "";
    if (!SafeFolderName(folder)) {
      lua_pushboolean(L, 0);
      lua_pushstring(L, "not a map's folder");
      return 2;
    }
    const std::filesystem::path path = MapsFolder() / folder;
    std::error_code error;
    if (!std::filesystem::is_directory(path, error)) {
      lua_pushboolean(L, 0);
      lua_pushstring(L, ("no map folder " + path.string()).c_str());
      return 2;
    }
    (void)moho::DISK_UnmountNow(("/maps/" + folder).c_str());
    ForgetFileInfo(L);
    std::filesystem::remove_all(path, error);
    if (error) {
      lua_pushboolean(L, 0);
      lua_pushstring(L, ("can't delete " + path.string() + ": " + error.message()).c_str());
      return 2;
    }
    LogLine("removed the map " + path.string());
    lua_pushboolean(L, 1);
    lua_pushnil(L);
    return 2;
  }

  // ---------------------------------------------------------------------------------------------------------------
  // Uploads: a map or mod folder of the vault zipped (the folder itself as the archive's top, as FAF's client zips
  // them) and sent to FAF's vault: a map in one multipart request (/maps/upload with its ranked flag), a mod in three
  // (the API's signed upload address from /mods/upload/start, the archive put there, /mods/upload/complete), as the FAF
  // client sends them.

  /** The files under `folder` as zip entries named "<folder's name>/...", folders ending in "/"; or why not. */
  std::expected<std::vector<faf::online::ZipEntry>, std::string> FolderEntries(
    const std::filesystem::path& folder
  )
  {
    constexpr std::uintmax_t kLimit = 512ull * 1024 * 1024;
    std::vector<faf::online::ZipEntry> entries;
    const std::string top = reinterpret_cast<const char*>(folder.filename().generic_u8string().c_str());
    entries.push_back({top + "/", ""});
    std::uintmax_t total = 0;
    std::error_code error;
    for (auto it = std::filesystem::recursive_directory_iterator(folder, error);
         !error && it != std::filesystem::recursive_directory_iterator();
         it.increment(error)) {
      if (it->is_symlink(error)) {
        continue; // nothing outside the folder goes along
      }
      const std::u8string relative = std::filesystem::relative(it->path(), folder, error).generic_u8string();
      const std::string name = top + "/" + reinterpret_cast<const char*>(relative.c_str());
      if (it->is_directory(error)) {
        entries.push_back({name + "/", ""});
        continue;
      }
      total += it->file_size(error);
      if (total > kLimit) {
        return std::unexpected(std::string("the folder is over 512 MB"));
      }
      std::ifstream in(it->path(), std::ios::binary);
      std::string data((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
      if (!in && !in.eof()) {
        return std::unexpected("can't read " + it->path().string());
      }
      entries.push_back({name, std::move(data)});
    }
    if (error) {
      return std::unexpected("can't read " + folder.string() + ": " + error.message());
    }
    return entries;
  }

  /** A request to FAF's API with the player's token (`contentType` and `body` when it sends one); the answer or why
   * not. */
  std::expected<std::string, std::string> ApiCall(
    const std::string& method,
    const std::string& url,
    const std::string& contentType,
    const std::string& body,
    const bool signedIn = true
  )
  {
    platform::http::Call call;
    call.method = method;
    call.url = url;
    call.body = body;
    call.userAgent = UserAgent();
    call.headers = "Accept: application/json\r\n";
    if (signedIn) {
      const auto token = moho::ONLINE_AccessToken();
      if (!token) {
        return std::unexpected("sign in to FAF first (" + token.error() + ")");
      }
      call.headers += "Authorization: Bearer " + *token + "\r\n";
    }
    if (!contentType.empty()) {
      call.headers += "Content-Type: " + contentType + "\r\n";
    }
    long status = 0;
    std::string answer;
    if (const auto sent = platform::http::Request(call, status, answer); !sent) {
      return std::unexpected("no answer: " + sent.error());
    }
    if (status >= 200 && status < 300) {
      return answer;
    }
    std::string why = "HTTP " + std::to_string(status);
    if (const auto parsed = ParseJson(answer); parsed) {
      if (
        const JsonNode* const errors = parsed->Get("errors");
        errors != nullptr && errors->kind == JsonNode::Kind::Array && !errors->items.empty()
      ) {
        const std::string detail = errors->items[0].String("detail");
        const std::string title = errors->items[0].String("title");
        if (!detail.empty() || !title.empty()) {
          why += ": " + (detail.empty() ? title : detail);
        }
      }
    }
    return std::unexpected(why);
  }

  /**
   * id, why = FafLibrary_Upload{kind = "map" or "mod", folder = <its name in the vault's maps or mods folder>,
   * ranked = <a map's ranked flag>}: the folder zipped and sent to FAF's vault under the signed-in player.
   */
  int UploadBody(
    lua_State* const L
  )
  {
    const std::string kind = lua_istable(L, 1) ? TableString(L, 1, "kind") : "";
    const std::string folder = lua_istable(L, 1) ? TableString(L, 1, "folder") : "";
    bool ranked = false;
    if (lua_istable(L, 1)) {
      lua_pushstring(L, "ranked");
      lua_gettable(L, 1);
      ranked = lua_toboolean(L, -1) != 0;
      lua_pop(L, 1);
    }
    std::error_code error;
    const std::filesystem::path path = (kind == "map" ? MapsFolder() : ModsFolder()) / folder;
    if ((kind != "map" && kind != "mod") || !SafeFolderName(folder) || !std::filesystem::is_directory(path, error)) {
      lua_pushnil(L);
      lua_pushstring(L, ("no " + kind + " folder " + folder + " in the vault").c_str());
      return 2;
    }
    const std::string api = moho::ONLINE_ApiBase();
    lua_pushnumber(L, static_cast<lua_Number>(StartJob("api", [kind, folder, path, ranked, api](Job& job) {
      const auto entries = FolderEntries(path);
      if (!entries) {
        job.Fail(entries.error());
        return;
      }
      const auto zip = faf::online::WriteZip(*entries);
      if (!zip) {
        job.Fail(zip.error());
        return;
      }
      job.total = static_cast<std::uint64_t>(zip->size());
      if (kind == "map") {
        const std::string boundary =
          "fafre" + std::to_string(std::chrono::steady_clock::now().time_since_epoch().count());
        std::string body = "--" + boundary + "\r\nContent-Disposition: form-data; name=\"file\"; filename=\"" + folder +
          ".zip\"\r\nContent-Type: application/zip\r\n\r\n";
        body += *zip;
        body += "\r\n--" + boundary +
          "\r\nContent-Disposition: form-data; name=\"metadata\"\r\n"
          "Content-Type: application/json\r\n\r\n";
        body += ranked ? "{\"isRanked\":true}" : "{\"isRanked\":false}";
        body += "\r\n--" + boundary + "--\r\n";
        const auto sent = ApiCall("POST", api + "/maps/upload", "multipart/form-data; boundary=" + boundary, body);
        if (!sent) {
          job.Fail("FAF's vault refused the map: " + sent.error());
          return;
        }
      } else {
        const auto start = ApiCall("GET", api + "/mods/upload/start", "", "");
        const auto address =
          start ? ParseJson(*start) : std::expected<JsonNode, std::string>(std::unexpected(start.error()));
        const std::string url = address ? address->String("uploadUrl") : "";
        const std::string requestId = address ? address->String("requestId") : "";
        if (url.rfind("https://", 0) != 0 && url.rfind("http://", 0) != 0) {
          job.Fail(
            "FAF's vault gave no upload address: " + (start ? std::string("its answer has none") : start.error())
          );
          return;
        }
        if (const auto put = ApiCall("PUT", url, "application/zip", *zip, false); !put) {
          job.Fail("the mod's archive didn't upload: " + put.error());
          return;
        }
        using faf::online::JsonObject;
        using faf::online::JsonString;
        const std::string complete = faf::online::ToJson(JsonObject({{"requestId", JsonString(requestId)}}));
        if (const auto done = ApiCall("POST", api + "/mods/upload/complete", "application/json", complete); !done) {
          job.Fail("FAF's vault didn't take the mod: " + done.error());
          return;
        }
      }
      job.received = job.total.load();
      LogLine("uploaded the " + kind + " " + folder + " (" + std::to_string(zip->size()) + " bytes)");
      std::lock_guard<std::mutex> guard(job.lock);
      job.message = folder;
      job.answer = faf::online::JsonObject({});
    })));
    return 1;
  }

  /** text FafLibrary_ModsFolder(): the vault's mods folder on disk. */
  int ModsFolderBody(
    lua_State* const L
  )
  {
    lua_pushstring(L, ModsFolder().string().c_str());
    return 1;
  }

  // ---------------------------------------------------------------------------------------------------------------
  // Pictures from FAF's content server (map thumbnails): kept on disk beside the vault and read through the game's
  // files. The file system indexes a folder when it mounts it, so new pictures are mounted again in one go
  // (FafLibrary_MountThumbnails) once a page's downloads are in.

  constexpr const char* kThumbnailMount = "/fafre_thumbnails";
  constexpr std::size_t kThumbnailMaxBytes = 4 * 1024 * 1024;
  bool gThumbnailsMounted = false;      ///< the folder is in the game's file system (main thread)
  std::set<std::string> gThumbnailsNew; ///< files written since it was mounted (main thread)

  std::filesystem::path ThumbnailFolder()
  {
    return VaultFolder() / "cache" / "thumbnails";
  }

  /** A picture's file name: a hash of its address, with the address's own extension (.png when it has none). */
  std::string ThumbnailName(
    const std::string& url
  )
  {
    std::uint64_t hash = 1469598103934665603ULL;
    for (const unsigned char c : url) {
      hash = (hash ^ c) * 1099511628211ULL;
    }
    std::string extension = ".png";
    if (const auto dot = url.find_last_of('.'); dot != std::string::npos && url.find('/', dot) == std::string::npos) {
      const std::string own = Lower(url.substr(dot));
      if (own == ".jpg" || own == ".jpeg" || own == ".dds") {
        extension = own;
      }
    }
    char text[24];
    (void)std::snprintf(text, sizeof(text), "%016llx", static_cast<unsigned long long>(hash));
    return text + extension;
  }

  /** Mounts the pictures' folder (again, when pictures came since): true when the game can read every one. */
  bool MountThumbnails()
  {
    if (gThumbnailsMounted && gThumbnailsNew.empty()) {
      return true;
    }
    std::error_code error;
    std::filesystem::create_directories(ThumbnailFolder(), error);
    if (gThumbnailsMounted) {
      (void)moho::DISK_UnmountNow(kThumbnailMount);
    }
    gThumbnailsMounted = moho::DISK_MountDirectoryNow(ThumbnailFolder(), kThumbnailMount);
    if (gThumbnailsMounted) {
      gThumbnailsNew.clear();
    }
    return gThumbnailsMounted;
  }

  /**
   * path, id = FafLibrary_Thumbnail(url): a picture from FAF's content server. path (a path of the game's files) when
   * it can be shown now; else id, the download bringing it (FafLibrary_Job), or 0 when it is on disk and waits for
   * FafLibrary_MountThumbnails. nil, nil for an address that isn't FAF's content server.
   */
  int ThumbnailBody(
    lua_State* const L
  )
  {
    const std::string url = lua_isstring(L, 1) ? lua_tostring(L, 1) : "";
    if (url.empty() || !AllowedPictureUrl(url)) {
      lua_pushnil(L);
      lua_pushnil(L);
      return 2;
    }
    const std::string name = ThumbnailName(url);
    const std::filesystem::path file = ThumbnailFolder() / name;
    std::error_code error;
    const auto size = std::filesystem::file_size(file, error);
    if (!error && size > 0) {
      if (!gThumbnailsMounted && gThumbnailsNew.empty()) {
        (void)MountThumbnails(); // the first picture this run: the folder as it is on disk
      }
      if (gThumbnailsMounted && !gThumbnailsNew.contains(name)) {
        lua_pushstring(L, (std::string(kThumbnailMount) + "/" + name).c_str());
        lua_pushnil(L);
        return 2;
      }
      lua_pushnil(L);
      lua_pushnumber(L, 0);
      return 2;
    }
    lua_pushnil(L);
    lua_pushnumber(L, static_cast<lua_Number>(StartJob("thumbnail", [url, file, name](Job& job) {
      platform::http::Call call;
      call.url = url;
      call.userAgent = UserAgent();
      long status = 0;
      std::string body;
      if (const auto sent = platform::http::Request(call, status, body, &job.received, &job.total); !sent) {
        job.Fail("the picture didn't download: " + sent.error());
        return;
      }
      if (status != 200 || body.empty() || body.size() > kThumbnailMaxBytes) {
        job.Fail("the content server answered HTTP " + std::to_string(status));
        return;
      }
      if (const auto written = WriteWhole(file, body); !written) {
        job.Fail(written.error());
        return;
      }
      std::lock_guard<std::mutex> guard(job.lock);
      job.path = name;
    })));
    return 2;
  }

  /** bool FafLibrary_MountThumbnails(): the pictures downloaded since the last call readable by the game. */
  int MountThumbnailsBody(
    lua_State* const L
  )
  {
    const bool mounted = MountThumbnails();
    ForgetFileInfo(L);
    lua_pushboolean(L, mounted ? 1 : 0);
    return 1;
  }

  /**
   * id = FafLibrary_Api(path[, query]): GET <FAF's API><path>?<query> with the player's sign-in, the answer read as
   * JSON; FafLibrary_Job gives it as `data` (objects as tables, arrays from 1, null as nil). query is a table of
   * parameter -> text (filter, include, sort, page[size], ...), encoded here. Only FAF's data and the player's own
   * record: the path starts with /data/ or is /me, and carries no query of its own.
   */
  int ApiBody(
    lua_State* const L
  )
  {
    const std::string path = lua_isstring(L, 1) ? lua_tostring(L, 1) : "";
    if (
      // FAF's data, the signed-in player, and FAF's tournaments (the API's Challonge proxy, as the FAF client reads
      // them).
      (path.rfind("/data/", 0) != 0 && path != "/me" && path != "/challonge/v1/tournaments.json") ||
      path.find("..") != std::string::npos || path.find_first_of(" \r\n?#%&") != std::string::npos
    ) {
      lua_pushnil(L);
      lua_pushstring(L, "not a path of FAF's data");
      return 2;
    }
    std::vector<std::pair<std::string, std::string>> parameters;
    if (lua_istable(L, 2)) {
      lua_pushnil(L);
      while (lua_next(L, 2) != 0) {
        if (lua_type(L, -2) == LUA_TSTRING && lua_isstring(L, -1)) {
          parameters.emplace_back(lua_tostring(L, -2), lua_tostring(L, -1));
        }
        lua_pop(L, 1);
      }
      std::sort(parameters.begin(), parameters.end());
    }
    const std::string url = faf::online::ApiUrl(moho::ONLINE_ApiBase(), path, parameters);
    lua_pushnumber(L, static_cast<lua_Number>(StartJob("api", [url](Job& job) {
      const auto body = ApiGet(url);
      if (!body) {
        job.Fail(body.error());
        return;
      }
      auto parsed = ParseJson(*body);
      if (!parsed) {
        job.Fail("FAF's API answered with something that isn't JSON");
        return;
      }
      std::lock_guard<std::mutex> guard(job.lock);
      job.answer = std::move(*parsed);
    })));
    return 1;
  }

  /** A JSON value as a Lua value on the stack: objects as tables, arrays from 1, null as nil. */
  void PushJson(
    lua_State* const L,
    const JsonNode& node,
    const int depth
  )
  {
    if (depth > 40) {
      lua_pushnil(L);
      return;
    }
    switch (node.kind) {
    case JsonNode::Kind::Bool:
      lua_pushboolean(L, node.boolean ? 1 : 0);
      return;
    case JsonNode::Kind::Number:
      lua_pushnumber(L, static_cast<lua_Number>(node.number));
      return;
    case JsonNode::Kind::String:
      lua_pushstring(L, node.text.c_str());
      return;
    case JsonNode::Kind::Array: {
      lua_newtable(L);
      int index = 1;
      for (const JsonNode& item : node.items) {
        PushJson(L, item, depth + 1);
        lua_rawseti(L, -2, index++);
      }
      return;
    }
    case JsonNode::Kind::Object:
      lua_newtable(L);
      for (const auto& [key, value] : node.members) {
        if (value.kind == JsonNode::Kind::Null) {
          continue;
        }
        lua_pushstring(L, key.c_str());
        PushJson(L, value, depth + 1);
        lua_rawset(L, -3);
      }
      return;
    default:
      lua_pushnil(L);
      return;
    }
  }

  /** id = FafLibrary_SearchMods{name=, author=, type=, recommended=, sort=, page=, pageSize=}. */
  int SearchModsBody(
    lua_State* const L
  )
  {
    ModQuery query;
    if (lua_istable(L, 1)) {
      query.name = TableString(L, 1, "name");
      query.author = TableString(L, 1, "author");
      query.type = TableString(L, 1, "type");
      query.recommendedOnly = TableBool(L, 1, "recommended");
      if (const std::string sort = TableString(L, 1, "sort"); !sort.empty()) {
        query.sort = sort;
      }
      query.page = static_cast<int>(TableNumber(L, 1, "page", 1));
      query.pageSize = static_cast<int>(TableNumber(L, 1, "pageSize", 36));
    }
    const std::string url = ModSearchUrl(moho::ONLINE_ApiBase(), query);
    lua_pushnumber(L, static_cast<lua_Number>(StartJob("mods", [url](Job& job) {
      const auto body = ApiGet(url);
      if (!body) {
        job.Fail(body.error());
        return;
      }
      VaultPage page;
      auto rows = ReadModPage(*body, &page);
      if (!rows) {
        job.Fail(rows.error());
        return;
      }
      std::lock_guard<std::mutex> guard(job.lock);
      job.page = page;
      job.mods = std::move(*rows);
    })));
    return 1;
  }

  void PushReplayRows(
    lua_State* const L,
    const std::vector<VaultReplay>& rows
  )
  {
    lua_pushstring(L, "items");
    lua_newtable(L);
    int index = 1;
    for (const VaultReplay& row : rows) {
      lua_newtable(L);
      SetField(L, "id", row.id);
      SetField(L, "title", row.title);
      SetField(L, "map", Lower(row.mapFolder));
      SetField(L, "mapName", row.mapName);
      SetField(L, "featuredMod", row.featuredMod);
      SetField(L, "startTime", row.startTime);
      SetField(L, "endTime", row.endTime);
      SetField(L, "wallSeconds", row.wallSeconds);
      SetField(L, "seconds", row.seconds);
      SetBool(L, "available", row.replayAvailable);
      SetField(L, "validity", row.validity);
      SetField(L, "reviewScore", row.reviewScore);
      SetField(L, "reviews", static_cast<double>(row.reviews));
      lua_pushstring(L, "players");
      lua_newtable(L);
      int playerIndex = 1;
      for (const VaultReplayPlayer& player : row.players) {
        lua_newtable(L);
        SetField(L, "name", player.login);
        SetField(L, "team", static_cast<double>(player.team));
        SetField(L, "faction", player.faction);
        SetField(L, "rating", static_cast<double>(player.rating));
        SetBool(L, "rated", player.rated);
        SetField(L, "ratingAfter", static_cast<double>(player.ratingAfter));
        SetBool(L, "changed", player.changed);
        SetField(L, "result", player.result);
        SetField(L, "score", player.score);
        lua_rawseti(L, -2, playerIndex++);
      }
      lua_rawset(L, -3);
      lua_rawseti(L, -2, index++);
    }
    lua_rawset(L, -3);
  }

  void PushModRows(
    lua_State* const L,
    const std::vector<VaultMod>& rows
  )
  {
    lua_pushstring(L, "items");
    lua_newtable(L);
    int index = 1;
    for (const VaultMod& row : rows) {
      lua_newtable(L);
      SetField(L, "id", row.id);
      SetField(L, "name", row.name);
      SetField(L, "author", row.author);
      SetField(L, "uploader", row.uploader);
      SetBool(L, "recommended", row.recommended);
      SetField(L, "uid", row.uid);
      SetField(L, "version", row.version);
      SetField(L, "description", row.description);
      SetField(L, "type", row.type);
      SetBool(L, "ranked", row.ranked);
      SetField(L, "downloadUrl", row.downloadUrl);
      SetField(L, "thumbnailUrl", row.thumbnailUrl);
      SetField(L, "updateTime", row.updateTime);
      SetField(L, "reviewScore", row.reviewScore);
      SetField(L, "reviews", static_cast<double>(row.reviews));
      lua_rawseti(L, -2, index++);
    }
    lua_rawset(L, -3);
  }

  /**
   * table|nil FafLibrary_Job(id): {kind, state ("working", "done", "failed"), message, received, total, path, items,
   * totalPages, totalRecords}. A finished job is answered once, then forgotten; nil for one that isn't known.
   */
  int JobBody(
    lua_State* const L
  )
  {
    const int id = lua_isnumber(L, 1) ? static_cast<int>(lua_tonumber(L, 1)) : 0;
    std::shared_ptr<Job> job;
    {
      std::lock_guard<std::mutex> guard(gJobsLock);
      const auto found = gJobs.find(id);
      if (found == gJobs.end()) {
        lua_pushnil(L);
        return 1;
      }
      job = found->second;
    }
    const bool done = job->done.load();
    lua_newtable(L);
    SetField(L, "kind", job->kind);
    SetField(L, "received", static_cast<double>(job->received.load()));
    SetField(L, "total", static_cast<double>(job->total.load()));
    if (!done) {
      SetField(L, "state", "working");
      return 1;
    }
    if (job->thread.joinable()) {
      job->thread.join();
    }
    if (job->kind == "thumbnail" && !job->failed && !job->mounted) {
      job->mounted = true;
      std::lock_guard<std::mutex> guard(job->lock);
      gThumbnailsNew.insert(job->path); // readable after the next FafLibrary_MountThumbnails
    }
    if (job->kind == "map" && !job->failed && !job->mounted) {
      job->mounted = true;
      const std::string folder = job->message;
      (void)moho::DISK_UnmountNow(("/maps/" + folder).c_str()); // an older version's
      if (!moho::DISK_MountDirectoryNow(std::filesystem::path(job->path), ("/maps/" + folder).c_str())) {
        job->Fail("installed, but the game couldn't read it yet: it is there after a restart");
      }
      ForgetFileInfo(L);
    }
    if (job->kind == "mod" && !job->failed && !job->mounted) {
      job->mounted = true;
      const std::string folder = job->message;
      (void)moho::DISK_UnmountNow(("/mods/" + folder).c_str()); // an older version's
      if (!moho::DISK_MountDirectoryNow(std::filesystem::path(job->path), ("/mods/" + folder).c_str())) {
        job->Fail("installed, but the game couldn't read it yet: it is there after a restart");
      }
      ForgetFileInfo(L);
    }
    {
      std::lock_guard<std::mutex> guard(job->lock);
      SetField(L, "state", job->failed ? "failed" : "done");
      SetField(L, "message", job->message);
      SetField(L, "path", job->path);
      SetField(L, "totalPages", static_cast<double>(job->page.totalPages));
      SetField(L, "totalRecords", static_cast<double>(job->page.totalRecords));
      if (job->kind == "replays") {
        PushReplayRows(L, job->replays);
      } else if (job->kind == "mods") {
        PushModRows(L, job->mods);
      } else if (job->kind == "api" && !job->failed) {
        lua_pushstring(L, "data");
        PushJson(L, job->answer, 0);
        lua_rawset(L, -3);
      }
    }
    std::lock_guard<std::mutex> guard(gJobsLock);
    gJobs.erase(id);
    return 1;
  }

  template <int (*Body)(lua_State*)>
  int Binding(
    lua_State* const luaContext
  )
  {
    LuaPlus::LuaState* const state = moho::SCR_ResolveBindingState(luaContext);
    return state != nullptr && state->m_state != nullptr ? Body(state->m_state) : 0;
  }

  void RegisterLibraryBindings()
  {
    static moho::CScrLuaBinder localTime(
      moho::SCR_UserLuaInitSet(),
      "FafLibrary_LocalTime",
      &Binding<&LocalTimeBody>,
      nullptr,
      "<global>",
      "string FafLibrary_LocalTime(when) - seconds since 1970 or an ISO time, as this computer's local time."
    );
    static moho::CScrLuaBinder utcDate(
      moho::SCR_UserLuaInitSet(),
      "FafLibrary_UtcDate",
      &Binding<&UtcDateBody>,
      nullptr,
      "<global>",
      "string FafLibrary_UtcDate(daysAgo) - the UTC date that many days back, as 2026-10-28T00:00:00Z."
    );
    static moho::CScrLuaBinder utcNow(
      moho::SCR_UserLuaInitSet(),
      "FafLibrary_UtcNow",
      &Binding<&UtcNowBody>,
      nullptr,
      "<global>",
      "number FafLibrary_UtcNow() - seconds since 1970, UTC."
    );
    static moho::CScrLuaBinder news(
      moho::SCR_UserLuaInitSet(),
      "FafLibrary_News",
      &Binding<&NewsBody>,
      nullptr,
      "<global>",
      "number FafLibrary_News{page=} - one page of FAF's news posts; FafLibrary_Job(id).data holds them."
    );
    static moho::CScrLuaBinder saveReview(
      moho::SCR_UserLuaInitSet(),
      "FafLibrary_SaveReview",
      &Binding<&SaveReviewBody>,
      nullptr,
      "<global>",
      "number, string FafLibrary_SaveReview{kind=, subject=, review=, player=, score=, text=} - "
      "writes the player's review of a map, mod or game to FAF."
    );
    static moho::CScrLuaBinder deleteReview(
      moho::SCR_UserLuaInitSet(),
      "FafLibrary_DeleteReview",
      &Binding<&DeleteReviewBody>,
      nullptr,
      "<global>",
      "number, string FafLibrary_DeleteReview{kind=, review=} - takes the player's review off FAF."
    );
    static moho::CScrLuaBinder report(
      moho::SCR_UserLuaInitSet(),
      "FafLibrary_Report",
      &Binding<&ReportBody>,
      nullptr,
      "<global>",
      "number, string FafLibrary_Report{reporter=, player=, text=, game=, time=} - "
      "sends the player's report of another player to FAF's moderators."
    );
    static moho::CScrLuaBinder releases(
      moho::SCR_UserLuaInitSet(),
      "FafLibrary_Releases",
      &Binding<&ReleasesBody>,
      nullptr,
      "<global>",
      "number FafLibrary_Releases() - this engine's releases on GitHub, newest first, as the job's data."
    );
    static moho::CScrLuaBinder events(
      moho::SCR_UserLuaInitSet(),
      "FafLibrary_Events",
      &Binding<&EventsBody>,
      nullptr,
      "<global>",
      "number FafLibrary_Events() - FAF's community events catalogue, as the job's data."
    );
    static moho::CScrLuaBinder upload(
      moho::SCR_UserLuaInitSet(),
      "FafLibrary_Upload",
      &Binding<&UploadBody>,
      nullptr,
      "<global>",
      "number, string FafLibrary_Upload{kind=, folder=, ranked=} - uploads a vault map or mod folder to FAF."
    );
    static moho::CScrLuaBinder localReplays(
      moho::SCR_UserLuaInitSet(),
      "FafLibrary_LocalReplays",
      &Binding<&LocalReplaysBody>,
      nullptr,
      "<global>",
      "table FafLibrary_LocalReplays() - the replays on this computer: {path, file, source, size, time}."
    );
    static moho::CScrLuaBinder replayInfo(
      moho::SCR_UserLuaInitSet(),
      "FafLibrary_ReplayInfo",
      &Binding<&ReplayInfoBody>,
      nullptr,
      "<global>",
      "table, string FafLibrary_ReplayInfo(path) - what a replay's head says (title, map, players, mods...)."
    );
    static moho::CScrLuaBinder prepareReplay(
      moho::SCR_UserLuaInitSet(),
      "FafLibrary_PrepareReplay",
      &Binding<&PrepareReplayBody>,
      nullptr,
      "<global>",
      "bool, string FafLibrary_PrepareReplay(path) - a file LaunchReplaySession plays (a FAF replay decoded)."
    );
    static moho::CScrLuaBinder replayLength(
      moho::SCR_UserLuaInitSet(),
      "FafLibrary_ReplayLength",
      &Binding<&ReplayLengthBody>,
      nullptr,
      "<global>",
      "number, string FafLibrary_ReplayLength(path) - the game's length in a replay, in game seconds."
    );
    static moho::CScrLuaBinder searchReplays(
      moho::SCR_UserLuaInitSet(),
      "FafLibrary_SearchReplays",
      &Binding<&SearchReplaysBody>,
      nullptr,
      "<global>",
      "number FafLibrary_SearchReplays(query) - searches FAF's replay vault; FafLibrary_Job(id) has the answer."
    );
    static moho::CScrLuaBinder downloadReplay(
      moho::SCR_UserLuaInitSet(),
      "FafLibrary_DownloadReplay",
      &Binding<&DownloadReplayBody>,
      nullptr,
      "<global>",
      "number FafLibrary_DownloadReplay(gameId) - downloads that game's replay; FafLibrary_Job(id) follows it."
    );
    static moho::CScrLuaBinder searchMods(
      moho::SCR_UserLuaInitSet(),
      "FafLibrary_SearchMods",
      &Binding<&SearchModsBody>,
      nullptr,
      "<global>",
      "number FafLibrary_SearchMods(query) - searches FAF's mod vault; FafLibrary_Job(id) has the answer."
    );
    static moho::CScrLuaBinder installMod(
      moho::SCR_UserLuaInitSet(),
      "FafLibrary_InstallMod",
      &Binding<&InstallModBody>,
      nullptr,
      "<global>",
      "number FafLibrary_InstallMod{url=, uid=} - downloads a mod from FAF's vault and makes it usable at once."
    );
    static moho::CScrLuaBinder removeMod(
      moho::SCR_UserLuaInitSet(),
      "FafLibrary_RemoveMod",
      &Binding<&RemoveModBody>,
      nullptr,
      "<global>",
      "bool, string FafLibrary_RemoveMod(folder) - takes a mod out of the game and off the disk."
    );
    static moho::CScrLuaBinder installMap(
      moho::SCR_UserLuaInitSet(),
      "FafLibrary_InstallMap",
      &Binding<&InstallMapBody>,
      nullptr,
      "<global>",
      "number FafLibrary_InstallMap{url=} - downloads a map from FAF's vault into the maps folder, mounted at once."
    );
    static moho::CScrLuaBinder removeMap(
      moho::SCR_UserLuaInitSet(),
      "FafLibrary_RemoveMap",
      &Binding<&RemoveMapBody>,
      nullptr,
      "<global>",
      "bool, string FafLibrary_RemoveMap(folder) - takes a vault map out of the game and off the disk."
    );
    static moho::CScrLuaBinder rawFileInfo(
      moho::SCR_UserLuaInitSet(),
      "FafDisk_FileInfo",
      &moho::cfunc_DiskGetFileInfo,
      nullptr,
      "<global>",
      "FileInfo|false FafDisk_FileInfo(path) - the engine's DiskGetFileInfo, never cached."
    );
    static moho::CScrLuaBinder modsFolder(
      moho::SCR_UserLuaInitSet(),
      "FafLibrary_ModsFolder",
      &Binding<&ModsFolderBody>,
      nullptr,
      "<global>",
      "string FafLibrary_ModsFolder() - the vault's mods folder on disk."
    );
    static moho::CScrLuaBinder api(
      moho::SCR_UserLuaInitSet(),
      "FafLibrary_Api",
      &Binding<&ApiBody>,
      nullptr,
      "<global>",
      "number FafLibrary_Api(path, query) - reads FAF's API (/data/... or /me); FafLibrary_Job(id).data has it."
    );
    static moho::CScrLuaBinder thumbnail(
      moho::SCR_UserLuaInitSet(),
      "FafLibrary_Thumbnail",
      &Binding<&ThumbnailBody>,
      nullptr,
      "<global>",
      "string, number FafLibrary_Thumbnail(url) - a picture of FAF's content server: its game path, or a download."
    );
    static moho::CScrLuaBinder mountThumbnails(
      moho::SCR_UserLuaInitSet(),
      "FafLibrary_MountThumbnails",
      &Binding<&MountThumbnailsBody>,
      nullptr,
      "<global>",
      "bool FafLibrary_MountThumbnails() - makes the pictures downloaded since the last call readable."
    );
    static moho::CScrLuaBinder job(
      moho::SCR_UserLuaInitSet(),
      "FafLibrary_Job",
      &Binding<&JobBody>,
      nullptr,
      "<global>",
      "table FafLibrary_Job(id) - a search's or download's state, and its answer once done (then forgotten)."
    );
  }

  struct LibraryLuaFuncDefBootstrap
  {
    LibraryLuaFuncDefBootstrap()
    {
      RegisterLibraryBindings();
    }
  };

  LibraryLuaFuncDefBootstrap gLibraryLuaFuncDefBootstrap;
} // namespace

void moho::LIBRARY_Shutdown()
{
  std::map<int, std::shared_ptr<Job>> jobs;
  {
    std::lock_guard<std::mutex> guard(gJobsLock);
    jobs.swap(gJobs);
  }
  // A search ends with its answer and a download with its file; neither can be stopped halfway, so they're waited for.
  for (auto& [id, job] : jobs) {
    if (job->thread.joinable()) {
      job->thread.join();
    }
  }
}
