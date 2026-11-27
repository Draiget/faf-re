#pragma once

// Engine addition (in-game launcher plan, WP5/WP6, the launcher's Replays and Mods pages): FAF's replay vault and mod
// vault as its clients search them (the Rust client's infra/replay/vault.rs and infra/mods.rs; notes in the plan's
// working folder): the JSON:API query for a page of games or mods, and that page read into plain rows.

#include <expected>
#include <string>
#include <vector>

#include "online/Json.h"

namespace faf::online
{
  /** What a replay search asks for; empty fields don't filter. */
  struct ReplayQuery
  {
    std::string player; ///< a login, matched anywhere in the name
    std::string map;    ///< a map's display name or folder, anywhere in it
    std::string title;  ///< the game's title, anywhere in it
    std::string featuredMod;
    bool ratedOnly = false;
    int page = 1;      ///< from 1
    int pageSize = 30; ///< 1 to 100 (the API caps at 100)
  };

  struct VaultReplayPlayer
  {
    std::string login;
    int team = -1;
    std::string faction; ///< as the API names it, or its number
    int rating = 0;      ///< mean - 3 deviations before the game, 0 when unknown
    bool rated = false;  ///< a rating before the game was known
    std::string result;
    double score = 0;
  };

  struct VaultReplay
  {
    std::string id;
    std::string title;
    std::string mapFolder; ///< empty for a generated map
    std::string mapName;
    std::string featuredMod;
    std::string startTime; ///< as the API writes it (ISO 8601)
    double seconds = 0;    ///< game length from the replay's ticks
    bool replayAvailable = false;
    std::string validity;
    double reviewScore = 0;
    int reviews = 0;
    std::vector<VaultReplayPlayer> players;
  };

  struct VaultPage
  {
    int totalPages = 0;
    int totalRecords = 0;
  };

  /** `/data/game?...` for the query, on `apiBase` (https://api.faforever.com). */
  [[nodiscard]] std::string ReplaySearchUrl(const std::string& apiBase, const ReplayQuery& query);

  /** A /data/game answer read into rows, newest first as the API sorted them; the error when it isn't one. */
  [[nodiscard]] std::expected<std::vector<VaultReplay>, std::string>
  ReadReplayPage(const std::string& body, VaultPage* page = nullptr);

  /** Where a replay downloads from: the replay host follows on to the file (no sign-in). */
  [[nodiscard]] std::string ReplayDownloadUrl(const std::string& replayBase, const std::string& id);

  /** What a mod search asks for. */
  struct ModQuery
  {
    std::string name;   ///< each word must be in the mod's name
    std::string author; ///< the author or the uploader, anywhere in the name
    std::string type;   ///< "UI", "SIM" or empty for both
    bool recommendedOnly = false;
    std::string sort = "-reviewsSummary.lowerBound";
    int page = 1;
    int pageSize = 36;
  };

  struct VaultMod
  {
    std::string id;
    std::string name;
    std::string author;
    std::string uploader;
    bool recommended = false;
    std::string uid; ///< the latest version's
    std::string version;
    std::string description;
    std::string type; ///< "UI" or "SIM"
    bool ranked = false;
    std::string downloadUrl;
    std::string thumbnailUrl;
    std::string updateTime;
    double reviewScore = 0;
    int reviews = 0;
  };

  /** `/data/mod?...` for the query. */
  [[nodiscard]] std::string ModSearchUrl(const std::string& apiBase, const ModQuery& query);

  /** A /data/mod answer read into rows; the error when it isn't one. */
  [[nodiscard]] std::expected<std::vector<VaultMod>, std::string>
  ReadModPage(const std::string& body, VaultPage* page = nullptr);

  /** Text as it may go into an RSQL value: the characters that would end or widen it ("\*;(),') taken out. */
  [[nodiscard]] std::string RsqlSafe(const std::string& text);
} // namespace faf::online
