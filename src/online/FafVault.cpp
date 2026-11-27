// Engine addition (in-game launcher plan, WP5/WP6): FAF's replay and mod vaults (online/FafVault.h).

#include "online/FafVault.h"

#include <algorithm>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstdlib>
#include <map>
#include <sstream>
#include <utility>

#include "online/Url.h"

namespace faf::online
{
  namespace
  {
    /** The `included` resources of a JSON:API answer, by "type/id". */
    using Included = std::map<std::string, const JsonNode*>;

    Included IndexIncluded(
      const JsonNode& root
    )
    {
      Included out;
      if (
        const JsonNode* const included = root.Get("included");
        included != nullptr && included->kind == JsonNode::Kind::Array
      ) {
        for (const JsonNode& item : included->items) {
          out[item.String("type") + "/" + item.String("id")] = &item;
        }
      }
      return out;
    }

    /** A resource's to-one relationship, resolved through `included`; null when absent. */
    const JsonNode* One(
      const JsonNode& resource,
      const char* const name,
      const Included& included
    )
    {
      const JsonNode* const relationships = resource.Get("relationships");
      const JsonNode* const relation = relationships != nullptr ? relationships->Get(name) : nullptr;
      const JsonNode* const data = relation != nullptr ? relation->Get("data") : nullptr;
      if (data == nullptr || data->kind != JsonNode::Kind::Object) {
        return nullptr;
      }
      const auto found = included.find(data->String("type") + "/" + data->String("id"));
      return found != included.end() ? found->second : nullptr;
    }

    /** A resource's to-many relationship, resolved through `included` (those it lists that are there). */
    std::vector<const JsonNode*> Many(
      const JsonNode& resource,
      const char* const name,
      const Included& included
    )
    {
      std::vector<const JsonNode*> out;
      const JsonNode* const relationships = resource.Get("relationships");
      const JsonNode* const relation = relationships != nullptr ? relationships->Get(name) : nullptr;
      const JsonNode* const data = relation != nullptr ? relation->Get("data") : nullptr;
      if (data == nullptr || data->kind != JsonNode::Kind::Array) {
        return out;
      }
      for (const JsonNode& item : data->items) {
        const auto found = included.find(item.String("type") + "/" + item.String("id"));
        if (found != included.end()) {
          out.push_back(found->second);
        }
      }
      return out;
    }

    const JsonNode& Attributes(
      const JsonNode* const resource
    )
    {
      static const JsonNode kNone;
      const JsonNode* const attributes = resource != nullptr ? resource->Get("attributes") : nullptr;
      return attributes != nullptr ? *attributes : kNone;
    }

    /** A member that may be a number or a text holding one. */
    double NumberOf(
      const JsonNode& node,
      const char* const key,
      const double fallback
    )
    {
      const JsonNode* const value = node.Get(key);
      if (value == nullptr) {
        return fallback;
      }
      if (value->kind == JsonNode::Kind::Number) {
        return value->number;
      }
      if (value->kind == JsonNode::Kind::String && !value->text.empty()) {
        return std::atof(value->text.c_str());
      }
      return fallback;
    }

    bool HasNumber(
      const JsonNode& node,
      const char* const key
    )
    {
      const JsonNode* const value = node.Get(key);
      return value != nullptr && value->kind == JsonNode::Kind::Number;
    }

    std::expected<JsonNode, std::string> ReadRoot(
      const std::string& body,
      VaultPage* const page
    )
    {
      auto root = ParseJson(body);
      if (!root || root->kind != JsonNode::Kind::Object) {
        return std::unexpected(std::string("FAF's API answered with something that isn't JSON"));
      }
      if (
        const JsonNode* const errors = root->Get("errors");
        errors != nullptr && errors->kind == JsonNode::Kind::Array && !errors->items.empty()
      ) {
        const JsonNode& first = errors->items.front();
        std::string why = first.String("detail");
        if (why.empty()) {
          why = first.String("title");
        }
        return std::unexpected("FAF's API refused the search: " + (why.empty() ? std::string("no reason") : why));
      }
      const JsonNode* const data = root->Get("data");
      if (data == nullptr || data->kind != JsonNode::Kind::Array) {
        return std::unexpected(std::string("FAF's API answered without a list"));
      }
      if (page != nullptr) {
        const JsonNode* const meta = root->Get("meta");
        const JsonNode* const counts = meta != nullptr ? meta->Get("page") : nullptr;
        if (counts != nullptr) {
          page->totalPages = static_cast<int>(NumberOf(*counts, "totalPages", 0));
          page->totalRecords = static_cast<int>(NumberOf(*counts, "totalRecords", 0));
        }
      }
      return root;
    }

    std::string Query(
      const std::vector<std::pair<std::string, std::string>>& parameters
    )
    {
      std::string out;
      for (const auto& [key, value] : parameters) {
        out += out.empty() ? "?" : "&";
        out += UrlEncode(key);
        if (!value.empty()) {
          out += "=" + UrlEncode(value);
        }
      }
      return out;
    }

    std::string Clauses(
      const std::vector<std::string>& clauses
    )
    {
      if (clauses.empty()) {
        return {};
      }
      if (clauses.size() == 1) {
        return clauses.front();
      }
      std::string out = "(";
      for (std::size_t i = 0; i < clauses.size(); ++i) {
        out += (i == 0 ? "" : ";") + clauses[i];
      }
      return out + ")";
    }
  } // namespace

  double IsoSeconds(
    const std::string& text
  )
  {
    int year = 0;
    int month = 0;
    int day = 0;
    int hour = 0;
    int minute = 0;
    int second = 0;
    if (
      std::sscanf(text.c_str(), "%d-%d-%dT%d:%d:%d", &year, &month, &day, &hour, &minute, &second) < 6 || month < 1 ||
      month > 12 || day < 1 || day > 31
    ) {
      return 0;
    }
    const std::chrono::sys_days date = std::chrono::year(year) / std::chrono::month(static_cast<unsigned>(month)) /
      std::chrono::day(static_cast<unsigned>(day));
    return static_cast<double>(date.time_since_epoch().count()) * 86400.0 + hour * 3600 + minute * 60 + second;
  }

  std::string RsqlSafe(
    const std::string& text
  )
  {
    std::string out;
    for (const char c : text) {
      if (std::string("\"\\*;(),'").find(c) == std::string::npos) {
        out += c;
      }
    }
    // Leading and trailing blanks: a search box's stray space would match nothing.
    const std::size_t first = out.find_first_not_of(' ');
    const std::size_t last = out.find_last_not_of(' ');
    return first == std::string::npos ? std::string() : out.substr(first, last - first + 1);
  }

  std::string ReplaySearchUrl(
    const std::string& apiBase,
    const ReplayQuery& query
  )
  {
    std::vector<std::string> clauses;
    if (const std::string player = RsqlSafe(query.player); !player.empty()) {
      clauses.push_back("playerStats.player.login==\"*" + player + "*\"");
    }
    if (const std::string map = RsqlSafe(query.map); !map.empty()) {
      clauses.push_back("(mapVersion.map.displayName==\"*" + map + "*\",mapVersion.folderName==\"*" + map + "*\")");
    }
    if (const std::string title = RsqlSafe(query.title); !title.empty()) {
      clauses.push_back("name==\"*" + title + "*\"");
    }
    if (
      const std::string id = RsqlSafe(query.id); !id.empty() && id.find_first_not_of("0123456789") == std::string::npos
    ) {
      clauses.push_back("id==\"" + id + "\"");
    }
    if (const std::string mod = RsqlSafe(query.featuredMod); !mod.empty()) {
      clauses.push_back("featuredMod.technicalName==\"" + mod + "\"");
    }
    if (query.ratedOnly) {
      clauses.push_back("validity==\"VALID\"");
    }
    std::vector<std::pair<std::string, std::string>> parameters{
      {"sort", "-startTime"},
      {"page[size]", std::to_string(std::clamp(query.pageSize, 1, 100))},
      {"page[number]", std::to_string(std::max(1, query.page))},
      {"page[totals]", ""},
      {"include", "mapVersion,mapVersion.map,featuredMod,playerStats.player,playerStats.ratingChanges,reviewsSummary"},
    };
    if (!clauses.empty()) {
      parameters.emplace_back("filter", Clauses(clauses));
    }
    return apiBase + "/data/game" + Query(parameters);
  }

  std::expected<std::vector<VaultReplay>, std::string> ReadReplayPage(
    const std::string& body,
    VaultPage* const page
  )
  {
    auto root = ReadRoot(body, page);
    if (!root) {
      return std::unexpected(root.error());
    }
    const Included included = IndexIncluded(*root);
    std::vector<VaultReplay> rows;
    for (const JsonNode& game : root->Get("data")->items) {
      const JsonNode& attributes = Attributes(&game);
      VaultReplay row;
      row.id = game.String("id");
      row.title = attributes.String("name");
      row.startTime = attributes.String("startTime");
      row.endTime = attributes.String("endTime");
      if (const double start = IsoSeconds(row.startTime), end = IsoSeconds(row.endTime); start > 0 && end > start) {
        row.wallSeconds = end - start;
      }
      row.seconds = NumberOf(attributes, "replayTicks", 0) / 10.0;
      row.replayAvailable = attributes.Bool("replayAvailable");
      row.validity = attributes.String("validity");
      const JsonNode* const mod = One(game, "featuredMod", included);
      row.featuredMod = mod != nullptr ? Attributes(mod).String("technicalName") : std::string();
      if (row.featuredMod.empty()) {
        row.featuredMod = "faf";
      }
      if (const JsonNode* const version = One(game, "mapVersion", included)) {
        row.mapFolder = Attributes(version).String("folderName");
        const JsonNode* const map = One(*version, "map", included);
        row.mapName = map != nullptr ? Attributes(map).String("displayName") : std::string();
        if (row.mapName.empty()) {
          row.mapName = row.mapFolder;
        }
      } else if (row.featuredMod != "coop") {
        row.mapName = "Neroxis Map Generator";
      }
      if (const JsonNode* const reviews = One(game, "reviewsSummary", included)) {
        row.reviewScore = NumberOf(Attributes(reviews), "averageScore", 0);
        row.reviews = static_cast<int>(NumberOf(Attributes(reviews), "reviews", 0));
      }
      for (const JsonNode* const stat : Many(game, "playerStats", included)) {
        const JsonNode& stats = Attributes(stat);
        VaultReplayPlayer player;
        const JsonNode* const who = One(*stat, "player", included);
        player.login = who != nullptr ? Attributes(who).String("login") : std::string();
        player.team = HasNumber(stats, "team") ? static_cast<int>(NumberOf(stats, "team", -1)) : -1;
        player.faction = stats.String("faction");
        player.result = stats.String("result");
        player.score = NumberOf(stats, "score", 0);
        // The leaderboard's journal first, else the stat's own numbers from before the game.
        double mean = 0;
        double deviation = 0;
        bool known = false;
        for (const JsonNode* const change : Many(*stat, "ratingChanges", included)) {
          const JsonNode& journal = Attributes(change);
          if (HasNumber(journal, "meanBefore")) {
            mean = NumberOf(journal, "meanBefore", 0);
            deviation = NumberOf(journal, "deviationBefore", 0);
            known = true;
            if (HasNumber(journal, "meanAfter")) {
              player.ratingAfter = static_cast<int>(
                std::trunc(NumberOf(journal, "meanAfter", 0) - 3.0 * NumberOf(journal, "deviationAfter", 0))
              );
              player.changed = true;
            }
            break;
          }
        }
        if (!known && HasNumber(stats, "beforeMean")) {
          mean = NumberOf(stats, "beforeMean", 0);
          deviation = NumberOf(stats, "beforeDeviation", 0);
          known = true;
        }
        player.rated = known;
        player.rating = known ? static_cast<int>(std::trunc(mean - 3.0 * deviation)) : 0;
        row.players.push_back(std::move(player));
      }
      rows.push_back(std::move(row));
    }
    return rows;
  }

  std::string ReplayDownloadUrl(
    const std::string& replayBase,
    const std::string& id
  )
  {
    std::string digits;
    for (const char c : id) {
      if (c >= '0' && c <= '9') {
        digits += c;
      }
    }
    return replayBase + "/" + digits;
  }

  std::string ApiUrl(
    const std::string& apiBase,
    const std::string& path,
    const std::vector<std::pair<std::string, std::string>>& parameters
  )
  {
    return apiBase + path + Query(parameters);
  }

  std::string ModSearchUrl(
    const std::string& apiBase,
    const ModQuery& query
  )
  {
    std::vector<std::string> clauses{"latestVersion.hidden==\"false\""};
    std::istringstream words(RsqlSafe(query.name));
    for (std::string word; words >> word;) {
      clauses.push_back("displayName==\"*" + word + "*\"");
    }
    if (const std::string author = RsqlSafe(query.author); !author.empty()) {
      clauses.push_back("(author==\"*" + author + "*\",uploader.login==\"*" + author + "*\")");
    }
    if (query.type == "UI" || query.type == "SIM") {
      clauses.push_back("latestVersion.type==\"" + query.type + "\"");
    }
    if (query.recommendedOnly) {
      clauses.push_back("recommended==\"true\"");
    }
    std::string sort = query.sort;
    if (
      sort != "-reviewsSummary.lowerBound" && sort != "-latestVersion.createTime" &&
      sort != "-latestVersion.updateTime" && sort != "displayName"
    ) {
      sort = "-reviewsSummary.lowerBound";
    }
    return apiBase + "/data/mod" +
      Query({
        {"filter", Clauses(clauses)},
        {"sort", sort},
        {"page[size]", std::to_string(std::clamp(query.pageSize, 1, 100))},
        {"page[number]", std::to_string(std::max(1, query.page))},
        {"page[totals]", ""},
        {"include", "latestVersion,latestVersion.reviewsSummary,reviewsSummary,uploader"},
      });
  }

  std::expected<std::vector<VaultMod>, std::string> ReadModPage(
    const std::string& body,
    VaultPage* const page
  )
  {
    auto root = ReadRoot(body, page);
    if (!root) {
      return std::unexpected(root.error());
    }
    const Included included = IndexIncluded(*root);
    std::vector<VaultMod> rows;
    for (const JsonNode& mod : root->Get("data")->items) {
      const JsonNode& attributes = Attributes(&mod);
      VaultMod row;
      row.id = mod.String("id");
      row.name = attributes.String("displayName");
      row.author = attributes.String("author");
      row.recommended = attributes.Bool("recommended");
      if (const JsonNode* const uploader = One(mod, "uploader", included)) {
        row.uploader = Attributes(uploader).String("login");
      }
      const JsonNode* const latest = One(mod, "latestVersion", included);
      const JsonNode& version = Attributes(latest);
      row.uid = version.String("uid");
      row.version = version.String("version");
      row.description = version.String("description");
      row.type = version.String("type");
      row.ranked = version.Bool("ranked");
      row.downloadUrl = version.String("downloadUrl");
      row.thumbnailUrl = version.String("thumbnailUrl");
      row.updateTime = version.String("updateTime");
      const JsonNode* reviews = One(mod, "reviewsSummary", included);
      if (reviews == nullptr && latest != nullptr) {
        reviews = One(*latest, "reviewsSummary", included);
      }
      if (reviews != nullptr) {
        row.reviewScore = NumberOf(Attributes(reviews), "averageScore", 0);
        row.reviews = static_cast<int>(NumberOf(Attributes(reviews), "reviews", 0));
      }
      rows.push_back(std::move(row));
    }
    return rows;
  }
} // namespace faf::online
