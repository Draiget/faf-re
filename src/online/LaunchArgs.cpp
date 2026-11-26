// Engine addition (in-game launcher plan, WP4): a FAF match's switches (src/online/LaunchArgs.h).

#include "online/LaunchArgs.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdio>

namespace faf::online
{
  namespace
  {
    // The TrueSkill starting pair, which describes an unrated player (launcher.rs DEFAULT_MEAN, DEFAULT_DEVIATION).
    constexpr double kDefaultMean = 1500.0;
    constexpr double kDefaultDeviation = 500.0;

    bool SameNoCase(
      const std::string& a,
      const std::string& b
    )
    {
      return a.size() == b.size() && std::equal(a.begin(), a.end(), b.begin(), [](char x, char y) {
        return std::tolower(static_cast<unsigned char>(x)) == std::tolower(static_cast<unsigned char>(y));
      });
    }

    bool Has(
      const std::vector<std::string>& args,
      const std::string& flag
    )
    {
      return std::any_of(args.begin(), args.end(), [&](const std::string& arg) {
        return SameNoCase(arg, flag);
      });
    }

    void PushPair(
      std::vector<std::string>& args,
      const std::string& flag,
      std::string value
    )
    {
      if (!Has(args, flag)) {
        args.push_back(flag);
        args.push_back(std::move(value));
      }
    }

    /** A rating as the clients write it: whole numbers without decimals (launcher.rs keeps them as i32). */
    std::string RatingText(
      const double value
    )
    {
      char text[32];
      (void)std::snprintf(text, sizeof(text), "%lld", static_cast<long long>(std::llround(value)));
      return text;
    }

    std::optional<int> OptionalInt(
      const JsonNode& node,
      const std::string& key
    )
    {
      const JsonNode* const value = node.Get(key);
      if (value == nullptr || value->kind != JsonNode::Kind::Number) {
        return std::nullopt;
      }
      return static_cast<int>(value->number);
    }

    const char* FactionSwitch(
      const int faction
    )
    {
      switch (faction) {
      case 1:
        return "/uef";
      case 2:
        return "/aeon";
      case 3:
        return "/cybran";
      case 4:
        return "/seraphim";
      default:
        return nullptr;
      }
    }
  } // namespace

  LaunchPlayer ReadLaunchPlayer(
    const JsonNode& record
  )
  {
    LaunchPlayer player;
    player.login = record.String("login");
    if (const JsonNode* const id = record.Get("id"); id != nullptr) {
      player.id = id->text;
    }
    player.country = record.String("country");
    player.clan = record.String("clan");
    if (
      const JsonNode* const ratings = record.Get("ratings");
      ratings != nullptr && ratings->kind == JsonNode::Kind::Object
    ) {
      for (const auto& [type, entry] : ratings->members) {
        LaunchRating rating;
        if (
          const JsonNode* const pair = entry.Get("rating");
          pair != nullptr && pair->kind == JsonNode::Kind::Array && pair->items.size() >= 2
        ) {
          rating.mean = pair->items[0].number;
          rating.deviation = pair->items[1].number;
        }
        rating.games = static_cast<int>(entry.Number("number_of_games"));
        player.ratings[type] = rating;
      }
    }
    return player;
  }

  GameLaunch ReadGameLaunch(
    const JsonNode& message
  )
  {
    GameLaunch launch;
    if (const JsonNode* const args = message.Get("args"); args != nullptr && args->kind == JsonNode::Kind::Array) {
      for (const JsonNode& arg : args->items) {
        launch.serverArgs.push_back(
          arg.kind == JsonNode::Kind::String || arg.kind == JsonNode::Kind::Number ? arg.text : ToJson(arg)
        );
      }
    }
    if (const JsonNode* const uid = message.Get("uid"); uid != nullptr) {
      launch.uid = uid->text;
    }
    if (const std::string mod = message.String("mod"); !mod.empty()) {
      launch.featuredMod = mod;
    }
    launch.gameType = message.String("game_type");
    launch.ratingType = message.String("rating_type");
    launch.initMode = static_cast<int>(message.Number("init_mode"));
    launch.faction = OptionalInt(message, "faction");
    launch.team = OptionalInt(message, "team");
    launch.expectedPlayers = OptionalInt(message, "expected_players");
    launch.mapPosition = OptionalInt(message, "map_position");
    if (
      const JsonNode* const options = message.Get("game_options");
      options != nullptr && options->kind == JsonNode::Kind::Object
    ) {
      for (const auto& [name, value] : options->members) {
        launch.gameOptions.emplace_back(
          name,
          value.kind == JsonNode::Kind::String || value.kind == JsonNode::Kind::Number ? value.text : ToJson(value)
        );
      }
    }
    return launch;
  }

  std::vector<std::string> BuildLaunchArgs(
    const GameLaunch& launch,
    const LaunchPlayer* const player,
    const LaunchLocal& local
  )
  {
    // The server's own args first (/numgames for the game's rating type), as both clients do.
    std::vector<std::string> args = launch.serverArgs;

    // The rating pair is never left out (launcher.rs): the game's rating type, else global, else the starting pair.
    const std::string ratingType = launch.ratingType.empty() ? std::string("global") : launch.ratingType;
    const LaunchRating* rating = nullptr;
    if (player != nullptr) {
      for (const auto& [type, entry] : player->ratings) {
        if (SameNoCase(type, ratingType)) {
          rating = &entry;
        }
      }
      if (rating == nullptr) {
        for (const auto& [type, entry] : player->ratings) {
          if (SameNoCase(type, "global")) {
            rating = &entry;
          }
        }
      }
    }
    PushPair(args, "/mean", RatingText(rating != nullptr ? rating->mean : kDefaultMean));
    PushPair(args, "/deviation", RatingText(rating != nullptr ? rating->deviation : kDefaultDeviation));
    if (player != nullptr) {
      if (!player->country.empty()) {
        PushPair(args, "/country", player->country);
      }
      if (!player->clan.empty()) {
        PushPair(args, "/clan", player->clan);
      }
      int games = 0;
      for (const auto& [type, entry] : player->ratings) {
        games += entry.games;
      }
      PushPair(args, "/numgames", std::to_string(std::max(games, 0)));
    }

    if (SameNoCase(launch.gameType, "matchmaker")) {
      if (launch.faction) {
        if (const char* const faction = FactionSwitch(*launch.faction); faction != nullptr && !Has(args, faction)) {
          args.push_back(faction);
        }
      }
      if (launch.team) {
        PushPair(args, "/team", std::to_string(*launch.team));
      }
      if (launch.expectedPlayers) {
        PushPair(args, "/players", std::to_string(*launch.expectedPlayers));
      }
      if (launch.mapPosition) {
        PushPair(args, "/startspot", std::to_string(*launch.mapPosition));
      }
      if (!launch.gameOptions.empty() && !Has(args, "/gameoptions")) {
        args.push_back("/gameoptions");
        for (const auto& [name, value] : launch.gameOptions) {
          args.push_back(name + ":" + value);
        }
      }
    }

    // What the launcher adds (infra/game.rs build_arguments), then our own network's switches.
    args.push_back("/init");
    args.push_back(local.initFile.empty() ? "init_" + launch.featuredMod + ".lua" : local.initFile);
    args.push_back("/nobugreport");
    if (local.replayPort != 0 && !launch.uid.empty()) {
      const std::string name = player != nullptr && !player->login.empty() ? player->login : std::string("player");
      args.push_back("/savereplay");
      args.push_back(
        "gpgnet://127.0.0.1:" + std::to_string(local.replayPort) + "/" + launch.uid + "/" + name + ".SCFAreplay"
      );
    }
    args.push_back("/gpgnet");
    args.push_back("127.0.0.1:" + std::to_string(local.gpgnetPort));
    if (!local.logFile.empty()) {
      args.push_back("/log");
      args.push_back(local.logFile);
    }
    if (local.nativeNet) {
      args.push_back("/nativenet");
      if (local.forceRelay) {
        args.push_back("/nativenetrelay");
      }
      if (!local.bindAddress.empty()) {
        args.push_back("/nativenetbind");
        args.push_back(local.bindAddress);
      }
    }
    return args;
  }
} // namespace faf::online
