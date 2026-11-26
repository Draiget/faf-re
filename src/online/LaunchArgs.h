#pragma once

// Engine addition (in-game launcher plan, WP4): a FAF match's switches, as the official client and the Rust client
// put them on the game's command line, for moho::CFG_SetLaunchArgs. The rules are FAForeverRustClient's
// (crates/faf-app/src/services/launcher.rs launch_arguments, infra/game.rs build_arguments), which mirror the Java
// client's LaunchCommandBuilder and the Python client's handle_game_launch.

#include <cstdint>
#include <map>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "online/Json.h"

namespace faf::online
{
  /** One rating of the signed-in player (the lobby's player record, "ratings"). */
  struct LaunchRating
  {
    double mean = 0.0;
    double deviation = 0.0;
    int games = 0;
  };

  /** The signed-in player as the lobby describes them (welcome's "me", or their player_info). */
  struct LaunchPlayer
  {
    std::string login;
    std::string id;
    std::string country;
    std::string clan;
    std::map<std::string, LaunchRating> ratings; ///< by rating type: global, ladder_1v1, tmm_2v2...
  };

  /** What `game_launch` says (FAForever/server lobbyconnection.py _prepare_launch_game, types.py GameLaunchOptions). */
  struct GameLaunch
  {
    std::vector<std::string> serverArgs; ///< "args", each as text: ["/numgames", "12"]
    std::string uid;
    std::string featuredMod = "faf";
    std::string gameType; ///< custom, matchmaker, coop
    std::string ratingType;
    int initMode = 0;
    std::optional<int> faction;
    std::optional<int> team;
    std::optional<int> expectedPlayers;
    std::optional<int> mapPosition;
    std::vector<std::pair<std::string, std::string>> gameOptions;
  };

  /** What this program adds: where the match's GPGNet and replay go, and our own network's switches. */
  struct LaunchLocal
  {
    std::uint16_t gpgnetPort = 0;
    std::uint16_t replayPort = 0; ///< 0: no /savereplay
    std::string initFile;         ///< empty: init_<featured mod>.lua
    std::string logFile;          ///< empty: no /log
    bool nativeNet = true;
    bool forceRelay = false; ///< the ICE session's forceRelay
    std::string bindAddress; ///< /nativenetbind; empty: none
  };

  [[nodiscard]] LaunchPlayer ReadLaunchPlayer(const JsonNode& record);
  [[nodiscard]] GameLaunch ReadGameLaunch(const JsonNode& message);
  /** The match's switches; `player` may be null (no record yet: the default rating pair). */
  [[nodiscard]] std::vector<std::string>
  BuildLaunchArgs(const GameLaunch& launch, const LaunchPlayer* player, const LaunchLocal& local);
} // namespace faf::online
