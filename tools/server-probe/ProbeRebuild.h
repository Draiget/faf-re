#pragma once

#include <cstdint>
#include <memory>
#include <span>
#include <string>

#include "lua/LuaObject.h"
#include "remote/ContentCheck.h"

// Plan WP11 step 1 (research/WP11-network-client-map.md): the probe as a client that keeps no sim. With
// `--rebuild <match.lua>` it starts the engine as the server does, loads the match's rules, and rebuilds each beat's
// game data from the server's view frames alone (`CSyncRebuilder` on a fresh `SSyncData` per view), as a remote client
// will. What the frames can't give yet shows in the rebuild's counts.

namespace faf::probe
{
  class CProbeRebuild
  {
  public:
    CProbeRebuild();
    ~CProbeRebuild();

    /** The engine's services, then the match file's rules (as the server loads them). False with `error`. */
    [[nodiscard]] bool Load(const std::string& matchPath, int uid, std::string& error);
    /** The engine's services alone: the rules come with the server's `LaunchInfo` (plan WPR.55). */
    [[nodiscard]] bool Start(std::string& error);
    /** `LaunchInfo`: the configuration the server launched, and its rules. False with `error`. */
    [[nodiscard]] bool OnLaunchInfo(std::span<const std::uint8_t> configuration, int uid, std::string& error);

    /** `GameInfo`: the map's size makes the codec; the rebuilder starts here. `army`: the player's (-1: none). */
    void OnGameInfo(float mapSizeX, float mapSizeZ, std::int32_t army);
    /**
     * One view's own and team frames (empty team: none), merged and rebuilt; and its army and grid lanes, decoded
     * against what this client holds of them (plan WP11 step 2).
     */
    void OnView(
      std::span<const std::uint8_t> own, std::span<const std::uint8_t> team, std::span<const std::uint8_t> armies,
      std::span<const std::uint8_t> grids, std::span<const std::uint8_t> poses = {}, bool hasPoses = false
    );

    /** A whole `SessionTables` message (plan WP11 step 4). */
    void OnTables(std::span<const std::uint8_t> message);

    /** The match's rules are loaded (from the file, or from the server's `LaunchInfo`). */
    [[nodiscard]] bool HasRules() const noexcept;
    /** Plan WP2.6: the content report for the loaded rules, as the game client sends it. False without rules. */
    [[nodiscard]] bool Content(remote::SContentReport& out) const;

    /** The rebuild's counts, one line each. */
    void Report(int uid) const;

  private:
    [[nodiscard]] bool LoadRules(LuaPlus::LuaObject& config, int uid, std::string& error);

    struct SState;
    std::unique_ptr<SState> mState;
  };
} // namespace faf::probe
