#pragma once

#include <cstdint>
#include <memory>
#include <span>
#include <string>

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

    /** `GameInfo`: the map's size makes the codec; the rebuilder starts here. `army`: the player's (-1: none). */
    void OnGameInfo(float mapSizeX, float mapSizeZ, std::int32_t army);
    /** One view's own and team frames (empty team: none), merged and rebuilt. */
    void OnView(std::span<const std::uint8_t> own, std::span<const std::uint8_t> team);

    /** The rebuild's counts, one line each. */
    void Report(int uid) const;

  private:
    struct SState;
    std::unique_ptr<SState> mState;
  };
} // namespace faf::probe
