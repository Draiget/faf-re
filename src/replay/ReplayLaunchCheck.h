#pragma once

#include <string>

// Engine addition, server mode (plan WP2.10): `faf-replay --launch-check`. A replay's header is
// the launch info the original lobby built (`VCR_CreateReplay` writes it). The check rebuilds
// the lobby's game config from that header, runs `moho::BuildLaunchInfo` on it twice, with the
// participants in the lobby's order and in another order (as a game server's roster would give
// them), and compares every field the header carries with the recorded one, byte for byte.

namespace faf::replay
{
  struct SLaunchCheckResult
  {
    bool ran = false;        // false: the replay or its config could not be read (see `error`)
    int differences = 0;
    int orderOnly = 0;       // serialised Lua values with the same content in another key order
    std::string error;
    std::string report;      // one line per difference, then a summary line
  };

  /**
   * Rebuilds the config from `replayPath`'s header and compares the launch with `expectPath`'s
   * header (another client's replay of the same game), or with its own when that is empty.
   */
  [[nodiscard]] SLaunchCheckResult RunLaunchCheck(const std::string& replayPath, const std::string& expectPath);
} // namespace faf::replay
