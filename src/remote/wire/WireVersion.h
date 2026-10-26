#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string>

#include "remote/wire/BitStream.h"

// Engine addition, server mode (plan WP7.1): every lane of the server-mode wire format has
// its own schema version, and the handshake carries the protocol version, every lane's
// version and the content-table hash (WP7.2). A client and server that differ in any of
// them do not play together; there is no negotiation down to an older lane version.

namespace faf::remote::wire
{
  /** Bumped when the handshake or the datagram framing changes. */
  inline constexpr std::uint16_t kProtocolVersion = 1;

  enum class ELane : std::uint8_t
  {
    Entities,   // view frames: entity creation, change and removal (EntityFrame.h)
    Armies,     // army constant and variable data (§6)
    Grids,      // the view's intel grids
    Events,     // effects, sounds, decals, camera events
    LuaSync,    // routed Lua `Sync` payloads (§8)
    Commands,   // client commands and their acknowledgements
    Count,
  };

  inline constexpr std::size_t kLaneCount = static_cast<std::size_t>(ELane::Count);

  /**
   * This build's schema version of each lane. Entities 2: flag bit 12 marks an orphaned
   * record (an erased entity the client keeps until its view sees the spot, WP7.7).
   * Entities 3: 32-bit field masks with the appearance block, a mask on creations too, and
   * positions outside the quantiser's range as exact floats. Entities 4: sounds and the
   * strategic underlay in the appearance block, as session-table ids; a unit's stats tree and
   * creation constants in its unit block. Entities 5: the rest of a unit's variable data (ids,
   * economy, command and build queues, weapons, attributes) in its unit block. Entities 6: a
   * texture scroll whose start is the old end goes as one bit and the end. Entities 7: a
   * dead-reckoned position carries a vertical acceleration after its velocity, and a reckoned
   * yaw-only orientation its anchor age and turn rate. Entities 8: the session record carries
   * the resource deposits the sim adds and the terrain edits; a creation carries the sim's
   * creation tick. Entities 9: with ground following, a dead-reckoned position carries a bit
   * saying its height is the terrain's.
   */
  inline constexpr std::array<std::uint16_t, kLaneCount> kLaneVersions{9, 1, 1, 1, 1, 1};

  [[nodiscard]] const char* LaneName(ELane lane) noexcept;

  /** What each side sends first. */
  struct SWireHello
  {
    std::uint16_t protocolVersion = kProtocolVersion;
    std::array<std::uint16_t, kLaneCount> laneVersions = kLaneVersions;
    std::uint64_t contentHash = 0;

    void Encode(BitWriter& writer) const;
    /** Empty on a malformed hello; a hello from a newer build with more lanes decodes. */
    [[nodiscard]] static std::optional<SWireHello> Decode(BitReader& reader);
  };

  /** Empty when the two can play together, otherwise why not (for the player and the log). */
  [[nodiscard]] std::optional<std::string> WireIncompatibility(const SWireHello& local, const SWireHello& remote);
} // namespace faf::remote::wire
