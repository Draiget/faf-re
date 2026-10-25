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

  /** This build's schema version of each lane. */
  inline constexpr std::array<std::uint16_t, kLaneCount> kLaneVersions{1, 1, 1, 1, 1, 1};

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
