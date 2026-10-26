#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "remote/wire/BitStream.h"

// Engine addition, server mode (plan WP11.4): the session's roster as the server tells each
// client, on the reliable stream. A remote client has no peers of its own; its client manager
// (CRemoteClientManager) answers the user code's roster questions (SessionGetClients, chat
// targets, the network stats) from the last roster, which the server sends whole whenever it
// changes.

namespace faf::remote::wire
{
  struct SRosterEntry
  {
    static constexpr std::size_t kMaxNameBytes = 256;
    static constexpr std::size_t kMaxSources = 32;

    std::uint8_t index = 0;               // the session's client index
    std::string name;                     // nickname
    std::int32_t ownerId = 0;             // the player's id
    std::vector<std::uint8_t> sources;    // command sources the client may issue for, ascending
    std::int32_t simRate = 0;             // the speed the client asks for
    float ping = 0.0f;                    // as the server measures it, milliseconds
    float quiet = 0.0f;                   // time since the client was last heard from
    bool connected = true;                // no ejection pending
    std::vector<std::uint8_t> ejectedBy;  // the clients asking to eject this one

    [[nodiscard]] bool operator==(const SRosterEntry& other) const noexcept;
  };

  struct SRoster
  {
    static constexpr std::size_t kMaxEntries = 64;

    std::int32_t localIndex = -1; // the receiving client's own entry (-1: none, an observer of a replay)
    std::vector<SRosterEntry> entries;

    void Encode(BitWriter& writer) const;
    /** Empty when malformed; never reads out of bounds or allocates past the limits. */
    [[nodiscard]] static std::optional<SRoster> Decode(BitReader& reader);

    [[nodiscard]] bool operator==(const SRoster& other) const noexcept;
  };
} // namespace faf::remote::wire
