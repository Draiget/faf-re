#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

#include "remote/wire/Roster.h"

// Engine addition, server mode (plan WP11.4): the two seat messages a server game's roster needs, shared by the
// server, the client's network driver and the probe. `Roster`: the session's clients as the server knows them, whole,
// which the client's `CRemoteClientManager` answers the user code's roster questions from. `Chat`: one chat message
// between two clients, through the server (a server client has no peers of its own).

namespace faf::remote
{
  /** The longest chat payload the server relays; FAF's chat lines are a few hundred bytes. */
  inline constexpr std::size_t kMaxChatBytes = 4096;

  /** The `Roster` message (net/GameLinks.h): its kind, then the roster's bits. */
  [[nodiscard]] std::vector<std::uint8_t> EncodeRosterMessage(const wire::SRoster& roster);
  /** Empty unless `message` is a whole `Roster`. */
  [[nodiscard]] std::optional<wire::SRoster> DecodeRosterMessage(std::span<const std::uint8_t> message);

  /** The same clients, names, sources, rates, connection and votes; ping and quiet time may differ. */
  [[nodiscard]] bool SameBesidesTimes(const wire::SRoster& a, const wire::SRoster& b) noexcept;

  /** The `Chat` message: its kind, a varint client index (the addressee from a player, the sender from the server), the payload. */
  [[nodiscard]] std::vector<std::uint8_t> EncodeChatMessage(int clientIndex, std::span<const std::uint8_t> payload);
  /** False unless `message` is a whole `Chat` with an index under `wire::SRoster::kMaxEntries` and at most `kMaxChatBytes`. */
  [[nodiscard]] bool DecodeChatMessage(std::span<const std::uint8_t> message, int& clientIndex, std::span<const std::uint8_t>& payload);

  /**
   * How much chat one player may send through the server: `kBurst` at once, then `kPerSecond`. A player's game sends a
   * line to each addressee, so a line to everyone in a 16-player game is 15 messages.
   */
  class CChatBudget
  {
  public:
    static constexpr double kPerSecond = 40.0;
    static constexpr double kBurst = 80.0;

    /** Takes one message at `nowUs` if the budget has it. */
    [[nodiscard]] bool Take(std::uint64_t nowUs) noexcept;

  private:
    double mTokens = kBurst;
    std::uint64_t mLastUs = 0;
    bool mStarted = false;
  };
} // namespace faf::remote
