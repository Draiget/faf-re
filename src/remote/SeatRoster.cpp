#include "remote/SeatRoster.h"

#include <algorithm>

#include "remote/net/GameLinks.h"

// Engine addition, server mode: see SeatRoster.h.

namespace faf::remote
{
  std::vector<std::uint8_t> EncodeRosterMessage(const wire::SRoster& roster)
  {
    wire::BitWriter writer;
    roster.Encode(writer);
    const std::span<const std::uint8_t> bits = writer.Bytes();
    std::vector<std::uint8_t> message;
    message.reserve(1u + bits.size());
    message.push_back(static_cast<std::uint8_t>(net::ESeatMessage::Roster));
    message.insert(message.end(), bits.begin(), bits.end());
    return message;
  }

  std::optional<wire::SRoster> DecodeRosterMessage(const std::span<const std::uint8_t> message)
  {
    if (message.empty() || message[0] != static_cast<std::uint8_t>(net::ESeatMessage::Roster)) {
      return std::nullopt;
    }
    wire::BitReader reader(message.subspan(1));
    return wire::SRoster::Decode(reader);
  }

  bool SameBesidesTimes(const wire::SRoster& a, const wire::SRoster& b) noexcept
  {
    if (a.localIndex != b.localIndex || a.entries.size() != b.entries.size()) {
      return false;
    }
    for (std::size_t i = 0; i < a.entries.size(); ++i) {
      wire::SRosterEntry left = a.entries[i];
      left.ping = b.entries[i].ping;
      left.quiet = b.entries[i].quiet;
      if (!(left == b.entries[i])) {
        return false;
      }
    }
    return true;
  }

  std::vector<std::uint8_t> EncodeChatMessage(const int clientIndex, const std::span<const std::uint8_t> payload)
  {
    std::vector<std::uint8_t> message;
    message.reserve(3u + payload.size());
    message.push_back(static_cast<std::uint8_t>(net::ESeatMessage::Chat));
    auto value = static_cast<std::uint32_t>(clientIndex < 0 ? 0 : clientIndex);
    do {
      const auto low = static_cast<std::uint8_t>(value & 0x7Fu);
      value >>= 7u;
      message.push_back(static_cast<std::uint8_t>(low | (value != 0u ? 0x80u : 0u)));
    } while (value != 0u);
    message.insert(message.end(), payload.begin(), payload.end());
    return message;
  }

  bool DecodeChatMessage(const std::span<const std::uint8_t> message, int& clientIndex, std::span<const std::uint8_t>& payload)
  {
    if (message.empty() || message[0] != static_cast<std::uint8_t>(net::ESeatMessage::Chat)) {
      return false;
    }
    std::uint32_t value = 0;
    std::size_t at = 1;
    for (unsigned shift = 0;; shift += 7u) {
      if (at >= message.size() || shift > 14u) {
        return false; // cut short, or more than an index needs
      }
      const std::uint8_t byte = message[at++];
      value |= static_cast<std::uint32_t>(byte & 0x7Fu) << shift;
      if ((byte & 0x80u) == 0u) {
        break;
      }
    }
    if (value >= wire::SRoster::kMaxEntries || message.size() - at > kMaxChatBytes) {
      return false;
    }
    clientIndex = static_cast<int>(value);
    payload = message.subspan(at);
    return true;
  }

  bool CChatBudget::Take(const std::uint64_t nowUs) noexcept
  {
    if (mStarted && nowUs > mLastUs) {
      mTokens = std::min(kBurst, mTokens + static_cast<double>(nowUs - mLastUs) * 1e-6 * kPerSecond);
    }
    mStarted = true;
    mLastUs = std::max(mLastUs, nowUs);
    if (mTokens < 1.0) {
      return false;
    }
    mTokens -= 1.0;
    return true;
  }
} // namespace faf::remote
