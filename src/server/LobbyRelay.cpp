#include "server/LobbyRelay.h"

#include <algorithm>

#include "remote/net/Datagram.h"
#include "remote/net/GameLinks.h"

// Engine addition, dedicated server: see LobbyRelay.h.

namespace faf::server
{
  namespace
  {
    /** A LEB128 uid at the start of `body`: its value and length, or false for none, one past 31 bits, or a long form. */
    [[nodiscard]] bool ReadUid(const std::span<const std::uint8_t> body, std::uint32_t& uid, std::size_t& length) noexcept
    {
      std::uint64_t value = 0;
      for (std::size_t i = 0; i < body.size() && i < 5u; ++i) {
        value |= static_cast<std::uint64_t>(body[i] & 0x7Fu) << (7u * i);
        if ((body[i] & 0x80u) == 0u) {
          length = i + 1u;
          // The shortest form only, so a uid has one spelling.
          if (value > 0x7FFFFFFFull || (length > 1u && body[i] == 0u)) {
            return false;
          }
          uid = static_cast<std::uint32_t>(value);
          return true;
        }
      }
      return false;
    }
  } // namespace

  CLobbyRelay::CLobbyRelay(const SLobbyRelayLimits& limits)
    : mLimits(limits)
  {}

  void CLobbyRelay::AddParticipant(const std::int32_t uid)
  {
    // A new sender starts with a full bucket: joining sends a burst (`Join`, then the peers' hellos).
    mSenders.try_emplace(uid, SBucket{mLimits.burstBytes, mLimits.burstMessages, 0u});
  }

  void CLobbyRelay::RemoveParticipant(const std::int32_t uid)
  {
    mSenders.erase(uid);
  }

  bool CLobbyRelay::IsParticipant(const std::int32_t uid) const
  {
    return mSenders.contains(uid);
  }

  ELobbyRelayVerdict CLobbyRelay::Take(
    const std::int32_t from, const std::span<const std::uint8_t> body, const std::uint64_t nowUs, std::int32_t& to,
    std::vector<std::uint8_t>& out, std::span<const std::uint8_t>& message
  )
  {
    const auto verdict = [this](const ELobbyRelayVerdict result) {
      ++mCounts[static_cast<std::size_t>(result)];
      return result;
    };
    if (!mOpen) {
      return verdict(ELobbyRelayVerdict::Closed);
    }
    const auto sender = mSenders.find(from);
    if (sender == mSenders.end()) {
      return verdict(ELobbyRelayVerdict::UnknownSender);
    }
    std::uint32_t target = 0;
    std::size_t length = 0;
    if (!ReadUid(body, target, length) || length >= body.size()) {
      return verdict(ELobbyRelayVerdict::Malformed);
    }
    message = body.subspan(length);
    if (message.size() > mLimits.maxMessageBytes) {
      return verdict(ELobbyRelayVerdict::TooLarge);
    }

    // The sender's buckets fill at their rates up to their bursts; each message takes one and its size.
    SBucket& bucket = sender->second;
    if (bucket.lastUs != 0u && nowUs > bucket.lastUs) {
      const double seconds = static_cast<double>(nowUs - bucket.lastUs) * 1e-6;
      bucket.bytes = std::min(mLimits.burstBytes, bucket.bytes + seconds * mLimits.bytesPerSecond);
      bucket.messages = std::min(mLimits.burstMessages, bucket.messages + seconds * mLimits.messagesPerSecond);
    }
    if (bucket.lastUs == 0u || nowUs > bucket.lastUs) {
      bucket.lastUs = nowUs;
    }
    const auto size = static_cast<double>(message.size());
    if (bucket.bytes < size || bucket.messages < 1.0) {
      return verdict(ELobbyRelayVerdict::TooFast);
    }
    bucket.bytes -= size;
    bucket.messages -= 1.0;

    if (target == 0u) {
      to = 0;
      return verdict(ELobbyRelayVerdict::ToServer);
    }
    const auto targetUid = static_cast<std::int32_t>(target);
    if (targetUid == from || !mSenders.contains(targetUid)) {
      return verdict(ELobbyRelayVerdict::UnknownTarget);
    }
    to = targetUid;
    out.clear();
    remote::net::ByteWriter writer(out);
    writer.Byte(static_cast<std::uint8_t>(remote::net::ESeatMessage::Lobby));
    writer.Varint(static_cast<std::uint64_t>(from));
    writer.Bytes(message.data(), message.size());
    return verdict(ELobbyRelayVerdict::Forward);
  }

  std::vector<std::uint8_t> CLobbyRelay::FrameFromServer(const std::span<const std::uint8_t> message)
  {
    std::vector<std::uint8_t> out;
    remote::net::ByteWriter writer(out);
    writer.Byte(static_cast<std::uint8_t>(remote::net::ESeatMessage::Lobby));
    writer.Varint(0u);
    writer.Bytes(message.data(), message.size());
    return out;
  }
} // namespace faf::server
