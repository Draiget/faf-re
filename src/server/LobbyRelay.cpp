#include "server/LobbyRelay.h"

#include <algorithm>

#include "moho/net/ELobbyMsg.h"
#include "remote/net/Datagram.h"
#include "remote/net/GameLinks.h"

// Engine addition, dedicated server: see LobbyRelay.h.

namespace faf::server
{
  namespace
  {
    // A `CLobby` message: its type, then its whole size in 16 bits (moho/net/CMessage.h), then the payload.
    constexpr std::size_t kMessageHeaderBytes = 3u;

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

    // Plan WPR.49: what the relay reads of a `CLobby` message (type, 16-bit whole size, payload): its type.
    const std::uint8_t type = message[0];
    bool eject = false;
    if (type == static_cast<std::uint8_t>(moho::ELobbyMsg::LOBMSG_Rejected) || type == static_cast<std::uint8_t>(moho::ELobbyMsg::LOBMSG_DeletePeer)) {
      // Plan WP17.1: only a player-hosted lobby's current host ejects.
      if (mControl != ELobbyControl::Player || mHost == 0 || from != mHost) {
        return verdict(ELobbyRelayVerdict::EjectIgnored);
      }
      eject = true;
    }
    std::span<const std::uint8_t> forwarded = message;
    const bool script = type == static_cast<std::uint8_t>(moho::ELobbyMsg::LOBMSG_BroadcastScriptData)
                        || type == static_cast<std::uint8_t>(moho::ELobbyMsg::LOBMSG_DirectScriptData);
    if (mControl == ELobbyControl::Organiser && from != mHost && script && message.size() > kMessageHeaderBytes) {
      // Plan WP17.6: what the organiser set stays; a player chats, readies up and leaves.
      mPayload.assign(message.begin() + kMessageHeaderBytes, message.end());
      const EPlayerScript limited = LimitPlayerScript(mPayload);
      if (limited == EPlayerScript::Refused) {
        return verdict(ELobbyRelayVerdict::Locked);
      }
      if (limited == EPlayerScript::Rewritten) {
        const std::size_t size = kMessageHeaderBytes + mPayload.size();
        mPayload.insert(mPayload.begin(), {type, static_cast<std::uint8_t>(size), static_cast<std::uint8_t>(size >> 8u)});
        forwarded = mPayload;
        ++mPlayerOptionsLimited;
      }
    }
    if (mControl == ELobbyControl::Organiser && !mPinned.empty() && forwarded.data() == message.data() && message.size() > kMessageHeaderBytes
        && (type == static_cast<std::uint8_t>(moho::ELobbyMsg::LOBMSG_BroadcastScriptData)
            || type == static_cast<std::uint8_t>(moho::ELobbyMsg::LOBMSG_DirectScriptData))) {
      mPayload.assign(message.begin() + kMessageHeaderBytes, message.end());
      if (PinGameOptions(mPayload, mPinned)) {
        const std::size_t size = kMessageHeaderBytes + mPayload.size();
        if (size > 0xFFFFu || size > mLimits.maxMessageBytes) {
          return verdict(ELobbyRelayVerdict::TooLarge);
        }
        mPayload.insert(mPayload.begin(), {type, static_cast<std::uint8_t>(size), static_cast<std::uint8_t>(size >> 8u)});
        forwarded = mPayload;
        ++mOptionsPinned;
      }
    }

    // Plan WP17.2: who sits in which lobby slot, as the host says it, and who is ready, as the PlayerOptions (after
    // this relay's limits) say it.
    if (script && forwarded.size() > kMessageHeaderBytes) {
      const SLobbyFacts facts = ReadLobbyFacts(forwarded.subspan(kMessageHeaderBytes));
      if (from == mHost) {
        for (const auto& [owner, slot] : facts.seats) {
          mLobbySlots[owner] = slot;
        }
      }
      if (facts.ready) {
        // A player sets only their own slot (lobby.lua refuses the rest); the host sets any (everyone's Ready goes
        // false when the options change), so its message counts for the slot's owner.
        std::int32_t owner = from;
        if (from == mHost && facts.slot) {
          const auto seated = std::find_if(mLobbySlots.begin(), mLobbySlots.end(), [&facts](const auto& entry) { return entry.second == *facts.slot; });
          owner = seated == mLobbySlots.end() ? 0 : seated->first;
        }
        if (owner != 0) {
          const auto [entry, added] = mReady.try_emplace(owner, *facts.ready);
          if (added || entry->second != *facts.ready) {
            entry->second = *facts.ready;
            mReadyChanges.emplace_back(owner, *facts.ready);
          }
        }
      }
    }
    to = targetUid;
    out.clear();
    remote::net::ByteWriter writer(out);
    writer.Byte(static_cast<std::uint8_t>(remote::net::ESeatMessage::Lobby));
    writer.Varint(static_cast<std::uint64_t>(from));
    writer.Bytes(forwarded.data(), forwarded.size());
    return verdict(eject ? ELobbyRelayVerdict::EjectForwarded : ELobbyRelayVerdict::Forward);
  }

  std::optional<ELobbyControl> ReadLobbyControl(const std::string_view text) noexcept
  {
    if (text == "organiser") {
      return ELobbyControl::Organiser;
    }
    if (text == "player") {
      return ELobbyControl::Player;
    }
    return std::nullopt;
  }

  std::vector<std::uint8_t> CLobbyRelay::FrameFromServer(const std::span<const std::uint8_t> message)
  {
    return FrameFrom(0, message);
  }

  std::vector<std::uint8_t> CLobbyRelay::FrameFrom(const std::int32_t from, const std::span<const std::uint8_t> message)
  {
    std::vector<std::uint8_t> out;
    remote::net::ByteWriter writer(out);
    writer.Byte(static_cast<std::uint8_t>(remote::net::ESeatMessage::Lobby));
    writer.Varint(static_cast<std::uint64_t>(from < 0 ? 0 : from));
    writer.Bytes(message.data(), message.size());
    return out;
  }
} // namespace faf::server
