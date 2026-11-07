#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <span>
#include <utility>
#include <vector>

#include "server/LobbyScriptData.h"

// Engine addition, dedicated server (plan WP2.13, WPR.51; design research/WP2.13-lobby-relay-design.md): the rules
// of the lobby relay. Before launch each participant's `CLobby` talks to every other one over a virtual connection
// through the server's channel (`ESeatMessage::Lobby`); this decides what each frame a player sends becomes:
// relayed to another participant with the sender written by the server, handed to the server as the lobby's host,
// or dropped. Only participants of the match, a size cap per message and a rate cap per sender (bytes and messages,
// each a token bucket), and nothing once the game has launched. No sockets: `CServerNet` sends what it returns.
//
// Plan WPR.49: the logical host can't take a participant out of the match or change what the match pins. Every
// participant is one the match names, so an eject (`LOBMSG_Rejected`, which `CLobby::KickPeer` sends, and
// `LOBMSG_DeletePeer`) never reaches anyone; and the match's pinned game options are written over whatever a message
// carries for them (LobbyScriptData.h), so nobody's lobby shows other values than the game will be launched with.

namespace faf::server
{
  struct SLobbyRelayLimits
  {
    std::size_t maxMessageBytes = 16u * 1024u; // one lobby message; FAF's largest, the game options, is a few KB
    double bytesPerSecond = 32.0 * 1024.0;     // a sender's sustained rate
    double burstBytes = 256.0 * 1024.0;        // what a sender may send at once (joining sends a burst)
    double messagesPerSecond = 60.0;
    double burstMessages = 400.0;
  };

  enum class ELobbyRelayVerdict : std::uint8_t
  {
    Forward,       // `out` goes to `to`
    ToServer,      // the message is for the server itself (uid 0)
    Closed,        // the game has launched
    UnknownSender, // not a participant of the match
    UnknownTarget, // the uid it is for isn't one, or is the sender
    TooLarge,
    TooFast,       // past the sender's rate
    Malformed,     // no uid, or no message after it
    EjectIgnored,  // plan WPR.49: an eject of a participant of the match
    Count
  };

  class CLobbyRelay
  {
  public:
    explicit CLobbyRelay(const SLobbyRelayLimits& limits = {});

    void AddParticipant(std::int32_t uid);
    void RemoveParticipant(std::int32_t uid);
    [[nodiscard]] bool IsParticipant(std::int32_t uid) const;
    /** At launch: every frame from now on is `Closed`. */
    void Close() noexcept { mOpen = false; }
    [[nodiscard]] bool Open() const noexcept { return mOpen; }
    /** Plan WPR.49: the game options the match pins, which no participant's message changes. */
    void PinOptions(SPinnedOptions pinned) { mPinned = std::move(pinned); }

    /**
     * A `Lobby` frame's body from `from` (varint uid it is for, then the message) at `nowUs`. With `Forward`, `to`
     * is the participant and `out` the whole frame for them (`ESeatMessage::Lobby`, varint `from`, the message, with the
     * match's pinned options written back into script data); with `ToServer`, `message` is the lobby message for the
     * server. Counted by verdict either way.
     */
    [[nodiscard]] ELobbyRelayVerdict Take(
      std::int32_t from, std::span<const std::uint8_t> body, std::uint64_t nowUs, std::int32_t& to, std::vector<std::uint8_t>& out,
      std::span<const std::uint8_t>& message
    );

    /** The frame for `to` carrying a message from the server itself (uid 0). */
    [[nodiscard]] static std::vector<std::uint8_t> FrameFromServer(std::span<const std::uint8_t> message);

    [[nodiscard]] std::uint64_t Count(ELobbyRelayVerdict verdict) const noexcept { return mCounts[static_cast<std::size_t>(verdict)]; }
    /** Forwarded messages whose pinned options were written back. */
    [[nodiscard]] std::uint64_t OptionsPinned() const noexcept { return mOptionsPinned; }

  private:
    struct SBucket
    {
      double bytes = 0.0;
      double messages = 0.0;
      std::uint64_t lastUs = 0;
    };

    SLobbyRelayLimits mLimits;
    std::map<std::int32_t, SBucket> mSenders;
    bool mOpen = true;
    SPinnedOptions mPinned;
    std::vector<std::uint8_t> mPayload;
    std::uint64_t mOptionsPinned = 0;
    std::uint64_t mCounts[static_cast<std::size_t>(ELobbyRelayVerdict::Count)]{};
  };
} // namespace faf::server
