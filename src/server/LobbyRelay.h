#pragma once

#include <cstddef>
#include <cstdint>
#include <map>
#include <optional>
#include <span>
#include <string_view>
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
//
// Plan WP17.1: those rules belong to an organised lobby (`MatchLobbyControl` "organiser", the default). In a lobby a
// player hosts ("player") the host keeps a host's powers: an eject from the current logical host goes through (and
// the server takes that participant out of the match), anyone else's is dropped, and nothing is pinned.

namespace faf::server
{
  /** Plan WP17.1: who controls a server lobby (the match file's `MatchLobbyControl`). */
  enum class ELobbyControl : std::uint8_t
  {
    Organiser, // nobody in it hosts: the match's options and slots hold (WPR.49)
    Player,    // the logical host changes options and ejects, as a host does
  };

  /** "organiser" or "player"; nothing for any other text. */
  [[nodiscard]] std::optional<ELobbyControl> ReadLobbyControl(std::string_view text) noexcept;

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
    EjectIgnored,  // plan WPR.49: an eject of a participant of the match (organised, or not from the host)
    EjectForwarded, // plan WP17.1: a player-hosted lobby's host ejects a participant: `out` goes to `to`, who is out
    Locked,        // plan WP17.6: an organiser-run lobby's player asked to move, change colour or sides, or set more than Ready
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
    /** Plan WP17.1: organised (the default) or player-hosted. */
    void SetControl(const ELobbyControl control) noexcept { mControl = control; }
    [[nodiscard]] ELobbyControl Control() const noexcept { return mControl; }
    /** The current logical host (0: none), whose ejects go through in a player-hosted lobby. */
    void SetHost(const std::int32_t uid) noexcept { mHost = uid; }

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
    /** Plan WP17.2: the frame for a participant carrying a message the server sends in `from`'s name (the lobby's
     * host, for what only a host may send: FAF lobby.lua takes `GameOptions` from the host alone). */
    [[nodiscard]] static std::vector<std::uint8_t> FrameFrom(std::int32_t from, std::span<const std::uint8_t> message);

    [[nodiscard]] std::uint64_t Count(ELobbyRelayVerdict verdict) const noexcept { return mCounts[static_cast<std::size_t>(verdict)]; }
    /** Forwarded messages whose pinned options were written back. */
    [[nodiscard]] std::uint64_t OptionsPinned() const noexcept { return mOptionsPinned; }
    /** Plan WP17.6: a player's own options that went on with only `Ready` left. */
    [[nodiscard]] std::uint64_t PlayerOptionsLimited() const noexcept { return mPlayerOptionsLimited; }
    /** Plan WP17.2: a participant's ready state as their own `PlayerOptions` last set it; nothing before they did. */
    [[nodiscard]] std::optional<bool> ReadyOf(const std::int32_t uid) const
    {
      const auto found = mReady.find(uid);
      return found == mReady.end() ? std::nullopt : std::optional<bool>(found->second);
    }
    /** Plan WP17.2: a participant's lobby slot as the host's lobby last said it (`SLobbyFacts::seats`); 0 before. */
    [[nodiscard]] int LobbySlotOf(const std::int32_t uid) const
    {
      const auto found = mLobbySlots.find(uid);
      return found == mLobbySlots.end() ? 0 : found->second;
    }
    /** The ready states that changed since the last call, in order. */
    [[nodiscard]] std::vector<std::pair<std::int32_t, bool>> TakeReadyChanges() { return std::exchange(mReadyChanges, {}); }

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
    ELobbyControl mControl = ELobbyControl::Organiser;
    std::int32_t mHost = 0;
    SPinnedOptions mPinned;
    std::vector<std::uint8_t> mPayload;
    std::uint64_t mOptionsPinned = 0;
    std::uint64_t mPlayerOptionsLimited = 0;
    std::map<std::int32_t, bool> mReady;
    std::map<std::int32_t, int> mLobbySlots;
    std::vector<std::pair<std::int32_t, bool>> mReadyChanges;
    std::uint64_t mCounts[static_cast<std::size_t>(ELobbyRelayVerdict::Count)]{};
  };
} // namespace faf::server
