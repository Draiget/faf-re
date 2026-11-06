#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <vector>

#include "remote/net/Handshake.h"
#include "remote/net/NetChannel.h"
#include "remote/net/UdpSocket.h"

// Engine addition, net channel (plan WP10.1, WP10.5): the two ends of a game's links, handshake and
// channels over one UDP socket. No engine dependency and no thread: the owner pumps them. Who holds a
// token may hold a channel; what the bytes on it mean is up to the owner.

namespace faf::remote::net
{
  /** The first byte of each message between a player and a game server. */
  enum class ESeatMessage : std::uint8_t
  {
    /** Player to server, reliable: one command, as the sim's stream has it (type, size, payload). */
    Command = 1,
    /** Player to server, reliable: the game is loaded. */
    Loaded = 2,
    /** Player to server, reliable: leaving for good. */
    Leaving = 3,
    /** Server to player, unreliable: the newest beat, varint. */
    Beat = 4,
    /**
     * Server to player, reliable, one per beat: varints beat, entities in the player's own frame and in their team's,
     * then the own frame, team frame (empty without one), army, grid and Lua lanes, each a varint size and its bytes
     * (remote/ViewLanes.h). The player's client holds both frames; a blip of the player's own unit is theirs to leave out.
     * An empty team frame means none: a player cut from their team drops what they held of it. After a reconnect the
     * first view's frames are whole (no baseline), and so are its army and grid lanes.
     */
    View = 5,
    /**
     * Server to player, reliable, before any view: the map's size, x and z, as two 32-bit floats, then the
     * player's army (-1: none) and command source, as two 32-bit integers. Again after a reconnect.
     */
    GameInfo = 6,
    /**
     * Server to player, reliable, one per command in the order sent: varint the beat it went in (0 if it
     * didn't), then an `ECommandAnswer` byte.
     */
    CommandAnswer = 7,
  };

  /** What became of a player's command. */
  enum class ECommandAnswer : std::uint8_t
  {
    Applied = 0,
    /** A kind of command a player may not send, or the seat has ended. */
    Refused = 1,
    /** It doesn't decode, or names an id the player's view was never given. */
    Dropped = 2,
  };

  struct SGameLinkStats
  {
    std::uint64_t datagramsIn = 0;
    /** Not ours, or a channel datagram from an address with no channel. */
    std::uint64_t strangersDropped = 0;
    /** Handshakes past the rate limit. */
    std::uint64_t handshakesLimited = 0;
    std::uint64_t badCookies = 0;
    std::uint64_t refused = 0;
  };

  /** A game server's end: one channel per player in the match. */
  class CServerLinks
  {
  public:
    class IEvents
    {
    public:
      virtual ~IEvents() = default;
      /** `returning`: the uid had a channel before. */
      virtual void OnJoined(std::int32_t uid, const SEndpoint& from, bool returning) = 0;
      virtual void OnMessage(std::int32_t uid, const std::vector<std::uint8_t>& message) = 0;
      /** Nothing has arrived for the channel's timeout. Its seat is the owner's business; the uid may still return. */
      virtual void OnLost(std::int32_t uid) = 0;
    };

    /** Handshakes a second at most, so a flood can't take the whole CPU in key exchanges. */
    static constexpr double kHandshakesPerSecond = 200.0;

    explicit CServerLinks(const ChannelConfig& channel = {});

    [[nodiscard]] bool Open(const SEndpoint& local, std::string& error);
    [[nodiscard]] SEndpoint Local() const noexcept { return mSocket.Local(); }

    void AddPlayer(std::int32_t uid, const Token& token);
    /** No more handshakes for this uid, and its channel is gone. */
    void RemovePlayer(std::int32_t uid);

    /** Takes what has arrived, tells `events`, and sends what's due. */
    void Pump(std::uint64_t nowUs, IEvents& events);
    void Wait(int milliseconds) noexcept { mSocket.Wait(milliseconds); }

    bool SendReliable(std::int32_t uid, const void* data, std::size_t size);
    /** To every player with a live channel. */
    void SendUnreliableToAll(const void* data, std::size_t size);

    [[nodiscard]] const SGameLinkStats& Stats() const noexcept { return mStats; }
    [[nodiscard]] const ChannelStats* StatsOf(std::int32_t uid) const;
    /** Reliable bytes the uid hasn't acknowledged. */
    [[nodiscard]] std::uint64_t ReliableUnacked(std::int32_t uid) const;

  private:
    struct SPlayer
    {
      Token token{};
      std::unique_ptr<NetChannel> channel;
      SEndpoint from;
      PublicKey clientPublic{};
      std::vector<PublicKey> usedPublics;
      std::vector<std::uint8_t> accept;
      bool lost = false;
    };

    void HandleDatagram(const std::uint8_t* data, std::size_t size, const SEndpoint& from, std::uint64_t nowUs, IEvents& events);
    void HandleConnect(const std::uint8_t* data, std::size_t size, const SEndpoint& from, std::uint64_t nowUs, IEvents& events);
    [[nodiscard]] bool TakeHandshakeBudget(std::uint64_t nowUs) noexcept;

    ChannelConfig mChannelConfig;
    CUdpSocket mSocket;
    CCookieJar mCookies;
    std::map<std::int32_t, SPlayer> mPlayers;
    std::unordered_map<std::uint64_t, std::int32_t> mByAddress;
    SGameLinkStats mStats;
    double mHandshakeBudget = kHandshakesPerSecond;
    std::uint64_t mHandshakeBudgetUs = 0;
    std::vector<std::vector<std::uint8_t>> mOut;
    std::vector<std::uint8_t> mMessage;
  };

  /** A player's end. */
  class CClientLink
  {
  public:
    enum class EState
    {
      Connecting,
      Connected,
      Refused,
      /** The channel timed out or failed. */
      Lost,
    };

    /** The handshake's repeat period while no answer comes. */
    static constexpr std::uint64_t kRetryUs = 250'000u;

    CClientLink(std::int32_t uid, const Token& token, const SEndpoint& server, const ChannelConfig& channel = {});

    [[nodiscard]] bool Open(std::string& error);
    /** Starts a new session with new keys, as after a lost link or a restart. */
    void Reconnect();

    void Pump(std::uint64_t nowUs);
    void Wait(int milliseconds) noexcept { mSocket.Wait(milliseconds); }

    [[nodiscard]] EState State() const noexcept { return mState; }
    [[nodiscard]] std::optional<EHandshakeRefusal> Refusal() const noexcept { return mRefusal; }

    bool SendReliable(const void* data, std::size_t size);
    bool TakeUnreliable(std::vector<std::uint8_t>& out);
    bool TakeReliable(std::vector<std::uint8_t>& out);

  private:
    std::int32_t mUid;
    Token mToken;
    SEndpoint mServer;
    ChannelConfig mChannelConfig;
    CUdpSocket mSocket;
    std::unique_ptr<CClientHandshake> mHandshake;
    std::unique_ptr<NetChannel> mChannel;
    std::vector<std::uint8_t> mConnect;
    EState mState = EState::Connecting;
    std::optional<EHandshakeRefusal> mRefusal;
    std::uint64_t mNextSendUs = 0;
    std::vector<std::vector<std::uint8_t>> mOut;
  };
} // namespace faf::remote::net
