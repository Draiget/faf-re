#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <map>
#include <memory>
#include <optional>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "remote/net/Handshake.h"
#include "remote/net/NetChannel.h"
#include "remote/net/StreamCompression.h"
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
     * (remote/ViewLanes.h). The player's client holds both frames; a blip of the player's own unit is theirs to leave
     * out. An empty team frame means none: a player cut from their team drops what they held of it. After a reconnect
     * the first view's frames are whole (no baseline), and so are its army and grid lanes. Then, when the server sends
     * them, the pose lane (wire/PoseLane.h) and the effects lane (wire/EffectLane.h), framed the same way. A client
     * skips lanes past the ones it knows (a varint size and its bytes each), to the message's last byte.
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
    /**
     * Server to player, reliable, after a beat's view every few beats (plan WPR.30): varint beat, then what the
     * player's client should hold after it, `wire::HashRecord` summed over its own frame and over its team's frame, as
     * two 64-bit integers (the second 0 without a team frame).
     */
    ViewCheck = 8,
    /** Player to server, reliable: its frames didn't match a `ViewCheck`; it wants its next view whole. */
    ViewMismatch = 9,
    /**
     * Both ways, reliable, before the game launches (plan WP2.13): one lobby (`CLobby`) message on the virtual
     * connection between two participants. Player to server: varint the uid it is for, then the message. Server to
     * player: varint the uid it is from, then the message; the server writes the sender itself, so no player chooses
     * whom a message seems to come from. Uid 0 is the server itself, whose messages are lobby signals
     * (LobbySignals.h), as FAF's lobby server sends a game over GPGNet.
     */
    Lobby = 10,
    /**
     * Server to player, reliable, before `GameInfo` (plan WPR.55): the game's configuration as the server launched it
     * (the table `CLobby.LaunchGame` takes: scenario, armies, options, mods), in the lobby's Lua byte form
     * (`LuaObject::ToByteStream`). A client takes its launch from this, never from the lobby's own Launch message.
     * Again after a reconnect, with `GameInfo`.
     */
    LaunchInfo = 11,
    /**
     * Server to player, reliable (plan WP11): varint beat, then that beat's Lua lane (wire/LuaSyncLane.h: the player's
     * `Sync` table and print lines), sent once `Sim::Sync` has written and routed the beat's table. A `View`'s own Lua
     * lane is then empty: it is built in `Sim::Sync`'s entity walk, before the table exists. It may come before or
     * after the beat's `View` (the views' pipeline), never after the next beat's: a client with the next `View` and no
     * `LuaSync` for a beat has none coming.
     */
    LuaSync = 12,
    /**
     * Server to player, reliable (plan WP11 step 4): varint beat, a flags byte (1: reset), then a session-table record
     * (wire/SessionTables.h: new sounds, names, deposits and terrain edits) to the message's end. It comes before
     * the first `View` that names its entries. Reset: the client forgets its tables; the session's every record
     * follows, from the first, before the whole view a returning player gets (a reset carries no record itself).
     */
    SessionTables = 13,
    /**
     * Player to server, reliable, once its game has loaded the launch's rules and before `Loaded` (plan WP2.6): what
     * its game data and mods are, as remote/ContentCheck.h hashes them: two 64-bit integers, the blueprint tables'
     * hash, then the mod set's. The server compares them with its own and refuses or warns as the match says.
     */
    ContentReport = 14,
    /**
     * Server to player, reliable, once the player's launch has gone and then whenever it changes (plan WP11.4): the
     * session's clients as `wire::SRoster` (remote/SeatRoster.h), the receiver's own entry named by its `localIndex`.
     * Who is there, their names, sources and connection go at once; ping and quiet time at most once a second.
     * Again after a reconnect.
     */
    Roster = 15,
    /**
     * Both ways, reliable (plan WP11.4): one chat message. Player to server: varint the client index it is for, then
     * the payload as the game's chat sends it (`IClient::ReceiveChat`). Server to player: varint the sender's client
     * index, written by the server, then the payload. The server drops one for no player, too large or too many.
     */
    Chat = 16,
    /**
     * Player to server, reliable, after `ContentReport` (plan WP17.8): varint count, then per mod a kind byte (0 sim,
     * 1 UI), its uid and its version, each a varint length and its bytes. UI mods load only in the player's own game,
     * so the server takes them as reported.
     */
    ModReport = 17,
    /**
     * Player to server, reliable (plan WP10.7): varint (speed limit + 10). The player's sim-speed limit: the speed step
     * its game keeps up with, from what applying the server's views costs it (remote/SpeedLimit.h), as a lockstep
     * client's `CLIMSG_IntParam` reports its sim's. Sent when it changes. The server runs at the slowest playing
     * seat's.
     */
    SpeedLimit = 18,
    /**
     * Both ways, reliable (plan WP11.1): varint (army + 1). Player to server: the army its UI asks to focus on
     * (`SetArmyIndex`, from `SetFocusArmy`; -1 none). Server to player: the army the server grants, which the client
     * shows from then on: the player's own, or with `DefeatedPlayerView = "observe"` after their defeat whatever they
     * asked (remote/FocusAndCameras.h).
     */
    FocusArmy = 19,
    /**
     * Player to server, reliable (plan WP11.1): the player's cameras (`SetGeomCams`) at most every 250 ms: varint
     * count, then per camera its view-projection and LOD scale as 17 floats. Kept per seat for camera-ordered work
     * (WP8.2).
     */
    Cameras = 20,
    /**
     * Player to server, reliable, the first message on each new channel (plan WP10.13, StreamCompression.h): varint
     * format (1), then a byte, the largest zstd window (log 2) the player's decoder takes. The player's client decodes
     * `Compressed` messages from then on. Taken by the links (`CServerLinks`), never handed to the server's owner.
     */
    CompressOffer = 21,
    /**
     * Server to player, reliable (plan WP10.13), only on a channel whose player offered: varint the message's size,
     * then the next piece of the channel's zstd stream, which decodes to that message (any other kind above).
     * `CClientLink::TakeReliable` hands out the message it holds.
     */
    Compressed = 22,
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
    /** Handshakes past their address's own limit. */
    std::uint64_t addressLimited = 0;
    /** With an allowlist: datagrams from an address not on it, past the budget such addresses share. */
    std::uint64_t unlistedDropped = 0;
    std::uint64_t badCookies = 0;
    std::uint64_t refused = 0;
    /** Plan WP10.13: compression offers taken (one per channel), and those not taken (compression off, a repeat). */
    std::uint64_t compressOffers = 0;
    std::uint64_t compressOffersIgnored = 0;
    /** Compressors that failed (zstd); their channel sends the rest as it is. */
    std::uint64_t compressFailures = 0;
  };

  /**
   * Plan WP10.13: what the server sent one player on the reliable stream, over every channel it had. `messageBytes`
   * are the messages as given; `streamBytes` what went into the stream for them (`Compressed` messages for those that
   * were compressed, the rest as they are). The datagrams add the stream's framing, headers, acks and resends.
   */
  struct SLinkTraffic
  {
    std::uint64_t messages = 0;
    std::uint64_t messageBytes = 0;
    std::uint64_t streamBytes = 0;
    std::uint64_t compressedMessages = 0;
    std::uint64_t compressedMessageBytes = 0; // those messages as given
    std::uint64_t compressedStreamBytes = 0;  // and as `Compressed` messages
    /** Time in the compressor, on the thread that sends. */
    std::uint64_t compressNs = 0;
    /** The channels' datagrams out (`ChannelStats`), the live one's included. */
    std::uint64_t datagramsSent = 0;
    std::uint64_t datagramBytesSent = 0;
    std::uint64_t channels = 0;
    std::uint64_t compressedChannels = 0;
    /** The live channel's compressor (`ZSTD_sizeof_CCtx`); 0 without one. */
    std::uint64_t compressorBytes = 0;
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
    /**
     * Plan WPR.28: handshakes a second from one address, after a burst, so one address can't spend everyone's
     * budget. Players behind one router share an address, so it allows a whole game rejoining at once. Kept in a
     * fixed table by a salted hash of the address: no state grows with the addresses a flood comes from.
     */
    static constexpr double kHandshakesPerAddressPerSecond = 16.0;
    static constexpr double kHandshakeBurstPerAddress = 64.0;
    /** Plan WPR.48: with an allowlist, handshakes a second from every address not on it together. */
    static constexpr double kUnlistedHandshakesPerSecond = 20.0;

    explicit CServerLinks(const ChannelConfig& channel = {});

    [[nodiscard]] bool Open(const SEndpoint& local, std::string& error);
    [[nodiscard]] SEndpoint Local() const noexcept
    {
      return mSocket.Local();
    }

    /**
     * Plan WPR.45, WPR.48: from the first call on, only datagrams from these addresses (any port) reach the handshake
     * at the normal budget. The rest share `kUnlistedHandshakesPerSecond`, so a player behind a VPN, whose address
     * the match didn't know, still gets in with a valid token, and their address is then listed. Without any call,
     * every address is treated as listed.
     */
    void AllowAddress(std::uint32_t ip);
    /** Plan WP17.2: off the allowlist again (it shares the unlisted budget from now on); the list stays on. */
    void DisallowAddress(std::uint32_t ip);

    void AddPlayer(std::int32_t uid, const Token& token);
    /** No more handshakes for this uid, and its channel is gone. */
    void RemovePlayer(std::int32_t uid);

    /** Takes what has arrived, tells `events`, and sends what's due. */
    void Pump(std::uint64_t nowUs, IEvents& events);
    void Wait(
      int milliseconds
    ) noexcept
    {
      mSocket.Wait(milliseconds);
    }

    /**
     * Plan WP10.13: from the next channel on, a player whose client offers it gets the server's reliable messages
     * compressed (StreamCompression.h) at this zstd level; 0 (the default) sends them as they are.
     */
    void SetCompression(
      const int level
    ) noexcept
    {
      mCompressionLevel = level;
    }

    /**
     * `streamBytes`: what went into the stream, the message as `Compressed` when it was compressed. On the thread
     * that pumps.
     */
    bool SendReliable(std::int32_t uid, const void* data, std::size_t size, std::size_t* streamBytes = nullptr);
    /** To every player with a live channel. */
    void SendUnreliableToAll(const void* data, std::size_t size);

    [[nodiscard]] const SGameLinkStats& Stats() const noexcept
    {
      return mStats;
    }
    [[nodiscard]] const ChannelStats* StatsOf(std::int32_t uid) const;
    /** Plan WP10.13: what a uid was sent over all its channels, also after it was removed; zeros for a stranger. */
    [[nodiscard]] SLinkTraffic TrafficOf(std::int32_t uid) const;
    /** Whether the uid's live channel compresses (its client offered, and compression is on). */
    [[nodiscard]] bool Compresses(std::int32_t uid) const;
    /** Reliable bytes the uid hasn't acknowledged. */
    [[nodiscard]] std::uint64_t ReliableUnacked(std::int32_t uid) const;
    /**
     * Plan WPR.50: how long nothing has arrived from the uid's channel, at `nowUs` (`Pump`'s clock); 0 without a
     * channel. A live client's keepalives come every quarter second.
     */
    [[nodiscard]] std::uint64_t SilentUs(std::int32_t uid, std::uint64_t nowUs) const;

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
      // Plan WP10.13: the live channel's compressor, once its client offered; none before, or with compression off.
      std::unique_ptr<CStreamCompressor> compressor;
      bool offerSeen = false; // on the live channel
    };

    /** The channel goes (replaced, taken by another, removed): its counts into the uid's traffic, its compressor too.
     */
    void RetireChannel(std::int32_t uid, SPlayer& player);
    /** Plan WP10.13: a `CompressOffer` from the uid's live channel. */
    void TakeCompressOffer(std::int32_t uid, SPlayer& player, const std::vector<std::uint8_t>& message);

    void HandleDatagram(
      const std::uint8_t* data,
      std::size_t size,
      const SEndpoint& from,
      std::uint64_t nowUs,
      IEvents& events
    );
    void HandleConnect(
      const std::uint8_t* data,
      std::size_t size,
      const SEndpoint& from,
      std::uint64_t nowUs,
      IEvents& events
    );
    [[nodiscard]] bool TakeHandshakeBudget(std::uint64_t nowUs) noexcept;
    /** One address's own budget (`kHandshakesPerAddressPerSecond`). */
    [[nodiscard]] bool TakeAddressBudget(std::uint32_t ip, std::uint64_t nowUs) noexcept;
    [[nodiscard]] bool TakeUnlistedBudget(std::uint64_t nowUs) noexcept;

    struct SAddressBucket
    {
      double tokens = kHandshakeBurstPerAddress;
      std::uint64_t lastUs = 0;
    };
    static constexpr std::size_t kAddressBuckets = 4096;

    ChannelConfig mChannelConfig;
    CUdpSocket mSocket;
    CCookieJar mCookies;
    std::map<std::int32_t, SPlayer> mPlayers;
    std::unordered_map<std::uint64_t, std::int32_t> mByAddress;
    SGameLinkStats mStats;
    double mHandshakeBudget = kHandshakesPerSecond;
    std::uint64_t mHandshakeBudgetUs = 0;
    std::array<SAddressBucket, kAddressBuckets> mAddressBuckets{};
    std::uint64_t mAddressSalt = 0;
    bool mAllowlistOn = false;
    std::unordered_set<std::uint32_t> mAllowed;
    double mUnlistedBudget = kUnlistedHandshakesPerSecond;
    std::uint64_t mUnlistedBudgetUs = 0;
    std::vector<std::vector<std::uint8_t>> mOut;
    std::vector<std::uint8_t> mMessage;
    int mCompressionLevel = 0;                     // plan WP10.13
    std::map<std::int32_t, SLinkTraffic> mTraffic; // retired channels' and the sends so far, by uid
    std::vector<std::uint8_t> mCompressed;         // the message being sent, compressed
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
    void Wait(
      int milliseconds
    ) noexcept
    {
      mSocket.Wait(milliseconds);
    }

    [[nodiscard]] EState State() const noexcept
    {
      return mState;
    }
    [[nodiscard]] std::optional<EHandshakeRefusal> Refusal() const noexcept
    {
      return mRefusal;
    }

    bool SendReliable(const void* data, std::size_t size);
    bool TakeUnreliable(std::vector<std::uint8_t>& out);
    /** The next message, a `Compressed` one decoded (plan WP10.13). A message that doesn't decode loses the link. */
    bool TakeReliable(std::vector<std::uint8_t>& out);

    /**
     * Plan WP10.13: offer the server compression on each new channel (StreamCompression.h); on by default. Off, the
     * client is as one from before it: the server sends everything as it is. Takes effect at the next channel.
     */
    void SetCompressionOffer(
      const bool offer
    ) noexcept
    {
      mOfferCompression = offer;
    }

    /** Plan WP10.13: what came compressed, over every channel. */
    struct SCompressionStats
    {
      std::uint64_t messages = 0;
      std::uint64_t compressedBytes = 0; // as `Compressed` messages
      std::uint64_t messageBytes = 0;    // decoded
      std::uint64_t failures = 0;        // didn't decode (each lost the link)
      std::uint64_t decompressorBytes = 0;
    };
    [[nodiscard]] const SCompressionStats& CompressionStats() const noexcept
    {
      return mCompression;
    }

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
    bool mOfferCompression = true;
    std::unique_ptr<CStreamDecompressor> mDecompressor; // the live channel's, once offered
    std::vector<std::uint8_t> mPacked;
    SCompressionStats mCompression;
  };
} // namespace faf::remote::net
