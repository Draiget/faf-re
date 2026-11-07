#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

#include "remote/net/DatagramCipher.h"

// Engine addition, net channel (plan §7.1, WP10.5): how a player gets a channel on a game server.
// Pure logic: no socket and no clock of its own. Little-endian throughout, on datagrams starting
// with kHandshakeTag, which a channel datagram (kDatagramTag) never does.
//
//   client -> server  Hello      tag, type, version; padded to kHelloSize
//   server -> client  Challenge  tag, type, cookie
//   client -> server  Connect    tag, type, version, cookie, uid, client public key, proof
//   server -> client  Accept     tag, type, server public key, proof
//   server -> client  Reject     tag, type, reason
//
// The challenge keeps a forged source address from costing anything: answering a Hello stores nothing
// and sends less than it got, and only a sender who really receives at that address can return the
// cookie, a keyed hash of the address and the time. Only then does the server do the slow part.
//
// The token, the secret the player was issued for this match, never goes on the wire. It keys the
// proof in Connect, and it keys the channel's keys along with an X25519 exchange (fresh keys on both
// sides each time), so whoever doesn't hold the token can neither join nor sit in the middle.
// Someone who holds it can't read an earlier session either, as the exchange's secrets are gone.

namespace faf::remote::net
{
  inline constexpr std::uint8_t kHandshakeTag = 0xFB;
  inline constexpr std::uint16_t kHandshakeVersion = 1;
  inline constexpr std::size_t kHelloSize = 128;
  inline constexpr std::size_t kCookieSize = 16;
  inline constexpr std::size_t kProofSize = 16;
  inline constexpr std::size_t kPublicKeySize = 32;
  inline constexpr std::size_t kChallengeSize = 2 + kCookieSize;
  inline constexpr std::size_t kConnectSize = 2 + 2 + kCookieSize + 4 + kPublicKeySize + kProofSize;
  inline constexpr std::size_t kAcceptSize = 2 + kPublicKeySize + kProofSize;
  inline constexpr std::size_t kRejectSize = 3;

  enum class EHandshakeType : std::uint8_t
  {
    Hello = 1,
    Challenge = 2,
    Connect = 3,
    Accept = 4,
    Reject = 5,
  };

  enum class EHandshakeRefusal : std::uint8_t
  {
    /** Another protocol version: this client can't play here. */
    Version = 1,
    /** The uid isn't in this match, or the proof doesn't hold. */
    NotAdmitted = 2,
  };

  using PublicKey = std::array<std::uint8_t, kPublicKeySize>;
  using Token = std::array<std::uint8_t, kKeySize>;
  using Cookie = std::array<std::uint8_t, kCookieSize>;

  /** Secure random bytes from the system; false when it had none to give. */
  [[nodiscard]] bool FillRandom(void* out, std::size_t size) noexcept;

  /** What keys the handshake, from the text issued to the player. */
  [[nodiscard]] Token MakeToken(std::string_view text) noexcept;

  [[nodiscard]] std::vector<std::uint8_t> WriteHello();

  /** The type of a handshake datagram; empty when it isn't one. */
  [[nodiscard]] std::optional<EHandshakeType> HandshakeTypeOf(const std::uint8_t* data, std::size_t size) noexcept;

  /** The server's cookies. A cookie holds for 30 to 60 s. */
  class CCookieJar
  {
  public:
    static constexpr std::uint64_t kPeriodUs = 30'000'000u;

    /** False when the system gave no random secret; then no cookie can be trusted. */
    [[nodiscard]] bool Init() noexcept;
    [[nodiscard]] Cookie Make(std::uint64_t addressKey, std::uint64_t nowUs) const noexcept;
    [[nodiscard]] bool Check(const Cookie& cookie, std::uint64_t addressKey, std::uint64_t nowUs) const noexcept;

  private:
    std::array<std::uint8_t, 32> mSecret{};
  };

  /** A Hello answered: its Challenge, or a Reject for another version. */
  [[nodiscard]] std::vector<std::uint8_t> AnswerHello(const std::uint8_t* data, std::size_t size, const CCookieJar& jar, std::uint64_t addressKey, std::uint64_t nowUs);

  struct SConnectRequest
  {
    Cookie cookie{};
    std::int32_t uid = 0;
    PublicKey clientPublic{};
    std::array<std::uint8_t, kProofSize> proof{};
  };

  /** False when it's the wrong size or version, or not a Connect. */
  [[nodiscard]] bool ReadConnect(const std::uint8_t* data, std::size_t size, SConnectRequest& out) noexcept;

  struct SServerSession
  {
    ChannelKeys keys;
    std::vector<std::uint8_t> accept;
  };

  /** A Connect whose cookie held, and the uid's token: empty when the proof doesn't hold or the exchange is degenerate. */
  [[nodiscard]] std::optional<SServerSession> AnswerConnect(const SConnectRequest& request, const Token& token);

  [[nodiscard]] std::vector<std::uint8_t> WriteReject(EHandshakeRefusal why);

  /** A client's side of it. */
  class CClientHandshake
  {
  public:
    CClientHandshake(std::int32_t uid, const Token& token) noexcept;
    ~CClientHandshake();
    CClientHandshake(const CClientHandshake&) = delete;
    CClientHandshake& operator=(const CClientHandshake&) = delete;

    /** The Connect for a Challenge, which later Challenges repeat. Empty when it isn't a Challenge or no random came. */
    [[nodiscard]] std::vector<std::uint8_t> OnChallenge(const std::uint8_t* data, std::size_t size);
    /** The channel's keys from an Accept; empty when it isn't one for this Connect. */
    [[nodiscard]] std::optional<ChannelKeys> OnAccept(const std::uint8_t* data, std::size_t size) const;

  private:
    std::int32_t mUid;
    Token mToken;
    std::array<std::uint8_t, kPublicKeySize> mSecret{};
    PublicKey mPublic{};
    bool mHaveKeys = false;
  };
} // namespace faf::remote::net
