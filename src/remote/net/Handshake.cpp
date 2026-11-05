#include "remote/net/Handshake.h"

#include <algorithm>
#include <cstring>

#include "monocypher.h"

#if defined(_WIN32)
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif
// clang-format off
#include <windows.h>
#include <bcrypt.h>
// clang-format on
#else
#include <sys/random.h>
#endif

namespace faf::remote::net
{
  namespace
  {
    // Keeps what each hash is for apart, so no output of one can stand in for another.
    constexpr std::uint8_t kLabelProof = 1;
    constexpr std::uint8_t kLabelClientKey = 2;
    constexpr std::uint8_t kLabelServerKey = 3;
    constexpr std::uint8_t kLabelAccept = 4;
    constexpr std::uint8_t kLabelCookie = 5;

    void WriteU16(std::uint8_t* const out, const std::uint16_t value) noexcept
    {
      out[0] = static_cast<std::uint8_t>(value);
      out[1] = static_cast<std::uint8_t>(value >> 8);
    }

    [[nodiscard]] std::uint16_t ReadU16(const std::uint8_t* const in) noexcept
    {
      return static_cast<std::uint16_t>(in[0] | (in[1] << 8));
    }

    void WriteI32(std::uint8_t* const out, const std::int32_t value) noexcept
    {
      const auto bits = static_cast<std::uint32_t>(value);
      for (int i = 0; i < 4; ++i) {
        out[i] = static_cast<std::uint8_t>(bits >> (8 * i));
      }
    }

    [[nodiscard]] std::int32_t ReadI32(const std::uint8_t* const in) noexcept
    {
      std::uint32_t bits = 0;
      for (int i = 0; i < 4; ++i) {
        bits |= static_cast<std::uint32_t>(in[i]) << (8 * i);
      }
      return static_cast<std::int32_t>(bits);
    }

    [[nodiscard]] std::array<std::uint8_t, kProofSize> ConnectProof(const Token& token, const Cookie& cookie, const std::int32_t uid, const PublicKey& clientPublic) noexcept
    {
      std::array<std::uint8_t, 1 + kCookieSize + 4 + kPublicKeySize> message{};
      message[0] = kLabelProof;
      std::memcpy(message.data() + 1, cookie.data(), kCookieSize);
      WriteI32(message.data() + 1 + kCookieSize, uid);
      std::memcpy(message.data() + 1 + kCookieSize + 4, clientPublic.data(), kPublicKeySize);
      std::array<std::uint8_t, kProofSize> proof{};
      crypto_blake2b_keyed(proof.data(), proof.size(), token.data(), token.size(), message.data(), message.size());
      return proof;
    }

    /** Hashes of the exchange, keyed by the token: without the token, knowing the exchange gives nothing. */
    class CSessionHasher
    {
    public:
      CSessionHasher(const Token& token, const std::uint8_t* const shared, const PublicKey& clientPublic, const PublicKey& serverPublic) noexcept
        : mToken(token)
      {
        std::memcpy(mMessage.data() + 1, shared, kKeySize);
        std::memcpy(mMessage.data() + 1 + kKeySize, clientPublic.data(), kPublicKeySize);
        std::memcpy(mMessage.data() + 1 + kKeySize + kPublicKeySize, serverPublic.data(), kPublicKeySize);
      }

      ~CSessionHasher() { crypto_wipe(mMessage.data(), mMessage.size()); }
      CSessionHasher(const CSessionHasher&) = delete;
      CSessionHasher& operator=(const CSessionHasher&) = delete;

      void Hash(const std::uint8_t label, std::uint8_t* const out, const std::size_t size) noexcept
      {
        mMessage[0] = label;
        crypto_blake2b_keyed(out, size, mToken.data(), mToken.size(), mMessage.data(), mMessage.size());
      }

    private:
      const Token& mToken;
      std::array<std::uint8_t, 1 + kKeySize + kPublicKeySize + kPublicKeySize> mMessage{};
    };

    /** X25519 gives all zeros for a low-order point, which would let anyone predict the result. */
    [[nodiscard]] bool IsDegenerate(const std::uint8_t* const shared) noexcept
    {
      std::uint8_t any = 0;
      for (std::size_t i = 0; i < kKeySize; ++i) {
        any = static_cast<std::uint8_t>(any | shared[i]);
      }
      return any == 0u;
    }
  } // namespace

  bool FillRandom(void* const out, const std::size_t size) noexcept
  {
#if defined(_WIN32)
    return BCryptGenRandom(nullptr, static_cast<PUCHAR>(out), static_cast<ULONG>(size), BCRYPT_USE_SYSTEM_PREFERRED_RNG) == 0;
#else
    auto* cursor = static_cast<std::uint8_t*>(out);
    std::size_t left = size;
    while (left != 0u) {
      const ssize_t got = getrandom(cursor, left, 0);
      if (got <= 0) {
        return false;
      }
      cursor += got;
      left -= static_cast<std::size_t>(got);
    }
    return true;
#endif
  }

  Token MakeToken(const std::string_view text) noexcept
  {
    Token token{};
    crypto_blake2b(token.data(), token.size(), reinterpret_cast<const std::uint8_t*>(text.data()), text.size());
    return token;
  }

  std::vector<std::uint8_t> WriteHello()
  {
    std::vector<std::uint8_t> out(kHelloSize, 0u);
    out[0] = kHandshakeTag;
    out[1] = static_cast<std::uint8_t>(EHandshakeType::Hello);
    WriteU16(out.data() + 2, kHandshakeVersion);
    return out;
  }

  std::optional<EHandshakeType> HandshakeTypeOf(const std::uint8_t* const data, const std::size_t size) noexcept
  {
    if (size < 2u || data[0] != kHandshakeTag || data[1] < static_cast<std::uint8_t>(EHandshakeType::Hello) || data[1] > static_cast<std::uint8_t>(EHandshakeType::Reject)) {
      return std::nullopt;
    }
    return static_cast<EHandshakeType>(data[1]);
  }

  bool CCookieJar::Init() noexcept
  {
    return FillRandom(mSecret.data(), mSecret.size());
  }

  namespace
  {
    [[nodiscard]] Cookie CookieFor(const std::array<std::uint8_t, 32>& secret, const std::uint64_t addressKey, const std::uint64_t period) noexcept
    {
      std::array<std::uint8_t, 17> message{};
      message[0] = kLabelCookie;
      for (int i = 0; i < 8; ++i) {
        message[static_cast<std::size_t>(1 + i)] = static_cast<std::uint8_t>(addressKey >> (8 * i));
        message[static_cast<std::size_t>(9 + i)] = static_cast<std::uint8_t>(period >> (8 * i));
      }
      Cookie cookie{};
      crypto_blake2b_keyed(cookie.data(), cookie.size(), secret.data(), secret.size(), message.data(), message.size());
      return cookie;
    }

    [[nodiscard]] bool SameCookie(const Cookie& a, const Cookie& b) noexcept
    {
      return crypto_verify16(a.data(), b.data()) == 0;
    }
  } // namespace

  Cookie CCookieJar::Make(const std::uint64_t addressKey, const std::uint64_t nowUs) const noexcept
  {
    return CookieFor(mSecret, addressKey, nowUs / kPeriodUs);
  }

  bool CCookieJar::Check(const Cookie& cookie, const std::uint64_t addressKey, const std::uint64_t nowUs) const noexcept
  {
    const std::uint64_t period = nowUs / kPeriodUs;
    return SameCookie(cookie, CookieFor(mSecret, addressKey, period)) || (period > 0u && SameCookie(cookie, CookieFor(mSecret, addressKey, period - 1u)));
  }

  std::vector<std::uint8_t> AnswerHello(const std::uint8_t* const data, const std::size_t size, const CCookieJar& jar, const std::uint64_t addressKey, const std::uint64_t nowUs)
  {
    // Smaller Hellos get nothing, so nobody can use this server to send more than they sent.
    if (size < kHelloSize || HandshakeTypeOf(data, size) != EHandshakeType::Hello) {
      return {};
    }
    if (ReadU16(data + 2) != kHandshakeVersion) {
      return WriteReject(EHandshakeRefusal::Version);
    }
    std::vector<std::uint8_t> out(kChallengeSize);
    out[0] = kHandshakeTag;
    out[1] = static_cast<std::uint8_t>(EHandshakeType::Challenge);
    const Cookie cookie = jar.Make(addressKey, nowUs);
    std::memcpy(out.data() + 2, cookie.data(), kCookieSize);
    return out;
  }

  bool ReadConnect(const std::uint8_t* const data, const std::size_t size, SConnectRequest& out) noexcept
  {
    if (size != kConnectSize || HandshakeTypeOf(data, size) != EHandshakeType::Connect || ReadU16(data + 2) != kHandshakeVersion) {
      return false;
    }
    const std::uint8_t* cursor = data + 4;
    std::memcpy(out.cookie.data(), cursor, kCookieSize);
    cursor += kCookieSize;
    out.uid = ReadI32(cursor);
    cursor += 4;
    std::memcpy(out.clientPublic.data(), cursor, kPublicKeySize);
    cursor += kPublicKeySize;
    std::memcpy(out.proof.data(), cursor, kProofSize);
    return true;
  }

  std::optional<SServerSession> AnswerConnect(const SConnectRequest& request, const Token& token)
  {
    const auto expected = ConnectProof(token, request.cookie, request.uid, request.clientPublic);
    if (crypto_verify16(expected.data(), request.proof.data()) != 0) {
      return std::nullopt;
    }

    std::array<std::uint8_t, kKeySize> secret{};
    if (!FillRandom(secret.data(), secret.size())) {
      return std::nullopt;
    }
    PublicKey serverPublic{};
    crypto_x25519_public_key(serverPublic.data(), secret.data());
    std::array<std::uint8_t, kKeySize> shared{};
    crypto_x25519(shared.data(), secret.data(), request.clientPublic.data());
    crypto_wipe(secret.data(), secret.size());
    if (IsDegenerate(shared.data())) {
      return std::nullopt;
    }

    SServerSession session;
    {
      CSessionHasher hasher(token, shared.data(), request.clientPublic, serverPublic);
      hasher.Hash(kLabelClientKey, session.keys.receive.data(), kKeySize);
      hasher.Hash(kLabelServerKey, session.keys.send.data(), kKeySize);
      session.accept.resize(kAcceptSize);
      session.accept[0] = kHandshakeTag;
      session.accept[1] = static_cast<std::uint8_t>(EHandshakeType::Accept);
      std::memcpy(session.accept.data() + 2, serverPublic.data(), kPublicKeySize);
      hasher.Hash(kLabelAccept, session.accept.data() + 2 + kPublicKeySize, kProofSize);
    }
    crypto_wipe(shared.data(), shared.size());
    return session;
  }

  std::vector<std::uint8_t> WriteReject(const EHandshakeRefusal why)
  {
    return {kHandshakeTag, static_cast<std::uint8_t>(EHandshakeType::Reject), static_cast<std::uint8_t>(why)};
  }

  CClientHandshake::CClientHandshake(const std::int32_t uid, const Token& token) noexcept
    : mUid(uid)
    , mToken(token)
  {}

  CClientHandshake::~CClientHandshake()
  {
    crypto_wipe(mSecret.data(), mSecret.size());
    crypto_wipe(mToken.data(), mToken.size());
  }

  std::vector<std::uint8_t> CClientHandshake::OnChallenge(const std::uint8_t* const data, const std::size_t size)
  {
    if (size != kChallengeSize || HandshakeTypeOf(data, size) != EHandshakeType::Challenge) {
      return {};
    }
    if (!mHaveKeys) {
      if (!FillRandom(mSecret.data(), mSecret.size())) {
        return {};
      }
      crypto_x25519_public_key(mPublic.data(), mSecret.data());
      mHaveKeys = true;
    }
    Cookie cookie{};
    std::memcpy(cookie.data(), data + 2, kCookieSize);

    std::vector<std::uint8_t> out(kConnectSize);
    out[0] = kHandshakeTag;
    out[1] = static_cast<std::uint8_t>(EHandshakeType::Connect);
    WriteU16(out.data() + 2, kHandshakeVersion);
    std::uint8_t* cursor = out.data() + 4;
    std::memcpy(cursor, cookie.data(), kCookieSize);
    cursor += kCookieSize;
    WriteI32(cursor, mUid);
    cursor += 4;
    std::memcpy(cursor, mPublic.data(), kPublicKeySize);
    cursor += kPublicKeySize;
    const auto proof = ConnectProof(mToken, cookie, mUid, mPublic);
    std::memcpy(cursor, proof.data(), kProofSize);
    return out;
  }

  std::optional<ChannelKeys> CClientHandshake::OnAccept(const std::uint8_t* const data, const std::size_t size) const
  {
    if (!mHaveKeys || size != kAcceptSize || HandshakeTypeOf(data, size) != EHandshakeType::Accept) {
      return std::nullopt;
    }
    PublicKey serverPublic{};
    std::memcpy(serverPublic.data(), data + 2, kPublicKeySize);

    std::array<std::uint8_t, kKeySize> shared{};
    crypto_x25519(shared.data(), mSecret.data(), serverPublic.data());
    if (IsDegenerate(shared.data())) {
      return std::nullopt;
    }

    ChannelKeys keys;
    std::array<std::uint8_t, kProofSize> expected{};
    {
      CSessionHasher hasher(mToken, shared.data(), mPublic, serverPublic);
      hasher.Hash(kLabelAccept, expected.data(), kProofSize);
      hasher.Hash(kLabelClientKey, keys.send.data(), kKeySize);
      hasher.Hash(kLabelServerKey, keys.receive.data(), kKeySize);
    }
    crypto_wipe(shared.data(), shared.size());
    if (crypto_verify16(expected.data(), data + 2 + kPublicKeySize) != 0) {
      WipeKey(keys.send);
      WipeKey(keys.receive);
      return std::nullopt;
    }
    return keys;
  }
} // namespace faf::remote::net
