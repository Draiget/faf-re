#include "netlink/LinkKeys.h"

#include "remote/net/Handshake.h"

#include <cstring>

#include "monocypher.h"

namespace faf::netlink
{
  namespace
  {
    // Keeps these hashes apart from every other use of the same primitives.
    constexpr char kDomain[] = "faf-netlink-lane-keys-1";
    constexpr std::uint8_t kLabelOffererSends = 1;
    constexpr std::uint8_t kLabelAnswererSends = 2;

    constexpr char kHex[] = "0123456789abcdef";

    int HexValue(const char c)
    {
      if (c >= '0' && c <= '9') {
        return c - '0';
      }
      if (c >= 'a' && c <= 'f') {
        return c - 'a' + 10;
      }
      return -1;
    }
  } // namespace

  LinkKeyPair::~LinkKeyPair()
  {
    Clear();
  }

  bool LinkKeyPair::Generate()
  {
    Clear();
    if (!remote::net::FillRandom(mSecret.data(), mSecret.size())) {
      return false;
    }
    crypto_x25519_public_key(mPublic.data(), mSecret.data());
    mSet = true;
    return true;
  }

  void LinkKeyPair::Clear()
  {
    crypto_wipe(mSecret.data(), mSecret.size());
    mPublic.fill(0);
    mSet = false;
  }

  std::optional<remote::net::ChannelKeys> LinkKeyPair::Derive(const LinkPublicKey& peer, const bool offerer) const
  {
    if (!mSet) {
      return std::nullopt;
    }
    std::array<std::uint8_t, 32> shared{};
    crypto_x25519(shared.data(), mSecret.data(), peer.data());
    std::uint8_t any = 0;
    for (const std::uint8_t b : shared) {
      any = static_cast<std::uint8_t>(any | b);
    }
    if (any == 0u) {
      return std::nullopt;
    }

    // label, domain, shared, offerer's public key, answerer's public key.
    const LinkPublicKey& offererKey = offerer ? mPublic : peer;
    const LinkPublicKey& answererKey = offerer ? peer : mPublic;
    constexpr std::size_t kDomainSize = sizeof(kDomain) - 1;
    std::array<std::uint8_t, 1 + kDomainSize + 32 + 2 * kLinkPublicKeySize> message{};
    std::memcpy(message.data() + 1, kDomain, kDomainSize);
    std::memcpy(message.data() + 1 + kDomainSize, shared.data(), shared.size());
    std::memcpy(message.data() + 1 + kDomainSize + 32, offererKey.data(), kLinkPublicKeySize);
    std::memcpy(message.data() + 1 + kDomainSize + 32 + kLinkPublicKeySize, answererKey.data(), kLinkPublicKeySize);
    crypto_wipe(shared.data(), shared.size());

    remote::net::ChannelKeys offererSends;
    message[0] = kLabelOffererSends;
    crypto_blake2b(offererSends.send.data(), offererSends.send.size(), message.data(), message.size());
    message[0] = kLabelAnswererSends;
    crypto_blake2b(offererSends.receive.data(), offererSends.receive.size(), message.data(), message.size());
    crypto_wipe(message.data(), message.size());

    if (offerer) {
      return offererSends;
    }
    remote::net::ChannelKeys answerer;
    answerer.send = offererSends.receive;
    answerer.receive = offererSends.send;
    remote::net::WipeKey(offererSends.send);
    remote::net::WipeKey(offererSends.receive);
    return answerer;
  }

  std::string KeyMarkFor(const LinkPublicKey& key)
  {
    std::string out(kKeyMark);
    out.reserve(out.size() + 2 * key.size());
    for (const std::uint8_t b : key) {
      out.push_back(kHex[b >> 4]);
      out.push_back(kHex[b & 15]);
    }
    return out;
  }

  std::optional<LinkPublicKey> KeyFromUfrag(std::string_view ufrag, const std::string_view prefix)
  {
    if (prefix.empty() || ufrag.substr(0, prefix.size()) != prefix) {
      return std::nullopt;
    }
    ufrag.remove_prefix(prefix.size());
    for (const std::string_view mark : {std::string_view("w+"), std::string_view("c+")}) {
      if (ufrag.substr(0, mark.size()) == mark) {
        ufrag.remove_prefix(mark.size());
      }
    }
    const std::string_view keyMark(kKeyMark);
    if (ufrag.substr(0, keyMark.size()) != keyMark) {
      return std::nullopt;
    }
    ufrag.remove_prefix(keyMark.size());
    if (ufrag.size() != 2 * kLinkPublicKeySize) {
      return std::nullopt;
    }
    LinkPublicKey key{};
    for (std::size_t i = 0; i < key.size(); ++i) {
      const int hi = HexValue(ufrag[2 * i]);
      const int lo = HexValue(ufrag[2 * i + 1]);
      if (hi < 0 || lo < 0) {
        return std::nullopt;
      }
      key[i] = static_cast<std::uint8_t>(hi * 16 + lo);
    }
    return key;
  }
} // namespace faf::netlink
