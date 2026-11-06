#pragma once

// Issue #289: keys for the redundant lane (#240) between two of our links,
// agreed per connection attempt. Engine addition, not recovered code.
//
// Each attempt makes a new X25519 key pair. Its public key goes in the ICE
// ufrag, after the other marks: "fnl+" ["w+"] "c+" "k+" <64 lowercase hex>.
// The ufrag already travels in the CandidatesMessage through iceMsg, so no new
// message is needed and nothing secret is sent. Both lane keys come from
// BLAKE2b over the X25519 result and both public keys, one per direction.
//
// This keeps the game's datagrams from anyone on the network path. It does
// not protect against whoever relays iceMsg (the lobby server): it could swap
// or drop the keys.

#include "remote/net/DatagramCipher.h"

#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace faf::netlink
{
  inline constexpr std::size_t kLinkPublicKeySize = 32;
  using LinkPublicKey = std::array<std::uint8_t, kLinkPublicKeySize>;

  // The mark that offers keys, before the hex public key.
  inline constexpr const char* kKeyMark = "k+";

  class LinkKeyPair
  {
  public:
    LinkKeyPair() = default;
    ~LinkKeyPair();
    LinkKeyPair(const LinkKeyPair&) = delete;
    LinkKeyPair& operator=(const LinkKeyPair&) = delete;

    // A new pair from the system's random source; false when it has none.
    [[nodiscard]] bool Generate();
    [[nodiscard]] bool IsSet() const { return mSet; }
    const LinkPublicKey& Public() const { return mPublic; }
    // Wipes the secret.
    void Clear();

    // The lane keys for this end, from the peer's public key. None when the
    // X25519 result is all zeros (a low-order point, never an honest peer's).
    [[nodiscard]] std::optional<remote::net::ChannelKeys> Derive(const LinkPublicKey& peer, bool offerer) const;

  private:
    std::array<std::uint8_t, 32> mSecret{};
    LinkPublicKey mPublic{};
    bool mSet = false;
  };

  // "k+" and the key as 64 lowercase hex digits.
  std::string KeyMarkFor(const LinkPublicKey& key);

  // The key a marked ufrag offers: `prefix`, then "w+" and "c+" if present,
  // then "k+" and exactly 64 lowercase hex digits to the end. None otherwise,
  // which is how a Java adapter's, an older build's or a garbled ufrag reads.
  std::optional<LinkPublicKey> KeyFromUfrag(std::string_view ufrag, std::string_view prefix);
} // namespace faf::netlink
