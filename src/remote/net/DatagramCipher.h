#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

// Engine addition, net channel (plan WP10.6, issue #145): authenticated encryption of every
// datagram once the handshake (WP10.5) has given the channel its keys. XChaCha20-Poly1305
// from Monocypher 4.0.2 (BSD-2-Clause or CC0, cmake/deps/monocypher).
//
// The 16-byte header stays readable and is the associated data, so the tag covers it too;
// the payload is encrypted in place and the 16-byte tag follows it. The nonce is the
// header's sequence number, which never repeats under one key: each direction has its own
// key, a channel never reuses a sequence, and the handshake makes new keys per session.
// Replays are refused after authentication by the receive window (Datagram.h).

namespace faf::remote::net
{
  inline constexpr std::size_t kKeySize = 32;
  inline constexpr std::size_t kTagSize = 16;

  using ChannelKey = std::array<std::uint8_t, kKeySize>;

  /** One key per direction. The two ends swap them: one's send is the other's receive. */
  struct ChannelKeys
  {
    ChannelKey send{};
    ChannelKey receive{};
  };

  /**
   * Encrypts `datagram[kHeaderSize, kHeaderSize + payloadSize)` in place and writes the tag
   * after it; `datagram` holds kHeaderSize + payloadSize + kTagSize bytes and its header is
   * already written (with kFlagEncrypted).
   */
  void SealDatagram(const ChannelKey& key, std::uint32_t sequence, std::uint8_t* datagram, std::size_t payloadSize) noexcept;

  /**
   * Checks the tag of a `size`-byte sealed datagram and decrypts its payload into `plain`
   * (size - kHeaderSize - kTagSize bytes). False, with `plain` untouched, when the datagram
   * is too short or was not sealed with `key` and `sequence` exactly as received.
   */
  [[nodiscard]] bool OpenDatagram(
    const ChannelKey& key, std::uint32_t sequence, const std::uint8_t* datagram, std::size_t size, std::uint8_t* plain
  ) noexcept;

  /** Overwrites key material so it does not linger in freed memory. */
  void WipeKey(ChannelKey& key) noexcept;
} // namespace faf::remote::net
