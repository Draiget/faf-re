#include "remote/net/DatagramCipher.h"

#include "monocypher.h"
#include "remote/net/Datagram.h"

namespace faf::remote::net
{
  namespace
  {
    std::array<std::uint8_t, 24> NonceFor(const std::uint32_t sequence) noexcept
    {
      std::array<std::uint8_t, 24> nonce{};
      nonce[0] = static_cast<std::uint8_t>(sequence);
      nonce[1] = static_cast<std::uint8_t>(sequence >> 8);
      nonce[2] = static_cast<std::uint8_t>(sequence >> 16);
      nonce[3] = static_cast<std::uint8_t>(sequence >> 24);
      return nonce;
    }
  } // namespace

  void SealDatagram(
    const ChannelKey& key, const std::uint32_t sequence, std::uint8_t* const datagram, const std::size_t payloadSize
  ) noexcept
  {
    const auto nonce = NonceFor(sequence);
    std::uint8_t* const payload = datagram + kHeaderSize;
    crypto_aead_lock(
      payload, payload + payloadSize, key.data(), nonce.data(), datagram, kHeaderSize, payload, payloadSize
    );
  }

  bool OpenDatagram(
    const ChannelKey& key,
    const std::uint32_t sequence,
    const std::uint8_t* const datagram,
    const std::size_t size,
    std::uint8_t* const plain
  ) noexcept
  {
    if (size < kHeaderSize + kTagSize) {
      return false;
    }
    const std::size_t payloadSize = size - kHeaderSize - kTagSize;
    const auto nonce = NonceFor(sequence);
    const std::uint8_t* const cipher = datagram + kHeaderSize;
    return crypto_aead_unlock(
             plain, cipher + payloadSize, key.data(), nonce.data(), datagram, kHeaderSize, cipher, payloadSize
           ) == 0;
  }

  void WipeKey(ChannelKey& key) noexcept
  {
    crypto_wipe(key.data(), key.size());
  }
} // namespace faf::remote::net
