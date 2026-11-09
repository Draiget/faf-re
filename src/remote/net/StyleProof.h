#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

// Engine addition: the signature behind a player's lobby style (docs/PEER_FEATURES.md). EdDSA
// from Monocypher 4.0.2 (cmake/deps/monocypher). What is signed names both players and a
// challenge the checking player just made up, so a proof only ever convinces that player,
// that once: a copy made by anyone else doesn't check.

namespace faf::remote::net
{
  using StyleSeed = std::array<std::uint8_t, 32>;
  using StylePublicKey = std::array<std::uint8_t, 32>;
  using StyleSignature = std::array<std::uint8_t, 64>;
  using StyleChallenge = std::array<std::uint8_t, 32>;
  using StyleColor = std::array<std::uint8_t, 3>;

  struct StyleSigningKey
  {
    std::array<std::uint8_t, 64> secret{};
    StylePublicKey publicKey{};

    StyleSigningKey() = default;
    StyleSigningKey(const StyleSigningKey&) = delete;
    StyleSigningKey& operator=(const StyleSigningKey&) = delete;
    ~StyleSigningKey();
  };

  /** Fills `key` from `seed` and wipes the seed. */
  void MakeStyleSigningKey(StyleSeed& seed, StyleSigningKey& key) noexcept;

  [[nodiscard]] StyleSignature SignStyle(
    const StyleSigningKey& key,
    std::int32_t signerUid,
    std::int32_t checkerUid,
    const StyleChallenge& challenge,
    const StyleColor& color
  ) noexcept;

  [[nodiscard]] bool CheckStyle(
    const StylePublicKey& publicKey,
    std::int32_t signerUid,
    std::int32_t checkerUid,
    const StyleChallenge& challenge,
    const StyleColor& color,
    const StyleSignature& signature
  ) noexcept;
} // namespace faf::remote::net
