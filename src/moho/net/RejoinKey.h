#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace moho
{
  /**
   * Engine addition (issue #275): what proves a client taking a seat back is the player who had it.
   *
   * A client makes a key pair when its game starts, keeps the private half in a file only it was told about
   * (`/rejoinkeyfile`, by default in the OS user's temp folder) and gives the public half to its peers. A peer
   * accepts a rejoin only after the client signs a random challenge with that key, so a player on another account
   * or another computer gets nothing, however it connects. The first public key a peer hears for a seat stays.
   */
  using SRejoinPublicKey = std::array<std::uint8_t, 32>;
  using SRejoinNonce = std::array<std::uint8_t, 32>;
  using SRejoinSignature = std::array<std::uint8_t, 64>;

  /// Makes this game's key and saves it. False if it could not be saved, and then this seat cannot rejoin.
  [[nodiscard]] bool REJOIN_CreateKey();

  /// Reads the key the game was started with, for a client restarted with `/rejoin`.
  [[nodiscard]] bool REJOIN_LoadKey();

  /// Whether this client holds a key, and the public half to give out.
  [[nodiscard]] bool REJOIN_HasKey();
  [[nodiscard]] const SRejoinPublicKey& REJOIN_PublicKey();

  [[nodiscard]] SRejoinNonce REJOIN_MakeNonce();

  /// Signs a peer's challenge for seat `source`, addressed to the peer with client index `peerIndex`.
  [[nodiscard]] SRejoinSignature REJOIN_SignChallenge(const SRejoinNonce& nonce, int source, int peerIndex);

  /// As a peer: whether `signature` answers this challenge from the holder of `key`, for that seat, to this peer.
  [[nodiscard]] bool REJOIN_CheckProof(
    const SRejoinPublicKey& key, const SRejoinNonce& nonce, int source, int peerIndex, const SRejoinSignature& signature
  );
} // namespace moho
