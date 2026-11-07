#include "remote/net/StyleProof.h"

#include <cstring>

#include "monocypher.h"

namespace faf::remote::net
{
  namespace
  {
    // Kept apart from anything else this key could ever sign.
    constexpr char kDomain[] = "faf-re peer style 1";

    using SignedBytes = std::array<std::uint8_t, sizeof(kDomain) + 4u + 4u + 32u + 3u>;

    void PutUid(std::uint8_t* const out, const std::int32_t uid) noexcept
    {
      const auto value = static_cast<std::uint32_t>(uid);
      out[0] = static_cast<std::uint8_t>(value);
      out[1] = static_cast<std::uint8_t>(value >> 8);
      out[2] = static_cast<std::uint8_t>(value >> 16);
      out[3] = static_cast<std::uint8_t>(value >> 24);
    }

    [[nodiscard]] SignedBytes BuildSignedBytes(
      const std::int32_t signerUid,
      const std::int32_t checkerUid,
      const StyleChallenge& challenge,
      const StyleColor& color
    ) noexcept
    {
      SignedBytes bytes{};
      std::uint8_t* out = bytes.data();
      std::memcpy(out, kDomain, sizeof(kDomain));
      out += sizeof(kDomain);
      PutUid(out, signerUid);
      out += 4;
      PutUid(out, checkerUid);
      out += 4;
      std::memcpy(out, challenge.data(), challenge.size());
      out += challenge.size();
      std::memcpy(out, color.data(), color.size());
      return bytes;
    }
  } // namespace

  StyleSigningKey::~StyleSigningKey()
  {
    crypto_wipe(secret.data(), secret.size());
  }

  void MakeStyleSigningKey(StyleSeed& seed, StyleSigningKey& key) noexcept
  {
    crypto_eddsa_key_pair(key.secret.data(), key.publicKey.data(), seed.data());
  }

  StyleSignature SignStyle(
    const StyleSigningKey& key,
    const std::int32_t signerUid,
    const std::int32_t checkerUid,
    const StyleChallenge& challenge,
    const StyleColor& color
  ) noexcept
  {
    const SignedBytes bytes = BuildSignedBytes(signerUid, checkerUid, challenge, color);
    StyleSignature signature{};
    crypto_eddsa_sign(signature.data(), key.secret.data(), bytes.data(), bytes.size());
    return signature;
  }

  bool CheckStyle(
    const StylePublicKey& publicKey,
    const std::int32_t signerUid,
    const std::int32_t checkerUid,
    const StyleChallenge& challenge,
    const StyleColor& color,
    const StyleSignature& signature
  ) noexcept
  {
    const SignedBytes bytes = BuildSignedBytes(signerUid, checkerUid, challenge, color);
    return crypto_eddsa_check(signature.data(), publicKey.data(), bytes.data(), bytes.size()) == 0;
  }
} // namespace faf::remote::net
