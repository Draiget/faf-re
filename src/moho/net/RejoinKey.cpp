#include "moho/net/RejoinKey.h"

#include <algorithm>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <random>
#include <string>
#include <system_error>

#include "gpg/core/utils/Logging.h"
#include "monocypher.h"
#include "moho/misc/StartupHelpers.h"

namespace moho
{
  namespace
  {
    constexpr std::size_t kSeedBytes = 32u;
    constexpr char kProofLabel[] = "FAF rejoin proof 1";

    std::array<std::uint8_t, 64> sSecretKey{};
    SRejoinPublicKey sPublicKey{};
    bool sHasKey = false;

    [[nodiscard]] std::string KeyFilePath()
    {
      fa::vector<fa::string> args;
      if (CFG_GetArgOption("/rejoinkeyfile", 1, &args) && !args.empty()) {
        return args[0].c_str();
      }
      std::error_code ignored;
      return (std::filesystem::temp_directory_path(ignored) / "faf_rejoin_seat.key").string();
    }

    void FillRandom(std::uint8_t* const out, const std::size_t size)
    {
      std::random_device source;
      for (std::size_t index = 0; index < size;) {
        const unsigned int word = source();
        for (std::size_t byte = 0; byte < sizeof(word) && index < size; ++byte, ++index) {
          out[index] = static_cast<std::uint8_t>(word >> (byte * 8u));
        }
      }
    }

    void UseSeed(std::array<std::uint8_t, kSeedBytes>& seed)
    {
      crypto_eddsa_key_pair(sSecretKey.data(), sPublicKey.data(), seed.data());
      crypto_wipe(seed.data(), seed.size());
      sHasKey = true;
    }

    /// What a signature covers: the challenge, the seat and the peer, so it answers nothing else.
    [[nodiscard]] std::array<std::uint8_t, sizeof(kProofLabel) + sizeof(SRejoinNonce) + 8u> ProofMessage(
      const SRejoinNonce& nonce, const int source, const int peerIndex
    )
    {
      std::array<std::uint8_t, sizeof(kProofLabel) + sizeof(SRejoinNonce) + 8u> message{};
      std::uint8_t* out = message.data();
      std::memcpy(out, kProofLabel, sizeof(kProofLabel));
      out += sizeof(kProofLabel);
      std::memcpy(out, nonce.data(), nonce.size());
      out += nonce.size();
      const std::int32_t numbers[2] = {source, peerIndex};
      std::memcpy(out, numbers, sizeof(numbers));
      return message;
    }
  } // namespace

  bool REJOIN_CreateKey()
  {
    sHasKey = false;
    std::array<std::uint8_t, kSeedBytes> seed{};
    FillRandom(seed.data(), seed.size());

    const std::string path = KeyFilePath();
    std::FILE* file = nullptr;
    if (fopen_s(&file, path.c_str(), "wb") != 0 || file == nullptr) {
      gpg::Warnf("REJOIN: cannot write the seat's key to %s; this seat cannot rejoin", path.c_str());
      crypto_wipe(seed.data(), seed.size());
      return false;
    }
    const bool written = std::fwrite(seed.data(), seed.size(), 1u, file) == 1u;
    const bool closed = std::fclose(file) == 0;
    if (!written || !closed) {
      gpg::Warnf("REJOIN: cannot write the seat's key to %s; this seat cannot rejoin", path.c_str());
      crypto_wipe(seed.data(), seed.size());
      return false;
    }
    UseSeed(seed);
    return true;
  }

  bool REJOIN_LoadKey()
  {
    sHasKey = false;
    const std::string path = KeyFilePath();
    std::FILE* file = nullptr;
    if (fopen_s(&file, path.c_str(), "rb") != 0 || file == nullptr) {
      gpg::Warnf("REJOIN: this computer has no key for that seat (%s)", path.c_str());
      return false;
    }
    std::array<std::uint8_t, kSeedBytes> seed{};
    const bool read = std::fread(seed.data(), seed.size(), 1u, file) == 1u;
    std::fclose(file);
    if (!read) {
      gpg::Warnf("REJOIN: the seat's key file %s is damaged", path.c_str());
      return false;
    }
    UseSeed(seed);
    return true;
  }

  bool REJOIN_HasKey()
  {
    return sHasKey;
  }

  const SRejoinPublicKey& REJOIN_PublicKey()
  {
    return sPublicKey;
  }

  SRejoinNonce REJOIN_MakeNonce()
  {
    SRejoinNonce nonce{};
    FillRandom(nonce.data(), nonce.size());
    return nonce;
  }

  SRejoinSignature REJOIN_SignChallenge(const SRejoinNonce& nonce, const int source, const int peerIndex)
  {
    const auto message = ProofMessage(nonce, source, peerIndex);
    SRejoinSignature signature{};
    crypto_eddsa_sign(signature.data(), sSecretKey.data(), message.data(), message.size());
    return signature;
  }

  bool REJOIN_CheckProof(
    const SRejoinPublicKey& key, const SRejoinNonce& nonce, const int source, const int peerIndex,
    const SRejoinSignature& signature
  )
  {
    const auto message = ProofMessage(nonce, source, peerIndex);
    return crypto_eddsa_check(signature.data(), key.data(), message.data(), message.size()) == 0;
  }
} // namespace moho
