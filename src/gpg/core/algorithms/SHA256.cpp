#include "gpg/core/algorithms/SHA256.h"

#include <algorithm>
#include <bit>
#include <cstring>

namespace
{
  constexpr std::array<std::uint32_t, 64> kRoundConstants = {
    0x428a2f98u, 0x71374491u, 0xb5c0fbcfu, 0xe9b5dba5u, 0x3956c25bu, 0x59f111f1u, 0x923f82a4u, 0xab1c5ed5u,
    0xd807aa98u, 0x12835b01u, 0x243185beu, 0x550c7dc3u, 0x72be5d74u, 0x80deb1feu, 0x9bdc06a7u, 0xc19bf174u,
    0xe49b69c1u, 0xefbe4786u, 0x0fc19dc6u, 0x240ca1ccu, 0x2de92c6fu, 0x4a7484aau, 0x5cb0a9dcu, 0x76f988dau,
    0x983e5152u, 0xa831c66du, 0xb00327c8u, 0xbf597fc7u, 0xc6e00bf3u, 0xd5a79147u, 0x06ca6351u, 0x14292967u,
    0x27b70a85u, 0x2e1b2138u, 0x4d2c6dfcu, 0x53380d13u, 0x650a7354u, 0x766a0abbu, 0x81c2c92eu, 0x92722c85u,
    0xa2bfe8a1u, 0xa81a664bu, 0xc24b8b70u, 0xc76c51a3u, 0xd192e819u, 0xd6990624u, 0xf40e3585u, 0x106aa070u,
    0x19a4c116u, 0x1e376c08u, 0x2748774cu, 0x34b0bcb5u, 0x391c0cb3u, 0x4ed8aa4au, 0x5b9cca4fu, 0x682e6ff3u,
    0x748f82eeu, 0x78a5636fu, 0x84c87814u, 0x8cc70208u, 0x90befffau, 0xa4506cebu, 0xbef9a3f7u, 0xc67178f2u,
  };

  [[nodiscard]] std::uint32_t LoadBigEndian(const std::uint8_t* const bytes) noexcept
  {
    return (std::uint32_t{bytes[0]} << 24) | (std::uint32_t{bytes[1]} << 16) | (std::uint32_t{bytes[2]} << 8) |
           std::uint32_t{bytes[3]};
  }
} // namespace

namespace gpg
{
  SHA256::SHA256() noexcept
    : mState{0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au, 0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u}
  {}

  void SHA256::Compress(const std::uint8_t* const block) noexcept
  {
    std::array<std::uint32_t, 64> schedule{};
    for (std::size_t i = 0; i < 16; ++i) {
      schedule[i] = LoadBigEndian(block + i * 4);
    }
    for (std::size_t i = 16; i < 64; ++i) {
      const std::uint32_t s0 =
        std::rotr(schedule[i - 15], 7) ^ std::rotr(schedule[i - 15], 18) ^ (schedule[i - 15] >> 3);
      const std::uint32_t s1 =
        std::rotr(schedule[i - 2], 17) ^ std::rotr(schedule[i - 2], 19) ^ (schedule[i - 2] >> 10);
      schedule[i] = schedule[i - 16] + s0 + schedule[i - 7] + s1;
    }

    std::uint32_t a = mState[0], b = mState[1], c = mState[2], d = mState[3];
    std::uint32_t e = mState[4], f = mState[5], g = mState[6], h = mState[7];
    for (std::size_t i = 0; i < 64; ++i) {
      const std::uint32_t s1 = std::rotr(e, 6) ^ std::rotr(e, 11) ^ std::rotr(e, 25);
      const std::uint32_t choose = (e & f) ^ (~e & g);
      const std::uint32_t t1 = h + s1 + choose + kRoundConstants[i] + schedule[i];
      const std::uint32_t s0 = std::rotr(a, 2) ^ std::rotr(a, 13) ^ std::rotr(a, 22);
      const std::uint32_t majority = (a & b) ^ (a & c) ^ (b & c);
      const std::uint32_t t2 = s0 + majority;
      h = g;
      g = f;
      f = e;
      e = d + t1;
      d = c;
      c = b;
      b = a;
      a = t1 + t2;
    }

    mState[0] += a;
    mState[1] += b;
    mState[2] += c;
    mState[3] += d;
    mState[4] += e;
    mState[5] += f;
    mState[6] += g;
    mState[7] += h;
  }

  void SHA256::Update(const void* const data, std::size_t size) noexcept
  {
    const auto* bytes = static_cast<const std::uint8_t*>(data);
    mTotalBytes += size;

    if (mBuffered != 0) {
      const std::size_t take = std::min(size, mBuffer.size() - mBuffered);
      std::memcpy(mBuffer.data() + mBuffered, bytes, take);
      mBuffered += take;
      bytes += take;
      size -= take;
      if (mBuffered < mBuffer.size()) {
        return;
      }
      Compress(mBuffer.data());
      mBuffered = 0;
    }

    for (; size >= mBuffer.size(); bytes += mBuffer.size(), size -= mBuffer.size()) {
      Compress(bytes);
    }

    std::memcpy(mBuffer.data(), bytes, size);
    mBuffered = size;
  }

  SHA256::Digest SHA256::Snapshot() const noexcept
  {
    SHA256 copy = *this;

    // Padding: 0x80, zeros to 56 bytes mod 64, then the bit length big-endian.
    const std::uint64_t bitLength = mTotalBytes * 8u;
    const std::uint8_t one = 0x80;
    copy.Update(&one, 1);
    const std::uint8_t zero = 0;
    while (copy.mBuffered != 56) {
      copy.Update(&zero, 1);
    }
    std::array<std::uint8_t, 8> lengthBytes{};
    for (std::size_t i = 0; i < 8; ++i) {
      lengthBytes[i] = static_cast<std::uint8_t>(bitLength >> (56 - 8 * i));
    }
    copy.Update(lengthBytes.data(), lengthBytes.size());

    Digest digest{};
    for (std::size_t i = 0; i < 8; ++i) {
      digest[i * 4 + 0] = static_cast<std::uint8_t>(copy.mState[i] >> 24);
      digest[i * 4 + 1] = static_cast<std::uint8_t>(copy.mState[i] >> 16);
      digest[i * 4 + 2] = static_cast<std::uint8_t>(copy.mState[i] >> 8);
      digest[i * 4 + 3] = static_cast<std::uint8_t>(copy.mState[i]);
    }
    return digest;
  }
} // namespace gpg
