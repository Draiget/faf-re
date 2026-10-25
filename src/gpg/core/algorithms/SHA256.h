#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace gpg
{
  /**
   * Engine addition, not in the binary: SHA-256 (FIPS 180-4), fed in pieces.
   * Used where a digest must hold up against someone choosing the input, which
   * MD5 does not (two inputs with one MD5 can be made in seconds).
   */
  class SHA256
  {
  public:
    using Digest = std::array<std::uint8_t, 32>;

    SHA256() noexcept;

    /** Appends `size` bytes. */
    void Update(const void* data, std::size_t size) noexcept;

    /** The digest of everything appended so far; the hasher can keep going. */
    [[nodiscard]] Digest Snapshot() const noexcept;

  private:
    void Compress(const std::uint8_t* block) noexcept;

    std::array<std::uint32_t, 8> mState;
    std::array<std::uint8_t, 64> mBuffer{};
    std::size_t mBuffered{0};
    std::uint64_t mTotalBytes{0};
  };
} // namespace gpg
