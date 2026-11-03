#include "remote/wire/BitStream.h"

#include <bit>

// Engine addition, server mode: see BitStream.h.

namespace faf::remote::wire
{
  void BitWriter::WriteBits(const std::uint32_t value, const int bitCount)
  {
    // Least significant bit first, filling each byte from its low bit: as many bits per step as
    // the current byte has room for.
    std::uint64_t bits = bitCount >= 32 ? value : (value & ((std::uint64_t{1} << bitCount) - 1u));
    int left = bitCount;
    while (left > 0) {
      const auto used = static_cast<int>(mBitCount & 7u);
      if (used == 0) {
        mBytes.push_back(0u);
      }
      const int room = 8 - used;
      const int take = left < room ? left : room;
      mBytes.back() = static_cast<std::uint8_t>(mBytes.back() | ((bits & ((1u << take) - 1u)) << used));
      bits >>= take;
      left -= take;
      mBitCount += static_cast<std::size_t>(take);
    }
  }

  void BitWriter::WriteVarUint(std::uint32_t value)
  {
    while (value >= 0x80u) {
      WriteBits((value & 0x7Fu) | 0x80u, 8);
      value >>= 7;
    }
    WriteBits(value, 8);
  }

  void BitWriter::WriteFloatExact(const float value)
  {
    WriteBits(std::bit_cast<std::uint32_t>(value), 32);
  }

  void BitWriter::Append(const BitWriter& other)
  {
    const std::size_t whole = other.mBitCount / 8u;
    if ((mBitCount & 7u) == 0u) {
      mBytes.insert(mBytes.end(), other.mBytes.begin(), other.mBytes.begin() + static_cast<std::ptrdiff_t>(whole));
      mBitCount += whole * 8u;
    } else {
      for (std::size_t i = 0; i < whole; ++i) {
        WriteBits(other.mBytes[i], 8);
      }
    }
    if (const auto rest = static_cast<int>(other.mBitCount & 7u); rest != 0) {
      WriteBits(other.mBytes[whole], rest);
    }
  }

  std::uint32_t BitReader::ReadBits(const int bitCount) noexcept
  {
    if (mFailed || bitCount < 0 || bitCount > 32) {
      mFailed = true;
      return 0u;
    }
    if (mBitPos + static_cast<std::size_t>(bitCount) > mBytes.size() * 8u) {
      mFailed = true;
      return 0u;
    }
    std::uint64_t value = 0;
    int done = 0;
    while (done < bitCount) {
      const auto used = static_cast<int>(mBitPos & 7u);
      const int room = 8 - used;
      const int take = bitCount - done < room ? bitCount - done : room;
      const std::uint32_t chunk = (static_cast<std::uint32_t>(mBytes[mBitPos >> 3]) >> used) & ((1u << take) - 1u);
      value |= static_cast<std::uint64_t>(chunk) << done;
      done += take;
      mBitPos += static_cast<std::size_t>(take);
    }
    return static_cast<std::uint32_t>(value);
  }

  std::uint32_t BitReader::ReadVarUint() noexcept
  {
    std::uint32_t value = 0;
    for (int group = 0; group < 5; ++group) {
      const std::uint32_t byte = ReadBits(8);
      if (!Ok()) {
        return 0u;
      }
      const std::uint32_t data = byte & 0x7Fu;
      if (group == 4 && (data > 0x0Fu || (byte & 0x80u) != 0u)) {
        Fail();
        return 0u;
      }
      value |= data << (7 * group);
      if ((byte & 0x80u) == 0u) {
        return value;
      }
    }
    Fail();
    return 0u;
  }

  float BitReader::ReadFloatExact() noexcept
  {
    return std::bit_cast<float>(ReadBits(32));
  }
} // namespace faf::remote::wire
