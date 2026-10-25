#include "remote/wire/BitStream.h"

#include <bit>

// Engine addition, server mode: see BitStream.h.

namespace faf::remote::wire
{
  void BitWriter::WriteBits(const std::uint32_t value, const int bitCount)
  {
    for (int bit = 0; bit < bitCount; ++bit) {
      if ((mBitCount & 7u) == 0u) {
        mBytes.push_back(0u);
      }
      if (((value >> bit) & 1u) != 0u) {
        mBytes.back() = static_cast<std::uint8_t>(mBytes.back() | (1u << (mBitCount & 7u)));
      }
      ++mBitCount;
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
    std::uint32_t value = 0;
    for (int bit = 0; bit < bitCount; ++bit) {
      const std::uint8_t byte = mBytes[mBitPos >> 3];
      if (((byte >> (mBitPos & 7u)) & 1u) != 0u) {
        value |= 1u << bit;
      }
      ++mBitPos;
    }
    return value;
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
