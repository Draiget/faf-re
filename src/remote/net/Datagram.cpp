#include "remote/net/Datagram.h"

namespace faf::remote::net
{
  namespace
  {
    void Put32(std::uint8_t* out, const std::uint32_t value) noexcept
    {
      out[0] = static_cast<std::uint8_t>(value);
      out[1] = static_cast<std::uint8_t>(value >> 8);
      out[2] = static_cast<std::uint8_t>(value >> 16);
      out[3] = static_cast<std::uint8_t>(value >> 24);
    }

    std::uint32_t Get32(const std::uint8_t* in) noexcept
    {
      return static_cast<std::uint32_t>(in[0]) | (static_cast<std::uint32_t>(in[1]) << 8) |
             (static_cast<std::uint32_t>(in[2]) << 16) | (static_cast<std::uint32_t>(in[3]) << 24);
    }
  } // namespace

  void WriteHeader(const DatagramHeader& header, std::uint8_t* const out) noexcept
  {
    out[0] = kDatagramTag;
    out[1] = header.flags;
    Put32(out + 2, header.sequence);
    Put32(out + 6, header.ack);
    Put32(out + 10, header.ackBits);
    out[14] = static_cast<std::uint8_t>(header.ackDelay);
    out[15] = static_cast<std::uint8_t>(header.ackDelay >> 8);
  }

  bool ReadHeader(const std::uint8_t* const data, const std::size_t size, DatagramHeader& out) noexcept
  {
    if (size < kHeaderSize || data[0] != kDatagramTag || (data[1] & ~kKnownFlags) != 0) {
      return false;
    }
    out.flags = data[1];
    out.sequence = Get32(data + 2);
    out.ack = Get32(data + 6);
    out.ackBits = Get32(data + 10);
    out.ackDelay = static_cast<std::uint16_t>(data[14] | (data[15] << 8));
    return out.sequence != 0;
  }

  ReceiveWindow::Verdict ReceiveWindow::Check(const std::uint32_t sequence) const noexcept
  {
    if (sequence == 0) {
      return Verdict::TooOld;
    }
    if (sequence > mNewest) {
      return Verdict::New;
    }
    if (mNewest - sequence >= kSize) {
      return Verdict::TooOld;
    }
    return mSeen.test(sequence % kSize) ? Verdict::Duplicate : Verdict::New;
  }

  void ReceiveWindow::Accept(const std::uint32_t sequence) noexcept
  {
    if (sequence > mNewest) {
      // The slots between the old newest and this one now stand for sequences not received.
      if (sequence - mNewest >= kSize) {
        mSeen.reset();
      } else {
        for (std::uint32_t s = mNewest + 1; s != sequence; ++s) {
          mSeen.reset(s % kSize);
        }
      }
      mNewest = sequence;
    }
    mSeen.set(sequence % kSize);
  }

  std::uint32_t ReceiveWindow::AckBits() const noexcept
  {
    std::uint32_t bits = 0;
    for (std::uint32_t i = 0; i < 32; ++i) {
      const std::uint32_t back = i + 1;
      if (back >= mNewest) {
        break;  // sequence 0 and below were never sent
      }
      if (mSeen.test((mNewest - back) % kSize)) {
        bits |= 1u << i;
      }
    }
    return bits;
  }

  std::uint32_t ReceiveWindow::BitsDownFrom(const std::uint32_t top) const noexcept
  {
    std::uint32_t bits = 0;
    for (std::uint32_t i = 0; i < 32 && i < top; ++i) {
      const std::uint32_t sequence = top - i;
      if (sequence <= mNewest && mNewest - sequence < kSize && mSeen.test(sequence % kSize)) {
        bits |= 1u << i;
      }
    }
    return bits;
  }

  std::size_t VarintSize(std::uint64_t value) noexcept
  {
    std::size_t size = 1;
    while (value >= 0x80) {
      value >>= 7;
      ++size;
    }
    return size;
  }

  void ByteWriter::Varint(std::uint64_t value)
  {
    while (value >= 0x80) {
      mOut.push_back(static_cast<std::uint8_t>(value | 0x80));
      value >>= 7;
    }
    mOut.push_back(static_cast<std::uint8_t>(value));
  }

  std::uint8_t ByteReader::Byte() noexcept
  {
    if (mFailed || mPos >= mSize) {
      mFailed = true;
      return 0;
    }
    return mData[mPos++];
  }

  std::uint64_t ByteReader::Varint() noexcept
  {
    std::uint64_t value = 0;
    for (int shift = 0; shift < 70; shift += 7) {
      const std::uint8_t byte = Byte();
      if (mFailed || (shift == 63 && byte > 1)) {
        mFailed = true;
        return 0;
      }
      value |= static_cast<std::uint64_t>(byte & 0x7F) << shift;
      if ((byte & 0x80) == 0) {
        return value;
      }
    }
    mFailed = true;
    return 0;
  }

  const std::uint8_t* ByteReader::Bytes(const std::size_t size) noexcept
  {
    if (mFailed || size > mSize - mPos) {
      mFailed = true;
      return nullptr;
    }
    const std::uint8_t* const at = mData + mPos;
    mPos += size;
    return at;
  }
} // namespace faf::remote::net
