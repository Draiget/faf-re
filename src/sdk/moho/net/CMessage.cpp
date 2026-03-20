#include "CMessage.h"

#include <cstddef>
#include <stdexcept>
#include <string>

#include "gpg/core/streams/Stream.h"
using namespace moho;

namespace
{
  constexpr std::size_t kHeaderSize = 3;
  constexpr std::size_t kMaxWireSizeExclusive = 0x10000;
} // namespace

/**
 * Address: 0x00483510 (FUN_00483510)
 *
 * What it does:
 * Initializes inline message storage and resets incremental read cursor.
 */
CMessage::CMessage()
{
  mPos = 0;
}

/**
 * Address: 0x00483490 (FUN_00483490)
 * Address: 0x10076360 (sub_10076360)
 * Address: 0x100763B0 (sub_100763B0)
 *
 * What it does:
 * Initializes message buffer with 3-byte header and requested payload space.
 */
CMessage::CMessage(const MessageType type, size_t size)
{
  size += kHeaderSize;
  constexpr char fill = 0;
  mBuff.Resize(size, fill);
  SetSize(size);
  SetType(type);
  mPos = 0;
}

/**
 * Address: <synthetic host-build helper>
 *
 * What it does:
 * Deep-copies message storage and read cursor for host-side containers/callers.
 */
CMessage::CMessage(const CMessage& other)
{
  mBuff.ResetFrom(other.mBuff);
  mPos = other.mPos;
}

/**
 * Address: <synthetic host-build helper>
 *
 * What it does:
 * Deep-copy assignment for message storage and read cursor.
 */
CMessage& CMessage::operator=(const CMessage& other)
{
  if (this == &other) {
    return *this;
  }

  mBuff.ResetFrom(other.mBuff);
  mPos = other.mPos;
  return *this;
}

/**
 * Address: <synthetic host-build helper>
 *
 * What it does:
 * Transfers message state by clone+reset semantics.
 */
CMessage::CMessage(CMessage&& other)
{
  mBuff.ResetFrom(other.mBuff);
  mPos = other.mPos;
  other.Clear();
}

/**
 * Address: <synthetic host-build helper>
 *
 * What it does:
 * Move assignment via clone+reset semantics.
 */
CMessage& CMessage::operator=(CMessage&& other)
{
  if (this == &other) {
    return *this;
  }

  mBuff.ResetFrom(other.mBuff);
  mPos = other.mPos;
  other.Clear();
  return *this;
}

/**
 * Address: 0x0047BE90 (FUN_0047BE90)
 * Address: 0x100764F0 (sub_100764F0)
 *
 * What it does:
 * Returns payload size (wire-size minus header size).
 */
int CMessage::GetMessageSize()
{
  int size = GetSize();
  if (size >= static_cast<int>(kHeaderSize)) {
    size -= static_cast<int>(kHeaderSize);
  }
  return size;
}

/**
 * Address: 0x0047BDE0 (FUN_0047BDE0)
 * Address: 0x10076460 (sub_10076460)
 *
 * What it does:
 * Appends raw bytes, updates header size bytes, and returns header high-byte.
 */
unsigned int CMessage::Append(const char* ptr, const size_t size)
{
  if (mBuff.Size() + size >= kMaxWireSizeExclusive) {
    throw std::runtime_error{std::string{"Message too large"}};
  }

  mBuff.InsertAt(mBuff.end_, ptr, &ptr[size]);

  const auto targetSize = mBuff.Size();
  SetSize(targetSize);
  return static_cast<unsigned int>(targetSize >> 8);
}

/**
 * Address: 0x00483530 (FUN_00483530)
 *
 * What it does:
 * Resets storage to inline vector and clears incremental read cursor.
 */
void CMessage::Clear() noexcept
{
  mBuff.ResetStorageToInline();
  mPos = 0;
}

/**
 * Address: 0x0047BD40 (FUN_0047BD40)
 * Address: 0x100763E0 (sub_100763E0)
 *
 * What it does:
 * Reads a complete wire message (header first, then payload).
 */
bool CMessage::ReadMessage(gpg::Stream* stream)
{
  constexpr char fill = 0;
  mBuff.Resize(kHeaderSize, fill);
  if (stream->Read(mBuff.start_, kHeaderSize) != kHeaderSize) {
    return false;
  }
  const size_t wireSize = GetSize();
  if (wireSize < kHeaderSize) {
    return false;
  }
  if (wireSize == kHeaderSize) {
    return true;
  }
  mBuff.Resize(wireSize, fill);
  return stream->Read(&mBuff[kHeaderSize], wireSize - kHeaderSize) == wireSize - kHeaderSize;
}

/**
 * Address: 0x0047BEE0 (FUN_0047BEE0)
 * Address: 0x10076530 (sub_10076530)
 *
 * What it does:
 * Incrementally reads header and payload with non-blocking stream reads.
 */
bool CMessage::Read(gpg::Stream* stream)
{
  if (!HasReadLength()) {
    if (mBuff.Size() == 0) {
      constexpr char fill = 0;
      mBuff.Resize(kHeaderSize, fill);
    }
    mPos += static_cast<int>(stream->ReadNonBlocking(&mBuff[mPos], kHeaderSize - mPos));
    if (!HasReadLength()) {
      return false;
    }
  }
  const int newSize = GetSize();
  if (newSize < static_cast<int>(kHeaderSize)) {
    return false;
  }
  if (newSize == mPos) {
    return true;
  }
  constexpr char fill = 0;
  mBuff.Resize(newSize, fill);
  mPos += static_cast<int>(stream->ReadNonBlocking(&mBuff[mPos], newSize - mPos));
  return mPos == newSize;
}
