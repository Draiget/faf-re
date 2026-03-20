#include "CMessageStream.h"

#include <cstddef>
#include <cstring>
#include <stdexcept>

#include "CMessage.h"
using namespace moho;

namespace
{
  constexpr std::size_t kHeaderSize = 3;
}

/**
 * Address: 0x0047C030 (FUN_0047C030)
 * Address: 0x10076630 (sub_10076630)
 *
 * What it does:
 * Destroys stream wrapper; backing message remains owned externally.
 */
CMessageStream::~CMessageStream() = default;

/**
 * Address: 0x0047C0F0 (FUN_0047C0F0)
 * Address: 0x100766F0 (sub_100766F0)
 *
 * What it does:
 * Copies at most `len` bytes from read window and advances `mReadHead`.
 */
size_t CMessageStream::VirtRead(char* buff, size_t len)
{
  const size_t readable = static_cast<size_t>(mReadEnd - mReadHead);
  if (len > readable) {
    len = readable;
  }

  std::memcpy(buff, mReadHead, len);
  mReadHead += len;
  return len;
}

/**
 * Address: 0x0047C120 (FUN_0047C120)
 * Address: 0x10076720 (sub_10076720)
 *
 * What it does:
 * Returns whether stream read cursor reached payload end.
 */
bool CMessageStream::VirtAtEnd()
{
  return mReadHead == mReadEnd;
}

/**
 * Address: 0x0047C130 (FUN_0047C130)
 * Address: 0x10076730 (sub_10076730)
 *
 * What it does:
 * Writes into payload window, appends overflow into message buffer, then rebinds pointers.
 */
void CMessageStream::VirtWrite(const char* data, const size_t size)
{
  if (mWriteStart == nullptr) {
    throw std::logic_error("Can't write to a read-only message.");
  }

  size_t writeSize = static_cast<size_t>(mWriteEnd - mWriteHead);
  if (writeSize > size) {
    writeSize = size;
  }

  if (writeSize != 0) {
    std::memcpy(mWriteHead, data, writeSize);
    mWriteHead += writeSize;
  }

  const size_t overflowSize = size - writeSize;
  if (overflowSize == 0) {
    return;
  }

  const std::ptrdiff_t readOffset = mReadHead - mReadStart;
  const std::ptrdiff_t writeOffset = mWriteHead - mWriteStart;

  mMessage->Append(data + writeSize, overflowSize);
  RebindToPayloadUnchecked(readOffset, writeOffset + static_cast<std::ptrdiff_t>(overflowSize));
}

/**
 * Address: 0x0047BFE0 (FUN_0047BFE0)
 * Address: 0x100765E0 (sub_100765E0)
 *
 * What it does:
 * Constructs a read/write stream over message payload bytes.
 */
CMessageStream::CMessageStream(CMessage& msg)
  : Stream()
  , mMessage(&msg)
{
  auto [begin, end] = PayloadWindow(*mMessage);

  mReadStart = begin;
  mReadHead = begin;
  mReadEnd = end;
  mWriteStart = begin;
  mWriteHead = begin;
  mWriteEnd = end;
}

/**
 * Address: 0x0047C060 (FUN_0047C060)
 * Address: 0x10076660 (sub_10076660)
 *
 * What it does:
 * Constructs a read-only stream over message payload bytes.
 */
CMessageStream::CMessageStream(CMessage* msg)
  : Stream()
  , mMessage(msg)
{
  auto [begin, end] = PayloadWindow(*mMessage);

  mReadStart = begin;
  mReadHead = begin;
  mReadEnd = end;
  mWriteStart = nullptr;
  mWriteHead = nullptr;
  mWriteEnd = nullptr;
}

/**
 * Address: <synthetic host-build helper>
 *
 * What it does:
 * Optional access-mode wrapper over the binary read/write ctor.
 */
CMessageStream::CMessageStream(CMessage& msg, const Access access)
  : CMessageStream(msg)
{
  if (access == Access::kReadOnly) {
    mWriteStart = nullptr;
    mWriteHead = nullptr;
    mWriteEnd = nullptr;
  }
}

/**
 * Address: <synthetic host-build helper>
 *
 * What it does:
 * Optional access-mode wrapper over the binary read-only ctor.
 */
CMessageStream::CMessageStream(CMessage* msg, const Access access)
  : CMessageStream(msg)
{
  if (access == Access::kReadWrite) {
    mWriteStart = mReadStart;
    mWriteHead = mReadStart;
    mWriteEnd = mReadEnd;
  }
}

std::pair<char*, char*> CMessageStream::PayloadWindow(CMessage& m) noexcept
{
  char* const payloadBegin = m.mBuff.start_ + kHeaderSize;
  const std::size_t messageSize = m.GetSize();
  const std::size_t payloadSize = (messageSize >= kHeaderSize) ? (messageSize - kHeaderSize) : 0;
  return {payloadBegin, payloadBegin + payloadSize};
}

void CMessageStream::RebindToPayloadUnchecked(const std::ptrdiff_t readOff, const std::ptrdiff_t writeOffPlus) noexcept
{
  auto [begin, end] = PayloadWindow(*mMessage);

  mReadHead = begin + readOff;
  mReadStart = begin;
  mWriteStart = begin;
  mReadEnd = end;
  mWriteHead = begin + writeOffPlus;
  mWriteEnd = end;
}
