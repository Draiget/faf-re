#include "MemBufferStream.h"

#include <algorithm>
#include <cstdio>
#include <cstdlib>
#include <cstring>

#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Global.h"

using namespace gpg;

namespace
{
  class MemBufferCharTypeInfo final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0094E760 (FUN_0094E760, MemBufferCharTypeInfo::Init)
     *
     * What it does:
     * Seeds reflection lane size for `gpg::MemBuffer<char>`, then runs
     * base `RType` init/finalize registration.
     */
    void Init() override;
  };

  class MemBufferCharConstTypeInfo final : public gpg::RType
  {
  public:
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0094E830 (FUN_0094E830, MemBufferCharConstTypeInfo::Init)
     *
     * What it does:
     * Seeds reflection lane size for `gpg::MemBuffer<const char>`, then
     * runs base `RType` init/finalize registration.
     */
    void Init() override;
  };

  constexpr const char* kInitialLengthTooLarge = "initial length is too large for the supplied buffer.";
  constexpr const char* kTellInvalidMode = "invalid mode for MemBufferStream::Tell()";
  constexpr const char* kSeekInvalidOrigin = "invalid origin for MemBufferStream::Seek()";
  constexpr const char* kSeekBeforeBegin = "attempt to seek to before the beginning of a stream.";
  constexpr const char* kSeekOutputReadOnly = "can't seek the output position on a read-only MemBufferStream.";
  constexpr const char* kSeekPastEndReadOnly = "Can't seek past the end of a read-only MemBufferStream.";
  constexpr const char* kWriteReadOnly = "Can't write to a read-only MemBufferStream.";
  constexpr const char* kGetBufferReadOnly = "Can't return a mutable buffer from an immutable stream.";
  constexpr const char* kUngetBeyondStart = "Attempt to UnGetByte() beyond the start of the buffer.";
  constexpr const char* kSeekBufferTooLarge = "invalid position for MemBufferStream::Seek() -- buffer too large";

  constexpr const char* kWriteWindowAssertExpr = "size_t(mWriteEnd - mWritePtr) >= bytes";
  constexpr int kWriteWindowAssertLine = 185;
  constexpr const char* kWriteWindowAssertSource =
    "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\streams\\MemBufferStream.cpp";

  constexpr std::uint64_t kMaxStreamPosition = 0x7FFFFFFFULL;
} // namespace

const char* MemBufferCharTypeInfo::GetName() const
{
  return "gpg::MemBuffer<char>";
}

/**
 * Address: 0x0094E760 (FUN_0094E760, MemBufferCharTypeInfo::Init)
 *
 * What it does:
 * Seeds reflection lane size for `gpg::MemBuffer<char>`, then runs
 * base `RType` init/finalize registration.
 */
void MemBufferCharTypeInfo::Init()
{
  size_ = 0x10;
  gpg::RType::Init();
  Finish();
}

const char* MemBufferCharConstTypeInfo::GetName() const
{
  return "gpg::MemBuffer<const char>";
}

/**
 * Address: 0x0094E830 (FUN_0094E830, MemBufferCharConstTypeInfo::Init)
 *
 * What it does:
 * Seeds reflection lane size for `gpg::MemBuffer<const char>`, then
 * runs base `RType` init/finalize registration.
 */
void MemBufferCharConstTypeInfo::Init()
{
  size_ = 0x10;
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x0094E320 (FUN_0094E320)
 *
 * What it does:
 * Allocates a shared byte buffer of `size` bytes, zero-fills it, and returns begin/end view pointers.
 */
MemBuffer<char> gpg::AllocMemBuffer(
  const std::size_t size
)
{
  char* const buff = static_cast<char*>(std::malloc(size));
  if (buff != nullptr && size != 0) {
    std::memset(buff, 0, size);
  }

  boost::shared_ptr<char> ptr(buff, std::free);
  char* const end = (buff == nullptr) ? nullptr : (buff + size);
  return MemBuffer<char>(ptr, buff, end);
}

/**
 * Address: 0x0094E460 (FUN_0094E460, gpg::CopyMemBuffer)
 * What it does:
 * Creates one owned immutable byte view by copying `size` bytes from `source`.
 */
MemBuffer<const char> gpg::CopyMemBuffer(
  const void* const source,
  const std::size_t size
)
{
  if (source == nullptr && size != 0) {
    return {};
  }

  MemBuffer<char> mutableBuffer = AllocMemBuffer(size);
  if (size != 0 && mutableBuffer.mBegin != nullptr) {
    std::memcpy(mutableBuffer.mBegin, source, size);
  }

  return MemBuffer<const char>(mutableBuffer);
}

/**
 * Address: 0x0094E5D0 (FUN_0094E5D0, ?CopyMemBuffer@gpg@@YA?AU?$MemBuffer@D@1@ABU?$MemBuffer@$$CBD@1@@Z)
 *
 * What it does:
 * Copies one immutable mem-buffer view into a new owned immutable byte view.
 */
MemBuffer<char> gpg::CopyMemBuffer(
  const MemBuffer<const char>& source
)
{
  const std::size_t sourceSize = source.Size();
  if (source.mBegin == nullptr && sourceSize != 0) {
    return {};
  }

  MemBuffer<char> copied = AllocMemBuffer(sourceSize);
  if (sourceSize != 0 && copied.mBegin != nullptr) {
    std::memcpy(copied.mBegin, source.mBegin, sourceSize);
  }

  return copied;
}

/**
 * What it does:
 * Loads one file into an owned immutable byte view; returns empty view on failure.
 */
MemBuffer<const char> gpg::LoadFileToMemBuffer(
  const char* const path
)
{
  if (path == nullptr || path[0] == '\0') {
    return {};
  }

  FILE* file = nullptr;
  if (fopen_s(&file, path, "rb") != 0 || file == nullptr) {
    return {};
  }

  if (std::fseek(file, 0, SEEK_END) != 0) {
    std::fclose(file);
    return {};
  }

  const long fileBytes = std::ftell(file);
  if (fileBytes < 0) {
    std::fclose(file);
    return {};
  }

  if (std::fseek(file, 0, SEEK_SET) != 0) {
    std::fclose(file);
    return {};
  }

  const std::size_t byteCount = static_cast<std::size_t>(fileBytes);
  MemBuffer<char> mutableBuffer = AllocMemBuffer(byteCount);
  if (byteCount != 0 && mutableBuffer.mBegin == nullptr) {
    std::fclose(file);
    return {};
  }

  const std::size_t bytesRead = (byteCount != 0) ? std::fread(mutableBuffer.mBegin, 1, byteCount, file) : 0;
  std::fclose(file);

  if (bytesRead != byteCount) {
    return {};
  }

  return MemBuffer<const char>(mutableBuffer);
}

/**
 * Address: 0x004D3060 (FUN_004D3060)
 * Deleting owner: 0x008E5B80 (FUN_008E5B80)
 * Demangled: gpg::MemBufferStream::dtr
 *
 * What it does:
 * Tears down output/input shared-buffer views, then runs Stream base destructor.
 */
MemBufferStream::~MemBufferStream() = default;

/**
 * Address: 0x008E5AE0 (FUN_008E5AE0)
 *
 * What it does:
 * Initializes a writable in-memory stream with a newly allocated backing buffer.
 */
MemBufferStream::MemBufferStream(
  const unsigned int size
)
  : Stream()
  , mInput(AllocMemBuffer(size))
  , mOutput(mInput)
{
  const char* const readBeginConst = mOutput.begin();
  char* const readBegin = const_cast<char*>(readBeginConst);
  mReadStart = readBegin;
  mReadHead = readBegin;
  mReadEnd = readBegin;

  char* const writeBegin = mInput.begin();
  mWriteStart = writeBegin;
  mWriteHead = writeBegin;
  mWriteEnd = mInput.end();
}

/**
 * Address: 0x008E5BA0 (FUN_008E5BA0)
 *
 * What it does:
 * Initializes a writable in-memory stream from caller-owned mutable storage and an initial logical length.
 */
MemBufferStream::MemBufferStream(
  const MemBuffer<char>& input,
  const unsigned int initialLength
)
  : Stream()
  , mInput(input)
  , mOutput(input)
{
  const std::size_t capacity = mInput.Size();
  if (initialLength > capacity) {
    throw std::invalid_argument(kInitialLengthTooLarge);
  }

  const char* const readBeginConst = mOutput.begin();
  char* const readBegin = const_cast<char*>(readBeginConst);
  mReadStart = readBegin;
  mReadHead = readBegin;
  mReadEnd = (readBegin != nullptr) ? (readBegin + initialLength) : nullptr;

  char* const writeBegin = mInput.begin();
  mWriteStart = writeBegin;
  mWriteHead = writeBegin;
  mWriteEnd = (writeBegin != nullptr) ? (writeBegin + initialLength) : nullptr;
}

/**
 * Address: 0x008E5CC0 (FUN_008E5CC0)
 * Mangled: ??0MemBufferStream@gpg@@QAE@ABU?$MemBuffer@$$CBD@1@I@Z
 *
 * What it does:
 * Initializes a read-only in-memory stream from caller-owned const storage and an initial logical length.
 */
MemBufferStream::MemBufferStream(
  const MemBuffer<const char>& output,
  unsigned int initialLength
)
  : Stream()
  , mInput()
  , mOutput(output)
{
  const std::size_t capacity = mOutput.Size();
  if (initialLength == static_cast<unsigned int>(-1)) {
    initialLength = static_cast<unsigned int>(capacity);
  }

  if (initialLength > capacity) {
    throw std::invalid_argument(kInitialLengthTooLarge);
  }

  const char* const readBeginConst = mOutput.begin();
  char* const readBegin = const_cast<char*>(readBeginConst);
  mReadStart = readBegin;
  mReadHead = readBegin;
  mReadEnd = (readBegin != nullptr) ? (readBegin + initialLength) : nullptr;
}

/**
 * Address: 0x008E5A50 (FUN_008E5A50)
 *
 * What it does:
 * Reads up to `len` bytes from current read cursor and advances the read cursor.
 */
size_t MemBufferStream::VirtRead(
  char* const buf,
  const size_t len
)
{
  SyncReadEndWithWriteHead();

  const std::size_t available =
    (mReadEnd != nullptr && mReadHead != nullptr) ? static_cast<std::size_t>(mReadEnd - mReadHead) : 0u;
  const std::size_t bytesToRead = std::min(available, len);
  if (bytesToRead != 0) {
    std::memcpy(buf, mReadHead, bytesToRead);
    mReadHead += bytesToRead;
  }

  return bytesToRead;
}

/**
 * Address: 0x008E5AB0 (FUN_008E5AB0)
 *
 * What it does:
 * Returns true when read cursor reaches the logical end.
 */
bool MemBufferStream::VirtAtEnd()
{
  SyncReadEndWithWriteHead();
  return mReadHead == mReadEnd;
}

/**
 * Address: 0x008E5AD0 (FUN_008E5AD0)
 *
 * What it does:
 * Promotes logical read-end to include pending writes.
 */
void MemBufferStream::VirtFlush()
{
  SyncReadEndWithWriteHead();
}

/**
 * Address: 0x008E59F0 (FUN_008E59F0, gpg::MemBufferStream::GetLength)
 *
 * What it does:
 * Returns the current logical length from the write window when the stream
 * has a live writable end, otherwise from the read window.
 */
unsigned int MemBufferStream::GetLength() const
{
  char* const writeHead = mWriteHead;
  if (writeHead != nullptr && writeHead > mReadEnd) {
    return static_cast<unsigned int>(writeHead - mWriteStart);
  }

  return static_cast<unsigned int>(mReadEnd - mReadStart);
}

/**
 * Address: 0x004CCCD0 (FUN_004CCCD0, gpg::MemBufferStream::GetBuffer)
 *
 * What it does:
 * Returns one mutable buffer view for writable streams and throws on
 * immutable stream instances.
 */
MemBuffer<char> MemBufferStream::GetBuffer() const
{
  if (mInput.begin() == nullptr) {
    throw std::runtime_error(kGetBufferReadOnly);
  }

  return mInput;
}

/**
 * Address: 0x0088B7E0 (FUN_0088B7E0, gpg::MemBufferStream::GetConstBuffer)
 *
 * What it does:
 * Returns one immutable shared output view, retaining the underlying control
 * block when present.
 */
MemBuffer<const char> MemBufferStream::GetConstBuffer() const
{
  return mOutput;
}

/**
 * Address: 0x008E5DC0 (FUN_008E5DC0)
 *
 * What it does:
 * Returns current read/write offset based on mode (`ModeReceive` or `ModeSend`).
 */
std::uint64_t MemBufferStream::VirtTell(
  const Mode mode
)
{
  if (mode == ModeReceive) {
    if (mReadHead == nullptr || mReadStart == nullptr) {
      return 0;
    }
    return static_cast<std::uint64_t>(mReadHead - mReadStart);
  }

  if (mode == ModeSend) {
    if (mWriteHead == nullptr || mWriteStart == nullptr) {
      return 0;
    }
    return static_cast<std::uint64_t>(mWriteHead - mWriteStart);
  }

  throw std::invalid_argument(kTellInvalidMode);
}

/**
 * Address: 0x008E5E70 (FUN_008E5E70)
 *
 * What it does:
 * Throws when asked to unget beyond the start of the in-memory stream.
 */
void MemBufferStream::VirtUnGetByte(
  const int value
)
{
  (void)value;
  throw std::runtime_error(kUngetBeyondStart);
}

/**
 * Address: 0x008E5EE0 (FUN_008E5EE0)
 *
 * What it does:
 * Grows writable storage to satisfy `size`, preserving read/write cursor offsets.
 */
void MemBufferStream::Resize(
  const std::uint64_t size
)
{
  if (size > kMaxStreamPosition) {
    throw std::runtime_error(kSeekBufferTooLarge);
  }

  std::uint64_t resizedCapacity = static_cast<std::uint64_t>(mInput.Size()) * 2ULL;
  if (resizedCapacity < size) {
    do {
      resizedCapacity *= 2ULL;
    } while (resizedCapacity < size);
  }

  if (resizedCapacity > kMaxStreamPosition) {
    throw std::runtime_error(kSeekBufferTooLarge);
  }

  MemBuffer<char> resized = AllocMemBuffer(static_cast<std::size_t>(resizedCapacity));

  const std::size_t writeOffset =
    (mWriteHead != nullptr && mWriteStart != nullptr) ? static_cast<std::size_t>(mWriteHead - mWriteStart) : 0u;
  const std::size_t readOffset =
    (mReadHead != nullptr && mReadStart != nullptr) ? static_cast<std::size_t>(mReadHead - mReadStart) : 0u;
  const std::size_t usedBytes = (mWriteHead != nullptr && mWriteHead > mReadEnd)
    ? writeOffset
    : ((mReadEnd != nullptr && mReadStart != nullptr) ? static_cast<std::size_t>(mReadEnd - mReadStart) : 0u);

  if (usedBytes != 0) {
    std::memcpy(resized.begin(), mInput.begin(), usedBytes);
  }

  mInput = resized;
  mWriteStart = mInput.begin();
  mWriteHead = (mWriteStart != nullptr) ? (mWriteStart + writeOffset) : nullptr;
  mWriteEnd = mInput.end();

  mOutput = mInput;
  mReadStart = const_cast<char*>(mOutput.begin());
  mReadHead = (mReadStart != nullptr) ? (mReadStart + readOffset) : nullptr;
  mReadEnd = (mReadStart != nullptr) ? (mReadStart + static_cast<std::size_t>(size)) : nullptr;
}

/**
 * Address: 0x008E6140 (FUN_008E6140)
 *
 * What it does:
 * Seeks read/write cursors by mode and origin, growing writable storage and zero-filling gaps when needed.
 */
std::uint64_t MemBufferStream::VirtSeek(
  const Mode mode,
  const SeekOrigin origin,
  const std::int64_t pos
)
{
  SyncReadEndWithWriteHead();

  const std::int64_t offset = pos;
  const std::int64_t currentReadOffset =
    (mReadHead != nullptr && mReadStart != nullptr) ? static_cast<std::int64_t>(mReadHead - mReadStart) : 0;
  const std::int64_t currentLength =
    (mReadEnd != nullptr && mReadStart != nullptr) ? static_cast<std::int64_t>(mReadEnd - mReadStart) : 0;
  std::int64_t readPos = currentReadOffset;

  std::int64_t returnPos = 0;
  if ((mode & ModeReceive) != 0) {
    if (origin == OriginBegin) {
      readPos = offset;
    } else if (origin == OriginCurr) {
      readPos = currentReadOffset + offset;
    } else if (origin == OriginEnd) {
      readPos = currentLength + offset;
    } else {
      throw std::invalid_argument(kSeekInvalidOrigin);
    }

    if (readPos < 0) {
      throw std::invalid_argument(kSeekBeforeBegin);
    }

    returnPos = readPos;
  }

  std::int64_t writePos = 0;
  if (mWriteHead != nullptr && mWriteStart != nullptr) {
    writePos = static_cast<std::int64_t>(mWriteHead - mWriteStart);
  }
  if ((mode & ModeSend) != 0) {
    if (mInput.begin() == nullptr) {
      throw std::logic_error(kSeekOutputReadOnly);
    }

    const std::int64_t currentWriteOffset =
      (mWriteHead != nullptr && mWriteStart != nullptr) ? static_cast<std::int64_t>(mWriteHead - mWriteStart) : 0;
    if (origin == OriginBegin) {
      writePos = offset;
    } else if (origin == OriginCurr) {
      writePos = currentWriteOffset + offset;
    } else if (origin == OriginEnd) {
      writePos = currentLength + offset;
    } else {
      throw std::invalid_argument(kSeekInvalidOrigin);
    }

    if (writePos < 0) {
      throw std::invalid_argument(kSeekBeforeBegin);
    }

    returnPos = writePos;
  }

  const std::int64_t maxPos = std::max(readPos, writePos);
  if (maxPos > currentLength) {
    if (mInput.begin() == nullptr) {
      throw std::runtime_error(kSeekPastEndReadOnly);
    }

    if (maxPos > static_cast<std::int64_t>(mInput.Size())) {
      Resize(static_cast<std::uint64_t>(maxPos));
    }

    const std::size_t fillOffset = static_cast<std::size_t>(currentLength);
    const std::size_t fillCount = static_cast<std::size_t>(maxPos - currentLength);
    if (fillCount != 0) {
      std::memset(mInput.begin() + fillOffset, 0, fillCount);
    }
  }

  mWriteHead = (mWriteStart != nullptr) ? (mWriteStart + static_cast<std::size_t>(writePos)) : nullptr;
  mReadHead = (mReadStart != nullptr) ? (mReadStart + static_cast<std::size_t>(readPos)) : nullptr;
  return static_cast<std::uint64_t>(returnPos);
}

/**
 * Address: 0x008E6470 (FUN_008E6470)
 *
 * What it does:
 * Writes bytes to current write cursor, growing writable storage on demand.
 */
void MemBufferStream::VirtWrite(
  const char* const data,
  const size_t size
)
{
  if (mInput.begin() == nullptr) {
    throw std::runtime_error(kWriteReadOnly);
  }

  if ((mWriteHead + size) > mWriteEnd) {
    const std::uint64_t needed =
      static_cast<std::uint64_t>(mWriteHead - mWriteStart) + static_cast<std::uint64_t>(size);
    Resize(needed);
  }

  if (static_cast<size_t>(mWriteEnd - mWriteHead) < size) {
    HandleAssertFailure(kWriteWindowAssertExpr, kWriteWindowAssertLine, kWriteWindowAssertSource);
  }

  std::memcpy(mWriteHead, data, size);
  mWriteHead += size;
  if (mWriteHead > mReadEnd) {
    mReadEnd = mWriteHead;
  }
}

void MemBufferStream::SyncReadEndWithWriteHead()
{
  if (mWriteHead != nullptr && mWriteHead > mReadEnd) {
    mReadEnd = mWriteHead;
  }
}
