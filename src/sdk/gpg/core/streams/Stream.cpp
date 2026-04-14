#include "Stream.h"
#include <cstdarg>
#include <cstring>

#include "gpg/core/utils/Global.h"
using namespace gpg;

/**
 * Address: 0x00956DB0 (FUN_00956DB0)
 *
 * What it does:
 * Initializes stream read/write window pointers to null.
 */
Stream::Stream()
  : mReadStart(nullptr)
  , mReadHead(nullptr)
  , mReadEnd(nullptr)
  , mWriteStart(nullptr)
  , mWriteHead(nullptr)
  , mWriteEnd(nullptr)
{}

/**
 * Address: 0x00956DD0 (FUN_00956DD0, non-deleting dtor lane)
 * Address: 0x00956E20 (FUN_00956E20)
 *
 * What it does:
 * Resets Stream vftable in the base dtor lane and owns deleting-dtor dispatch
 * for scalar delete.
 */
Stream::~Stream() = default;

/**
 * Address: 0x00956E40 (FUN_00956E40)
 *
 * What it does:
 * Constructs the standard "Unsupported stream operation." logic_error payload.
 */
Stream::UnsupportedOperation::UnsupportedOperation()
  : std::logic_error{std::string{"Unsupported stream operation."}}
{}

/**
 * Address: 0x00956F50 (FUN_00956F50)
 *
 * What it does:
 * Default seek-position query lane throws UnsupportedOperation.
 */
std::uint64_t Stream::VirtTell(Mode)
{
  throw UnsupportedOperation{};
}

/**
 * Address: 0x00956F90 (FUN_00956F90)
 *
 * What it does:
 * Default seek lane throws UnsupportedOperation.
 */
std::uint64_t Stream::VirtSeek(Mode, SeekOrigin, std::int64_t)
{
  throw UnsupportedOperation{};
}

/**
 * Address: 0x00956FB0 (FUN_00956FB0)
 *
 * What it does:
 * Default read lane throws UnsupportedOperation.
 */
size_t Stream::VirtRead(char*, size_t)
{
  throw UnsupportedOperation{};
}

/**
 * Address: 0x00956DE0 (FUN_00956DE0)
 *
 * What it does:
 * Default non-blocking read forwards to VirtRead.
 */
size_t Stream::VirtReadNonBlocking(char* buf, size_t len)
{
  return VirtRead(buf, len);
}

/**
 * Address: 0x00956FD0 (FUN_00956FD0)
 *
 * What it does:
 * Default unget lane throws UnsupportedOperation.
 */
void Stream::VirtUnGetByte(int unknown)
{
  throw UnsupportedOperation{};
}

/**
 * Address: 0x00956DF0 (FUN_00956DF0)
 *
 * What it does:
 * Default end-of-stream query returns false.
 */
bool Stream::VirtAtEnd()
{
  return false;
}

/**
 * Address: 0x00956FF0 (FUN_00956FF0)
 *
 * What it does:
 * Default write lane throws UnsupportedOperation.
 */
void Stream::VirtWrite(const char* data, size_t size)
{
  throw UnsupportedOperation{};
}

/**
 * Address: 0x00956E00 (FUN_00956E00)
 *
 * What it does:
 * Default flush lane is a no-op.
 */
void Stream::VirtFlush() {}

/**
 * Address: 0x00956E10 (FUN_00956E10)
 *
 * What it does:
 * Default close lane is a no-op.
 */
void Stream::VirtClose(Mode) {}

/**
 * Address: 0x0046BED0 (FUN_0046BED0, __imp_?Seek@Stream@gpg@@QAE_KW4Mode@12@W4SeekOrigin@12@_J@Z)
 *
 * What it does:
 * Non-virtual receive-lane seek wrapper that forwards to `VirtSeek` with
 * `ModeReceive`.
 */
std::uint64_t Stream::Seek(const SeekOrigin origin, const std::int64_t pos)
{
  return VirtSeek(ModeReceive, origin, pos);
}

/**
 * Address: 0x006E5A10 (FUN_006E5A10)
 *
 * What it does:
 * Writes string bytes including trailing NUL via inline buffer or virtual write fallback.
 */
void Stream::Write(const msvc8::string& str)
{
  Write(str.c_str(), str.size() + 1);
}

/**
 * Address: 0x0043D130 (FUN_0043D130)
 * Address: 0x004D4E00 (FUN_004D4E00, __imp_?Write@Stream@gpg@@QAEXPBXI@Z)
 * Address: 0x004D4E30 (FUN_004D4E30, __imp_?Write@Stream@gpg@@QAEXPBXI@Z alias)
 *
 * What it does:
 * Writes one byte span via inline buffer fast path or virtual write fallback.
 */
void Stream::Write(const char* buf, const size_t size)
{
  if (size > LeftToWrite()) {
    VirtWrite(buf, size);
    return;
  }

  memcpy(mWriteHead, buf, size);
  mWriteHead += size;
}

/**
 * Address: 0x004CCD80 (FUN_004CCD80)
 *
 * What it does:
 * Writes one NUL-terminated C-string including terminator.
 */
void Stream::Write(const char* buf)
{
  const auto len = strlen(buf) + 1;
  Write(buf, len);
}

/**
 * Address: 0x004455B0 (FUN_004455B0)
 *
 * What it does:
 * Writes one 32-bit integer through inline-buffer fast path or virtual write fallback.
 */
void Stream::WriteInt32(const std::int32_t value)
{
  if (static_cast<unsigned int>(mWriteEnd - mWriteHead) < sizeof(value)) {
    VirtWrite(reinterpret_cast<const char*>(&value), sizeof(value));
    return;
  }

  *reinterpret_cast<std::int32_t*>(mWriteHead) = value;
  mWriteHead += sizeof(value);
}

/**
 * Address: 0x00955760 (FUN_00955760)
 *
 * What it does:
 * Calls `VirtClose(mode)` and converts any exception into a `false` return.
 */
bool Stream::CloseNoThrow(const Mode access)
{
  try {
    VirtClose(access);
    return true;
  } catch (...) {
    return false;
  }
}

bool Stream::Close(const Mode access)
{
  VirtClose(access);
  return true;
}

/**
 * Address: 0x0043D100 (FUN_0043D100)
 *
 * What it does:
 * Reads one byte span from inline read window or virtual read fallback.
 */
size_t Stream::Read(char* buf, size_t size)
{
  if (size > BytesRead()) {
    size = VirtRead(buf, size);
  } else if (size) {
    memcpy(buf, mReadHead, size);
    mReadHead += size;
  }
  return size;
}

/**
 * Address: 0x004CCC10 (FUN_004CCC10)
 *
 * What it does:
 * Rewinds one byte with value validation or delegates to virtual unget at read window boundary.
 */
void Stream::UnGetByte(const int value)
{
  char* const readHead = mReadHead;
  if (readHead == mReadStart) {
    VirtUnGetByte(value);
    return;
  }

  const int previousValue = static_cast<unsigned char>(*(readHead - 1));
  if (value != previousValue) {
    throw std::invalid_argument("Invalid argument to Stream::UnGetByte()");
  }

  mReadHead = readHead - 1;
}

/**
 * Address: 0x004D29F0 (FUN_004D29F0, gpg::Stream::CheckByte)
 *
 * What it does:
 * Reads one byte (buffer-fast-path or virtual fallback), rewinds it with
 * `UnGetByte`, and returns that byte value; returns `255` on EOF.
 */
int Stream::CheckByte()
{
  unsigned char value = 0;
  if (mReadHead == mReadEnd) {
    if (VirtRead(reinterpret_cast<char*>(&value), 1U) == 0U) {
      return 255;
    }
  } else {
    value = static_cast<unsigned char>(*mReadHead);
    ++mReadHead;
  }

  UnGetByte(static_cast<int>(value));
  return static_cast<int>(value);
}

void gpg::UnGetByteChecked(Stream& stream, const int value)
{
  stream.UnGetByte(value);
}

size_t Stream::ReadNonBlocking(char* buf, size_t size)
{
  if (size > BytesRead()) {
    size = VirtReadNonBlocking(buf, size);
  } else if (size) {
    memcpy(buf, mReadHead, size);
    mReadHead += size;
  }
  return size;
}

int8_t Stream::GetByte()
{
  if (mReadHead != mReadEnd) {
    const unsigned char c = static_cast<unsigned char>(*mReadHead);
    ++mReadHead;
    return static_cast<int8_t>(c);
  }

  unsigned char b = 0;
  const size_t got = VirtRead(reinterpret_cast<char*>(&b), 1u);
  if (got == 1u) {
    return static_cast<int8_t>(b);
  }

  return -1;
}

/**
 * Address: 0x00957040 (FUN_00957040)
 *
 * What it does:
 * Initializes writer state around a target stream and configured line-ending mode.
 */
TextWriter::TextWriter(Stream* const stream, const int mode)
  : mStream(stream)
  , mMode(mode)
  , mSawCarriageReturn(false)
{}

void TextWriter::WriteByte(const char value)
{
  if (mStream->mWriteHead == mStream->mWriteEnd) {
    mStream->VirtWrite(&value, 1);
    return;
  }

  *mStream->mWriteHead = value;
  ++mStream->mWriteHead;
}

/**
 * Address: 0x00957060 (FUN_00957060)
 *
 * What it does:
 * Emits one logical newline according to configured line-ending mode.
 */
void TextWriter::WriteNewline()
{
  switch (mMode) {
  case 0:
  case 1:
    WriteByte('\n');
    return;
  case 2:
    WriteByte('\r');
    WriteByte('\n');
    return;
  case 3:
    WriteByte('\r');
    return;
  default:
    HandleAssertFailure(
      "Reached the supposably unreachable.",
      40,
      "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\streams\\TextWriter.cpp"
    );
    return;
  }
}

/**
 * Address: 0x00957130 (FUN_00957130)
 *
 * What it does:
 * Writes one character with optional CR/LF normalization depending on writer mode.
 */
void TextWriter::WriteChar(const char value)
{
  if (mMode == 0) {
    WriteByte(value);
    return;
  }

  if (value == '\n') {
    if (mSawCarriageReturn) {
      mSawCarriageReturn = false;
      return;
    }
    WriteNewline();
    return;
  }

  if (value == '\r') {
    mSawCarriageReturn = true;
    WriteNewline();
    return;
  }

  mSawCarriageReturn = false;
  WriteByte(value);
}

/**
 * Address: 0x009571B0 (FUN_009571B0)
 *
 * What it does:
 * Writes one NUL-terminated C-string through WriteChar normalization.
 */
void TextWriter::WriteCString(const char* value)
{
  if (!value) {
    return;
  }

  for (char ch = *value; ch != '\0'; ch = *++value) {
    WriteChar(ch);
  }
}

/**
 * Address: 0x00957210 (FUN_00957210)
 *
 * What it does:
 * Writes one msvc8::string payload through WriteChar normalization.
 */
void TextWriter::WriteString(const msvc8::string& value)
{
  const char* const raw = value.data();
  const std::size_t length = value.size();
  for (std::size_t i = 0; i < length; ++i) {
    WriteChar(raw[i]);
  }
}

/**
 * Address: 0x00957250 (FUN_00957250)
 *
 * What it does:
 * Formats one vararg message with STR_Va and writes it through this TextWriter.
 */
void TextWriter::Printf(const char* const format, ...)
{
  va_list va;
  va_start(va, format);
  const char* formatRef = format;
  const msvc8::string rendered = STR_Va(formatRef, va);
  va_end(va);
  WriteString(rendered);
}
