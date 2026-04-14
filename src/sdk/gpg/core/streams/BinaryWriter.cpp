#include "BinaryWriter.h"

#include <cstring>

#include "Stream.h"

namespace gpg
{
/**
 * Address: <paired with BinaryReader::Read fast-path lane>
 *
 * What it does:
 * Writes exactly `size` bytes using the stream inline write window when
 * possible, falling back to `VirtWrite` when the inline space is exhausted.
 */
void BinaryWriter::Write(const char* const data, const std::size_t size) const
{
  Stream* const targetStream = mStream;
  if (size > static_cast<std::size_t>(targetStream->mWriteEnd - targetStream->mWriteHead)) {
    targetStream->VirtWrite(data, size);
    return;
  }

  if (size != 0u) {
    std::memcpy(targetStream->mWriteHead, data, size);
    targetStream->mWriteHead += size;
  }
}

/**
 * Address: <paired with Stream::Write(msvc8::string)>
 *
 * What it does:
 * Writes one NUL-terminated legacy string payload.
 */
void BinaryWriter::WriteString(const msvc8::string& value) const
{
  Write(value.c_str(), value.size() + 1u);
}

/**
 * Address: <compat helper for pointer-style callsites>
 *
 * What it does:
 * Writes one optional NUL-terminated legacy string payload.
 */
void BinaryWriter::WriteString(const msvc8::string* const value) const
{
  if (value == nullptr) {
    static constexpr char kEmptyTerminator = '\0';
    Write(&kEmptyTerminator, 1u);
    return;
  }

  WriteString(*value);
}

} // namespace gpg

