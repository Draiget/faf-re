// Shared helpers for faf_reflection_tests: expected archive bytes built by hand from the documented binary format,
// and a fixture that runs a body on a write archive (retail file archive, keyframe fast archive or text archive) and
// on a read archive over given bytes. Files go to a temporary folder the fixture removes.
//
// The binary format the expected bytes follow (WriteArchive::Write 0x00953CA0, WriteRawPointer 0x00953320,
// BinaryWriteArchive 0x009057C0-0x00905B60): each scalar at its width, little-endian; a string as a 32-bit length and
// its bytes; a token as one byte of `} N 0 * {`; an object as `{`, its type handle (-1, name, version the first
// time, the handle's index after), its payload and `}`; a pointer as `0`, `* index` or `N handle payload }`.
#pragma once

#include <cstddef>
#include <cstdint>
#include <filesystem>
#include <functional>
#include <string>
#include <string_view>
#include <gtest/gtest.h>

namespace gpg
{
  class ReadArchive;
  class WriteArchive;
} // namespace gpg

namespace faf_reflection_tests
{
  /** Expected archive bytes, built by hand from the documented format. */
  class Bytes
  {
  public:
    Bytes& I32(const std::int32_t value) { return Raw(&value, 4u); }
    Bytes& U32(const std::uint32_t value) { return Raw(&value, 4u); }
    Bytes& F32(const float value) { return Raw(&value, 4u); }
    Bytes& Str(const std::string_view text)
    {
      I32(static_cast<std::int32_t>(text.size()));
      mBytes.append(text);
      return *this;
    }
    Bytes& Token(const char token)
    {
      mBytes.push_back(token);
      return *this;
    }
    /** `{` and a type handle seen for the first time: -1, the name, the version. */
    Bytes& NewObject(const std::string_view typeName, const std::int32_t version)
    {
      return Token('{').I32(-1).Str(typeName).I32(version);
    }
    /** `{` and the index of a type handle already written. */
    Bytes& KnownObject(const std::int32_t handleIndex) { return Token('{').I32(handleIndex); }
    Bytes& End() { return Token('}'); }
    Bytes& Append(const std::string& bytes)
    {
      mBytes.append(bytes);
      return *this;
    }
    Bytes& Raw(const void* const data, const std::size_t size)
    {
      mBytes.append(static_cast<const char*>(data), size);
      return *this;
    }

    [[nodiscard]] const std::string& str() const noexcept { return mBytes; }

  private:
    std::string mBytes;
  };

  /** Lowercase hex of `bytes`, so a mismatch shows where the bytes differ. */
  [[nodiscard]] std::string ToHex(const std::string& bytes);

  enum class WriterKind
  {
    Binary,   // CreateBinaryWriteArchive: the save-game path
    FastSink, // CreateFastBinaryWriteArchive into memory: the replay keyframe path
  };

  /** A temporary folder for archive files, and the write/read runners. */
  class ArchiveFixture : public ::testing::Test
  {
  protected:
    ArchiveFixture();
    ~ArchiveFixture() override;

    /** Runs `body` on a fresh write archive, closes it and returns the bytes it produced. */
    std::string Write(const std::function<void(gpg::WriteArchive&)>& body, WriterKind kind = WriterKind::Binary);

    /** Runs `body` on a binary read archive over `bytes`. */
    void Read(const std::string& bytes, const std::function<void(gpg::ReadArchive&)>& body);

    /** Runs `body` on a text write archive and returns the text. */
    static std::string WriteText(const std::function<void(gpg::WriteArchive&)>& body);

    /** Runs `body` on a text read archive over `text`. */
    static void ReadText(const std::string& text, const std::function<void(gpg::ReadArchive&)>& body);

  private:
    [[nodiscard]] std::string NextFile(const char* prefix);

    std::filesystem::path mFolder;
    int mCount = 0;
  };
} // namespace faf_reflection_tests
