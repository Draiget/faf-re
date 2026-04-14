#pragma once

#include <cstddef>
#include <cstdint>
#include <type_traits>

#include "legacy/containers/String.h"

namespace gpg
{
  class Stream;

  class BinaryWriter
  {
  public:
    BinaryWriter() = default;

    explicit BinaryWriter(Stream* stream, const std::uint32_t port = 0u)
      : mStream(stream)
      , mPort(port)
      , mReserved0(0u)
      , mReserved1(0u)
    {
    }

    /**
     * Address: <paired with BinaryReader::Read fast-path lane>
     *
     * What it does:
     * Writes exactly `size` bytes using the stream inline write window when
     * possible, falling back to `VirtWrite` on short local space.
     */
    void Write(const char* data, std::size_t size) const;

    /**
     * Address: <paired with Stream::Write(msvc8::string)>
     *
     * What it does:
     * Writes one NUL-terminated legacy string payload.
     */
    void WriteString(const msvc8::string& value) const;

    /**
     * Address: <compat helper for pointer-style callsites>
     *
     * What it does:
     * Writes one optional NUL-terminated legacy string payload.
     */
    void WriteString(const msvc8::string* value) const;

    /**
     * Writes one trivially-copyable scalar by raw bytes.
     */
    template <class TValue>
    std::enable_if_t<std::is_trivially_copyable_v<TValue>, void> Write(const TValue& value) const
    {
      Write(reinterpret_cast<const char*>(&value), sizeof(value));
    }

    [[nodiscard]] Stream* stream() const noexcept
    {
      return mStream;
    }

  private:
    Stream* mStream = nullptr;   // +0x00
    std::uint32_t mPort = 0u;    // +0x04
    std::uint32_t mReserved0 = 0u; // +0x08
    std::uint32_t mReserved1 = 0u; // +0x0C
  };

  static_assert(sizeof(BinaryWriter) == 0x10, "gpg::BinaryWriter size must be 0x10");
} // namespace gpg

