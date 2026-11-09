#pragma once

// GPGNet framing between the game and its adapter (tools/gpgnet/codec.go,
// moho::CGpgNetInterface), little endian:
//
//   message := string(command) int32(argCount) arg*
//   string  := int32(length) bytes
//   arg     := 0x00 int32 | 0x01 string | 0x02 string (binary data)
//
// Engine addition, not recovered code.

#include <cstdint>
#include <optional>
#include <string>
#include <variant>
#include <vector>

namespace faf::netbridge
{
  struct GpgArg
  {
    enum class Kind : std::uint8_t
    {
      Int = 0,
      String = 1,
      Data = 2
    };
    Kind kind = Kind::Int;
    std::int32_t number = 0;
    std::string text;

    static GpgArg Int(const std::int32_t v) { GpgArg a; a.kind = Kind::Int; a.number = v; return a; }
    static GpgArg Str(std::string s) { GpgArg a; a.kind = Kind::String; a.text = std::move(s); return a; }
  };

  struct GpgMessage
  {
    std::string command;
    std::vector<GpgArg> args;
  };

  std::string EncodeGpg(const GpgMessage& m);

  // Incremental decoder for a TCP stream.
  class GpgDecoder
  {
  public:
    void Feed(const char* data, std::size_t size) { mBuffer.append(data, size); }
    // The next complete message, nullopt when more bytes are needed. Sets
    // *bad on a malformed stream.
    std::optional<GpgMessage> Next(bool* bad);

  private:
    std::string mBuffer;
  };

  std::string DescribeGpg(const GpgMessage& m);
} // namespace faf::netbridge
