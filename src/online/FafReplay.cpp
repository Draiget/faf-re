// Engine addition (in-game launcher plan, WP5, the launcher's replays): FAF's .fafreplay file (online/FafReplay.h).

#include "online/FafReplay.h"

#include <cstddef>
#include <cstdint>

#include "zlib.h"
#include "zstd.h"

namespace faf::online
{
  namespace
  {
    /** No replay stream is anywhere near this; a larger one is a damaged or hostile file. */
    constexpr std::size_t kMaxStream = 512u * 1024u * 1024u;

    std::expected<std::string, std::string> Unzstd(
      const std::string& body
    )
    {
      ZSTD_DStream* const stream = ZSTD_createDStream();
      if (stream == nullptr) {
        return std::unexpected(std::string("no memory for zstd"));
      }
      (void)ZSTD_initDStream(stream);
      std::string out;
      ZSTD_inBuffer in{body.data(), body.size(), 0};
      std::string chunk(ZSTD_DStreamOutSize(), '\0');
      std::size_t last = 1;
      while (in.pos < in.size || last != 0) {
        ZSTD_outBuffer target{chunk.data(), chunk.size(), 0};
        last = ZSTD_decompressStream(stream, &target, &in);
        if (ZSTD_isError(last) != 0u) {
          ZSTD_freeDStream(stream);
          return std::unexpected(std::string("the replay's zstd data is damaged: ") + ZSTD_getErrorName(last));
        }
        out.append(chunk.data(), target.pos);
        if (out.size() > kMaxStream) {
          ZSTD_freeDStream(stream);
          return std::unexpected(std::string("the replay is too large"));
        }
        if (target.pos == 0 && in.pos == in.size) {
          break; // nothing more comes out: the frame ended early (truncated file) or exactly here
        }
      }
      ZSTD_freeDStream(stream);
      if (last != 0) {
        return std::unexpected(std::string("the replay's zstd data ends early"));
      }
      return out;
    }

    std::expected<std::string, std::string> Unzlib(
      const std::string& blob
    )
    {
      if (blob.size() < 4) {
        return std::unexpected(std::string("the replay's data is too short"));
      }
      const auto byte = [&](const std::size_t at) {
        return static_cast<std::uint32_t>(static_cast<unsigned char>(blob[at]));
      };
      const std::uint32_t length = (byte(0) << 24) | (byte(1) << 16) | (byte(2) << 8) | byte(3);
      if (length > kMaxStream) {
        return std::unexpected(std::string("the replay is too large"));
      }
      std::string out(length, '\0');
      uLongf size = length;
      const int result = uncompress(
        reinterpret_cast<Bytef*>(out.data()),
        &size,
        reinterpret_cast<const Bytef*>(blob.data() + 4),
        static_cast<uLong>(blob.size() - 4)
      );
      if (result != Z_OK || size != length) {
        return std::unexpected("the replay's zlib data is damaged (zlib " + std::to_string(result) + ")");
      }
      return out;
    }
  } // namespace

  std::expected<std::string, std::string> DecodeBase64(
    const std::string& text
  )
  {
    std::string out;
    out.reserve(text.size() / 4 * 3);
    std::uint32_t bits = 0;
    int count = 0;
    for (const char c : text) {
      int value = -1;
      if (c >= 'A' && c <= 'Z') {
        value = c - 'A';
      } else if (c >= 'a' && c <= 'z') {
        value = c - 'a' + 26;
      } else if (c >= '0' && c <= '9') {
        value = c - '0' + 52;
      } else if (c == '+' || c == '-') {
        value = 62;
      } else if (c == '/' || c == '_') {
        value = 63;
      } else if (c == '=' || c == '\r' || c == '\n' || c == ' ' || c == '\t') {
        continue;
      } else {
        return std::unexpected(std::string("not base64"));
      }
      bits = (bits << 6) | static_cast<std::uint32_t>(value);
      count += 6;
      if (count >= 8) {
        count -= 8;
        out.push_back(static_cast<char>((bits >> count) & 0xFFu));
      }
    }
    return out;
  }

  std::expected<JsonNode, std::string> ReadFafReplayHeader(
    const std::string& raw
  )
  {
    const std::size_t end = raw.find('\n');
    if (end == std::string::npos || raw.empty() || raw[0] != '{') {
      return std::unexpected(std::string("not a FAF replay (no header line)"));
    }
    auto header = ParseJson(raw.substr(0, end));
    if (!header || header->kind != JsonNode::Kind::Object) {
      return std::unexpected(std::string("not a FAF replay (its header isn't JSON)"));
    }
    return header;
  }

  std::expected<FafReplayFile, std::string> DecodeFafReplay(
    const std::string& raw
  )
  {
    auto header = ReadFafReplayHeader(raw);
    if (!header) {
      return std::unexpected(header.error());
    }
    const std::string body = raw.substr(raw.find('\n') + 1);
    FafReplayFile file;
    file.header = std::move(*header);
    const bool zstd = file.header.String("compression") == "zstd" ||
      (body.size() >= 4 && static_cast<unsigned char>(body[0]) == 0x28 && static_cast<unsigned char>(body[1]) == 0xB5 &&
       static_cast<unsigned char>(body[2]) == 0x2F && static_cast<unsigned char>(body[3]) == 0xFD);
    if (zstd) {
      auto stream = Unzstd(body);
      if (!stream) {
        return std::unexpected(stream.error());
      }
      file.stream = std::move(*stream);
    } else {
      auto blob = DecodeBase64(body);
      if (!blob) {
        return std::unexpected("not a FAF replay (its body isn't base64)");
      }
      auto stream = Unzlib(*blob);
      if (!stream) {
        return std::unexpected(stream.error());
      }
      file.stream = std::move(*stream);
    }
    return file;
  }
} // namespace faf::online
