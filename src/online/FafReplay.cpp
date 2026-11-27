// Engine addition (in-game launcher plan, WP5, the launcher's replays): FAF's .fafreplay file (online/FafReplay.h).

#include "online/FafReplay.h"

#include <cstddef>
#include <cstdint>
#include <cstring>

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

  namespace
  {
    /** One value of the engine's Lua serialisation (replay heads): 0 float, 1 string, 2 nil, 3 bool, 4 table..5. */
    bool ReadLuaValue(
      const std::string& data,
      std::size_t& at,
      JsonNode& out,
      const int depth
    )
    {
      if (at >= data.size() || depth > 32) {
        return false;
      }
      const unsigned char kind = static_cast<unsigned char>(data[at++]);
      switch (kind) {
      case 0: {
        if (at + 4 > data.size()) {
          return false;
        }
        float value = 0;
        std::memcpy(&value, data.data() + at, 4);
        at += 4;
        out = JsonNumber(value);
        return true;
      }
      case 1: {
        const std::size_t end = data.find('\0', at);
        if (end == std::string::npos) {
          return false;
        }
        out = JsonString(data.substr(at, end - at));
        at = end + 1;
        return true;
      }
      case 2:
        out = JsonNode{};
        return true;
      case 3:
        if (at >= data.size()) {
          return false;
        }
        out = JsonBool(data[at++] != 0);
        return true;
      case 4: {
        std::vector<std::pair<std::string, JsonNode>> members;
        while (at < data.size() && static_cast<unsigned char>(data[at]) != 5) {
          JsonNode key;
          JsonNode value;
          if (!ReadLuaValue(data, at, key, depth + 1) || !ReadLuaValue(data, at, value, depth + 1)) {
            return false;
          }
          members.emplace_back(key.kind == JsonNode::Kind::String ? key.text : ToJson(key), std::move(value));
        }
        if (at >= data.size()) {
          return false;
        }
        ++at; // the table's end
        out = JsonObject(std::move(members));
        return true;
      }
      default:
        return false;
      }
    }

    bool ReadInt32(
      const std::string& data,
      std::size_t& at,
      std::int32_t& out
    )
    {
      if (at + 4 > data.size()) {
        return false;
      }
      std::memcpy(&out, data.data() + at, 4); // little-endian, as every platform the game runs on
      at += 4;
      return true;
    }
  } // namespace

  std::expected<GameReplaySummary, std::string> ReadGameReplaySummary(
    const std::string& stream,
    const bool countBeats
  )
  {
    const auto refuse = [] {
      return std::unexpected(std::string("not a replay of this game (its head can't be read)"));
    };
    GameReplaySummary summary;
    const std::size_t versionEnd = stream.find('\0');
    if (versionEnd == std::string::npos || versionEnd > 256) {
      return refuse();
    }
    summary.version = stream.substr(0, versionEnd);
    const std::size_t replayLine = stream.find("Replay v", versionEnd);
    const std::size_t lineEnd = replayLine == std::string::npos ? std::string::npos : stream.find("\r\n", replayLine);
    if (replayLine == std::string::npos || replayLine > 1024 || lineEnd == std::string::npos) {
      return refuse();
    }
    std::size_t at = lineEnd + 2;
    const std::size_t mapEnd = stream.find('\0', at);
    if (mapEnd == std::string::npos) {
      return refuse();
    }
    summary.map = stream.substr(at, mapEnd - at);
    // Then one more line: "\r\n\x1a" in FAF's builds, "\r\n" in older ones; the engine skips it whatever it says.
    const std::size_t separatorEnd = stream.find('\0', mapEnd + 1);
    if (separatorEnd == std::string::npos || separatorEnd - mapEnd > 8) {
      return refuse();
    }
    at = separatorEnd + 1;
    // The sim mods' table, then the scenario's (each after its size).
    std::int32_t size = 0;
    if (!ReadInt32(stream, at, size) || size < 0 || at + static_cast<std::size_t>(size) > stream.size()) {
      return refuse();
    }
    {
      std::size_t inside = at;
      JsonNode mods;
      if (ReadLuaValue(stream, inside, mods, 0) && mods.kind == JsonNode::Kind::Object) {
        for (const auto& [key, mod] : mods.members) {
          if (mod.kind == JsonNode::Kind::Object && !mod.String("name").empty()) {
            summary.mods.push_back(mod.String("name"));
          }
        }
      }
    }
    at += static_cast<std::size_t>(size);
    if (!ReadInt32(stream, at, size) || size < 0 || at + static_cast<std::size_t>(size) > stream.size()) {
      return refuse();
    }
    at += static_cast<std::size_t>(size);
    if (at >= stream.size()) {
      return refuse();
    }
    const unsigned char sources = static_cast<unsigned char>(stream[at++]);
    for (unsigned i = 0; i < sources; ++i) {
      const std::size_t end = stream.find('\0', at);
      if (end == std::string::npos || end + 1 + 4 > stream.size()) {
        return refuse();
      }
      summary.players.push_back(stream.substr(at, end - at));
      at = end + 1 + 4; // the name, then its timeout count
    }
    if (!countBeats) {
      return summary;
    }
    // Then the cheats flag, the armies (each a sized block and its unit sources up to 0xFF), the random seed, and the
    // command stream: [type][size, 16 bits][payload], an advance (type 0) carrying its beat count.
    if (at + 2 > stream.size()) {
      return summary;
    }
    const unsigned char armies = static_cast<unsigned char>(stream[at + 1]);
    at += 2;
    for (unsigned i = 0; i < armies; ++i) {
      std::int32_t size = 0;
      if (!ReadInt32(stream, at, size) || size < 0 || at + static_cast<std::size_t>(size) > stream.size()) {
        return summary;
      }
      at += static_cast<std::size_t>(size);
      const std::size_t end = stream.find('\xff', at);
      if (end == std::string::npos) {
        return summary;
      }
      at = end + 1;
    }
    at += 4;
    long long beats = 0;
    while (at + 3 <= stream.size()) {
      const unsigned char type = static_cast<unsigned char>(stream[at]);
      const std::size_t size = static_cast<unsigned char>(stream[at + 1]) |
        (static_cast<std::size_t>(static_cast<unsigned char>(stream[at + 2])) << 8);
      if (size < 3 || at + size > stream.size()) {
        break; // a cut file: the beats so far
      }
      if (type == 0 && size >= 7) {
        std::int32_t advance = 0;
        std::memcpy(&advance, stream.data() + at + 3, 4);
        beats += advance;
      }
      at += size;
    }
    summary.beats = beats;
    return summary;
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
