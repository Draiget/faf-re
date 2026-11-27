#pragma once

// Engine addition (in-game launcher plan, WP5, the launcher's replays): FAF's own replay file (.fafreplay), as its
// replay vault serves it and its client saves it. One JSON header line (uid, title, mapname, featured_mod, teams,
// game_time, launched_at, compression...), then the game's replay stream: zstd-compressed when the header says
// "compression": "zstd" (or the body starts with zstd's magic), else base64 of a 4-byte big-endian length followed
// by a zlib stream (older files). The same reading as tools/replay-parity/replayfile.py.

#include <expected>
#include <string>

#include "online/Json.h"

namespace faf::online
{
  struct FafReplayFile
  {
    JsonNode header;
    /** The replay stream as the game writes a .SCFAReplay file. */
    std::string stream;
  };

  /** The header of a .fafreplay file's bytes (only its first line is read); the error when it isn't one. */
  [[nodiscard]] std::expected<JsonNode, std::string> ReadFafReplayHeader(const std::string& raw);

  /** A .fafreplay file's bytes, header and replay stream; the error when it can't be read. */
  [[nodiscard]] std::expected<FafReplayFile, std::string> DecodeFafReplay(const std::string& raw);

  /** Base64 (RFC 4648, padding optional, line breaks ignored) to bytes; the error on any other character. */
  [[nodiscard]] std::expected<std::string, std::string> DecodeBase64(const std::string& text);
} // namespace faf::online
