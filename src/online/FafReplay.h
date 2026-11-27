#pragma once

// Engine addition (in-game launcher plan, WP5, the launcher's replays): FAF's own replay file (.fafreplay), as its
// replay vault serves it and its client saves it. One JSON header line (uid, title, mapname, featured_mod, teams,
// game_time, launched_at, compression...), then the game's replay stream: zstd-compressed when the header says
// "compression": "zstd" (or the body starts with zstd's magic), else base64 of a 4-byte big-endian length followed
// by a zlib stream (older files). The same reading as tools/replay-parity/replayfile.py.

#include <expected>
#include <string>
#include <vector>

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

  /** What the head of the game's own replay stream (.SCFAReplay) says, for a list of replays. */
  struct GameReplaySummary
  {
    std::string version;              ///< "Supreme Commander v1.50.3841"
    std::string map;                  ///< the scenario's path, /maps/<folder>/<folder>_scenario.lua
    std::vector<std::string> mods;    ///< the sim mods' names
    std::vector<std::string> players; ///< the command sources: each player who recorded commands, observers too
    /** The game's length in beats (10 a game second): the sum of its advance messages; -1 when not counted. */
    long long beats = -1;
  };

  /**
   * The summary of a replay stream's head, as VCR_SetupReplaySession reads it (and tools/replay-parity's
   * replay_stream): the version line, "Replay v1.9", the map path, the sim mods' and the scenario's Lua tables (each
   * with its size), the command sources. Only the head is needed; the error when it isn't one.
   */
  [[nodiscard]] std::expected<GameReplaySummary, std::string>
  ReadGameReplaySummary(const std::string& stream, bool countBeats = false);

  /** Base64 (RFC 4648, padding optional, line breaks ignored) to bytes; the error on any other character. */
  [[nodiscard]] std::expected<std::string, std::string> DecodeBase64(const std::string& text);
} // namespace faf::online
