#pragma once

#include <cstdint>
#include <string_view>

namespace faf::editor
{
  /**
   * The kind of ground a terrain texture shows (FAF Studio's roledetect.lua), found from its file name and its average
   * colour, so tools that read the paint (the map-wide specular and macrotexture, stratum recipes) don't depend on
   * which layer number holds what.
   */
  enum class GroundKind : std::uint8_t
  {
    Unknown,
    Grass,
    Rock,
    Sand,
    Dirt,
    Wet,
    HighRock,
    DarkRock,
    Snow,
  };

  struct GroundGuess
  {
    GroundKind kind = GroundKind::Unknown;
    float confidence = 0.0f; // 0..0.95
    /** By name: a plain rock word with no dark or light word, so the colour may say which rock. */
    bool plainRock = false;
    /** By name: the score of grass and of sand (the pair names and colours mix up). */
    float grassScore = 0.0f;
    float sandScore = 0.0f;
  };

  /** Lower case English name ("grass", "dark rock", ...); "unknown". */
  [[nodiscard]] const char* GroundKindName(GroundKind kind) noexcept;
  [[nodiscard]] bool IsRockKind(GroundKind kind) noexcept;

  /**
   * What a file name says: its words (case changes, digits and punctuation split them) matched against a token list,
   * longer tokens first (sandwet is wet, not sand); the last word counts a little more (the noun of a compound); a
   * dark or light word turns a rock into dark or high rock; ice and rock together are high rock. Unknown when nothing
   * matches.
   */
  [[nodiscard]] GroundGuess GroundKindOfName(std::string_view path);

  /** What an average colour (0..1) says: near white snow, green grass, tan sand, brown dirt, grey rock ... */
  [[nodiscard]] GroundGuess GroundKindOfColour(float r, float g, float b);

  /** Both together: a clear name wins; the colour says which rock, settles grass against sand, or decides alone. */
  [[nodiscard]] GroundGuess GroundKindOf(std::string_view path, const float* averageRgb);
} // namespace faf::editor
