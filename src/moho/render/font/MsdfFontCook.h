#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace moho
{
  /**
   * FAF addition, not in the shipped binary (issue #306).
   *
   * One glyph of an MSDF atlas. MSDF (multi-channel signed distance field) stores how far each texel
   * is from the glyph's outline, so one texture stays sharp at any size. RGB hold the multi-channel
   * distance and A the true distance; 0.5 is the outline, and `(value - 0.5) * mDistanceRange` is the
   * distance in atlas texels.
   */
  struct SMsdfGlyph
  {
    std::uint32_t mCodepoint = 0;
    float mAdvance = 0.0f; // em
    // The quad, in em, y up from the baseline. All zero for a glyph with no ink, such as a space.
    float mPlaneLeft = 0.0f;
    float mPlaneBottom = 0.0f;
    float mPlaneRight = 0.0f;
    float mPlaneTop = 0.0f;
    // The same corners in the atlas, in texels, origin top-left, on texel centers.
    float mAtlasLeft = 0.0f;
    float mAtlasBottom = 0.0f;
    float mAtlasRight = 0.0f;
    float mAtlasTop = 0.0f;
  };

  struct SMsdfCookOptions
  {
    std::int32_t mAtlasWidth = 1024;
    std::int32_t mHeightStep = 256;     // the atlas grows in these steps until the glyphs fit
    std::int32_t mMaxAtlasHeight = 4096;
    double mEmPixels = 48.0;
    double mDistanceRange = 12.0;       // atlas texels covered by the values 0..1
    double mMiterLimit = 1.0;           // glyph boxes hold sharp corners' miters up to this many ranges
    // Empty texels between boxes. Two boxes side by side can have different channels high, and a blend
    // of those has a median near the outline, so a sample past a box's edge would draw a line. Samples
    // land there under Direct3D 9 with antialiasing on, which drew such lines beside some glyphs.
    std::int32_t mGlyphSpacing = 3;
    std::int32_t mThreads = 1;          // the output doesn't depend on it
    std::vector<std::uint32_t> mCodepoints;
  };

  struct SMsdfFontAtlas
  {
    std::int32_t mWidth = 0;
    std::int32_t mHeight = 0;
    float mEmPixels = 0.0f;
    float mDistanceRange = 0.0f;
    std::vector<SMsdfGlyph> mGlyphs;   // by codepoint
    std::vector<std::uint8_t> mPixels; // RGBA8, rows from the top
    std::uint32_t mMissing = 0;        // codepoints asked for that the font doesn't draw
  };

  /** What an atlas holds by default: ASCII, Latin-1, Latin Extended-A, Cyrillic, General Punctuation, and a few signs. */
  [[nodiscard]] std::vector<std::uint32_t> MSDF_DefaultCodepoints();

  /**
   * Turns a TrueType or OpenType file in memory into an atlas, on the CPU, so it works the same under
   * every renderer. Outlines load unhinted, so a font's hinting programs don't run. Characters the font
   * lacks stay out and are counted in `mMissing`. Returns false with `error` set for a file that isn't
   * a font or glyphs that don't fit.
   */
  [[nodiscard]] bool MSDF_CookFont(
    const void* fontBytes, std::size_t byteCount, const SMsdfCookOptions& options, SMsdfFontAtlas& out, std::string& error
  );

  /**
   * The names a font answers to, in every language it lists: the full name (`Arial Bold`,
   * `Arial Gras`), and the family name only for a regular face, so `Arial` means the regular file
   * and not whichever bold or italic loaded first. Lowercase. Empty for a file that isn't a font.
   */
  [[nodiscard]] std::vector<std::string> MSDF_ReadFontNames(const void* fontBytes, std::size_t byteCount);

  /** An atlas as one zstd-packed block, for the cache. Empty on failure. */
  [[nodiscard]] std::vector<std::uint8_t> MSDF_SaveAtlas(const SMsdfFontAtlas& atlas);

  /**
   * Reads what `MSDF_SaveAtlas` wrote, checking every count, order and rectangle, so a damaged cache
   * file is refused rather than read past its end.
   */
  [[nodiscard]] bool MSDF_LoadAtlas(const void* bytes, std::size_t byteCount, SMsdfFontAtlas& out);
} // namespace moho
