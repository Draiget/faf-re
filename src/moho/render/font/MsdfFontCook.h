#pragma once

#include <atomic>
#include <cstddef>
#include <cstdint>
#include <memory>
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

  /** One small glyph rasterized at an exact pixel size, for text too small for a distance field (issue #308). */
  struct SMsdfStrikeGlyph
  {
    std::uint32_t mCodepoint = 0;
    std::int32_t mLeft = 0;   // pixels from the pen to the bitmap's left edge
    std::int32_t mTop = 0;    // pixels from the baseline up to its top edge
    std::int32_t mWidth = 0;
    std::int32_t mHeight = 0;
    float mAdvance = 0.0f;    // pixels
    std::uint32_t mOffset = 0; // into mCoverage, rows from the top, one byte a pixel
  };

  /** A font at one pixel size. */
  struct SMsdfStrike
  {
    std::int32_t mPixelSize = 0;
    std::vector<SMsdfStrikeGlyph> mGlyphs; // by codepoint
    std::vector<std::uint8_t> mCoverage;
  };

  struct SMsdfCookOptions
  {
    // Two atlases and the 3 texels between them fit across CD3DFont's 2048-texel page; at 1024 each font took a
    // row of its own, and the page ran out after a few fonts.
    std::int32_t mAtlasWidth = 1022;
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
    // A font past one of these is refused rather than drawn in part (issue #305). None changes the output
    // of a font within them, so they aren't part of the cache key. The game's fonts are far inside.
    std::int32_t mMaxFontGlyphs = 65535;
    std::int32_t mMaxEdgesPerGlyph = 8192;
    std::int32_t mMaxEdgesPerFont = 2097152;
    // The work of a field is its box's texels times its glyph's edges. These refuse a font on that count,
    // before any field is made, so every machine refuses the same fonts. 0 is no limit.
    std::uint64_t mMaxGlyphWork = 0u;
    std::uint64_t mMaxFontWork = 0u;
    // What FreeType may hold for this font at once; past it FreeType fails as if out of memory. 0 is no limit.
    std::size_t mMaxFreeTypeBytes = 0u;
    // A cook still running this long after it began gives up, unlike the limits above only for this time,
    // since it depends on the machine. 0 is no limit.
    double mMaxSeconds = 0.0;
    const std::atomic<bool>* mCancel = nullptr; // a cook gives up when this turns true, for shutdown
    std::vector<std::int32_t> mStrikeSizes; // pixel sizes also rasterized as bitmaps (a mod's font; see below)
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
    // The font's own line metrics in em, for a font GDI never sees. mDescent is positive below the baseline.
    float mAscent = 0.0f;
    float mDescent = 0.0f;
    float mLineGap = 0.0f;
    std::vector<SMsdfStrike> mStrikes; // by pixel size
  };

  /** One font's outline of one edge for a compute shader, in texels of its glyph's box. A cubic arrives split. */
  struct SMsdfGpuEdge
  {
    float mP0[2] = {};
    float mP1[2] = {};
    float mP2[2] = {};     // unused for a line
    std::uint32_t mColor = 0u;
    std::uint32_t mKind = 0u; // 1 a line, 2 a quadratic
    // Unit directions at both ends, and the unit bisectors of the corners there with the edges before and
    // after it in its contour; zero where a direction has no length, as msdfgen's normalize(true) gives.
    float mStartDirection[2] = {};
    float mEndDirection[2] = {};
    float mStartBisector[2] = {};
    float mEndBisector[2] = {};
  };

  struct SMsdfGpuGlyph
  {
    std::uint32_t mFirstEdge = 0u;
    std::uint32_t mEdgeCount = 0u;
    std::int32_t mWidth = 0; // 0 for a glyph with no ink
    std::int32_t mHeight = 0;
  };

  /**
   * A cook taken apart, so the middle step can run elsewhere: `Prepare` reads and packs the font, each glyph's
   * field comes from `GenerateOnCpu` or from `StoreGlyphField` with a field the GPU worked out, and `Finish`
   * hands over the atlas. `MSDF_CookFont` is all of it on the CPU. The font's bytes stay in use until `Finish`.
   */
  class MsdfCookPlan
  {
  public:
    MsdfCookPlan();
    ~MsdfCookPlan();
    MsdfCookPlan(const MsdfCookPlan&) = delete;
    MsdfCookPlan& operator=(const MsdfCookPlan&) = delete;

    /** False with `error` set for a font the options refuse; `TimedOut` then says whether it ran out of time. */
    [[nodiscard]] bool Prepare(const void* fontBytes, std::size_t byteCount, const SMsdfCookOptions& options, std::string& error);

    /** False with `error` set when the cook ran out of time or was cancelled; the plan is then of no use. */
    [[nodiscard]] bool GenerateOnCpu(std::string& error);

    /** The last failure came from `mMaxSeconds` or `mCancel`, not from the font, so the font may cook another time. */
    [[nodiscard]] bool TimedOut() const;

    /** Fills `GpuEdges` and `GpuGlyphs`, indexed as `StoreGlyphField` is. */
    void BuildGpuData();
    [[nodiscard]] const std::vector<SMsdfGpuEdge>& GpuEdges() const;
    [[nodiscard]] const std::vector<SMsdfGpuGlyph>& GpuGlyphs() const;
    [[nodiscard]] float RangeTexels() const;

    /** Takes four floats a texel, rows from the bottom, before error correction, which this runs. */
    void StoreGlyphField(std::size_t glyphIndex, std::vector<float>& field);

    void Finish(SMsdfFontAtlas& out);

  private:
    struct Impl;
    std::unique_ptr<Impl> mImpl;
  };

  /** What an atlas holds by default: ASCII, Latin-1, Latin Extended-A, Cyrillic, General Punctuation, and a few signs. */
  [[nodiscard]] std::vector<std::uint32_t> MSDF_DefaultCodepoints();

  /** The options every atlas is cooked with, for the default characters. */
  [[nodiscard]] SMsdfCookOptions MSDF_MakeCookOptions(std::int32_t threads);

  /**
   * The same for a mod's font, which isn't trusted (issue #305): with the work, memory and time limits set,
   * and with bitmaps of the small sizes, since a mod's font can't use GDI for those and FreeType's light
   * autohinter keeps them readable. They're cooked with the rest so that a small glyph never waits.
   */
  [[nodiscard]] SMsdfCookOptions MSDF_MakeModCookOptions(std::int32_t threads);

  /**
   * Turns a TrueType or OpenType file in memory into an atlas, on the CPU, so it works the same under
   * every renderer. Outlines load unhinted, so a font's hinting programs don't run. Characters the font
   * lacks stay out and are counted in `mMissing`. Returns false with `error` set for a file that isn't
   * a font, glyphs that don't fit, a font past the options' limits, or a cook out of time.
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
