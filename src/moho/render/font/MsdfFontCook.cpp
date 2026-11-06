#include "moho/render/font/MsdfFontCook.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstdlib>
#include <cstring>
#include <map>
#include <memory>
#include <thread>
#include <utility>

#include <ft2build.h>
#include FT_FREETYPE_H
#include FT_MODULE_H
#include FT_SFNT_NAMES_H
#include FT_TRUETYPE_IDS_H

#include "msdfgen.h"
#include "core/ShapeDistanceFinder.h"
#include "ext/import-font.h"
#include "zstd.h"

namespace moho
{
  namespace
  {
    constexpr double kCornerAngleThreshold = 3.0;       // radians; msdfgen's default for edge coloring
    constexpr std::uint64_t kColoringSeedStep = 6364136223846793005ull; // msdf-atlas-gen's per-glyph seed
    constexpr std::uint32_t kAtlasMagic = 0x4D465346u;  // "FSFM"
    constexpr std::uint32_t kAtlasVersion = 2u;
    constexpr std::uint32_t kMaxLoadedStrikes = 16u;
    constexpr std::int32_t kMaxLoadedStrikeBox = 64;
    constexpr float kMaxLoadedStrikeMetric = 1024.0f;
    constexpr std::int32_t kMaxLoadedAtlasSide = 8192;
    constexpr std::uint32_t kMaxLoadedGlyphs = 65536u;
    constexpr double kMaxBoxTexels = 65536.0;           // far past any atlas; only to keep the casts below defined

    /**
     * FreeType's memory with a ceiling: an allocation past it fails, and FreeType handles that as running out
     * of memory, so a font built to make it allocate without end only fails to load. Each block keeps its size
     * in front of it, since FreeType's free doesn't pass one.
     */
    struct CappedMemory
    {
      static constexpr std::size_t kHeader = 16u; // keeps the blocks as aligned as malloc's

      FT_MemoryRec_ mRecord{};
      std::size_t mUsed = 0u;
      std::size_t mLimit = 0u;

      explicit CappedMemory(const std::size_t limit)
        : mLimit(limit)
      {
        mRecord.user = this;
        mRecord.alloc = &Alloc;
        mRecord.free = &Free;
        mRecord.realloc = &Realloc;
      }

      [[nodiscard]] static CappedMemory& Of(const FT_Memory memory) { return *static_cast<CappedMemory*>(memory->user); }

      [[nodiscard]] static void* Alloc(const FT_Memory memory, const long size)
      {
        CappedMemory& self = Of(memory);
        const auto bytes = static_cast<std::size_t>(size);
        if (size <= 0 || bytes > self.mLimit - self.mUsed) {
          return nullptr;
        }
        auto* const block = static_cast<std::uint8_t*>(std::malloc(kHeader + bytes));
        if (block == nullptr) {
          return nullptr;
        }
        std::memcpy(block, &bytes, sizeof(bytes));
        self.mUsed += bytes;
        return block + kHeader;
      }

      static void Free(const FT_Memory memory, void* const pointer)
      {
        if (pointer == nullptr) {
          return;
        }
        auto* const block = static_cast<std::uint8_t*>(pointer) - kHeader;
        std::size_t bytes = 0u;
        std::memcpy(&bytes, block, sizeof(bytes));
        Of(memory).mUsed -= bytes;
        std::free(block);
      }

      [[nodiscard]] static void* Realloc(const FT_Memory memory, const long, const long newSize, void* const pointer)
      {
        if (pointer == nullptr) {
          return Alloc(memory, newSize);
        }
        CappedMemory& self = Of(memory);
        auto* const block = static_cast<std::uint8_t*>(pointer) - kHeader;
        std::size_t bytes = 0u;
        std::memcpy(&bytes, block, sizeof(bytes));
        const auto newBytes = static_cast<std::size_t>(newSize);
        if (newSize <= 0 || (newBytes > bytes && newBytes - bytes > self.mLimit - self.mUsed)) {
          return nullptr; // FreeType keeps the old block, as with realloc
        }
        auto* const grown = static_cast<std::uint8_t*>(std::realloc(block, kHeader + newBytes));
        if (grown == nullptr) {
          return nullptr;
        }
        std::memcpy(grown, &newBytes, sizeof(newBytes));
        self.mUsed = self.mUsed - bytes + newBytes;
        return grown + kHeader;
      }
    };

    /** One FreeType instance, with its memory capped when `memoryLimit` isn't 0. Not shared between threads. */
    struct FreeTypeLibrary
    {
      std::unique_ptr<CappedMemory> mMemory;
      FT_Library mLibrary = nullptr;

      explicit FreeTypeLibrary(const std::size_t memoryLimit = 0u)
      {
        if (memoryLimit == 0u) {
          (void)FT_Init_FreeType(&mLibrary);
          return;
        }
        // What FT_Init_FreeType does, with our memory in place of FreeType's own.
        mMemory = std::make_unique<CappedMemory>(memoryLimit);
        if (FT_New_Library(&mMemory->mRecord, &mLibrary) != 0) {
          mLibrary = nullptr;
          return;
        }
        FT_Add_Default_Modules(mLibrary);
        FT_Set_Default_Properties(mLibrary);
      }
      ~FreeTypeLibrary()
      {
        if (mLibrary == nullptr) {
          return;
        }
        if (mMemory) {
          (void)FT_Done_Library(mLibrary);
        } else {
          (void)FT_Done_FreeType(mLibrary);
        }
      }
      FreeTypeLibrary(const FreeTypeLibrary&) = delete;
      FreeTypeLibrary& operator=(const FreeTypeLibrary&) = delete;
    };

    struct FreeTypeFace
    {
      FT_Face mFace = nullptr;
      FreeTypeFace(const FT_Library library, const void* const bytes, const std::size_t byteCount)
      {
        if (library != nullptr && byteCount > 0u && byteCount <= 0x7FFFFFFFu) {
          (void)FT_New_Memory_Face(library, static_cast<const FT_Byte*>(bytes), static_cast<FT_Long>(byteCount), 0, &mFace);
        }
      }
      ~FreeTypeFace()
      {
        if (mFace != nullptr) {
          (void)FT_Done_Face(mFace);
        }
      }
      FreeTypeFace(const FreeTypeFace&) = delete;
      FreeTypeFace& operator=(const FreeTypeFace&) = delete;
    };

    struct FontHandleOwner
    {
      msdfgen::FontHandle* mFont;
      explicit FontHandleOwner(const FT_Face face)
        : mFont(msdfgen::adoptFreetypeFont(face))
      {}
      ~FontHandleOwner() { msdfgen::destroyFont(mFont); }
      FontHandleOwner(const FontHandleOwner&) = delete;
      FontHandleOwner& operator=(const FontHandleOwner&) = delete;
    };

    /** One glyph id's outline; several codepoints may share it. */
    struct SourceGlyph
    {
      msdfgen::Shape mShape;
      double mAdvance = 0.0; // font units
      double mTranslateX = 0.0;
      double mTranslateY = 0.0;
      std::int32_t mWidth = 0; // box in texels; 0 for a glyph with no ink
      std::int32_t mHeight = 0;
      std::int32_t mAtlasX = 0;
      std::int32_t mAtlasY = 0; // of the box's top row
    };

    [[nodiscard]] std::size_t CountEdges(const msdfgen::Shape& shape) noexcept
    {
      std::size_t edges = 0u;
      for (const msdfgen::Contour& contour : shape.contours) {
        edges += contour.edges.size();
      }
      return edges;
    }

    /**
     * Prepares an outline as msdf-atlas-gen does: valid, normalized and wound so that the outside is
     * negative. False for a glyph that doesn't load or has an open contour.
     */
    [[nodiscard]] bool LoadGlyph(
      SourceGlyph& glyph, msdfgen::FontHandle* const font, const unsigned glyphId, const std::uint64_t coloringSeed
    )
    {
      if (!msdfgen::loadGlyph(glyph.mShape, font, msdfgen::GlyphIndex(glyphId), msdfgen::FONT_SCALING_NONE, &glyph.mAdvance)) {
        return false;
      }
      if (!glyph.mShape.validate()) {
        return false;
      }
      glyph.mShape.normalize();
      const msdfgen::Shape::Bounds bounds = glyph.mShape.getBounds();
      if (bounds.l < bounds.r && bounds.b < bounds.t) {
        const msdfgen::Point2 outside(bounds.l - (bounds.r - bounds.l) - 1.0, bounds.b - (bounds.t - bounds.b) - 1.0);
        if (msdfgen::SimpleTrueShapeDistanceFinder::oneShotDistance(glyph.mShape, outside) > 0.0) {
          for (msdfgen::Contour& contour : glyph.mShape.contours) {
            contour.reverse();
          }
        }
      }
      return true;
    }

    /**
     * The glyph's box at one scale: the bounds grown by half the distance range and the miters, rounded
     * up to whole texels with the shape centered, plus one texel so the quad can stop at texel centers.
     * False for a box too large to be real.
     */
    [[nodiscard]] bool WrapBox(SourceGlyph& glyph, const double scale, const double rangeUnits, const double miterLimit)
    {
      const msdfgen::Shape::Bounds bounds = glyph.mShape.getBounds();
      if (bounds.l >= bounds.r || bounds.b >= bounds.t) {
        return true;
      }
      const double border = 0.5 * rangeUnits;
      double left = bounds.l - border;
      double bottom = bounds.b - border;
      double right = bounds.r + border;
      double top = bounds.t + border;
      if (miterLimit > 0.0) {
        glyph.mShape.boundMiters(left, bottom, right, top, border, miterLimit, 1);
      }
      const double width = scale * (right - left);
      const double height = scale * (top - bottom);
      if (!(width < kMaxBoxTexels) || !(height < kMaxBoxTexels)) {
        return false;
      }
      glyph.mWidth = static_cast<std::int32_t>(std::ceil(width)) + 1;
      glyph.mHeight = static_cast<std::int32_t>(std::ceil(height)) + 1;
      glyph.mTranslateX = -left + 0.5 * (glyph.mWidth - width) / scale;
      glyph.mTranslateY = -bottom + 0.5 * (glyph.mHeight - height) / scale;
      return true;
    }

    /** Shelves, tallest first. Returns the rows used, or -1 when any box is wider than the atlas. */
    [[nodiscard]] std::int32_t PackShelves(
      std::vector<SourceGlyph>& glyphs, const std::int32_t atlasWidth, const std::int32_t spacing
    )
    {
      std::vector<SourceGlyph*> order;
      order.reserve(glyphs.size());
      for (SourceGlyph& glyph : glyphs) {
        if (glyph.mWidth > 0) {
          order.push_back(&glyph);
        }
      }
      std::stable_sort(order.begin(), order.end(), [](const SourceGlyph* const a, const SourceGlyph* const b) {
        return a->mHeight > b->mHeight;
      });

      std::int32_t x = 0;
      std::int32_t y = 0;
      std::int32_t shelfHeight = 0;
      for (SourceGlyph* const glyph : order) {
        if (glyph->mWidth > atlasWidth) {
          return -1;
        }
        if (x + glyph->mWidth > atlasWidth) {
          y += shelfHeight + spacing;
          x = 0;
          shelfHeight = 0;
        }
        glyph->mAtlasX = x;
        glyph->mAtlasY = y;
        x += glyph->mWidth + spacing;
        shelfHeight = (std::max)(shelfHeight, glyph->mHeight);
      }
      return y + shelfHeight;
    }

    /** Scales a 2D vector to unit length; zero stays zero, as msdfgen's normalize(true) leaves it. */
    void NormalizeOrZero(float* const v) noexcept
    {
      const float length = std::sqrt(v[0] * v[0] + v[1] * v[1]);
      if (length > 0.0f) {
        v[0] /= length;
        v[1] /= length;
      } else {
        v[0] = 0.0f;
        v[1] = 0.0f;
      }
    }

    /** msdfgen's EdgeSegment::direction at the start or the end of a GPU edge, unit length or zero. */
    void GpuEdgeDirection(const SMsdfGpuEdge& edge, const bool atEnd, float* const out) noexcept
    {
      if (edge.mKind == 1u) {
        out[0] = edge.mP1[0] - edge.mP0[0];
        out[1] = edge.mP1[1] - edge.mP0[1];
      } else {
        const float* const from = atEnd ? edge.mP1 : edge.mP0;
        const float* const to = atEnd ? edge.mP2 : edge.mP1;
        out[0] = to[0] - from[0];
        out[1] = to[1] - from[1];
        if (out[0] == 0.0f && out[1] == 0.0f) {
          out[0] = edge.mP2[0] - edge.mP0[0];
          out[1] = edge.mP2[1] - edge.mP0[1];
        }
      }
      NormalizeOrZero(out);
    }

    /**
     * Adds a quadratic, split at its highest or lowest point when that lies inside it, so each piece only rises or
     * only falls. The shader's inside test then counts a crossing from the endpoints alone, as for a line; a ray
     * touching a curve's top was counted twice before, which drew a line beside the glyph. A split traces the same
     * curve, so no distance changes.
     */
    void PushGpuQuadratic(std::vector<SMsdfGpuEdge>& edges, const float* const p0, const float* const p1, const float* const p2, const std::uint32_t color)
    {
      const auto push = [&edges, color](const float* const a, const float* const b, const float* const c) {
        SMsdfGpuEdge edge;
        edge.mP0[0] = a[0];
        edge.mP0[1] = a[1];
        edge.mP1[0] = b[0];
        edge.mP1[1] = b[1];
        edge.mP2[0] = c[0];
        edge.mP2[1] = c[1];
        edge.mColor = color;
        edge.mKind = 2u;
        edges.push_back(edge);
      };
      const float denominator = p0[1] - 2.0f * p1[1] + p2[1];
      const float t = denominator != 0.0f ? (p0[1] - p1[1]) / denominator : -1.0f;
      if (!(t > 0.0f && t < 1.0f)) {
        push(p0, p1, p2);
        return;
      }
      const float q0[2] = {p0[0] + (p1[0] - p0[0]) * t, p0[1] + (p1[1] - p0[1]) * t};
      const float q1[2] = {p1[0] + (p2[0] - p1[0]) * t, p1[1] + (p2[1] - p1[1]) * t};
      const float middle[2] = {q0[0] + (q1[0] - q0[0]) * t, q0[1] + (q1[1] - q0[1]) * t};
      push(p0, q0, middle);
      push(middle, q1, p2);
    }

    /**
     * Fills the directions and corner bisectors of one contour's GPU edges, `[first, edges.size())`, each corner
     * between an edge and the one before it, wrapping around: the shader needs them to tell which side of a corner
     * a texel is on, as msdfgen's MultiDistanceSelector::addEdge does with the edges on either side.
     */
    void FillContourCorners(std::vector<SMsdfGpuEdge>& edges, const std::size_t first)
    {
      const std::size_t count = edges.size() - first;
      for (std::size_t i = 0; i < count; ++i) {
        SMsdfGpuEdge& edge = edges[first + i];
        GpuEdgeDirection(edge, false, edge.mStartDirection);
        GpuEdgeDirection(edge, true, edge.mEndDirection);
      }
      for (std::size_t i = 0; i < count; ++i) {
        SMsdfGpuEdge& edge = edges[first + i];
        const SMsdfGpuEdge& previous = edges[first + (i + count - 1u) % count];
        const SMsdfGpuEdge& next = edges[first + (i + 1u) % count];
        edge.mStartBisector[0] = previous.mEndDirection[0] + edge.mStartDirection[0];
        edge.mStartBisector[1] = previous.mEndDirection[1] + edge.mStartDirection[1];
        edge.mEndBisector[0] = edge.mEndDirection[0] + next.mStartDirection[0];
        edge.mEndBisector[1] = edge.mEndDirection[1] + next.mStartDirection[1];
        NormalizeOrZero(edge.mStartBisector);
        NormalizeOrZero(edge.mEndBisector);
      }
    }

    /** The last step of a field, wherever it came from: error correction, then the bytes into the atlas. */
    void StoreField(
      const SourceGlyph& glyph, std::vector<float>& field, const double scale, const double rangeUnits,
      const std::int32_t atlasWidth, std::uint8_t* const atlasPixels
    )
    {
      const msdfgen::BitmapSection<float, 4> section(field.data(), glyph.mWidth, glyph.mHeight, msdfgen::Y_UPWARD);
      const msdfgen::Projection projection(
        msdfgen::Vector2(scale), msdfgen::Vector2(glyph.mTranslateX, glyph.mTranslateY)
      );
      const msdfgen::Range range(rangeUnits);

      msdfgen::MSDFGeneratorConfig config(true);
      config.errorCorrection.mode = msdfgen::ErrorCorrectionConfig::EDGE_PRIORITY;
      config.errorCorrection.distanceCheckMode = msdfgen::ErrorCorrectionConfig::DO_NOT_CHECK_DISTANCE;
      msdfgen::msdfErrorCorrection(section, glyph.mShape, projection, range, config);

      // The field's rows go up; the atlas's go down from the top.
      for (std::int32_t y = 0; y < glyph.mHeight; ++y) {
        const std::size_t row = static_cast<std::size_t>(glyph.mAtlasY + glyph.mHeight - 1 - y);
        std::uint8_t* out = atlasPixels + (row * static_cast<std::size_t>(atlasWidth) + static_cast<std::size_t>(glyph.mAtlasX)) * 4u;
        const float* in = field.data() + static_cast<std::size_t>(y) * static_cast<std::size_t>(glyph.mWidth) * 4u;
        for (std::int32_t texel = 0; texel < glyph.mWidth * 4; ++texel) {
          out[texel] = msdfgen::pixelFloatToByte(in[texel]);
        }
      }
    }

    /**
     * One glyph's field, as msdf-atlas-gen makes it with a scanline pass: generate without error
     * correction, fix signs against the exact fill, then correct errors without distance checks.
     */
    void GenerateGlyph(
      const SourceGlyph& glyph, std::vector<float>& field, const double scale, const double rangeUnits,
      const std::int32_t atlasWidth, std::uint8_t* const atlasPixels
    )
    {
      field.resize(static_cast<std::size_t>(glyph.mWidth) * static_cast<std::size_t>(glyph.mHeight) * 4u);
      const msdfgen::BitmapSection<float, 4> section(field.data(), glyph.mWidth, glyph.mHeight, msdfgen::Y_UPWARD);
      const msdfgen::Projection projection(
        msdfgen::Vector2(scale), msdfgen::Vector2(glyph.mTranslateX, glyph.mTranslateY)
      );
      const msdfgen::Range range(rangeUnits);

      msdfgen::MSDFGeneratorConfig config(true);
      config.errorCorrection.mode = msdfgen::ErrorCorrectionConfig::DISABLED;
      msdfgen::generateMTSDF(section, glyph.mShape, projection, range, config);
      msdfgen::distanceSignCorrection(section, glyph.mShape, projection, 0.5f, msdfgen::FILL_NONZERO);
      StoreField(glyph, field, scale, rangeUnits, atlasWidth, atlasPixels);
    }

    /**
     * Rasterizes the small sizes with FreeType's light autohinter, which snaps outlines to the pixel grid
     * vertically and never runs the font's own hinting programs. Nothing here calls Win32, so a later
     * client on another system can use it. A glyph that won't rasterize, or is implausibly large, is left out.
     */
    void RasterizeStrikes(const FT_Face face, const SMsdfCookOptions& options, const std::vector<std::uint32_t>& codepoints, SMsdfFontAtlas& atlas)
    {
      constexpr int kMaxStrikeBox = 64;
      for (const std::int32_t size : options.mStrikeSizes) {
        if (FT_Set_Pixel_Sizes(face, 0u, static_cast<FT_UInt>(size)) != 0) {
          continue;
        }
        SMsdfStrike strike;
        strike.mPixelSize = size;
        for (const std::uint32_t codepoint : codepoints) {
          const FT_UInt glyphId = FT_Get_Char_Index(face, codepoint);
          if (glyphId == 0u || FT_Load_Glyph(face, glyphId, FT_LOAD_RENDER | FT_LOAD_TARGET_LIGHT) != 0) {
            continue;
          }
          const FT_GlyphSlot slot = face->glyph;
          const FT_Bitmap& bitmap = slot->bitmap;
          const int width = static_cast<int>(bitmap.width);
          const int rows = static_cast<int>(bitmap.rows);
          if ((width != 0 && bitmap.pixel_mode != FT_PIXEL_MODE_GRAY) || width > kMaxStrikeBox || rows > kMaxStrikeBox) {
            continue;
          }
          SMsdfStrikeGlyph glyph;
          glyph.mCodepoint = codepoint;
          glyph.mLeft = slot->bitmap_left;
          glyph.mTop = slot->bitmap_top;
          glyph.mWidth = width;
          glyph.mHeight = rows;
          glyph.mAdvance = static_cast<float>(slot->advance.x) / 64.0f;
          glyph.mOffset = static_cast<std::uint32_t>(strike.mCoverage.size());
          for (int row = 0; row < rows; ++row) {
            const unsigned char* const line = bitmap.buffer + static_cast<std::ptrdiff_t>(row) * bitmap.pitch;
            strike.mCoverage.insert(strike.mCoverage.end(), line, line + width);
          }
          strike.mGlyphs.push_back(glyph);
        }
        atlas.mStrikes.push_back(std::move(strike));
      }
    }

    [[nodiscard]] std::string DecodeName(const FT_SfntName& name)
    {
      std::string text;
      if (name.platform_id == TT_PLATFORM_MICROSOFT || name.platform_id == TT_PLATFORM_APPLE_UNICODE) {
        // UTF-16, big-endian. Names only compare with the ones Lua passes, so a character outside
        // ASCII keeps one marker byte; such a name won't match a Lua family and stays with GDI.
        for (FT_UInt i = 0; i + 1u < name.string_len; i += 2u) {
          const std::uint32_t unit = (static_cast<std::uint32_t>(name.string[i]) << 8u) | name.string[i + 1u];
          text.push_back(unit < 0x80u ? static_cast<char>(std::tolower(static_cast<int>(unit))) : '\x7F');
        }
      } else if (name.platform_id == TT_PLATFORM_MACINTOSH) {
        for (FT_UInt i = 0; i < name.string_len; ++i) {
          const std::uint8_t c = name.string[i];
          text.push_back(c < 0x80u ? static_cast<char>(std::tolower(c)) : '\x7F');
        }
      }
      return text;
    }

    template <class T>
    void AppendValue(std::vector<std::uint8_t>& out, const T& value)
    {
      const auto* const bytes = reinterpret_cast<const std::uint8_t*>(&value);
      out.insert(out.end(), bytes, bytes + sizeof(T));
    }

    template <class T>
    [[nodiscard]] bool ReadValue(const std::uint8_t*& at, const std::uint8_t* const end, T& value)
    {
      if (static_cast<std::size_t>(end - at) < sizeof(T)) {
        return false;
      }
      std::memcpy(&value, at, sizeof(T));
      at += sizeof(T);
      return true;
    }

    [[nodiscard]] bool IsGlyphRectValid(const SMsdfGlyph& glyph, const SMsdfFontAtlas& atlas) noexcept
    {
      const float values[] = {
        glyph.mAdvance,     glyph.mPlaneLeft,  glyph.mPlaneBottom, glyph.mPlaneRight, glyph.mPlaneTop,
        glyph.mAtlasLeft,   glyph.mAtlasBottom, glyph.mAtlasRight, glyph.mAtlasTop,
      };
      for (const float value : values) {
        if (!std::isfinite(value)) {
          return false;
        }
      }
      const auto width = static_cast<float>(atlas.mWidth);
      const auto height = static_cast<float>(atlas.mHeight);
      return glyph.mAtlasLeft >= 0.0f && glyph.mAtlasLeft <= glyph.mAtlasRight && glyph.mAtlasRight <= width
        && glyph.mAtlasTop >= 0.0f && glyph.mAtlasTop <= glyph.mAtlasBottom && glyph.mAtlasBottom <= height;
    }
  } // namespace

  std::vector<std::uint32_t> MSDF_DefaultCodepoints()
  {
    std::vector<std::uint32_t> codepoints;
    const auto addRange = [&codepoints](const std::uint32_t first, const std::uint32_t last) {
      for (std::uint32_t c = first; c <= last; ++c) {
        codepoints.push_back(c);
      }
    };
    addRange(0x20u, 0x7Eu);     // ASCII
    addRange(0xA0u, 0x17Fu);    // Latin-1, Latin Extended-A
    addRange(0x400u, 0x4FFu);   // Cyrillic
    addRange(0x2010u, 0x2027u); // dashes, quotes, bullets
    addRange(0x2030u, 0x205Eu); // per mille, primes, more punctuation
    for (const std::uint32_t sign : {0x20ACu, 0x20BDu, 0x2116u, 0x2122u, 0x2212u, 0x221Eu, 0x2264u, 0x2265u}) {
      codepoints.push_back(sign); // euro, rouble, numero, trademark, minus, infinity, less and greater or equal
    }
    return codepoints;
  }

  SMsdfCookOptions MSDF_MakeCookOptions(const std::int32_t threads)
  {
    SMsdfCookOptions options;
    options.mThreads = threads;
    options.mCodepoints = MSDF_DefaultCodepoints();
    return options;
  }

  SMsdfCookOptions MSDF_MakeModCookOptions(const std::int32_t threads)
  {
    SMsdfCookOptions options = MSDF_MakeCookOptions(threads);
    options.mStrikeSizes = {8, 9, 10, 11, 12, 13, 14};
    // Windows' Arial needs under 64 KB of FreeType's memory, 33.5 million texel-edges for the default
    // characters and 262,144 for its largest glyph (faf_msdf_safety_tests), so these leave room for fonts
    // far more detailed while a crafted one stops early.
    options.mMaxEdgesPerFont = 262144;
    options.mMaxGlyphWork = 64ull * 1024ull * 1024ull;
    options.mMaxFontWork = 1024ull * 1024ull * 1024ull;
    options.mMaxFreeTypeBytes = 64u * 1024u * 1024u;
    options.mMaxSeconds = 60.0;
    return options;
  }

  struct MsdfCookPlan::Impl
  {
    std::unique_ptr<FreeTypeLibrary> mLibrary;
    std::unique_ptr<FreeTypeFace> mFace;
    std::unique_ptr<FontHandleOwner> mFont;
    SMsdfCookOptions mOptions;
    std::vector<std::uint32_t> mCodepoints;
    // One source glyph per glyph id, in codepoint order: the order seeds the coloring, so the result
    // doesn't depend on anything but the font and the options.
    std::vector<SourceGlyph> mGlyphs;
    std::vector<std::pair<std::uint32_t, std::size_t>> mMappings;
    double mUnitsPerEm = 0.0;
    double mScale = 0.0;
    double mRangeUnits = 0.0;
    SMsdfFontAtlas mAtlas;
    std::vector<SMsdfGpuEdge> mGpuEdges;
    std::vector<SMsdfGpuGlyph> mGpuGlyphs;
    std::chrono::steady_clock::time_point mStart;
    bool mTimedOut = false;

    /** Whether to give up now, for time or a cancel; sets `error` when it does. */
    [[nodiscard]] bool ShouldStop(std::string& error)
    {
      if (mOptions.mCancel != nullptr && mOptions.mCancel->load(std::memory_order_relaxed)) {
        error = "cancelled";
        mTimedOut = true;
      } else if (mOptions.mMaxSeconds > 0.0
                 && std::chrono::duration<double>(std::chrono::steady_clock::now() - mStart).count() > mOptions.mMaxSeconds) {
        error = "it took too long";
        mTimedOut = true;
      }
      return mTimedOut;
    }
  };

  MsdfCookPlan::MsdfCookPlan()
    : mImpl(std::make_unique<Impl>())
  {}

  MsdfCookPlan::~MsdfCookPlan() = default;

  bool MsdfCookPlan::TimedOut() const
  {
    return mImpl->mTimedOut;
  }

  bool MsdfCookPlan::Prepare(const void* const fontBytes, const std::size_t byteCount, const SMsdfCookOptions& options, std::string& error)
  {
    Impl& plan = *mImpl;
    plan.mOptions = options;
    plan.mStart = std::chrono::steady_clock::now();
    plan.mLibrary = std::make_unique<FreeTypeLibrary>(options.mMaxFreeTypeBytes);
    if (plan.mLibrary->mLibrary == nullptr) {
      error = "FreeType didn't start";
      return false;
    }
    plan.mFace = std::make_unique<FreeTypeFace>(plan.mLibrary->mLibrary, fontBytes, byteCount);
    const FT_Face face = plan.mFace->mFace;
    if (face == nullptr) {
      error = "FreeType can't read this file as a font";
      return false;
    }
    if ((face->face_flags & FT_FACE_FLAG_SCALABLE) == 0 || face->units_per_EM == 0) {
      error = "not a scalable font";
      return false;
    }
    if (face->num_glyphs > options.mMaxFontGlyphs) {
      error = "the font has too many glyphs";
      return false;
    }
    plan.mFont = std::make_unique<FontHandleOwner>(face);

    plan.mCodepoints = options.mCodepoints;
    std::sort(plan.mCodepoints.begin(), plan.mCodepoints.end());
    plan.mCodepoints.erase(std::unique(plan.mCodepoints.begin(), plan.mCodepoints.end()), plan.mCodepoints.end());

    std::map<unsigned, std::size_t> glyphOfId;
    std::uint64_t coloringSeed = 0;
    std::size_t edgesInFont = 0u;
    for (const std::uint32_t codepoint : plan.mCodepoints) {
      if (plan.ShouldStop(error)) {
        return false;
      }
      const unsigned glyphId = FT_Get_Char_Index(face, codepoint);
      if (glyphId == 0u) {
        ++plan.mAtlas.mMissing;
        continue;
      }
      auto known = glyphOfId.find(glyphId);
      if (known == glyphOfId.end()) {
        coloringSeed *= kColoringSeedStep;
        SourceGlyph glyph;
        if (!LoadGlyph(glyph, plan.mFont->mFont, glyphId, coloringSeed)) {
          ++plan.mAtlas.mMissing;
          continue;
        }
        const std::size_t edges = CountEdges(glyph.mShape);
        edgesInFont += edges;
        if (edges > static_cast<std::size_t>(options.mMaxEdgesPerGlyph)) {
          error = "a glyph has too many edges";
          return false;
        }
        if (edgesInFont > static_cast<std::size_t>(options.mMaxEdgesPerFont)) {
          error = "the font has too many edges";
          return false;
        }
        // Only now: this is the step whose cost grows with a glyph's edges.
        msdfgen::edgeColoringInkTrap(glyph.mShape, kCornerAngleThreshold, coloringSeed);
        known = glyphOfId.emplace(glyphId, plan.mGlyphs.size()).first;
        plan.mGlyphs.push_back(std::move(glyph));
      }
      plan.mMappings.emplace_back(codepoint, known->second);
    }

    plan.mUnitsPerEm = face->units_per_EM;
    plan.mScale = options.mEmPixels / plan.mUnitsPerEm;
    plan.mRangeUnits = options.mDistanceRange / plan.mScale;
    std::uint64_t fontWork = 0u;
    for (SourceGlyph& glyph : plan.mGlyphs) {
      if (!WrapBox(glyph, plan.mScale, plan.mRangeUnits, options.mMiterLimit)) {
        error = "a glyph is far too large";
        return false;
      }
      const std::uint64_t work = static_cast<std::uint64_t>(glyph.mWidth) * static_cast<std::uint64_t>(glyph.mHeight)
        * static_cast<std::uint64_t>(CountEdges(glyph.mShape));
      fontWork += work;
      if (options.mMaxGlyphWork != 0u && work > options.mMaxGlyphWork) {
        error = "a glyph would take too much work";
        return false;
      }
      if (options.mMaxFontWork != 0u && fontWork > options.mMaxFontWork) {
        error = "the font would take too much work";
        return false;
      }
    }

    // Any box wider than the atlas refuses the font, wherever it sorts: one left unplaced would be written past the atlas.
    const std::int32_t rowsUsed = PackShelves(plan.mGlyphs, options.mAtlasWidth, options.mGlyphSpacing);
    const std::int32_t step = (std::max)(options.mHeightStep, 1);
    const std::int32_t rows = (std::max)((rowsUsed + step - 1) / step, 1) * step;
    if (rowsUsed < 0 || rows > options.mMaxAtlasHeight) {
      error = "the glyphs don't fit the atlas";
      return false;
    }

    SMsdfFontAtlas& atlas = plan.mAtlas;
    atlas.mWidth = options.mAtlasWidth;
    atlas.mHeight = rows;
    atlas.mEmPixels = static_cast<float>(options.mEmPixels);
    atlas.mDistanceRange = static_cast<float>(options.mDistanceRange);
    atlas.mAscent = static_cast<float>(face->ascender / plan.mUnitsPerEm);
    atlas.mDescent = static_cast<float>(-face->descender / plan.mUnitsPerEm);
    atlas.mLineGap = static_cast<float>((face->height - face->ascender + face->descender) / plan.mUnitsPerEm);
    atlas.mPixels.assign(static_cast<std::size_t>(atlas.mWidth) * static_cast<std::size_t>(atlas.mHeight) * 4u, 0u);
    return true;
  }

  bool MsdfCookPlan::GenerateOnCpu(std::string& error)
  {
    Impl& plan = *mImpl;
    // Boxes don't overlap, so threads write disjoint texels.
    std::atomic<std::size_t> next{0u};
    std::atomic<bool> stopped{false};
    const auto work = [&]() {
      std::vector<float> field;
      for (std::size_t i = next++; i < plan.mGlyphs.size() && !stopped.load(std::memory_order_relaxed); i = next++) {
        if (plan.mGlyphs[i].mWidth > 0) {
          GenerateGlyph(plan.mGlyphs[i], field, plan.mScale, plan.mRangeUnits, plan.mAtlas.mWidth, plan.mAtlas.mPixels.data());
        }
      }
    };
    // The checks run here, between glyphs, while the workers cook.
    std::vector<std::thread> pool;
    for (std::int32_t t = 0; t < (std::max)(plan.mOptions.mThreads, 1); ++t) {
      pool.emplace_back(work);
    }
    std::string stopReason;
    while (next.load(std::memory_order_relaxed) < plan.mGlyphs.size() && !stopped.load(std::memory_order_relaxed)) {
      if (plan.ShouldStop(stopReason)) {
        stopped.store(true, std::memory_order_relaxed);
        break;
      }
      std::this_thread::sleep_for(std::chrono::milliseconds(20));
    }
    for (std::thread& thread : pool) {
      thread.join();
    }
    if (stopped.load(std::memory_order_relaxed)) {
      error = stopReason;
      return false;
    }
    return true;
  }

  void MsdfCookPlan::BuildGpuData()
  {
    Impl& plan = *mImpl;
    plan.mGpuEdges.clear();
    plan.mGpuGlyphs.assign(plan.mGlyphs.size(), SMsdfGpuGlyph{});
    for (std::size_t i = 0; i < plan.mGlyphs.size(); ++i) {
      const SourceGlyph& glyph = plan.mGlyphs[i];
      SMsdfGpuGlyph& gpuGlyph = plan.mGpuGlyphs[i];
      if (glyph.mWidth <= 0) {
        continue;
      }
      gpuGlyph.mFirstEdge = static_cast<std::uint32_t>(plan.mGpuEdges.size());
      gpuGlyph.mWidth = glyph.mWidth;
      gpuGlyph.mHeight = glyph.mHeight;
      const auto project = [&](const msdfgen::Point2 point, float* const out) {
        out[0] = static_cast<float>(plan.mScale * (point.x + glyph.mTranslateX));
        out[1] = static_cast<float>(plan.mScale * (point.y + glyph.mTranslateY));
      };
      for (const msdfgen::Contour& contour : glyph.mShape.contours) {
        const std::size_t contourFirst = plan.mGpuEdges.size();
        for (const msdfgen::EdgeHolder& holder : contour.edges) {
          const msdfgen::EdgeSegment* const segment = holder.operator->();
          const msdfgen::Point2* const points = segment->controlPoints();
          const std::uint32_t color = static_cast<std::uint32_t>(segment->color);
          if (segment->type() == static_cast<int>(msdfgen::LinearSegment::EDGE_TYPE)) {
            SMsdfGpuEdge edge;
            project(points[0], edge.mP0);
            project(points[1], edge.mP1);
            edge.mColor = color;
            edge.mKind = 1u;
            plan.mGpuEdges.push_back(edge);
          } else if (segment->type() == static_cast<int>(msdfgen::QuadraticSegment::EDGE_TYPE)) {
            float p0[2];
            float p1[2];
            float p2[2];
            project(points[0], p0);
            project(points[1], p1);
            project(points[2], p2);
            PushGpuQuadratic(plan.mGpuEdges, p0, p1, p2, color);
          } else {
            // A cubic as four quadratics, each with the control point that best fits its piece.
            constexpr int kPieces = 4;
            for (int piece = 0; piece < kPieces; ++piece) {
              const double t0 = static_cast<double>(piece) / kPieces;
              const double t1 = static_cast<double>(piece + 1) / kPieces;
              const msdfgen::Point2 start = segment->point(t0);
              const msdfgen::Point2 end = segment->point(t1);
              const msdfgen::Vector2 startDirection = segment->direction(t0);
              const double scaleToPiece = 3.0 * (t1 - t0) / 2.0; // direction() is the derivative over 3
              const msdfgen::Point2 control = start + startDirection * scaleToPiece;
              float p0[2];
              float p1[2];
              float p2[2];
              project(start, p0);
              project(control, p1);
              project(end, p2);
              PushGpuQuadratic(plan.mGpuEdges, p0, p1, p2, color);
            }
          }
        }
        FillContourCorners(plan.mGpuEdges, contourFirst);
      }
      gpuGlyph.mEdgeCount = static_cast<std::uint32_t>(plan.mGpuEdges.size()) - gpuGlyph.mFirstEdge;
    }
  }

  const std::vector<SMsdfGpuEdge>& MsdfCookPlan::GpuEdges() const
  {
    return mImpl->mGpuEdges;
  }

  const std::vector<SMsdfGpuGlyph>& MsdfCookPlan::GpuGlyphs() const
  {
    return mImpl->mGpuGlyphs;
  }

  float MsdfCookPlan::RangeTexels() const
  {
    return static_cast<float>(mImpl->mOptions.mDistanceRange);
  }

  void MsdfCookPlan::StoreGlyphField(const std::size_t glyphIndex, std::vector<float>& field)
  {
    Impl& plan = *mImpl;
    StoreField(plan.mGlyphs[glyphIndex], field, plan.mScale, plan.mRangeUnits, plan.mAtlas.mWidth, plan.mAtlas.mPixels.data());
  }

  void MsdfCookPlan::Finish(SMsdfFontAtlas& out)
  {
    Impl& plan = *mImpl;
    SMsdfFontAtlas& atlas = plan.mAtlas;
    atlas.mGlyphs.reserve(plan.mMappings.size());
    for (const auto& [codepoint, source] : plan.mMappings) {
      const SourceGlyph& glyph = plan.mGlyphs[source];
      SMsdfGlyph& result = atlas.mGlyphs.emplace_back();
      result.mCodepoint = codepoint;
      result.mAdvance = static_cast<float>(glyph.mAdvance / plan.mUnitsPerEm);
      if (glyph.mWidth <= 0) {
        continue;
      }
      const double inverseScale = 1.0 / plan.mScale;
      result.mPlaneLeft = static_cast<float>((-glyph.mTranslateX + 0.5 * inverseScale) / plan.mUnitsPerEm);
      result.mPlaneBottom = static_cast<float>((-glyph.mTranslateY + 0.5 * inverseScale) / plan.mUnitsPerEm);
      result.mPlaneRight = static_cast<float>((-glyph.mTranslateX + (glyph.mWidth - 0.5) * inverseScale) / plan.mUnitsPerEm);
      result.mPlaneTop = static_cast<float>((-glyph.mTranslateY + (glyph.mHeight - 0.5) * inverseScale) / plan.mUnitsPerEm);
      result.mAtlasLeft = static_cast<float>(glyph.mAtlasX) + 0.5f;
      result.mAtlasRight = static_cast<float>(glyph.mAtlasX + glyph.mWidth) - 0.5f;
      result.mAtlasTop = static_cast<float>(glyph.mAtlasY) + 0.5f;
      result.mAtlasBottom = static_cast<float>(glyph.mAtlasY + glyph.mHeight) - 0.5f;
    }
    RasterizeStrikes(plan.mFace->mFace, plan.mOptions, plan.mCodepoints, atlas);
    out = std::move(atlas);
  }

  bool MSDF_CookFont(
    const void* const fontBytes, const std::size_t byteCount, const SMsdfCookOptions& options, SMsdfFontAtlas& out,
    std::string& error
  )
  {
    out = SMsdfFontAtlas{};
    MsdfCookPlan plan;
    if (!plan.Prepare(fontBytes, byteCount, options, error) || !plan.GenerateOnCpu(error)) {
      return false;
    }
    plan.Finish(out);
    return true;
  }

  std::vector<std::string> MSDF_ReadFontNames(const void* const fontBytes, const std::size_t byteCount)
  {
    std::vector<std::string> names;
    const FreeTypeLibrary library{};
    const FreeTypeFace face(library.mLibrary, fontBytes, byteCount);
    if (face.mFace == nullptr) {
      return names;
    }
    const bool regular = (face.mFace->style_flags & (FT_STYLE_FLAG_BOLD | FT_STYLE_FLAG_ITALIC)) == 0;
    const FT_UInt count = FT_Get_Sfnt_Name_Count(face.mFace);
    for (FT_UInt i = 0; i < count; ++i) {
      FT_SfntName name{};
      if (FT_Get_Sfnt_Name(face.mFace, i, &name) != 0) {
        continue;
      }
      const bool fullName = name.name_id == TT_NAME_ID_FULL_NAME;
      const bool familyName = name.name_id == TT_NAME_ID_FONT_FAMILY || name.name_id == TT_NAME_ID_TYPOGRAPHIC_FAMILY;
      if (fullName || (familyName && regular)) {
        std::string text = DecodeName(name);
        if (!text.empty() && std::find(names.begin(), names.end(), text) == names.end()) {
          names.push_back(std::move(text));
        }
      }
    }
    return names;
  }

  std::vector<std::uint8_t> MSDF_SaveAtlas(const SMsdfFontAtlas& atlas)
  {
    std::vector<std::uint8_t> plain;
    plain.reserve(atlas.mGlyphs.size() * sizeof(SMsdfGlyph) + atlas.mPixels.size() + 64u);
    AppendValue(plain, atlas.mWidth);
    AppendValue(plain, atlas.mHeight);
    AppendValue(plain, atlas.mEmPixels);
    AppendValue(plain, atlas.mDistanceRange);
    AppendValue(plain, atlas.mMissing);
    AppendValue(plain, atlas.mAscent);
    AppendValue(plain, atlas.mDescent);
    AppendValue(plain, atlas.mLineGap);
    AppendValue(plain, static_cast<std::uint32_t>(atlas.mGlyphs.size()));
    for (const SMsdfGlyph& glyph : atlas.mGlyphs) {
      AppendValue(plain, glyph);
    }
    AppendValue(plain, static_cast<std::uint32_t>(atlas.mStrikes.size()));
    for (const SMsdfStrike& strike : atlas.mStrikes) {
      AppendValue(plain, strike.mPixelSize);
      AppendValue(plain, static_cast<std::uint32_t>(strike.mGlyphs.size()));
      AppendValue(plain, static_cast<std::uint32_t>(strike.mCoverage.size()));
      for (const SMsdfStrikeGlyph& glyph : strike.mGlyphs) {
        AppendValue(plain, glyph);
      }
      plain.insert(plain.end(), strike.mCoverage.begin(), strike.mCoverage.end());
    }
    plain.insert(plain.end(), atlas.mPixels.begin(), atlas.mPixels.end());

    std::vector<std::uint8_t> packed(sizeof(kAtlasMagic) + sizeof(kAtlasVersion) + ZSTD_compressBound(plain.size()));
    std::memcpy(packed.data(), &kAtlasMagic, sizeof(kAtlasMagic));
    std::memcpy(packed.data() + sizeof(kAtlasMagic), &kAtlasVersion, sizeof(kAtlasVersion));
    const std::size_t header = sizeof(kAtlasMagic) + sizeof(kAtlasVersion);
    const std::size_t written = ZSTD_compress(packed.data() + header, packed.size() - header, plain.data(), plain.size(), 3);
    if (ZSTD_isError(written) != 0u) {
      return {};
    }
    packed.resize(header + written);
    return packed;
  }

  bool MSDF_LoadAtlas(const void* const bytes, const std::size_t byteCount, SMsdfFontAtlas& out)
  {
    out = SMsdfFontAtlas{};
    const std::size_t header = sizeof(kAtlasMagic) + sizeof(kAtlasVersion);
    if (bytes == nullptr || byteCount < header) {
      return false;
    }
    std::uint32_t magic = 0u;
    std::uint32_t version = 0u;
    std::memcpy(&magic, bytes, sizeof(magic));
    std::memcpy(&version, static_cast<const std::uint8_t*>(bytes) + sizeof(magic), sizeof(version));
    if (magic != kAtlasMagic || version != kAtlasVersion) {
      return false;
    }

    const void* const packed = static_cast<const std::uint8_t*>(bytes) + header;
    const unsigned long long plainSize = ZSTD_getFrameContentSize(packed, byteCount - header);
    const unsigned long long largest = static_cast<unsigned long long>(kMaxLoadedAtlasSide) * kMaxLoadedAtlasSide * 4ull
      + kMaxLoadedGlyphs * sizeof(SMsdfGlyph) + 64ull;
    if (plainSize == ZSTD_CONTENTSIZE_UNKNOWN || plainSize == ZSTD_CONTENTSIZE_ERROR || plainSize > largest) {
      return false;
    }
    std::vector<std::uint8_t> plain(static_cast<std::size_t>(plainSize));
    const std::size_t read = ZSTD_decompress(plain.data(), plain.size(), packed, byteCount - header);
    if (ZSTD_isError(read) != 0u || read != plain.size()) {
      return false;
    }

    const std::uint8_t* at = plain.data();
    const std::uint8_t* const end = plain.data() + plain.size();
    std::uint32_t glyphCount = 0u;
    SMsdfFontAtlas atlas;
    if (!ReadValue(at, end, atlas.mWidth) || !ReadValue(at, end, atlas.mHeight) || !ReadValue(at, end, atlas.mEmPixels)
        || !ReadValue(at, end, atlas.mDistanceRange) || !ReadValue(at, end, atlas.mMissing)
        || !ReadValue(at, end, atlas.mAscent) || !ReadValue(at, end, atlas.mDescent) || !ReadValue(at, end, atlas.mLineGap)
        || !ReadValue(at, end, glyphCount)) {
      return false;
    }
    if (atlas.mWidth <= 0 || atlas.mHeight <= 0 || atlas.mWidth > kMaxLoadedAtlasSide || atlas.mHeight > kMaxLoadedAtlasSide
        || glyphCount > kMaxLoadedGlyphs || !std::isfinite(atlas.mEmPixels) || atlas.mEmPixels <= 0.0f
        || !std::isfinite(atlas.mDistanceRange) || atlas.mDistanceRange <= 0.0f || !std::isfinite(atlas.mAscent)
        || !std::isfinite(atlas.mDescent) || !std::isfinite(atlas.mLineGap)) {
      return false;
    }
    atlas.mGlyphs.resize(glyphCount);
    std::uint32_t previous = 0u;
    for (std::uint32_t i = 0; i < glyphCount; ++i) {
      SMsdfGlyph& glyph = atlas.mGlyphs[i];
      if (!ReadValue(at, end, glyph) || !IsGlyphRectValid(glyph, atlas) || (i != 0u && glyph.mCodepoint <= previous)) {
        return false;
      }
      previous = glyph.mCodepoint;
    }
    std::uint32_t strikeCount = 0u;
    if (!ReadValue(at, end, strikeCount) || strikeCount > kMaxLoadedStrikes) {
      return false;
    }
    atlas.mStrikes.resize(strikeCount);
    for (SMsdfStrike& strike : atlas.mStrikes) {
      std::uint32_t strikeGlyphs = 0u;
      std::uint32_t coverageBytes = 0u;
      if (!ReadValue(at, end, strike.mPixelSize) || !ReadValue(at, end, strikeGlyphs) || !ReadValue(at, end, coverageBytes)
          || strike.mPixelSize <= 0 || strike.mPixelSize > kMaxLoadedStrikeBox || strikeGlyphs > kMaxLoadedGlyphs) {
        return false;
      }
      strike.mGlyphs.resize(strikeGlyphs);
      std::uint32_t previousStrike = 0u;
      for (std::uint32_t i = 0; i < strikeGlyphs; ++i) {
        SMsdfStrikeGlyph& glyph = strike.mGlyphs[i];
        if (!ReadValue(at, end, glyph) || (i != 0u && glyph.mCodepoint <= previousStrike) || glyph.mWidth < 0
            || glyph.mHeight < 0 || glyph.mWidth > kMaxLoadedStrikeBox || glyph.mHeight > kMaxLoadedStrikeBox
            || !std::isfinite(glyph.mAdvance) || std::fabs(glyph.mAdvance) > kMaxLoadedStrikeMetric
            || std::abs(glyph.mLeft) > static_cast<int>(kMaxLoadedStrikeMetric) || std::abs(glyph.mTop) > static_cast<int>(kMaxLoadedStrikeMetric)
            || static_cast<std::uint64_t>(glyph.mOffset) + static_cast<std::uint64_t>(glyph.mWidth) * static_cast<std::uint64_t>(glyph.mHeight) > coverageBytes) {
          return false;
        }
        previousStrike = glyph.mCodepoint;
      }
      if (static_cast<std::size_t>(end - at) < coverageBytes) {
        return false;
      }
      strike.mCoverage.assign(at, at + coverageBytes);
      at += coverageBytes;
    }
    const std::size_t pixelBytes = static_cast<std::size_t>(atlas.mWidth) * static_cast<std::size_t>(atlas.mHeight) * 4u;
    if (static_cast<std::size_t>(end - at) != pixelBytes) {
      return false;
    }
    atlas.mPixels.assign(at, end);
    out = std::move(atlas);
    return true;
  }
} // namespace moho
