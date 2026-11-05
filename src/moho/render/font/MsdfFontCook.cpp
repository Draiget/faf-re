#include "moho/render/font/MsdfFontCook.h"

#include <algorithm>
#include <atomic>
#include <cctype>
#include <cmath>
#include <cstring>
#include <map>
#include <memory>
#include <thread>
#include <utility>

#include <ft2build.h>
#include FT_FREETYPE_H
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
    constexpr std::uint32_t kAtlasVersion = 1u;
    constexpr std::int32_t kMaxLoadedAtlasSide = 8192;
    constexpr std::uint32_t kMaxLoadedGlyphs = 65536u;

    struct FreeTypeLibrary
    {
      FT_Library mLibrary = nullptr;
      FreeTypeLibrary() { (void)FT_Init_FreeType(&mLibrary); }
      ~FreeTypeLibrary()
      {
        if (mLibrary != nullptr) {
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

    /**
     * Prepares an outline as msdf-atlas-gen does: valid, normalized, wound so that the outside is
     * negative, and colored. False for a glyph that doesn't load or has an open contour.
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
      msdfgen::edgeColoringInkTrap(glyph.mShape, kCornerAngleThreshold, coloringSeed);
      return true;
    }

    /**
     * The glyph's box at one scale: the bounds grown by half the distance range and the miters, rounded
     * up to whole texels with the shape centered, plus one texel so the quad can stop at texel centers.
     */
    void WrapBox(SourceGlyph& glyph, const double scale, const double rangeUnits, const double miterLimit)
    {
      const msdfgen::Shape::Bounds bounds = glyph.mShape.getBounds();
      if (bounds.l >= bounds.r || bounds.b >= bounds.t) {
        return;
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
      glyph.mWidth = static_cast<std::int32_t>(std::ceil(width)) + 1;
      glyph.mHeight = static_cast<std::int32_t>(std::ceil(height)) + 1;
      glyph.mTranslateX = -left + 0.5 * (glyph.mWidth - width) / scale;
      glyph.mTranslateY = -bottom + 0.5 * (glyph.mHeight - height) / scale;
    }

    /** Shelves, tallest first. Returns the rows used, or 0 when a box is wider than the atlas. */
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
          return 0;
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

  bool MSDF_CookFont(
    const void* const fontBytes, const std::size_t byteCount, const SMsdfCookOptions& options, SMsdfFontAtlas& out,
    std::string& error
  )
  {
    out = SMsdfFontAtlas{};
    const FreeTypeLibrary library;
    const FreeTypeFace face(library.mLibrary, fontBytes, byteCount);
    if (face.mFace == nullptr) {
      error = "FreeType can't read this file as a font";
      return false;
    }
    if ((face.mFace->face_flags & FT_FACE_FLAG_SCALABLE) == 0 || face.mFace->units_per_EM == 0) {
      error = "not a scalable font";
      return false;
    }
    const FontHandleOwner font(face.mFace);

    std::vector<std::uint32_t> codepoints = options.mCodepoints;
    std::sort(codepoints.begin(), codepoints.end());
    codepoints.erase(std::unique(codepoints.begin(), codepoints.end()), codepoints.end());

    // One source glyph per glyph id, in codepoint order: the order seeds the coloring, so the result
    // doesn't depend on anything but the font and the options.
    std::vector<SourceGlyph> glyphs;
    std::map<unsigned, std::size_t> glyphOfId;
    std::vector<std::pair<std::uint32_t, std::size_t>> mappings;
    std::uint64_t coloringSeed = 0;
    for (const std::uint32_t codepoint : codepoints) {
      const unsigned glyphId = FT_Get_Char_Index(face.mFace, codepoint);
      if (glyphId == 0u) {
        ++out.mMissing;
        continue;
      }
      auto known = glyphOfId.find(glyphId);
      if (known == glyphOfId.end()) {
        coloringSeed *= kColoringSeedStep;
        SourceGlyph glyph;
        if (!LoadGlyph(glyph, font.mFont, glyphId, coloringSeed)) {
          ++out.mMissing;
          continue;
        }
        known = glyphOfId.emplace(glyphId, glyphs.size()).first;
        glyphs.push_back(std::move(glyph));
      }
      mappings.emplace_back(codepoint, known->second);
    }

    const double unitsPerEm = face.mFace->units_per_EM;
    const double scale = options.mEmPixels / unitsPerEm;
    const double rangeUnits = options.mDistanceRange / scale;
    for (SourceGlyph& glyph : glyphs) {
      WrapBox(glyph, scale, rangeUnits, options.mMiterLimit);
    }

    const std::int32_t rowsUsed = PackShelves(glyphs, options.mAtlasWidth, options.mGlyphSpacing);
    const std::int32_t step = (std::max)(options.mHeightStep, 1);
    const std::int32_t rows = (std::max)((rowsUsed + step - 1) / step, 1) * step;
    if (rows > options.mMaxAtlasHeight || (rowsUsed == 0 && !glyphs.empty() && glyphs.front().mWidth > options.mAtlasWidth)) {
      error = "the glyphs don't fit the atlas";
      return false;
    }

    out.mWidth = options.mAtlasWidth;
    out.mHeight = rows;
    out.mEmPixels = static_cast<float>(options.mEmPixels);
    out.mDistanceRange = static_cast<float>(options.mDistanceRange);
    out.mPixels.assign(static_cast<std::size_t>(out.mWidth) * static_cast<std::size_t>(out.mHeight) * 4u, 0u);

    // Boxes don't overlap, so threads write disjoint texels.
    std::atomic<std::size_t> next{0u};
    const auto work = [&]() {
      std::vector<float> field;
      for (std::size_t i = next++; i < glyphs.size(); i = next++) {
        if (glyphs[i].mWidth > 0) {
          GenerateGlyph(glyphs[i], field, scale, rangeUnits, out.mWidth, out.mPixels.data());
        }
      }
    };
    {
      std::vector<std::thread> pool;
      for (std::int32_t t = 1; t < options.mThreads; ++t) {
        pool.emplace_back(work);
      }
      work();
      for (std::thread& thread : pool) {
        thread.join();
      }
    }

    out.mGlyphs.reserve(mappings.size());
    for (const auto& [codepoint, source] : mappings) {
      const SourceGlyph& glyph = glyphs[source];
      SMsdfGlyph& result = out.mGlyphs.emplace_back();
      result.mCodepoint = codepoint;
      result.mAdvance = static_cast<float>(glyph.mAdvance / unitsPerEm);
      if (glyph.mWidth <= 0) {
        continue;
      }
      const double inverseScale = 1.0 / scale;
      result.mPlaneLeft = static_cast<float>((-glyph.mTranslateX + 0.5 * inverseScale) / unitsPerEm);
      result.mPlaneBottom = static_cast<float>((-glyph.mTranslateY + 0.5 * inverseScale) / unitsPerEm);
      result.mPlaneRight = static_cast<float>((-glyph.mTranslateX + (glyph.mWidth - 0.5) * inverseScale) / unitsPerEm);
      result.mPlaneTop = static_cast<float>((-glyph.mTranslateY + (glyph.mHeight - 0.5) * inverseScale) / unitsPerEm);
      result.mAtlasLeft = static_cast<float>(glyph.mAtlasX) + 0.5f;
      result.mAtlasRight = static_cast<float>(glyph.mAtlasX + glyph.mWidth) - 0.5f;
      result.mAtlasTop = static_cast<float>(glyph.mAtlasY) + 0.5f;
      result.mAtlasBottom = static_cast<float>(glyph.mAtlasY + glyph.mHeight) - 0.5f;
    }
    return true;
  }

  std::vector<std::string> MSDF_ReadFontNames(const void* const fontBytes, const std::size_t byteCount)
  {
    std::vector<std::string> names;
    const FreeTypeLibrary library;
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
    AppendValue(plain, static_cast<std::uint32_t>(atlas.mGlyphs.size()));
    for (const SMsdfGlyph& glyph : atlas.mGlyphs) {
      AppendValue(plain, glyph);
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
        || !ReadValue(at, end, glyphCount)) {
      return false;
    }
    if (atlas.mWidth <= 0 || atlas.mHeight <= 0 || atlas.mWidth > kMaxLoadedAtlasSide || atlas.mHeight > kMaxLoadedAtlasSide
        || glyphCount > kMaxLoadedGlyphs || !std::isfinite(atlas.mEmPixels) || atlas.mEmPixels <= 0.0f
        || !std::isfinite(atlas.mDistanceRange) || atlas.mDistanceRange <= 0.0f) {
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
    const std::size_t pixelBytes = static_cast<std::size_t>(atlas.mWidth) * static_cast<std::size_t>(atlas.mHeight) * 4u;
    if (static_cast<std::size_t>(end - at) != pixelBytes) {
      return false;
    }
    atlas.mPixels.assign(at, end);
    out = std::move(atlas);
    return true;
  }
} // namespace moho
