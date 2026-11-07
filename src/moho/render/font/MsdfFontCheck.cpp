#include "moho/render/font/MsdfFontCheck.h"

#include <algorithm>
#include <cctype>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <iterator>
#include <utility>
#include <vector>

namespace moho
{
  namespace
  {
    constexpr std::size_t kHeaderBytes = 12u;
    constexpr std::size_t kDirectoryEntryBytes = 16u;
    constexpr std::size_t kMaxTables = 64u; // the game's fonts have 13 to 23
    constexpr std::size_t kMaxTimestampTableBytes = 64u;
    constexpr float kMaxQuadEm = 16.0f;

    [[nodiscard]] constexpr std::uint32_t Tag(const char (&text)[5]) noexcept
    {
      return (static_cast<std::uint32_t>(static_cast<std::uint8_t>(text[0])) << 24u)
        | (static_cast<std::uint32_t>(static_cast<std::uint8_t>(text[1])) << 16u)
        | (static_cast<std::uint32_t>(static_cast<std::uint8_t>(text[2])) << 8u)
        | static_cast<std::uint32_t>(static_cast<std::uint8_t>(text[3]));
    }

    // Outlines, metrics, names, layout and hinting. Hinting tables are allowed but never run: the cook loads
    // outlines unhinted and FreeType is built with no bytecode interpreter. Variable-font tables stay out
    // because that build ignores them, and bitmap and color tables because nothing here draws them.
    constexpr std::uint32_t kAllowedTables[] = {
      Tag("cmap"), Tag("head"), Tag("hhea"), Tag("hmtx"), Tag("maxp"), Tag("name"), Tag("OS/2"), Tag("post"),
      Tag("glyf"), Tag("loca"), Tag("CFF "),
      Tag("cvt "), Tag("fpgm"), Tag("prep"), Tag("gasp"), Tag("hdmx"), Tag("LTSH"), Tag("VDMX"),
      Tag("GDEF"), Tag("GPOS"), Tag("GSUB"), Tag("BASE"), Tag("JSTF"), Tag("kern"), Tag("STAT"),
      Tag("vhea"), Tag("vmtx"), Tag("VORG"), Tag("DSIG"), Tag("PCLT"), Tag("meta"),
      Tag("FFTM"), // FontForge's timestamps, which many free fonts carry; its size is limited below
    };
    constexpr std::uint32_t kRequiredTables[] = {
      Tag("cmap"), Tag("head"), Tag("hhea"), Tag("hmtx"), Tag("maxp"), Tag("name"),
    };

    [[nodiscard]] std::uint32_t ReadU32(const std::uint8_t* const at) noexcept
    {
      return (static_cast<std::uint32_t>(at[0]) << 24u) | (static_cast<std::uint32_t>(at[1]) << 16u)
        | (static_cast<std::uint32_t>(at[2]) << 8u) | static_cast<std::uint32_t>(at[3]);
    }

    [[nodiscard]] std::string TagText(const std::uint32_t tag)
    {
      std::string text;
      for (const int shift : {24, 16, 8, 0}) {
        const unsigned char c = static_cast<unsigned char>(tag >> shift);
        text.push_back(c >= 0x20u && c < 0x7Fu ? static_cast<char>(c) : '?');
      }
      return text;
    }

    [[nodiscard]] bool Refuse(std::string& reason, std::string text)
    {
      reason = std::move(text);
      return false;
    }

    [[nodiscard]] bool AllZero(const std::uint8_t* const first, const std::uint8_t* const last) noexcept
    {
      return std::all_of(first, last, [](const std::uint8_t value) { return value == 0u; });
    }
  } // namespace

  bool MSDF_CheckFontStructure(const void* const bytes, const std::size_t byteCount, std::string& reason)
  {
    if (bytes == nullptr || byteCount == 0u) {
      return Refuse(reason, "the file is empty");
    }
    if (byteCount > kMsdfMaxFontBytes) {
      return Refuse(reason, "the file is over the size limit");
    }
    if (byteCount < kHeaderBytes) {
      return Refuse(reason, "the file is too short to be a font");
    }
    const auto* const data = static_cast<const std::uint8_t*>(bytes);
    const std::uint32_t signature = ReadU32(data);
    if (signature != 0x00010000u && signature != Tag("OTTO")) {
      return Refuse(reason, "not a TrueType or OpenType file");
    }

    const std::size_t tableCount = (static_cast<std::size_t>(data[4]) << 8u) | data[5];
    if (tableCount == 0u || tableCount > kMaxTables) {
      return Refuse(reason, "an unusable number of tables");
    }
    const std::size_t directoryEnd = kHeaderBytes + tableCount * kDirectoryEntryBytes;
    if (directoryEnd > byteCount) {
      return Refuse(reason, "the table directory runs past the end of the file");
    }

    std::vector<std::pair<std::uint64_t, std::uint64_t>> spans;
    spans.reserve(tableCount);
    std::uint32_t previousTag = 0u;
    bool hasGlyf = false;
    bool hasLoca = false;
    bool hasCff = false;
    std::size_t requiredFound = 0u;
    for (std::size_t i = 0; i < tableCount; ++i) {
      const std::uint8_t* const entry = data + kHeaderBytes + i * kDirectoryEntryBytes;
      const std::uint32_t tag = ReadU32(entry);
      const std::uint64_t offset = ReadU32(entry + 8u);
      const std::uint64_t length = ReadU32(entry + 12u);
      if (i != 0u && tag <= previousTag) {
        return Refuse(reason, "the table directory isn't sorted");
      }
      previousTag = tag;
      if (std::find(std::begin(kAllowedTables), std::end(kAllowedTables), tag) == std::end(kAllowedTables)) {
        return Refuse(reason, "table '" + TagText(tag) + "' isn't on the allowed list");
      }
      if (tag == Tag("FFTM") && length > kMaxTimestampTableBytes) {
        return Refuse(reason, "table 'FFTM' is larger than a timestamp table can be");
      }
      if (offset % 4u != 0u) {
        return Refuse(reason, "table '" + TagText(tag) + "' isn't aligned");
      }
      if (offset < directoryEnd || offset + length > byteCount) {
        return Refuse(reason, "table '" + TagText(tag) + "' lies outside the file");
      }
      if (std::find(std::begin(kRequiredTables), std::end(kRequiredTables), tag) != std::end(kRequiredTables)) {
        ++requiredFound;
      }
      hasGlyf = hasGlyf || tag == Tag("glyf");
      hasLoca = hasLoca || tag == Tag("loca");
      hasCff = hasCff || tag == Tag("CFF ");
      spans.emplace_back(offset, offset + length);
    }
    if (requiredFound != std::size(kRequiredTables) || !((hasGlyf && hasLoca) || hasCff)) {
      return Refuse(reason, "a table every font needs is missing");
    }

    // Walk the file in order: only tables, each followed by nothing but the zeros that align the next.
    std::sort(spans.begin(), spans.end());
    std::uint64_t position = directoryEnd;
    for (const auto& [first, last] : spans) {
      if (first < position) {
        return Refuse(reason, "tables overlap");
      }
      if (first - position > 3u || !AllZero(data + position, data + first)) {
        return Refuse(reason, "bytes that belong to no table");
      }
      position = last;
    }
    const std::uint64_t tail = byteCount - position;
    if (tail != 0u && (tail > 3u || byteCount % 4u != 0u || !AllZero(data + position, data + byteCount))) {
      return Refuse(reason, "bytes after the last table");
    }
    return true;
  }

  bool MSDF_IsAllowedModFontPath(const char* const path, std::string& reason)
  {
    if (path == nullptr || *path == '\0') {
      return Refuse(reason, "no path given");
    }
    std::string lower(path);
    std::transform(lower.begin(), lower.end(), lower.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
    if (lower.find("..") != std::string::npos || lower.find('\\') != std::string::npos || lower.find(':') != std::string::npos) {
      return Refuse(reason, "the path has parts a font path can't have");
    }
    constexpr char kModsPrefix[] = "/mods/";
    constexpr std::size_t kModsPrefixBytes = sizeof(kModsPrefix) - 1u;
    if (lower.compare(0u, kModsPrefixBytes, kModsPrefix) != 0) {
      return Refuse(reason, "the path isn't under /mods/<mod>/fonts/");
    }
    const std::size_t modEnd = lower.find('/', kModsPrefixBytes);
    constexpr char kFontsFolder[] = "/fonts/";
    constexpr std::size_t kFontsFolderBytes = sizeof(kFontsFolder) - 1u;
    if (modEnd == std::string::npos || modEnd == kModsPrefixBytes || lower.compare(modEnd, kFontsFolderBytes, kFontsFolder) != 0) {
      return Refuse(reason, "the path isn't under /mods/<mod>/fonts/");
    }
    const std::size_t dot = lower.rfind('.');
    const std::size_t slash = lower.rfind('/');
    if (dot == std::string::npos || dot < slash || dot == slash + 1u || (lower.compare(dot, std::string::npos, ".ttf") != 0 && lower.compare(dot, std::string::npos, ".otf") != 0)) {
      return Refuse(reason, "a font file has to be a .ttf or .otf");
    }
    return true;
  }

  bool MSDF_CheckCookedAtlas(const SMsdfFontAtlas& atlas, const SMsdfCookOptions& options, std::string& reason)
  {
    if (atlas.mWidth != options.mAtlasWidth || atlas.mHeight <= 0 || atlas.mHeight > options.mMaxAtlasHeight) {
      return Refuse(reason, "the atlas has the wrong size");
    }
    if (atlas.mEmPixels != static_cast<float>(options.mEmPixels) || atlas.mDistanceRange != static_cast<float>(options.mDistanceRange)) {
      return Refuse(reason, "the atlas has the wrong scale");
    }
    std::vector<std::uint32_t> asked = options.mCodepoints;
    std::sort(asked.begin(), asked.end());
    if (atlas.mGlyphs.size() > asked.size() || atlas.mMissing > asked.size()) {
      return Refuse(reason, "the atlas has too many glyphs");
    }
    for (const SMsdfGlyph& glyph : atlas.mGlyphs) {
      if (!std::binary_search(asked.begin(), asked.end(), glyph.mCodepoint)) {
        return Refuse(reason, "the atlas has a character nobody asked for");
      }
      const float metrics[] = {glyph.mAdvance, glyph.mPlaneLeft, glyph.mPlaneBottom, glyph.mPlaneRight, glyph.mPlaneTop};
      for (const float value : metrics) {
        if (!std::isfinite(value) || std::fabs(value) > kMaxQuadEm) {
          return Refuse(reason, "a glyph's size is out of range");
        }
      }
    }
    if (std::fabs(atlas.mAscent) > kMaxQuadEm || std::fabs(atlas.mDescent) > kMaxQuadEm || std::fabs(atlas.mLineGap) > kMaxQuadEm) {
      return Refuse(reason, "the font's line metrics are out of range");
    }
    if (atlas.mStrikes.size() != options.mStrikeSizes.size()) {
      return Refuse(reason, "the atlas has the wrong small sizes");
    }
    for (std::size_t i = 0; i < atlas.mStrikes.size(); ++i) {
      if (atlas.mStrikes[i].mPixelSize != options.mStrikeSizes[i]) {
        return Refuse(reason, "the atlas has the wrong small sizes");
      }
      for (const SMsdfStrikeGlyph& glyph : atlas.mStrikes[i].mGlyphs) {
        if (!std::binary_search(asked.begin(), asked.end(), glyph.mCodepoint)) {
          return Refuse(reason, "the atlas has a character nobody asked for");
        }
      }
    }
    return true;
  }
} // namespace moho
