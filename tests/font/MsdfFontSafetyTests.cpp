// Engine addition: the checks on a mod's font (issue #305).
//
//   faf_msdf_safety_tests [folder of fonts that must pass the structure check] [more fonts for the out of memory sweep]
//
// Without a folder it uses Windows' Arial alone.

#include <algorithm>
#include <gtest/gtest.h>
#include <atomic>
#include <cctype>
#include <chrono>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "moho/render/font/MsdfFontCheck.h"

namespace
{
  using Bytes = std::vector<std::uint8_t>;

  Bytes ReadFile(const std::filesystem::path& path)
  {
    std::ifstream in(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
  }

  void PutU32(Bytes& bytes, const std::size_t at, const std::uint32_t value)
  {
    bytes[at] = static_cast<std::uint8_t>(value >> 24u);
    bytes[at + 1u] = static_cast<std::uint8_t>(value >> 16u);
    bytes[at + 2u] = static_cast<std::uint8_t>(value >> 8u);
    bytes[at + 3u] = static_cast<std::uint8_t>(value);
  }

  std::uint32_t GetU32(const Bytes& bytes, const std::size_t at)
  {
    return (static_cast<std::uint32_t>(bytes[at]) << 24u) | (static_cast<std::uint32_t>(bytes[at + 1u]) << 16u)
      | (static_cast<std::uint32_t>(bytes[at + 2u]) << 8u) | bytes[at + 3u];
  }

  std::size_t TableCount(const Bytes& bytes)
  {
    return (static_cast<std::size_t>(bytes[4]) << 8u) | bytes[5];
  }

  std::size_t EntryAt(const std::size_t index)
  {
    return 12u + index * 16u;
  }

  void ExpectRefused(const std::string& what, const Bytes& bytes, const char* const expected)
  {
    std::string reason;
    const bool passed = moho::MSDF_CheckFontStructure(bytes.data(), bytes.size(), reason);
    EXPECT_FALSE(passed) << what + ": passed the structure check";
    if (!passed) {
      std::printf("  refused, %s: %s\n", what.c_str(), reason.c_str());
      EXPECT_TRUE(reason.find(expected) != std::string::npos) << what + ": wrong reason: " + reason;
    }
  }

  void TestStructure(const Bytes& font)
  {
    std::string reason;
    EXPECT_TRUE(moho::MSDF_CheckFontStructure(font.data(), font.size(), reason)) << "a real font was refused: " + reason;

    ExpectRefused("an empty file", Bytes{}, "empty");
    ExpectRefused("too short", Bytes(8u, std::uint8_t{0}), "too short");

    Bytes program(4096u, std::uint8_t{0x90});
    program[0] = 'M';
    program[1] = 'Z';
    ExpectRefused("a renamed .exe", program, "not a TrueType");

    Bytes collection = font;
    collection[0] = 't';
    collection[1] = 't';
    collection[2] = 'c';
    collection[3] = 'f';
    ExpectRefused("a font collection", collection, "not a TrueType");

    Bytes appended = font;
    appended.insert(appended.end(), {'M', 'Z', 0x90, 0x90, 0x90, 0x90, 0x90, 0x90});
    ExpectRefused("a font with bytes appended", appended, "after the last table");

    Bytes oneByte = font;
    oneByte.push_back(0u);
    ExpectRefused("a font with one byte appended", oneByte, "after the last table");

    Bytes huge(moho::kMsdfMaxFontBytes + 1u, std::uint8_t{0});
    ExpectRefused("a file over the size limit", huge, "size limit");

    const std::size_t count = TableCount(font);

    Bytes unknown = font;
    PutU32(unknown, EntryAt(count - 1u), 0x7A7A7A7Au); // "zzzz", which still sorts last
    ExpectRefused("a font with an unknown table", unknown, "allowed list");

    Bytes variable = font;
    PutU32(variable, EntryAt(0u), 0x4D455247u); // "MERG"
    ExpectRefused("a table that isn't on the list", variable, "");

    Bytes unsorted = font;
    for (std::size_t i = 0; i < 16u; ++i) {
      std::swap(unsorted[EntryAt(0u) + i], unsorted[EntryAt(1u) + i]);
    }
    ExpectRefused("an unsorted directory", unsorted, "sorted");

    Bytes pastEnd = font;
    PutU32(pastEnd, EntryAt(2u) + 12u, static_cast<std::uint32_t>(font.size()));
    ExpectRefused("a table past the end of the file", pastEnd, "outside the file");

    Bytes wraps = font;
    PutU32(wraps, EntryAt(2u) + 12u, 0xFFFFFFFCu);
    ExpectRefused("a table length that would wrap around", wraps, "outside the file");

    Bytes intoDirectory = font;
    PutU32(intoDirectory, EntryAt(2u) + 8u, 12u);
    ExpectRefused("a table on top of the directory", intoDirectory, "outside the file");

    // Point one table at another's bytes.
    Bytes overlap = font;
    std::size_t lowest = 0u;
    std::size_t next = 0u;
    std::uint32_t lowestOffset = 0xFFFFFFFFu;
    std::uint32_t nextOffset = 0xFFFFFFFFu;
    for (std::size_t i = 0; i < count; ++i) {
      const std::uint32_t offset = GetU32(font, EntryAt(i) + 8u);
      if (offset < lowestOffset) {
        nextOffset = lowestOffset;
        next = lowest;
        lowestOffset = offset;
        lowest = i;
      } else if (offset < nextOffset) {
        nextOffset = offset;
        next = i;
      }
    }
    PutU32(overlap, EntryAt(next) + 8u, lowestOffset);
    ExpectRefused("overlapping tables", overlap, "overlap");

    Bytes gap = font;
    PutU32(gap, EntryAt(lowest) + 12u, GetU32(font, EntryAt(lowest) + 12u) - 16u);
    ExpectRefused("a gap between tables", gap, "no table");

    Bytes dirtyPadding = font;
    bool foundPadding = false;
    for (std::size_t i = 0; i < count && !foundPadding; ++i) {
      const std::uint32_t end = GetU32(font, EntryAt(i) + 8u) + GetU32(font, EntryAt(i) + 12u);
      if (end % 4u != 0u && end < font.size()) {
        dirtyPadding[end] = 0xCCu;
        foundPadding = true;
      }
    }
    if (foundPadding) {
      ExpectRefused("bytes hidden in padding", dirtyPadding, "");
    }

    Bytes noCmap = font;
    for (std::size_t i = 0; i < count; ++i) {
      if (GetU32(font, EntryAt(i)) == 0x636D6170u) { // "cmap", swapped for an allowed one that sorts nearby
        PutU32(noCmap, EntryAt(i), 0x62617365u);
      }
    }
    ExpectRefused("a font with no cmap", noCmap, "");
  }

  void TestFolder(const std::filesystem::path& folder)
  {
    int checked = 0;
    for (const auto& entry : std::filesystem::directory_iterator(folder)) {
      std::string extension = entry.path().extension().string();
      std::transform(extension.begin(), extension.end(), extension.begin(), [](const unsigned char c) { return static_cast<char>(std::tolower(c)); });
      if (extension != ".ttf" && extension != ".otf") {
        continue;
      }
      const Bytes bytes = ReadFile(entry.path());
      std::string reason;
      EXPECT_TRUE(moho::MSDF_CheckFontStructure(bytes.data(), bytes.size(), reason)) << entry.path().string() + " was refused: " + reason;
      ++checked;
    }
    std::printf("%d fonts in %s checked\n", checked, folder.string().c_str());
  }

  void TestPaths()
  {
    const struct
    {
      const char* mPath;
      bool mAllowed;
    } cases[] = {
      {"/mods/MyMod/fonts/MyFont.ttf", true},
      {"/mods/my mod/fonts/sub/font.OTF", true},
      {"/mods/mymod/font.ttf", false},
      {"/mods//fonts/font.ttf", false},
      {"/mods/mymod/fonts/../../../secret.ttf", false},
      {"/mods/mymod/fonts/font.exe", false},
      {"/mods/mymod/fonts/.ttf", false},
      {"/fonts/arial.ttf", false},
      {"C:/Windows/Fonts/arial.ttf", false},
      {"\\mods\\mymod\\fonts\\font.ttf", false},
      {"", false},
    };
    for (const auto& item : cases) {
      std::string reason;
      EXPECT_EQ(moho::MSDF_IsAllowedModFontPath(item.mPath, reason), item.mAllowed) << std::string("path check got this wrong: ") + item.mPath;
    }
  }

  void TestStrikes(const Bytes& font)
  {
    const moho::SMsdfCookOptions options = moho::MSDF_MakeModCookOptions(2);
    moho::SMsdfFontAtlas atlas;
    std::string error;
    EXPECT_TRUE(moho::MSDF_CookFont(font.data(), font.size(), options, atlas, error)) << "couldn't cook with small sizes: " + error;
    EXPECT_EQ(atlas.mStrikes.size(), options.mStrikeSizes.size()) << "the small sizes are missing";
    EXPECT_TRUE(atlas.mAscent > 0.0f && atlas.mDescent > 0.0f) << "the font's line metrics are missing";
    EXPECT_TRUE(moho::MSDF_CheckCookedAtlas(atlas, options, error)) << "an atlas with small sizes was refused: " + error;

    for (const moho::SMsdfStrike& strike : atlas.mStrikes) {
      int inked = 0;
      for (const std::uint8_t value : strike.mCoverage) {
        inked += value > 127u ? 1 : 0;
      }
      std::printf("  %d px: %zu glyphs, %zu bytes, %d inked\n", strike.mPixelSize, strike.mGlyphs.size(), strike.mCoverage.size(), inked);
      EXPECT_TRUE(strike.mGlyphs.size() > 200u && inked > 0) << "a small size has no glyphs";
    }

    const std::vector<std::uint8_t> packed = moho::MSDF_SaveAtlas(atlas);
    moho::SMsdfFontAtlas loaded;
    EXPECT_TRUE(moho::MSDF_LoadAtlas(packed.data(), packed.size(), loaded)) << "an atlas with small sizes didn't load back";
    EXPECT_TRUE(loaded.mStrikes.size() == atlas.mStrikes.size() && loaded.mStrikes[0].mCoverage == atlas.mStrikes[0].mCoverage) << "small sizes changed on the way back";

    const auto refusedAfter = [&atlas](const char* const what, void (*const tamper)(moho::SMsdfFontAtlas&)) {
      moho::SMsdfFontAtlas bad = atlas;
      tamper(bad);
      const std::vector<std::uint8_t> badPacked = moho::MSDF_SaveAtlas(bad);
      moho::SMsdfFontAtlas badLoaded;
      EXPECT_FALSE(moho::MSDF_LoadAtlas(badPacked.data(), badPacked.size(), badLoaded)) << std::string("loaded: ") + what;
    };
    refusedAfter("a bitmap past its coverage", [](moho::SMsdfFontAtlas& bad) { bad.mStrikes[0].mGlyphs[5].mOffset = 0x7FFFFFFFu; });
    refusedAfter("a bitmap of negative width", [](moho::SMsdfFontAtlas& bad) { bad.mStrikes[0].mGlyphs[5].mWidth = -4; });
    refusedAfter("an unsorted small size", [](moho::SMsdfFontAtlas& bad) { bad.mStrikes[0].mGlyphs[5].mCodepoint = 1u; });
    refusedAfter("a line metric that isn't a number", [](moho::SMsdfFontAtlas& bad) { bad.mAscent = std::nanf(""); });
  }

  void TestCookLimits(const Bytes& font)
  {
    moho::SMsdfCookOptions options = moho::MSDF_MakeCookOptions(2);
    options.mCodepoints = {'A', 'B', 'g', '&'};

    moho::SMsdfFontAtlas atlas;
    std::string error;
    EXPECT_TRUE(moho::MSDF_CookFont(font.data(), font.size(), options, atlas, error)) << "the default limits refused a real font: " + error;

    moho::SMsdfCookOptions fewEdges = options;
    fewEdges.mMaxEdgesPerGlyph = 2;
    EXPECT_FALSE(moho::MSDF_CookFont(font.data(), font.size(), fewEdges, atlas, error)) << "the edges-per-glyph limit didn't hold";
    std::printf("  refused: %s\n", error.c_str());

    moho::SMsdfCookOptions fewTotal = options;
    fewTotal.mMaxEdgesPerFont = 5;
    EXPECT_FALSE(moho::MSDF_CookFont(font.data(), font.size(), fewTotal, atlas, error)) << "the edges-per-font limit didn't hold";
    std::printf("  refused: %s\n", error.c_str());

    // A box wider than the atlas behind a narrow first one: unplaced, it would be written past the atlas.
    moho::SMsdfCookOptions narrowAtlas = options;
    narrowAtlas.mCodepoints = {'i', 'W'};
    narrowAtlas.mAtlasWidth = 40;
    EXPECT_FALSE(moho::MSDF_CookFont(font.data(), font.size(), narrowAtlas, atlas, error)) << "a glyph wider than the atlas, not the first, wasn't refused";
    std::printf("  refused: %s\n", error.c_str());

    moho::SMsdfCookOptions fewGlyphs = options;
    fewGlyphs.mMaxFontGlyphs = 10;
    EXPECT_FALSE(moho::MSDF_CookFont(font.data(), font.size(), fewGlyphs, atlas, error)) << "the glyphs-per-font limit didn't hold";
    std::printf("  refused: %s\n", error.c_str());
  }

  void TestCookedAtlasCheck(const Bytes& font)
  {
    moho::SMsdfCookOptions options = moho::MSDF_MakeCookOptions(2);
    moho::SMsdfFontAtlas atlas;
    std::string error;
    EXPECT_TRUE(moho::MSDF_CookFont(font.data(), font.size(), options, atlas, error)) << "couldn't cook: " + error;
    EXPECT_TRUE(moho::MSDF_CheckCookedAtlas(atlas, options, error)) << "a real atlas was refused: " + error;

    moho::SMsdfFontAtlas wrongSize = atlas;
    wrongSize.mWidth = 2048;
    EXPECT_FALSE(moho::MSDF_CheckCookedAtlas(wrongSize, options, error)) << "a wrong atlas width passed";

    moho::SMsdfFontAtlas unasked = atlas;
    unasked.mGlyphs.back().mCodepoint = 0x10FFFFu;
    EXPECT_FALSE(moho::MSDF_CheckCookedAtlas(unasked, options, error)) << "a character nobody asked for passed";

    moho::SMsdfFontAtlas hugeQuad = atlas;
    hugeQuad.mGlyphs.front().mPlaneRight = 1000000.0f;
    EXPECT_FALSE(moho::MSDF_CheckCookedAtlas(hugeQuad, options, error)) << "a huge glyph quad passed";
  }

  /**
   * FreeType out of memory at many different points: each step allows 5% more, so allocations fail in other
   * places, the autohinter's among them. A crash here is a FreeType path that doesn't survive a failed
   * allocation (dependencies/patches/freetype_2_15_0_faf_oom.md); a refusal or missing glyphs are fine.
   */
  void TestOutOfMemory(const Bytes& font)
  {
    moho::SMsdfCookOptions options = moho::MSDF_MakeModCookOptions(2);
    options.mCodepoints = {' ', 'A', 'a', 'g', 'W', '&', '0', 0xE9u, 0x416u, 0x436u, 0x2014u};
    int cooked = 0;
    int refused = 0;
    for (double limit = 4096.0; limit < 8.0 * 1024.0 * 1024.0; limit *= 1.05) {
      moho::SMsdfCookOptions probe = options;
      probe.mMaxFreeTypeBytes = static_cast<std::size_t>(limit);
      moho::SMsdfFontAtlas out;
      std::string reason;
      (moho::MSDF_CookFont(font.data(), font.size(), probe, out, reason) ? cooked : refused) += 1;
    }
    std::printf("  out of memory sweep: %d cooked, %d refused, none crashed\n", cooked, refused);
    EXPECT_TRUE(cooked > 0) << "no limit in the sweep let the font cook";
  }

  /** The limits a mod's font cooks under, now that it cooks in the game's process. */
  void TestModLimits(const Bytes& font)
  {
    moho::SMsdfCookOptions options = moho::MSDF_MakeModCookOptions(2);
#if defined(FAF_COVERAGE_PROFILE)
    // Coverage counters slow the cook several times over; the wall-clock limit is checked below on its own.
    options.mMaxSeconds = 0.0;
#endif
    moho::SMsdfFontAtlas atlas;
    std::string error;
    const auto start = std::chrono::steady_clock::now();
    EXPECT_TRUE(moho::MSDF_CookFont(font.data(), font.size(), options, atlas, error)) << "a real font didn't cook under a mod's limits: " + error;
    std::printf(
      "cooked under a mod's limits: %zu glyphs, %d ms\n", atlas.mGlyphs.size(),
      static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count())
    );

    moho::SMsdfFontAtlas unlimited;
    moho::SMsdfCookOptions plain = moho::MSDF_MakeCookOptions(2);
    plain.mStrikeSizes = options.mStrikeSizes;
    if (moho::MSDF_CookFont(font.data(), font.size(), plain, unlimited, error)) {
      EXPECT_EQ(unlimited.mPixels, atlas.mPixels) << "the limits changed the atlas of a font inside them";
    }

    const auto refused = [&font](const char* const what, const moho::SMsdfCookOptions& tight, const char* const expected) {
      moho::SMsdfFontAtlas out;
      std::string reason;
      const bool cooked = moho::MSDF_CookFont(font.data(), font.size(), tight, out, reason);
      EXPECT_FALSE(cooked) << std::string(what) + " didn't hold";
      std::printf("  %s: %s\n", what, reason.c_str());
      EXPECT_TRUE(cooked || reason.find(expected) != std::string::npos) << std::string(what) + ": wrong reason: " + reason;
    };

    // How close a real font comes to the limits, to within a factor of two. Short of memory, FreeType drops
    // glyphs rather than the font, so a pass has to keep every glyph and bitmap the full cook has.
    const auto countStrikeGlyphs = [](const moho::SMsdfFontAtlas& cooked) {
      std::size_t count = 0u;
      for (const moho::SMsdfStrike& strike : cooked.mStrikes) {
        count += strike.mGlyphs.size();
      }
      return count;
    };
    const auto smallestPassing = [&](auto set) {
      for (std::uint64_t limit = 1024u; limit < (1ull << 40u); limit *= 2u) {
        moho::SMsdfCookOptions probe = options;
        set(probe, limit);
        moho::SMsdfFontAtlas out;
        std::string reason;
        if (moho::MSDF_CookFont(font.data(), font.size(), probe, out, reason) && out.mGlyphs.size() == atlas.mGlyphs.size()
            && out.mMissing == atlas.mMissing && countStrikeGlyphs(out) == countStrikeGlyphs(atlas)) {
          return limit;
        }
      }
      return std::uint64_t{0};
    };
    std::printf(
      "  this font needs: FreeType memory %llu, font work %llu, glyph work %llu (limits %zu, %llu, %llu)\n",
      static_cast<unsigned long long>(smallestPassing([](moho::SMsdfCookOptions& o, const std::uint64_t v) { o.mMaxFreeTypeBytes = static_cast<std::size_t>(v); })),
      static_cast<unsigned long long>(smallestPassing([](moho::SMsdfCookOptions& o, const std::uint64_t v) { o.mMaxFontWork = v; })),
      static_cast<unsigned long long>(smallestPassing([](moho::SMsdfCookOptions& o, const std::uint64_t v) { o.mMaxGlyphWork = v; })),
      options.mMaxFreeTypeBytes, static_cast<unsigned long long>(options.mMaxFontWork), static_cast<unsigned long long>(options.mMaxGlyphWork)
    );

    moho::SMsdfCookOptions tinyMemory = options;
    tinyMemory.mMaxFreeTypeBytes = 4096u;
    refused("FreeType's memory limit", tinyMemory, "FreeType");

    moho::SMsdfCookOptions glyphWork = options;
    glyphWork.mMaxGlyphWork = 1000u;
    refused("the work limit of a glyph", glyphWork, "a glyph would take too much work");

    moho::SMsdfCookOptions fontWork = options;
    fontWork.mMaxFontWork = 1000000u;
    refused("the work limit of a font", fontWork, "the font would take too much work");

    moho::SMsdfCookOptions noTime = options;
    noTime.mMaxSeconds = 1.0e-9;
    refused("the time limit", noTime, "too long");

    std::atomic<bool> cancel{true};
    moho::SMsdfCookOptions cancelled = options;
    cancelled.mCancel = &cancel;
    refused("a cancel", cancelled, "cancelled");

    // The time limit has to stop a cook that is already making fields, not only one still reading outlines.
    moho::SMsdfCookOptions slow = options;
    // About 60 glyphs of 130,000 texels each: seconds of fields, in a 32 MB atlas.
    slow.mEmPixels = 300.0;
    slow.mDistanceRange = 30.0;
    slow.mAtlasWidth = 4096;
    slow.mMaxAtlasHeight = 8192;
    slow.mHeightStep = 256;
    slow.mCodepoints.clear();
    for (std::uint32_t c = '0'; c <= 'z'; ++c) {
      if (std::isalnum(static_cast<int>(c)) != 0) {
        slow.mCodepoints.push_back(c);
      }
    }
    slow.mMaxGlyphWork = 0u;
    slow.mMaxFontWork = 0u;
    slow.mMaxSeconds = 0.5;
    const auto slowStart = std::chrono::steady_clock::now();
    moho::MsdfCookPlan plan;
    std::string reason;
    const bool prepared = plan.Prepare(font.data(), font.size(), slow, reason);
    EXPECT_TRUE(prepared) << "a large cook didn't prepare: " + reason;
    if (prepared) {
      const bool generated = plan.GenerateOnCpu(reason);
      const int ms = static_cast<int>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - slowStart).count());
      std::printf("  a large cook with half a second: %d ms, %s\n", ms, generated ? "finished" : reason.c_str());
      EXPECT_TRUE(!generated && plan.TimedOut()) << "the time limit didn't stop a cook making fields";
      EXPECT_TRUE(ms < 5000) << "the time limit stopped the cook late";
    }
  }
} // namespace

static std::string gFolder;
static std::vector<std::string> gExtraFonts;

TEST(Existing_MsdfFontSafety, Structure)
{
  std::setvbuf(stdout, nullptr, _IONBF, 0);
  const Bytes font = ReadFile("C:/Windows/Fonts/arial.ttf");
  ASSERT_FALSE(font.empty()) << "can't read Windows' Arial";
  TestStructure(font);
  if (!gFolder.empty()) {
    TestFolder(gFolder);
  }
}

TEST(Existing_MsdfFontSafety, PathsAndStrikes)
{
  const Bytes font = ReadFile("C:/Windows/Fonts/arial.ttf");
  ASSERT_FALSE(font.empty()) << "can't read Windows' Arial";
  TestPaths();
  TestStrikes(font);
}

TEST(Existing_MsdfFontSafety, CookLimitsAndAtlasCheck)
{
  const Bytes font = ReadFile("C:/Windows/Fonts/arial.ttf");
  ASSERT_FALSE(font.empty()) << "can't read Windows' Arial";
  TestCookLimits(font);
  TestCookedAtlasCheck(font);
}

TEST(Existing_MsdfFontSafety, OutOfMemorySweep)
{
  const Bytes font = ReadFile("C:/Windows/Fonts/arial.ttf");
  ASSERT_FALSE(font.empty()) << "can't read Windows' Arial";
  TestOutOfMemory(font);
  for (const auto& path : gExtraFonts) {
    TestOutOfMemory(ReadFile(path));
  }
}

TEST(Existing_MsdfFontSafety, ModLimits)
{
  const Bytes font = ReadFile("C:/Windows/Fonts/arial.ttf");
  ASSERT_FALSE(font.empty()) << "can't read Windows' Arial";
  TestModLimits(font);
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  if (argc > 1) {
    gFolder = argv[1];
  }
  for (int i = 2; i < argc; ++i) {
    gExtraFonts.push_back(argv[i]);
  }
  return RUN_ALL_TESTS();
}
