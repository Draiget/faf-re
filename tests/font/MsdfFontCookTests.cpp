// Engine addition: the MSDF font cook (issue #306).
//
//   faf_msdf_cook_tests [font file] [--dump <folder>]
//
// Without a font file it uses Windows' Arial. --dump writes each atlas's RGBA bytes and a glyph list,
// for looking at the result outside the engine.

#include <algorithm>
#include <gtest/gtest.h>
#include <chrono>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

#include "moho/render/font/MsdfFontCook.h"

namespace
{
  int gFailures = 0;

  void Check(const bool ok, const char* const what)
  {
    EXPECT_TRUE(ok) << what;
    if (!ok) {
      std::printf("FAIL: %s\n", what);
      ++gFailures;
    }
  }

  std::vector<char> ReadFile(const std::string& path)
  {
    std::ifstream in(path, std::ios::binary);
    return {std::istreambuf_iterator<char>(in), std::istreambuf_iterator<char>()};
  }

  const moho::SMsdfGlyph* FindGlyph(const moho::SMsdfFontAtlas& atlas, const std::uint32_t codepoint)
  {
    const auto it = std::lower_bound(
      atlas.mGlyphs.begin(), atlas.mGlyphs.end(), codepoint,
      [](const moho::SMsdfGlyph& glyph, const std::uint32_t c) { return glyph.mCodepoint < c; }
    );
    return it != atlas.mGlyphs.end() && it->mCodepoint == codepoint ? &*it : nullptr;
  }

  /** The median of the three distance channels, in 0..255: above 127 is inside the glyph. */
  int MedianAt(const moho::SMsdfFontAtlas& atlas, const float x, const float y)
  {
    const auto column = static_cast<std::size_t>(x);
    const auto row = static_cast<std::size_t>(y);
    const std::uint8_t* const texel = atlas.mPixels.data() + (row * static_cast<std::size_t>(atlas.mWidth) + column) * 4u;
    const int r = texel[0];
    const int g = texel[1];
    const int b = texel[2];
    return (std::max)((std::min)(r, g), (std::min)((std::max)(r, g), b));
  }

  void CheckGlyphShapes(const moho::SMsdfFontAtlas& atlas)
  {
    const moho::SMsdfGlyph* const letterI = FindGlyph(atlas, 'I');
    Check(letterI != nullptr, "the atlas has I");
    if (letterI != nullptr) {
      // The middle of an I is ink; the corners of its box are past the outline.
      const float middleX = 0.5f * (letterI->mAtlasLeft + letterI->mAtlasRight);
      const float middleY = 0.5f * (letterI->mAtlasTop + letterI->mAtlasBottom);
      Check(MedianAt(atlas, middleX, middleY) > 127, "the middle of I is inside");
      Check(MedianAt(atlas, letterI->mAtlasLeft, letterI->mAtlasTop) < 127, "the top-left of I's box is outside");
      Check(MedianAt(atlas, letterI->mAtlasRight, letterI->mAtlasBottom) < 127, "the bottom-right of I's box is outside");
    }
    const moho::SMsdfGlyph* const space = FindGlyph(atlas, ' ');
    Check(space != nullptr && space->mAdvance > 0.0f && space->mAtlasRight == 0.0f, "a space advances and has no box");
    const moho::SMsdfGlyph* const letterO = FindGlyph(atlas, 'O');
    Check(letterO != nullptr, "the atlas has O");
    if (letterO != nullptr) {
      // The hole of an O is outside, so the winding is right.
      const float middleX = 0.5f * (letterO->mAtlasLeft + letterO->mAtlasRight);
      const float middleY = 0.5f * (letterO->mAtlasTop + letterO->mAtlasBottom);
      Check(MedianAt(atlas, middleX, middleY) < 127, "the hole of O is outside");
    }
    // A blend of two boxes' texels can have a median near the outline, so empty texels keep them apart.
    for (const moho::SMsdfGlyph& glyph : atlas.mGlyphs) {
      if (glyph.mAtlasRight <= glyph.mAtlasLeft) {
        continue;
      }
      const int left = static_cast<int>(glyph.mAtlasLeft);
      const int top = static_cast<int>(glyph.mAtlasTop);
      const int bottom = static_cast<int>(glyph.mAtlasBottom);
      for (int row = top; left > 0 && row <= bottom; ++row) {
        const std::uint8_t* const texel =
          atlas.mPixels.data() + (static_cast<std::size_t>(row) * static_cast<std::size_t>(atlas.mWidth) + static_cast<std::size_t>(left - 1)) * 4u;
        Check(texel[0] == 0u && texel[1] == 0u && texel[2] == 0u, "the texels left of a box are empty");
      }
    }
    for (const moho::SMsdfGlyph& glyph : atlas.mGlyphs) {
      Check(
        glyph.mAtlasLeft >= 0.0f && glyph.mAtlasRight <= static_cast<float>(atlas.mWidth) && glyph.mAtlasTop >= 0.0f
          && glyph.mAtlasBottom <= static_cast<float>(atlas.mHeight),
        "every glyph is inside the atlas"
      );
    }
  }

  void CheckCache(const moho::SMsdfFontAtlas& atlas)
  {
    const std::vector<std::uint8_t> saved = moho::MSDF_SaveAtlas(atlas);
    Check(!saved.empty(), "an atlas saves");

    moho::SMsdfFontAtlas loaded;
    Check(moho::MSDF_LoadAtlas(saved.data(), saved.size(), loaded), "a saved atlas loads");
    Check(loaded.mPixels == atlas.mPixels, "pixels survive the cache");
    Check(loaded.mGlyphs.size() == atlas.mGlyphs.size(), "glyphs survive the cache");
    Check(loaded.mMissing == atlas.mMissing, "the missing count survives the cache");

    moho::SMsdfFontAtlas refused;
    Check(!moho::MSDF_LoadAtlas(nullptr, 0u, refused), "nothing is refused");
    Check(!moho::MSDF_LoadAtlas(saved.data(), saved.size() / 2u, refused), "a cut-short file is refused");
    std::vector<std::uint8_t> damaged = saved;
    damaged[0] ^= 0xFFu;
    Check(!moho::MSDF_LoadAtlas(damaged.data(), damaged.size(), refused), "a wrong magic is refused");
    damaged = saved;
    damaged[damaged.size() / 2u] ^= 0xFFu;
    damaged[damaged.size() / 2u + 1u] ^= 0xFFu;
    Check(!moho::MSDF_LoadAtlas(damaged.data(), damaged.size(), refused) || refused.mPixels.size() == atlas.mPixels.size(),
      "damaged data is refused, or at least stays in bounds");
    std::printf("cache: %zu bytes packed from %zu\n", saved.size(), atlas.mPixels.size());
  }

  void CheckBadFiles(const std::vector<char>& font)
  {
    moho::SMsdfCookOptions options;
    options.mCodepoints = moho::MSDF_DefaultCodepoints();
    moho::SMsdfFontAtlas atlas;
    std::string error;

    const char notAFont[] = "MZ this is a program, not a font";
    Check(!moho::MSDF_CookFont(notAFont, sizeof(notAFont), options, atlas, error), "a file that isn't a font is refused");
    Check(moho::MSDF_ReadFontNames(notAFont, sizeof(notAFont)).empty(), "a file that isn't a font has no names");
    Check(!moho::MSDF_CookFont(nullptr, 0u, options, atlas, error), "no bytes are refused");

    // Cut short at several points: refused or cooked, but never a crash.
    for (const std::size_t divisor : {2u, 3u, 7u, 50u, 1000u}) {
      (void)moho::MSDF_CookFont(font.data(), font.size() / divisor, options, atlas, error);
    }
    std::printf("cut-short files: no crash\n");

    moho::SMsdfCookOptions small = options;
    small.mMaxAtlasHeight = 256;
    Check(!moho::MSDF_CookFont(font.data(), font.size(), small, atlas, error), "glyphs that don't fit are refused");
  }

  void Dump(const moho::SMsdfFontAtlas& atlas, const std::string& folder)
  {
    std::ofstream pixels(folder + "/atlas.rgba", std::ios::binary);
    pixels.write(reinterpret_cast<const char*>(atlas.mPixels.data()), static_cast<std::streamsize>(atlas.mPixels.size()));
    std::ofstream list(folder + "/atlas.txt");
    list << atlas.mWidth << ' ' << atlas.mHeight << ' ' << atlas.mEmPixels << ' ' << atlas.mDistanceRange << '\n';
    for (const moho::SMsdfGlyph& g : atlas.mGlyphs) {
      list << g.mCodepoint << ' ' << g.mAdvance << ' ' << g.mPlaneLeft << ' ' << g.mPlaneBottom << ' ' << g.mPlaneRight << ' '
           << g.mPlaneTop << ' ' << g.mAtlasLeft << ' ' << g.mAtlasBottom << ' ' << g.mAtlasRight << ' ' << g.mAtlasTop << '\n';
    }
  }
} // namespace

static std::string gFontPath = "C:/Windows/Fonts/arial.ttf";
static std::string gDumpFolder;

TEST(Existing_MsdfFontCook, CookAndValidate)
{
  const std::vector<char> font = ReadFile(gFontPath);
  if (font.empty()) {
    GTEST_SKIP() << "can't read " << gFontPath;
  }

  for (const std::string& name : moho::MSDF_ReadFontNames(font.data(), font.size())) {
    std::printf("name: %s\n", name.c_str());
  }

  moho::SMsdfCookOptions options;
  options.mCodepoints = moho::MSDF_DefaultCodepoints();
  std::string error;

  moho::SMsdfFontAtlas oneThread;
  auto start = std::chrono::steady_clock::now();
  Check(moho::MSDF_CookFont(font.data(), font.size(), options, oneThread, error), error.c_str());
  const auto oneMs = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();

  options.mThreads = 4;
  moho::SMsdfFontAtlas fourThreads;
  start = std::chrono::steady_clock::now();
  Check(moho::MSDF_CookFont(font.data(), font.size(), options, fourThreads, error), error.c_str());
  const auto fourMs = std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::steady_clock::now() - start).count();

  std::printf(
    "%s: %zu glyphs, %u missing, atlas %dx%d, %lld ms on 1 thread, %lld ms on 4\n", gFontPath.c_str(), oneThread.mGlyphs.size(),
    oneThread.mMissing, oneThread.mWidth, oneThread.mHeight, static_cast<long long>(oneMs), static_cast<long long>(fourMs)
  );

  Check(oneThread.mPixels == fourThreads.mPixels, "the thread count doesn't change the pixels");
  CheckGlyphShapes(oneThread);
  CheckCache(oneThread);
  CheckBadFiles(font);
  if (!gDumpFolder.empty()) {
    Dump(oneThread, gDumpFolder);
  }

  EXPECT_EQ(gFailures, 0);
}

int main(int argc, char** argv)
{
  ::testing::InitGoogleTest(&argc, argv);
  for (int i = 1; i < argc; ++i) {
    if (std::strcmp(argv[i], "--dump") == 0 && i + 1 < argc) {
      gDumpFolder = argv[++i];
    } else {
      gFontPath = argv[i];
    }
  }
  return RUN_ALL_TESTS();
}
