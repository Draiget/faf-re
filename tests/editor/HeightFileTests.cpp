// The map editor's height images (src/editor/tools/EdHeightFile.cpp): .raw, .r16 and 16-bit PNG read back
// exactly as written, a map-sized raw that isn't square is read at the map's size, and resampling keeps the
// corners and scales the heights.

#include "editor/tools/EdHeightFile.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <random>
#include <string>

namespace
{
  using faf::editor::HeightImage;
  using faf::editor::ReadHeightImage;
  using faf::editor::ResampleHeights;
  using faf::editor::ScaleHeights;
  using faf::editor::WriteHeightImage;

  HeightImage Random(const int width, const int height, const unsigned seed)
  {
    HeightImage image;
    image.width = width;
    image.height = height;
    std::mt19937 random(seed);
    std::uniform_int_distribution<int> word(0, 65535);
    image.words.resize(static_cast<std::size_t>(width) * static_cast<std::size_t>(height));
    for (std::uint16_t& value : image.words) {
      value = static_cast<std::uint16_t>(word(random));
    }
    return image;
  }

  std::filesystem::path TempFile(const char* const name)
  {
    const std::filesystem::path folder = std::filesystem::temp_directory_path() / "faf_editor_height_tests";
    std::filesystem::create_directories(folder);
    return folder / name;
  }

  class EveryFormat : public ::testing::TestWithParam<const char*>
  {};

  TEST_P(EveryFormat, ReadsBackWhatItWrote)
  {
    const HeightImage written = Random(65, 65, 3u);
    const std::filesystem::path file = TempFile(GetParam());
    std::string error;
    ASSERT_TRUE(WriteHeightImage(file, written, error)) << error;
    HeightImage read;
    ASSERT_TRUE(ReadHeightImage(file, 0, 0, read, error)) << error;
    EXPECT_EQ(read.width, 65);
    EXPECT_EQ(read.height, 65);
    EXPECT_EQ(read.words, written.words);
  }

  INSTANTIATE_TEST_SUITE_P(HeightFile, EveryFormat, ::testing::Values("heights.raw", "heights.r16", "heights.png"));

  TEST(HeightFile, RawOfTheMapsSizeNeedNotBeSquare)
  {
    const HeightImage written = Random(129, 65, 4u);
    const std::filesystem::path file = TempFile("wide.raw");
    std::string error;
    ASSERT_TRUE(WriteHeightImage(file, written, error)) << error;
    HeightImage read;
    EXPECT_FALSE(ReadHeightImage(file, 0, 0, read, error));
    ASSERT_TRUE(ReadHeightImage(file, 129, 65, read, error)) << error;
    EXPECT_EQ(read.words, written.words);
  }

  TEST(HeightFile, ResampleKeepsCornersAndScaleMultiplies)
  {
    HeightImage image = Random(33, 33, 5u);
    const HeightImage bigger = ResampleHeights(image, 65, 65);
    EXPECT_EQ(bigger.words.front(), image.words.front());
    EXPECT_EQ(bigger.words.back(), image.words.back());
    // Every second sample of the bigger grid is a sample of the smaller one.
    EXPECT_EQ(bigger.words[static_cast<std::size_t>(2 * 65 + 2)], image.words[static_cast<std::size_t>(1 * 33 + 1)]);
    image.words[0] = 1000;
    ScaleHeights(image, 2.5f);
    EXPECT_EQ(image.words[0], 2500);
  }
} // namespace
