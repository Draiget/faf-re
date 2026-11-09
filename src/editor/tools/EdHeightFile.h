#pragma once

#include <cstdint>
#include <filesystem>
#include <string>
#include <vector>

namespace faf::editor
{
  /** A grid of 16-bit heights, row by row (the height field's words: 1/128 of a game unit). */
  struct HeightImage
  {
    int width = 0;
    int height = 0;
    std::vector<std::uint16_t> words;
  };

  /**
   * Reads a height image by its extension: `.raw` and `.r16` (World Machine) are 16-bit little-endian
   * words, square or of `expectWidth` x `expectHeight`; anything else (PNG, BMP, TIFF, ...) is read
   * through the Windows imaging component as 16-bit grey (an 8-bit image's values spread over 16 bits).
   */
  bool ReadHeightImage(const std::filesystem::path& file, int expectWidth, int expectHeight, HeightImage& out, std::string& error);

  /** Writes a height image by its extension: `.raw` / `.r16` as 16-bit little-endian words, `.png` as 16-bit grey. */
  bool WriteHeightImage(const std::filesystem::path& file, const HeightImage& image, std::string& error);

  /** The image resampled to `width` x `height` samples, read between samples; corners map to corners. */
  HeightImage ResampleHeights(const HeightImage& image, int width, int height);

  /** Every height times `scale`, kept within 0..65535. */
  void ScaleHeights(HeightImage& image, float scale);
} // namespace faf::editor
