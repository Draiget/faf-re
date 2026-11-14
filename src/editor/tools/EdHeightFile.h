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
   * words, square or of `expectWidth` x `expectHeight`; `.r32` 32-bit floats (0..1 spread over the 16 bits, or game
   * units when any is above 1); anything else (PNG, BMP, TIFF, ...) is read
   * through the Windows imaging component as 16-bit grey (an 8-bit image's values spread over 16 bits).
   */
  bool ReadHeightImage(
    const std::filesystem::path& file,
    int expectWidth,
    int expectHeight,
    HeightImage& out,
    std::string& error
  );

  /** Writes a 32-bit BGRA picture (B in the low byte) as a PNG; false with `error`. */
  bool WriteColourPng(
    const std::filesystem::path& file,
    int width,
    int height,
    const std::vector<std::uint32_t>& bgra,
    std::string& error
  );
  /**
   * Writes a height image by its extension: `.raw` / `.r16` as 16-bit little-endian words, `.r32` as 32-bit floats
   * (0..1, as Gaea and World Machine read them), `.png` and `.tif` / `.tiff` as 16-bit grey, or 8-bit grey with
   * `eightBit` (FAF Studio's PNG 8 for tools that take only 8 bits).
   */
  bool WriteHeightImage(
    const std::filesystem::path& file,
    const HeightImage& image,
    std::string& error,
    bool eightBit = false
  );

  /** How ResampleHeights reads between samples (FAF Studio's img_resample filters). */
  enum class ResampleFilter
  {
    Bilinear,
    Nearest,
    Bicubic,
    Lanczos3,
  };
  [[nodiscard]] const char* ResampleFilterName(ResampleFilter filter) noexcept;

  /** The image resampled to `width` x `height` samples, read between samples; corners map to corners. */
  HeightImage
  ResampleHeights(const HeightImage& image, int width, int height, ResampleFilter filter = ResampleFilter::Bilinear);

  /** Every height times `scale`, kept within 0..65535. */
  void ScaleHeights(HeightImage& image, float scale);
} // namespace faf::editor
