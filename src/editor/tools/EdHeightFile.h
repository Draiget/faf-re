#pragma once

#include <cstdint>
#include <expected>
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
  [[nodiscard]] std::expected<HeightImage, std::string>
  ReadHeightImage(const std::filesystem::path& file, int expectWidth, int expectHeight);

  /** How an import reads its file (FAF Studio's import options): an image's channel, a raw file's layout. */
  struct HeightReadOptions
  {
    int channel = 0; // 0 grey (the image as it is), 1 red, 2 green, 3 blue, 4 alpha
    // A .raw / .r16 / .r32 file: its sample size, float or whole numbers, byte order, its size (0: square / the map's).
    int rawBits = 16; // 8, 16 or 32
    bool rawFloat = false;
    bool bigEndian = false;
    int rawWidth = 0;
    int rawHeight = 0;
  };
  /** ReadHeightImage with those options (the defaults read as ReadHeightImage does). */
  [[nodiscard]] std::expected<HeightImage, std::string> ReadHeightImageWith(
    const std::filesystem::path& file,
    int expectWidth,
    int expectHeight,
    const HeightReadOptions& options
  );

  /** Writes a 32-bit BGRA picture (B in the low byte) as a PNG; the error when it can't. */
  [[nodiscard]] std::expected<void, std::string>
  WriteColourPng(const std::filesystem::path& file, int width, int height, const std::vector<std::uint32_t>& bgra);
  /**
   * Writes a height image by its extension: `.raw` / `.r16` as 16-bit little-endian words, `.r32` as 32-bit floats
   * (0..1, as Gaea and World Machine read them), `.png` and `.tif` / `.tiff` as 16-bit grey, or 8-bit grey with
   * `eightBit` (FAF Studio's PNG 8 for tools that take only 8 bits).
   */
  [[nodiscard]] std::expected<void, std::string>
  WriteHeightImage(const std::filesystem::path& file, const HeightImage& image, bool eightBit = false);
  /**
   * Writes floats as they are (FAF Studio's 32-bit float export): `.r32` as raw little-endian floats, `.tif` / `.tiff`
   * as a 32-bit float grey TIFF. `values` row by row, `width` x `height`.
   */
  [[nodiscard]] std::expected<void, std::string>
  WriteFloatImage(const std::filesystem::path& file, int width, int height, const std::vector<float>& values);

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
