#pragma once

// Engine addition (in-game launcher, WP5): pictures the UI draws for itself at runtime, so no image files have to be
// shipped: icons from SVG drawings (the launcher's set is Lucide's, as the FAF Rust client uses), rounded boxes and
// their corners, and any image file the engine fetched (map previews). Each is kept in memory as PNG bytes under a
// path starting with kMemoryPrefix; a Bitmap takes that path like any texture file (CD3DBatchTexture::FromFile looks
// here before the file system).

#include <cstdint>
#include <expected>
#include <memory>
#include <string>
#include <string_view>
#include <vector>

namespace moho::uiart
{
  /** Paths under this prefix are images kept in memory (RegisterImage), not files. */
  inline constexpr std::string_view kMemoryPrefix = "/fafengine-mem/";

  struct Rgba
  {
    std::uint8_t r = 255;
    std::uint8_t g = 255;
    std::uint8_t b = 255;
    std::uint8_t a = 255;
  };

  /** "AARRGGBB" or "RRGGBB" in hex, as the UI writes colours. False when the text is neither. */
  [[nodiscard]] bool ParseColor(std::string_view text, Rgba& out);

  /** Straight (not premultiplied) RGBA, 4 bytes a pixel, rows from the top. */
  struct Image
  {
    int width = 0;
    int height = 0;
    std::vector<std::uint8_t> rgba;
  };

  /**
   * An icon from SVG elements drawn on a square grid of `viewBox` units (Lucide's is 24), stroked `strokeWidth` grid
   * units wide with round ends and joins, `size` pixels square, in one colour. Elements: path (M L H V C S Q T A Z,
   * absolute and relative), circle, ellipse, rect (with rx/ry), line, polyline, polygon. A `fill` other than "none"
   * fills the shape as well. Unknown elements and attributes are skipped.
   */
  [[nodiscard]] std::expected<Image, std::string>
  DrawIcon(std::string_view elements, int size, Rgba color, float strokeWidth = 2.0f, float viewBox = 24.0f);

  /** A box `width` x `height` with corners of `radius`, filled, with a border `borderWidth` wide inside its edge. */
  [[nodiscard]] Image DrawRoundedRect(int width, int height, float radius, Rgba fill, Rgba border, float borderWidth);

  /**
   * One corner of a rounded box, `radius` x `radius` pixels: 0 top left, 1 top right, 2 bottom right, 3 bottom left.
   * Four of them and straight edges make a box of any size.
   */
  [[nodiscard]] Image DrawCorner(int corner, int radius, Rgba fill, Rgba border, float borderWidth);

  /** PNG bytes (8-bit RGBA, deflated) of `image`. */
  [[nodiscard]] std::vector<std::uint8_t> EncodePng(const Image& image);

  /** Keeps `bytes` (an image file's) under `path`, which starts with kMemoryPrefix, for the texture loader. */
  void RegisterImage(const std::string& path, std::vector<std::uint8_t> bytes);

  /** The bytes kept under `path` (case-insensitive), or null. */
  [[nodiscard]] std::shared_ptr<const std::vector<std::uint8_t>> FindImage(std::string_view path);

  /** True for a path under kMemoryPrefix. */
  [[nodiscard]] bool IsMemoryPath(std::string_view path);
} // namespace moho::uiart
