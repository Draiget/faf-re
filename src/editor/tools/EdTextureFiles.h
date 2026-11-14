#pragma once

#include <cstdint>
#include <filesystem>
#include <vector>

namespace faf::editor
{
  /**
   * A normal map's pixels (0xAARRGGBB) turned into a grey relief lit from the north-west (FAF Studio's
   * normalpreview.lua): bumps read as bumps, which the raw blue-purple picture hides. Normal maps whose red is flat and
   * alpha varies keep x in alpha (the DXT5 packing); the others in red. y is green.
   */
  void NormalRelief(std::vector<std::uint32_t>& pixels);

  /** The eight strata masks as one set of files: `<base>_1<ext>` .. `<base>_8<ext>` beside `file`. */
  [[nodiscard]] std::filesystem::path MaskSetFile(const std::filesystem::path& file, int layer);
  /** The set's base from one of its files (`masks_3.png` -> `masks.png`; any other name stays). */
  [[nodiscard]] std::filesystem::path MaskSetBase(const std::filesystem::path& file);
} // namespace faf::editor
