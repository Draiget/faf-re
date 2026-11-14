#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace faf::editor
{
  /** The box of a render's drawn pixels (alpha above 0), inclusive; `empty` when nothing was drawn. */
  struct IconBox
  {
    int x0 = 0;
    int y0 = 0;
    int x1 = -1;
    int y1 = -1;
    bool empty = true;
  };
  [[nodiscard]] IconBox AlphaBox(const std::uint32_t* bgra, int side);

  /**
   * A unit icon from a render of its model (FAF Studio's icon generator, its framing step): the square around the
   * drawn box's centre whose side is the box's longer side over `fill` (the unit fills that much of the icon), each
   * icon pixel the average of the render pixels it covers (alpha-weighted colour, so the edge doesn't go dark). Pixels
   * are 32-bit BGRA (B in the low byte); the result is `out` x `out` RGBA floats 0..1, top row first. Empty when
   * nothing was drawn.
   */
  [[nodiscard]] std::vector<float> IconPixels(const std::uint32_t* bgra, int side, int out, float fill);

  /**
   * Why a render can't be an icon, or "": nothing drawn; drawn edge to edge (the background is opaque, so there is no
   * outline to frame); or so dark (the drawn pixels' mean brightness under `minLight`, 0..1) the build menu would show
   * a black square.
   */
  [[nodiscard]] std::string IconRenderProblem(const std::uint32_t* bgra, int side, float minLight);
} // namespace faf::editor
