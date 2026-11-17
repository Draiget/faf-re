#pragma once

#include <cstdint>
#include <map>
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

  /**
   * One render on black and one on white made into one with its background keyed out (FAF Studio's icon maker): each
   * pixel's alpha is 1 less how much brighter the white render is there, its colour the black render's over that
   * alpha. Then, when the drawn pixels' mean brightness is under `wantLight`, their colour scaled up to it (the
   * game's thumbnail pass draws unlit and dark). 32-bit BGRA in and out.
   */
  [[nodiscard]] std::vector<std::uint32_t>
  KeyedIcon(const std::uint32_t* onBlack, const std::uint32_t* onWhite, int side, float wantLight);

  /**
   * How a made icon compares with the one the game ships (FAF Studio's icongen.lua Compare), both RGBA 0..255 bytes of
   * the same size: the silhouettes' overlap (intersection over union of the pixels with alpha >= 128), the mean colour
   * difference where both are drawn, the mean alpha difference, the difference of the two drawn parts' mean colours
   * (tint), and the mean difference of 8 x 8 blocks (coarse look).
   */
  struct IconMetrics
  {
    float iou = 0.0f;
    int areaA = 0;
    int areaB = 0;
    float colour = 255.0f;
    float alpha = 255.0f;
    float tint = 255.0f;
    float coarse = 255.0f;
  };
  [[nodiscard]] IconMetrics CompareIcons(const std::uint8_t* a, const std::uint8_t* b, int side);

  /**
   * Tone fit (Studio's ToneFit): per faction, what the shipped icons' colours are over the renders' where both are
   * fully drawn and the shipped one isn't near white; gains (r, g, b) once a faction has 200 pixels.
   */
  struct IconToneFit
  {
    struct Sums
    {
      long long n = 0;
      double x[3] = {0, 0, 0};
      double y[3] = {0, 0, 0};
    };
    std::map<std::string, Sums> sums;
    void Add(const std::string& faction, const std::uint8_t* render, const std::uint8_t* shipped, int side);
    /** The faction's gains, or false when it has too few pixels (then `all` factions together, if enough). */
    bool Gains(const std::string& faction, float (&gains)[3]) const;
  };
  /** The colours of RGBA bytes times the gains (alpha kept). */
  void ApplyIconTone(std::vector<std::uint8_t>& rgba, const float (&gains)[3]);
  /**
   * The shipped icons' light edge (FAF Studio's Glow): a white halo round the silhouette, `solid` pixels at `peak`,
   * then fading out over `soft` pixels, the unit over it; pixels it doesn't reach become clear white. `rgba` is
   * `side` x `side` RGBA floats 0..1 (IconPixels'). Nothing when solid and soft are 0.
   */
  void IconLightEdge(std::vector<float>& rgba, int side, float solid, float soft = 3.5f, float peak = 0.65f);
  /**
   * Two icons' silhouettes (alpha from 128) as a picture (FAF Studio's DiffImage): green where both are, red only the
   * first (made), blue only the second (the game's), dark grey neither. RGBA bytes in, BGRA words out.
   */
  [[nodiscard]] std::vector<std::uint32_t>
  IconDifference(const std::uint8_t* made, const std::uint8_t* shipped, int side);
  /** A unit id's faction by its letters (uel / uea / ues / ueb: UEF, ua*: Aeon, ur*: Cybran, xs*: Seraphim); "" none.
   */
  [[nodiscard]] std::string IconFactionOf(const std::string& id);
} // namespace faf::editor
