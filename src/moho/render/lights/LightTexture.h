#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

// CPU colour of an effect texture, for lights whose colour has to match what the effect draws (docs/DYNAMIC_LIGHTS.md,
// "Colour").
//
// The engine keeps no pixels of its textures (the GPU copy is made and the file bytes are dropped), so this reads the
// DDS file itself: the top mip that fits `maxDim`, DXT1/3/5 or an uncompressed 16/24/32-bit surface, decoded to RGBA8.
// Pure functions on a byte buffer, no engine headers: the host test feeds it synthetic files.
namespace moho::lights
{
  struct Rgba8Image
  {
    std::uint32_t width = 0;
    std::uint32_t height = 0;
    std::vector<std::uint8_t> rgba; // width * height * 4, row-major, R G B A
  };

  // Decodes the largest mip of a DDS file whose sides are both <= maxDim (the smallest mip when none is). False for a
  // file this reader does not handle (cube maps, volumes, other formats, a truncated file); `out` is then empty.
  bool DecodeDds(const std::uint8_t* data, std::size_t size, std::uint32_t maxDim, Rgba8Image& out);

  struct TextureColour
  {
    bool valid = false;
    float hue[3] = {
      1.0f,
      1.0f,
      1.0f
    }; // the colour the texture glows in, brightest channel = 1 (brightness-weighted mean of the texels)
    float brightness = 0.0f; // mean of alpha x luminance over the whole texture, 0..1: how much of the quad glows
    float peak = 0.0f;       // the brightest alpha x luminance, 0..1
    float alpha = 0.0f;      // mean alpha, 0..1
    float average[3] = {
      1.0f,
      1.0f,
      1.0f
    }; // alpha-weighted mean colour of all texels (not luminance-weighted: the halo counts as much as the core)
    float tint[3] = {
      1.0f,
      1.0f,
      1.0f
    }; // `average` with the white taken out (ReduceWhite), brightest channel = 1: the colour the light has
  };

  // Takes the white out of a colour: subtracts `amount` x the smallest channel from every channel and scales the result
  // so the largest channel keeps its old value. A glow texture is white-hot in the middle and coloured at the edge; its
  // mean colour is pale, the light should have the colour of the edge. amount 0 returns the colour unchanged, 1 removes
  // all the white. White stays white.
  void ReduceWhite(float (&rgb)[3], float amount);

  TextureColour Summarise(const Rgba8Image& image);

  // The ramp texture of a particle: U is the age 0..1, V the row the emitter picked (0..1). Clamped, nearest row,
  // linear between columns. rgba in 0..1, not premultiplied.
  void SampleRamp(const Rgba8Image& ramp, float u, float v, float (&rgba)[4]);
} // namespace moho::lights
