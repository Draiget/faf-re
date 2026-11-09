#pragma once

// Shared by the faf_gal_tests suites: reading the $Globals image, stand-in textures and render
// targets (the parameter store only keeps the pointers), and one small effect in the D3D10
// dialect that several suites parse, rewrite and compile.

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>

#include "gpg/gal/RenderTarget.hpp"
#include "gpg/gal/Texture.hpp"

namespace faf_gal_tests
{
  [[nodiscard]] float FloatAt(std::span<const std::uint8_t> image, std::size_t offset);
  [[nodiscard]] std::uint32_t WordAt(std::span<const std::uint8_t> image, std::size_t offset);
  [[nodiscard]] std::int32_t IntAt(std::span<const std::uint8_t> image, std::size_t offset);
  [[nodiscard]] std::uint32_t Bits(float value);

  /** Number of non-overlapping occurrences of `needle` in `text`. */
  [[nodiscard]] std::size_t Count(std::string_view text, std::string_view needle);

  class FakeTexture final : public gpg::gal::Texture
  {
  public:
    gpg::gal::TextureContext* GetContext() override { return nullptr; }
    gpg::gal::TextureLockRect Lock(int, const RECT&, int) override { return {}; }
    int Unlock(gpg::gal::TextureLockRect) override { return 0; }
    int Unlock(int) override { return 0; }
    void SaveToBuffer(gpg::MemBuffer<char>*) override {}
  };

  class FakeRenderTarget final : public gpg::gal::RenderTarget
  {
  public:
    gpg::gal::RenderTargetContext* GetContext() override { return nullptr; }
    HDC GetDC() override { return nullptr; }
  };

  /**
   * An effect as the D3D11 override layer hands it on: numeric globals with defaults, two
   * textures read through a 2D and a cube sampler, a vertex shader that writes a global and
   * takes a compile-time argument, a pixel shader that passes a sampler to a helper, and a
   * technique whose passes share and differ in entry points.
   */
  extern const char* const kDrawEffect;

  /**
   * Engine addition (tessellation): an effect whose pass names a hull function returning the edge and inside
   * factors of a 3-point patch and a domain function placing each generated point, as terrain_tess.fx does: the
   * vertex shader only hands its position on, the domain function takes a compile-time argument.
   */
  extern const char* const kTessellatedEffect;
} // namespace faf_gal_tests
