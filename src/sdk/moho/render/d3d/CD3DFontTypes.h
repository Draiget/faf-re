#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "moho/render/textures/CD3DBatchTexture.h"

namespace moho
{
  /**
   * Address: 0x00425940 (FUN_00425940, Moho::CD3DFont::GetCharInfo)
   *
   * What it does:
   * Stores one baked glyph texture plus per-glyph axis extents and advance data
   * consumed by prim-batcher text draw paths.
   */
  struct CD3DFontCharInfo
  {
    boost::shared_ptr<CD3DBatchTexture> mTex; // +0x00
    float mV2 = 0.0f;                         // +0x08
    float mV3 = 0.0f;                         // +0x0C
    float mV4 = 0.0f;                         // +0x10
    float mV5 = 0.0f;                         // +0x14
    float mAdvance = 0.0f;                    // +0x18
    std::uint32_t mUnknown1C = 0;             // +0x1C
    std::uint32_t mUnknown20 = 0;             // +0x20
  };

  static_assert(sizeof(CD3DFontCharInfo) == 0x24, "moho::CD3DFontCharInfo size must be 0x24");
  static_assert(offsetof(CD3DFontCharInfo, mTex) == 0x00, "moho::CD3DFontCharInfo::mTex offset must be 0x00");
  static_assert(offsetof(CD3DFontCharInfo, mV2) == 0x08, "moho::CD3DFontCharInfo::mV2 offset must be 0x08");
  static_assert(offsetof(CD3DFontCharInfo, mV3) == 0x0C, "moho::CD3DFontCharInfo::mV3 offset must be 0x0C");
  static_assert(offsetof(CD3DFontCharInfo, mV4) == 0x10, "moho::CD3DFontCharInfo::mV4 offset must be 0x10");
  static_assert(offsetof(CD3DFontCharInfo, mV5) == 0x14, "moho::CD3DFontCharInfo::mV5 offset must be 0x14");
  static_assert(
    offsetof(CD3DFontCharInfo, mAdvance) == 0x18, "moho::CD3DFontCharInfo::mAdvance offset must be 0x18"
  );
} // namespace moho
