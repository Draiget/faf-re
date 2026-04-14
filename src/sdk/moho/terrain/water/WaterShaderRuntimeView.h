#pragma once

#include <cstddef>
#include <cstdint>

namespace moho
{
  class CWaterShaderProperties;

  /**
   * Recovered shader-parameter payload view for `CWaterShaderProperties`.
   *
   * Offsets are relative to the complete-object base (`this`), including the
   * vtable pointer at `+0x00`.
   */
  struct WaterShaderRuntimeView
  {
    std::uint8_t mUnknown00_03[0x04]; // +0x00

    float mWaterColor[3];             // +0x04
    float mWaterLerp[2];              // +0x10
    float mRefractionScale;           // +0x18
    float mFresnelBias;               // +0x1C
    float mFresnelPower;              // +0x20
    float mUnitReflectionAmount;      // +0x24
    float mSkyReflectionAmount;       // +0x28
    float mNormalRepeatRate[4];       // +0x2C
    float mNormal1Movement[2];        // +0x3C
    float mNormal2Movement[2];        // +0x44
    float mNormal3Movement[2];        // +0x4C
    float mNormal4Movement[2];        // +0x54
    float mSunShininess;              // +0x5C
    float mUnknown60;                 // +0x60
    float mSunDirection[3];           // +0x64
    float mSunColor[3];               // +0x70
    float mSunReflectionAmount;       // +0x7C
    float mSunGlow;                   // +0x80
  };

  static_assert(offsetof(WaterShaderRuntimeView, mWaterColor) == 0x04, "WaterShaderRuntimeView::mWaterColor offset must be 0x04");
  static_assert(offsetof(WaterShaderRuntimeView, mWaterLerp) == 0x10, "WaterShaderRuntimeView::mWaterLerp offset must be 0x10");
  static_assert(
    offsetof(WaterShaderRuntimeView, mRefractionScale) == 0x18,
    "WaterShaderRuntimeView::mRefractionScale offset must be 0x18"
  );
  static_assert(
    offsetof(WaterShaderRuntimeView, mFresnelBias) == 0x1C,
    "WaterShaderRuntimeView::mFresnelBias offset must be 0x1C"
  );
  static_assert(
    offsetof(WaterShaderRuntimeView, mFresnelPower) == 0x20,
    "WaterShaderRuntimeView::mFresnelPower offset must be 0x20"
  );
  static_assert(
    offsetof(WaterShaderRuntimeView, mUnitReflectionAmount) == 0x24,
    "WaterShaderRuntimeView::mUnitReflectionAmount offset must be 0x24"
  );
  static_assert(
    offsetof(WaterShaderRuntimeView, mSkyReflectionAmount) == 0x28,
    "WaterShaderRuntimeView::mSkyReflectionAmount offset must be 0x28"
  );
  static_assert(
    offsetof(WaterShaderRuntimeView, mNormalRepeatRate) == 0x2C,
    "WaterShaderRuntimeView::mNormalRepeatRate offset must be 0x2C"
  );
  static_assert(
    offsetof(WaterShaderRuntimeView, mNormal1Movement) == 0x3C,
    "WaterShaderRuntimeView::mNormal1Movement offset must be 0x3C"
  );
  static_assert(
    offsetof(WaterShaderRuntimeView, mNormal2Movement) == 0x44,
    "WaterShaderRuntimeView::mNormal2Movement offset must be 0x44"
  );
  static_assert(
    offsetof(WaterShaderRuntimeView, mNormal3Movement) == 0x4C,
    "WaterShaderRuntimeView::mNormal3Movement offset must be 0x4C"
  );
  static_assert(
    offsetof(WaterShaderRuntimeView, mNormal4Movement) == 0x54,
    "WaterShaderRuntimeView::mNormal4Movement offset must be 0x54"
  );
  static_assert(
    offsetof(WaterShaderRuntimeView, mSunShininess) == 0x5C,
    "WaterShaderRuntimeView::mSunShininess offset must be 0x5C"
  );
  static_assert(
    offsetof(WaterShaderRuntimeView, mSunDirection) == 0x64,
    "WaterShaderRuntimeView::mSunDirection offset must be 0x64"
  );
  static_assert(offsetof(WaterShaderRuntimeView, mSunColor) == 0x70, "WaterShaderRuntimeView::mSunColor offset must be 0x70");
  static_assert(
    offsetof(WaterShaderRuntimeView, mSunReflectionAmount) == 0x7C,
    "WaterShaderRuntimeView::mSunReflectionAmount offset must be 0x7C"
  );
  static_assert(offsetof(WaterShaderRuntimeView, mSunGlow) == 0x80, "WaterShaderRuntimeView::mSunGlow offset must be 0x80");
  static_assert(sizeof(WaterShaderRuntimeView) == 0x84, "WaterShaderRuntimeView size must be 0x84");

  [[nodiscard]] inline const WaterShaderRuntimeView& AsWaterShaderRuntimeView(
    const CWaterShaderProperties& properties
  ) noexcept
  {
    return *reinterpret_cast<const WaterShaderRuntimeView*>(&properties);
  }
} // namespace moho
