#include "remote/wire/Quantize.h"

#include <cmath>

// Engine addition, server mode: see Quantize.h. Display-side code only: nothing here is
// reachable from sim code, so the platform maths it uses cannot change sim results (I2b).

namespace faf::remote::wire
{
  namespace
  {
    constexpr float kPositionStep = 1.0f / 64.0f;
    constexpr float kPositionMargin = 256.0f;
    constexpr float kHeightMin = -256.0f;
    constexpr int kHeightBits = 16; // 1024 units of height at 1/64

    constexpr int kQuaternionComponentBits = 10;
    constexpr float kQuaternionComponentLimit = 0.70710678f;

    [[nodiscard]] int BitsForSpan(const float span, const float step) noexcept
    {
      int bits = 1;
      while (bits < 32 && static_cast<double>(1u << bits) * step < span) {
        ++bits;
      }
      return bits;
    }
  } // namespace

  std::uint32_t SAxisQuantizer::Encode(const float value) const noexcept
  {
    if (!(value == value)) {
      return 0u;
    }
    const double scaled = std::floor((static_cast<double>(value) - minValue) / step + 0.5);
    if (scaled <= 0.0) {
      return 0u;
    }
    const double maxQuantized = static_cast<double>(MaxQuantized());
    return scaled >= maxQuantized ? MaxQuantized() : static_cast<std::uint32_t>(scaled);
  }

  float SAxisQuantizer::Decode(const std::uint32_t quantized) const noexcept
  {
    const std::uint32_t clamped = quantized > MaxQuantized() ? MaxQuantized() : quantized;
    return static_cast<float>(static_cast<double>(minValue) + static_cast<double>(clamped) * step);
  }

  SPositionQuantizer SPositionQuantizer::ForMap(const float sizeX, const float sizeZ) noexcept
  {
    SPositionQuantizer quantizer{};
    quantizer.x = {-kPositionMargin, kPositionStep, BitsForSpan(sizeX + 2.0f * kPositionMargin, kPositionStep)};
    quantizer.z = {-kPositionMargin, kPositionStep, BitsForSpan(sizeZ + 2.0f * kPositionMargin, kPositionStep)};
    quantizer.y = {kHeightMin, kPositionStep, kHeightBits};
    return quantizer;
  }

  std::uint32_t PackQuaternion(const std::array<float, 4>& q) noexcept
  {
    int largest = 0;
    for (int i = 1; i < 4; ++i) {
      if (std::fabs(q[i]) > std::fabs(q[largest])) {
        largest = i;
      }
    }
    const float sign = q[largest] < 0.0f ? -1.0f : 1.0f;
    const SAxisQuantizer component{
      -kQuaternionComponentLimit, 2.0f * kQuaternionComponentLimit / ((1 << kQuaternionComponentBits) - 1),
      kQuaternionComponentBits
    };
    std::uint32_t packed = static_cast<std::uint32_t>(largest);
    int shift = 2;
    for (int i = 0; i < 4; ++i) {
      if (i == largest) {
        continue;
      }
      packed |= component.Encode(q[i] * sign) << shift;
      shift += kQuaternionComponentBits;
    }
    return packed;
  }

  std::array<float, 4> UnpackQuaternion(const std::uint32_t packed) noexcept
  {
    const SAxisQuantizer component{
      -kQuaternionComponentLimit, 2.0f * kQuaternionComponentLimit / ((1 << kQuaternionComponentBits) - 1),
      kQuaternionComponentBits
    };
    const int largest = static_cast<int>(packed & 3u);
    std::array<float, 4> q{};
    float sumSquares = 0.0f;
    int shift = 2;
    for (int i = 0; i < 4; ++i) {
      if (i == largest) {
        continue;
      }
      q[i] = component.Decode((packed >> shift) & ((1u << kQuaternionComponentBits) - 1u));
      sumSquares += q[i] * q[i];
      shift += kQuaternionComponentBits;
    }
    q[largest] = std::sqrt(sumSquares < 1.0f ? 1.0f - sumSquares : 0.0f);
    return q;
  }
} // namespace faf::remote::wire
