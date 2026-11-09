#pragma once

#include <array>
#include <cstdint>

// Engine addition, server mode: quantisation of view-frame fields (plan §7.2, WP7.3).
// Frames hold the quantised integers, never floats, so a decoded frame equals the encoded
// one exactly (WPR.38) and only the conversion back to floats for display is lossy. Values
// the UI shows as numbers (health, fuel, progress, shield) are not quantised: they travel as
// exact float bits.

namespace faf::remote::wire
{
  /** One axis: `value = minValue + q * step`, `q` in `[0, 2^bits)`. */
  struct SAxisQuantizer
  {
    float minValue = 0.0f;
    float step = 1.0f;
    int bits = 16;

    /** Clamped to the range; NaN maps to 0. */
    [[nodiscard]] std::uint32_t Encode(float value) const noexcept;
    [[nodiscard]] float Decode(std::uint32_t quantized) const noexcept;
    [[nodiscard]] std::uint32_t MaxQuantized() const noexcept { return (1u << bits) - 1u; }
  };

  /** World positions: x and z over the map plus a margin, y over terrain and flight heights. */
  struct SPositionQuantizer
  {
    SAxisQuantizer x;
    SAxisQuantizer y;
    SAxisQuantizer z;

    /** Map size in world units (ogrids); 1/64 unit steps; 256 units of margin on x and z. */
    [[nodiscard]] static SPositionQuantizer ForMap(float sizeX, float sizeZ) noexcept;
  };

  /** Quantised position, as the frame stores it. */
  using QuantizedPosition = std::array<std::uint32_t, 3>;

  /**
   * Smallest-three quaternion packing: 2 bits for the index of the largest component, then
   * the other three, each in `[-1/sqrt(2), 1/sqrt(2)]`, in 10 bits. 32 bits in all. The
   * sign is chosen so the largest component is positive (q and -q are one rotation).
   * Components are in the caller's order; the frame does not interpret them.
   */
  [[nodiscard]] std::uint32_t PackQuaternion(const std::array<float, 4>& q) noexcept;
  [[nodiscard]] std::array<float, 4> UnpackQuaternion(std::uint32_t packed) noexcept;

  /**
   * Ground units mostly turn about the vertical axis only: (x, y, z, w) with x and z zero,
   * y = sin(yaw / 2), w = cos(yaw / 2). Such a rotation travels as a 16-bit yaw (§7.2, 2 bytes).
   * The server decides once, from the sim's quaternion; the client only turns the yaw back
   * into a quaternion for display, so no rounding of either step reaches a frame.
   */
  [[nodiscard]] bool IsYawOnly(const std::array<float, 4>& q) noexcept;
  /** The yaw of a yaw-only (x, y, z, w) quaternion in 1/65536 turns. */
  [[nodiscard]] std::uint32_t QuantizeYaw(const std::array<float, 4>& q) noexcept;
  [[nodiscard]] std::array<float, 4> YawToQuaternion(std::uint32_t yaw) noexcept;
} // namespace faf::remote::wire
