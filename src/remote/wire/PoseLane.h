#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <vector>

#include "remote/wire/BitStream.h"

// Engine addition, server mode (plan WP8.1, research/WP8-pose-lane.md): the pose lane of a server's view. For the
// units the player's client holds, their animation bones: every bone of a unit new to the client (or whose skeleton
// changed), then each beat the bones that moved past the tolerance.
//
// A bone is quantised (`QuantizeBone`): its local position in steps of 1/2048 (half of M0.3's 0.001 tolerance),
// each quaternion component in steps of 1/16384, and two flags. A whole unit's bones go as these values; a changed
// bone as its difference from the value its client holds (every client that held the unit since holds the same:
// the server's last sent), so a bone that moved a little costs a byte a component.
//
// Lane: varuint unit count; per unit, in ascending id order: varuint id step from the previous (the first from 0),
// 1 bit whole; whole: varuint bone count, then every bone in index order; else varuint bone count, then per bone a
// varuint index step from the previous (+1, the first from 0) and the bone's difference. A bone: 7 zigzag varuints
// (position x, y, z, rotation x, y, z, w), then 1 bit visible and 1 bit skip interpolation (whole: their values;
// a difference: their new values too).

namespace faf::remote::wire
{
  inline constexpr float kPosePositionSteps = 2048.0f;  // per unit of local position
  inline constexpr float kPoseRotationSteps = 16384.0f; // per unit of a quaternion component

  /** A quantised bone, or (in a changed unit) its difference from the client's. */
  struct SPoseBone
  {
    std::array<std::int32_t, 3> position{};
    std::array<std::int32_t, 4> rotation{0, 0, 0, static_cast<std::int32_t>(kPoseRotationSteps)};
    bool visible = true;
    bool skipInterp = false;

    [[nodiscard]] bool operator==(const SPoseBone&) const noexcept = default;
  };

  /** A bone's local transform and flags, quantised. */
  [[nodiscard]] SPoseBone QuantizeBone(const float position[3], const float rotation[4], bool visible, bool skipInterp) noexcept;
  /** The values back (the quaternion normalised). */
  void DequantizeBone(const SPoseBone& bone, float position[3], float rotation[4]) noexcept;

  struct SUnitPose
  {
    static constexpr std::uint32_t kMaxBones = 1024;

    std::uint32_t id = 0;
    bool whole = false;
    std::vector<std::uint16_t> indices; // without `whole`: the bones that go, ascending
    std::vector<SPoseBone> bones;       // `whole`: every bone's values; else one difference per index

    [[nodiscard]] bool operator==(const SUnitPose&) const noexcept = default;
  };

  inline constexpr std::uint32_t kMaxPoseUnits = 1u << 16;

  /** `units` in ascending id order; false (nothing to trust in `out`) on a malformed one. */
  [[nodiscard]] bool EncodePoseLane(std::span<const SUnitPose> units, BitWriter& out);
  [[nodiscard]] bool DecodePoseLane(BitReader& in, std::vector<SUnitPose>& out);
} // namespace faf::remote::wire
