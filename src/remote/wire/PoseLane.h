#pragma once

#include <array>
#include <cstdint>
#include <span>
#include <vector>

#include "remote/wire/BitStream.h"

// Engine addition, server mode (plan WP8.1, research/WP8-pose-lane.md): the pose lane of a server's view. For the
// units the player's client holds, their animation bones: every bone of a unit new to the client (or whose skeleton
// changed), then each beat the bones that moved past the tolerance. Each bone's local transform goes whole (not a
// delta), so a client that got a unit's bones from either source holds the same values.
//
// Lane: varuint unit count; per unit, in ascending id order: varuint id step from the previous (the first from 0),
// 1 bit whole; whole: varuint bone count, then every bone in index order; else varuint bone count, then per bone a
// varuint index step from the previous (+1, the first from 0) and the bone. A bone: position 3 floats, rotation 4
// floats (x, y, z, w), 1 bit visible, 1 bit skip interpolation.

namespace faf::remote::wire
{
  struct SPoseBone
  {
    std::array<float, 3> position{};
    std::array<float, 4> rotation{0.0f, 0.0f, 0.0f, 1.0f};
    bool visible = true;
    bool skipInterp = false;

    [[nodiscard]] bool operator==(const SPoseBone&) const noexcept = default;
  };

  struct SUnitPose
  {
    static constexpr std::uint32_t kMaxBones = 1024;

    std::uint32_t id = 0;
    bool whole = false;
    std::vector<std::uint16_t> indices; // without `whole`: the bones that go, ascending
    std::vector<SPoseBone> bones;       // `whole`: every bone; else one per index

    [[nodiscard]] bool operator==(const SUnitPose&) const noexcept = default;
  };

  inline constexpr std::uint32_t kMaxPoseUnits = 1u << 16;

  /** `units` in ascending id order; false (nothing to trust in `out`) on a malformed one. */
  [[nodiscard]] bool EncodePoseLane(std::span<const SUnitPose> units, BitWriter& out);
  [[nodiscard]] bool DecodePoseLane(BitReader& in, std::vector<SUnitPose>& out);

  /** One bone as the lane writes it. */
  void WritePoseBone(const SPoseBone& bone, BitWriter& out);
} // namespace faf::remote::wire
