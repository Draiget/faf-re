#include "remote/wire/PoseLane.h"

#include <cmath>
#include <limits>

// Engine addition, server mode: see PoseLane.h.

namespace faf::remote::wire
{
  namespace
  {
    [[nodiscard]] std::uint32_t ZigZag(const std::int32_t value) noexcept
    {
      return (static_cast<std::uint32_t>(value) << 1) ^ static_cast<std::uint32_t>(value >> 31);
    }

    [[nodiscard]] std::int32_t UnZigZag(const std::uint32_t value) noexcept
    {
      return static_cast<std::int32_t>(value >> 1) ^ -static_cast<std::int32_t>(value & 1u);
    }

    /** `value * steps` rounded, clamped to a range a zigzag varuint holds (and NaN to 0). */
    [[nodiscard]] std::int32_t Quantize(const float value, const float steps) noexcept
    {
      const double scaled = static_cast<double>(value) * steps;
      if (!(scaled == scaled)) {
        return 0;
      }
      constexpr double kLimit = static_cast<double>(1 << 30);
      return static_cast<std::int32_t>(std::llround(scaled < -kLimit ? -kLimit : (scaled > kLimit ? kLimit : scaled)));
    }

    void WriteBone(const SPoseBone& bone, BitWriter& out)
    {
      for (const std::int32_t value : bone.position) {
        out.WriteVarUint(ZigZag(value));
      }
      for (const std::int32_t value : bone.rotation) {
        out.WriteVarUint(ZigZag(value));
      }
      out.WriteBool(bone.visible);
      out.WriteBool(bone.skipInterp);
    }

    [[nodiscard]] bool ReadBone(BitReader& in, SPoseBone& bone)
    {
      for (std::int32_t& value : bone.position) {
        value = UnZigZag(in.ReadVarUint());
      }
      for (std::int32_t& value : bone.rotation) {
        value = UnZigZag(in.ReadVarUint());
      }
      bone.visible = in.ReadBool();
      bone.skipInterp = in.ReadBool();
      return in.Ok();
    }
  } // namespace

  SPoseBone QuantizeBone(const float position[3], const float rotation[4], const bool visible, const bool skipInterp) noexcept
  {
    SPoseBone bone;
    for (std::size_t i = 0; i < 3; ++i) {
      bone.position[i] = Quantize(position[i], kPosePositionSteps);
    }
    for (std::size_t i = 0; i < 4; ++i) {
      bone.rotation[i] = Quantize(rotation[i], kPoseRotationSteps);
    }
    bone.visible = visible;
    bone.skipInterp = skipInterp;
    return bone;
  }

  void DequantizeBone(const SPoseBone& bone, float position[3], float rotation[4]) noexcept
  {
    for (std::size_t i = 0; i < 3; ++i) {
      position[i] = static_cast<float>(bone.position[i]) / kPosePositionSteps;
    }
    float length = 0.0f;
    for (std::size_t i = 0; i < 4; ++i) {
      rotation[i] = static_cast<float>(bone.rotation[i]) / kPoseRotationSteps;
      length += rotation[i] * rotation[i];
    }
    if (length > 0.0f) {
      const float scale = 1.0f / std::sqrt(length);
      for (std::size_t i = 0; i < 4; ++i) {
        rotation[i] *= scale;
      }
    } else {
      rotation[0] = rotation[1] = rotation[2] = 0.0f;
      rotation[3] = 1.0f;
    }
  }

  bool EncodePoseLane(const std::span<const SUnitPose> units, BitWriter& out)
  {
    if (units.size() > kMaxPoseUnits) {
      return false;
    }
    out.WriteVarUint(static_cast<std::uint32_t>(units.size()));
    std::uint32_t lastId = 0;
    bool first = true;
    for (const SUnitPose& unit : units) {
      if ((!first && unit.id <= lastId) || unit.bones.size() > SUnitPose::kMaxBones
          || (!unit.whole && unit.indices.size() != unit.bones.size())) {
        return false;
      }
      out.WriteVarUint(first ? unit.id : unit.id - lastId);
      lastId = unit.id;
      first = false;
      out.WriteBool(unit.whole);
      out.WriteVarUint(static_cast<std::uint32_t>(unit.bones.size()));
      std::uint32_t next = 0; // the index a step of 0 names
      for (std::size_t i = 0; i < unit.bones.size(); ++i) {
        if (!unit.whole) {
          if (unit.indices[i] < next) {
            return false;
          }
          out.WriteVarUint(unit.indices[i] - next);
          next = static_cast<std::uint32_t>(unit.indices[i]) + 1u;
        }
        WriteBone(unit.bones[i], out);
      }
    }
    return true;
  }

  bool DecodePoseLane(BitReader& in, std::vector<SUnitPose>& out)
  {
    out.clear();
    const std::uint32_t count = in.ReadVarUint();
    if (!in.Ok() || count > kMaxPoseUnits) {
      return false;
    }
    out.reserve(count);
    std::uint32_t lastId = 0;
    for (std::uint32_t u = 0; u < count; ++u) {
      SUnitPose& unit = out.emplace_back();
      const std::uint32_t step = in.ReadVarUint();
      if (u != 0u && step == 0u) {
        return false;
      }
      unit.id = u == 0u ? step : lastId + step;
      if (u != 0u && unit.id <= lastId) {
        return false; // wrapped
      }
      lastId = unit.id;
      unit.whole = in.ReadBool();
      const std::uint32_t bones = in.ReadVarUint();
      if (!in.Ok() || bones > SUnitPose::kMaxBones) {
        return false;
      }
      unit.bones.resize(bones);
      std::uint32_t next = 0;
      for (std::uint32_t b = 0; b < bones; ++b) {
        if (!unit.whole) {
          const std::uint32_t index = next + in.ReadVarUint();
          if (!in.Ok() || index >= SUnitPose::kMaxBones) {
            return false;
          }
          unit.indices.push_back(static_cast<std::uint16_t>(index));
          next = index + 1u;
        }
        if (!ReadBone(in, unit.bones[b])) {
          return false;
        }
      }
    }
    return in.Ok();
  }
} // namespace faf::remote::wire
