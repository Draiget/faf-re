#include "remote/wire/PoseLane.h"

// Engine addition, server mode: see PoseLane.h.

namespace faf::remote::wire
{
  namespace
  {
    [[nodiscard]] bool ReadPoseBone(BitReader& in, SPoseBone& bone)
    {
      for (float& value : bone.position) {
        value = in.ReadFloatExact();
      }
      for (float& value : bone.rotation) {
        value = in.ReadFloatExact();
      }
      bone.visible = in.ReadBool();
      bone.skipInterp = in.ReadBool();
      return in.Ok();
    }
  } // namespace

  void WritePoseBone(const SPoseBone& bone, BitWriter& out)
  {
    for (const float value : bone.position) {
      out.WriteFloatExact(value);
    }
    for (const float value : bone.rotation) {
      out.WriteFloatExact(value);
    }
    out.WriteBool(bone.visible);
    out.WriteBool(bone.skipInterp);
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
        WritePoseBone(unit.bones[i], out);
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
        if (!ReadPoseBone(in, unit.bones[b])) {
          return false;
        }
      }
    }
    return in.Ok();
  }
} // namespace faf::remote::wire
