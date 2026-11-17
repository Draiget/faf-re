#include "editor/tools/EdScaAnim.h"

#include <algorithm>
#include <cmath>
#include <cstring>

namespace faf::editor
{
  namespace
  {
    bool U32(
      const std::vector<std::uint8_t>& b,
      const std::size_t at,
      std::uint32_t& out
    )
    {
      if (at + 4 > b.size()) {
        return false;
      }
      std::memcpy(&out, b.data() + at, 4);
      return true;
    }

    bool F32(
      const std::vector<std::uint8_t>& b,
      const std::size_t at,
      float& out
    )
    {
      if (at + 4 > b.size()) {
        return false;
      }
      std::memcpy(&out, b.data() + at, 4);
      return true;
    }

    bool Key(
      const std::vector<std::uint8_t>& b,
      const std::size_t at,
      const int version,
      ScaKey& out
    )
    {
      float v[7];
      for (int i = 0; i < 7; ++i) {
        if (!F32(b, at + static_cast<std::size_t>(i) * 4, v[i])) {
          return false;
        }
      }
      out.position = {v[0], v[1], v[2]};
      // Version 5 keeps w, x, y, z; older files keep x, w, y, z (RScaResource's fixup).
      out.rotation =
        version < 5 ? std::array<float, 4>{v[4], v[3], v[5], v[6]} : std::array<float, 4>{v[3], v[4], v[5], v[6]};
      return true;
    }

    std::array<float, 4> Slerp(
      const std::array<float, 4>& a,
      std::array<float, 4> b,
      const float t
    )
    {
      float dot = a[0] * b[0] + a[1] * b[1] + a[2] * b[2] + a[3] * b[3];
      if (dot < 0.0f) {
        dot = -dot;
        for (float& c : b) {
          c = -c;
        }
      }
      float wa = 1.0f - t;
      float wb = t;
      if (dot < 0.9995f) {
        const float angle = std::acos(std::clamp(dot, -1.0f, 1.0f));
        const float s = std::sin(angle);
        wa = std::sin((1.0f - t) * angle) / s;
        wb = std::sin(t * angle) / s;
      }
      std::array<float, 4> out{};
      float len = 0.0f;
      for (int i = 0; i < 4; ++i) {
        out[static_cast<std::size_t>(i)] = a[static_cast<std::size_t>(i)] * wa + b[static_cast<std::size_t>(i)] * wb;
        len += out[static_cast<std::size_t>(i)] * out[static_cast<std::size_t>(i)];
      }
      len = std::sqrt(len);
      if (len > 1e-9f) {
        for (float& c : out) {
          c /= len;
        }
      }
      return out;
    }

    std::array<float, 3> Rotate(
      const std::array<float, 4>& q,
      const std::array<float, 3>& v
    )
    {
      // v' = q v q*, q = (w, x, y, z)
      const float w = q[0], x = q[1], y = q[2], z = q[3];
      const float tx = 2.0f * (y * v[2] - z * v[1]);
      const float ty = 2.0f * (z * v[0] - x * v[2]);
      const float tz = 2.0f * (x * v[1] - y * v[0]);
      return {v[0] + w * tx + (y * tz - z * ty), v[1] + w * ty + (z * tx - x * tz), v[2] + w * tz + (x * ty - y * tx)};
    }

    std::array<float, 4> Multiply(
      const std::array<float, 4>& a,
      const std::array<float, 4>& b
    )
    {
      return {
        a[0] * b[0] - a[1] * b[1] - a[2] * b[2] - a[3] * b[3],
        a[0] * b[1] + a[1] * b[0] + a[2] * b[3] - a[3] * b[2],
        a[0] * b[2] - a[1] * b[3] + a[2] * b[0] + a[3] * b[1],
        a[0] * b[3] + a[1] * b[2] - a[2] * b[1] + a[3] * b[0],
      };
    }
  } // namespace

  std::expected<void, std::string> ReadSca(
    const std::vector<std::uint8_t>& b,
    ScaAnimation& out
  )
  {
    out = ScaAnimation{};
    if (b.size() < 0x24 || std::memcmp(b.data(), "ANIM", 4) != 0) {
      return std::unexpected("not an animation file (no ANIM header)");
    }
    std::uint32_t version = 0, frames = 0, bones = 0, namesAt = 0, linksAt = 0, firstAt = 0, frameSize = 0;
    float duration = 0.0f;
    (void)U32(b, 0x04, version);
    (void)U32(b, 0x08, frames);
    (void)F32(b, 0x0C, duration);
    (void)U32(b, 0x10, bones);
    (void)U32(b, 0x14, namesAt);
    (void)U32(b, 0x18, linksAt);
    (void)U32(b, 0x1C, firstAt);
    (void)U32(b, 0x20, frameSize);
    if (bones == 0 || bones > 1024 || frames > 100000) {
      return std::unexpected("the animation's bone or frame count is out of range");
    }
    out.version = static_cast<int>(version);
    out.duration = duration;
    // Names: zero ended, one after another.
    std::size_t at = namesAt;
    for (std::uint32_t i = 0; i < bones; ++i) {
      std::string name;
      while (at < b.size() && b[at] != 0) {
        name += static_cast<char>(b[at++]);
      }
      ++at;
      out.bones.push_back(name);
    }
    for (std::uint32_t i = 0; i < bones; ++i) {
      std::uint32_t parent = 0;
      if (!U32(b, linksAt + i * 4, parent)) {
        return std::unexpected("the bone links run past the end of the file");
      }
      out.parents.push_back(parent == 0xFFFFFFFFu ? -1 : static_cast<int>(parent));
    }
    if (!Key(b, firstAt, out.version, out.rootStart)) {
      return std::unexpected("the first frame runs past the end of the file");
    }
    const std::size_t stride = frameSize != 0 ? frameSize : 8 + static_cast<std::size_t>(bones) * 28;
    const std::size_t framesAt = firstAt + 28;
    for (std::uint32_t f = 0; f < frames; ++f) {
      const std::size_t fa = framesAt + static_cast<std::size_t>(f) * stride;
      ScaAnimation::Frame frame;
      if (!F32(b, fa, frame.time) || !U32(b, fa + 4, frame.flags)) {
        return std::unexpected("frame " + std::to_string(f) + " runs past the end of the file");
      }
      frame.keys.resize(bones);
      for (std::uint32_t k = 0; k < bones; ++k) {
        if (!Key(b, fa + 8 + static_cast<std::size_t>(k) * 28, out.version, frame.keys[k])) {
          return std::unexpected("frame " + std::to_string(f) + " runs past the end of the file");
        }
      }
      out.frames.push_back(std::move(frame));
    }
    if (out.duration <= 0.0f && !out.frames.empty()) {
      out.duration = out.frames.back().time;
    }
    return {};
  }

  std::vector<ScaKey> SampleSca(
    const ScaAnimation& anim,
    float time,
    const bool loop
  )
  {
    if (anim.frames.empty()) {
      return std::vector<ScaKey>(anim.bones.size());
    }
    if (anim.frames.size() == 1 || anim.duration <= 0.0f) {
      return anim.frames.front().keys;
    }
    if (loop) {
      time = std::fmod(time, anim.duration);
      if (time < 0.0f) {
        time += anim.duration;
      }
    } else {
      time = std::clamp(time, 0.0f, anim.duration);
    }
    std::size_t b = 0;
    while (b < anim.frames.size() && anim.frames[b].time < time) {
      ++b;
    }
    if (b == 0) {
      return anim.frames.front().keys;
    }
    if (b >= anim.frames.size()) {
      return anim.frames.back().keys;
    }
    const ScaAnimation::Frame& f0 = anim.frames[b - 1];
    const ScaAnimation::Frame& f1 = anim.frames[b];
    const float span = f1.time - f0.time;
    const float t = span > 1e-6f ? (time - f0.time) / span : 0.0f;
    std::vector<ScaKey> out(f0.keys.size());
    for (std::size_t k = 0; k < out.size() && k < f1.keys.size(); ++k) {
      for (int c = 0; c < 3; ++c) {
        out[k].position[static_cast<std::size_t>(c)] = f0.keys[k].position[static_cast<std::size_t>(c)] +
          (f1.keys[k].position[static_cast<std::size_t>(c)] - f0.keys[k].position[static_cast<std::size_t>(c)]) * t;
      }
      out[k].rotation = Slerp(f0.keys[k].rotation, f1.keys[k].rotation, t);
    }
    return out;
  }

  std::vector<std::array<float, 3>> ScaBoneWorld(
    const ScaAnimation& anim,
    const std::vector<ScaKey>& keys
  )
  {
    std::vector<std::array<float, 3>> pos(keys.size(), std::array<float, 3>{0, 0, 0});
    std::vector<std::array<float, 4>> rot(keys.size(), std::array<float, 4>{1, 0, 0, 0});
    for (std::size_t i = 0; i < keys.size(); ++i) {
      const int p = i < anim.parents.size() ? anim.parents[i] : -1;
      if (p >= 0 && static_cast<std::size_t>(p) < i) {
        const std::array<float, 3> r = Rotate(rot[static_cast<std::size_t>(p)], keys[i].position);
        pos[i] = {
          pos[static_cast<std::size_t>(p)][0] + r[0],
          pos[static_cast<std::size_t>(p)][1] + r[1],
          pos[static_cast<std::size_t>(p)][2] + r[2]
        };
        rot[i] = Multiply(rot[static_cast<std::size_t>(p)], keys[i].rotation);
      } else {
        pos[i] = keys[i].position;
        rot[i] = keys[i].rotation;
      }
    }
    return pos;
  }
} // namespace faf::editor
