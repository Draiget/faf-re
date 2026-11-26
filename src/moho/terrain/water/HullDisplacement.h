#pragma once

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <unordered_map>
#include <vector>

#include "HullFoot.h"

// What a body has done to the water between two frames, as the change of the volume it takes up in every bin of the
// world (HullFoot.h). Pure functions on plain numbers (no engine types), so the headless lab can drive it too.
//
// A body keeps its volume in a bin while it sits still (no change, no wave). A body that moves into a bin raises the
// water there (positive change: the bow wave, the splash of a crash), one that leaves a bin leaves a gap the water runs
// into (negative change: the trough and the wash behind a stern). A body that is seen for the first time makes nothing
// happen (a unit that comes into view is not a splash).
namespace moho::water
{
  constexpr float kBodyBin = 1.0f; // world units

  struct BodyBin
  {
    std::int32_t ix = 0;
    std::int32_t iz = 0;
    float volume = 0.0f; // world units cubed
  };

  // The volume of a body in the bins of the world: every column of its footprint (HullFoot.h) is put where the pose of
  // the body (`rotate(x, y, z, wx, wy, wz)` turns a model offset, already scaled, into a world offset) takes it, as
  // much of it as is under `waterY`, and shared between the four bins around it. A body well under the surface is felt
  // less.
  template <class Rotate>
  void BodyBins(
    const HullFoot& foot,
    const float px,
    const float py,
    const float pz,
    const float sx,
    const float sy,
    const float sz,
    const float waterY,
    Rotate&& rotate,
    std::vector<BodyBin>& out
  )
  {
    const float area = foot.cellX * sx * foot.cellZ * sz;
    for (int j = 0; j < foot.nz; ++j) {
      for (int i = 0; i < foot.nx; ++i) {
        const int k = j * kFootMax + i;
        if (!foot.has[k]) {
          continue;
        }
        const float mx = foot.x0 + (static_cast<float>(i) + 0.5f) * foot.cellX;
        const float mz = foot.z0 + (static_cast<float>(j) + 0.5f) * foot.cellZ;
        const float my = 0.5f * (foot.bottom[k] + foot.top[k]);
        float wx, wy, wz;
        rotate(mx * sx, my * sy, mz * sz, wx, wy, wz);
        const float height = (foot.top[k] - foot.bottom[k]) * sy;
        const float columnBottom = py + wy - 0.5f * height;
        const float columnTop = py + wy + 0.5f * height;
        float depth = std::min(columnTop, waterY) - columnBottom;
        if (!(depth > 0.0f)) {
          continue;
        }
        if (columnTop < waterY) {
          depth *= std::exp(-(waterY - columnTop) / 3.0f);
        }
        const float volume = depth * area;
        const float gx = (px + wx) / kBodyBin - 0.5f;
        const float gz = (pz + wz) / kBodyBin - 0.5f;
        const float fx = gx - std::floor(gx);
        const float fz = gz - std::floor(gz);
        const std::int32_t ix = static_cast<std::int32_t>(std::floor(gx));
        const std::int32_t iz = static_cast<std::int32_t>(std::floor(gz));
        out.push_back({ix, iz, volume * (1.0f - fx) * (1.0f - fz)});
        out.push_back({ix + 1, iz, volume * fx * (1.0f - fz)});
        out.push_back({ix, iz + 1, volume * (1.0f - fx) * fz});
        out.push_back({ix + 1, iz + 1, volume * fx * fz});
      }
    }
  }

  /// Everything that decides the bins of a body: where it stands, how it is turned and scaled, the level of the water
  /// at its place and the shape its columns come from (`shape` is any pointer that is the same for the same shape).
  struct BodyPose
  {
    float values[11] = {};
    const void* shape = nullptr;

    friend bool operator==(
      const BodyPose& a,
      const BodyPose& b
    )
    {
      for (int i = 0; i < 11; ++i) {
        if (!(a.values[i] == b.values[i])) {
          return false;
        }
      }
      return a.shape == b.shape;
    }
  };

  class BodyTracker
  {
  public:
    void BeginFrame()
    {
      ++frame_;
    }

    // True when `id` was updated before and `pose` is exactly the pose of that update: its bins are what they were, so
    // every delta an Update would find is zero and nothing is emitted; the body counts as seen this frame (EndFrame
    // keeps it). False: the caller works the bins out, calls Update and then Remember. The still bodies of a map (trees
    // in a river, buildings on a shore) cost a lookup a frame instead of their columns, a sort and a merge.
    bool Hold(
      const void* const id,
      const BodyPose& pose
    )
    {
      const auto found = bodies_.find(id);
      if (
        found == bodies_.end() || found->second.frame == 0U || !found->second.known || !(found->second.pose == pose)
      ) {
        return false;
      }
      found->second.frame = frame_;
      return true;
    }

    // The pose the bins of the last Update of `id` were worked out from.
    void Remember(
      const void* const id,
      const BodyPose& pose
    )
    {
      const auto found = bodies_.find(id);
      if (found != bodies_.end()) {
        found->second.pose = pose;
        found->second.known = true;
      }
    }

    // `now` is the volume of the body in the bins it touches now (any order, bins may repeat). `emit(x, z, delta)` is
    // called for every bin whose volume changed since the last frame this body was seen: the world position of the
    // middle of the bin and the change of volume.
    template <class Emit>
    void Update(
      const void* const id,
      std::vector<BodyBin>& now,
      Emit&& emit
    )
    {
      std::sort(now.begin(), now.end(), [](const BodyBin& a, const BodyBin& b) {
        return a.iz != b.iz ? a.iz < b.iz : a.ix < b.ix;
      });
      std::vector<BodyBin> merged;
      merged.reserve(now.size());
      for (const BodyBin& b : now) {
        if (!merged.empty() && merged.back().ix == b.ix && merged.back().iz == b.iz) {
          merged.back().volume += b.volume;
        } else {
          merged.push_back(b);
        }
      }
      Entry& entry = bodies_[id];
      if (entry.frame != 0U) {
        std::size_t i = 0;
        std::size_t j = 0;
        const std::vector<BodyBin>& was = entry.bins;
        const auto lessKey = [](const BodyBin& a, const BodyBin& b) {
          return a.iz != b.iz ? a.iz < b.iz : a.ix < b.ix;
        };
        while (i < merged.size() || j < was.size()) {
          float delta;
          std::int32_t ix;
          std::int32_t iz;
          if (j >= was.size() || (i < merged.size() && lessKey(merged[i], was[j]))) {
            ix = merged[i].ix;
            iz = merged[i].iz;
            delta = merged[i].volume;
            ++i;
          } else if (i >= merged.size() || lessKey(was[j], merged[i])) {
            ix = was[j].ix;
            iz = was[j].iz;
            delta = -was[j].volume;
            ++j;
          } else {
            ix = merged[i].ix;
            iz = merged[i].iz;
            delta = merged[i].volume - was[j].volume;
            ++i;
            ++j;
          }
          if (std::fabs(delta) > 1.0e-5f) {
            emit((static_cast<float>(ix) + 0.5f) * kBodyBin, (static_cast<float>(iz) + 0.5f) * kBodyBin, delta);
          }
        }
      }
      entry.bins.swap(merged);
      entry.frame = frame_;
      entry.known = false; // Remember says from which pose
    }

    // Forgets the bodies that were not updated this frame (out of view, hidden, away from the water).
    void EndFrame()
    {
      for (auto it = bodies_.begin(); it != bodies_.end();) {
        it = it->second.frame != frame_ ? bodies_.erase(it) : std::next(it);
      }
    }

    void Clear()
    {
      bodies_.clear();
    }
    std::size_t Size() const
    {
      return bodies_.size();
    }

  private:
    struct Entry
    {
      std::vector<BodyBin> bins;
      std::uint64_t frame = 0;
      BodyPose pose;
      bool known = false;
    };
    std::unordered_map<const void*, Entry> bodies_;
    std::uint64_t frame_ = 1;
  };
} // namespace moho::water
