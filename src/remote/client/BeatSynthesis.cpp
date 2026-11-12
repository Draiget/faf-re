#include "remote/client/BeatSynthesis.h"

#include <algorithm>
#include <cmath>
#include <unordered_set>

// Engine addition, server mode: see BeatSynthesis.h.

namespace faf::remote::client
{
  namespace
  {
    struct SQuat
    {
      double w = 1.0;
      double x = 0.0;
      double y = 0.0;
      double z = 0.0;
    };

    [[nodiscard]] SQuat Multiply(
      const SQuat& a,
      const SQuat& b
    ) noexcept
    {
      return SQuat{
        a.w * b.w - a.x * b.x - a.y * b.y - a.z * b.z,
        a.w * b.x + a.x * b.w + a.y * b.z - a.z * b.y,
        a.w * b.y - a.x * b.z + a.y * b.w + a.z * b.x,
        a.w * b.z + a.x * b.y - a.y * b.x + a.z * b.w,
      };
    }

    [[nodiscard]] SQuat Normalized(
      const SQuat& q
    ) noexcept
    {
      const double norm = std::sqrt(q.w * q.w + q.x * q.x + q.y * q.y + q.z * q.z);
      if (!(norm > 0.0) || !std::isfinite(norm)) {
        return SQuat{};
      }
      return SQuat{q.w / norm, q.x / norm, q.y / norm, q.z / norm};
    }
  } // namespace

  SSynthTransform ExtrapolateTransform(
    const SSynthTransform& last,
    const SSynthTransform& cur,
    const int ahead
  )
  {
    if (ahead <= 0) {
      return cur;
    }
    const double dx = static_cast<double>(cur.px) - last.px;
    const double dy = static_cast<double>(cur.py) - last.py;
    const double dz = static_cast<double>(cur.pz) - last.pz;
    const double step = std::sqrt(dx * dx + dy * dy + dz * dz);
    if (!std::isfinite(step) || step > static_cast<double>(kMaxSynthStep)) {
      return cur; // a warp or a fresh placement, not motion
    }
    SSynthTransform out = cur;
    out.px = static_cast<float>(cur.px + dx * ahead);
    out.py = static_cast<float>(cur.py + dy * ahead);
    out.pz = static_cast<float>(cur.pz + dz * ahead);

    // The turn from `last` to `cur` (taken the short way round), applied `ahead` more times.
    const SQuat to{cur.qw, cur.qx, cur.qy, cur.qz};
    SQuat from{last.qw, last.qx, last.qy, last.qz};
    if (from.w * to.w + from.x * to.x + from.y * to.y + from.z * to.z < 0.0) {
      from = SQuat{-from.w, -from.x, -from.y, -from.z};
    }
    const SQuat turn = Normalized(Multiply(to, SQuat{from.w, -from.x, -from.y, -from.z}));
    SQuat orientation = to;
    for (int i = 0; i < ahead; ++i) {
      orientation = Multiply(turn, orientation);
    }
    orientation = Normalized(orientation);
    out.qw = static_cast<float>(orientation.w);
    out.qx = static_cast<float>(orientation.x);
    out.qy = static_cast<float>(orientation.y);
    out.qz = static_cast<float>(orientation.z);
    return out;
  }

  float PositionError(
    const SSynthTransform& a,
    const SSynthTransform& b
  ) noexcept
  {
    const double dx = static_cast<double>(a.px) - b.px;
    const double dy = static_cast<double>(a.py) - b.py;
    const double dz = static_cast<double>(a.pz) - b.pz;
    return static_cast<float>(std::sqrt(dx * dx + dy * dy + dz * dz));
  }

  void CBeatSynthesizer::Synthesize(
    const std::int32_t tick,
    const std::int32_t ahead,
    const ForEach& forEach,
    const Lookup& lookup,
    std::vector<SSynthUpdate>& out
  )
  {
    out.clear();
    std::unordered_set<std::uint32_t> moving;
    // Every entity the last real beat moved: on by its motion, from where the screen shows it.
    forEach([&](const std::uint32_t id, const SSynthTransform& last, const SSynthTransform& cur) {
      if (!Moves(last, cur)) {
        return;
      }
      const auto shown = mShown.find(id);
      SSynthUpdate update;
      update.id = id;
      update.last = shown != mShown.end() ? shown->second : cur;
      update.cur = ExtrapolateTransform(last, cur, ahead);
      out.push_back(update);
      moving.insert(id);
    });
    // Every entity shown off its place that no longer moves: back to its real place.
    std::vector<std::uint32_t> gone;
    for (const auto& [id, shown] : mShown) {
      if (moving.count(id) != 0u) {
        continue;
      }
      SSynthTransform last;
      SSynthTransform cur;
      if (!lookup(id, last, cur)) {
        gone.push_back(id);
        continue;
      }
      SSynthUpdate update;
      update.id = id;
      update.last = shown;
      update.cur = cur;
      out.push_back(update);
      gone.push_back(id); // shown at its real place after this beat
    }
    for (const std::uint32_t id : gone) {
      mShown.erase(id);
    }
    std::sort(out.begin(), out.end(), [](const SSynthUpdate& a, const SSynthUpdate& b) {
      return a.id < b.id;
    });
    std::vector<std::pair<std::uint32_t, SSynthTransform>>& madeUp = mMadeUp[tick];
    madeUp.clear();
    for (const SSynthUpdate& update : out) {
      if (moving.count(update.id) != 0u) {
        mShown[update.id] = update.cur;
        madeUp.emplace_back(update.id, update.cur);
      }
    }
    while (mMadeUp.size() > 16u) {
      mMadeUp.erase(mMadeUp.begin());
    }
    ++mStats.beats;
    mStats.moved += out.size();
  }

  void CBeatSynthesizer::CompareWithReal(
    const std::int32_t beat,
    const Lookup& lookup
  )
  {
    if (const auto found = mMadeUp.find(beat); found != mMadeUp.end()) {
      for (const auto& [id, madeUp] : found->second) {
        SSynthTransform last;
        SSynthTransform cur;
        if (!lookup(id, last, cur)) {
          continue;
        }
        const double error = PositionError(madeUp, cur);
        ++mStats.compared;
        mStats.errorSum += error;
        mStats.errorMost = std::max(mStats.errorMost, error);
      }
    }
    while (!mMadeUp.empty() && mMadeUp.begin()->first <= beat) {
      mMadeUp.erase(mMadeUp.begin());
    }
  }

  void CBeatSynthesizer::OnCatchUp(
    const std::vector<SSynthUpdate>& updates
  )
  {
    for (const SSynthUpdate& update : updates) {
      // The screen showed this entity at the transform the session had as current, which this update replaces.
      if (Moves(update.last, update.cur) && mShown.count(update.id) == 0u) {
        mShown.emplace(update.id, update.last);
      }
    }
  }

  void CBeatSynthesizer::OnAdvance(
    std::vector<SSynthUpdate>& updates,
    const Lookup& lookup,
    std::vector<SSynthUpdate>& added
  )
  {
    added.clear();
    if (mShown.empty()) {
      return;
    }
    for (SSynthUpdate& update : updates) {
      if (const auto shown = mShown.find(update.id); shown != mShown.end()) {
        update.last = shown->second;
        mShown.erase(shown);
        ++mStats.eased;
      }
    }
    for (const auto& [id, shown] : mShown) {
      SSynthTransform last;
      SSynthTransform cur;
      if (!lookup(id, last, cur)) {
        continue; // gone in this beat
      }
      SSynthUpdate update;
      update.id = id;
      update.last = shown;
      update.cur = cur;
      added.push_back(update);
      ++mStats.eased;
      ++mStats.easedAdded;
    }
    std::sort(added.begin(), added.end(), [](const SSynthUpdate& a, const SSynthUpdate& b) {
      return a.id < b.id;
    });
    mShown.clear();
  }
} // namespace faf::remote::client
