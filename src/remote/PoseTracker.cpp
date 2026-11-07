#include "remote/PoseTracker.h"

#include <cmath>

#include "moho/animation/CAniPose.h"
#include "moho/entity/Entity.h"
#include "moho/render/camera/VTransform.h"
#include "moho/sim/SimWorkerPool.h"
#include "moho/unit/core/Unit.h"

// Engine addition, server mode: see PoseTracker.h.

namespace faf::remote
{
  namespace
  {
    [[nodiscard]] wire::SPoseBone ReadBone(const moho::CAniPoseBone& bone)
    {
      wire::SPoseBone out;
      const moho::VTransform& local = bone.mLocalTransform;
      out.position = {local.pos_.x, local.pos_.y, local.pos_.z};
      out.rotation = {local.orient_.x, local.orient_.y, local.orient_.z, local.orient_.w};
      out.visible = bone.mVisible != 0u;
      out.skipInterp = bone.mSkipNextInterp != 0u;
      return out;
    }

    /** Whether a client holding `held` should get `now`: moved past the tolerance, or other flags. */
    [[nodiscard]] bool Moved(const wire::SPoseBone& held, const wire::SPoseBone& now) noexcept
    {
      for (std::size_t i = 0; i < 3; ++i) {
        // Written so that a NaN counts as moved.
        if (!(std::fabs(now.position[i] - held.position[i]) <= CPoseTracker::kPositionTolerance)) {
          return true;
        }
      }
      for (std::size_t i = 0; i < 4; ++i) {
        if (!(std::fabs(now.rotation[i] - held.rotation[i]) <= CPoseTracker::kRotationTolerance)) {
          return true;
        }
      }
      return now.visible != held.visible || now.skipInterp != held.skipInterp;
    }
  } // namespace

  void CPoseTracker::ReadUnit(SUnit& unit)
  {
    unit.changed.clear();
    unit.reset = false;
    const moho::CAniPose* const pose = unit.unit != nullptr ? unit.unit->VarDat().mSharedPose.get() : nullptr;
    if (pose == nullptr) {
      unit.reset = !unit.sent.empty() || unit.pose != nullptr; // the clients drop theirs
      unit.sent.clear();
      unit.pose = nullptr;
      return;
    }
    const std::size_t bones = pose->mBones.size();
    if (pose != unit.pose || bones != unit.sent.size()) {
      // New, or another skeleton (`Unit::SetMesh`): every bone, whole.
      unit.pose = pose;
      unit.reset = true;
      unit.sent.clear();
      unit.sent.reserve(bones);
      for (const moho::CAniPoseBone& bone : pose->mBones) {
        unit.sent.push_back(ReadBone(bone));
      }
      return;
    }
    std::size_t index = 0;
    for (const moho::CAniPoseBone& bone : pose->mBones) {
      const wire::SPoseBone now = ReadBone(bone);
      if (Moved(unit.sent[index], now)) {
        unit.sent[index] = now;
        unit.changed.push_back(static_cast<std::uint16_t>(index));
      }
      ++index;
    }
  }

  void CPoseTracker::Refresh(const std::span<const std::uint32_t> ids, const std::span<moho::Entity* const> entities, const bool parallel)
  {
    // Last beat's units merged with this beat's, both by id: a unit seen before keeps what its clients hold.
    mNext.clear();
    mNext.reserve(ids.size());
    std::size_t old = 0;
    for (std::size_t i = 0; i < ids.size(); ++i) {
      while (old < mUnits.size() && mUnits[old].id < ids[i]) {
        ++old;
      }
      if (old < mUnits.size() && mUnits[old].id == ids[i] && mUnits[old].entity == entities[i]) {
        mNext.push_back(std::move(mUnits[old++]));
        continue;
      }
      SUnit unit;
      unit.id = ids[i];
      unit.entity = entities[i];
      unit.unit = entities[i]->IsUnit();
      mNext.push_back(std::move(unit));
    }
    mUnits.swap(mNext);

    const auto read = [this](const std::size_t begin, const std::size_t end) {
      for (std::size_t i = begin; i < end; ++i) {
        ReadUnit(mUnits[i]);
      }
    };
    constexpr std::size_t kGrain = 64;
    if (parallel && mUnits.size() > kGrain) {
      moho::CSimWorkerPool::Get().ParallelFor(mUnits.size(), kGrain, read);
    } else {
      read(0u, mUnits.size());
    }
    mPosed = 0;
    mChangedBones = 0;
    for (const SUnit& unit : mUnits) {
      mPosed += unit.sent.empty() ? 0u : 1u;
      mChangedBones += unit.changed.size();
    }
    mTotalChangedBones += mChangedBones;
    ++mBeats;
  }

  bool CPoseTracker::EncodeView(
    const std::span<const std::uint32_t> held, const std::span<const std::uint32_t> heldBefore, const bool fresh, wire::BitWriter& out
  ) const
  {
    thread_local std::vector<wire::SUnitPose> lane;
    lane.clear();
    std::size_t unitAt = 0;
    std::size_t beforeAt = 0;
    for (const std::uint32_t id : held) {
      while (unitAt < mUnits.size() && mUnits[unitAt].id < id) {
        ++unitAt;
      }
      if (unitAt == mUnits.size() || mUnits[unitAt].id != id) {
        continue; // not a unit this beat
      }
      const SUnit& unit = mUnits[unitAt];
      while (beforeAt < heldBefore.size() && heldBefore[beforeAt] < id) {
        ++beforeAt;
      }
      const bool heldLastBeat = beforeAt < heldBefore.size() && heldBefore[beforeAt] == id;
      const bool whole = fresh || unit.reset || !heldLastBeat;
      if (whole) {
        if (unit.sent.empty() && !(unit.reset && heldLastBeat && !fresh)) {
          continue; // no pose: nothing to send, unless a client holding one must drop it
        }
        wire::SUnitPose& pose = lane.emplace_back();
        pose.id = id;
        pose.whole = true;
        pose.bones = unit.sent; // empty: the client drops the unit's poses
        continue;
      }
      if (unit.changed.empty()) {
        continue;
      }
      wire::SUnitPose& pose = lane.emplace_back();
      pose.id = id;
      pose.indices = unit.changed;
      pose.bones.reserve(unit.changed.size());
      for (const std::uint16_t index : unit.changed) {
        pose.bones.push_back(unit.sent[index]);
      }
    }
    return wire::EncodePoseLane(lane, out);
  }
} // namespace faf::remote
