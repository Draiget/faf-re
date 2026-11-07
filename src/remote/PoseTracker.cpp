#include "remote/PoseTracker.h"

#include <atomic>
#include <cstdlib>
#include <cstring>

#include "moho/animation/CAniActor.h"
#include "moho/animation/CAniPose.h"
#include "moho/animation/PoseJobs.h"
#include "moho/entity/Entity.h"
#include "moho/render/camera/VTransform.h"
#include "moho/sim/SimWorkerPool.h"
#include "moho/unit/core/Unit.h"

// Engine addition, server mode: see PoseTracker.h.

namespace faf::remote
{
  namespace
  {
    [[nodiscard]] CPoseTracker::SRawBone RawBone(const moho::CAniPoseBone& bone) noexcept
    {
      CPoseTracker::SRawBone raw{};
      std::memcpy(raw.transform, &bone.mLocalTransform, sizeof(raw.transform));
      raw.flags = static_cast<std::uint32_t>(bone.mVisible) | (static_cast<std::uint32_t>(bone.mSkipNextInterp) << 8u);
      return raw;
    }

    [[nodiscard]] wire::SPoseBone ReadBone(const moho::CAniPoseBone& bone)
    {
      const moho::VTransform& local = bone.mLocalTransform;
      const float position[3] = {local.pos_.x, local.pos_.y, local.pos_.z};
      const float rotation[4] = {local.orient_.x, local.orient_.y, local.orient_.z, local.orient_.w};
      return wire::QuantizeBone(position, rotation, bone.mVisible != 0u, bone.mSkipNextInterp != 0u);
    }

    /**
     * Whether a client holding `held` should get `now`: moved by `kMoveSteps` quantiser steps (about M0.3's tolerance:
     * 0.001 in position, 0.0001 in a quaternion component), or other flags.
     */
    [[nodiscard]] bool Moved(const wire::SPoseBone& held, const wire::SPoseBone& now) noexcept
    {
      constexpr std::int64_t kMoveSteps = 2;
      for (std::size_t i = 0; i < 3; ++i) {
        if (std::llabs(static_cast<std::int64_t>(now.position[i]) - held.position[i]) >= kMoveSteps) {
          return true;
        }
      }
      for (std::size_t i = 0; i < 4; ++i) {
        if (std::llabs(static_cast<std::int64_t>(now.rotation[i]) - held.rotation[i]) >= kMoveSteps) {
          return true;
        }
      }
      return now.visible != held.visible || now.skipInterp != held.skipInterp;
    }

    /** `now - held`, component by component; the flags are `now`'s. */
    [[nodiscard]] wire::SPoseBone Difference(const wire::SPoseBone& held, const wire::SPoseBone& now) noexcept
    {
      wire::SPoseBone out;
      for (std::size_t i = 0; i < 3; ++i) {
        out.position[i] = now.position[i] - held.position[i];
      }
      for (std::size_t i = 0; i < 4; ++i) {
        out.rotation[i] = now.rotation[i] - held.rotation[i];
      }
      out.visible = now.visible;
      out.skipInterp = now.skipInterp;
      return out;
    }
  } // namespace

  void CPoseTracker::ReadUnit(SUnit& unit)
  {
    unit.changed.clear();
    unit.differences.clear();
    unit.reset = false;
    // The actor's current pose, not the unit's published one: a server keeps no client handles, so that one is null
    // for most units (`POSE_HoldClientHandles`), and the actor's poses are recycled in place (`sim_RecyclePose`), the
    // current one swapping objects from tick to tick. A new skeleton (`Unit::SetMesh`) is told by the skeleton itself.
    moho::CAniActor* const actor = unit.unit != nullptr ? unit.unit->AniActor : nullptr;
    if (actor != nullptr && actor == unit.actor && !unit.sent.empty()) {
      // Each step the actor resets its pose's bones to the skeleton's (`UpdateBones`) and runs its enabled
      // manipulators: with none for a couple of reads (the step after the last one went resets the bones), the pose
      // is the skeleton's and stays so. Most units (buildings) have none: their bones aren't read (plan #118).
      const bool animating = !actor->AllEnabledManipulators(+[](const moho::IAniManipulator&) { return false; });
      unit.quietReads = animating ? 0u : (unit.quietReads < 255u ? static_cast<std::uint8_t>(unit.quietReads + 1u) : unit.quietReads);
      if (unit.quietReads > 2u) {
        return;
      }
    } else {
      unit.quietReads = 0;
    }
    unit.actor = actor; // `Unit::SetMesh` makes a new actor
    const moho::CAniPose* pose = nullptr;
    if (actor != nullptr) {
      moho::POSE_WaitFor(actor); // the beat's pose jobs (sim_ParallelPose), as `GetPoseShared` does, with no count
      pose = actor->mPose.get();
    }
    if (pose == nullptr) {
      unit.reset = !unit.sent.empty() || unit.skeleton != nullptr; // the clients drop theirs
      unit.sent.clear();
      unit.skeleton = nullptr;
      return;
    }
    const std::size_t bones = pose->mBones.size();
    const void* const skeleton = pose->mSkeleton.get();
    if (skeleton != unit.skeleton || bones != unit.sent.size()) {
      // New, or another skeleton: every bone, whole.
      unit.skeleton = skeleton;
      unit.reset = true;
      unit.sent.clear();
      unit.sent.reserve(bones);
      unit.raw.clear();
      unit.raw.reserve(bones);
      for (const moho::CAniPoseBone& bone : pose->mBones) {
        unit.sent.push_back(ReadBone(bone));
        unit.raw.push_back(RawBone(bone));
      }
      return;
    }
    std::size_t index = 0;
    for (const moho::CAniPoseBone& bone : pose->mBones) {
      // Bit for bit as last read: nothing to quantise (most bones of most units, most beats).
      const SRawBone raw = RawBone(bone);
      if (std::memcmp(&raw, &unit.raw[index], sizeof(SRawBone)) == 0) {
        ++index;
        continue;
      }
      unit.raw[index] = raw;
      const wire::SPoseBone now = ReadBone(bone);
      if (Moved(unit.sent[index], now)) {
        unit.differences.push_back(Difference(unit.sent[index], now));
        unit.sent[index] = now;
        unit.changed.push_back(static_cast<std::uint16_t>(index));
      }
      ++index;
    }
  }

  void CPoseTracker::Refresh(const std::span<const std::uint32_t> ids, const std::span<moho::Entity* const> entities, const bool parallel)
  {
    // Last beat's units merged with this beat's, both by id: a unit seen before keeps what its clients hold. Most
    // beats the units are last beat's: then the list stays as it is (no unit is moved).
    bool same = ids.size() == mUnits.size();
    for (std::size_t i = 0; same && i < ids.size(); ++i) {
      same = mUnits[i].id == ids[i] && mUnits[i].entity == entities[i];
    }
    if (!same) {
      Merge(ids, entities);
    }
    ReadAll(parallel);
  }

  void CPoseTracker::Merge(const std::span<const std::uint32_t> ids, const std::span<moho::Entity* const> entities)
  {
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
  }

  void CPoseTracker::ReadAll(const bool parallel)
  {
    std::atomic<std::size_t> posed{0};
    std::atomic<std::size_t> changed{0};
    const auto read = [this, &posed, &changed](const std::size_t begin, const std::size_t end) {
      std::size_t chunkPosed = 0;
      std::size_t chunkChanged = 0;
      for (std::size_t i = begin; i < end; ++i) {
        SUnit& unit = mUnits[i];
        ReadUnit(unit);
        chunkPosed += unit.sent.empty() ? 0u : 1u;
        chunkChanged += unit.changed.size();
      }
      posed.fetch_add(chunkPosed, std::memory_order_relaxed);
      changed.fetch_add(chunkChanged, std::memory_order_relaxed);
    };
    constexpr std::size_t kGrain = 64;
    if (parallel && mUnits.size() > kGrain) {
      moho::CSimWorkerPool::Get().ParallelFor(mUnits.size(), kGrain, read);
    } else {
      read(0u, mUnits.size());
    }
    mPosed = posed.load(std::memory_order_relaxed);
    mChangedBones = changed.load(std::memory_order_relaxed);
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
      pose.bones = unit.differences;
    }
    return wire::EncodePoseLane(lane, out);
  }
} // namespace faf::remote
