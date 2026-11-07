#include "remote/PoseTracker.h"

#include <algorithm>
#include <atomic>
#include <bit>
#include <cstdlib>
#include <utility>
#include <cstring>
#include <mutex>

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

  namespace
  {
    CPoseTracker* sHookTracker = nullptr; // `InstallHook`'s
  } // namespace

  CPoseTracker::~CPoseTracker()
  {
    if (mHooked && sHookTracker == this) {
      moho::gAniPoseUpdatedHook = nullptr;
      sHookTracker = nullptr;
    }
  }

  void CPoseTracker::InstallHook()
  {
    sHookTracker = this;
    mHooked = true;
    moho::gAniPoseUpdatedHook = &OnPoseUpdated;
  }

  void CPoseTracker::OnPoseUpdated(const moho::CAniActor& actor)
  {
    // On a pose job's thread (or the sim thread), during the tick: the index doesn't change then, and each actor's
    // update runs once a tick, so only this unit's hook state (and one slot of the marked list) is written here.
    CPoseTracker* const tracker = sHookTracker;
    if (tracker == nullptr) {
      return;
    }
    const auto found = tracker->mByActor.find(&actor);
    if (found == tracker->mByActor.end()) {
      return; // a unit `Refresh` hasn't read whole yet
    }
    SHookState& state = *found->second;
    const moho::CAniPose* const pose = actor.mPose.get();
    if (pose == nullptr || pose->mBones.size() != state.raw.size() || pose->mSkeleton.get() != state.skeleton) {
      return; // something else changed: the sweep reads it the slow way
    }
    // Quantised and tested here, while the bones are in this thread's cache: a marked bone is one that goes.
    bool marked = false;
    std::size_t index = 0;
    for (const moho::CAniPoseBone& bone : pose->mBones) {
      const SRawBone raw = RawBone(bone);
      if (std::memcmp(&raw, &state.raw[index], sizeof(SRawBone)) != 0) {
        state.raw[index] = raw;
        const wire::SPoseBone now = ReadBone(bone);
        const std::uint64_t bit = std::uint64_t{1} << (index & 63u);
        if (Moved(state.mirror[index], now)) {
          state.pending[index] = now;
          state.dirty[index >> 6u] |= bit;
          marked = true;
        } else if ((state.dirty[index >> 6u] & bit) != 0u) {
          state.pending[index] = now; // marked earlier this beat: the newest value goes
        }
      }
      ++index;
    }
    if (marked && !state.queued && state.owner != nullptr) {
      state.queued = true;
      const std::size_t slot = tracker->mMarkedCount.fetch_add(1u, std::memory_order_relaxed);
      if (slot < tracker->mMarked.size()) {
        tracker->mMarked[slot] = state.owner;
      } else {
        state.queued = false; // no room (can't happen: a unit is listed once): the marks wait for its next listing
      }
    }
  }

  void CPoseTracker::Unindex(SUnit& unit)
  {
    if (unit.hook == nullptr || unit.hook->indexedUnder == nullptr) {
      return;
    }
    if (const auto found = mByActor.find(unit.hook->indexedUnder); found != mByActor.end() && found->second == unit.hook.get()) {
      mByActor.erase(found);
    }
    unit.hook->indexedUnder = nullptr;
  }

  void CPoseTracker::TakeMarks(SUnit& unit)
  {
    // #118: the hook quantised the marked bones and found them moved: their values only move over (no bone is read).
    SHookState& state = *unit.hook;
    state.queued = false;
    for (std::size_t word = 0; word < state.dirty.size(); ++word) {
      std::uint64_t bits = std::exchange(state.dirty[word], 0u);
      while (bits != 0u) {
        const std::size_t index = word * 64u + static_cast<std::size_t>(std::countr_zero(bits));
        bits &= bits - 1u;
        const wire::SPoseBone& now = state.pending[index];
        unit.differences.push_back(Difference(unit.sent[index], now));
        unit.sent[index] = now;
        state.mirror[index] = now;
        unit.changed.push_back(static_cast<std::uint16_t>(index));
      }
    }
  }

  void CPoseTracker::ReadUnit(SUnit& unit)
  {
    // The actor's current pose, not the unit's published one: a server keeps no client handles, so that one is null
    // for most units (`POSE_HoldClientHandles`), and the actor's poses are recycled in place (`sim_RecyclePose`), the
    // current one swapping objects from tick to tick. A new skeleton (`Unit::SetMesh`) is told by the skeleton itself.
    moho::CAniActor* const actor = unit.unit != nullptr ? unit.unit->AniActor : nullptr;
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
    if (unit.hook == nullptr) {
      unit.hook = std::make_unique<SHookState>();
    }
    SHookState& state = *unit.hook;
    const std::size_t bones = pose->mBones.size();
    const void* const skeleton = pose->mSkeleton.get();
    if (skeleton != unit.skeleton || bones != unit.sent.size()) {
      // New, or another skeleton: every bone, whole.
      unit.skeleton = skeleton;
      unit.reset = true;
      unit.sent.clear();
      unit.sent.reserve(bones);
      state.raw.clear();
      state.raw.reserve(bones);
      for (const moho::CAniPoseBone& bone : pose->mBones) {
        unit.sent.push_back(ReadBone(bone));
        state.raw.push_back(RawBone(bone));
      }
      state.dirty.assign((bones + 63u) / 64u, 0u);
      state.mirror = unit.sent;
      state.pending.resize(bones);
      state.skeleton = skeleton;
      state.queued = false;
      return;
    }
    std::size_t index = 0;
    for (const moho::CAniPoseBone& bone : pose->mBones) {
      // Bit for bit as last read: nothing to quantise (most bones of most units, most beats).
      const SRawBone raw = RawBone(bone);
      if (std::memcmp(&raw, &state.raw[index], sizeof(SRawBone)) == 0) {
        ++index;
        continue;
      }
      state.raw[index] = raw;
      const wire::SPoseBone now = ReadBone(bone);
      if (Moved(unit.sent[index], now)) {
        unit.differences.push_back(Difference(unit.sent[index], now));
        unit.sent[index] = now;
        state.mirror[index] = now;
        unit.changed.push_back(static_cast<std::uint16_t>(index));
      }
      ++index;
    }
  }

  void CPoseTracker::Refresh(const std::span<const std::uint32_t> ids, const std::span<moho::Entity* const> entities, const bool parallel)
  {
    // Last beat's changes leave first: the units holding them may leave the list below.
    for (SUnit* const unit : mTouched) {
      unit->changed.clear();
      unit->differences.clear();
      unit->reset = false;
    }
    mTouched.clear();
    // Last beat's units merged with this beat's, both by id: a unit seen before keeps what its clients hold. Most
    // beats the units are last beat's: then the list stays as it is.
    bool same = ids.size() == mUnits.size();
    for (std::size_t i = 0; same && i < ids.size(); ++i) {
      same = mUnits[i]->id == ids[i] && mUnits[i]->entity == entities[i];
    }
    if (!same) {
      Merge(ids, entities);
    }
    ReadAll(parallel);
    mNext.clear(); // the units that left, freed now that nothing of this beat points at them
  }

  void CPoseTracker::Merge(const std::span<const std::uint32_t> ids, const std::span<moho::Entity* const> entities)
  {
    mNext.clear();
    std::vector<std::unique_ptr<SUnit>> merged;
    merged.reserve(ids.size());
    const auto drop = [this](std::unique_ptr<SUnit>& unit) {
      Unindex(*unit);
      unit->dropped = true; // a mark of the last tick may still point at it: freed after the read
      mNext.push_back(std::move(unit));
    };
    std::size_t old = 0;
    for (std::size_t i = 0; i < ids.size(); ++i) {
      while (old < mUnits.size() && mUnits[old]->id < ids[i]) {
        drop(mUnits[old++]); // gone
      }
      if (old < mUnits.size() && mUnits[old]->id == ids[i] && mUnits[old]->entity == entities[i]) {
        merged.push_back(std::move(mUnits[old++])); // a pointer: the unit and its hook state keep their addresses
        continue;
      }
      if (old < mUnits.size() && mUnits[old]->id == ids[i]) {
        drop(mUnits[old++]); // the id is another entity's now
      }
      auto unit = std::make_unique<SUnit>();
      unit->id = ids[i];
      unit->entity = entities[i];
      unit->unit = entities[i]->IsUnit();
      mNewUnits.push_back(unit.get());
      merged.push_back(std::move(unit));
    }
    while (old < mUnits.size()) {
      drop(mUnits[old++]);
    }
    mUnits.swap(merged);
  }

  void CPoseTracker::ReadAll(const bool parallel)
  {
    // #118: only the units the hook marked, the new ones and a sixteenth of all (the sweep: what the hook can't see,
    // such as a new actor or a bone a script hid between updates). The first beat reads every unit.
    const std::uint32_t beat = static_cast<std::uint32_t>(mBeats);
    const std::uint32_t stamp = beat + 1u;
    mWork.clear();
    const std::size_t marks = std::min(mMarkedCount.exchange(0u, std::memory_order_relaxed), mMarked.size());
    for (std::size_t i = 0; i < marks; ++i) {
      SUnit* const unit = mMarked[i];
      if (unit != nullptr && !unit->dropped && unit->visited != stamp) {
        unit->visited = stamp;
        mWork.push_back({unit, true});
      } else if (unit != nullptr && unit->hook != nullptr) {
        unit->hook->queued = false;
      }
    }
    for (SUnit* const unit : mNewUnits) {
      if (unit->visited != stamp) {
        unit->visited = stamp;
        mWork.push_back({unit, false});
      }
    }
    mNewUnits.clear();
    const std::size_t count = mUnits.size();
    const std::size_t share = mFirstRead ? 0u : beat % kSweepBeats;
    const std::size_t begin = mFirstRead ? 0u : count * share / kSweepBeats;
    const std::size_t end = mFirstRead ? count : count * (share + 1u) / kSweepBeats;
    mFirstRead = false;
    for (std::size_t i = begin; i < end; ++i) {
      SUnit* const unit = mUnits[i].get();
      if (unit->visited != stamp) {
        unit->visited = stamp;
        mWork.push_back({unit, false});
      }
    }

    std::atomic<std::size_t> changed{0};
    std::mutex lock;
    std::vector<SUnit*> reindex; // units whose index entry must follow their actor (few a beat)
    const auto read = [this, &changed, &lock, &reindex](const std::size_t from, const std::size_t to) {
      std::size_t chunkChanged = 0;
      thread_local std::vector<SUnit*> chunkTouched;
      thread_local std::vector<SUnit*> chunkReindex;
      chunkTouched.clear();
      chunkReindex.clear();
      for (std::size_t i = from; i < to; ++i) {
        SUnit& unit = *mWork[i].unit;
        if (mWork[i].marked) {
          TakeMarks(unit);
        } else {
          ReadUnit(unit);
        }
        chunkChanged += unit.changed.size();
        if (!unit.changed.empty() || unit.reset) {
          chunkTouched.push_back(&unit);
        }
        if (mHooked && unit.hook != nullptr && unit.hook->indexedUnder != (unit.sent.empty() ? nullptr : unit.actor)) {
          chunkReindex.push_back(&unit);
        }
      }
      changed.fetch_add(chunkChanged, std::memory_order_relaxed);
      if (!chunkTouched.empty() || !chunkReindex.empty()) {
        const std::lock_guard<std::mutex> guard(lock);
        mTouched.insert(mTouched.end(), chunkTouched.begin(), chunkTouched.end());
        reindex.insert(reindex.end(), chunkReindex.begin(), chunkReindex.end());
      }
    };
    constexpr std::size_t kGrain = 32;
    if (parallel && mWork.size() > kGrain) {
      moho::CSimWorkerPool::Get().ParallelFor(mWork.size(), kGrain, read);
    } else {
      read(0u, mWork.size());
    }
    // Before the next tick, whose pose jobs read the index: new units in, changed actors moved, poseless ones out.
    for (SUnit* const unit : reindex) {
      Unindex(*unit);
      if (!unit->sent.empty() && unit->actor != nullptr) {
        mByActor[unit->actor] = unit->hook.get();
        unit->hook->indexedUnder = unit->actor;
        unit->hook->owner = unit;
      }
    }
    if (mMarked.size() < mUnits.size()) {
      mMarked.resize(mUnits.size()); // a unit is marked at most once a tick
    }
    mChangedBones = changed.load(std::memory_order_relaxed);
    mTotalChangedBones += mChangedBones;
    mTotalHookedUnits += marks;
    ++mBeats;
  }

  std::size_t CPoseTracker::PosedUnits() const noexcept
  {
    std::size_t posed = 0;
    for (const std::unique_ptr<SUnit>& unit : mUnits) {
      posed += unit->sent.empty() ? 0u : 1u;
    }
    return posed;
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
      while (unitAt < mUnits.size() && mUnits[unitAt]->id < id) {
        ++unitAt;
      }
      if (unitAt == mUnits.size() || mUnits[unitAt]->id != id) {
        continue; // not a unit this beat
      }
      const SUnit& unit = *mUnits[unitAt];
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
