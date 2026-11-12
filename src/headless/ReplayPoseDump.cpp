#include "headless/ReplayPoseDump.h"

#include <algorithm>
#include <cmath>
#include <utility>

#include "moho/animation/CAniPose.h"
#include "moho/entity/REntityBlueprint.h"
#include "moho/sim/SimDriver.h"
#include "moho/unit/core/Unit.h"
#include "remote/ContentTables.h"
#include "remote/ViewLanes.h"
#include "remote/wire/BitStream.h"

// Engine addition, server mode: see ReplayPoseDump.h.

namespace faf::headless
{
  namespace
  {
    constexpr double kOverDistance = 0.05; // world units: a drawn bone this far off is a visible difference
    constexpr double kOverDegrees = 2.0;
    // The poses' world transforms this far apart: the cause is where they stand (above the position quantiser's
    // 1/64 a side, up to 0.027 across).
    constexpr double kWorldCause = 0.03;
    constexpr float kSamples[3] = {0.0f, 0.5f, 1.0f};

    [[nodiscard]] bool IsUnitId(
      const std::uint32_t id
    ) noexcept
    {
      return (id >> 28u) == 0u; // entity family 0: units (they keep their sim ids in every view)
    }

    [[nodiscard]] double Distance(
      const float* const a,
      const float* const b
    ) noexcept
    {
      const double x = static_cast<double>(a[0]) - b[0];
      const double y = static_cast<double>(a[1]) - b[1];
      const double z = static_cast<double>(a[2]) - b[2];
      return std::sqrt(x * x + y * y + z * z);
    }

    [[nodiscard]] double Distance(
      const Wm3::Vec3f& a,
      const Wm3::Vec3f& b
    ) noexcept
    {
      const float pa[3] = {a.x, a.y, a.z};
      const float pb[3] = {b.x, b.y, b.z};
      return Distance(pa, pb);
    }

    /** Degrees between two rotations (w, x, y, z), either sign. */
    [[nodiscard]] double Degrees(
      const float* const a,
      const float* const b
    ) noexcept
    {
      const double na = std::sqrt(
        static_cast<double>(a[0]) * a[0] + static_cast<double>(a[1]) * a[1] + static_cast<double>(a[2]) * a[2] +
        static_cast<double>(a[3]) * a[3]
      );
      const double nb = std::sqrt(
        static_cast<double>(b[0]) * b[0] + static_cast<double>(b[1]) * b[1] + static_cast<double>(b[2]) * b[2] +
        static_cast<double>(b[3]) * b[3]
      );
      if (na <= 0.0 || nb <= 0.0) {
        return 0.0;
      }
      double dot = (static_cast<double>(a[0]) * b[0] + static_cast<double>(a[1]) * b[1] +
                    static_cast<double>(a[2]) * b[2] + static_cast<double>(a[3]) * b[3]) /
        (na * nb);
      dot = std::min(1.0, std::fabs(dot));
      return 2.0 * std::acos(dot) * 180.0 / 3.14159265358979323846;
    }

    void Store(
      const moho::VTransform& transform,
      CReplayPoseDump::SDrawnBone& out
    ) noexcept
    {
      out.pos[0] = transform.pos_.x;
      out.pos[1] = transform.pos_.y;
      out.pos[2] = transform.pos_.z;
      out.rot[0] = transform.orient_.w;
      out.rot[1] = transform.orient_.x;
      out.rot[2] = transform.orient_.y;
      out.rot[3] = transform.orient_.z;
    }

    [[nodiscard]] std::size_t BoneCount(
      const moho::CAniPose& pose
    ) noexcept
    {
      return static_cast<std::size_t>(pose.mBones.end() - pose.mBones.begin());
    }
  } // namespace

  CReplayPoseDump::CReplayPoseDump(
    std::string prefix,
    const std::int32_t army,
    const float mapSizeX,
    const float mapSizeZ
  )
    : mPrefix(std::move(prefix))
    , mArmy(army)
    , mMapSizeX(mapSizeX)
    , mMapSizeZ(mapSizeZ)
  {
    mBeatsFile = std::fopen((mPrefix + ".beats.csv").c_str(), "w");
    if (mBeatsFile != nullptr) {
      std::fprintf(
        mBeatsFile,
        "beat,both,lockstep_only,client_only,posed,over_world,over_bones,over_blend,same_pose_only_client,"
        "max_entity,max_drawn,max_drawn_deg,max_world,max_local\n"
      );
    }
  }

  CReplayPoseDump::~CReplayPoseDump()
  {
    (void)Finish();
  }

  void CReplayPoseDump::SSession::Apply(
    const moho::SSyncData& packet
  )
  {
    // As `CWldSession` takes a beat: entity updates move the transforms, unit updates replace the two poses (a user
    // unit keeps the last pair it was given until the next unit update).
    for (const moho::SEntityVariableUpdateEntry& update : packet.mEntityUpdates) {
      const auto id = static_cast<std::uint32_t>(update.mEntityId);
      if (!IsUnitId(id)) {
        continue;
      }
      SHeldUnit& unit = units[id];
      unit.last = update.mVariableData.mLastTransform;
      unit.cur = update.mVariableData.mCurTransform;
      unit.hasTransforms = true;
    }
    for (const moho::SUnitVariableUpdateEntry& update : packet.mUnitUpdates) {
      const auto id = static_cast<std::uint32_t>(update.mEntityId);
      if (!IsUnitId(id)) {
        continue;
      }
      SHeldUnit& unit = units[id];
      unit.prior = update.mVariableData.mPriorSharedPose;
      unit.pose = update.mVariableData.mSharedPose;
      ++unit.updates;
    }
    for (const moho::EntId id : packet.mDeleteIds) {
      units.erase(static_cast<std::uint32_t>(id));
    }
    for (const moho::EntId id : packet.mEraseIds) {
      units.erase(static_cast<std::uint32_t>(id));
    }
  }

  void CReplayPoseDump::QueueView(
    moho::RRuleGameRules& rules,
    const std::uint32_t beat,
    const std::span<const std::uint8_t> own,
    const std::span<const std::uint8_t> team,
    const std::span<const std::uint8_t> poses,
    const bool hasPoses
  )
  {
    SQueuedView view;
    view.beat = beat;
    view.own.assign(own.begin(), own.end());
    view.team.assign(team.begin(), team.end());
    view.poses.assign(poses.begin(), poses.end());
    view.hasPoses = hasPoses;
    const std::lock_guard<std::mutex> lock(mQueueLock);
    mRules = &rules;
    mQueued.push_back(std::move(view));
  }

  void CReplayPoseDump::ApplyQueued()
  {
    std::vector<SQueuedView> queued;
    {
      const std::lock_guard<std::mutex> lock(mQueueLock);
      queued.swap(mQueued);
    }
    for (const SQueuedView& view : queued) {
      ApplyView(view);
    }
  }

  void CReplayPoseDump::ApplyView(
    const SQueuedView& view
  )
  {
    if (mRules == nullptr) {
      return;
    }
    if (!mClient) {
      // `CServerViewClient`'s constructor, with this army.
      mClient = std::make_unique<SClient>();
      SClient& client = *mClient;
      client.codec = remote::MakeViewCodec(mMapSizeX, mMapSizeZ);
      const remote::wire::SContentTables tables = remote::BuildContentTables(*mRules);
      client.rebuilder = std::make_unique<remote::client::CSyncRebuilder>(
        client.codec, remote::client::ResolveBlueprints(*mRules, tables), remote::client::ResolveMeshes(*mRules, tables)
      );
      client.rebuilder->SetRules(mRules);
      client.rebuilder->SetNoSim();
      client.tables = std::make_unique<remote::wire::CSessionTableReaders>();
      client.rebuilder->SetSessionTables(client.tables.get());
      client.merger.SetArmy(mArmy);
    }
    SClient& client = *mClient;
    ++client.views;
    client.poseBytes += view.poses.size();

    // `CServerViewClient::Apply`: the pose lane, then the frames.
    moho::SSyncData packet{};
    packet.mCurBeat = static_cast<std::int32_t>(view.beat);
    packet.mCurTick = static_cast<std::int32_t>(view.beat);
    packet.mFocusArmy = mArmy;
    client.poses.clear();
    if (view.hasPoses) {
      remote::wire::BitReader reader(view.poses);
      if (!remote::wire::DecodePoseLane(reader, client.poses)) {
        client.poses.clear();
        ++client.lanesBad;
      }
    }
    client.rebuilder->SetPoseLane(view.hasPoses ? &client.poses : nullptr);
    remote::wire::SViewFrame merged;
    const bool applied = client.merger.Decode(view.own, view.team, client.codec, merged) &&
      client.rebuilder->ApplyFrame(std::move(merged), view.own.size() + view.team.size(), packet);
    client.rebuilder->SetPoseLane(nullptr);
    if (!applied) {
      ++client.framesBad;
      return;
    }
    mClientSession.Apply(packet);

    std::vector<SDrawnUnit> drawn = Snapshot(mClientSession, true);
    if (const auto found = mLockstepBeats.find(view.beat); found != mLockstepBeats.end()) {
      Compare(view.beat, found->second, drawn);
      mLockstepBeats.erase(found);
    } else {
      mClientBeats[view.beat] = std::move(drawn);
    }
  }

  void CReplayPoseDump::OnLockstepPacket(
    const moho::SSyncData& packet
  )
  {
    const std::lock_guard<std::mutex> lock(mLock);
    if (mFinished || packet.mCurBeat < 0) {
      return;
    }
    mLockstep.Apply(packet);
    const auto beat = static_cast<std::uint32_t>(packet.mCurBeat);
    std::vector<SDrawnUnit> drawn = Snapshot(mLockstep, false);
    // The client's views up to this beat (the sim made them before it published this packet).
    ApplyQueued();
    if (const auto found = mClientBeats.find(beat); found != mClientBeats.end()) {
      Compare(beat, drawn, found->second);
      mClientBeats.erase(found);
    } else {
      mLockstepBeats[beat] = std::move(drawn);
    }
    // A beat one side never gets (a view that didn't apply) is dropped once both have moved well past it.
    while (!mLockstepBeats.empty() && mLockstepBeats.begin()->first + 64u < beat) {
      mLockstepBeats.erase(mLockstepBeats.begin());
    }
    while (!mClientBeats.empty() && mClientBeats.begin()->first + 64u < beat) {
      mClientBeats.erase(mClientBeats.begin());
    }
  }

  std::vector<CReplayPoseDump::SDrawnUnit> CReplayPoseDump::Snapshot(
    const SSession& session,
    const bool client
  ) const
  {
    std::vector<SDrawnUnit> out;
    out.reserve(session.units.size());
    for (const auto& [id, unit] : session.units) {
      if (!unit.hasTransforms) {
        continue;
      }
      SDrawnUnit& drawn = out.emplace_back();
      drawn.id = id;
      drawn.last = unit.last;
      drawn.cur = unit.cur;
      drawn.hasTransforms = true;
      if (client && mClient) {
        remote::client::CSyncRebuilder::SHeldView held;
        if (mClient->rebuilder->FindHeld(id, false, held) && held.blueprint != nullptr) {
          drawn.blueprint = held.blueprint->mBlueprintId.c_str();
        }
      }
      if (!unit.pose || !unit.prior) {
        continue;
      }
      const moho::CAniPose& start = *unit.prior;
      const moho::CAniPose& end = *unit.pose;
      drawn.hasPose = true;
      drawn.samePose = unit.prior.get() == unit.pose.get();
      drawn.priorWorld = start.mLocalTransform;
      drawn.poseWorld = end.mLocalTransform;
      // A blend into a pose of our own (the mesh's `curPose`), its composites worked out there: the runtimes' poses
      // are only read.
      moho::CAniPose scratch(end.GetSkeleton(), end.mScale);
      const std::size_t count = std::min({BoneCount(start), BoneCount(end), BoneCount(scratch)});
      drawn.bones = static_cast<std::uint32_t>(count);
      drawn.drawn.resize(3u * count);
      drawn.local.resize(2u * count);
      drawn.visible.resize(count);
      for (std::size_t sample = 0; sample < 3u; ++sample) {
        scratch.InterpolatePose(kSamples[sample], &start, &end, static_cast<int>(count));
        const moho::CAniPoseBone* const bones = scratch.mBones.begin();
        for (std::size_t bone = 0; bone < count; ++bone) {
          Store(bones[bone].GetCompositeTransform(), drawn.drawn[sample * count + bone]);
        }
        if (sample != 1u) {
          scratch.SetWorldTransform(moho::VTransform());
          const std::size_t row = sample == 0u ? 0u : 1u;
          for (std::size_t bone = 0; bone < count; ++bone) {
            Store(bones[bone].GetCompositeTransform(), drawn.local[row * count + bone]);
          }
        }
      }
      const moho::CAniPoseBone* const endBones = end.mBones.begin();
      for (std::size_t bone = 0; bone < count; ++bone) {
        drawn.visible[bone] = endBones[bone].mVisible;
      }
    }
    std::sort(out.begin(), out.end(), [](const SDrawnUnit& a, const SDrawnUnit& b) {
      return a.id < b.id;
    });
    return out;
  }

  void CReplayPoseDump::Compare(
    const std::uint32_t beat,
    const std::vector<SDrawnUnit>& lockstep,
    const std::vector<SDrawnUnit>& client
  )
  {
    STotals& t = mTotals;
    ++t.beats;
    std::uint64_t both = 0;
    std::uint64_t lockstepOnly = 0;
    std::uint64_t clientOnly = 0;
    std::uint64_t posed = 0;
    std::uint64_t overWorld = 0;
    std::uint64_t overBones = 0;
    std::uint64_t overBlend = 0;
    std::uint64_t samePoseOnlyClient = 0;
    double maxEntity = 0.0;
    double maxDrawn = 0.0;
    double maxDrawnDeg = 0.0;
    double maxWorld = 0.0;
    double maxLocal = 0.0;
    auto l = lockstep.begin();
    for (const SDrawnUnit& c : client) {
      while (l != lockstep.end() && l->id < c.id) {
        ++lockstepOnly;
        ++l;
      }
      if (l == lockstep.end() || l->id != c.id) {
        ++clientOnly;
        continue;
      }
      const SDrawnUnit& s = *l;
      ++l;
      ++both;
      const double curError = Distance(c.cur.pos_, s.cur.pos_);
      const double lastError = Distance(c.last.pos_, s.last.pos_);
      const double entity = std::max(curError, lastError);
      maxEntity = std::max(maxEntity, entity);
      t.maxCurError = std::max(t.maxCurError, curError);
      t.maxLastError = std::max(t.maxLastError, lastError);
      t.curOver += curError > 0.02 ? 1u : 0u;
      t.lastOver += lastError > 0.02 ? 1u : 0u;
      if (lastError > 0.02 && mLastSamples.size() < 12u) {
        char sample[200];
        std::snprintf(
          sample,
          sizeof(sample),
          "beat %u 0x%08x %s last off %.3f (cur off %.3f, lockstep moved %.3f)",
          beat,
          c.id,
          c.blueprint != nullptr ? c.blueprint : "?",
          lastError,
          curError,
          Distance(s.cur.pos_, s.last.pos_)
        );
        mLastSamples.emplace_back(sample);
      }
      if (!c.hasPose || !s.hasPose) {
        t.noPoseClient += c.hasPose ? 0u : 1u;
        t.noPoseLockstep += s.hasPose ? 0u : 1u;
        continue;
      }
      if (c.bones != s.bones) {
        ++t.boneCountDiffers;
        continue;
      }
      ++posed;
      t.samePoseClient += c.samePose ? 1u : 0u;
      t.samePoseLockstep += s.samePose ? 1u : 0u;
      if (c.samePose && !s.samePose) {
        ++samePoseOnlyClient;
      }
      const double world =
        std::max(Distance(c.priorWorld.pos_, s.priorWorld.pos_), Distance(c.poseWorld.pos_, s.poseWorld.pos_));
      maxWorld = std::max(maxWorld, world);
      double drawnError = 0.0;
      double drawnDeg = 0.0;
      std::uint32_t worstBone = 0;
      std::uint32_t worstSample = 0;
      for (std::size_t i = 0; i < c.drawn.size(); ++i) {
        const double d = Distance(c.drawn[i].pos, s.drawn[i].pos);
        const double a = Degrees(c.drawn[i].rot, s.drawn[i].rot);
        if (d > drawnError) {
          drawnError = d;
          worstBone = static_cast<std::uint32_t>(i % c.bones);
          worstSample = static_cast<std::uint32_t>(i / c.bones);
        }
        drawnDeg = std::max(drawnDeg, a);
      }
      double localError = 0.0;
      double localDeg = 0.0;
      for (std::size_t i = 0; i < c.local.size(); ++i) {
        localError = std::max(localError, Distance(c.local[i].pos, s.local[i].pos));
        localDeg = std::max(localDeg, Degrees(c.local[i].rot, s.local[i].rot));
      }
      bool visibleDiffers = false;
      for (std::size_t i = 0; i < c.visible.size(); ++i) {
        if (c.visible[i] != s.visible[i]) {
          if (!visibleDiffers && mVisibleSamples.size() < 12u) {
            char sample[200];
            std::snprintf(
              sample,
              sizeof(sample),
              "beat %u 0x%08x %s bone %zu: client %u lockstep %u (same pose: client %d lockstep %d)",
              beat,
              c.id,
              c.blueprint != nullptr ? c.blueprint : "?",
              i,
              static_cast<unsigned>(c.visible[i]),
              static_cast<unsigned>(s.visible[i]),
              c.samePose ? 1 : 0,
              s.samePose ? 1 : 0
            );
            mVisibleSamples.emplace_back(sample);
          }
          visibleDiffers = true;
        }
      }
      t.visibleDiffers += visibleDiffers ? 1u : 0u;
      if (visibleDiffers) {
        ++mVisibleBeatsByUnit[c.id];
      }
      maxDrawn = std::max(maxDrawn, drawnError);
      maxDrawnDeg = std::max(maxDrawnDeg, drawnDeg);
      maxLocal = std::max(maxLocal, localError);
      t.maxLocalAngle = std::max(t.maxLocalAngle, localDeg);
      static constexpr double kBuckets[7] = {0.001, 0.01, 0.05, 0.1, 0.5, 1.0, 5.0};
      std::size_t bucket = 0;
      while (bucket < 7u && drawnError >= kBuckets[bucket]) {
        ++bucket;
      }
      ++t.drawnHistogram[bucket];
      const std::string blueprint = c.blueprint != nullptr ? c.blueprint : "?";
      SBlueprintCounts& counts = mByBlueprint[blueprint];
      ++counts.unitBeats;
      counts.maxError = std::max(counts.maxError, drawnError);
      const bool over = drawnError > kOverDistance || drawnDeg > kOverDegrees;
      if (
        mCameraHalf > 0.0f && std::fabs(c.cur.pos_.x - mCameraX) <= mCameraHalf &&
        std::fabs(c.cur.pos_.z - mCameraZ) <= mCameraHalf
      ) {
        ++t.onScreen;
        t.onScreenOver += over ? 1u : 0u;
        t.maxOnScreenError = std::max(t.maxOnScreenError, drawnError);
      }
      if (over) {
        if (world > kWorldCause) {
          ++overWorld;
          ++counts.overWorld;
        } else if (localError > kOverDistance || localDeg > kOverDegrees) {
          ++overBones;
          ++counts.overBones;
        } else {
          ++overBlend;
          ++counts.overBlend;
        }
      }
      // The largest drawn errors (a min-heap on the error).
      SWorst worst;
      worst.error = drawnError;
      worst.angle = drawnDeg;
      worst.world = world;
      worst.local = localError;
      worst.beat = beat;
      worst.id = c.id;
      worst.bone = worstBone;
      worst.sample = worstSample;
      worst.samePoseClient = c.samePose;
      worst.samePoseLockstep = s.samePose;
      worst.blueprint = c.blueprint;
      const auto greater = [](const SWorst& a, const SWorst& b) {
        return a.error > b.error;
      };
      if (mWorst.size() < kWorstKept) {
        mWorst.push_back(worst);
        std::push_heap(mWorst.begin(), mWorst.end(), greater);
      } else if (drawnError > mWorst.front().error) {
        std::pop_heap(mWorst.begin(), mWorst.end(), greater);
        mWorst.back() = worst;
        std::push_heap(mWorst.begin(), mWorst.end(), greater);
      }
    }
    lockstepOnly += static_cast<std::uint64_t>(lockstep.end() - l);

    t.unitBeats += both;
    t.posedUnitBeats += posed;
    t.lockstepOnly += lockstepOnly;
    t.clientOnly += clientOnly;
    t.overWorld += overWorld;
    t.overBones += overBones;
    t.overBlend += overBlend;
    t.samePoseOnlyClient += samePoseOnlyClient;
    t.maxEntityError = std::max(t.maxEntityError, maxEntity);
    t.maxDrawnError = std::max(t.maxDrawnError, maxDrawn);
    t.maxDrawnAngle = std::max(t.maxDrawnAngle, maxDrawnDeg);
    t.maxWorldError = std::max(t.maxWorldError, maxWorld);
    t.maxLocalError = std::max(t.maxLocalError, maxLocal);
    if (mBeatsFile != nullptr) {
      std::fprintf(
        mBeatsFile,
        "%u,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%llu,%.4f,%.4f,%.3f,%.4f,%.4f\n",
        beat,
        static_cast<unsigned long long>(both),
        static_cast<unsigned long long>(lockstepOnly),
        static_cast<unsigned long long>(clientOnly),
        static_cast<unsigned long long>(posed),
        static_cast<unsigned long long>(overWorld),
        static_cast<unsigned long long>(overBones),
        static_cast<unsigned long long>(overBlend),
        static_cast<unsigned long long>(samePoseOnlyClient),
        maxEntity,
        maxDrawn,
        maxDrawnDeg,
        maxWorld,
        maxLocal
      );
    }
  }

  std::string CReplayPoseDump::Report() const
  {
    const STotals& t = mTotals;
    std::string text;
    char line[1024];
    const SClient* const client = mClient.get();
    std::snprintf(
      line,
      sizeof(line),
      "pose dump army %d: %llu beats compared, %llu unit-beats both hold (%llu with poses on both), %llu only "
      "lockstep's "
      "session holds (it holds every unit, seen or not), %llu only the client holds; no pose: client %llu, lockstep "
      "%llu; bone counts differ %llu; a visible flag differs %llu\n",
      mArmy,
      static_cast<unsigned long long>(t.beats),
      static_cast<unsigned long long>(t.unitBeats),
      static_cast<unsigned long long>(t.posedUnitBeats),
      static_cast<unsigned long long>(t.lockstepOnly),
      static_cast<unsigned long long>(t.clientOnly),
      static_cast<unsigned long long>(t.noPoseClient),
      static_cast<unsigned long long>(t.noPoseLockstep),
      static_cast<unsigned long long>(t.boneCountDiffers),
      static_cast<unsigned long long>(t.visibleDiffers)
    );
    text += line;
    std::snprintf(
      line,
      sizeof(line),
      "  client: %llu views, %llu frames didn't apply, %llu pose lanes didn't decode, pose lane %.2f KB/s at 10 beats "
      "a second\n",
      client != nullptr ? static_cast<unsigned long long>(client->views) : 0ull,
      client != nullptr ? static_cast<unsigned long long>(client->framesBad) : 0ull,
      client != nullptr ? static_cast<unsigned long long>(client->lanesBad) : 0ull,
      client != nullptr && client->views != 0u
        ? static_cast<double>(client->poseBytes) * 10.0 / 1024.0 / static_cast<double>(client->views)
        : 0.0
    );
    text += line;
    if (client != nullptr) {
      const remote::client::SRebuildStats& stats = client->rebuilder->Stats();
      std::snprintf(
        line,
        sizeof(line),
        "  client rebuild: %llu unit updates, %llu poses made, %llu unit-beats given new bones, %llu bones applied, "
        "%llu bad, %llu lane units without a mesh\n",
        static_cast<unsigned long long>(stats.unitUpdates),
        static_cast<unsigned long long>(stats.posesMade),
        static_cast<unsigned long long>(stats.poseBeats),
        static_cast<unsigned long long>(stats.poseBonesApplied),
        static_cast<unsigned long long>(stats.poseBonesBad),
        static_cast<unsigned long long>(stats.posesWithoutMesh)
      );
      text += line;
    }
    std::snprintf(
      line,
      sizeof(line),
      "  one pose for both ends of the blend: client %llu, lockstep %llu, the client only %llu unit-beats\n",
      static_cast<unsigned long long>(t.samePoseClient),
      static_cast<unsigned long long>(t.samePoseLockstep),
      static_cast<unsigned long long>(t.samePoseOnlyClient)
    );
    text += line;
    std::snprintf(
      line,
      sizeof(line),
      "  max errors: transforms %.4f, drawn bones %.4f (%.2f deg), the poses' world transforms %.4f, bones under them "
      "%.4f (%.2f deg)\n",
      t.maxEntityError,
      t.maxDrawnError,
      t.maxDrawnAngle,
      t.maxWorldError,
      t.maxLocalError,
      t.maxLocalAngle
    );
    text += line;
    std::snprintf(
      line,
      sizeof(line),
      "  unit-beats by largest drawn bone error: <0.001 %llu, <0.01 %llu, <0.05 %llu, <0.1 %llu, <0.5 %llu, <1 %llu, "
      "<5 %llu, more %llu\n",
      static_cast<unsigned long long>(t.drawnHistogram[0]),
      static_cast<unsigned long long>(t.drawnHistogram[1]),
      static_cast<unsigned long long>(t.drawnHistogram[2]),
      static_cast<unsigned long long>(t.drawnHistogram[3]),
      static_cast<unsigned long long>(t.drawnHistogram[4]),
      static_cast<unsigned long long>(t.drawnHistogram[5]),
      static_cast<unsigned long long>(t.drawnHistogram[6]),
      static_cast<unsigned long long>(t.drawnHistogram[7])
    );
    text += line;
    std::snprintf(
      line,
      sizeof(line),
      "  over %.2f units or %.0f deg: %llu unit-beats where the poses stand elsewhere (world transforms > %.2f), %llu "
      "where the bones differ, %llu in the blend only\n",
      kOverDistance,
      kOverDegrees,
      static_cast<unsigned long long>(t.overWorld),
      kWorldCause,
      static_cast<unsigned long long>(t.overBones),
      static_cast<unsigned long long>(t.overBlend)
    );
    text += line;
    std::snprintf(
      line,
      sizeof(line),
      "  transforms: mCurTransform max %.4f, %llu unit-beats over 0.02; mLastTransform max %.4f, %llu over 0.02\n",
      t.maxCurError,
      static_cast<unsigned long long>(t.curOver),
      t.maxLastError,
      static_cast<unsigned long long>(t.lastOver)
    );
    text += line;
    for (const std::string& sample : mLastSamples) {
      text += "    " + sample + "\n";
    }
    if (!mVisibleBeatsByUnit.empty()) {
      std::uint32_t most = 0;
      std::uint64_t sum = 0;
      std::uint64_t one = 0;
      for (const auto& [id, beats] : mVisibleBeatsByUnit) {
        most = std::max(most, beats);
        sum += beats;
        one += beats == 1u ? 1u : 0u;
      }
      std::snprintf(
        line,
        sizeof(line),
        "  visible flags differ on %zu units: %.1f beats each on average, %llu for one beat only, the most %u\n",
        mVisibleBeatsByUnit.size(),
        static_cast<double>(sum) / static_cast<double>(mVisibleBeatsByUnit.size()),
        static_cast<unsigned long long>(one),
        most
      );
      text += line;
    }
    for (const std::string& sample : mVisibleSamples) {
      text += "    visible: " + sample + "\n";
    }
    if (mCameraHalf > 0.0f) {
      std::snprintf(
        line,
        sizeof(line),
        "  inside the camera square (%.0f, %.0f) +-%.0f: %llu unit-beats, %llu over the limit, max drawn error %.4f\n",
        mCameraX,
        mCameraZ,
        mCameraHalf,
        static_cast<unsigned long long>(t.onScreen),
        static_cast<unsigned long long>(t.onScreenOver),
        t.maxOnScreenError
      );
      text += line;
    }
    // The blueprints with the most unit-beats over the limit.
    std::vector<std::pair<std::string, SBlueprintCounts>> blueprints(mByBlueprint.begin(), mByBlueprint.end());
    std::sort(blueprints.begin(), blueprints.end(), [](const auto& a, const auto& b) {
      const std::uint64_t ao = a.second.overWorld + a.second.overBones + a.second.overBlend;
      const std::uint64_t bo = b.second.overWorld + b.second.overBones + b.second.overBlend;
      return ao != bo ? ao > bo : a.second.unitBeats > b.second.unitBeats;
    });
    text += "  by blueprint (unit-beats, over: world / bones / blend, max error):";
    for (std::size_t i = 0; i < blueprints.size() && i < 15u; ++i) {
      const SBlueprintCounts& counts = blueprints[i].second;
      std::snprintf(
        line,
        sizeof(line),
        " %s %llu %llu/%llu/%llu %.3f;",
        blueprints[i].first.c_str(),
        static_cast<unsigned long long>(counts.unitBeats),
        static_cast<unsigned long long>(counts.overWorld),
        static_cast<unsigned long long>(counts.overBones),
        static_cast<unsigned long long>(counts.overBlend),
        counts.maxError
      );
      text += line;
    }
    text += "\n";
    return text;
  }

  std::string CReplayPoseDump::Finish()
  {
    {
      const std::lock_guard<std::mutex> lock(mLock);
      if (mFinished) {
        return mResult;
      }
      ApplyQueued();
      mFinished = true;
      mResult = Report();
    }
    if (mBeatsFile != nullptr) {
      std::fclose(mBeatsFile);
      mBeatsFile = nullptr;
    }
    if (std::FILE* const worst = std::fopen((mPrefix + ".worst.csv").c_str(), "w"); worst != nullptr) {
      std::vector<SWorst> sorted = mWorst;
      std::sort(sorted.begin(), sorted.end(), [](const SWorst& a, const SWorst& b) {
        return a.error > b.error;
      });
      std::fprintf(worst, "beat,id,blueprint,bone,sample,error,deg,world,local,same_pose_client,same_pose_lockstep\n");
      for (const SWorst& w : sorted) {
        std::fprintf(
          worst,
          "%u,0x%08x,%s,%u,%u,%.4f,%.2f,%.4f,%.4f,%d,%d\n",
          w.beat,
          w.id,
          w.blueprint != nullptr ? w.blueprint : "?",
          w.bone,
          w.sample,
          w.error,
          w.angle,
          w.world,
          w.local,
          w.samePoseClient ? 1 : 0,
          w.samePoseLockstep ? 1 : 0
        );
      }
      std::fclose(worst);
    }
    if (std::FILE* const summary = std::fopen((mPrefix + ".summary.txt").c_str(), "w"); summary != nullptr) {
      std::fputs(mResult.c_str(), summary);
      std::fclose(summary);
    }
    // The sessions' poses (the sim's among them) are released here, on this thread.
    mLockstep.units.clear();
    mClientSession.units.clear();
    mLockstepBeats.clear();
    mClientBeats.clear();
    return mResult;
  }
} // namespace faf::headless
