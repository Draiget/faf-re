#include "headless/ReplayEffectDump.h"

#include <algorithm>
#include <atomic>
#include <cmath>
#include <map>
#include <utility>

#include "moho/effects/rendering/IEffect.h"
#include "moho/effects/rendering/IEffectManager.h"
#include "moho/entity/Entity.h"
#include "moho/entity/EntityDb.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/Sim.h"
#include "moho/particles/SParticleBuffer.h"
#include "moho/sim/SimDriver.h"
#include "remote/ContentTables.h"
#include "remote/ViewLanes.h"
#include "remote/wire/BitStream.h"
#include "server/EffectOpRecorder.h"

// Engine addition, server mode: see ReplayEffectDump.h.

namespace faf::headless
{
  namespace
  {
    std::atomic<CReplayEffectDump*> sDump{nullptr};

    [[nodiscard]] bool IsCreate(
      const moho::EEffectOp op
    ) noexcept
    {
      return op <= moho::EEffectOp::AttachBeamEntityToEntity;
    }

    [[nodiscard]] const char* EndName(
      const CReplayEffectDump::EEnd end
    ) noexcept
    {
      static constexpr const char* kNames[] = {"alive", "lifetime", "entity", "not-visible", "script", "other"};
      const auto index = static_cast<std::size_t>(end);
      return index < std::size(kNames) ? kNames[index] : "?";
    }

    [[nodiscard]] std::uint64_t Emitted(
      const CReplayEffectDump::SRecord& record
    ) noexcept
    {
      return record.particles + record.trails + record.beams;
    }

    /** "v*n v*n ...": the per-beat counts, run-length. */
    [[nodiscard]] std::string RunLength(
      const std::vector<std::uint16_t>& counts
    )
    {
      std::string out;
      for (std::size_t at = 0; at < counts.size();) {
        std::size_t run = 1;
        while (at + run < counts.size() && counts[at + run] == counts[at]) {
          ++run;
        }
        if (!out.empty()) {
          out += ' ';
        }
        out += std::to_string(counts[at]);
        if (run > 1u) {
          out += '*';
          out += std::to_string(run);
        }
        at += run;
      }
      return out;
    }

    /** At most this many beats per effect are kept beat by beat (totals go on). */
    constexpr std::size_t kPerBeatCap = 600;
  } // namespace

  CReplayEffectDump::CReplayEffectDump(
    std::string prefix,
    const std::int32_t army,
    server::CEffectOpRecorder& recorder
  )
    : mPrefix(std::move(prefix))
    , mArmy(army)
    , mRecorder(recorder)
  {
    sDump.store(this);
    moho::gEffectTickObserver = this;
  }

  CReplayEffectDump::~CReplayEffectDump()
  {
    if (moho::gEffectTickObserver == this) {
      moho::gEffectTickObserver = nullptr;
    }
    CReplayEffectDump* self = this;
    (void)sDump.compare_exchange_strong(self, nullptr);
    // The hosted effects go before the rebuilder whose entities they follow.
    if (mHost) {
      mHost->applier.reset();
      mHost->hosted.reset();
    }
  }

  fa::vector<moho::GeomCamera3> CReplayEffectDump::EverywhereCamera()
  {
    // As faf_server_probe's `--host-effects`: no frustum plane, and a zero viewport puts every point at depth 0.
    moho::GeomCamera3 everywhere;
    everywhere.solid2 = moho::CGeomSolid3{};
    everywhere.viewport = moho::VMatrix4{};
    fa::vector<moho::GeomCamera3> cameras;
    cameras.push_back(everywhere);
    return cameras;
  }

  void CReplayEffectDump::Hook(
    const moho::EEffectOp op,
    const moho::SEffectOpArgs& args
  )
  {
    server::CEffectOpRecorder::Hook(op, args);
    if (CReplayEffectDump* const dump = sDump.load(); dump != nullptr) {
      dump->OnSimOp(op, args);
    }
  }

  std::uint32_t CReplayEffectDump::Name(
    const char* const name
  )
  {
    if (name == nullptr || *name == '\0') {
      return 0u;
    }
    const auto [at, added] = mNameIds.try_emplace(name, static_cast<std::uint32_t>(mNames.size()));
    if (added) {
      mNames.emplace_back(name);
    }
    return at->second;
  }

  void CReplayEffectDump::OnSimOp(
    const moho::EEffectOp op,
    const moho::SEffectOpArgs& args
  )
  {
    if (op == moho::EEffectOp::CreateLightParticle) {
      const std::lock_guard<std::recursive_mutex> lock(mLock);
      ++mLockstep.lights; // made here: with a focus army, `CreateLightParticleIntel` makes only what it detects
      return;
    }
    if (!IsCreate(op) && op != moho::EEffectOp::DestroyByScript) {
      return;
    }
    std::uint32_t id = 0;
    if (args.effect == nullptr || !mRecorder.IdOf(args.effect, id)) {
      return;
    }
    const std::lock_guard<std::recursive_mutex> lock(mLock);
    if (mFinished) {
      return;
    }
    if (op == moho::EEffectOp::DestroyByScript) {
      (void)mScriptDestroyed.insert(id);
      return;
    }
    SRecord record;
    record.op = op;
    if (args.blueprint != nullptr) {
      record.blueprint = Name(args.blueprint);
    } else if (args.beam != nullptr) {
      // A beam from create parameters has no blueprint: its texture names it.
      record.blueprint = Name(("params:" + std::string(args.beam->mTexture.c_str())).c_str());
    }
    record.army = args.army;
    record.entity = args.entity;
    record.bone = args.bone;
    if (args.beam != nullptr) {
      record.army = args.beam->mAttachArmyIndex;
      record.entity = moho::EffectOpEntity(args.beam->mAttachEntity);
      record.bone = args.beam->mAttachBoneIndex;
    }
    record.created = mLockstep.beat;
    if (mSim != nullptr && record.entity >= 0 && mSim->mEntityDB != nullptr) {
      moho::Entity* const entity = mSim->mEntityDB->FindEntityById(static_cast<std::uint32_t>(record.entity));
      record.onCollisionBeam = entity != nullptr && entity->IsCollisionBeam() != nullptr;
    }
    mLockstep.records[id] = std::move(record);
    mLockstep.ids[args.effect] = id;
  }

  CReplayEffectDump::SRecord* CReplayEffectDump::Find(
    const moho::IEffect& effect,
    bool& client
  )
  {
    const moho::IEffectManager* const manager = effect.GetManager();
    client = manager != nullptr && manager->AsHosted() != nullptr;
    std::uint32_t id = 0;
    SSide& side = client ? mClient : mLockstep;
    if (client) {
      if (!mHost || !mHost->hosted || !mHost->hosted->ServerId(&effect, id)) {
        return nullptr;
      }
    } else {
      const auto found = mLockstep.ids.find(&effect);
      if (found == mLockstep.ids.end()) {
        return nullptr;
      }
      id = found->second;
    }
    const auto record = side.records.find(id);
    return record != side.records.end() ? &record->second : nullptr;
  }

  void CReplayEffectDump::Emit(
    SRecord& record,
    const std::uint32_t beat,
    const std::uint32_t amount
  )
  {
    if (amount != 0u) {
      if (!record.emitted) {
        record.emitted = true;
        record.firstEmit = beat;
      }
      record.lastEmit = beat;
    }
    if (beat < record.created) {
      return;
    }
    const std::size_t index = beat - record.created;
    if (index >= kPerBeatCap) {
      return;
    }
    if (record.perBeat.size() <= index) {
      record.perBeat.resize(index + 1u, 0u);
    }
    const std::uint32_t sum = record.perBeat[index] + amount;
    record.perBeat[index] = static_cast<std::uint16_t>(std::min<std::uint32_t>(sum, 0xFFFFu));
  }

  void CReplayEffectDump::OnEffectTicked(
    const moho::IEffect& effect,
    const moho::SEffectTick& tick
  )
  {
    const std::lock_guard<std::recursive_mutex> lock(mLock);
    if (mFinished) {
      return;
    }
    bool client = false;
    SRecord* const record = Find(effect, client);
    if (record == nullptr) {
      return;
    }
    const std::uint32_t beat = client ? mClient.beat : mLockstep.beat;
    ++record->ticks;
    record->hidden += tick.hidden ? 1u : 0u;
    record->particles += tick.particles;
    record->trails += tick.trails;
    record->beams += tick.beams;
    Emit(*record, beat, tick.particles + tick.trails + tick.beams);
    if (!record->positioned && tick.positioned) {
      record->positioned = true;
      record->position = {tick.position[0], tick.position[1], tick.position[2]};
    }
    if (!record->hashed) {
      record->hashed = true;
      record->paramsHash = tick.paramsHash;
    }
    if (
      client && mSightChecked && tick.positioned && mSim != nullptr && mHost && mHost->hosted && mArmy >= 0 &&
      static_cast<std::size_t>(mArmy) < mSim->mArmiesList.size() && mSim->mArmiesList[mArmy] != nullptr
    ) {
      const Wm3::Vec3f point(tick.position[0], tick.position[1], tick.position[2]);
      const bool sim =
        mSim->mArmiesList[mArmy]->GetReconDB()->ReconCanDetect(point, moho::RECON_LOSNow) != moho::RECON_None;
      const bool host = mHost->hosted->FocusArmyDetects(point);
      ++mSightChecks;
      if (sim != host) {
        ++(sim ? mSightSimOnly : mSightClientOnly);
        if (mSightSamples.size() < 12u) {
          char text[200];
          std::snprintf(
            text,
            sizeof(text),
            "beat %u %s at (%.2f, %.2f, %.2f) water %.2f: sim %d client %d",
            mClient.beat,
            mNames[record->blueprint].c_str(),
            point.x,
            point.y,
            point.z,
            mHost->hosted->WaterElevationAt(point.x, point.z),
            sim ? 1 : 0,
            host ? 1 : 0
          );
          mSightSamples.emplace_back(text);
        }
      }
    }
  }

  void CReplayEffectDump::OnEffectEnding(
    const moho::IEffect& effect,
    const moho::EEffectEnd why
  )
  {
    const std::lock_guard<std::recursive_mutex> lock(mLock);
    if (mFinished) {
      return;
    }
    bool client = false;
    SRecord* const record = Find(effect, client);
    if (record == nullptr || record->destroyed) {
      return;
    }
    switch (why) {
    case moho::EEffectEnd::Lifetime:
      record->end = EEnd::Lifetime;
      break;
    case moho::EEffectEnd::EntityGone:
      record->end = EEnd::EntityGone;
      break;
    case moho::EEffectEnd::NotVisible:
      record->end = EEnd::NotVisible;
      break;
    }
    record->endingSeen = true;
  }

  void CReplayEffectDump::OnEffectDestroyed(
    const moho::IEffect& effect
  )
  {
    const std::lock_guard<std::recursive_mutex> lock(mLock);
    if (mFinished) {
      return;
    }
    bool client = false;
    SRecord* const record = Find(effect, client);
    if (record == nullptr || record->destroyed) {
      return;
    }
    SSide& side = client ? mClient : mLockstep;
    std::uint32_t id = 0;
    if (client) {
      (void)mHost->hosted->ServerId(&effect, id);
      if (mViewReplacing.erase(id) != 0u) {
        ++record->incarnations; // a create for an id the client holds: the old one goes, the new one goes on here
        return;
      }
    } else {
      id = mLockstep.ids[&effect];
    }
    record->destroyed = true;
    record->ended = side.beat;
    if (!record->endingSeen) {
      const bool script = client ? mViewScript.count(id) != 0u : mScriptDestroyed.count(id) != 0u;
      record->end = script ? EEnd::Script : EEnd::Other;
    }
    side.released.push_back(&effect);
  }

  void CReplayEffectDump::OnSimSynced(
    moho::Sim& sim
  )
  {
    const std::lock_guard<std::recursive_mutex> lock(mLock);
    const std::uint32_t beat = sim.mCurBeat;
    const std::uint32_t tick = sim.mCurTick;
    mSim = &sim;
    mRules = sim.mRules;
    mMap = sim.mMapData;
    if (mHaveOffset && tick == mLastTick) {
      // The sim didn't tick this beat (a pause, the game over): its effects didn't tick either.
      if (mUntickedBeats.size() < 20u) {
        mUntickedBeats.push_back(beat);
      }
      ++mUnticked;
    }
    mLastTick = tick;
    // The sim's effects of the next beat tick as that beat; the ones it purged this beat are gone.
    for (const moho::IEffect* const effect : mLockstep.released) {
      mLockstep.ids.erase(effect);
    }
    mLockstep.released.clear();
    mLockstep.beat = beat + 1u;
    const std::uint32_t offset = tick - beat;
    if (!mHaveOffset) {
      mHaveOffset = true;
      mFirstTickOffset = offset;
    } else if (offset != mFirstTickOffset) {
      ++mTickOffsetChanges;
    }
  }

  bool CReplayEffectDump::HoldsEntity(
    const std::int32_t id,
    const bool orRemoved
  ) const
  {
    // As `CServerViewClient::HoldsEntity`: the frame shown, or (an impact) the one before it.
    if (id < 0 || !mHost) {
      return false;
    }
    const auto key = static_cast<std::uint32_t>(id);
    if (const remote::wire::SViewFrame* const shown = mHost->rebuilder->Baseline(); shown != nullptr) {
      const auto found = std::lower_bound(
        shown->entities.begin(),
        shown->entities.end(),
        key,
        [](const remote::wire::SEntityRecord& record, const std::uint32_t at) {
        return record.id < at;
      }
      );
      if (found != shown->entities.end() && found->id == key) {
        return true;
      }
    }
    return orRemoved && std::binary_search(mHost->previousIds.begin(), mHost->previousIds.end(), key);
  }

  void CReplayEffectDump::QueueView(
    const std::uint32_t beat,
    const std::span<const std::uint8_t> own,
    const std::span<const std::uint8_t> team,
    const std::span<const std::uint8_t> grids,
    const std::span<const std::uint8_t> poses,
    const bool hasPoses,
    const std::span<const std::uint8_t> effects,
    const std::vector<remote::wire::SEffectLaneOp>& ops,
    const remote::wire::CEffectLaneReader& names
  )
  {
    SQueuedView view;
    view.beat = beat;
    view.own.assign(own.begin(), own.end());
    view.team.assign(team.begin(), team.end());
    view.grids.assign(grids.begin(), grids.end());
    view.poses.assign(poses.begin(), poses.end());
    view.hasPoses = hasPoses;
    view.effects.assign(effects.begin(), effects.end());
    view.ops = ops;
    for (const remote::wire::SEffectLaneOp& op : ops) {
      if (IsCreate(op.op) && op.blueprint != 0u) {
        if (const std::string* const name = names.Name(false, op.blueprint); name != nullptr) {
          view.names.emplace(op.blueprint, *name);
        }
      }
    }
    const std::lock_guard<std::recursive_mutex> lock(mLock);
    mQueued.push_back(std::move(view));
  }

  void CReplayEffectDump::HostQueued(
    const bool sameBeat
  )
  {
    const std::lock_guard<std::recursive_mutex> lock(mLock);
    mSightChecked = mSightChecked && (sameBeat || mQueued.empty());
    std::vector<SQueuedView> queued;
    queued.swap(mQueued);
    for (const SQueuedView& view : queued) {
      HostView(view);
    }
  }

  void CReplayEffectDump::HostView(
    const SQueuedView& view
  )
  {
    const std::uint32_t beat = view.beat;
    const std::span<const std::uint8_t> own(view.own);
    const std::span<const std::uint8_t> team(view.team);
    const std::span<const std::uint8_t> grids(view.grids);
    const std::span<const std::uint8_t> poses(view.poses);
    const bool hasPoses = view.hasPoses;
    const std::span<const std::uint8_t> effects(view.effects);
    const std::vector<remote::wire::SEffectLaneOp>& ops = view.ops;
    const std::lock_guard<std::recursive_mutex> lock(mLock);
    if (mFinished || mRules == nullptr) {
      return;
    }
    mClient.beat = beat;
    mClient.released.clear(); // the client's ids are `CClientEffects::ServerId`'s, forgotten at its purge
    ++mViews;
    mLaneBytes += effects.size();
    mLaneOps += ops.size();
    if (!mHost) {
      // `CServerViewClient`'s constructor and `HostEffects`, with this army.
      mHost = std::make_unique<SClient>();
      SClient& host = *mHost;
      host.codec = remote::MakeViewCodec(mMapSizeX, mMapSizeZ);
      const remote::wire::SContentTables tables = remote::BuildContentTables(*mRules);
      host.rebuilder = std::make_unique<remote::client::CSyncRebuilder>(
        host.codec, remote::client::ResolveBlueprints(*mRules, tables), remote::client::ResolveMeshes(*mRules, tables)
      );
      host.rebuilder->SetRules(mRules);
      host.rebuilder->SetNoSim();
      host.tables = std::make_unique<remote::wire::CSessionTableReaders>();
      host.rebuilder->SetSessionTables(host.tables.get());
      host.rebuilder->KeepRemoved(true);
      host.merger.SetArmy(mArmy);
      remote::client::SEffectHostWorld world;
      world.cameras = [](fa::vector<moho::GeomCamera3>& out) {
        out = EverywhereCamera();
      };
      moho::STIMap* const map = mMap;
      world.map = [map]() {
        return map;
      };
      host.hosted = std::make_unique<remote::client::CClientEffects>(
        *mRules, *host.rebuilder, [this](const std::int32_t id, const bool orRemoved) {
        return HoldsEntity(id, orRemoved);
      }, std::move(world)
      );
      host.applier = std::make_unique<remote::client::CEffectLaneApplier>(*host.hosted);
      remote::client::CEffectLaneApplier* const applier = host.applier.get();
      host.hosted->SetEndedHandler([applier](const std::uint32_t id) {
        applier->Ended(id);
      });
    }
    SClient& host = *mHost;

    // `CServerViewClient::Apply`: the grids and poses, the frames, then the effects lane, one tick.
    moho::SSyncData packet{};
    packet.mCurBeat = static_cast<std::int32_t>(beat);
    packet.mCurTick = static_cast<std::int32_t>(beat);
    packet.mFocusArmy = mArmy; // as the game client's driver (`CNetworkSimDriver::QueueView`)
    if (!grids.empty()) {
      remote::wire::BitReader reader(grids);
      (void)remote::wire::DecodeGridLane(reader, host.grids);
    }
    host.poses.clear();
    if (hasPoses) {
      remote::wire::BitReader reader(poses);
      if (!remote::wire::DecodePoseLane(reader, host.poses)) {
        host.poses.clear();
      }
    }
    host.rebuilder->SetPoseLane(hasPoses ? &host.poses : nullptr);
    host.previousIds.clear();
    if (
      const remote::wire::SViewFrame* const shown = host.rebuilder->Baseline(); shown != nullptr && !effects.empty()
    ) {
      host.previousIds.reserve(shown->entities.size());
      for (const remote::wire::SEntityRecord& record : shown->entities) {
        host.previousIds.push_back(record.id);
      }
    }
    remote::wire::SViewFrame merged;
    const bool applied = host.merger.Decode(own, team, host.codec, merged) &&
      host.rebuilder->ApplyFrame(std::move(merged), own.size() + team.size(), packet);
    host.rebuilder->SetPoseLane(nullptr);
    if (!applied) {
      ++host.framesBad;
      return;
    }
    const bool whole = remote::wire::PeekFrameBaseline(own) == remote::wire::kNoBaseline;

    // What the lane makes: a record per id (the first create), a new incarnation for a create on one held.
    mViewReplacing.clear();
    mViewScript.clear();
    std::vector<std::uint32_t> created;
    for (const remote::wire::SEffectLaneOp& op : ops) {
      if (op.op == moho::EEffectOp::DestroyByScript) {
        (void)mViewScript.insert(op.id);
        continue;
      }
      if (!IsCreate(op.op)) {
        continue;
      }
      created.push_back(op.id);
      const auto found = mClient.records.find(op.id);
      if (found != mClient.records.end() && !found->second.destroyed && host.hosted->Hosts(op.id)) {
        (void)mViewReplacing.insert(op.id);
        continue;
      }
      const auto name = view.names.find(op.blueprint);
      SRecord record;
      record.op = op.op;
      record.blueprint = Name(name != view.names.end() ? name->second.c_str() : nullptr);
      record.army = op.army;
      record.entity = op.entity;
      record.bone = op.bone;
      record.created = beat;
      if (found != mClient.records.end()) {
        // Sent whole again after the client dropped it: one effect, made again.
        SRecord& again = found->second;
        again.destroyed = false;
        again.end = EEnd::Alive;
        again.endingSeen = false;
        again.made = true;
        ++again.incarnations;
        continue;
      }
      const auto lockstep = mLockstep.records.find(op.id);
      if (
        lockstep != mLockstep.records.end() && op.op != moho::EEffectOp::CreateBeam &&
        lockstep->second.blueprint != record.blueprint
      ) {
        ++mNameMismatches;
      }
      mClient.records[op.id] = std::move(record);
    }

    if (host.hosted) {
      host.hosted->BeginBeat(beat, mArmy, host.grids);
    }
    if (!host.applier->Apply(effects, whole)) {
      ++host.lanesBad;
    }
    for (const std::uint32_t id : created) {
      if (const auto found = mClient.records.find(id); found != mClient.records.end() && !host.hosted->Hosts(id)) {
        SRecord& record = found->second;
        if (!record.destroyed) {
          record.made = false; // the applier skipped it (an entity, a blueprint or a name it lacks)
          record.destroyed = true;
          record.ended = beat;
          record.end = EEnd::Other;
        }
      }
    }
    mViewReplacing.clear();
    host.hosted->EndBeat(&packet);
  }

  void CReplayEffectDump::WriteSide(
    const SSide& side,
    const char* const which
  ) const
  {
    const std::string path = mPrefix + "." + which + ".csv";
    std::FILE* file = nullptr;
    if (fopen_s(&file, path.c_str(), "w") != 0 || file == nullptr) {
      return;
    }
    std::fprintf(
      file,
      "id,op,blueprint,army,entity,bone,created,ended,end,made,incarnations,ticks,hidden,particles,trails,beams,"
      "first_emit,last_emit,x,y,z,per_beat\n"
    );
    std::map<std::uint32_t, const SRecord*> ordered;
    for (const auto& [id, record] : side.records) {
      ordered.emplace(id, &record);
    }
    for (const auto& [id, record] : ordered) {
      std::fprintf(
        file,
        "%u,%s,%s,%d,%d,%d,%u,%d,%s,%d,%u,%u,%u,%llu,%llu,%llu,%u,%u,%.2f,%.2f,%.2f,%s\n",
        id,
        moho::EffectOpName(record->op),
        mNames[record->blueprint].c_str(),
        record->army,
        record->entity,
        record->bone,
        record->created,
        record->destroyed ? static_cast<int>(record->ended) : -1,
        EndName(record->end),
        record->made ? 1 : 0,
        record->incarnations,
        record->ticks,
        record->hidden,
        static_cast<unsigned long long>(record->particles),
        static_cast<unsigned long long>(record->trails),
        static_cast<unsigned long long>(record->beams),
        record->firstEmit,
        record->lastEmit,
        record->position[0],
        record->position[1],
        record->position[2],
        RunLength(record->perBeat).c_str()
      );
    }
    std::fclose(file);
  }

  std::string CReplayEffectDump::Finish()
  {
    const std::lock_guard<std::recursive_mutex> lock(mLock);
    if (mFinished) {
      return mResult;
    }
    HostQueued(false); // the last beat's view, with the pipeline
    mFinished = true;
    if (moho::gEffectTickObserver == this) {
      moho::gEffectTickObserver = nullptr;
    }
    WriteSide(mLockstep, "lockstep");
    WriteSide(mClient, "client");
    mResult = Compare();
    std::FILE* file = nullptr;
    if (fopen_s(&file, (mPrefix + ".join.txt").c_str(), "w") == 0 && file != nullptr) {
      std::fputs(mResult.c_str(), file);
      std::fclose(file);
    }
    return mResult;
  }

  std::string CReplayEffectDump::Compare() const
  {
    // Why a pair differs: the first of these that holds.
    enum ECause : std::size_t
    {
      kNotMade,        // the client's applier skipped its create
      kLater,          // sent after its create (held until the client could place it)
      kAgain,          // sent whole again (dropped, then its entity came back)
      kScriptMissed,   // lockstep's script destroyed it; the client dropped it later (the destroy didn't reach it)
      kDropped,        // the client dropped it (its entity left the view) while lockstep's went on
      kHidden,         // the visibility test said no on a different number of ticks (lifetimes follow from it)
      kEndedOtherBeat, // both ended by themselves or by script, at another beat
      kUnticked,       // alive at the end, ticked more on the client by beats the sim didn't tick
      kTicks,          // ticked a different number of times
      kRest,           // same ticks and visibility, different counts
      kCauses
    };
    static constexpr const char* kCauseNames[kCauses] = {
      "the client's applier didn't make it",
      "sent later than its create (held)",
      "sent whole again",
      "the script's destroy didn't reach the client",
      "dropped by the client while lockstep's went on",
      "visibility said no on other ticks",
      "ended at another beat",
      "ticked on beats the sim didn't tick",
      "ticked another number of times",
      "same ticks and visibility, other counts"
    };
    struct SKind
    {
      std::uint64_t lockstep = 0;
      std::uint64_t sent = 0;
      std::uint64_t same = 0;
      std::uint64_t differ = 0;
      std::uint64_t lockEmitted = 0;
      std::uint64_t clientEmitted = 0;
    };
    std::array<SKind, static_cast<std::size_t>(moho::EEffectOp::Count)> kinds{};
    std::array<std::uint64_t, kCauses> causes{};
    std::array<std::int64_t, kCauses> causeEmitted{}; // client less lockstep, summed
    // Of the pairs that differ: client less lockstep, by bucket.
    static constexpr const char* kBucketNames[] = {
      "< -100", "-100..-11", "-10..-2", "-1", "+1", "+2..+10", "+11..+100", "> +100"
    };
    std::array<std::uint64_t, std::size(kBucketNames)> buckets{};
    std::uint64_t pairs = 0;
    std::uint64_t same = 0;
    std::uint64_t notSent = 0;
    std::uint64_t notSentEmitting = 0;
    std::uint64_t notSentEmitted = 0;
    std::uint64_t lockEmitted = 0;
    std::uint64_t lockParticles = 0;
    std::uint64_t clientEmitted = 0;
    std::uint64_t clientParticles = 0;
    std::uint64_t pairedLockEmitted = 0;
    std::uint64_t pairedClientEmitted = 0;
    std::uint64_t absDifference = 0;
    std::uint64_t sameCreated = 0;
    std::uint64_t createdLater = 0;
    std::uint64_t placedElsewhere = 0;
    std::uint64_t placedElsewhereBone1Other = 0; // on bone 1 of a collision beam (its end splash)
    std::uint64_t onCollisionBeamBone1 = 0;
    std::map<std::string, std::uint64_t> elsewhereBy; // placed elsewhere, by op and what the entity is
    std::map<std::string, std::pair<std::uint64_t, std::uint64_t>> paramsBy; // by op: pairs compared, differing
    std::uint64_t positionsCompared = 0;
    std::uint64_t endPairs[static_cast<std::size_t>(EEnd::Count)][static_cast<std::size_t>(EEnd::Count)]{};
    std::map<std::string, std::pair<std::uint64_t, std::int64_t>> byBlueprint; // differing pairs, difference
    for (const auto& [id, lock] : mLockstep.records) {
      const std::uint64_t lockTotal = Emitted(lock);
      lockEmitted += lockTotal;
      lockParticles += lock.particles;
      SKind& kind = kinds[static_cast<std::size_t>(lock.op) % kinds.size()];
      ++kind.lockstep;
      kind.lockEmitted += lockTotal;
      const auto found = mClient.records.find(id);
      if (found == mClient.records.end()) {
        ++notSent;
        notSentEmitting += lockTotal != 0u ? 1u : 0u;
        notSentEmitted += lockTotal;
        continue;
      }
      const SRecord& client = found->second;
      const std::uint64_t clientTotal = Emitted(client);
      ++kind.sent;
      kind.clientEmitted += clientTotal;
      ++pairs;
      pairedLockEmitted += lockTotal;
      pairedClientEmitted += clientTotal;
      sameCreated += client.created == lock.created ? 1u : 0u;
      createdLater += client.created > lock.created ? 1u : 0u;
      ++endPairs[static_cast<std::size_t>(lock.end)][static_cast<std::size_t>(client.end)];
      onCollisionBeamBone1 += lock.onCollisionBeam && lock.bone == 1 ? 1u : 0u;
      if (lock.hashed && client.hashed && client.incarnations == 1u && client.created == lock.created) {
        const std::string what =
          lock.op == moho::EEffectOp::CreateBeam && mNames[lock.blueprint].rfind("params:", 0) == 0
          ? "CreateBeam from parameters"
          : moho::EffectOpName(lock.op);
        auto& entry = paramsBy[what];
        ++entry.first;
        entry.second += lock.paramsHash != client.paramsHash ? 1u : 0u;
      }
      if (lock.positioned && client.positioned) {
        ++positionsCompared;
        const float dx = lock.position[0] - client.position[0];
        const float dy = lock.position[1] - client.position[1];
        const float dz = lock.position[2] - client.position[2];
        if (std::sqrt(dx * dx + dy * dy + dz * dz) > 1.0f) {
          ++placedElsewhere;
          placedElsewhereBone1Other += lock.onCollisionBeam && lock.bone == 1 ? 1u : 0u;
          static constexpr const char* kFamilies[] = {"unit", "projectile", "prop", "blip", "shield", "other"};
          const std::uint32_t family =
            lock.entity >= 0 ? static_cast<std::uint32_t>(lock.entity) >> 28u : static_cast<std::uint32_t>(-1);
          const char* const on = lock.onCollisionBeam ? "a collision beam"
            : family < std::size(kFamilies)           ? kFamilies[family]
                                                      : "nothing";
          ++elsewhereBy[std::string(moho::EffectOpName(lock.op)) + " on " + on];
        }
      }
      if (clientTotal == lockTotal && client.particles == lock.particles && client.trails == lock.trails) {
        ++same;
        ++kind.same;
        continue;
      }
      ++kind.differ;
      const auto difference = static_cast<std::int64_t>(clientTotal) - static_cast<std::int64_t>(lockTotal);
      absDifference += static_cast<std::uint64_t>(difference < 0 ? -difference : difference);
      std::size_t bucket = 0;
      if (difference < -100) {
        bucket = 0;
      } else if (difference < -10) {
        bucket = 1;
      } else if (difference < -1) {
        bucket = 2;
      } else if (difference == -1) {
        bucket = 3;
      } else if (difference == 1) {
        bucket = 4;
      } else if (difference <= 10) {
        bucket = 5;
      } else if (difference <= 100) {
        bucket = 6;
      } else {
        bucket = 7;
      }
      ++buckets[bucket];
      ECause cause = kRest;
      if (!client.made) {
        cause = kNotMade;
      } else if (client.created > lock.created) {
        cause = kLater;
      } else if (client.incarnations > 1u) {
        cause = kAgain;
      } else if (
        lock.end == EEnd::Script && client.end == EEnd::Other && client.destroyed && client.ended > lock.ended
      ) {
        cause = kScriptMissed;
      } else if (client.end == EEnd::Other && (!lock.destroyed || lock.ended > client.ended)) {
        cause = kDropped;
      } else if (client.hidden != lock.hidden) {
        cause = kHidden;
      } else if (client.destroyed != lock.destroyed || (client.destroyed && client.ended != lock.ended)) {
        cause = kEndedOtherBeat;
      } else if (
        !client.destroyed && !lock.destroyed && client.ticks > lock.ticks && client.ticks - lock.ticks <= mUnticked
      ) {
        cause = kUnticked;
      } else if (client.ticks != lock.ticks) {
        cause = kTicks;
      }
      ++causes[cause];
      causeEmitted[cause] += difference;
      auto& entry = byBlueprint[mNames[lock.blueprint]];
      ++entry.first;
      entry.second += difference;
    }
    std::uint64_t clientOnly = 0;
    for (const auto& [id, client] : mClient.records) {
      clientEmitted += Emitted(client);
      clientParticles += client.particles;
      clientOnly += mLockstep.records.count(id) == 0u ? 1u : 0u;
    }

    std::string out;
    char line[512];
    const auto add = [&out, &line](const int written) {
      if (written > 0) {
        out += line;
      }
    };
    add(
      std::snprintf(
        line,
        sizeof(line),
        "effect dump, army %d: lockstep %zu effects (%llu particles, %llu emitted with trail segments and beams, %llu "
        "lights); client %zu effects (%llu particles, %llu emitted, %llu lights)\n",
        mArmy,
        mLockstep.records.size(),
        static_cast<unsigned long long>(lockParticles),
        static_cast<unsigned long long>(lockEmitted),
        static_cast<unsigned long long>(mLockstep.lights),
        mClient.records.size(),
        static_cast<unsigned long long>(clientParticles),
        static_cast<unsigned long long>(clientEmitted),
        static_cast<unsigned long long>(mHost && mHost->hosted ? mHost->hosted->Counts().lights : 0u)
      )
    );
    add(
      std::snprintf(
        line,
        sizeof(line),
        "  not sent to the view: %llu effects, %llu of them emitted in lockstep (%llu emitted); sent: %llu, the "
        "same count %llu (%.2f %%), differing %llu (sum |client - lockstep| %llu; lockstep %llu, client %llu emitted "
        "over the pairs); client only %llu\n",
        static_cast<unsigned long long>(notSent),
        static_cast<unsigned long long>(notSentEmitting),
        static_cast<unsigned long long>(notSentEmitted),
        static_cast<unsigned long long>(pairs),
        static_cast<unsigned long long>(same),
        pairs != 0u ? 100.0 * static_cast<double>(same) / static_cast<double>(pairs) : 0.0,
        static_cast<unsigned long long>(pairs - same),
        static_cast<unsigned long long>(absDifference),
        static_cast<unsigned long long>(pairedLockEmitted),
        static_cast<unsigned long long>(pairedClientEmitted),
        static_cast<unsigned long long>(clientOnly)
      )
    );
    add(
      std::snprintf(
        line,
        sizeof(line),
        "  created the same beat %llu, later %llu; placed elsewhere at the first tick (> 1 unit) %llu of %llu (on bone "
        "1 of a collision beam %llu, of %llu sent); blueprint names that differ %llu\n",
        static_cast<unsigned long long>(sameCreated),
        static_cast<unsigned long long>(createdLater),
        static_cast<unsigned long long>(placedElsewhere),
        static_cast<unsigned long long>(positionsCompared),
        static_cast<unsigned long long>(placedElsewhereBone1Other),
        static_cast<unsigned long long>(onCollisionBeamBone1),
        static_cast<unsigned long long>(mNameMismatches)
      )
    );
    out += "  parameters at the first tick (made the same beat), differing / compared:";
    for (const auto& [what, counts] : paramsBy) {
      add(
        std::snprintf(
          line,
          sizeof(line),
          " %s %llu / %llu;",
          what.c_str(),
          static_cast<unsigned long long>(counts.second),
          static_cast<unsigned long long>(counts.first)
        )
      );
    }
    out += "\n  placed elsewhere, by op and what it is on:";
    for (const auto& [what, count] : elsewhereBy) {
      add(std::snprintf(line, sizeof(line), " %s %llu;", what.c_str(), static_cast<unsigned long long>(count)));
    }
    out += "\n";
    out += "  differing, client less lockstep:";
    for (std::size_t b = 0; b < buckets.size(); ++b) {
      add(std::snprintf(line, sizeof(line), " %s %llu;", kBucketNames[b], static_cast<unsigned long long>(buckets[b])));
    }
    out += "\n  differing by cause (pairs, emitted client less lockstep):";
    for (std::size_t c = 0; c < kCauses; ++c) {
      add(
        std::snprintf(
          line,
          sizeof(line),
          " %s %llu (%+lld);",
          kCauseNames[c],
          static_cast<unsigned long long>(causes[c]),
          static_cast<long long>(causeEmitted[c])
        )
      );
    }
    out += "\n  how pairs ended, lockstep -> client:";
    for (std::size_t a = 0; a < static_cast<std::size_t>(EEnd::Count); ++a) {
      for (std::size_t b = 0; b < static_cast<std::size_t>(EEnd::Count); ++b) {
        if (endPairs[a][b] != 0u) {
          add(
            std::snprintf(
              line,
              sizeof(line),
              " %s->%s %llu;",
              EndName(static_cast<EEnd>(a)),
              EndName(static_cast<EEnd>(b)),
              static_cast<unsigned long long>(endPairs[a][b])
            )
          );
        }
      }
    }
    out += "\n  by kind (lockstep / sent / same / differing; emitted lockstep / client over all):";
    for (std::size_t k = 0; k < kinds.size(); ++k) {
      const SKind& kind = kinds[k];
      if (kind.lockstep == 0u) {
        continue;
      }
      add(
        std::snprintf(
          line,
          sizeof(line),
          " %s %llu / %llu / %llu / %llu (%llu / %llu);",
          moho::EffectOpName(static_cast<moho::EEffectOp>(k)),
          static_cast<unsigned long long>(kind.lockstep),
          static_cast<unsigned long long>(kind.sent),
          static_cast<unsigned long long>(kind.same),
          static_cast<unsigned long long>(kind.differ),
          static_cast<unsigned long long>(kind.lockEmitted),
          static_cast<unsigned long long>(kind.clientEmitted)
        )
      );
    }
    std::vector<std::pair<std::string, std::pair<std::uint64_t, std::int64_t>>> top(
      byBlueprint.begin(), byBlueprint.end()
    );
    std::sort(top.begin(), top.end(), [](const auto& a, const auto& b) {
      return a.second.first > b.second.first;
    });
    out += "\n  blueprints with the most differing pairs (pairs, client less lockstep):";
    for (std::size_t i = 0; i < top.size() && i < 12u; ++i) {
      add(
        std::snprintf(
          line,
          sizeof(line),
          " %s %llu (%+lld);",
          top[i].first.c_str(),
          static_cast<unsigned long long>(top[i].second.first),
          static_cast<long long>(top[i].second.second)
        )
      );
    }
    add(
      std::snprintf(
        line,
        sizeof(line),
        "\n  sight at the client's effects' places: %llu checks, the sim sees and the client's grids don't %llu, the "
        "grids see and the sim doesn't %llu",
        static_cast<unsigned long long>(mSightChecks),
        static_cast<unsigned long long>(mSightSimOnly),
        static_cast<unsigned long long>(mSightClientOnly)
      )
    );
    if (!mSightChecked) {
      out += " (checked only while views were hosted in their own beat: not with the view pipeline)";
    }
    for (const std::string& sample : mSightSamples) {
      out += "\n    " + sample;
    }
    const std::uint64_t views = mViews != 0u ? mViews : 1u;
    std::string untickedList;
    for (const std::uint32_t beat : mUntickedBeats) {
      untickedList += (untickedList.empty() ? " (" : ", ") + std::to_string(beat);
    }
    if (!untickedList.empty()) {
      untickedList += mUnticked > mUntickedBeats.size() ? ", ...)" : ")";
    }
    add(
      std::snprintf(
        line,
        sizeof(line),
        "\n  the view's effects lane: %llu views, %llu ops, %llu bytes (%.1f a view); the client spawned %llu "
        "particles "
        "from them (%.3f lane bytes a particle; %zu bytes each as a particle struct); frames that didn't apply %llu, "
        "lanes that didn't apply %llu; the sim's tick less its beat %u (changed on %llu beats); beats the sim didn't "
        "tick %llu%s\n",
        static_cast<unsigned long long>(mViews),
        static_cast<unsigned long long>(mLaneOps),
        static_cast<unsigned long long>(mLaneBytes),
        static_cast<double>(mLaneBytes) / static_cast<double>(views),
        static_cast<unsigned long long>(clientParticles),
        clientParticles != 0u ? static_cast<double>(mLaneBytes) / static_cast<double>(clientParticles) : 0.0,
        sizeof(moho::SWorldParticle),
        static_cast<unsigned long long>(mHost ? mHost->framesBad : 0u),
        static_cast<unsigned long long>(mHost ? mHost->lanesBad : 0u),
        mFirstTickOffset,
        static_cast<unsigned long long>(mTickOffsetChanges),
        static_cast<unsigned long long>(mUnticked),
        untickedList.c_str()
      )
    );
    return out;
  }
} // namespace faf::headless
