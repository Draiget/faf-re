#pragma once

#include <array>
#include <cstdint>
#include <cstdio>
#include <functional>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "legacy/containers/Vector.h"
#include "moho/effects/rendering/EffectOps.h"
#include "moho/effects/rendering/EffectTickObserver.h"
#include "moho/render/camera/GeomCamera3.h"
#include "remote/client/EffectHosting.h"
#include "remote/client/EffectLaneApplier.h"
#include "remote/client/SyncRebuilder.h"
#include "remote/client/ViewMerge.h"
#include "remote/wire/ArmyLane.h"
#include "remote/wire/EffectLane.h"
#include "remote/wire/EntityFrame.h"
#include "remote/wire/PoseLane.h"
#include "remote/wire/SessionTables.h"

namespace moho
{
  class RRuleGameRules;
  class Sim;
  class STIMap;
} // namespace moho

namespace faf::server
{
  class CEffectOpRecorder;
}

// Engine addition, server mode (plan WP9.5, WPR.10): headless's `--effect-dump <prefix>`, with `--view-bench
// --view-effects --view-poses --keep-client-data --focus <army>`. One replay, two runtimes of that army's effects:
//
// - lockstep: the sim's own effect manager, focused on the army as a player's client is (its sight decides what an
//   emitter that needs to be seen draws);
// - the server-mode client: the army's view as a server builds it (frames, grids, poses, the routed effects lane with
//   the client's entity ids), applied as the game client applies it (`CServerViewClient::Apply`'s hosting path: the
//   rebuilder's frames, then the lane through `CEffectLaneApplier` into `CClientEffects`, one tick), with the
//   view's army as focus.
//
// Both see one camera that sees everything (no frustum plane, every point at depth 0), so cameras decide nothing.
// Every effect is reported per tick (moho/effects/rendering/EffectTickObserver.h): particles, trail segments and beams
// it put in its buffer, whether its visibility test said no, an emitter's place. An effect is the same in both by the
// server's effect id (the lane carries it; the sim's comes from the recorder at the create), which is the join on
// (blueprint, created beat, entity) made exact. Particles come from the non-sim random, so positions of particles are
// not compared, only counts.
//
// Writes `<prefix>.lockstep.csv` and `<prefix>.client.csv` (one line per effect) and `<prefix>.join.txt` (the
// comparison), which `Summary` returns too.

namespace faf::headless
{
  class CReplayEffectDump final : public moho::IEffectTickObserver
  {
  public:
    CReplayEffectDump(std::string prefix, std::int32_t army, server::CEffectOpRecorder& recorder);
    ~CReplayEffectDump();

    CReplayEffectDump(const CReplayEffectDump&) = delete;
    CReplayEffectDump& operator=(const CReplayEffectDump&) = delete;

    [[nodiscard]] std::int32_t Army() const noexcept
    {
      return mArmy;
    }
    /** The camera both runtimes draw with: no frustum plane, every point at depth 0 (inside every LOD cutoff). */
    [[nodiscard]] static fa::vector<moho::GeomCamera3> EverywhereCamera();

    /** The hook the bench sets: the recorder's, then the creates and script destroys noted here (sim thread). */
    static void Hook(moho::EEffectOp op, const moho::SEffectOpArgs& args);

    /** On the sim thread in each beat's `Sync` (its beat and tick, its rules and map for the client). */
    void OnSimSynced(moho::Sim& sim);
    /**
     * The army's view of `beat`, as its client gets it (lanes as the server writes them; `effects` the routed lane
     * with client ids), from the view's own job. `ops`: that lane read back by `names` (the bench's reader), for the
     * creates' blueprints. Kept until `HostQueued`.
     */
    void QueueView(
      std::uint32_t beat,
      std::span<const std::uint8_t> own,
      std::span<const std::uint8_t> team,
      std::span<const std::uint8_t> grids,
      std::span<const std::uint8_t> poses,
      bool hasPoses,
      std::span<const std::uint8_t> effects,
      const std::vector<remote::wire::SEffectLaneOp>& ops,
      const remote::wire::CEffectLaneReader& names
    );
    /**
     * On the sim thread: the client applies the views queued, in order. Right after `QueueView` with serial views; with
     * the view pipeline (team views need it) at the next beat's start, after the sim's next tick, so the check of the
     * sim's sight at the client's effects is then left out (it would read the next beat's).
     */
    void HostQueued(bool sameBeat);

    /** Writes the files and returns the comparison (once; later calls return it again). */
    std::string Finish();

    // moho::IEffectTickObserver
    void OnEffectTicked(const moho::IEffect& effect, const moho::SEffectTick& tick) override;
    void OnEffectEnding(const moho::IEffect& effect, moho::EEffectEnd why) override;
    void OnEffectDestroyed(const moho::IEffect& effect) override;

    /** How an effect ended, in a dump. */
    enum class EEnd : std::uint8_t
    {
      Alive,      // at the end of the replay
      Lifetime,   // by itself (EffectTickObserver.h)
      EntityGone, // by itself
      NotVisible, // by itself
      Script,     // `IEffect:Destroy()` (lockstep), or that op (client)
      Other,      // lockstep: any other `DestroyEffect` (fidelity, an owner's teardown); client: the applier dropped it
      Count
    };

    /** One effect in one runtime. */
    struct SRecord
    {
      moho::EEffectOp op = moho::EEffectOp::Count;
      std::uint32_t blueprint = 0; // into `mNames`, 0 none
      std::int32_t army = -1;
      std::int32_t entity = -1; // lockstep: sim id; client: the client's id
      std::int32_t bone = -1;
      std::uint32_t created = 0;
      std::uint32_t ended = 0; // beat of its destroy (valid unless `end` is Alive)
      EEnd end = EEnd::Alive;
      bool endingSeen = false; // `OnEffectEnding` came first: `end` is its reason
      bool destroyed = false;
      bool onCollisionBeam = false;   // lockstep: its entity is a collision beam (an end splash on bone 1, say)
      bool made = true;               // client: the applier made it (a create it skipped is counted, not made)
      std::uint32_t incarnations = 1; // client: made again under the same id (sent whole again)
      std::uint32_t ticks = 0;
      std::uint32_t hidden = 0; // ticks its visibility test said no
      std::uint64_t particles = 0;
      std::uint64_t trails = 0;
      std::uint64_t beams = 0;
      bool emitted = false;
      std::uint32_t firstEmit = 0; // beats, valid when anything was emitted
      std::uint32_t lastEmit = 0;
      bool positioned = false;
      std::array<float, 3> position{}; // at its first tick
      std::uint64_t paramsHash = 0;    // its parameters as its first tick began
      bool hashed = false;
      std::vector<std::uint16_t> perBeat; // particles + trail segments + beams, by beat from `created`
    };

  private:
    struct SSide
    {
      std::unordered_map<std::uint32_t, SRecord> records;          // by the server's effect id
      std::unordered_map<const moho::IEffect*, std::uint32_t> ids; // live effects (lockstep's; the client asks)
      std::vector<const moho::IEffect*> released;                  // destroyed: forgotten at the next beat
      std::uint32_t beat = 0;
      std::uint64_t lights = 0;
    };

    [[nodiscard]] std::uint32_t Name(const char* name);
    [[nodiscard]] SRecord* Find(const moho::IEffect& effect, bool& client);
    void OnSimOp(moho::EEffectOp op, const moho::SEffectOpArgs& args);
    void Emit(SRecord& record, std::uint32_t beat, std::uint32_t amount);
    void WriteSide(const SSide& side, const char* which) const;
    [[nodiscard]] std::string Compare() const;
    [[nodiscard]] bool HoldsEntity(std::int32_t id, bool orRemoved) const;

    struct SQueuedView
    {
      std::uint32_t beat = 0;
      std::vector<std::uint8_t> own;
      std::vector<std::uint8_t> team;
      std::vector<std::uint8_t> grids;
      std::vector<std::uint8_t> poses;
      bool hasPoses = false;
      std::vector<std::uint8_t> effects;
      std::vector<remote::wire::SEffectLaneOp> ops;
      std::unordered_map<std::uint32_t, std::string> names; // the creates' blueprints, by reference
    };
    void HostView(const SQueuedView& view);
    std::vector<SQueuedView> mQueued; // under `mLock`
    bool mSightChecked = true;        // false once a view was hosted a beat late (the pipeline)

    std::string mPrefix;
    std::int32_t mArmy;
    server::CEffectOpRecorder& mRecorder;
    // The observer is called from the sim's workers too; recursive: the client's tick reports while `OnView` holds it.
    mutable std::recursive_mutex mLock;
    std::unordered_set<std::uint32_t> mViewReplacing; // this view's creates for an id the client holds
    std::unordered_set<std::uint32_t> mViewScript;    // this view's `DestroyByScript`s
    bool mFinished = false;
    std::string mResult;
    std::vector<std::string> mNames{std::string()};
    std::unordered_map<std::string, std::uint32_t> mNameIds;
    SSide mLockstep;
    SSide mClient;
    std::unordered_set<std::uint32_t> mScriptDestroyed; // lockstep ids `IEffect:Destroy()` ended
    std::uint32_t mFirstTickOffset = 0;                 // the sim's tick less its beat, at the first beat
    bool mHaveOffset = false;
    std::uint64_t mTickOffsetChanges = 0; // beats whose tick less beat differs from the first (paused beats)
    std::uint32_t mLastTick = 0;
    std::vector<std::uint32_t> mUntickedBeats; // beats the sim didn't tick (paused, or the game over), the first 20
    std::uint64_t mUnticked = 0;
    moho::Sim* mSim = nullptr;
    // At each tick of a client effect with a place: the sim's sight of that point (`ReconCanDetect(point,
    // RECON_LOSNow)`, the test a lockstep effect makes) against the client's (`CClientEffects::FocusArmyDetects`).
    std::uint64_t mSightChecks = 0;
    std::uint64_t mSightSimOnly = 0;    // the sim sees it, the client's grids don't
    std::uint64_t mSightClientOnly = 0; // the client's grids see it, the sim doesn't
    std::vector<std::string> mSightSamples;
    std::uint64_t mViews = 0;
    std::uint64_t mLaneBytes = 0;
    std::uint64_t mLaneOps = 0;
    std::uint64_t mNameMismatches = 0; // a client create whose blueprint name isn't lockstep's for that id

    // The army's client, as `CServerViewClient` builds it for hosting (its `Apply`'s steps).
    struct SClient
    {
      remote::wire::SFrameCodec codec{};
      std::unique_ptr<remote::wire::CSessionTableReaders> tables;
      std::unique_ptr<remote::client::CSyncRebuilder> rebuilder;
      remote::client::CViewFrameMerger merger;
      std::vector<remote::wire::SGridSlot> grids;
      std::vector<remote::wire::SUnitPose> poses;
      std::vector<std::uint32_t> previousIds;
      std::unique_ptr<remote::client::CClientEffects> hosted;
      std::unique_ptr<remote::client::CEffectLaneApplier> applier;
      std::uint64_t framesBad = 0;
      std::uint64_t lanesBad = 0;
    };
    std::unique_ptr<SClient> mHost;
    moho::RRuleGameRules* mRules = nullptr;
    moho::STIMap* mMap = nullptr;
    float mMapSizeX = 0.0f;
    float mMapSizeZ = 0.0f;

  public:
    void SetMapSize(
      const float x,
      const float z
    ) noexcept
    {
      mMapSizeX = x;
      mMapSizeZ = z;
    }
  };
} // namespace faf::headless
