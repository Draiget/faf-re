#pragma once

#include <cstdint>
#include <cstdio>
#include <map>
#include <memory>
#include <mutex>
#include <span>
#include <string>
#include <unordered_map>
#include <vector>

#include "boost/shared_ptr.h"
#include "moho/render/camera/VTransform.h"
#include "remote/client/SyncRebuilder.h"
#include "remote/client/ViewMerge.h"
#include "remote/wire/EntityFrame.h"
#include "remote/wire/PoseLane.h"
#include "remote/wire/SessionTables.h"

namespace moho
{
  class CAniPose;
  class RRuleGameRules;
  struct SSyncData;
} // namespace moho

// Engine addition, server mode (plan WP8.4): headless's `--pose-dump <prefix>`, with `--view-bench --view-poses
// --keep-client-data --focus <army>` (serial views). One replay, two runtimes of what that army's player sees of its
// units' bodies:
//
// - lockstep: the sim's own packets for the focused army, as `CWldSession` gives them to its user units (each unit's
//   two poses from its last unit update, its two transforms from its last entity update);
// - the server-mode client: the army's view as a server builds it (frames and the pose lane, with the server's pose
//   budget when one is set), applied as the game client applies it (`CServerViewClient::Apply`: the merged frames into
//   `CSyncRebuilder` with the pose lane), and its packet given to the same model of the session.
//
// For every unit both hold, every beat: the transforms (where the unit is drawn from and to), and every bone as the
// mesh draws it (`MeshInstance` blends the two poses with `CAniPose::InterpolatePose`, and the skinning palette takes
// each bone's composite transform, which includes the pose's own world transform) at the beat's start, middle and end.
// A bone's error is split into the poses' world transforms (where the skeleton stands) and the bones under them.
//
// The client is applied on the main thread when lockstep's packet of the same beat arrives, never on the sim thread:
// a pose made there would take blocks from the sim's block lane (moho/sim/SimBlockLane.h) and could change what the
// sim computes. The sim's poses are only read (local transforms and flags; the composites are worked out on copies).
//
// Writes `<prefix>.beats.csv` (one line per beat), `<prefix>.worst.csv` (the unit-beats with the largest errors) and
// `<prefix>.summary.txt`, which `Finish` returns too.

namespace faf::headless
{
  class CReplayPoseDump
  {
  public:
    CReplayPoseDump(std::string prefix, std::int32_t army, float mapSizeX, float mapSizeZ);
    ~CReplayPoseDump();

    CReplayPoseDump(const CReplayPoseDump&) = delete;
    CReplayPoseDump& operator=(const CReplayPoseDump&) = delete;

    [[nodiscard]] std::int32_t Army() const noexcept
    {
      return mArmy;
    }

    /** The army's view of `beat` as its client gets it, from the view's job (serial views: the sim thread). */
    void QueueView(
      moho::RRuleGameRules& rules,
      std::uint32_t beat,
      std::span<const std::uint8_t> own,
      std::span<const std::uint8_t> team,
      std::span<const std::uint8_t> poses,
      bool hasPoses
    );
    /** Lockstep's packet for the focused army (the runner's thread); applies the client's views queued so far. */
    void OnLockstepPacket(const moho::SSyncData& packet);

    /** Applies what is left, writes the files and returns the comparison (once; later calls return it again). */
    std::string Finish();

    /** What one runtime's session holds of a unit, as its user unit draws it. */
    struct SHeldUnit
    {
      boost::shared_ptr<moho::CAniPose> prior; // `mPosePrimary`: the blend's start
      boost::shared_ptr<moho::CAniPose> pose;  // `mPoseSecondary`: its end
      moho::VTransform last;                   // `mLastTransform`
      moho::VTransform cur;                    // `mCurTransform`
      bool hasTransforms = false;
      std::uint32_t updates = 0; // unit updates with poses received
    };

    /** One bone as drawn: world position and rotation. */
    struct SDrawnBone
    {
      float pos[3];
      float rot[4]; // w, x, y, z
    };

    /** One unit at one beat, as drawn. */
    struct SDrawnUnit
    {
      std::uint32_t id = 0;
      bool hasPose = false;
      bool samePose = false;             // prior and end are one pose (nothing to blend)
      std::uint32_t bones = 0;           // per sample
      std::vector<SDrawnBone> drawn;     // 3 samples (t = 0, 0.5, 1) x bones
      std::vector<SDrawnBone> local;     // t = 0 and 1 with the pose's world transform taken out: 2 x bones
      std::vector<std::uint8_t> visible; // the end pose's flags
      moho::VTransform priorWorld;       // the two poses' world transforms
      moho::VTransform poseWorld;
      moho::VTransform last; // the entity's two transforms
      moho::VTransform cur;
      bool hasTransforms = false;
      const char* blueprint = nullptr; // client side: its blueprint id (static strings of the rules)
    };

  private:
    /** A runtime's session, as far as the units' bodies go. */
    struct SSession
    {
      std::unordered_map<std::uint32_t, SHeldUnit> units; // family-0 ids
      void Apply(const moho::SSyncData& packet);
    };

    struct SQueuedView
    {
      std::uint32_t beat = 0;
      std::vector<std::uint8_t> own;
      std::vector<std::uint8_t> team;
      std::vector<std::uint8_t> poses;
      bool hasPoses = false;
    };

    /** The army's client, as `CServerViewClient` builds it. */
    struct SClient
    {
      remote::wire::SFrameCodec codec{};
      std::unique_ptr<remote::wire::CSessionTableReaders> tables;
      std::unique_ptr<remote::client::CSyncRebuilder> rebuilder;
      remote::client::CViewFrameMerger merger;
      std::vector<remote::wire::SUnitPose> poses;
      std::uint64_t framesBad = 0;
      std::uint64_t lanesBad = 0;
      std::uint64_t views = 0;
      std::uint64_t poseBytes = 0;
    };

    /** The client's views queued so far, applied in order (runner's thread). */
    void ApplyQueued();
    void ApplyView(const SQueuedView& view);
    /** A session's units as drawn now. */
    [[nodiscard]] std::vector<SDrawnUnit> Snapshot(const SSession& session, bool client) const;
    /** Both runtimes have `beat`: compare and forget them. */
    void Compare(std::uint32_t beat, const std::vector<SDrawnUnit>& lockstep, const std::vector<SDrawnUnit>& client);
    [[nodiscard]] std::string Report() const;

    std::string mPrefix;
    std::int32_t mArmy;
    float mMapSizeX;
    float mMapSizeZ;
    std::mutex mQueueLock;
    std::vector<SQueuedView> mQueued; // under `mQueueLock`
    moho::RRuleGameRules* mRules = nullptr;

    std::mutex mLock; // the rest: the runner's thread, and `Finish`
    std::unique_ptr<SClient> mClient;
    SSession mLockstep;
    SSession mClientSession;
    std::map<std::uint32_t, std::vector<SDrawnUnit>> mLockstepBeats; // drawn, waiting for the client's beat
    std::map<std::uint32_t, std::vector<SDrawnUnit>> mClientBeats;   // drawn, waiting for lockstep's beat
    bool mFinished = false;
    std::string mResult;
    std::FILE* mBeatsFile = nullptr;

    // Totals over all beats compared.
    struct STotals
    {
      std::uint64_t beats = 0;
      std::uint64_t unitBeats = 0;        // units both hold, both with transforms
      std::uint64_t posedUnitBeats = 0;   // of them, both with poses of the same bone count
      std::uint64_t lockstepOnly = 0;     // unit-beats only lockstep's session holds (it holds every unit, seen or not)
      std::uint64_t clientOnly = 0;       // only the client holds
      std::uint64_t noPoseClient = 0;     // both hold it, the client has no pose
      std::uint64_t noPoseLockstep = 0;   // lockstep has none
      std::uint64_t boneCountDiffers = 0; // both have poses of a different bone count
      std::uint64_t visibleDiffers = 0;   // unit-beats with a bone whose visible flag differs
      std::uint64_t samePoseClient = 0;   // the client's two poses are one (nothing blends) ...
      std::uint64_t samePoseLockstep = 0; // ... and lockstep's
      std::uint64_t samePoseOnlyClient = 0; // the client's are one where lockstep's are two
      // Unit-beats whose drawn bones are off by more than 0.05 world units or 2 degrees, by cause: the poses' world
      // transforms (where the skeleton stands) differ by more than 0.01, else the bones under them, else the blend.
      std::uint64_t overWorld = 0;
      std::uint64_t overBones = 0;
      std::uint64_t overBlend = 0;
      double maxEntityError = 0.0; // transforms, world units (cur and last)
      double maxCurError = 0.0;    // `mCurTransform` alone
      double maxLastError = 0.0;   // `mLastTransform` alone
      std::uint64_t curOver = 0;   // unit-beats whose `mCurTransform` is off by more than 0.02 (the quantiser's 1/64)
      std::uint64_t lastOver = 0;  // and `mLastTransform`
      double maxDrawnError = 0.0;  // drawn bones, world units
      double maxDrawnAngle = 0.0;  // degrees
      double maxLocalError = 0.0;  // bones under the pose's world transform, world units
      double maxLocalAngle = 0.0;
      double maxWorldError = 0.0; // the poses' world transforms
      std::uint64_t
        drawnHistogram[8]{}; // unit-beats by max drawn error: <0.001, <0.01, <0.05, <0.1, <0.5, <1, <5, more
    };
    STotals mTotals;
    struct SWorst
    {
      double error = 0.0;
      double angle = 0.0;
      double world = 0.0;
      double local = 0.0;
      std::uint32_t beat = 0;
      std::uint32_t id = 0;
      std::uint32_t bone = 0;
      std::uint32_t sample = 0;
      bool samePoseClient = false;
      bool samePoseLockstep = false;
      const char* blueprint = nullptr;
    };
    std::vector<SWorst> mWorst; // the largest drawn errors, a heap of at most kWorstKept
    static constexpr std::size_t kWorstKept = 200;
    // Per blueprint: unit-beats compared and over the limit, by cause.
    struct SBlueprintCounts
    {
      std::uint64_t unitBeats = 0;
      std::uint64_t overWorld = 0;
      std::uint64_t overBones = 0;
      std::uint64_t overBlend = 0;
      double maxError = 0.0;
    };
    std::map<std::string, SBlueprintCounts> mByBlueprint;
    std::vector<std::string> mVisibleSamples; // the first unit-beats whose visible flags differ
    std::unordered_map<std::uint32_t, std::uint32_t> mVisibleBeatsByUnit; // beats each unit's flags differed
    std::vector<std::string> mLastSamples; // the first unit-beats whose `mLastTransform` is off
  };
} // namespace faf::headless
