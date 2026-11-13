#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include <memory>
#include "legacy/containers/Vector.h"
#include "moho/effects/rendering/CHostedEffectManager.h"
#include "moho/effects/rendering/EffectHost.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/render/camera/VTransform.h"
#include "remote/client/EffectLaneApplier.h"
#include "remote/wire/ArmyLane.h"

// Engine addition, server mode (plan WP9.3, hosting): the effects a server-mode client draws. The client has no `Sim`,
// so it runs the sim's own effect classes in a `CHostedEffectManager` (moho/effects/rendering/CHostedEffectManager.h)
// over its own world (`CClientEffects`, an `IEffectHost`): the view's beat, the session's cameras and map, the focus
// army's sight from the view's grid lane, and each entity an effect follows as the view's frames hold it
// (`CClientFollowTarget`, refreshed each beat from the rebuilder). The effects lane's ops make, change and destroy the
// effects (`CClientEffects` is the applier's `IEffectLaneTarget`); each beat the manager ticks once, as the sim's does,
// and its particles, trails and beams go to the session in the beat's packet (`SSyncData::mParticleBuffer`), where the
// sim's go in lockstep (Sim::Sync), so the session draws them the same way.
//
// One thread: the one that applies the views (`CNetworkSimDriver::Dispatch`, the game's main thread).

namespace moho
{
  class CAniPose;
  class RRuleGameRules;
  class RScmResource;
  class STIMap;
  struct REntityBlueprint;
  struct SParticleBuffer;
  struct SSyncData;
} // namespace moho

namespace faf::remote::client
{
  class CSyncRebuilder;

  /**
   * A beam from create parameters as the effects lane sends it (wire/EffectLane.h, `CreateBeam` without a blueprint),
   * into `out` (its attachment left out: the caller attaches the client's own target). False when the op has fewer
   * than its 9 first floats.
   */
  [[nodiscard]] bool
  BeamParamsFromOp(const wire::SEffectLaneOp& op, const std::string* texture, moho::SCreateBeamParams& out);

  /** What the game's session lends the effects a client hosts. Either may be empty (no camera: nothing is drawn). */
  struct SEffectHostWorld
  {
    std::function<void(fa::vector<moho::GeomCamera3>&)> cameras; // the session's cameras now, copied
    std::function<moho::STIMap*()> map;                          // the session's map, or null
  };

  /** One entity of the client's world as the hosted effects read it (moho::IEffectFollowTarget). */
  class CClientFollowTarget final : public moho::IEffectFollowTarget
  {
  public:
    static constexpr int kHistorySamples = 25; // `PositionHistory::kSampleCount`

    /** What a beat's frame left of the entity (`CSyncRebuilder::FindHeld`). */
    struct SState
    {
      moho::VTransform current; // the sim's `mCurTransform` in its effect tick: the beat before the one shown
      moho::VTransform pending; // the beat shown
      float velocityScale = 1.0f;
      std::shared_ptr<moho::RScmResource> mesh;
      Wm3::Vector3f scale{1.0f, 1.0f, 1.0f};
      const moho::REntityBlueprint* blueprint = nullptr;
      std::shared_ptr<moho::CAniPose> pose; // a unit's client pose this beat (its world at `pending`)
      bool isUnit = false;
    };

    /**
     * This beat's state. The history moves on, as `Entity::AdvanceCoords` moves it, when the entity moved: its new
     * `current` goes in after the old one.
     */
    void Update(const SState& state);
    /** The client no longer holds it: the effects that follow it end (`Dying`). Its last state stays. */
    void MarkGone() noexcept;
    /**
     * Plan WP9.5: a collision beam's length (`CollisionBeamEntity::mLastBeamLength`), which the client learns from the
     * length its beam is given (`CollisionBeamEntity::CheckCollision` sets both, and the beam's goes in the effects
     * lane). From then on its bones are a collision beam's: bone 1 at the beam's end. Only an entity with no mesh that
     * is no unit takes it (a collision beam has neither); a `const` setter, as `ResetHistory`, since effects hold
     * their targets as `const`.
     */
    void LearnBeamLength(float length) const noexcept;
    [[nodiscard]] bool HasBeamLength() const noexcept
    {
      return mHasBeamLength;
    }

    [[nodiscard]] bool Dying() const override
    {
      return mGone;
    }
    [[nodiscard]] const moho::VTransform& Current() const override
    {
      return mState.current;
    }
    [[nodiscard]] const moho::VTransform& Pending() const override
    {
      return mState.pending;
    }
    [[nodiscard]] float PendingVelocityScale() const override
    {
      return mState.velocityScale;
    }
    [[nodiscard]] const moho::VTransform& History(int tick) const override;
    [[nodiscard]] moho::VTransform BoneLocal(int bone) const override;
    [[nodiscard]] moho::VTransform BoneWorld(int bone) const override;
    [[nodiscard]] bool UpdatesBeams() const override;
    void ResetHistory() const override;

  private:
    SState mState;
    bool mGone = false;
    mutable std::array<moho::VTransform, kHistorySamples> mHistory{};
    mutable int mCursor = 0;
    mutable bool mHasBeamLength = false; // `LearnBeamLength`
    mutable float mBeamLength = 0.0f;
  };

  /** What `CClientEffects` did, over the whole session. */
  struct SHostedEffectCounts
  {
    std::uint64_t beats = 0;
    std::uint64_t created = 0;
    std::uint64_t createFailed = 0;      // a blueprint the client's rules don't have, or no target
    std::uint64_t endedByThemselves = 0; // lifetime, entity gone, fidelity: the applier was told
    std::uint64_t particles = 0;         // handed to the session
    std::uint64_t beatsDrawing = 0;      // beats whose buffer had anything
    std::uint64_t mostParticles = 0;     // in one beat
    std::uint64_t trails = 0;
    std::uint64_t beams = 0;
    std::uint64_t lights = 0;
    std::uint64_t mostAlive = 0;
    std::uint64_t mostTargets = 0;
    std::uint64_t untickedBeats = 0; // beats the sim didn't tick, held as it held them (plan WP9.5)
  };

  class CClientEffects final : public moho::IEffectHost, public IEffectLaneTarget
  {
  public:
    /**
     * `rules`: the client's, for blueprints by name. `holds`: whether the client holds an entity (the applier's
     * `HoldsEntity`).
     */
    CClientEffects(
      moho::RRuleGameRules& rules,
      const CSyncRebuilder& rebuilder,
      std::function<bool(std::int32_t, bool)> holds,
      SEffectHostWorld world
    );
    ~CClientEffects() override;

    CClientEffects(const CClientEffects&) = delete;
    CClientEffects& operator=(const CClientEffects&) = delete;

    /** `ended(id)` for each effect that ended by itself (the applier's `Ended`). */
    void SetEndedHandler(
      std::function<void(std::uint32_t)> ended
    )
    {
      mEnded = std::move(ended);
    }

    /**
     * Before a view's effects lane: its beat, the focus army, the view's grids (as the client holds them after this
     * view), and the targets refreshed from the frame just applied (gone ones marked).
     */
    void BeginBeat(std::uint32_t beat, int focusArmy, const std::vector<wire::SGridSlot>& grids);
    /**
     * After it: one tick of every effect, the purge (each effect that ended by itself is reported), and the particle
     * buffer into `packet` (null: dropped).
     */
    void EndBeat(moho::SSyncData* packet);

    [[nodiscard]] const SHostedEffectCounts& Counts() const noexcept
    {
      return mCounts;
    }
    /** Effects alive now, and the entities they follow. */
    [[nodiscard]] std::size_t Alive() const noexcept;
    [[nodiscard]] std::size_t Targets() const noexcept
    {
      return mTargets.size();
    }
    [[nodiscard]] const moho::CHostedEffectManager& Manager() const noexcept
    {
      return *mManager;
    }
    /**
     * The server's id of a hosted effect while it is hosted: an effect that ends by itself until its purge, one an op
     * destroys until its `DestroyEffect` returns (so an effect tick observer can still ask).
     */
    [[nodiscard]] bool ServerId(const moho::IEffect* effect, std::uint32_t& id) const;
    /** Whether an effect with the server's id `id` is hosted now. */
    [[nodiscard]] bool Hosts(
      const std::uint32_t id
    ) const noexcept
    {
      return mEffects.find(id) != mEffects.end();
    }

    // moho::IEffectHost
    [[nodiscard]] moho::SParticleBuffer* ParticleBuffer() override;
    [[nodiscard]] std::uint32_t CurTick() const override
    {
      // The sim's tick counts the beats it ticked: the beat less those the server said it didn't (plan WP9.5).
      return mBeat - mUntickedBeats;
    }
    [[nodiscard]] const fa::vector<moho::GeomCamera3>& Cameras() const override
    {
      return mCameras;
    }
    [[nodiscard]] bool HasFocusArmy() const override
    {
      return mFocusArmy >= 0;
    }
    [[nodiscard]] bool FocusArmyDetects(const Wm3::Vec3f& position) const override;
    [[nodiscard]] float WaterElevationAt(float x, float z) const override;
    [[nodiscard]] float TerrainElevationAt(float x, float z) const override;

    // IEffectLaneTarget
    [[nodiscard]] bool HoldsEntity(std::int32_t entity, bool orRemoved) const override;
    [[nodiscard]] bool Create(
      std::uint32_t id,
      const wire::SEffectLaneOp& op,
      const std::string* blueprint,
      const std::string* texture
    ) override;
    void Change(std::uint32_t id, const wire::SEffectLaneOp& op) override;
    void Destroy(std::uint32_t id) override;
    void Light(const wire::SEffectLaneOp& op, const std::string* texture, const std::string* ramp) override;
    void Unticked() override
    {
      mUnticked = true;
      ++mUntickedBeats;
      ++mCounts.untickedBeats;
    }

  private:
    using TargetPtr = std::shared_ptr<CClientFollowTarget>;

    /** The target of a client entity id (made on first use), or null when the client doesn't hold it. */
    [[nodiscard]] TargetPtr Target(std::int32_t entity, bool orRemoved);
    /** Fills `out` from the rebuilder's view of `id`; false when it holds none. */
    [[nodiscard]] bool ReadState(std::uint32_t id, bool orRemoved, CClientFollowTarget::SState& out) const;
    [[nodiscard]] moho::IEffect* Find(std::uint32_t id) const;

    moho::RRuleGameRules& mRules;
    const CSyncRebuilder& mRebuilder;
    std::function<bool(std::int32_t, bool)> mHolds;
    SEffectHostWorld mWorld;
    std::unique_ptr<moho::CHostedEffectManager> mManager;
    std::function<void(std::uint32_t)> mEnded;
    // By server id and back; looked up only (their order reaches nothing).
    std::unordered_map<std::uint32_t, moho::IEffect*> mEffects;
    std::unordered_map<const moho::IEffect*, std::uint32_t> mIds;
    std::unordered_map<std::uint32_t, TargetPtr> mTargets; // by client entity id, while held
    std::shared_ptr<moho::SParticleBuffer> mParticles;
    fa::vector<moho::GeomCamera3> mCameras;
    std::uint32_t mBeat = 0;
    bool mUnticked = false;           // this beat's lane said the sim didn't tick (`Unticked`)
    std::uint32_t mUntickedBeats = 0; // such beats, over the session
    int mFocusArmy = -1;
    const std::vector<wire::SGridSlot>* mGrids = nullptr;
    moho::STIMap* mMap = nullptr;
    SHostedEffectCounts mCounts;
  };
} // namespace faf::remote::client
