#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>

#include "boost/shared_ptr.h"
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
      boost::shared_ptr<moho::RScmResource> mesh;
      Wm3::Vector3f scale{1.0f, 1.0f, 1.0f};
      const moho::REntityBlueprint* blueprint = nullptr;
      boost::shared_ptr<moho::CAniPose> pose; // a unit's client pose this beat (its world at `pending`)
      bool isUnit = false;
    };

    /**
     * This beat's state. The history moves on, as `Entity::AdvanceCoords` moves it, when the entity moved: its new
     * `current` goes in after the old one.
     */
    void Update(const SState& state);
    /** The client no longer holds it: the effects that follow it end (`Dying`). Its last state stays. */
    void MarkGone() noexcept;

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

    // moho::IEffectHost
    [[nodiscard]] moho::SParticleBuffer* ParticleBuffer() override;
    [[nodiscard]] std::uint32_t CurTick() const override
    {
      return mBeat;
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
    boost::shared_ptr<moho::SParticleBuffer> mParticles;
    fa::vector<moho::GeomCamera3> mCameras;
    std::uint32_t mBeat = 0;
    int mFocusArmy = -1;
    const std::vector<wire::SGridSlot>* mGrids = nullptr;
    moho::STIMap* mMap = nullptr;
    SHostedEffectCounts mCounts;
  };
} // namespace faf::remote::client
