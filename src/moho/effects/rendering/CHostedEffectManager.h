#pragma once

#include <cstddef>
#include <cstdint>
#include <functional>
#include <memory>
#include <unordered_map>
#include <utility>

#include "moho/effects/rendering/CEffectManagerImpl.h"
#include "moho/effects/rendering/EffectHost.h"

namespace moho
{
  struct REmitterBlueprint;
  struct RTrailBlueprint;

  /**
   * Engine addition (server mode, plan WP9.3): an effect manager with no `Sim`, which runs the sim's effect classes
   * over an `IEffectHost` (the server-mode client's world, remote/client/EffectHosting.h). Its creates are the
   * `CEffectManagerImpl` ones with a followed target (`IEffectFollowTarget`) in place of each `Entity*` and the
   * blueprint already looked up: the same constructors, attached and seeded in the same order, and the same fidelity
   * check. `Tick` is the base's serial walk; `PurgeDestroyedEffects` also forgets what each effect followed and tells
   * `SetEndedHandler`'s handler which effects went, so whoever named them can forget them.
   *
   * One thread at a time, the thread that applies the client's views (as the sim's manager is the sim thread's).
   */
  class CHostedEffectManager final : public CEffectManagerImpl
  {
  public:
    using Target = std::shared_ptr<const IEffectFollowTarget>;

    explicit CHostedEffectManager(IEffectHost& host);
    ~CHostedEffectManager() override;

    CHostedEffectManager(const CHostedEffectManager&) = delete;
    CHostedEffectManager& operator=(const CHostedEffectManager&) = delete;

    [[nodiscard]] const CHostedEffectManager* AsHosted() const noexcept override
    {
      return this;
    }
    [[nodiscard]] IEffectHost& Host() const noexcept
    {
      return mHost;
    }
    /** What `effect` follows (`beamEnd`: a beam's other end), or null. */
    [[nodiscard]] const IEffectFollowTarget* Follows(const IEffect& effect, bool beamEnd) const noexcept;

    /** `CreateEmitter`: placed at a point. */
    IEffect* HostEmitterAt(const Wm3::Vector3<float>& position, const REmitterBlueprint* blueprint, int army);
    /** `CreateAttachedEmitter`: follows `target`'s bone. */
    IEffect* HostAttachedEmitter(Target target, int bone, const REmitterBlueprint* blueprint, int army);
    /** `CreateEmitterAtBone`: placed once at the bone's world transform. */
    IEffect*
    HostEmitterAtBone(const IEffectFollowTarget& target, int bone, const REmitterBlueprint* blueprint, int army);
    /** `CreateEmitterAtEntity`: placed once at the entity's position. */
    IEffect* HostEmitterAtEntity(const IEffectFollowTarget& target, const REmitterBlueprint* blueprint, int army);
    /** `CreateEmitterOnEntity`: follows `target`. */
    IEffect* HostEmitterOnEntity(Target target, const REmitterBlueprint* blueprint, int army);
    /** `CreateTrail`: follows `target`'s bone. */
    IEffect* HostTrail(Target target, int bone, RTrailBlueprint* blueprint, int army);
    /** `CreateBeam(RBeamBlueprint*, army)`: attached later (`Attach`, `AttachBone`). */
    IEffect* HostBeam(const RBeamBlueprint* blueprint, int army);
    /**
     * `CreateBeam(SCreateBeamParams)`, the attachment (`params.mAttachEntity` null) given as `target` (null: none),
     * by entity for `bone` -1, else by bone.
     */
    IEffect* HostBeamWithParams(const SCreateBeamParams& params, Target target, int bone);
    /** `CreateBeamEntityToEntity`: endpoints placed once at the two bones. */
    IEffect* HostBeamBetween(
      const IEffectFollowTarget& source,
      int sourceBone,
      const IEffectFollowTarget& target,
      int targetBone,
      const RBeamBlueprint* blueprint,
      int army
    );
    /** `AttachBeamEntityToEntity`: follows both. */
    IEffect* HostAttachedBeamBetween(
      Target source,
      int sourceBone,
      Target target,
      int targetBone,
      const RBeamBlueprint* blueprint,
      int army
    );
    /** `IEffect::SetEntity` with a target. */
    void Attach(IEffect& effect, Target target);
    /** `IEffect::SetBone` with a target. */
    void AttachBone(IEffect& effect, Target target, int bone);

    void PurgeDestroyedEffects() override;
    /** Called in `PurgeDestroyedEffects` for each effect before it is deleted. */
    void SetEndedHandler(
      std::function<void(const IEffect&)> ended
    )
    {
      mEnded = std::move(ended);
    }

    /** Effects alive (linked active), and the ones whose ends wait for the purge. */
    [[nodiscard]] std::size_t ActiveCount() const noexcept;
    [[nodiscard]] std::size_t FollowingCount() const noexcept
    {
      return mFollows.size();
    }

  private:
    struct SFollows
    {
      Target start;
      Target end;
    };

    /** Links a freshly constructed effect as `LinkActiveEffect` does. */
    template <class TEffect>
    TEffect* Link(TEffect* effect);
    /** Destroys a create whose blueprint the client's fidelity leaves out, as the sim's creates do. */
    void ApplyFidelity(IEffect* effect, const REffectBlueprint* blueprint);

    IEffectHost& mHost;
    // Looked up by effect and erased at its purge, never walked: its order reaches nothing, and no sim has one.
    std::unordered_map<const IEffect*, SFollows> mFollows;
    std::function<void(const IEffect&)> mEnded;
  };
} // namespace moho
