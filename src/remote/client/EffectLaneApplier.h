#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <unordered_map>
#include <utility>
#include <vector>

#include "remote/wire/EffectLane.h"

// Engine addition, server mode (plan WP9.3): the client's end of the server's effects lane (remote/wire/EffectLane.h).
// Each view's lane is read after the view's frames are applied (an op names entities the same message may create),
// and its ops are applied in order to the client's effects through `IEffectLaneTarget`:
//
// - A create makes the effect under the server's id. A create for an id the client holds replaces that effect (the
//   server sends an effect whole again, with the same id, when its entity comes back or after a whole view). One whose
//   entity the client doesn't hold, whose name it was never sent or whose blueprint it doesn't have is skipped and
//   counted; later ops on that id then count as on an unknown effect.
// - Setters go to the held effect; `SetEntity`/`SetBone` to an entity the client lacks drops the effect.
// - `DestroyByScript` destroys it. Every other end is the client's own: `Ended` for an effect whose lifetime ran out
//   or whose entity died (the client's effect manager knows), and, after each lane, every effect that follows an
//   entity (or a beam end) the client no longer holds is dropped with it, as the server expects. An emitter placed
//   once at an entity or a bone, or at a point, doesn't follow anything and stays.
// - A whole view (the server takes the client to hold nothing: back from a lost connection, or a mended frame) drops
//   every effect first; the server sends again whatever the client can place.
//
// Lights have no id: each one is handed to the target once.
//
// The ids in ops are the client's own: the server translates each entity to the id the view's client holds it under
// (server/EffectOpRouter.h `CEffectViewRoute::Write`), -1 for one it holds under none.

namespace moho
{
  class RRuleGameRules;
}

namespace faf::remote::client
{
  /**
   * Whether `rules` have the blueprint a create op names: an emitter's, a trail's, or a beam's (beam creates,
   * `CreateBeamEntityToEntity`, `AttachBeamEntityToEntity`), looked up as the sim's effect manager and bindings do
   * (EffectBlueprint.cpp; needs the engine, unlike the rest of this header).
   */
  [[nodiscard]] bool HasEffectBlueprint(moho::RRuleGameRules& rules, moho::EEffectOp op, const std::string& name);

  /** Why an op wasn't applied. */
  enum class EEffectSkip : std::uint8_t
  {
    EntityNotHeld,    // a create or an attach naming an entity the client doesn't hold
    UnknownEffect,    // a setter or a destroy for an id the client doesn't hold
    UnknownName,      // a blueprint or texture reference to a name the client wasn't sent
    UnknownBlueprint, // a blueprint the client's rules don't have (the target refused the create)
    Count
  };

  [[nodiscard]] const char* EffectSkipName(EEffectSkip skip) noexcept;

  inline constexpr std::size_t kEffectSkipCount = static_cast<std::size_t>(EEffectSkip::Count);

  /** What the applier did with some lanes (one beat's, or every lane so far). */
  struct SEffectApplyCounts
  {
    std::uint64_t lanes = 0;    // lanes with ops
    std::uint64_t ops = 0;      // ops read
    std::uint64_t applied = 0;  // ops that reached the target (creates, setters, destroys, lights)
    std::uint64_t created = 0;  // effects made (replacements included)
    std::uint64_t replaced = 0; // creates for an id held: the old effect went first
    std::uint64_t setters = 0;
    std::uint64_t lights = 0;
    std::uint64_t destroyedByScript = 0;
    std::uint64_t droppedWithEntity = 0; // following an entity the client no longer holds
    std::uint64_t droppedWhole = 0;      // at a whole view
    std::uint64_t ended = 0;             // `Ended`: the client derived the end
    std::uint64_t agedOut = 0;           // `SetHorizon`
    std::uint64_t badLanes = 0;          // lanes that didn't decode
    std::uint64_t unticked = 0;          // plan WP9.5: lanes saying the sim didn't tick its effects
    std::array<std::uint64_t, kEffectSkipCount> skipped{};

    [[nodiscard]] std::uint64_t Skipped() const noexcept;
    void Add(const SEffectApplyCounts& other) noexcept;
  };

  /**
   * The client's effects as the applier drives them: the effect manager's creates and the effect's setters, and what
   * the client's world holds. Ids are the server's effect ids (never reused); entities the client's ids.
   */
  class IEffectLaneTarget
  {
  public:
    virtual ~IEffectLaneTarget() = default;

    /**
     * Whether the client holds an entity with this id now; `orRemoved`: or held it until the view just applied
     * removed it (an emitter placed once at an entity may name a projectile the same message removes).
     */
    [[nodiscard]] virtual bool HoldsEntity(std::int32_t entity, bool orRemoved) const = 0;
    /**
     * Makes effect `id` from a create op (any but `CreateLightParticle`); `blueprint` and `texture` are the op's names
     * (null for none). False when the client can't make it (a blueprint its rules don't have).
     */
    [[nodiscard]] virtual bool Create(
      std::uint32_t id,
      const wire::SEffectLaneOp& op,
      const std::string* blueprint,
      const std::string* texture
    ) = 0;
    /** A setter on effect `id`, which the target made (`SetFloat`, `SetVector`, `SetN`, `SetCurve`, `SetEntity`,
     * `SetBone`). */
    virtual void Change(std::uint32_t id, const wire::SEffectLaneOp& op) = 0;
    /** Effect `id` goes: the script destroyed it, it was replaced, or its entity went. */
    virtual void Destroy(std::uint32_t id) = 0;
    /** A one-shot light. */
    virtual void Light(const wire::SEffectLaneOp& op, const std::string* texture, const std::string* ramp) = 0;
    /** Plan WP9.5: the sim didn't tick its effects this beat (`wire::IsUntickedEffectLane`): nor should the target. */
    virtual void Unticked() {}
  };

  class CEffectLaneApplier
  {
  public:
    explicit CEffectLaneApplier(
      IEffectLaneTarget& target
    ) noexcept
      : mTarget(target)
    {}

    /**
     * One view's effects lane, after its frames are applied. `whole`: the view came whole (its frame against
     * nothing), so the server takes this client to hold no effect: every one is dropped first. False when the lane
     * doesn't decode (the ops before the fault are applied).
     */
    bool Apply(std::span<const std::uint8_t> lane, bool whole);

    /** The client derived the end of effect `id` (its lifetime, its entity's death): forgotten, nothing destroyed. */
    void Ended(std::uint32_t id);

    /**
     * For a target that can't run an effect out (one that only counts, until effects are hosted outside the sim):
     * effects no op has named for `beats` lanes are forgotten as if they had ended (`agedOut`). 0: never (the default).
     */
    void SetHorizon(
      const std::uint32_t beats
    ) noexcept
    {
      mHorizon = beats;
    }

    /** Effects held now. */
    [[nodiscard]] std::size_t Live() const noexcept
    {
      return mLive.size();
    }
    [[nodiscard]] bool Holds(
      const std::uint32_t id
    ) const noexcept
    {
      return mLive.contains(id);
    }
    /** The entity a held effect follows (its first, for a beam between two), -1 for none or an effect not held. */
    [[nodiscard]] std::int32_t Following(
      const std::uint32_t id
    ) const noexcept
    {
      const auto found = mLive.find(id);
      return found != mLive.end() ? found->second.entity : -1;
    }
    /** `visit(id)` for each effect held. */
    template <class Visit>
    void ForEachHeld(
      Visit&& visit
    ) const
    {
      for (const auto& [id, live] : mLive) {
        visit(id);
      }
    }
    /** The last lane's counts, and every lane's. */
    [[nodiscard]] const SEffectApplyCounts& LastLane() const noexcept
    {
      return mLast;
    }
    [[nodiscard]] const SEffectApplyCounts& Total() const noexcept
    {
      return mTotal;
    }
    /** The most ops one lane carried. */
    [[nodiscard]] std::uint64_t MostOps() const noexcept
    {
      return mMostOps;
    }
    [[nodiscard]] const wire::CEffectLaneReader& Reader() const noexcept
    {
      return mReader;
    }

  private:
    struct SLive
    {
      std::int32_t entity = -1;  // what it follows; -1: nothing (placed once, at a point, an unattached beam)
      std::int32_t entity2 = -1; // a beam's other end
      std::uint32_t lane = 0;    // the lane that last named it (`SetHorizon`)
    };

    void Skip(
      EEffectSkip why
    ) noexcept
    {
      ++mLast.skipped[static_cast<std::size_t>(why)];
    }
    void ApplyOp(const wire::SEffectLaneOp& op);
    void Create(const wire::SEffectLaneOp& op);
    void Drop(std::uint32_t id);

    IEffectLaneTarget& mTarget;
    wire::CEffectLaneReader mReader;
    std::vector<wire::SEffectLaneOp> mOps;
    std::unordered_map<std::uint32_t, SLive> mLive;
    std::uint32_t mLanes = 0; // lanes applied, empty ones too
    std::uint32_t mHorizon = 0;
    SEffectApplyCounts mLast;
    SEffectApplyCounts mTotal;
    std::uint64_t mMostOps = 0;
  };

  /**
   * A target that makes nothing and only answers for the client's world: what a client that doesn't host effects
   * (the probe, a bench, the game client until effects run outside the sim) keeps of them. `holds` answers
   * `HoldsEntity`; `hasBlueprint`, when set, whether a create's blueprint is one the client has.
   */
  template <class Holds, class HasBlueprint>
  class CEffectCountTarget final : public IEffectLaneTarget
  {
  public:
    CEffectCountTarget(
      Holds holds,
      HasBlueprint hasBlueprint
    )
      : mHolds(std::move(holds))
      , mHasBlueprint(std::move(hasBlueprint))
    {}

    [[nodiscard]] bool HoldsEntity(
      const std::int32_t entity,
      const bool orRemoved
    ) const override
    {
      return mHolds(entity, orRemoved);
    }
    [[nodiscard]] bool Create(
      const std::uint32_t,
      const wire::SEffectLaneOp& op,
      const std::string* const blueprint,
      const std::string*
    ) override
    {
      return blueprint == nullptr || mHasBlueprint(op.op, *blueprint);
    }
    void Change(
      std::uint32_t,
      const wire::SEffectLaneOp&
    ) override
    {}
    void Destroy(
      std::uint32_t
    ) override
    {}
    void Light(
      const wire::SEffectLaneOp&,
      const std::string*,
      const std::string*
    ) override
    {}

  private:
    Holds mHolds;
    HasBlueprint mHasBlueprint;
  };
} // namespace faf::remote::client
