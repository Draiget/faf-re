#pragma once

#include <cstdint>

namespace moho
{
  class IEffect;
  struct SCreateBeamParams;
  struct SEfxCurve;

  /**
   * Engine addition (dedicated-server plan WP9.1): every effect operation the sim performs ends in one of these entry
   * points (research WPR.9: the effect manager's creating methods, `DestroyEffect`, and the `IEffect` setters). A hook
   * set here sees each one as it happens; it is null in the game, where the call costs one load and a branch and
   * changes nothing the sim computes. Headless's `--effect-ops` counts them per beat and `--effect-record` encodes
   * them as the server's replication would send them.
   */
  enum class EEffectOp : std::uint8_t
  {
    CreateEmitter,
    CreateAttachedEmitter,
    CreateEmitterAtBone,
    CreateEmitterAtEntity,
    CreateEmitterOnEntity,
    CreateTrail,
    CreateBeam,
    CreateBeamEntityToEntity,
    AttachBeamEntityToEntity,
    CreateLightParticle,
    Destroy,
    SetFloat,
    SetVector,
    SetN,
    SetCurve,
    SetEntity,
    SetBone,
    DestroyByScript, // `IEffect:Destroy()` from Lua; `Destroy` counts every destroy, lifetime ends too
    Count
  };

  /** The op's name as `--effect-ops` writes it. */
  [[nodiscard]] const char* EffectOpName(EEffectOp op) noexcept;

  /**
   * One op's arguments, as its entry point has them. Unused fields keep their defaults. Entities are their ids
   * (`Entity::id_`), bones their index, `army` the army index. Pointers are valid only during the hook call.
   *
   * - Creates carry the new effect (after it is attached; a create that fails records nothing). `blueprint` is the
   *   effect blueprint's id (`REffectBlueprint::BlueprintId`); `CreateEmitter` and `CreateLightParticle` have their
   *   position in `values` (the light also its size and lifetime: 5 floats), the light its two textures.
   *   `CreateBeam` from `SCreateBeamParams` has no blueprint, only `beam`.
   * - `SetFloat`/`SetN`: `param` and `values`; `SetCurve`: `param` and `curve`; `SetEntity`: `entity`;
   *   `SetBone`: `entity` and `bone`. `Destroy`/`DestroyByScript`: the effect only.
   */
  struct SEffectOpArgs
  {
    const IEffect* effect = nullptr;
    std::int32_t entity = -1;
    std::int32_t bone = -1;
    std::int32_t entity2 = -1;
    std::int32_t bone2 = -1;
    std::int32_t army = -1;
    const char* blueprint = nullptr;
    const char* texture = nullptr;
    const char* texture2 = nullptr;
    std::int32_t param = -1;
    const float* values = nullptr;
    std::uint32_t valueCount = 0;
    const SEfxCurve* curve = nullptr;
    const SCreateBeamParams* beam = nullptr;
    /** `CreateLightParticle`: the armies (bit n: army n) whose intel shows it (`tEffectOpLightArmies`); all ones for a
     * plain light. */
    std::uint32_t armies = ~0u;
  };

  /**
   * Plan WP9.2: `CreateLightParticleIntel` makes its light only where the focus army's intel detects the point. A sim
   * with no focus army (the server's) makes it always; while a hook is set, the binding puts here the armies whose
   * intel detects it, as each army's client would decide, for the light's op (`SEffectOpArgs::armies`), and sets it
   * back to all ones after. Only the sim thread's Lua writes it.
   */
  inline thread_local std::uint32_t tEffectOpLightArmies = ~0u;

  /** `entity`'s id for `SEffectOpArgs`, -1 without one (a template so this header needs no `Entity`). */
  template <class TEntity>
  [[nodiscard]] inline std::int32_t EffectOpEntity(
    const TEntity* const entity
  ) noexcept
  {
    return entity != nullptr ? static_cast<std::int32_t>(entity->id_) : -1;
  }

  /** Called on the thread that performs the op. */
  using EffectOpHook = void (*)(EEffectOp op, const SEffectOpArgs& args);
  extern EffectOpHook gEffectOpHook;

  inline void EFFECT_Op(
    const EEffectOp op,
    const SEffectOpArgs& args
  ) noexcept
  {
    if (gEffectOpHook != nullptr) {
      gEffectOpHook(op, args);
    }
  }
} // namespace moho
