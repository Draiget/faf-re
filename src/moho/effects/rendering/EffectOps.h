#pragma once

#include <cstdint>

namespace moho
{
  class IEffect;

  /**
   * Engine addition (dedicated-server plan WP9.1): every effect operation the sim performs ends in one of these entry
   * points (research WPR.9: the effect manager's creating methods, `DestroyEffect`, and the `IEffect` setters). A hook
   * set here sees each one as it happens; it is null in the game, where the call costs one load and a branch and
   * changes nothing the sim computes. Headless's `--effect-ops` counts them per beat; the server's replication records
   * them.
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

  /** Called on the thread that performs the op (emitters ending their lifetime can be on a sim worker). */
  using EffectOpHook = void (*)(EEffectOp op, const IEffect* effect);
  extern EffectOpHook gEffectOpHook;

  inline void EFFECT_Op(
    const EEffectOp op,
    const IEffect* const effect
  ) noexcept
  {
    if (gEffectOpHook != nullptr) {
      gEffectOpHook(op, effect);
    }
  }
} // namespace moho
