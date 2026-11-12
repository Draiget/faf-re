#pragma once

#include <cstddef>
#include <cstdint>

namespace moho
{
  class CEffectImpl;
  class IEffect;
  struct SParticleBuffer;

  /**
   * Engine addition (dedicated-server plan WPR.10): what each effect does in each tick, for a per-effect comparison of
   * two runtimes (a lockstep sim's effects against the effects a server-mode client hosts from the server's lane).
   * The observer is null in the game: every call below is then one load and a branch, and nothing the effects or the
   * sim compute changes. Set, it is called from whichever thread ticks the effect (a sim worker in the parallel effect
   * tick), so it serialises itself.
   */
  enum class EEffectEnd : std::uint8_t
  {
    Lifetime,   // its lifetime ran out
    EntityGone, // what it follows is gone or dying
    NotVisible, // an emitter made only if a camera sees it (`EFFECT_CREATEIFVISIBLE`) that none saw
  };

  /** One effect's tick: what it put in the particle buffer, and where an emitter is (no random in it). */
  struct SEffectTick
  {
    std::uint32_t particles = 0;
    std::uint32_t trails = 0;
    std::uint32_t beams = 0;
    bool hidden = false;     // its visibility test said no this tick (an emitter, a trail)
    bool positioned = false; // `position` is set: an emitter's place (`EFFECT_POSITION` on its attachment)
    float position[3]{};
    std::uint64_t paramsHash = 0; // the effect's parameters (`CEffectImpl::mParams`) as the tick began, hashed
  };

  class IEffectTickObserver
  {
  public:
    /** After each `OnTick` of an emitter, a trail or a beam (also one that ended in it). */
    virtual void OnEffectTicked(const IEffect& effect, const SEffectTick& tick) = 0;
    /** An effect ends itself, just before its `DestroyEffect`. */
    virtual void OnEffectEnding(const IEffect& effect, EEffectEnd why) = 0;
    /** `DestroyEffect`, for every reason, once per call (on the thread that commits it). */
    virtual void OnEffectDestroyed(const IEffect& effect) = 0;

  protected:
    ~IEffectTickObserver() = default;
  };

  /** Null in the game. */
  extern IEffectTickObserver* gEffectTickObserver;

  /**
   * Plan WPR.10: an effect curve's sample has a random spread (`SEfxCurve::GetValue`, each key's Z), drawn from the
   * non-sim random, so an emitter's particle count per tick differs between two runtimes as between two lockstep
   * clients. A comparison of two runtimes sets this to hold the spread at its centre in both, which makes their counts
   * comparable one for one. False in the game.
   */
  extern bool gEffectCurveSpreadCentred;

  inline void EFFECT_Ending(
    const IEffect& effect,
    const EEffectEnd why
  )
  {
    if (gEffectTickObserver != nullptr) {
      gEffectTickObserver->OnEffectEnding(effect, why);
    }
  }

  /**
   * One `OnTick` of `effect`, reported when the scope ends. With no observer it reads nothing; with one it reads the
   * effect's particle buffer's sizes at the start and the end (the buffer is the one the tick writes into: the sim's,
   * a parallel tick's chunk, or a hosted manager's host's).
   */
  class CEffectTickScope
  {
  public:
    explicit CEffectTickScope(const CEffectImpl& effect);
    ~CEffectTickScope();

    CEffectTickScope(const CEffectTickScope&) = delete;
    CEffectTickScope& operator=(const CEffectTickScope&) = delete;

    [[nodiscard]] bool Observing() const noexcept
    {
      return mBuffer != nullptr;
    }
    void SetHidden() noexcept
    {
      mTick.hidden = true;
    }
    void SetPosition(
      const float x,
      const float y,
      const float z
    ) noexcept
    {
      mTick.positioned = true;
      mTick.position[0] = x;
      mTick.position[1] = y;
      mTick.position[2] = z;
    }

  private:
    const CEffectImpl& mEffect;
    SParticleBuffer* mBuffer = nullptr;
    std::size_t mParticles = 0;
    std::size_t mTrails = 0;
    std::size_t mBeams = 0;
    SEffectTick mTick{};
  };
} // namespace moho
