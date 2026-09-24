#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/FastVector.h"
#include "gpg/core/reflection/Reflection.h"
#include "legacy/containers/Vector.h"
#include "moho/effects/rendering/CEffectImpl.h"
#include "moho/effects/rendering/SEfxCurve.h"
#include "moho/particles/SWorldParticle.h"
#include "moho/render/EmitterType.h"
#include "Wm3Vector3.h"

namespace moho
{
  struct GeomCamera3;
  struct REmitterBlueprint;
  /// One emitter curve per `EEmitterCurve` lane; also the inline capacity.
  inline constexpr std::size_t kEmitterCurveCount = 21u;

  /**
   * VFTABLE: 0x00E240B4
   * COL: 0x00E7E5E4
   *
   * Particle emitter effect implementation with recovered visibility lanes.
   */
  class CEfxEmitter : public CEffectImpl
  {
  public:
    static gpg::RType* sType;

    /**
     * Address: 0x0065DD70 (FUN_0065DD70, Moho::CEfxEmitter::dtr)
     *
     * What it does:
     * Runs emitter teardown and forwards into `CEffectImpl` destructor paths.
     */
    ~CEfxEmitter() override;

    /**
     * Address: 0x0065C290 (FUN_0065C290, Moho::CEfxEmitter::UpdateCurveMask)
     *
     * What it does:
     * Rebuilds the packed bitmask for Z-flat curves by probing every emitter
     * curve lane and testing one-key Z magnitude against epsilon.
     */
    void UpdateCurveMask();

    /**
     * Address: 0x0065C370 (FUN_0065C370)
     * Slot: 10 (IEffect::GetCurveParam)
     *
     * What it does:
     * The emitter's curve `paramIndex` (an EEmitterCurve), in place.
     */
    SEfxCurve* GetCurveParam(std::int32_t paramIndex) override;

    /**
     * Address: 0x0065C320 (FUN_0065C320, Moho::CEfxEmitter::SetCurveParam)
     *
     * What it does:
     * Replaces curve `paramIndex` with a copy of `curve` - bounds and keys -
     * and invalidates it.
     */
    void SetCurveParam(std::int32_t paramIndex, const SEfxCurve* curve) override;

    /**
     * Address: 0x0065C390 (FUN_0065C390, Moho::CEfxEmitter::Invalidate1)
     *
     * What it does:
     * Clears emitter validity flag for one two-argument invalidation lane.
     */
    void Invalidate(std::int32_t paramIndex, std::int32_t valueCount) override;

    /**
     * Address: 0x0065C3A0 (FUN_0065C3A0, Moho::CEfxEmitter::Invalidate2)
     *
     * What it does:
     * Clears emitter validity flag for one single-argument invalidation lane.
     */
    void Invalidate2(std::int32_t paramIndex) override;

    /**
     * Address: 0x0065C420 (FUN_0065C420, Moho::CEfxEmitter::CanSeeCam)
     *
     * What it does:
     * Applies depth/frustum visibility checks and focused-army recon probes for
     * one camera.
     */
    [[nodiscard]] bool CanSeeCam(const GeomCamera3* camera);

    /**
     * Address: 0x0065C600 (FUN_0065C600, Moho::CEfxEmitter::IsVisible)
     *
     * What it does:
     * Scans sync cameras and returns whether this emitter should be processed
     * for the current tick.
     */
    [[nodiscard]] bool IsVisible();

    /**
     * Address: 0x006593E0 (FUN_006593E0, Moho::CEfxEmitter::InterpolatePosition)
     *
     * What it does:
     * Resolves entity transform history for one effect attachment lane, blends
     * orientation/position at `tick` + `interp`, and writes the resulting
     * world matrix (optionally composed with one parent-bone local transform).
     */
    [[nodiscard]] static bool InterpolatePosition(const CEffectImpl* effect, VMatrix4* outMatrix, int tick, float interp);

    /**
     * Address: 0x0065C1A0 (FUN_0065C1A0, Moho::CEfxEmitter::Interpolate)
     *
     * What it does:
     * Interpolates emitter attachment transform at `(tick=0, interp=0.0)` and
     * projects the first start-vector lane through that matrix into `mPos`.
     */
    void Interpolate();

    /**
     * Address: 0x0065C700 (FUN_0065C700, Moho::CEfxEmitter::ProcessLifetime)
     *
     * What it does:
     * Applies lifetime/attachment visibility gates and destroys the effect
     * when one terminal condition is met.
     */
    [[nodiscard]] bool ProcessLifetime();

    /**
     * Address: 0x0065DAC0 (FUN_0065DAC0, Moho::CEfxEmitter::OnTick)
     *
     * What it does:
     * Per-frame emitter update: refreshes cached position, gates on
     * lifetime/visibility, bumps the active-emitter stat, rebuilds curves when
     * invalid, and drives the per-sub-tick particle emission loop.
     */
    void OnTick() override;

    /**
     * Address: 0x0065CE00 (FUN_0065CE00, Moho::CEfxEmitter::Tick)
     *
     * What it does:
     * Emits the accumulated whole+fractional particle count for one sub-tick,
     * building and queuing one SWorldParticle per emission.
     */
    [[nodiscard]] bool Tick(std::int32_t tick);

    /**
     * Address: 0x0065C7F0 (FUN_0065C7F0, IDA-mislabeled Moho::SEfxCurve::UpdateCurve)
     *
     * What it does:
     * Rebuilds the cached particle template from the current curve lanes and
     * scalar params, then marks the emitter valid.
     */
    void UpdateCurve();

    /**
     * Address: 0x00660280 (FUN_00660280, Moho::CEfxEmitter::MemberSerialize)
     *
     * What it does:
     * Serializes base effect lanes, emitter metadata, blueprint pointer,
     * particle payload, and visibility/lifetime state.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    /**
     * Address: 0x006600D0 (FUN_006600D0, Moho::CEfxEmitter::MemberDeserialize)
     *
     * What it does:
     * Inverse of `MemberSerialize`: reads base effect lanes, emitter
     * metadata, curves vector, blueprint pointer, particle payload, and
     * visibility/lifetime state from one read archive in the same
     * field-by-field order that `MemberSerialize` wrote.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

  public:
    /**
     * Address: 0x0065B9B0 (FUN_0065B9B0, Moho::CEfxEmitter::CEfxEmitter)
     *
     * What it does:
     * Default-constructs one emitter: invokes the `CEffectImpl` base ctor,
     * publishes the `CEfxEmitter` vftable, zeroes the emitter type, arms the
     * embedded `mCurves` fastvector on its own 21-entry inline window,
     * default-constructs the particle slot, and zero-initializes the remaining
     * emitter-state fields. The curve vector is left empty -- only the
     * blueprint constructor fills it.
     */
    CEfxEmitter();

    /**
     * Address: 0x0065BA80 (FUN_0065BA80, Moho::CEfxEmitter::CEfxEmitter)
     *
     * What it does:
     * Blueprint-driven emitter ctor. Chains the manager-bound `CEffectImpl` base
     * ctor, fills `mCurves` with 21 default curves,
     * sizes the param/texture/string lanes, seeds the emit position and three
     * fixed defaults (tick-increment=1, tick-count=0, scale=1), and -- when a
     * blueprint is supplied -- rebuilds all 21 emitter curves from the blueprint
     * and publishes the 20 blueprint scalar parameters plus the two texture
     * names, then interpolates the initial attachment transform. (In the binary
     * the manager arrives in ecx and the object/position/token/blueprint are
     * stack args; IDA mislabels the symbol as the default ctor.)
     */
    CEfxEmitter(
      CEffectManagerImpl* manager,
      const Wm3::Vector3<float>& position,
      int scriptObjectToken,
      const REmitterBlueprint* blueprint
    );

  private:
    friend struct CEfxEmitterLayoutVerifier;

    EmitterType mEmitterType;               // +0x190
    std::uint8_t mPad194[0x04];             // +0x194
    /**
     * A `0x10` `{start_, end_, capacity_, originalVec_}`
     * head at `+0x198` followed immediately by its own `21 * 0x38` inline window
     * at `+0x1A8`, which ends exactly where `mBlueprint` begins (`+0x640`).
     *
     * Both constructors arm it with the four stores at 0x0065B9F0 / 0x0065BAC7
     * (`start_ = end_ = originalVec_ = this + 0x1A8`, `capacity_ = that + 0x498`),
     * `~CEfxEmitter` releases it at 0x0065DE3F through the `ResetInline_` shape,
     * and a blueprint emitter fills it with `resize(21, SEfxCurve{})` at
     * 0x0065BB41. Capacity is exactly the fill count, so a well-formed emitter
     * never leaves the inline window -- the destructor's heap arm is dead in
     * practice and stays only because the container cannot know that.
     *
     * Formerly modelled as a hand-written `CEfxCurveVectorRuntime` four-pointer
     * head plus a separate `std::uint8_t mInlineCurveStorage[21 * 0x38]` byte
     * lane, with both constructors writing the four pointers by hand and
     * `mEnd` spelled `reinterpret_cast<SEfxCurve*>(&mBlueprint)` -- the
     * capacity-end of the window happens to be the address of the next member.
     */
    gpg::fastvector_n<SEfxCurve, kEmitterCurveCount> mCurves; // +0x198
    REmitterBlueprint* mBlueprint;          // +0x640
    float mTotalEmissions;                  // +0x644
    std::uint32_t mLife;                    // +0x648
    SWorldParticle mParticle;               // +0x64C
    bool mValid;                            // +0x6D8
    std::uint8_t mPad6D9[0x03];             // +0x6D9
    std::uint32_t mZCurveMask;              // +0x6DC
    std::int32_t mMaxLifetime;              // +0x6E0
    bool mVisible;                          // +0x6E4
    std::uint8_t mPad6E5[0x03];             // +0x6E5
    std::uint32_t mLastUpdate;              // +0x6E8
    Wm3::Vec3f mPos;                        // +0x6EC
  };

  struct CEfxEmitterLayoutVerifier
  {
    static_assert(offsetof(CEfxEmitter, mEmitterType) == 0x190, "CEfxEmitter::mEmitterType offset must be 0x190");
    static_assert(offsetof(CEfxEmitter, mCurves) == 0x198, "CEfxEmitter::mCurves offset must be 0x198");
    static_assert(sizeof(CEfxEmitter::mCurves) == 0x4A8, "CEfxEmitter::mCurves size must be 0x4A8");
    static_assert(
      offsetof(CEfxEmitter, mCurves.inlineVec_) == 0x1A8, "CEfxEmitter::mCurves inline window offset must be 0x1A8"
    );
    static_assert(offsetof(CEfxEmitter, mBlueprint) == 0x640, "CEfxEmitter::mBlueprint offset must be 0x640");
    static_assert(offsetof(CEfxEmitter, mTotalEmissions) == 0x644, "CEfxEmitter::mTotalEmissions offset must be 0x644");
    static_assert(offsetof(CEfxEmitter, mLife) == 0x648, "CEfxEmitter::mLife offset must be 0x648");
    static_assert(offsetof(CEfxEmitter, mParticle) == 0x64C, "CEfxEmitter::mParticle offset must be 0x64C");
    static_assert(offsetof(CEfxEmitter, mValid) == 0x6D8, "CEfxEmitter::mValid offset must be 0x6D8");
    static_assert(offsetof(CEfxEmitter, mZCurveMask) == 0x6DC, "CEfxEmitter::mZCurveMask offset must be 0x6DC");
    static_assert(offsetof(CEfxEmitter, mMaxLifetime) == 0x6E0, "CEfxEmitter::mMaxLifetime offset must be 0x6E0");
    static_assert(offsetof(CEfxEmitter, mVisible) == 0x6E4, "CEfxEmitter::mVisible offset must be 0x6E4");
    static_assert(offsetof(CEfxEmitter, mLastUpdate) == 0x6E8, "CEfxEmitter::mLastUpdate offset must be 0x6E8");
    static_assert(offsetof(CEfxEmitter, mPos) == 0x6EC, "CEfxEmitter::mPos offset must be 0x6EC");
    static_assert(sizeof(CEfxEmitter) == 0x6F8, "CEfxEmitter size must be 0x6F8");
  };
} // namespace moho
