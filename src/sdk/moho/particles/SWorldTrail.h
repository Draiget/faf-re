#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/particles/CParticleTextureCountedPtr.h"
#include "Wm3Vector3.h"

namespace moho
{
  /**
   * One trail ribbon segment queued for rendering, the third element type of
   * `SParticleBuffer` alongside `SWorldParticle` (+0x00) and `SWorldBeam`
   * (+0x20). `CEfxTrailEmitter::Tick` (0x00671850) pushes one per sub-tick and
   * `CWorldParticles` re-buckets it by texture/tag/blend mode before
   * `UploadPendingTrailsIntoWorkItem` expands it into four vertices.
   *
   * Naming: unlike its two siblings this struct is not reflected -- there is no
   * `SWorldTrail` type info, serializer or RTTI descriptor, and neither
   * "SWorldTrail" nor "STrail" occurs anywhere in the shipped image, so the
   * original spelling is not recoverable. The name follows the two siblings it
   * shares `SParticleBuffer` with. Every offset below, by contrast, is read
   * straight out of the binary.
   *
   * Layout evidence: the writer `CEfxTrailEmitter::Tick` builds the record on
   * the stack from `[esp+0x38]`; the bucket-key reader (0x00492390) takes
   * `[trail+0x48]` as the sort scalar and `[trail+0x50]` as the first texture;
   * the vertex packer reads it as `float[20]`; and the copy constructor
   * (0x0049BDD0) and destructor (0x0049BE90) touch exactly the two counted
   * handles.
   */
  struct SWorldTrail
  {
    /**
     * Address: 0x0049BDD0 (FUN_0049BDD0 -- the compiler-generated copy of this
     * 0x60-byte record: the float block, then both counted texture handles
     * retained through `CountedPtr`'s copy, then `mTypeTag`/`mBlendMode`;
     * emitted out of line for `msvc8::vector<SWorldTrail>`'s copy steps.
     * Formerly transcribed as `CopyTrailRuntimeViewForVectorMove` in
     * ParticleRenderBuckets.cpp, removed 2026-09-10.)
     * Address: 0x0049BE90 (FUN_0049BE90 -- the implicit destructor: both
     * `CountedPtr` handles release their texture. Formerly
     * `DestroyTrailRuntimeViewForVectorTail`, removed.)
     * Address: 0x0049FBF0 (FUN_0049FBF0 -- the compiler-generated copy assignment as emitted for the `msvc8::vector` instantiation; callers 0x00495850, 0x0049DE60, 0x0049E4E0; formerly `CopyAssignTrailRuntimeAndReturnDestination` in moho/particles/CWorldParticles.cpp (RULE ONE), removed 2026-09-10.)
     * Address: 0x0049FFB0 (FUN_0049FFB0 -- a second emission of that copy assignment; zero callers, unreachable; formerly `CopyAssignTrailRuntimeIfDestinationPresent`, removed 2026-09-10.)
     * Address: 0x0049FFC0 (FUN_0049FFC0 -- the implicit destructor as emitted for the `msvc8::vector` instantiation; zero callers, unreachable; formerly `DestroyTrailRuntimeInPlace`, removed 2026-09-10.)
     * Address: 0x004A0620 (FUN_004A0620 -- the placement copy constructor as emitted for the `msvc8::vector` instantiation; zero callers, unreachable; formerly `CopyConstructTrailRuntimeIfDestinationPresent`, removed 2026-09-10.)
     * Address: 0x004A0630 (FUN_004A0630 -- another emission of the implicit destructor; zero callers, unreachable; formerly `DestroyTrailRuntimeInPlaceDuplicateA`, removed 2026-09-10.)
     * Address: 0x004A0720 (FUN_004A0720 -- another emission of the implicit destructor; zero callers, unreachable; formerly `DestroyTrailRuntimeInPlaceAndReturnSelf`, removed 2026-09-10.)
     */

    /// Ribbon start, the trail point interpolated at `(tick, 0.0)`.
    Wm3::Vector3<float> mStartPos;                // +0x00

    /// Ribbon end, the trail point interpolated at `(tick, interpScale)`.
    Wm3::Vector3<float> mEndPos;                  // +0x0C

    /**
     * Ribbon tangent at `mStartPos`: the *previous* segment's normalized
     * direction, carried across ticks in `CEfxTrailEmitter::mSerializedTrailPosition`
     * (and equal to `mEndTangent` on the emitter's first tick, when there is no
     * previous segment). The vertex packer emits it negated for one side of the
     * quad and plain for the other, which is what makes it a tangent and not a
     * position.
     */
    Wm3::Vector3<float> mStartTangent;            // +0x18

    /// Ribbon tangent at `mEndPos`: this segment's normalized direction.
    Wm3::Vector3<float> mEndTangent;              // +0x24

    /**
     * Age in frames of each ribbon end, counted from the segment's emission:
     * `-1 - tick` at the start and that plus the interpolation scale at the
     * end. `UploadPendingTrailsIntoWorkItem` advances both by `frameDelta + 1`
     * every time the segment is uploaded, so they run up towards `mLifetime`.
     */
    float mStartAge = 0.0f;                       // +0x30
    float mEndAge = 0.0f;                         // +0x34

    /// Lifetime in frames (blueprint `TrailLength`); the work-item interval is `mLifetime + 1`.
    float mLifetime = 0.0f;                       // +0x38

    /// Emitter age when this segment was emitted, negated; advanced with the two ages above.
    float mEmitterAge = 0.0f;                     // +0x3C

    /**
     * Texture U coordinate at each ribbon end: blueprint `TextureRepeatRate`
     * times the accumulated trail length before and after this segment, so the
     * sheet scrolls with distance travelled rather than with time.
     */
    float mTexCoordStart = 0.0f;                  // +0x40
    float mTexCoordEnd = 0.0f;                    // +0x44

    /// Blueprint `SortOrder`; the primary bucket-key sort scalar (float compare at 0x00492520).
    float mSortOrder = 0.0f;                      // +0x48

    /// Blueprint `StartSize`; the ribbon half-width handed to every vertex.
    float mSize = 0.0f;                           // +0x4C

    /// Blueprint `RepeatTexture`, resolved through `CEfxTrailEmitter::mParticleTextures[0]`.
    CountedPtr_CParticleTexture mTexture;         // +0x50

    /// Blueprint `RampTexture`, resolved through `CEfxTrailEmitter::mParticleTextures[1]`.
    CountedPtr_CParticleTexture mRampTexture;     // +0x54

    /// Effect technique family; always the literal `"TPolyTrail"`.
    const char* mTypeTag = nullptr;               // +0x58

    /**
     * Blueprint `BlendMode`, a `std::int32_t` and not a float: the bucket-key
     * comparator at 0x0049253F loads this lane with `mov`/`cmp`/`setl` -- a
     * signed integer compare -- where it loads the sort scalar at +0x00 with
     * `movss`/`ucomiss`. It used to be declared `float uvScalar` here and in
     * all three structs it flows through, with a `std::memcpy` at each end of
     * the chain to launder the type back.
     */
    std::int32_t mBlendMode = 0;                  // +0x5C
  };

  static_assert(offsetof(SWorldTrail, mStartPos) == 0x00, "SWorldTrail::mStartPos offset must be 0x00");
  static_assert(offsetof(SWorldTrail, mEndPos) == 0x0C, "SWorldTrail::mEndPos offset must be 0x0C");
  static_assert(offsetof(SWorldTrail, mStartTangent) == 0x18, "SWorldTrail::mStartTangent offset must be 0x18");
  static_assert(offsetof(SWorldTrail, mEndTangent) == 0x24, "SWorldTrail::mEndTangent offset must be 0x24");
  static_assert(offsetof(SWorldTrail, mStartAge) == 0x30, "SWorldTrail::mStartAge offset must be 0x30");
  static_assert(offsetof(SWorldTrail, mEndAge) == 0x34, "SWorldTrail::mEndAge offset must be 0x34");
  static_assert(offsetof(SWorldTrail, mLifetime) == 0x38, "SWorldTrail::mLifetime offset must be 0x38");
  static_assert(offsetof(SWorldTrail, mEmitterAge) == 0x3C, "SWorldTrail::mEmitterAge offset must be 0x3C");
  static_assert(offsetof(SWorldTrail, mTexCoordStart) == 0x40, "SWorldTrail::mTexCoordStart offset must be 0x40");
  static_assert(offsetof(SWorldTrail, mTexCoordEnd) == 0x44, "SWorldTrail::mTexCoordEnd offset must be 0x44");
  static_assert(offsetof(SWorldTrail, mSortOrder) == 0x48, "SWorldTrail::mSortOrder offset must be 0x48");
  static_assert(offsetof(SWorldTrail, mSize) == 0x4C, "SWorldTrail::mSize offset must be 0x4C");
  static_assert(offsetof(SWorldTrail, mTexture) == 0x50, "SWorldTrail::mTexture offset must be 0x50");
  static_assert(offsetof(SWorldTrail, mRampTexture) == 0x54, "SWorldTrail::mRampTexture offset must be 0x54");
  static_assert(offsetof(SWorldTrail, mTypeTag) == 0x58, "SWorldTrail::mTypeTag offset must be 0x58");
  static_assert(offsetof(SWorldTrail, mBlendMode) == 0x5C, "SWorldTrail::mBlendMode offset must be 0x5C");
  static_assert(sizeof(SWorldTrail) == 0x60, "SWorldTrail size must be 0x60");
} // namespace moho
