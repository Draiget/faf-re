#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "legacy/containers/Map.h"
#include "legacy/containers/Vector.h"
#include "legacy/containers/String.h"
#include "moho/math/Vector4f.h"
#include "moho/particles/SWorldBeam.h"
#include "moho/particles/CParticleTextureCountedPtr.h"
#include "moho/particles/SWorldTrail.h"
#include "moho/particles/SWorldParticle.h"
#include "moho/resource/CParticleTexture.h"
#include "Wm3Vector3.h"

namespace moho
{
  struct BeamBucketContainerRuntime;
  class ID3DTextureSheet;
  class CD3DVertexFormat;
  class CD3DVertexSheet;

  /**
   * One batching quad writer over a `CD3DVertexSheet`: reserve a sheet sized
   * for `maxQuadCount` quads, map its first vertex stream, append quads through
   * the write cursor, then flush one indexed triangle-list draw for everything
   * appended since the map. A 5-dword block in the binary, passed as `this`.
   *
   * The nine members below are out-of-line COMDATs at 0x0043C360..0x0043C760
   * with no callers and no xrefs -- every use site inlined them -- so the class
   * that owns an instance is still unidentified and nothing in `src/sdk`
   * constructs one yet. That is a research task on the owner, not on this
   * object: its own shape is fully determined by the nine bodies.
   */
  struct BeamDrawContext
  {
    CD3DVertexSheet* sheet = nullptr; // +0x00
    std::int32_t maxQuadCount = 0;    // +0x04
    std::int32_t maxVertexCount = 0;  // +0x08  always 4 * maxQuadCount
    std::int32_t quadCount = 0;       // +0x0C  appended since the last BeginMap
    float* writeCursor = nullptr;     // +0x10  null outside a map session

    /**
     * Address: 0x0043C360 (FUN_0043C360, sub_43C360)
     *
     * What it does:
     * Lazy first-use setup, a no-op once a sheet exists: records the quad
     * capacity, derives the vertex capacity as `4 * quadCount`
     * (`add eax,eax; add eax,eax` at 0x0043C36B -- which is what identifies
     * `+0x04` as the quad count and `+0x08` as the vertex count), clears the
     * cursor, builds the shared vertex sheet and primes the shared index sheet.
     */
    void Initialize(int quadCount);

    /**
     * Address: 0x0043C3D0 (FUN_0043C3D0, sub_43C3D0)
     *
     * What it does:
     * Locks the sheet's first vertex stream for exclusive write access over the
     * full vertex capacity, seats the write cursor on the mapped pointer and
     * resets the running quad count.
     */
    void BeginMap();

    /**
     * Address: 0x0043C400 (FUN_0043C400, sub_43C400)
     *
     * What it does:
     * Unlocks the vertex stream and clears the cursor, if a map session is live.
     */
    void EndMap();

    /**
     * Address: 0x0043C390 (FUN_0043C390, sub_43C390)
     *
     * What it does:
     * Ends any map session, then releases the vertex sheet through its
     * deleting-destructor thunk and nulls it, leaving the context reusable.
     */
    void Teardown();

    /**
     * Address: 0x0043C430 (FUN_0043C430, sub_43C430)
     *
     * What it does:
     * Appends one axis-aligned quad built from a 6-float min/max box and a
     * translation, in the winding the binary emits:
     *   v0 = (box[0]+dx, box[4]+dy, box[2]+dz)
     *   v1 = (box[3]+dx, box[4]+dy, box[2]+dz)
     *   v2 = (box[3]+dx, box[1]+dy, box[5]+dz)
     *   v3 = (box[0]+dx, box[1]+dy, box[5]+dz)
     */
    float* WriteTranslatedQuad(const float* boxCorners, float dx, float dy, float dz);

    /**
     * Address: 0x0043C510 (FUN_0043C510, sub_43C510)
     *
     * What it does:
     * Appends one already-packed quad: twelve floats copied straight through.
     */
    const float* WritePackedQuad(const float* packedQuad);

    /**
     * Address: 0x0043C580 (FUN_0043C580, sub_43C580)
     *
     * What it does:
     * Ends any map session, then submits one indexed triangle-list draw
     * covering the quads appended since `BeginMap`, through the shared
     * forward-filled index sheet.
     */
    bool FlushQuadDraw();

    /**
     * Address: 0x0043C610 (FUN_0043C610, sub_43C610)
     *
     * What it does:
     * The same flush with caller-supplied view bounds; the running count is not
     * consulted.
     */
    bool FlushQuadDraw(int quadCount);

    /**
     * Address: 0x0043C760 (FUN_0043C760, sub_43C760)
     *
     * What it does:
     * Builds a fresh vertex sheet for the current vertex capacity from vertex
     * format 3 and the shared vertex stream, installs it and releases the one
     * it replaced. Returns the old sheet.
     */
    CD3DVertexSheet* CreateVertexSheet();
  };

  static_assert(offsetof(BeamDrawContext, sheet) == 0x00, "BeamDrawContext::sheet offset must be 0x00");
  static_assert(offsetof(BeamDrawContext, maxQuadCount) == 0x04, "BeamDrawContext::maxQuadCount offset must be 0x04");
  static_assert(
    offsetof(BeamDrawContext, maxVertexCount) == 0x08, "BeamDrawContext::maxVertexCount offset must be 0x08"
  );
  static_assert(offsetof(BeamDrawContext, quadCount) == 0x0C, "BeamDrawContext::quadCount offset must be 0x0C");
  static_assert(offsetof(BeamDrawContext, writeCursor) == 0x10, "BeamDrawContext::writeCursor offset must be 0x10");
  static_assert(sizeof(BeamDrawContext) == 0x14, "BeamDrawContext size must be 0x14");

  using TextureSheetHandle = boost::shared_ptr<ID3DTextureSheet>;

  /**
   * What it does:
   * Runtime key lane used by beam texture/render buckets.
   * Address: 0x004921D0 (FUN_004921D0 -- the key's implicit default constructor -- both `TextureSheetHandle` members start empty for `msvc8::map<BeamTextureBucketKeyRuntime, msvc8::vector<SWorldBeam>>` (`CWorldParticles::mBeams.mBuckets`; pair 0x24, node 0x34, colour@+0x30, isNil@+0x31); zero callers, unreachable; formerly `InitializeBeamTextureBucketKeyHandles` in moho/particles/BeamRenderHelpers.cpp (RULE ONE), removed 2026-09-10.)
   */
  struct BeamTextureBucketKeyRuntime
  {
    TextureSheetHandle texture0;   // +0x00
    TextureSheetHandle texture1;   // +0x08
    std::int32_t blendMode = 0;    // +0x10
  };

  static_assert(
    offsetof(BeamTextureBucketKeyRuntime, texture0) == 0x00, "BeamTextureBucketKeyRuntime::texture0 offset must be 0x00"
  );
  static_assert(
    offsetof(BeamTextureBucketKeyRuntime, texture1) == 0x08, "BeamTextureBucketKeyRuntime::texture1 offset must be 0x08"
  );
  static_assert(
    offsetof(BeamTextureBucketKeyRuntime, blendMode) == 0x10, "BeamTextureBucketKeyRuntime::blendMode offset must be 0x10"
  );
  static_assert(sizeof(BeamTextureBucketKeyRuntime) == 0x14, "BeamTextureBucketKeyRuntime size must be 0x14");

  /**
   * What it does:
   * Comparator lane for `BeamTextureBucketKeyRuntime`, matching binary ordering:
   * blend mode first, then texture ownership lanes.
   */
  struct BeamTextureBucketKeyLess
  {
    [[nodiscard]] bool operator()(
      const BeamTextureBucketKeyRuntime& lhs, const BeamTextureBucketKeyRuntime& rhs
    ) const noexcept;
  };

  // Binary-facing layout: the MSVC8 tree header is 0x0C bytes, which `std::map`
  // only measures under `_ITERATOR_DEBUG_LEVEL=2`. Using the legacy tree keeps
  // `CWorldParticles` at 0xDC in every build configuration.
  using BeamTextureBucketMapRuntime =
    msvc8::map<BeamTextureBucketKeyRuntime, msvc8::vector<SWorldBeam>, BeamTextureBucketKeyLess>;

  /**
   * What it does:
   * One packed beam-vertex lane emitted by beam interpolation helper paths.
   */
  /**
   * Address: 0x0049C0E0 (FUN_0049C0E0 -- the compiler-generated copy of this
   * 0x38-byte vertex record, emitted out of line for
   * `msvc8::vector<BeamRenderVertexRuntime>`'s copy steps. Formerly transcribed
   * as `CopyBeamRenderVertexLanePacked` in BeamRenderHelpers.cpp, removed
   * 2026-09-10.)
   * Address: 0x0049FEF0 (FUN_0049FEF0 -- the compiler-generated copy constructor (placement copy into a raw slot) of `BeamRenderVertexRuntime` as emitted for its `msvc8::vector` instantiation; zero callers, unreachable; formerly `CopySingleFifteenFloatLaneAndReturnDestination` in moho/particles/CWorldParticles.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x004A0040 (FUN_004A0040 -- the compiler-generated copy constructor (placement copy into a raw slot) of `BeamRenderVertexRuntime` as emitted for its `msvc8::vector` instantiation; zero callers, unreachable; formerly `CopySingleFifteenFloatLaneIfDestinationPresent` in moho/particles/CWorldParticles.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x004A06B0 (FUN_004A06B0 -- the compiler-generated copy constructor (placement copy into a raw slot) of `BeamRenderVertexRuntime` as emitted for its `msvc8::vector` instantiation; zero callers, unreachable; formerly `CopySingleFifteenFloatLaneIfDestinationPresentDuplicateA` in moho/particles/CWorldParticles.cpp (RULE ONE), removed 2026-09-10.)
   */
  struct BeamRenderVertexRuntime
  {
    Wm3::Vector3<float> worldPosition;   // +0x00
    Wm3::Vector3<float> axis;            // +0x0C
    float width;                         // +0x18
    Vector4f color;                      // +0x1C
    float sideSign;                      // +0x2C
    float repeatCoord;                   // +0x30
    float uShift;                        // +0x34
    float vShift;                        // +0x38
  };

  static_assert(
    offsetof(BeamRenderVertexRuntime, worldPosition) == 0x00,
    "BeamRenderVertexRuntime::worldPosition offset must be 0x00"
  );
  static_assert(offsetof(BeamRenderVertexRuntime, axis) == 0x0C, "BeamRenderVertexRuntime::axis offset must be 0x0C");
  static_assert(offsetof(BeamRenderVertexRuntime, width) == 0x18, "BeamRenderVertexRuntime::width offset must be 0x18");
  static_assert(offsetof(BeamRenderVertexRuntime, color) == 0x1C, "BeamRenderVertexRuntime::color offset must be 0x1C");
  static_assert(
    offsetof(BeamRenderVertexRuntime, sideSign) == 0x2C, "BeamRenderVertexRuntime::sideSign offset must be 0x2C"
  );
  static_assert(
    offsetof(BeamRenderVertexRuntime, repeatCoord) == 0x30,
    "BeamRenderVertexRuntime::repeatCoord offset must be 0x30"
  );
  static_assert(offsetof(BeamRenderVertexRuntime, uShift) == 0x34, "BeamRenderVertexRuntime::uShift offset must be 0x34");
  static_assert(offsetof(BeamRenderVertexRuntime, vShift) == 0x38, "BeamRenderVertexRuntime::vShift offset must be 0x38");
  static_assert(sizeof(BeamRenderVertexRuntime) == 0x3C, "BeamRenderVertexRuntime size must be 0x3C");

  using BeamRenderVertexArrayRuntime = msvc8::vector<BeamRenderVertexRuntime>;

  /**
   * What it does:
   * Map key for world-particle render buckets: the bucket's whole identity --
   * everything `ParticleRenderBucketRuntime` carries before its pending-work
   * lanes, in the same order -- with the sort scalar prepended so the map
   * orders by draw order first.
   */
  struct ParticleBucketKeyRuntime
  {
    float sortScalar = 0.0f;              // +0x00
    bool dragEnabled = false;             // +0x04  SWorldParticle::mDragEnabled
    std::uint8_t statePadding[0x03]{};    // +0x05
    TextureSheetHandle texture0;          // +0x08
    TextureSheetHandle texture1;          // +0x10
    msvc8::string tag;                    // +0x18
    std::int32_t blendMode = 0;           // +0x34
    std::int32_t zMode = 0;               // +0x38
  };

  static_assert(
    offsetof(ParticleBucketKeyRuntime, sortScalar) == 0x00, "ParticleBucketKeyRuntime::sortScalar offset must be 0x00"
  );
  static_assert(
    offsetof(ParticleBucketKeyRuntime, dragEnabled) == 0x04, "ParticleBucketKeyRuntime::dragEnabled offset must be 0x04"
  );
  static_assert(
    offsetof(ParticleBucketKeyRuntime, texture0) == 0x08, "ParticleBucketKeyRuntime::texture0 offset must be 0x08"
  );
  static_assert(
    offsetof(ParticleBucketKeyRuntime, texture1) == 0x10, "ParticleBucketKeyRuntime::texture1 offset must be 0x10"
  );
  static_assert(offsetof(ParticleBucketKeyRuntime, tag) == 0x18, "ParticleBucketKeyRuntime::tag offset must be 0x18");
  static_assert(
    offsetof(ParticleBucketKeyRuntime, blendMode) == 0x34, "ParticleBucketKeyRuntime::blendMode offset must be 0x34"
  );
  static_assert(offsetof(ParticleBucketKeyRuntime, zMode) == 0x38, "ParticleBucketKeyRuntime::zMode offset must be 0x38");
  static_assert(sizeof(ParticleBucketKeyRuntime) == 0x3C, "ParticleBucketKeyRuntime size must be 0x3C");

  /**
   * What it does:
   * Map key for world-trail render buckets: the same shape as
   * `ParticleBucketKeyRuntime` minus the two lanes a trail has no use for (the
   * drag flag and the z mode), and again the bucket's own identity with the
   * sort scalar prepended.
   */
  struct TrailBucketKeyRuntime
  {
    float sortScalar = 0.0f;              // +0x00
    TextureSheetHandle texture0;          // +0x04
    TextureSheetHandle texture1;          // +0x0C
    msvc8::string tag;                    // +0x14
    /**
     * Blueprint `BlendMode`, copied straight out of `SWorldTrail::mBlendMode`.
     * A `std::int32_t`, not a float: `IsTrailBucketKeyRhsLessThanLhs`
     * (0x0049253F) loads this lane with `mov`/`cmp`/`setl`, a signed integer
     * compare, where it loads `sortScalar` at +0x00 with `movss`/`ucomiss`.
     */
    std::int32_t blendMode = 0;           // +0x30
  };

  static_assert(offsetof(TrailBucketKeyRuntime, sortScalar) == 0x00, "TrailBucketKeyRuntime::sortScalar offset must be 0x00");
  static_assert(offsetof(TrailBucketKeyRuntime, texture0) == 0x04, "TrailBucketKeyRuntime::texture0 offset must be 0x04");
  static_assert(offsetof(TrailBucketKeyRuntime, texture1) == 0x0C, "TrailBucketKeyRuntime::texture1 offset must be 0x0C");
  static_assert(offsetof(TrailBucketKeyRuntime, tag) == 0x14, "TrailBucketKeyRuntime::tag offset must be 0x14");
  static_assert(offsetof(TrailBucketKeyRuntime, blendMode) == 0x30, "TrailBucketKeyRuntime::blendMode offset must be 0x30");
  static_assert(sizeof(TrailBucketKeyRuntime) == 0x34, "TrailBucketKeyRuntime size must be 0x34");

  // The two `ParticleTechniqueSelection*Runtime` structs that used to sit here
  // were not types. They duplicated, field for field, the leading 0x30 / 0x34
  // bytes of `TrailRenderBucketRuntime` and `ParticleRenderBucketRuntime`, so
  // that the two technique selectors could be spelled as free functions taking
  // a copy. The binary passes the bucket itself -- `RenderTrailBucket` does
  // `mov ecx, edi; call 0x494740` at 0x0049488F with `edi` the same pointer it
  // reads `activeWorkItems` from at `[edi+0x48]`. Both selectors are now
  // `SelectTechnique()` members on the buckets (ParticleRenderBuckets.h), which
  // also retires a per-bucket, per-frame copy of an `msvc8::string` and two
  // texture handle retains.

  /**
   * Address: 0x00491440 (FUN_00491440, func_NewVertexSheet)
   *
   * What it does:
   * Allocates one beam-particle vertex sheet from device resources and swaps it
   * into the caller slot, deleting the old sheet when replaced.
   */
  void RecreateBeamParticleVertexSheet(CD3DVertexSheet*& vertexSheet, CD3DVertexFormat* vertexFormat);

  /**
   * Address: 0x00491540 (FUN_00491540, sub_491540)
   *
   * What it does:
   * Resolves beam textures into one bucket key and appends the beam payload
   * into the matching texture/blend bucket.
   */
  void AddBeamToTextureBuckets(BeamTextureBucketMapRuntime& buckets, const SWorldBeam& beam);

  /**
   * Address: 0x00491760 (FUN_00491760, sub_491760)
   *
   * What it does:
   * Interpolates one beam segment and emits four packed render vertices that
   * form one billboarded beam quad.
   */
  void EmitInterpolatedBeamQuadVertices(const SWorldBeam& beam, float frameAlpha, BeamRenderVertexArrayRuntime& outVertices);

  /**
   * Address: 0x00491E40 (FUN_00491E40, func_DrawBeamParticle)
   *
   * What it does:
   * Renders the active beam buckets into the shared vertex/index sheets using
   * beam-technique selection and 1000-vertex batching.
   */
  [[nodiscard]] bool DrawBeamParticle(BeamBucketContainerRuntime& beams, float frameAlpha, bool disable);

  /**
   * Address: 0x00492290 (FUN_00492290, sub_492290)
   *
   * What it does:
   * Strict-weak ordering comparator for world-particle bucket keys.
   */
  [[nodiscard]] bool IsParticleBucketKeyRhsLessThanLhs(
    const ParticleBucketKeyRuntime& lhs, const ParticleBucketKeyRuntime& rhs
  ) noexcept;

  /**
   * Address: 0x00492310 (FUN_00492310, sub_492310)
   *
   * What it does:
   * Equality comparator for world-particle bucket keys.
   */
  [[nodiscard]] bool AreParticleBucketKeysEquivalent(
    const ParticleBucketKeyRuntime& lhs, const ParticleBucketKeyRuntime& rhs
  ) noexcept;

  /**
   * Address: 0x00494B90 (FUN_00494B90, sub_494B90)
   *
   * What it does:
   * Copies one world-particle bucket key into destination storage while
   * preserving weak-handle control semantics for both texture lanes.
   */
  ParticleBucketKeyRuntime* CopyParticleBucketKey(
    ParticleBucketKeyRuntime* destination,
    const ParticleBucketKeyRuntime* source
  ) noexcept;

  /**
   * Address: 0x00492390 (FUN_00492390, sub_492390)
   *
   * What it does:
   * Builds one trail bucket key from one `STrail` runtime payload.
   */
  TrailBucketKeyRuntime* InitializeTrailBucketKeyFromTrail(
    TrailBucketKeyRuntime* key, const SWorldTrail& trail
  );

  /**
   * Address: 0x00492520 (FUN_00492520, sub_492520)
   *
   * What it does:
   * Strict-weak ordering comparator for trail bucket keys.
   */
  [[nodiscard]] bool IsTrailBucketKeyRhsLessThanLhs(
    const TrailBucketKeyRuntime& lhs, const TrailBucketKeyRuntime& rhs
  ) noexcept;

  /**
   * Address: 0x00492590 (FUN_00492590, sub_492590)
   *
   * What it does:
   * Equality comparator for trail bucket keys.
   */
  [[nodiscard]] bool AreTrailBucketKeysEquivalent(
    const TrailBucketKeyRuntime& lhs, const TrailBucketKeyRuntime& rhs
  ) noexcept;

  /**
   * Address: 0x00494D90 (FUN_00494D90, sub_494D90)
   *
   * What it does:
   * Copies one world-trail bucket key into destination storage while
   * preserving weak-handle control semantics for both texture lanes.
   */
  TrailBucketKeyRuntime* CopyTrailBucketKey(
    TrailBucketKeyRuntime* destination,
    const TrailBucketKeyRuntime* source
  ) noexcept;

  /**
   * Address: 0x00492EF0 (FUN_00492EF0, sub_492EF0)
   *
   * What it does:
   * Releases one world-particle bucket key resource lane.
   */
  void ResetParticleBucketKeyResources(ParticleBucketKeyRuntime& key);

  /**
   * Address: 0x00492FC0 (FUN_00492FC0, sub_492FC0)
   *
   * What it does:
   * Releases one world-trail bucket key resource lane.
   */
  void ResetTrailBucketKeyResources(TrailBucketKeyRuntime& key);
} // namespace moho
