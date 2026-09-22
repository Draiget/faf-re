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
   * Runtime view over one stack-allocated beam/particle draw context
   * used by the quad-emit helpers around 0x0043C3D0..0x0043C610.
   *
   * The binary treats this as a 5-dword block passed via `esi`:
   *   +0x00: owning `CD3DVertexSheet*` whose first vertex stream
   *          is locked/unlocked for writing.
   *   +0x04: scratch integer lane (not touched by the recovered
   *          members; semantics not yet pinned down).
   *   +0x08: maximum vertex count requested at `Lock` time.
   *   +0x0C: running quad count, bumped once per emitted quad.
   *   +0x10: active write cursor into the locked vertex buffer;
   *          null before `BeginMap` / after `EndMap`.
   *
   * Kept as a typed view rather than a first-class class because the
   * owning allocator and the surrounding render pass have not yet
   * been recovered.
   */
  struct BeamDrawContextRuntime
  {
    CD3DVertexSheet* sheet = nullptr; // +0x00
    std::int32_t field_0x04 = 0;       // +0x04 - unproven
    std::int32_t maxVertexCount = 0;   // +0x08
    std::int32_t quadCount = 0;        // +0x0C
    float* writeCursor = nullptr;      // +0x10
  };

  static_assert(offsetof(BeamDrawContextRuntime, sheet) == 0x00, "BeamDrawContextRuntime::sheet offset must be 0x00");
  static_assert(offsetof(BeamDrawContextRuntime, field_0x04) == 0x04, "BeamDrawContextRuntime::field_0x04 offset must be 0x04");
  static_assert(offsetof(BeamDrawContextRuntime, maxVertexCount) == 0x08, "BeamDrawContextRuntime::maxVertexCount offset must be 0x08");
  static_assert(offsetof(BeamDrawContextRuntime, quadCount) == 0x0C, "BeamDrawContextRuntime::quadCount offset must be 0x0C");
  static_assert(offsetof(BeamDrawContextRuntime, writeCursor) == 0x10, "BeamDrawContextRuntime::writeCursor offset must be 0x10");
  static_assert(sizeof(BeamDrawContextRuntime) == 0x14, "BeamDrawContextRuntime size must be 0x14");

  /**
   * Address: 0x0043C3D0 (FUN_0043C3D0, sub_43C3D0)
   *
   * What it does:
   * Locks the first vertex stream of `context.sheet` for writing the
   * full requested vertex count, stores the returned map pointer into
   * `context.writeCursor`, and resets `context.quadCount` to zero.
   */
  void BeamDrawContextBeginMap(BeamDrawContextRuntime& context);

  /**
   * Address: 0x0043C400 (FUN_0043C400, sub_43C400)
   *
   * What it does:
   * If the context currently holds a live map pointer, unlocks the
   * first vertex stream of `context.sheet` and clears the write
   * cursor.
   */
  void BeamDrawContextEndMap(BeamDrawContextRuntime& context);

  /**
   * Address: 0x0043C390 (FUN_0043C390, sub_43C390)
   *
   * What it does:
   * Ends any active map session, then releases the owning vertex
   * sheet through its vtable-0 slot (deleting dtor thunk) and nulls
   * the sheet pointer.
   */
  void BeamDrawContextTeardown(BeamDrawContextRuntime& context);

  /**
   * Address: 0x0043C430 (FUN_0043C430, sub_43C430)
   *
   * What it does:
   * Reads four corner offsets from the caller's 6-float "unit quad"
   * box (`boxCorners[0..5]`), adds a per-call XYZ translation to each
   * corner, writes four consecutive 3-float vertices into the
   * active write cursor, advances the cursor by 48 bytes, and bumps
   * `quadCount`.
   */
  float* BeamDrawContextWriteTranslatedQuad(
    BeamDrawContextRuntime& context,
    const float* boxCorners,
    float dx,
    float dy,
    float dz);

  /**
   * Address: 0x0043C510 (FUN_0043C510, sub_43C510)
   *
   * What it does:
   * Copies four packed 3-float vertices (12 floats) from `packedQuad`
   * into the active write cursor, advances the cursor by 48 bytes,
   * and bumps `quadCount`.
   */
  const float* BeamDrawContextWritePackedQuad(
    BeamDrawContextRuntime& context,
    const float* packedQuad);

  /**
   * Address: 0x0043C580 (FUN_0043C580, sub_43C580)
   *
   * What it does:
   * Flushes any pending write session on the context (unlocking the
   * vertex stream when still mapped), then submits one indexed
   * triangle-list draw covering `context.quadCount` quads. The call
   * builds the vertex-sheet view from the context's sheet and quad
   * count (4 vertices per quad), the index-sheet view from the
   * shared `sIndexSheet` singleton (6 indices per quad), and issues
   * the call through `CD3DDevice::DrawTriangleList` with primitive
   * type 4 (D3DPT_TRIANGLELIST).
   */
  bool BeamDrawContextFlushQuadDraw(BeamDrawContextRuntime& context);

  /**
   * Address: 0x0043C610 (FUN_0043C610, sub_43C610)
   *
   * What it does:
   * Same flush/draw shape as `BeamDrawContextFlushQuadDraw` but uses
   * a caller-supplied quad count instead of the context's own
   * running count. The context's `quadCount` field is not read for
   * view bounds on this path.
   */
  bool BeamDrawContextFlushQuadDrawWithCount(BeamDrawContextRuntime& context, int quadCount);

  /**
   * Address: 0x0043C760 (FUN_0043C760, sub_43C760)
   *
   * What it does:
   * Fetches vertex format 3 from the device resources, ensures the
   * shared `sVertexStream` singleton is initialized, then calls
   * `ID3DDeviceResources::Func6` to build a new vertex sheet from
   * the `[null, sVertexStream]` stream pair and the format, stores
   * the returned sheet into `context.sheet`, and releases the prior
   * sheet (if different and non-null) through its deleting dtor
   * thunk.
   */
  CD3DVertexSheet* BeamDrawContextCreateVertexSheet(BeamDrawContextRuntime& context);

  /**
   * Address: 0x0043C360 (FUN_0043C360, sub_43C360)
   *
   * What it does:
   * Lazy first-use initializer for a beam draw context: when the
   * context's sheet slot is empty, records the caller-supplied quad
   * count into `field_0x04`, derives `maxVertexCount` as `4 *
   * quadCount`, clears the write cursor, builds one shared vertex
   * sheet through `BeamDrawContextCreateVertexSheet`, and ensures
   * the shared index sheet is live through `func_InitSharedIndexSheet`.
   */
  void BeamDrawContextInitialize(BeamDrawContextRuntime& context, int quadCount);

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
   * Runtime key lane used for world-particle render buckets.
   */
  struct ParticleBucketKeyRuntime
  {
    float sortScalar = 0.0f;              // +0x00
    std::uint8_t stateByte = 0U;          // +0x04
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
    offsetof(ParticleBucketKeyRuntime, stateByte) == 0x04, "ParticleBucketKeyRuntime::stateByte offset must be 0x04"
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
   * Runtime key lane used for world-trail render buckets.
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

  /**
   * What it does:
   * Runtime view used by particle-technique selection helper paths.
   */
  struct ParticleTechniqueSelectionRuntime
  {
    CParticleTexture::TextureResourceHandle texture0; // +0x00
    CParticleTexture::TextureResourceHandle texture1; // +0x08
    msvc8::string techniqueBaseName;                     // +0x10
    std::int32_t blendMode = 0;                          // +0x2C
  };

  static_assert(
    offsetof(ParticleTechniqueSelectionRuntime, texture0) == 0x00,
    "ParticleTechniqueSelectionRuntime::texture0 offset must be 0x00"
  );
  static_assert(
    offsetof(ParticleTechniqueSelectionRuntime, texture1) == 0x08,
    "ParticleTechniqueSelectionRuntime::texture1 offset must be 0x08"
  );
  static_assert(
    offsetof(ParticleTechniqueSelectionRuntime, techniqueBaseName) == 0x10,
    "ParticleTechniqueSelectionRuntime::techniqueBaseName offset must be 0x10"
  );
  static_assert(
    offsetof(ParticleTechniqueSelectionRuntime, blendMode) == 0x2C,
    "ParticleTechniqueSelectionRuntime::blendMode offset must be 0x2C"
  );
  static_assert(sizeof(ParticleTechniqueSelectionRuntime) == 0x30, "ParticleTechniqueSelectionRuntime size must be 0x30");

  /**
   * What it does:
   * Runtime view used by drag-aware particle-technique selection helper paths.
   */
  struct ParticleTechniqueSelectionWithDragRuntime
  {
    bool dragEnabled = false;                            // +0x00
    std::uint8_t padding01_03[0x03]{};                  // +0x01
    CParticleTexture::TextureResourceHandle texture0; // +0x04
    CParticleTexture::TextureResourceHandle texture1; // +0x0C
    msvc8::string techniqueBaseName;                     // +0x14
    std::int32_t blendMode = 0;                          // +0x30
  };

  static_assert(
    offsetof(ParticleTechniqueSelectionWithDragRuntime, dragEnabled) == 0x00,
    "ParticleTechniqueSelectionWithDragRuntime::dragEnabled offset must be 0x00"
  );
  static_assert(
    offsetof(ParticleTechniqueSelectionWithDragRuntime, texture0) == 0x04,
    "ParticleTechniqueSelectionWithDragRuntime::texture0 offset must be 0x04"
  );
  static_assert(
    offsetof(ParticleTechniqueSelectionWithDragRuntime, texture1) == 0x0C,
    "ParticleTechniqueSelectionWithDragRuntime::texture1 offset must be 0x0C"
  );
  static_assert(
    offsetof(ParticleTechniqueSelectionWithDragRuntime, techniqueBaseName) == 0x14,
    "ParticleTechniqueSelectionWithDragRuntime::techniqueBaseName offset must be 0x14"
  );
  static_assert(
    offsetof(ParticleTechniqueSelectionWithDragRuntime, blendMode) == 0x30,
    "ParticleTechniqueSelectionWithDragRuntime::blendMode offset must be 0x30"
  );
  static_assert(
    sizeof(ParticleTechniqueSelectionWithDragRuntime) == 0x34,
    "ParticleTechniqueSelectionWithDragRuntime size must be 0x34"
  );

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
   * Address: 0x00494740 (FUN_00494740, func_ParticleSelectTechnique)
   *
   * What it does:
   * Binds particle textures and selects particle technique suffix by blend mode.
   */
  void SelectParticleTechnique(const ParticleTechniqueSelectionRuntime& selection);

  /**
   * Address: 0x00493AE0 (FUN_00493AE0, func_ParticleSelectTechnique2)
   *
   * What it does:
   * Binds drag-enabled flag and particle textures, then selects particle
   * technique suffix (including refraction lane).
   */
  void SelectParticleTechniqueWithDrag(const ParticleTechniqueSelectionWithDragRuntime& selection);

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
