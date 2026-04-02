#pragma once

#include <cstddef>
#include <cstdint>
#include <map>

#include "boost/shared_ptr.h"
#include "legacy/containers/Vector.h"
#include "legacy/containers/String.h"
#include "moho/math/Vector4f.h"
#include "moho/particles/SWorldBeam.h"
#include "moho/particles/SWorldParticle.h"
#include "moho/resource/CParticleTexture.h"
#include "wm3/Vector3.h"

namespace moho
{
  struct BeamBucketContainerRuntime;
  class ID3DTextureSheet;
  class CD3DVertexFormat;
  class CD3DVertexSheet;

  using TextureSheetHandle = boost::shared_ptr<ID3DTextureSheet>;

  /**
   * What it does:
   * Models one red-black tree node runtime lane used by beam texture buckets.
   */
  struct BeamBucketTreeNodeRuntime
  {
    BeamBucketTreeNodeRuntime* left;      // +0x00
    BeamBucketTreeNodeRuntime* parent;    // +0x04
    BeamBucketTreeNodeRuntime* right;     // +0x08
    std::uint8_t payload[0x28];           // +0x0C (key/value payload lane)
    std::uint8_t isBlack;                 // +0x34
    std::uint8_t isNilSentinel;           // +0x35
    std::uint8_t padding[0x02];           // +0x36
  };

  static_assert(offsetof(BeamBucketTreeNodeRuntime, left) == 0x00, "BeamBucketTreeNodeRuntime::left offset must be 0x00");
  static_assert(
    offsetof(BeamBucketTreeNodeRuntime, parent) == 0x04,
    "BeamBucketTreeNodeRuntime::parent offset must be 0x04"
  );
  static_assert(
    offsetof(BeamBucketTreeNodeRuntime, right) == 0x08,
    "BeamBucketTreeNodeRuntime::right offset must be 0x08"
  );
  static_assert(
    offsetof(BeamBucketTreeNodeRuntime, isBlack) == 0x34,
    "BeamBucketTreeNodeRuntime::isBlack offset must be 0x34"
  );
  static_assert(
    offsetof(BeamBucketTreeNodeRuntime, isNilSentinel) == 0x35,
    "BeamBucketTreeNodeRuntime::isNilSentinel offset must be 0x35"
  );
  static_assert(sizeof(BeamBucketTreeNodeRuntime) == 0x38, "BeamBucketTreeNodeRuntime size must be 0x38");

  /**
   * What it does:
   * Models the map-storage header lane used by beam bucket trees.
   */
  struct BeamBucketMapStorageRuntime
  {
    std::uint32_t allocatorProxy;             // +0x00
    std::uint32_t comparatorOrReserved;       // +0x04
    BeamBucketTreeNodeRuntime* head;          // +0x08
    std::uint32_t size;                       // +0x0C
  };

  static_assert(
    offsetof(BeamBucketMapStorageRuntime, allocatorProxy) == 0x00,
    "BeamBucketMapStorageRuntime::allocatorProxy offset must be 0x00"
  );
  static_assert(
    offsetof(BeamBucketMapStorageRuntime, comparatorOrReserved) == 0x04,
    "BeamBucketMapStorageRuntime::comparatorOrReserved offset must be 0x04"
  );
  static_assert(offsetof(BeamBucketMapStorageRuntime, head) == 0x08, "BeamBucketMapStorageRuntime::head offset must be 0x08");
  static_assert(offsetof(BeamBucketMapStorageRuntime, size) == 0x0C, "BeamBucketMapStorageRuntime::size offset must be 0x0C");
  static_assert(sizeof(BeamBucketMapStorageRuntime) == 0x10, "BeamBucketMapStorageRuntime size must be 0x10");

  /**
   * What it does:
   * Runtime key lane used by beam texture/render buckets.
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

  using BeamTextureBucketMapRuntime =
    std::map<BeamTextureBucketKeyRuntime, msvc8::vector<SWorldBeam>, BeamTextureBucketKeyLess>;

  /**
   * What it does:
   * Temporary entry lane used when constructing one missing beam bucket.
   */
  struct BeamTextureBucketEntryRuntime
  {
    BeamTextureBucketKeyRuntime key;      // +0x00
    std::uint32_t allocatorProxy = 0U;    // +0x14
    msvc8::vector<SWorldBeam> beams;      // +0x18
  };

  static_assert(
    offsetof(BeamTextureBucketEntryRuntime, key) == 0x00, "BeamTextureBucketEntryRuntime::key offset must be 0x00"
  );
  static_assert(
    offsetof(BeamTextureBucketEntryRuntime, allocatorProxy) == 0x14,
    "BeamTextureBucketEntryRuntime::allocatorProxy offset must be 0x14"
  );
  static_assert(
    offsetof(BeamTextureBucketEntryRuntime, beams) == 0x18, "BeamTextureBucketEntryRuntime::beams offset must be 0x18"
  );
  static_assert(sizeof(BeamTextureBucketEntryRuntime) == 0x28, "BeamTextureBucketEntryRuntime size must be 0x28");

  /**
   * What it does:
   * One packed beam-vertex lane emitted by beam interpolation helper paths.
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
    float uvScalar = 0.0f;                // +0x30
  };

  static_assert(offsetof(TrailBucketKeyRuntime, sortScalar) == 0x00, "TrailBucketKeyRuntime::sortScalar offset must be 0x00");
  static_assert(offsetof(TrailBucketKeyRuntime, texture0) == 0x04, "TrailBucketKeyRuntime::texture0 offset must be 0x04");
  static_assert(offsetof(TrailBucketKeyRuntime, texture1) == 0x0C, "TrailBucketKeyRuntime::texture1 offset must be 0x0C");
  static_assert(offsetof(TrailBucketKeyRuntime, tag) == 0x14, "TrailBucketKeyRuntime::tag offset must be 0x14");
  static_assert(offsetof(TrailBucketKeyRuntime, uvScalar) == 0x30, "TrailBucketKeyRuntime::uvScalar offset must be 0x30");
  static_assert(sizeof(TrailBucketKeyRuntime) == 0x34, "TrailBucketKeyRuntime size must be 0x34");

  /**
   * What it does:
   * Typed runtime view for one `STrail` payload lane used by key construction.
   */
  struct TrailRuntimeView
  {
    std::uint8_t unknownPrefix[0x48]{}; // +0x00
    float sortScalar = 0.0f;            // +0x48
    std::uint8_t unknown4C[0x04]{};     // +0x4C
    CParticleTexture* texture0 = nullptr; // +0x50
    CParticleTexture* texture1 = nullptr; // +0x54
    const char* tag = nullptr;            // +0x58
    float uvScalar = 0.0f;                // +0x5C
  };

  static_assert(offsetof(TrailRuntimeView, sortScalar) == 0x48, "TrailRuntimeView::sortScalar offset must be 0x48");
  static_assert(offsetof(TrailRuntimeView, texture0) == 0x50, "TrailRuntimeView::texture0 offset must be 0x50");
  static_assert(offsetof(TrailRuntimeView, texture1) == 0x54, "TrailRuntimeView::texture1 offset must be 0x54");
  static_assert(offsetof(TrailRuntimeView, tag) == 0x58, "TrailRuntimeView::tag offset must be 0x58");
  static_assert(offsetof(TrailRuntimeView, uvScalar) == 0x5C, "TrailRuntimeView::uvScalar offset must be 0x5C");
  static_assert(sizeof(TrailRuntimeView) == 0x60, "TrailRuntimeView size must be 0x60");

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
   * Address: 0x0049EB80 (FUN_0049EB80, sub_49EB80)
   *
   * What it does:
   * Allocates one array lane of `BeamBucketTreeNodeRuntime` with overflow guard.
   */
  BeamBucketTreeNodeRuntime* AllocateBeamBucketTreeNodes(std::uint32_t count);

  /**
   * Address: 0x0049C4D0 (FUN_0049C4D0, sub_49C4D0)
   *
   * What it does:
   * Allocates and clears one beam bucket tree node, initializing RB-tree flags
   * for non-sentinel usage.
   */
  BeamBucketTreeNodeRuntime* AllocateBeamBucketTreeNode();

  /**
   * Address: 0x004914B0 (FUN_004914B0, sub_4914B0)
   *
   * What it does:
   * Initializes one beam bucket map storage with a self-linked sentinel head.
   */
  BeamBucketMapStorageRuntime* InitializeBeamBucketMapStorage(BeamBucketMapStorageRuntime* storage);

  /**
   * Address: 0x004921D0 (FUN_004921D0, sub_4921D0)
   *
   * What it does:
   * Initializes the two texture handle lanes used by one beam bucket key.
   */
  BeamTextureBucketKeyRuntime* InitializeBeamTextureBucketKeyHandles(BeamTextureBucketKeyRuntime* key);

  /**
   * Address: 0x00492200 (FUN_00492200, sub_492200)
   *
   * What it does:
   * Releases one temporary beam bucket entry (vector storage + two retained
   * texture handles).
   */
  void DestroyBeamTextureBucketEntry(BeamTextureBucketEntryRuntime* entry);

  /**
   * Address: 0x004921A0 (FUN_004921A0, sub_4921A0)
   *
   * What it does:
   * Destroys all nodes in one beam texture bucket map and resets storage.
   */
  void DestroyBeamTextureBucketMap(BeamTextureBucketMapRuntime& buckets);

  /**
   * Address: 0x00491540 (FUN_00491540, sub_491540)
   *
   * What it does:
   * Resolves beam textures into one bucket key and appends the beam payload
   * into the matching texture/blend bucket.
   */
  void AddBeamToTextureBuckets(BeamTextureBucketMapRuntime& buckets, const SWorldBeam& beam);

  /**
   * Address: 0x00495620 (FUN_00495620, std::vector_SWorldParticle::push_back)
   *
   * What it does:
   * Appends one world-particle payload into a world-particle vector lane.
   */
  void AppendWorldParticleToVector(msvc8::vector<SWorldParticle>& particles, const SWorldParticle& particle);

  /**
   * Address: 0x004957C0 (FUN_004957C0, std::vector_STrail::push_back)
   *
   * What it does:
   * Appends one world-trail payload into a trail vector lane.
   */
  void AppendTrailToVector(msvc8::vector<TrailRuntimeView>& trails, const TrailRuntimeView& trail);

  /**
   * Address: 0x00495990 (FUN_00495990, std::vector_Beam::push_back)
   *
   * What it does:
   * Appends one world-beam payload into a beam vector lane.
   */
  void AppendBeamToVector(msvc8::vector<SWorldBeam>& beams, const SWorldBeam& beam);

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
    TrailBucketKeyRuntime* key, const TrailRuntimeView& trail
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
