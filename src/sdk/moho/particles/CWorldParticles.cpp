#include "moho/particles/CWorldParticles.h"

#include <cstring>
#include <cstdlib>
#include <limits>
#include <new>
#include <stdexcept>
#include <string>
#include <utility>

#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/BoostWrappers.h"
#include "gpg/gal/backends/d3d9/EffectVariableD3D9.hpp"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/console/CConCommand.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/render/ID3DIndexSheet.h"
#include "moho/render/SParticleBuffer.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DIndexSheet.h"
#include "moho/render/d3d/ShaderVar.h"
#include "moho/particles/ParticleRenderBuckets.h"
#include "moho/render/d3d/RD3DTextureResource.h"

namespace moho
{
  extern ShaderVar& shaderVarParticleViewMatrix;
  extern ShaderVar& shaderVarParticleProjection;
  extern ShaderVar& shaderVarParticleWorldToProjection;
  extern ShaderVar& shaderVarParticleInverseViewMatrix;
  extern ShaderVar& shaderVarParticleParticleSystemPosition;
  extern ShaderVar& shaderVarParticleTime;
  extern ShaderVar& shaderVarParticleParticleSystemShape;
  extern ShaderVar& shaderVarParticleParticleSpread;
  extern ShaderVar& shaderVarParticleParticleSpeed;
  extern ShaderVar& shaderVarParticleParticleSystemHeight;
  extern ShaderVar& shaderVarParticleParticleSize;
  extern ShaderVar& shaderVarParticleDragEnabled;
  extern ShaderVar& shaderVarParticleDragCoeff;
  extern ShaderVar& shaderVarParticleInvDragCoeff;
  extern ShaderVar& shaderVarParticleInvDragCoeffSq;
  extern ShaderVar& shaderVarParticleBackgroundTexture;
  extern ShaderVar& shaderVarParticleParticleTexture0;
  extern ShaderVar& shaderVarParticleParticleTexture1;
  extern float efx_ParticleWaterSurface;
} // namespace moho

namespace
{


  constexpr int kPooledParticleBufferCount = 400;
  constexpr int kParticleBufferCapacity = 200;
  constexpr int kPooledTrailSegmentBufferCount = 100;
  constexpr std::uint32_t kTrailSegmentCapacity = 100U;

  constexpr int kTrailVertexFormatToken = 12;
  constexpr std::uint32_t kTrailVertexSheetUsageToken = 1U;
  constexpr int kTrailVertexSheetFrequencyToken = 400;

  constexpr int kSharedTrailIndexSheetSize = 0x18000;
  constexpr std::uint32_t kSharedTrailQuadCount = 0x4000U;
  constexpr std::uint32_t kIndicesPerTrailQuad = 6U;
  constexpr std::size_t kLegacyVectorMaxCount = 0x3FFFFFFFU;
  constexpr const char* kParticleRendererSourcePath = "c:\\work\\rts\\main\\code\\src\\core\\ParticleRenderer.cpp";
  constexpr const char* kUnreachableAssertText = "Reached the supposably unreachable.";
  constexpr int kParticleSelectTechniqueAssertLine = 1359;
  constexpr int kParticleSelectTechniqueWithDragAssertLine = 1026;

  moho::ID3DIndexSheet* sSharedTrailQuadIndexSheet = nullptr;

  template <std::uintptr_t SlotAddress>
  struct ParticleShaderVarSlot;

#define DEFINE_PARTICLE_SHADER_VAR_SLOT(SLOT_ADDRESS) \
  template <> \
  struct ParticleShaderVarSlot<SLOT_ADDRESS> \
  { \
    alignas(moho::ShaderVar) static std::byte storage[sizeof(moho::ShaderVar)]; \
    static bool constructed; \
  }; \
  alignas(moho::ShaderVar) std::byte ParticleShaderVarSlot<SLOT_ADDRESS>::storage[sizeof(moho::ShaderVar)]{}; \
  bool ParticleShaderVarSlot<SLOT_ADDRESS>::constructed = false

  DEFINE_PARTICLE_SHADER_VAR_SLOT(0x010A8440u);
  DEFINE_PARTICLE_SHADER_VAR_SLOT(0x010A82D8u);
  DEFINE_PARTICLE_SHADER_VAR_SLOT(0x010A83F8u);
  DEFINE_PARTICLE_SHADER_VAR_SLOT(0x010A8638u);
  DEFINE_PARTICLE_SHADER_VAR_SLOT(0x010A8368u);
  DEFINE_PARTICLE_SHADER_VAR_SLOT(0x010A8560u);
  DEFINE_PARTICLE_SHADER_VAR_SLOT(0x010A84D0u);
  DEFINE_PARTICLE_SHADER_VAR_SLOT(0x010A8290u);
  DEFINE_PARTICLE_SHADER_VAR_SLOT(0x010A85A8u);
  DEFINE_PARTICLE_SHADER_VAR_SLOT(0x010A8518u);
  DEFINE_PARTICLE_SHADER_VAR_SLOT(0x010A8488u);
  DEFINE_PARTICLE_SHADER_VAR_SLOT(0x010A83B0u);
  DEFINE_PARTICLE_SHADER_VAR_SLOT(0x010A86C8u);
  DEFINE_PARTICLE_SHADER_VAR_SLOT(0x010A8320u);
  DEFINE_PARTICLE_SHADER_VAR_SLOT(0x010A8718u);
  DEFINE_PARTICLE_SHADER_VAR_SLOT(0x010A85F0u);
  DEFINE_PARTICLE_SHADER_VAR_SLOT(0x010A8680u);
  DEFINE_PARTICLE_SHADER_VAR_SLOT(0x010A8760u);

#undef DEFINE_PARTICLE_SHADER_VAR_SLOT

  template <std::uintptr_t SlotAddress>
  [[nodiscard]] moho::ShaderVar& AccessParticleShaderVarSlot() noexcept
  {
    auto* const slot = reinterpret_cast<moho::ShaderVar*>(ParticleShaderVarSlot<SlotAddress>::storage);
    if (!ParticleShaderVarSlot<SlotAddress>::constructed) {
      ::new (static_cast<void*>(slot)) moho::ShaderVar();
      ParticleShaderVarSlot<SlotAddress>::constructed = true;
    }
    return *slot;
  }

  template <std::uintptr_t SlotAddress>
  void DestroyParticleShaderVarSlot() noexcept
  {
    if (!ParticleShaderVarSlot<SlotAddress>::constructed) {
      return;
    }

    AccessParticleShaderVarSlot<SlotAddress>().~ShaderVar();
    ParticleShaderVarSlot<SlotAddress>::constructed = false;
  }

  template <std::uintptr_t SlotAddress>
  void RegisterParticleShaderVar(const char* const variableName)
  {
    moho::RegisterShaderVar(variableName, &AccessParticleShaderVarSlot<SlotAddress>(), "particle");
  }

  template <std::uintptr_t SlotAddress>
  void CleanupParticleShaderVarRegistration() noexcept
  {
    DestroyParticleShaderVarSlot<SlotAddress>();
  }

  template <std::uintptr_t SlotAddress>
  void RegisterParticleShaderVarWithAtexit(const char* const variableName)
  {
    RegisterParticleShaderVar<SlotAddress>(variableName);
    (void)std::atexit(&CleanupParticleShaderVarRegistration<SlotAddress>);
  }

  moho::TConVar<float> gTConVar_efx_ParticleWaterSurface(
    "efx_ParticleWaterSurface",
    "Particle water-surface control variable.",
    &moho::efx_ParticleWaterSurface
  );

  /**
   * Address: 0x00BF0060 (FUN_00BF0060, Moho::TConVar_efx_ParticleWaterSurface::~TConVar_efx_ParticleWaterSurface)
   *
   * What it does:
   * Tears down the static `efx_ParticleWaterSurface` console-variable
   * registration via the shared `TeardownConCommandRegistration` helper.
   * Registered via `atexit` from the convar startup path.
   */
  void CleanupTConVar_efx_ParticleWaterSurface() noexcept
  {
    moho::TeardownConCommandRegistration(gTConVar_efx_ParticleWaterSurface);
  }

  void CleanupSharedTrailQuadIndexSheetAtProcessExit() noexcept
  {
    if (sSharedTrailQuadIndexSheet != nullptr) {
      delete sSharedTrailQuadIndexSheet;
    }
  }

  /**
   * Address: 0x00BC5570 (FUN_00BC5570, register_TConVar_efx_ParticleWaterSurface)
   *
   * What it does:
   * Registers startup convar for `efx_ParticleWaterSurface`.
   */
  void register_TConVar_efx_ParticleWaterSurface()
  {
    moho::RegisterConCommand(gTConVar_efx_ParticleWaterSurface);
    (void)std::atexit(&CleanupTConVar_efx_ParticleWaterSurface);
  }

  /**
   * Address: 0x00BC55B0 (FUN_00BC55B0, register_ShaderVarParticleWorldToProjection)
   */
  void register_ShaderVarParticleWorldToProjection()
  {
    RegisterParticleShaderVarWithAtexit<0x010A83F8u>("WorldToProjection");
  }

  /**
   * Address: 0x00BC55D0 (FUN_00BC55D0, register_ShaderVarParticleViewMatrix)
   */
  void register_ShaderVarParticleViewMatrix()
  {
    RegisterParticleShaderVarWithAtexit<0x010A8440u>("ViewMatrix");
  }

  /**
   * Address: 0x00BC55F0 (FUN_00BC55F0, register_ShaderVarParticleInverseViewMatrix)
   */
  void register_ShaderVarParticleInverseViewMatrix()
  {
    RegisterParticleShaderVarWithAtexit<0x010A8638u>("InverseViewMatrix");
  }

  /**
   * Address: 0x00BC5610 (FUN_00BC5610, register_ShaderVarParticleProjection)
   */
  void register_ShaderVarParticleProjection()
  {
    RegisterParticleShaderVarWithAtexit<0x010A82D8u>("Projection");
  }

  /**
   * Address: 0x00BC5630 (FUN_00BC5630, register_ShaderVarParticleParticleSystemPosition)
   */
  void register_ShaderVarParticleParticleSystemPosition()
  {
    RegisterParticleShaderVarWithAtexit<0x010A8368u>("ParticleSystemPosition");
  }

  /**
   * Address: 0x00BC5650 (FUN_00BC5650, register_ShaderVarParticleTime)
   */
  void register_ShaderVarParticleTime()
  {
    RegisterParticleShaderVarWithAtexit<0x010A8560u>("time");
  }

  /**
   * Address: 0x00BC5670 (FUN_00BC5670, register_ShaderVarParticleParticleSystemShape)
   */
  void register_ShaderVarParticleParticleSystemShape()
  {
    RegisterParticleShaderVarWithAtexit<0x010A84D0u>("ParticleSystemShape");
  }

  /**
   * Address: 0x00BC5690 (FUN_00BC5690, register_ShaderVarParticleParticleSpread)
   */
  void register_ShaderVarParticleParticleSpread()
  {
    RegisterParticleShaderVarWithAtexit<0x010A8290u>("ParticleSpread");
  }

  /**
   * Address: 0x00BC56B0 (FUN_00BC56B0, register_ShaderVarParticleParticleSpeed)
   */
  void register_ShaderVarParticleParticleSpeed()
  {
    RegisterParticleShaderVarWithAtexit<0x010A85A8u>("ParticleSpeed");
  }

  /**
   * Address: 0x00BC56D0 (FUN_00BC56D0, register_ShaderVarParticleParticleSystemHeight)
   */
  void register_ShaderVarParticleParticleSystemHeight()
  {
    RegisterParticleShaderVarWithAtexit<0x010A8518u>("ParticleSystemHeight");
  }

  /**
   * Address: 0x00BC56F0 (FUN_00BC56F0, register_ShaderVarParticleParticleSize)
   */
  void register_ShaderVarParticleParticleSize()
  {
    RegisterParticleShaderVarWithAtexit<0x010A8488u>("ParticleSize");
  }

  /**
   * Address: 0x00BC5710 (FUN_00BC5710, register_ShaderVarParticleDragEnabled)
   */
  void register_ShaderVarParticleDragEnabled()
  {
    RegisterParticleShaderVarWithAtexit<0x010A83B0u>("DragEnabled");
  }

  /**
   * Address: 0x00BC5730 (FUN_00BC5730, register_ShaderVarParticleDragCoeff)
   */
  void register_ShaderVarParticleDragCoeff()
  {
    RegisterParticleShaderVarWithAtexit<0x010A86C8u>("DragCoeff");
  }

  /**
   * Address: 0x00BC5750 (FUN_00BC5750, register_ShaderVarParticleInvDragCoeff)
   */
  void register_ShaderVarParticleInvDragCoeff()
  {
    RegisterParticleShaderVarWithAtexit<0x010A8320u>("invDragCoeff");
  }

  /**
   * Address: 0x00BC5770 (FUN_00BC5770, register_ShaderVarParticleInvDragCoeffSq)
   */
  void register_ShaderVarParticleInvDragCoeffSq()
  {
    RegisterParticleShaderVarWithAtexit<0x010A8718u>("invDragCoeffSq");
  }

  /**
   * Address: 0x00BC5790 (FUN_00BC5790, register_ShaderVarParticleBackgroundTexture)
   */
  void register_ShaderVarParticleBackgroundTexture()
  {
    RegisterParticleShaderVarWithAtexit<0x010A85F0u>("BackgroundTexture");
  }

  /**
   * Address: 0x00BC57B0 (FUN_00BC57B0, register_ShaderVarParticleParticleTexture0)
   */
  void register_ShaderVarParticleParticleTexture0()
  {
    RegisterParticleShaderVarWithAtexit<0x010A8680u>("ParticleTexture0");
  }

  /**
   * Address: 0x00BC57D0 (FUN_00BC57D0, register_ShaderVarParticleParticleTexture1)
   */
  void register_ShaderVarParticleParticleTexture1()
  {
    RegisterParticleShaderVarWithAtexit<0x010A8760u>("ParticleTexture1");
  }

  /**
   * Address: 0x00BC57F0 (FUN_00BC57F0, sub_BC57F0)
   *
   * What it does:
   * Registers process-exit cleanup for the shared trail index-sheet lane.
   */
  int register_SharedTrailQuadIndexSheetCleanupAtExit()
  {
    return std::atexit(&CleanupSharedTrailQuadIndexSheetAtProcessExit);
  }

  struct ParticleShaderVarBootstrap
  {
    ParticleShaderVarBootstrap()
    {
      register_TConVar_efx_ParticleWaterSurface();
      register_ShaderVarParticleWorldToProjection();
      register_ShaderVarParticleViewMatrix();
      register_ShaderVarParticleInverseViewMatrix();
      register_ShaderVarParticleProjection();
      register_ShaderVarParticleParticleSystemPosition();
      register_ShaderVarParticleTime();
      register_ShaderVarParticleParticleSystemShape();
      register_ShaderVarParticleParticleSpread();
      register_ShaderVarParticleParticleSpeed();
      register_ShaderVarParticleParticleSystemHeight();
      register_ShaderVarParticleParticleSize();
      register_ShaderVarParticleDragEnabled();
      register_ShaderVarParticleDragCoeff();
      register_ShaderVarParticleInvDragCoeff();
      register_ShaderVarParticleInvDragCoeffSq();
      register_ShaderVarParticleBackgroundTexture();
      register_ShaderVarParticleParticleTexture0();
      register_ShaderVarParticleParticleTexture1();
      (void)register_SharedTrailQuadIndexSheetCleanupAtExit();
    }
  };

  ParticleShaderVarBootstrap gParticleShaderVarBootstrap;

  // A `ResolveParticleTechniqueSuffix(blendMode, allowRefract, assertLine)`
  // free function previously lived here, byte-for-byte identical (same
  // switch, same case strings) to moho/particles/BeamRenderHelpers.cpp's own
  // `ResolveParticleTechniqueSuffix` (called for real there: BuildBeamTechniqueName
  // and two selection-technique builders). This file has no
  // blend-mode-to-technique-name construction of its own -- no caller, and no
  // `Address:` citation tying it to a distinct compiled address in this TU
  // -- so it was a speculative, unevidenced duplicate rather than a second
  // real binary emission. Removed; BeamRenderHelpers.cpp's copy is the
  // evidenced one.

  void BindParticleTextureShaderVar(
    moho::ShaderVar& shaderVar,
    const moho::CParticleTexture::TextureResourceHandle& textureResource
  )
  {
    // RD3DTextureResource is an ID3DTextureSheet, so the sheet binder does the
    // GetTexture-then-SetTexture pair itself - there is no reason to resolve the
    // handle here and re-wrap it.
    shaderVar.GetTexture(textureResource);
  }

  void BindParticleCameraShaderState(
    moho::GeomCamera3* const camera,
    const int tick,
    const float frameDelta
  )
  {
    if (camera == nullptr) {
      return;
    }

    if (moho::shaderVarParticleViewMatrix.Exists()) {
      moho::shaderVarParticleViewMatrix.mEffectVariable->SetMatrix4x4(&camera->view);
    }

    if (moho::shaderVarParticleProjection.Exists()) {
      moho::shaderVarParticleProjection.mEffectVariable->SetMatrix4x4(&camera->projection);
    }

    if (moho::shaderVarParticleWorldToProjection.Exists()) {
      moho::shaderVarParticleWorldToProjection.mEffectVariable->SetMatrix4x4(&camera->viewProjection);
    }

    if (moho::shaderVarParticleInverseViewMatrix.Exists()) {
      moho::shaderVarParticleInverseViewMatrix.mEffectVariable->SetMatrix4x4(&camera->inverseView);
    }

    const float time = static_cast<float>(tick) + frameDelta;
    if (moho::shaderVarParticleTime.Exists()) {
      moho::shaderVarParticleTime.mEffectVariable->SetFloat(time);
    }
  }

  /**
   * Frees the buffers the pool owns. The binary recurses the tree and deletes
   * each node as it goes; with a real container the node teardown belongs to
   * the container, so only the owned payloads are released here.
   */
  void ReleaseTrailSegmentPoolBuffers(moho::TrailSegmentPoolRuntime& poolRuntime) noexcept
  {
    for (moho::TrailSegmentBufferRuntime* const segmentBuffer : poolRuntime) {
      if (segmentBuffer == nullptr) {
        continue;
      }

      delete segmentBuffer->vertexSheet;
      segmentBuffer->vertexSheet = nullptr;
      ::operator delete(segmentBuffer);
    }
  }

  /**
   * What it does:
   * Typed `std::map` node lane for world-particle buckets
   * (`key + mapped bucket pointer` payload at `+0x0C`).
   */
  struct ParticleBucketTreeEntryNodeRuntime
  {
    ParticleBucketTreeEntryNodeRuntime* left = nullptr;   // +0x00
    ParticleBucketTreeEntryNodeRuntime* parent = nullptr; // +0x04
    ParticleBucketTreeEntryNodeRuntime* right = nullptr;  // +0x08
    moho::ParticleBucketKeyRuntime key{};                 // +0x0C
    moho::ParticleRenderBucketRuntime* bucket = nullptr;  // +0x48
    std::uint8_t color = 0U;                              // +0x4C
    std::uint8_t isNil = 0U;                              // +0x4D
    std::uint16_t padding4E = 0U;                         // +0x4E
  };

  static_assert(
    offsetof(ParticleBucketTreeEntryNodeRuntime, key) == 0x0C,
    "ParticleBucketTreeEntryNodeRuntime::key offset must be 0x0C"
  );
  static_assert(
    offsetof(ParticleBucketTreeEntryNodeRuntime, bucket) == 0x48,
    "ParticleBucketTreeEntryNodeRuntime::bucket offset must be 0x48"
  );
  static_assert(
    offsetof(ParticleBucketTreeEntryNodeRuntime, isNil) == 0x4D,
    "ParticleBucketTreeEntryNodeRuntime::isNil offset must be 0x4D"
  );
  static_assert(sizeof(ParticleBucketTreeEntryNodeRuntime) == 0x50, "ParticleBucketTreeEntryNodeRuntime size must be 0x50");

  /**
   * What it does:
   * Typed `std::map` node lane for world-trail buckets
   * (`key + mapped bucket pointer` payload at `+0x0C`).
   */
  struct TrailBucketTreeEntryNodeRuntime
  {
    TrailBucketTreeEntryNodeRuntime* left = nullptr;   // +0x00
    TrailBucketTreeEntryNodeRuntime* parent = nullptr; // +0x04
    TrailBucketTreeEntryNodeRuntime* right = nullptr;  // +0x08
    moho::TrailBucketKeyRuntime key{};                 // +0x0C
    moho::TrailRenderBucketRuntime* bucket = nullptr;  // +0x40
    std::uint8_t color = 0U;                           // +0x44
    std::uint8_t isNil = 0U;                           // +0x45
    std::uint16_t padding46 = 0U;                      // +0x46
  };

  static_assert(
    offsetof(TrailBucketTreeEntryNodeRuntime, key) == 0x0C,
    "TrailBucketTreeEntryNodeRuntime::key offset must be 0x0C"
  );
  static_assert(
    offsetof(TrailBucketTreeEntryNodeRuntime, bucket) == 0x40,
    "TrailBucketTreeEntryNodeRuntime::bucket offset must be 0x40"
  );
  static_assert(
    offsetof(TrailBucketTreeEntryNodeRuntime, isNil) == 0x45,
    "TrailBucketTreeEntryNodeRuntime::isNil offset must be 0x45"
  );
  static_assert(sizeof(TrailBucketTreeEntryNodeRuntime) == 0x48, "TrailBucketTreeEntryNodeRuntime size must be 0x48");

  /**
   * Address: 0x0049EEE0 (FUN_0049EEE0, sub_49EEE0)
   *
   * What it does:
   * Returns the key lane address from one particle-bucket tree entry-node slot.
   */
  moho::ParticleBucketKeyRuntime* GetParticleBucketEntryNodeKeySlotA(
    ParticleBucketTreeEntryNodeRuntime* const* const nodeSlot
  ) noexcept
  {
    return &(*nodeSlot)->key;
  }

  /**
   * Address: 0x0049EEF0 (FUN_0049EEF0, sub_49EEF0)
   *
   * What it does:
   * Duplicate particle-bucket tree entry-node key-slot accessor.
   */
  moho::ParticleBucketKeyRuntime* GetParticleBucketEntryNodeKeySlotB(
    ParticleBucketTreeEntryNodeRuntime* const* const nodeSlot
  ) noexcept
  {
    return &(*nodeSlot)->key;
  }

  /**
   * Address: 0x0049EF20 (FUN_0049EF20, sub_49EF20)
   *
   * What it does:
   * Returns the key lane address from one trail-bucket tree entry-node slot.
   */
  moho::TrailBucketKeyRuntime* GetTrailBucketEntryNodeKeySlotA(
    TrailBucketTreeEntryNodeRuntime* const* const nodeSlot
  ) noexcept
  {
    return &(*nodeSlot)->key;
  }

  /**
   * Address: 0x0049EF30 (FUN_0049EF30, sub_49EF30)
   *
   * What it does:
   * Duplicate trail-bucket tree entry-node key-slot accessor.
   */
  moho::TrailBucketKeyRuntime* GetTrailBucketEntryNodeKeySlotB(
    TrailBucketTreeEntryNodeRuntime* const* const nodeSlot
  ) noexcept
  {
    return &(*nodeSlot)->key;
  }

  /**
   * What it does:
   * Compact `(key pointer, mapped bucket pointer)` lane exported from one
   * particle-bucket map node iterator.
   */
  struct ParticleBucketNodeKeyValuePairRuntime
  {
    const moho::ParticleBucketKeyRuntime* key = nullptr; // +0x00
    moho::ParticleRenderBucketRuntime* bucket = nullptr; // +0x04
  };

  static_assert(
    offsetof(ParticleBucketNodeKeyValuePairRuntime, key) == 0x00,
    "ParticleBucketNodeKeyValuePairRuntime::key offset must be 0x00"
  );
  static_assert(
    offsetof(ParticleBucketNodeKeyValuePairRuntime, bucket) == 0x04,
    "ParticleBucketNodeKeyValuePairRuntime::bucket offset must be 0x04"
  );
  static_assert(
    sizeof(ParticleBucketNodeKeyValuePairRuntime) == 0x08,
    "ParticleBucketNodeKeyValuePairRuntime size must be 0x08"
  );

  [[nodiscard]] ParticleBucketTreeEntryNodeRuntime* AsParticleBucketEntryNode(
    moho::ParticleBucketTreeNodeRuntime* const node
  ) noexcept
  {
    return reinterpret_cast<ParticleBucketTreeEntryNodeRuntime*>(node);
  }

  [[nodiscard]] const ParticleBucketTreeEntryNodeRuntime* AsParticleBucketEntryNode(
    const moho::ParticleBucketTreeNodeRuntime* const node
  ) noexcept
  {
    return reinterpret_cast<const ParticleBucketTreeEntryNodeRuntime*>(node);
  }

  [[nodiscard]] TrailBucketTreeEntryNodeRuntime* AsTrailBucketEntryNode(
    moho::TrailBucketTreeNodeRuntime* const node
  ) noexcept
  {
    return reinterpret_cast<TrailBucketTreeEntryNodeRuntime*>(node);
  }

  [[nodiscard]] const TrailBucketTreeEntryNodeRuntime* AsTrailBucketEntryNode(
    const moho::TrailBucketTreeNodeRuntime* const node
  ) noexcept
  {
    return reinterpret_cast<const TrailBucketTreeEntryNodeRuntime*>(node);
  }

  [[nodiscard]] bool IsParticleBucketTreeSentinel(
    const ParticleBucketTreeEntryNodeRuntime* const node
  ) noexcept
  {
    return node == nullptr || node->isNil != 0U;
  }

  [[nodiscard]] bool IsTrailBucketTreeSentinel(
    const TrailBucketTreeEntryNodeRuntime* const node
  ) noexcept
  {
    return node == nullptr || node->isNil != 0U;
  }

  [[nodiscard]] ParticleBucketTreeEntryNodeRuntime* LowerBoundParticleBucketNode(
    const moho::ParticleBucketTreeRuntime& treeRuntime,
    const moho::ParticleBucketKeyRuntime& key
  ) noexcept
  {
    ParticleBucketTreeEntryNodeRuntime* const head = AsParticleBucketEntryNode(treeRuntime.head);
    ParticleBucketTreeEntryNodeRuntime* result = head;
    ParticleBucketTreeEntryNodeRuntime* node = head != nullptr ? head->parent : nullptr;

    while (!IsParticleBucketTreeSentinel(node)) {
      if (!moho::IsParticleBucketKeyRhsLessThanLhs(key, node->key)) {
        result = node;
        node = node->left;
      } else {
        node = node->right;
      }
    }

    return result;
  }

  /**
   * Address: 0x0049C940 (FUN_0049C940, sub_49C940)
   *
   * What it does:
   * Returns the lower-bound candidate node for one particle-bucket key probe.
   */
  [[nodiscard]] ParticleBucketTreeEntryNodeRuntime* FindParticleBucketLowerBoundCandidateNode(
    const moho::ParticleBucketTreeRuntime& treeRuntime,
    const moho::ParticleBucketKeyRuntime& key
  ) noexcept
  {
    return LowerBoundParticleBucketNode(treeRuntime, key);
  }

  [[nodiscard]] TrailBucketTreeEntryNodeRuntime* LowerBoundTrailBucketNode(
    const moho::TrailBucketTreeRuntime& treeRuntime,
    const moho::TrailBucketKeyRuntime& key
  ) noexcept
  {
    TrailBucketTreeEntryNodeRuntime* const head = AsTrailBucketEntryNode(treeRuntime.head);
    TrailBucketTreeEntryNodeRuntime* result = head;
    TrailBucketTreeEntryNodeRuntime* node = head != nullptr ? head->parent : nullptr;

    while (!IsTrailBucketTreeSentinel(node)) {
      if (!moho::IsTrailBucketKeyRhsLessThanLhs(key, node->key)) {
        result = node;
        node = node->left;
      } else {
        node = node->right;
      }
    }

    return result;
  }

  /**
   * Address: 0x0049CC90 (FUN_0049CC90, sub_49CC90)
   *
   * What it does:
   * Returns the lower-bound candidate node for one trail-bucket key probe.
   */
  [[nodiscard]] TrailBucketTreeEntryNodeRuntime* FindTrailBucketLowerBoundCandidateNode(
    const moho::TrailBucketTreeRuntime& treeRuntime,
    const moho::TrailBucketKeyRuntime& key
  ) noexcept
  {
    return LowerBoundTrailBucketNode(treeRuntime, key);
  }

  /**
   * Address: 0x004963E0 (FUN_004963E0, sub_4963E0)
   *
   * What it does:
   * Finds the particle-bucket lower-bound candidate and returns either that
   * node or map head when key equivalence is not satisfied.
   */
  moho::ParticleBucketTreeNodeRuntime** ResolveParticleBucketCandidateOrHead(
    const moho::ParticleBucketKeyRuntime& key,
    moho::ParticleBucketTreeNodeRuntime** const outNode,
    const moho::ParticleBucketTreeRuntime& treeRuntime
  ) noexcept
  {
    ParticleBucketTreeEntryNodeRuntime* const candidate = FindParticleBucketLowerBoundCandidateNode(treeRuntime, key);
    ParticleBucketTreeEntryNodeRuntime* const head = AsParticleBucketEntryNode(treeRuntime.head);

    if (candidate == head || moho::IsParticleBucketKeyRhsLessThanLhs(candidate->key, key)) {
      *outNode = treeRuntime.head;
    } else {
      *outNode = reinterpret_cast<moho::ParticleBucketTreeNodeRuntime*>(candidate);
    }

    return outNode;
  }

  /**
   * Address: 0x004964B0 (FUN_004964B0, sub_4964B0)
   *
   * What it does:
   * Writes one particle-bucket map begin-node (`head->left`) into caller
   * storage.
   */
  moho::ParticleBucketTreeNodeRuntime** GetParticleBucketTreeBeginNode(
    moho::ParticleBucketTreeNodeRuntime** const outNode,
    const moho::ParticleBucketTreeRuntime& treeRuntime
  ) noexcept
  {
    *outNode = treeRuntime.head->left;
    return outNode;
  }

  /**
   * Address: 0x004964C0 (FUN_004964C0, sub_4964C0)
   *
   * What it does:
   * Writes one particle-bucket map head-sentinel node into caller storage.
   */
  moho::ParticleBucketTreeNodeRuntime** GetParticleBucketTreeHeadNode(
    moho::ParticleBucketTreeNodeRuntime** const outNode,
    const moho::ParticleBucketTreeRuntime& treeRuntime
  ) noexcept
  {
    *outNode = treeRuntime.head;
    return outNode;
  }

  /**
   * Address: 0x00496520 (FUN_00496520, sub_496520)
   *
   * What it does:
   * Exports `(key pointer, mapped bucket pointer)` from one particle-bucket map
   * iterator node.
   */
  ParticleBucketNodeKeyValuePairRuntime* ExportParticleBucketNodeKeyValuePair(
    ParticleBucketNodeKeyValuePairRuntime* const outPair,
    moho::ParticleBucketTreeNodeRuntime* const* const iteratorNode
  ) noexcept
  {
    const ParticleBucketTreeEntryNodeRuntime* const node = AsParticleBucketEntryNode(*iteratorNode);
    outPair->key = &node->key;
    outPair->bucket = node->bucket;
    return outPair;
  }

  /**
   * Address: 0x00496590 (FUN_00496590, sub_496590)
   *
   * What it does:
   * Finds the trail-bucket lower-bound candidate and returns either that node
   * or map head when key equivalence is not satisfied.
   */
  moho::TrailBucketTreeNodeRuntime** ResolveTrailBucketCandidateOrHead(
    const moho::TrailBucketKeyRuntime& key,
    moho::TrailBucketTreeNodeRuntime** const outNode,
    const moho::TrailBucketTreeRuntime& treeRuntime
  ) noexcept
  {
    TrailBucketTreeEntryNodeRuntime* const candidate = FindTrailBucketLowerBoundCandidateNode(treeRuntime, key);
    TrailBucketTreeEntryNodeRuntime* const head = AsTrailBucketEntryNode(treeRuntime.head);

    if (candidate == head || moho::IsTrailBucketKeyRhsLessThanLhs(candidate->key, key)) {
      *outNode = treeRuntime.head;
    } else {
      *outNode = reinterpret_cast<moho::TrailBucketTreeNodeRuntime*>(candidate);
    }

    return outNode;
  }

  /**
   * Address: 0x00496660 (FUN_00496660, sub_496660)
   *
   * What it does:
   * Writes one trail-bucket map begin-node (`head->left`) into caller storage.
   */
  moho::TrailBucketTreeNodeRuntime** GetTrailBucketTreeBeginNode(
    moho::TrailBucketTreeNodeRuntime** const outNode,
    const moho::TrailBucketTreeRuntime& treeRuntime
  ) noexcept
  {
    *outNode = treeRuntime.head->left;
    return outNode;
  }

  /**
   * Address: 0x00496670 (FUN_00496670, sub_496670)
   *
   * What it does:
   * Writes one trail-bucket map head-sentinel node into caller storage.
   */
  moho::TrailBucketTreeNodeRuntime** GetTrailBucketTreeHeadNode(
    moho::TrailBucketTreeNodeRuntime** const outNode,
    const moho::TrailBucketTreeRuntime& treeRuntime
  ) noexcept
  {
    *outNode = treeRuntime.head;
    return outNode;
  }

  void DestroyParticleBucketTreeNodesRecursive(
    ParticleBucketTreeEntryNodeRuntime* const node,
    ParticleBucketTreeEntryNodeRuntime* const head
  ) noexcept
  {
    if (node == nullptr || node == head || node->isNil != 0U) {
      return;
    }

    DestroyParticleBucketTreeNodesRecursive(node->left, head);
    DestroyParticleBucketTreeNodesRecursive(node->right, head);

    if (node->bucket != nullptr) {
      moho::DestroyParticleRenderBucket(*node->bucket);
      ::operator delete(node->bucket);
      node->bucket = nullptr;
    }

    moho::ResetParticleBucketKeyResources(node->key);
    ::operator delete(node);
  }

  void DestroyParticleBucketTreeNodesRecursive(
    moho::ParticleBucketTreeNodeRuntime* const node,
    moho::ParticleBucketTreeNodeRuntime* const head
  ) noexcept
  {
    DestroyParticleBucketTreeNodesRecursive(
      reinterpret_cast<ParticleBucketTreeEntryNodeRuntime*>(node),
      reinterpret_cast<ParticleBucketTreeEntryNodeRuntime*>(head)
    );
  }

  void DestroyTrailBucketTreeNodesRecursive(
    TrailBucketTreeEntryNodeRuntime* const node,
    TrailBucketTreeEntryNodeRuntime* const head
  ) noexcept
  {
    if (node == nullptr || node == head || node->isNil != 0U) {
      return;
    }

    DestroyTrailBucketTreeNodesRecursive(node->left, head);
    DestroyTrailBucketTreeNodesRecursive(node->right, head);

    if (node->bucket != nullptr) {
      moho::DestroyTrailRenderBucket(*node->bucket);
      ::operator delete(node->bucket);
      node->bucket = nullptr;
    }

    moho::ResetTrailBucketKeyResources(node->key);
    ::operator delete(node);
  }

  void DestroyTrailBucketTreeNodesRecursive(
    moho::TrailBucketTreeNodeRuntime* const node,
    moho::TrailBucketTreeNodeRuntime* const head
  ) noexcept
  {
    DestroyTrailBucketTreeNodesRecursive(
      reinterpret_cast<TrailBucketTreeEntryNodeRuntime*>(node),
      reinterpret_cast<TrailBucketTreeEntryNodeRuntime*>(head)
    );
  }

  ParticleBucketTreeEntryNodeRuntime** EraseParticleBucketTreeNodeRangeAndStoreIterator(
    moho::ParticleBucketTreeRuntime& treeRuntime,
    ParticleBucketTreeEntryNodeRuntime** outIterator,
    ParticleBucketTreeEntryNodeRuntime* eraseBegin,
    const ParticleBucketTreeEntryNodeRuntime* eraseEnd
  );

  ParticleBucketTreeEntryNodeRuntime* DestroyParticleBucketPayloadRange(
    ParticleBucketTreeEntryNodeRuntime* node,
    const ParticleBucketTreeEntryNodeRuntime* head
  ) noexcept;

  TrailBucketTreeEntryNodeRuntime** EraseTrailBucketTreeNodeRangeAndStoreIterator(
    moho::TrailBucketTreeRuntime& treeRuntime,
    TrailBucketTreeEntryNodeRuntime** outIterator,
    TrailBucketTreeEntryNodeRuntime* eraseBegin,
    const TrailBucketTreeEntryNodeRuntime* eraseEnd
  );

  TrailBucketTreeEntryNodeRuntime* DestroyTrailBucketPayloadRange(
    TrailBucketTreeEntryNodeRuntime* node,
    const TrailBucketTreeEntryNodeRuntime* head
  ) noexcept;

  /**
   * Address: 0x00496430 (FUN_00496430, sub_496430)
   *
   * What it does:
   * Releases one particle-bucket map lane: destroys mapped bucket payloads,
   * destroys all tree nodes/keys, then frees the map head sentinel.
   */
  void ReleaseParticleBucketTreeStorage(
    moho::ParticleBucketTreeRuntime& treeRuntime
  ) noexcept
  {
    auto* const head = AsParticleBucketEntryNode(treeRuntime.head);
    if (head == nullptr) {
      treeRuntime.size = 0U;
      return;
    }

    ParticleBucketTreeEntryNodeRuntime* const eraseBegin = head->left;
    (void)DestroyParticleBucketPayloadRange(eraseBegin, head);
    ParticleBucketTreeEntryNodeRuntime* eraseResult = nullptr;
    (void)EraseParticleBucketTreeNodeRangeAndStoreIterator(treeRuntime, &eraseResult, eraseBegin, head);
    ::operator delete(head);
    treeRuntime.head = nullptr;
    treeRuntime.size = 0U;
  }

  /**
   * Address: 0x004965E0 (FUN_004965E0, sub_4965E0)
   *
   * What it does:
   * Releases one trail-bucket map lane: destroys mapped bucket payloads,
   * destroys all tree nodes/keys, then frees the map head sentinel.
   */
  void ReleaseTrailBucketTreeStorage(
    moho::TrailBucketTreeRuntime& treeRuntime
  ) noexcept
  {
    auto* const head = AsTrailBucketEntryNode(treeRuntime.head);
    if (head == nullptr) {
      treeRuntime.size = 0U;
      return;
    }

    TrailBucketTreeEntryNodeRuntime* const eraseBegin = head->left;
    (void)DestroyTrailBucketPayloadRange(eraseBegin, head);
    TrailBucketTreeEntryNodeRuntime* eraseResult = nullptr;
    (void)EraseTrailBucketTreeNodeRangeAndStoreIterator(treeRuntime, &eraseResult, eraseBegin, head);
    ::operator delete(head);
    treeRuntime.head = nullptr;
    treeRuntime.size = 0U;
  }

  /**
   * Address: 0x00498350 (FUN_00498350, sub_498350)
   *
   * What it does:
   * Duplicate begin-node accessor thunk for particle-bucket tree headers.
   */
  moho::ParticleBucketTreeNodeRuntime** GetParticleBucketTreeBeginNodeDuplicate(
    moho::ParticleBucketTreeNodeRuntime** const outNode,
    const moho::ParticleBucketTreeRuntime& treeRuntime
  ) noexcept
  {
    return GetParticleBucketTreeBeginNode(outNode, treeRuntime);
  }

  /**
   * Address: 0x00498360 (FUN_00498360, sub_498360)
   *
   * What it does:
   * Duplicate head-node accessor thunk for particle-bucket tree headers.
   */
  moho::ParticleBucketTreeNodeRuntime** GetParticleBucketTreeHeadNodeDuplicate(
    moho::ParticleBucketTreeNodeRuntime** const outNode,
    const moho::ParticleBucketTreeRuntime& treeRuntime
  ) noexcept
  {
    return GetParticleBucketTreeHeadNode(outNode, treeRuntime);
  }

  /**
   * Address: 0x004983A0 (FUN_004983A0, sub_4983A0)
   *
   * What it does:
   * Duplicate candidate-or-head resolver thunk for particle-bucket lookup.
   *
   * ICF-style binary twin: a distinct compiled address whose body is a pure
   * forward to the canonical `ResolveParticleBucketCandidateOrHead` (this
   * file, called for real at 3 sites). Zero callers of its own (callgraph
   * index + repo-wide search).
   */
  [[maybe_unused]] moho::ParticleBucketTreeNodeRuntime** ResolveParticleBucketCandidateOrHeadDuplicate(
    const moho::ParticleBucketKeyRuntime& key,
    moho::ParticleBucketTreeNodeRuntime** const outNode,
    const moho::ParticleBucketTreeRuntime& treeRuntime
  ) noexcept
  {
    return ResolveParticleBucketCandidateOrHead(key, outNode, treeRuntime);
  }

  /**
   * What it does:
   * Compact pointer+flag pair lane used by adjacent helper-thunk wrappers.
   */
  struct PointerFlagPairRuntime
  {
    void* pointer = nullptr;      // +0x00
    std::uint32_t flag = 0U;      // +0x04
  };

  static_assert(
    offsetof(PointerFlagPairRuntime, pointer) == 0x00,
    "PointerFlagPairRuntime::pointer offset must be 0x00"
  );
  static_assert(
    offsetof(PointerFlagPairRuntime, flag) == 0x04,
    "PointerFlagPairRuntime::flag offset must be 0x04"
  );
  static_assert(sizeof(PointerFlagPairRuntime) == 0x08, "PointerFlagPairRuntime size must be 0x08");

  /**
   * Address: 0x00498600 (FUN_00498600, sub_498600)
   *
   * What it does:
   * Duplicate begin-node accessor thunk for trail-bucket tree headers.
   */
  moho::TrailBucketTreeNodeRuntime** GetTrailBucketTreeBeginNodeDuplicate(
    moho::TrailBucketTreeNodeRuntime** const outNode,
    const moho::TrailBucketTreeRuntime& treeRuntime
  ) noexcept
  {
    return GetTrailBucketTreeBeginNode(outNode, treeRuntime);
  }

  /**
   * Address: 0x00498610 (FUN_00498610, sub_498610)
   *
   * What it does:
   * Duplicate head-node accessor thunk for trail-bucket tree headers.
   */
  moho::TrailBucketTreeNodeRuntime** GetTrailBucketTreeHeadNodeDuplicate(
    moho::TrailBucketTreeNodeRuntime** const outNode,
    const moho::TrailBucketTreeRuntime& treeRuntime
  ) noexcept
  {
    return GetTrailBucketTreeHeadNode(outNode, treeRuntime);
  }

  /**
   * Address: 0x00498650 (FUN_00498650, sub_498650)
   *
   * What it does:
   * Duplicate candidate-or-head resolver thunk for trail-bucket lookup.
   *
   * ICF-style binary twin: a distinct compiled address whose body is a pure
   * forward to the canonical `ResolveTrailBucketCandidateOrHead` (this file,
   * called for real at 1 site). Zero callers of its own (callgraph index +
   * repo-wide search).
   */
  [[maybe_unused]] moho::TrailBucketTreeNodeRuntime** ResolveTrailBucketCandidateOrHeadDuplicate(
    const moho::TrailBucketKeyRuntime& key,
    moho::TrailBucketTreeNodeRuntime** const outNode,
    const moho::TrailBucketTreeRuntime& treeRuntime
  ) noexcept
  {
    return ResolveTrailBucketCandidateOrHead(key, outNode, treeRuntime);
  }

  /**
   * What it does:
   * Compact pointer+byte pair lane used by adjacent insert-result thunks.
   */
  struct PointerByteFlagPairRuntime
  {
    void* pointer = nullptr;             // +0x00
    std::uint8_t flag = 0U;              // +0x04
    std::uint8_t padding05_07[0x03]{};   // +0x05
  };

  static_assert(
    offsetof(PointerByteFlagPairRuntime, pointer) == 0x00,
    "PointerByteFlagPairRuntime::pointer offset must be 0x00"
  );
  static_assert(
    offsetof(PointerByteFlagPairRuntime, flag) == 0x04,
    "PointerByteFlagPairRuntime::flag offset must be 0x04"
  );
  static_assert(sizeof(PointerByteFlagPairRuntime) == 0x08, "PointerByteFlagPairRuntime size must be 0x08");

  constexpr std::uint32_t kLegacyDwordVectorMaxCount = 0x3FFFFFFFU;

  /**
   * Address: 0x004990B0 (FUN_004990B0, sub_4990B0)
   *
   * What it does:
   * Copy-constructs one particle-bucket key lane, preserving weak-handle
   * control-state increments and string payload ownership.
   */
  moho::ParticleBucketKeyRuntime* CopyConstructParticleBucketKey(
    const moho::ParticleBucketKeyRuntime& source,
    moho::ParticleBucketKeyRuntime& destination
  ) noexcept
  {
    destination.sortScalar = source.sortScalar;
    destination.stateByte = source.stateByte;
    boost::AssignWeakPairFromShared(
      reinterpret_cast<boost::SharedCountPair*>(&destination.texture0),
      reinterpret_cast<const boost::SharedCountPair*>(&source.texture0)
    );
    boost::AssignWeakPairFromShared(
      reinterpret_cast<boost::SharedCountPair*>(&destination.texture1),
      reinterpret_cast<const boost::SharedCountPair*>(&source.texture1)
    );
    destination.tag = msvc8::string{};
    destination.tag.assign(source.tag, 0U, msvc8::string::npos);
    destination.blendMode = source.blendMode;
    destination.zMode = source.zMode;
    return &destination;
  }


  /**
   * Address: 0x00499180 (FUN_00499180, sub_499180)
   *
   * What it does:
   * Copy-constructs one trail-bucket key lane, preserving weak-handle
   * control-state increments and string payload ownership.
   */
  moho::TrailBucketKeyRuntime* CopyConstructTrailBucketKey(
    const moho::TrailBucketKeyRuntime& source,
    moho::TrailBucketKeyRuntime& destination
  ) noexcept
  {
    destination.sortScalar = source.sortScalar;
    boost::AssignWeakPairFromShared(
      reinterpret_cast<boost::SharedCountPair*>(&destination.texture0),
      reinterpret_cast<const boost::SharedCountPair*>(&source.texture0)
    );
    boost::AssignWeakPairFromShared(
      reinterpret_cast<boost::SharedCountPair*>(&destination.texture1),
      reinterpret_cast<const boost::SharedCountPair*>(&source.texture1)
    );
    destination.tag = msvc8::string{};
    destination.tag.assign(source.tag, 0U, msvc8::string::npos);
    destination.uvScalar = source.uvScalar;
    return &destination;
  }


  /**
   * What it does:
   * Compact 3-dword lane used by adjacent slot-export helper thunks.
   */
  struct LegacyTripleDwordRuntime
  {
    std::uint32_t value0 = 0U; // +0x00
    std::uint32_t value1 = 0U; // +0x04
    std::uint32_t value2 = 0U; // +0x08
  };

  static_assert(
    offsetof(LegacyTripleDwordRuntime, value1) == 0x04,
    "LegacyTripleDwordRuntime::value1 offset must be 0x04"
  );
  static_assert(
    offsetof(LegacyTripleDwordRuntime, value2) == 0x08,
    "LegacyTripleDwordRuntime::value2 offset must be 0x08"
  );
  static_assert(sizeof(LegacyTripleDwordRuntime) == 0x0C, "LegacyTripleDwordRuntime size must be 0x0C");

  /**
   * Address: 0x0049C670 (FUN_0049C670, sub_49C670)
   *
   * What it does:
   * Returns one fixed legacy list-size cap constant.
   */
  [[nodiscard]] std::uint32_t GetLegacyListMaxElementCount_0x3FFFFFFF_DuplicateB() noexcept
  {
    return 0x3FFFFFFFU;
  }

  [[nodiscard]] moho::ParticleBucketTreeNodeRuntime* AllocateParticleBucketTreeHeadNode()
  {
    auto* const head = static_cast<moho::ParticleBucketTreeNodeRuntime*>(
      ::operator new(sizeof(moho::ParticleBucketTreeNodeRuntime))
    );
    std::memset(head, 0, sizeof(moho::ParticleBucketTreeNodeRuntime));
    head->left = head;
    head->parent = head;
    head->right = head;
    head->color = 1U;
    head->isNil = 1U;
    return head;
  }

  [[nodiscard]] moho::TrailBucketTreeNodeRuntime* AllocateTrailBucketTreeHeadNode()
  {
    auto* const head = static_cast<moho::TrailBucketTreeNodeRuntime*>(
      ::operator new(sizeof(moho::TrailBucketTreeNodeRuntime))
    );
    std::memset(head, 0, sizeof(moho::TrailBucketTreeNodeRuntime));
    head->left = head;
    head->parent = head;
    head->right = head;
    head->color = 1U;
    head->isNil = 1U;
    return head;
  }

  void InitializeParticleBucketTree(moho::ParticleBucketTreeRuntime& treeRuntime)
  {
    if (treeRuntime.head == nullptr) {
      treeRuntime.head = AllocateParticleBucketTreeHeadNode();
    } else {
      treeRuntime.head->left = treeRuntime.head;
      treeRuntime.head->parent = treeRuntime.head;
      treeRuntime.head->right = treeRuntime.head;
      treeRuntime.head->color = 1U;
      treeRuntime.head->isNil = 1U;
    }
    treeRuntime.size = 0U;
  }

  void InitializeTrailBucketTree(moho::TrailBucketTreeRuntime& treeRuntime)
  {
    if (treeRuntime.head == nullptr) {
      treeRuntime.head = AllocateTrailBucketTreeHeadNode();
    } else {
      treeRuntime.head->left = treeRuntime.head;
      treeRuntime.head->parent = treeRuntime.head;
      treeRuntime.head->right = treeRuntime.head;
      treeRuntime.head->color = 1U;
      treeRuntime.head->isNil = 1U;
    }
    treeRuntime.size = 0U;
  }

  [[nodiscard]] moho::ParticleBucketKeyRuntime* InitializeParticleBucketKeyFromWorldParticle(
    moho::ParticleBucketKeyRuntime* const key,
    const moho::SWorldParticle& particle
  )
  {
    if (key == nullptr) {
      return nullptr;
    }

    key->texture0.reset();
    key->texture1.reset();
    key->tag = msvc8::string{};

    key->sortScalar = particle.mReserved54;
    key->stateByte = particle.mEnabled ? 1U : 0U;

    moho::CParticleTexture::TextureResourceHandle texture0{};
    if (particle.mTexture.tex != nullptr) {
      particle.mTexture.tex->GetTexture(texture0);
    }
    boost::AssignSharedPairRetain(
      reinterpret_cast<boost::SharedCountPair*>(&key->texture0),
      reinterpret_cast<const boost::SharedCountPair*>(&texture0)
    );

    moho::CParticleTexture::TextureResourceHandle texture1{};
    if (particle.mRampTexture.tex != nullptr) {
      particle.mRampTexture.tex->GetTexture(texture1);
    }
    boost::AssignSharedPairRetain(
      reinterpret_cast<boost::SharedCountPair*>(&key->texture1),
      reinterpret_cast<const boost::SharedCountPair*>(&texture1)
    );

    key->tag.assign(particle.mTypeTag, 0U, msvc8::string::npos);
    key->blendMode = static_cast<std::int32_t>(particle.mBlendMode);
    key->zMode = static_cast<std::int32_t>(particle.mZMode);
    return key;
  }

  [[nodiscard]] bool IsParticleBucketNodeBlack(
    const ParticleBucketTreeEntryNodeRuntime* const node
  ) noexcept
  {
    return node == nullptr || IsParticleBucketTreeSentinel(node) || node->color != 0U;
  }

  [[nodiscard]] bool IsTrailBucketNodeBlack(
    const TrailBucketTreeEntryNodeRuntime* const node
  ) noexcept
  {
    return node == nullptr || IsTrailBucketTreeSentinel(node) || node->color != 0U;
  }

  /**
   * Address: 0x0049D390 (FUN_0049D390, sub_49D390)
   *
   * What it does:
   * Performs one left rotation around one particle-bucket tree pivot node.
   */
  void RotateParticleBucketTreeLeft(
    moho::ParticleBucketTreeRuntime& treeRuntime,
    ParticleBucketTreeEntryNodeRuntime* const node
  ) noexcept
  {
    ParticleBucketTreeEntryNodeRuntime* const head = AsParticleBucketEntryNode(treeRuntime.head);
    ParticleBucketTreeEntryNodeRuntime* const pivot = node->right;

    node->right = pivot->left;
    if (!IsParticleBucketTreeSentinel(pivot->left)) {
      pivot->left->parent = node;
    }

    pivot->parent = node->parent;
    if (node == head->parent) {
      head->parent = pivot;
    } else if (node == node->parent->left) {
      node->parent->left = pivot;
    } else {
      node->parent->right = pivot;
    }

    pivot->left = node;
    node->parent = pivot;
  }

  /**
   * Address: 0x0049D3E0 (FUN_0049D3E0, sub_49D3E0)
   *
   * What it does:
   * Performs one right rotation around one particle-bucket tree pivot node.
   */
  void RotateParticleBucketTreeRight(
    moho::ParticleBucketTreeRuntime& treeRuntime,
    ParticleBucketTreeEntryNodeRuntime* const node
  ) noexcept
  {
    ParticleBucketTreeEntryNodeRuntime* const head = AsParticleBucketEntryNode(treeRuntime.head);
    ParticleBucketTreeEntryNodeRuntime* const pivot = node->left;

    node->left = pivot->right;
    if (!IsParticleBucketTreeSentinel(pivot->right)) {
      pivot->right->parent = node;
    }

    pivot->parent = node->parent;
    if (node == head->parent) {
      head->parent = pivot;
    } else if (node == node->parent->right) {
      node->parent->right = pivot;
    } else {
      node->parent->left = pivot;
    }

    pivot->right = node;
    node->parent = pivot;
  }

  /**
   * Address: 0x0049D7E0 (FUN_0049D7E0, sub_49D7E0)
   *
   * What it does:
   * Performs one left rotation around one trail-bucket tree pivot node.
   */
  void RotateTrailBucketTreeLeft(
    moho::TrailBucketTreeRuntime& treeRuntime,
    TrailBucketTreeEntryNodeRuntime* const node
  ) noexcept
  {
    TrailBucketTreeEntryNodeRuntime* const head = AsTrailBucketEntryNode(treeRuntime.head);
    TrailBucketTreeEntryNodeRuntime* const pivot = node->right;

    node->right = pivot->left;
    if (!IsTrailBucketTreeSentinel(pivot->left)) {
      pivot->left->parent = node;
    }

    pivot->parent = node->parent;
    if (node == head->parent) {
      head->parent = pivot;
    } else if (node == node->parent->left) {
      node->parent->left = pivot;
    } else {
      node->parent->right = pivot;
    }

    pivot->left = node;
    node->parent = pivot;
  }

  /**
   * Address: 0x0049D830 (FUN_0049D830, sub_49D830)
   *
   * What it does:
   * Performs one right rotation around one trail-bucket tree pivot node.
   */
  void RotateTrailBucketTreeRight(
    moho::TrailBucketTreeRuntime& treeRuntime,
    TrailBucketTreeEntryNodeRuntime* const node
  ) noexcept
  {
    TrailBucketTreeEntryNodeRuntime* const head = AsTrailBucketEntryNode(treeRuntime.head);
    TrailBucketTreeEntryNodeRuntime* const pivot = node->left;

    node->left = pivot->right;
    if (!IsTrailBucketTreeSentinel(pivot->right)) {
      pivot->right->parent = node;
    }

    pivot->parent = node->parent;
    if (node == head->parent) {
      head->parent = pivot;
    } else if (node == node->parent->right) {
      node->parent->right = pivot;
    } else {
      node->parent->left = pivot;
    }

    pivot->right = node;
    node->parent = pivot;
  }

  void FixupParticleBucketTreeAfterInsert(
    moho::ParticleBucketTreeRuntime& treeRuntime,
    ParticleBucketTreeEntryNodeRuntime* node
  ) noexcept
  {
    ParticleBucketTreeEntryNodeRuntime* const head = AsParticleBucketEntryNode(treeRuntime.head);

    while (node != head->parent && !IsParticleBucketNodeBlack(node->parent)) {
      if (node->parent == node->parent->parent->left) {
        ParticleBucketTreeEntryNodeRuntime* uncle = node->parent->parent->right;
        if (!IsParticleBucketTreeSentinel(uncle) && uncle->color == 0U) {
          node->parent->color = 1U;
          uncle->color = 1U;
          node->parent->parent->color = 0U;
          node = node->parent->parent;
          continue;
        }

        if (node == node->parent->right) {
          node = node->parent;
          RotateParticleBucketTreeLeft(treeRuntime, node);
        }

        node->parent->color = 1U;
        node->parent->parent->color = 0U;
        RotateParticleBucketTreeRight(treeRuntime, node->parent->parent);
      } else {
        ParticleBucketTreeEntryNodeRuntime* uncle = node->parent->parent->left;
        if (!IsParticleBucketTreeSentinel(uncle) && uncle->color == 0U) {
          node->parent->color = 1U;
          uncle->color = 1U;
          node->parent->parent->color = 0U;
          node = node->parent->parent;
          continue;
        }

        if (node == node->parent->left) {
          node = node->parent;
          RotateParticleBucketTreeRight(treeRuntime, node);
        }

        node->parent->color = 1U;
        node->parent->parent->color = 0U;
        RotateParticleBucketTreeLeft(treeRuntime, node->parent->parent);
      }
    }

    head->parent->color = 1U;
  }

  void FixupTrailBucketTreeAfterInsert(
    moho::TrailBucketTreeRuntime& treeRuntime,
    TrailBucketTreeEntryNodeRuntime* node
  ) noexcept
  {
    TrailBucketTreeEntryNodeRuntime* const head = AsTrailBucketEntryNode(treeRuntime.head);

    while (node != head->parent && !IsTrailBucketNodeBlack(node->parent)) {
      if (node->parent == node->parent->parent->left) {
        TrailBucketTreeEntryNodeRuntime* uncle = node->parent->parent->right;
        if (!IsTrailBucketTreeSentinel(uncle) && uncle->color == 0U) {
          node->parent->color = 1U;
          uncle->color = 1U;
          node->parent->parent->color = 0U;
          node = node->parent->parent;
          continue;
        }

        if (node == node->parent->right) {
          node = node->parent;
          RotateTrailBucketTreeLeft(treeRuntime, node);
        }

        node->parent->color = 1U;
        node->parent->parent->color = 0U;
        RotateTrailBucketTreeRight(treeRuntime, node->parent->parent);
      } else {
        TrailBucketTreeEntryNodeRuntime* uncle = node->parent->parent->left;
        if (!IsTrailBucketTreeSentinel(uncle) && uncle->color == 0U) {
          node->parent->color = 1U;
          uncle->color = 1U;
          node->parent->parent->color = 0U;
          node = node->parent->parent;
          continue;
        }

        if (node == node->parent->left) {
          node = node->parent;
          RotateTrailBucketTreeRight(treeRuntime, node);
        }

        node->parent->color = 1U;
        node->parent->parent->color = 0U;
        RotateTrailBucketTreeLeft(treeRuntime, node->parent->parent);
      }
    }

    head->parent->color = 1U;
  }

  /**
   * Address: 0x0049DA00 (FUN_0049DA00, sub_49DA00)
   *
   * What it does:
   * Walks one particle-bucket subtree to its left-most node and returns that
   * iterator position (or the sentinel unchanged).
   */
  [[nodiscard]] ParticleBucketTreeEntryNodeRuntime* GetParticleBucketTreeMinimum(
    ParticleBucketTreeEntryNodeRuntime* node
  ) noexcept
  {
    if (IsParticleBucketTreeSentinel(node)) {
      return node;
    }

    while (!IsParticleBucketTreeSentinel(node->left)) {
      node = node->left;
    }
    return node;
  }

  /**
   * Address: 0x0049D9E0 (FUN_0049D9E0, sub_49D9E0)
   *
   * What it does:
   * Walks one particle-bucket subtree to its right-most node and returns that
   * iterator position.
   */
  [[nodiscard]] ParticleBucketTreeEntryNodeRuntime* GetParticleBucketTreeMaximum(
    ParticleBucketTreeEntryNodeRuntime* node
  ) noexcept
  {
    while (!IsParticleBucketTreeSentinel(node->right)) {
      node = node->right;
    }
    return node;
  }

  /**
   * Address: 0x0049DA50 (FUN_0049DA50, sub_49DA50)
   *
   * What it does:
   * Moves one particle-bucket iterator to its in-order predecessor (or max
   * node when called with the head sentinel).
   */
  [[nodiscard]] ParticleBucketTreeEntryNodeRuntime* GetPreviousParticleBucketTreeNode(
    ParticleBucketTreeEntryNodeRuntime* node
  ) noexcept
  {
    if (node == nullptr) {
      return nullptr;
    }

    if (IsParticleBucketTreeSentinel(node)) {
      return node->right;
    }

    if (!IsParticleBucketTreeSentinel(node->left)) {
      return GetParticleBucketTreeMaximum(node->left);
    }

    ParticleBucketTreeEntryNodeRuntime* parent = node->parent;
    while (!IsParticleBucketTreeSentinel(parent) && node == parent->left) {
      node = parent;
      parent = parent->parent;
    }

    return parent;
  }

  /**
   * Address: 0x0049DB20 (FUN_0049DB20, sub_49DB20)
   *
   * What it does:
   * Moves one trail-bucket iterator to its in-order predecessor (or max node
   * when called with the head sentinel).
   */
  [[nodiscard]] TrailBucketTreeEntryNodeRuntime* GetPreviousTrailBucketTreeNode(
    TrailBucketTreeEntryNodeRuntime* node
  ) noexcept
  {
    if (node == nullptr) {
      return nullptr;
    }

    if (IsTrailBucketTreeSentinel(node)) {
      return node->right;
    }

    if (!IsTrailBucketTreeSentinel(node->left)) {
      TrailBucketTreeEntryNodeRuntime* rightMost = node->left;
      while (!IsTrailBucketTreeSentinel(rightMost->right)) {
        rightMost = rightMost->right;
      }
      return rightMost;
    }

    TrailBucketTreeEntryNodeRuntime* parent = node->parent;
    while (!IsTrailBucketTreeSentinel(parent) && node == parent->left) {
      node = parent;
      parent = parent->parent;
    }

    return parent;
  }

  [[nodiscard]] ParticleBucketTreeEntryNodeRuntime* GetNextParticleBucketTreeNode(
    ParticleBucketTreeEntryNodeRuntime* node
  ) noexcept
  {
    if (node == nullptr) {
      return nullptr;
    }

    if (IsParticleBucketTreeSentinel(node)) {
      return node->right;
    }

    if (!IsParticleBucketTreeSentinel(node->right)) {
      ParticleBucketTreeEntryNodeRuntime* next = node->right;
      while (!IsParticleBucketTreeSentinel(next->left)) {
        next = next->left;
      }
      return next;
    }

    ParticleBucketTreeEntryNodeRuntime* parent = node->parent;
    while (!IsParticleBucketTreeSentinel(parent) && node == parent->right) {
      node = parent;
      parent = parent->parent;
    }

    return parent;
  }

  [[nodiscard]] TrailBucketTreeEntryNodeRuntime* GetNextTrailBucketTreeNode(
    TrailBucketTreeEntryNodeRuntime* node
  ) noexcept
  {
    if (node == nullptr) {
      return nullptr;
    }

    if (IsTrailBucketTreeSentinel(node)) {
      return node->right;
    }

    if (!IsTrailBucketTreeSentinel(node->right)) {
      TrailBucketTreeEntryNodeRuntime* next = node->right;
      while (!IsTrailBucketTreeSentinel(next->left)) {
        next = next->left;
      }
      return next;
    }

    TrailBucketTreeEntryNodeRuntime* parent = node->parent;
    while (!IsTrailBucketTreeSentinel(parent) && node == parent->right) {
      node = parent;
      parent = parent->parent;
    }

    return parent;
  }

  /**
   * Address: 0x0049DC80 (FUN_0049DC80, sub_49DC80)
   *
   * What it does:
   * Advances one particle-bucket iterator slot to its in-order successor.
   */
  ParticleBucketTreeEntryNodeRuntime* MoveParticleBucketIteratorToNext(
    ParticleBucketTreeEntryNodeRuntime** const inOutNode
  ) noexcept
  {
    if (inOutNode == nullptr || *inOutNode == nullptr) {
      return nullptr;
    }

    *inOutNode = GetNextParticleBucketTreeNode(*inOutNode);
    return *inOutNode;
  }

  /**
   * Address: 0x0049DCD0 (FUN_0049DCD0, sub_49DCD0)
   *
   * What it does:
   * Advances one trail-bucket iterator slot to its in-order successor.
   */
  TrailBucketTreeEntryNodeRuntime* MoveTrailBucketIteratorToNext(
    TrailBucketTreeEntryNodeRuntime** const inOutNode
  ) noexcept
  {
    if (inOutNode == nullptr || *inOutNode == nullptr) {
      return nullptr;
    }

    *inOutNode = GetNextTrailBucketTreeNode(*inOutNode);
    return *inOutNode;
  }

  /**
   * Address: 0x0049DE80 (FUN_0049DE80, sub_49DE80)
   *
   * What it does:
   * Thunk-style duplicate for particle-bucket iterator advance.
   */
  ParticleBucketTreeEntryNodeRuntime* MoveParticleBucketIteratorToNextDuplicate(
    ParticleBucketTreeEntryNodeRuntime** const inOutNode
  ) noexcept
  {
    return MoveParticleBucketIteratorToNext(inOutNode);
  }

  /**
   * Address: 0x0049DE90 (FUN_0049DE90, sub_49DE90)
   *
   * What it does:
   * Thunk-style duplicate for trail-bucket iterator advance.
   */
  TrailBucketTreeEntryNodeRuntime* MoveTrailBucketIteratorToNextDuplicate(
    TrailBucketTreeEntryNodeRuntime** const inOutNode
  ) noexcept
  {
    return MoveTrailBucketIteratorToNext(inOutNode);
  }

  /**
   * Address: 0x0049EDF0 (FUN_0049EDF0, sub_49EDF0)
   *
   * What it does:
   * Thunk-style duplicate for particle-bucket iterator advance.
   */
  ParticleBucketTreeEntryNodeRuntime* MoveParticleBucketIteratorToNextDuplicateB(
    ParticleBucketTreeEntryNodeRuntime** const inOutNode
  ) noexcept
  {
    return MoveParticleBucketIteratorToNext(inOutNode);
  }

  /**
   * Address: 0x0049EE10 (FUN_0049EE10, sub_49EE10)
   *
   * What it does:
   * Thunk-style duplicate for trail-bucket iterator advance.
   */
  TrailBucketTreeEntryNodeRuntime* MoveTrailBucketIteratorToNextDuplicateB(
    TrailBucketTreeEntryNodeRuntime** const inOutNode
  ) noexcept
  {
    return MoveTrailBucketIteratorToNext(inOutNode);
  }

  /**
   * What it does:
   * Temporary `(particle-bucket-key, mapped-bucket)` lane used by ptr-map
   * insert copy-wrapper helpers.
   */
  struct ParticleBucketKeyValueRuntime
  {
    moho::ParticleBucketKeyRuntime key{};           // +0x00
    moho::ParticleRenderBucketRuntime* bucket = nullptr; // +0x3C
  };

  static_assert(
    offsetof(ParticleBucketKeyValueRuntime, bucket) == 0x3C,
    "ParticleBucketKeyValueRuntime::bucket offset must be 0x3C"
  );
  static_assert(sizeof(ParticleBucketKeyValueRuntime) == 0x40, "ParticleBucketKeyValueRuntime size must be 0x40");

  /**
   * Address: 0x0049EE50 (FUN_0049EE50, sub_49EE50)
   *
   * What it does:
   * Copy-constructs one particle-bucket key/value lane from source key and
   * bucket slot pointers.
   */
  ParticleBucketKeyValueRuntime* CopyConstructParticleBucketKeyValueFromKeyAndBucketSlot(
    const moho::ParticleBucketKeyRuntime& sourceKey,
    ParticleBucketKeyValueRuntime* const destination,
    moho::ParticleRenderBucketRuntime* const* const bucketSlot
  ) noexcept
  {
    (void)CopyConstructParticleBucketKey(sourceKey, destination->key);
    destination->bucket = *bucketSlot;
    return destination;
  }

  /**
   * Address: 0x0049E0B0 (FUN_0049E0B0, sub_49E0B0)
   *
   * What it does:
   * Copy-constructs one particle-bucket key/value temporary lane and releases
   * source key resources after transfer.
   */
  ParticleBucketKeyValueRuntime* CopyConstructParticleBucketKeyValueAndReleaseSource(
    ParticleBucketKeyValueRuntime* const destination,
    ParticleBucketKeyValueRuntime& source
  )
  {
    if (destination == nullptr) {
      return nullptr;
    }

    ::new (static_cast<void*>(&destination->key)) moho::ParticleBucketKeyRuntime{};
    (void)CopyConstructParticleBucketKeyValueFromKeyAndBucketSlot(source.key, destination, &source.bucket);
    moho::ResetParticleBucketKeyResources(source.key);
    return destination;
  }

  /**
   * Address: 0x0049E1E0 (FUN_0049E1E0, sub_49E1E0)
   *
   * What it does:
   * Writes one dword lane into caller output storage.
   */
  std::uint32_t* WriteDwordSlotFromRegisterLike(
    std::uint32_t* const outValueSlot,
    const std::uint32_t value
  ) noexcept
  {
    *outValueSlot = value;
    return outValueSlot;
  }

  /**
   * What it does:
   * Temporary `(trail-bucket-key, mapped-bucket)` lane used by ptr-map insert
   * copy-wrapper helpers.
   */
  struct TrailBucketKeyValueRuntime
  {
    moho::TrailBucketKeyRuntime key{};           // +0x00
    moho::TrailRenderBucketRuntime* bucket = nullptr; // +0x34
  };

  static_assert(
    offsetof(TrailBucketKeyValueRuntime, bucket) == 0x34,
    "TrailBucketKeyValueRuntime::bucket offset must be 0x34"
  );
  static_assert(sizeof(TrailBucketKeyValueRuntime) == 0x38, "TrailBucketKeyValueRuntime size must be 0x38");

  /**
   * Address: 0x0049EE80 (FUN_0049EE80, sub_49EE80)
   *
   * What it does:
   * Copy-constructs one trail-bucket key/value lane from source key and bucket
   * slot pointers.
   */
  TrailBucketKeyValueRuntime* CopyConstructTrailBucketKeyValueFromKeyAndBucketSlot(
    const moho::TrailBucketKeyRuntime& sourceKey,
    TrailBucketKeyValueRuntime* const destination,
    moho::TrailRenderBucketRuntime* const* const bucketSlot
  ) noexcept
  {
    (void)CopyConstructTrailBucketKey(sourceKey, destination->key);
    destination->bucket = *bucketSlot;
    return destination;
  }

  /**
   * Address: 0x0049E1F0 (FUN_0049E1F0, sub_49E1F0)
   *
   * What it does:
   * Copy-constructs one trail-bucket key/value temporary lane and releases
   * source key resources after transfer.
   */
  TrailBucketKeyValueRuntime* CopyConstructTrailBucketKeyValueAndReleaseSource(
    TrailBucketKeyValueRuntime* const destination,
    TrailBucketKeyValueRuntime& source
  )
  {
    if (destination == nullptr) {
      return nullptr;
    }

    ::new (static_cast<void*>(&destination->key)) moho::TrailBucketKeyRuntime{};
    (void)CopyConstructTrailBucketKeyValueFromKeyAndBucketSlot(source.key, destination, &source.bucket);
    moho::ResetTrailBucketKeyResources(source.key);
    return destination;
  }

  /**
   * Address: 0x0049E150 (FUN_0049E150, sub_49E150)
   *
   * What it does:
   * Walks one particle-bucket node iterator range, destroying mapped bucket
   * payloads while preserving key-node ownership for caller erase helpers.
   */
  ParticleBucketTreeEntryNodeRuntime* DestroyParticleBucketPayloadRange(
    ParticleBucketTreeEntryNodeRuntime* const rangeBegin,
    const ParticleBucketTreeEntryNodeRuntime* const rangeEnd
  ) noexcept
  {
    ParticleBucketTreeEntryNodeRuntime* cursor = rangeBegin;
    while (cursor != rangeEnd) {
      if (cursor->bucket != nullptr) {
        moho::DestroyParticleRenderBucket(*cursor->bucket);
        ::operator delete(cursor->bucket);
        cursor->bucket = nullptr;
      }
      (void)MoveParticleBucketIteratorToNext(&cursor);
    }
    return rangeBegin;
  }

  /**
   * Address: 0x0049E290 (FUN_0049E290, sub_49E290)
   *
   * What it does:
   * Walks one trail-bucket node iterator range, destroying mapped bucket
   * payloads while preserving key-node ownership for caller erase helpers.
   */
  TrailBucketTreeEntryNodeRuntime* DestroyTrailBucketPayloadRange(
    TrailBucketTreeEntryNodeRuntime* const rangeBegin,
    const TrailBucketTreeEntryNodeRuntime* const rangeEnd
  ) noexcept
  {
    TrailBucketTreeEntryNodeRuntime* cursor = rangeBegin;
    while (cursor != rangeEnd) {
      if (cursor->bucket != nullptr) {
        moho::DestroyTrailRenderBucket(*cursor->bucket);
        ::operator delete(cursor->bucket);
        cursor->bucket = nullptr;
      }
      (void)MoveTrailBucketIteratorToNext(&cursor);
    }
    return rangeBegin;
  }

  /**
   * Address: 0x0049DAD0 (FUN_0049DAD0, sub_49DAD0)
   *
   * What it does:
   * Walks one trail-bucket subtree to its left-most node and returns that
   * iterator position (or the sentinel unchanged).
   */
  [[nodiscard]] TrailBucketTreeEntryNodeRuntime* GetTrailBucketTreeMinimum(
    TrailBucketTreeEntryNodeRuntime* node
  ) noexcept
  {
    if (IsTrailBucketTreeSentinel(node)) {
      return node;
    }

    while (!IsTrailBucketTreeSentinel(node->left)) {
      node = node->left;
    }
    return node;
  }

  /**
   * Address: 0x0049DAB0 (FUN_0049DAB0, sub_49DAB0)
   *
   * What it does:
   * Walks one trail-bucket subtree to its right-most node and returns that
   * iterator position.
   */
  [[nodiscard]] TrailBucketTreeEntryNodeRuntime* GetTrailBucketTreeMaximum(
    TrailBucketTreeEntryNodeRuntime* node
  ) noexcept
  {
    while (!IsTrailBucketTreeSentinel(node->right)) {
      node = node->right;
    }
    return node;
  }

  void FixupParticleBucketTreeAfterKeyNodeErase(
    moho::ParticleBucketTreeRuntime& treeRuntime,
    ParticleBucketTreeEntryNodeRuntime* node,
    ParticleBucketTreeEntryNodeRuntime* parent
  ) noexcept
  {
    ParticleBucketTreeEntryNodeRuntime* const head = AsParticleBucketEntryNode(treeRuntime.head);
    if (head == nullptr) {
      return;
    }

    while (node != head->parent && IsParticleBucketNodeBlack(node)) {
      if (node == parent->left) {
        ParticleBucketTreeEntryNodeRuntime* sibling = parent->right;

        if (!IsParticleBucketTreeSentinel(sibling) && sibling->color == 0U) {
          sibling->color = 1U;
          parent->color = 0U;
          RotateParticleBucketTreeLeft(treeRuntime, parent);
          sibling = parent->right;
        }

        if (IsParticleBucketTreeSentinel(sibling)) {
          node = parent;
          parent = parent->parent;
          continue;
        }

        if (IsParticleBucketNodeBlack(sibling->left) && IsParticleBucketNodeBlack(sibling->right)) {
          sibling->color = 0U;
          node = parent;
          parent = parent->parent;
          continue;
        }

        if (IsParticleBucketNodeBlack(sibling->right)) {
          if (!IsParticleBucketTreeSentinel(sibling->left)) {
            sibling->left->color = 1U;
          }
          sibling->color = 0U;
          RotateParticleBucketTreeRight(treeRuntime, sibling);
          sibling = parent->right;
        }

        sibling->color = parent->color;
        parent->color = 1U;
        if (!IsParticleBucketTreeSentinel(sibling->right)) {
          sibling->right->color = 1U;
        }
        RotateParticleBucketTreeLeft(treeRuntime, parent);
      } else {
        ParticleBucketTreeEntryNodeRuntime* sibling = parent->left;

        if (!IsParticleBucketTreeSentinel(sibling) && sibling->color == 0U) {
          sibling->color = 1U;
          parent->color = 0U;
          RotateParticleBucketTreeRight(treeRuntime, parent);
          sibling = parent->left;
        }

        if (IsParticleBucketTreeSentinel(sibling)) {
          node = parent;
          parent = parent->parent;
          continue;
        }

        if (IsParticleBucketNodeBlack(sibling->right) && IsParticleBucketNodeBlack(sibling->left)) {
          sibling->color = 0U;
          node = parent;
          parent = parent->parent;
          continue;
        }

        if (IsParticleBucketNodeBlack(sibling->left)) {
          if (!IsParticleBucketTreeSentinel(sibling->right)) {
            sibling->right->color = 1U;
          }
          sibling->color = 0U;
          RotateParticleBucketTreeLeft(treeRuntime, sibling);
          sibling = parent->left;
        }

        sibling->color = parent->color;
        parent->color = 1U;
        if (!IsParticleBucketTreeSentinel(sibling->left)) {
          sibling->left->color = 1U;
        }
        RotateParticleBucketTreeRight(treeRuntime, parent);
      }

      break;
    }

    if (!IsParticleBucketTreeSentinel(node)) {
      node->color = 1U;
    }
  }

  void FixupTrailBucketTreeAfterKeyNodeErase(
    moho::TrailBucketTreeRuntime& treeRuntime,
    TrailBucketTreeEntryNodeRuntime* node,
    TrailBucketTreeEntryNodeRuntime* parent
  ) noexcept
  {
    TrailBucketTreeEntryNodeRuntime* const head = AsTrailBucketEntryNode(treeRuntime.head);
    if (head == nullptr) {
      return;
    }

    while (node != head->parent && IsTrailBucketNodeBlack(node)) {
      if (node == parent->left) {
        TrailBucketTreeEntryNodeRuntime* sibling = parent->right;

        if (!IsTrailBucketTreeSentinel(sibling) && sibling->color == 0U) {
          sibling->color = 1U;
          parent->color = 0U;
          RotateTrailBucketTreeLeft(treeRuntime, parent);
          sibling = parent->right;
        }

        if (IsTrailBucketTreeSentinel(sibling)) {
          node = parent;
          parent = parent->parent;
          continue;
        }

        if (IsTrailBucketNodeBlack(sibling->left) && IsTrailBucketNodeBlack(sibling->right)) {
          sibling->color = 0U;
          node = parent;
          parent = parent->parent;
          continue;
        }

        if (IsTrailBucketNodeBlack(sibling->right)) {
          if (!IsTrailBucketTreeSentinel(sibling->left)) {
            sibling->left->color = 1U;
          }
          sibling->color = 0U;
          RotateTrailBucketTreeRight(treeRuntime, sibling);
          sibling = parent->right;
        }

        sibling->color = parent->color;
        parent->color = 1U;
        if (!IsTrailBucketTreeSentinel(sibling->right)) {
          sibling->right->color = 1U;
        }
        RotateTrailBucketTreeLeft(treeRuntime, parent);
      } else {
        TrailBucketTreeEntryNodeRuntime* sibling = parent->left;

        if (!IsTrailBucketTreeSentinel(sibling) && sibling->color == 0U) {
          sibling->color = 1U;
          parent->color = 0U;
          RotateTrailBucketTreeRight(treeRuntime, parent);
          sibling = parent->left;
        }

        if (IsTrailBucketTreeSentinel(sibling)) {
          node = parent;
          parent = parent->parent;
          continue;
        }

        if (IsTrailBucketNodeBlack(sibling->right) && IsTrailBucketNodeBlack(sibling->left)) {
          sibling->color = 0U;
          node = parent;
          parent = parent->parent;
          continue;
        }

        if (IsTrailBucketNodeBlack(sibling->left)) {
          if (!IsTrailBucketTreeSentinel(sibling->right)) {
            sibling->right->color = 1U;
          }
          sibling->color = 0U;
          RotateTrailBucketTreeLeft(treeRuntime, sibling);
          sibling = parent->left;
        }

        sibling->color = parent->color;
        parent->color = 1U;
        if (!IsTrailBucketTreeSentinel(sibling->left)) {
          sibling->left->color = 1U;
        }
        RotateTrailBucketTreeRight(treeRuntime, parent);
      }

      break;
    }

    if (!IsTrailBucketTreeSentinel(node)) {
      node->color = 1U;
    }
  }

  /**
   * Address: 0x0049D0D0 (FUN_0049D0D0, sub_49D0D0)
   *
   * What it does:
   * Erases one particle-bucket map key node by iterator, preserving red-black
   * invariants and map begin/end sentinel links.
   */
  void EraseParticleBucketTreeKeyNode(
    moho::ParticleBucketTreeRuntime& treeRuntime,
    ParticleBucketTreeEntryNodeRuntime* const eraseTarget
  )
  {
    ParticleBucketTreeEntryNodeRuntime* const head = AsParticleBucketEntryNode(treeRuntime.head);
    if (IsParticleBucketTreeSentinel(eraseTarget) || IsParticleBucketTreeSentinel(head)) {
      throw std::out_of_range("invalid map/set<T> iterator");
    }

    ParticleBucketTreeEntryNodeRuntime* const next = GetNextParticleBucketTreeNode(eraseTarget);
    ParticleBucketTreeEntryNodeRuntime* fixupNode = nullptr;
    ParticleBucketTreeEntryNodeRuntime* fixupParent = nullptr;

    if (IsParticleBucketTreeSentinel(eraseTarget->left)) {
      fixupNode = eraseTarget->right;
      fixupParent = eraseTarget->parent;
      if (!IsParticleBucketTreeSentinel(fixupNode)) {
        fixupNode->parent = fixupParent;
      }

      if (head->parent == eraseTarget) {
        head->parent = fixupNode;
      } else if (fixupParent->left == eraseTarget) {
        fixupParent->left = fixupNode;
      } else {
        fixupParent->right = fixupNode;
      }

      if (head->left == eraseTarget) {
        head->left = IsParticleBucketTreeSentinel(fixupNode) ? fixupParent : GetParticleBucketTreeMinimum(fixupNode);
      }
      if (head->right == eraseTarget) {
        head->right = IsParticleBucketTreeSentinel(fixupNode) ? fixupParent : GetParticleBucketTreeMaximum(fixupNode);
      }
    } else if (IsParticleBucketTreeSentinel(eraseTarget->right)) {
      fixupNode = eraseTarget->left;
      fixupParent = eraseTarget->parent;
      if (!IsParticleBucketTreeSentinel(fixupNode)) {
        fixupNode->parent = fixupParent;
      }

      if (head->parent == eraseTarget) {
        head->parent = fixupNode;
      } else if (fixupParent->left == eraseTarget) {
        fixupParent->left = fixupNode;
      } else {
        fixupParent->right = fixupNode;
      }

      if (head->left == eraseTarget) {
        head->left = IsParticleBucketTreeSentinel(fixupNode) ? fixupParent : GetParticleBucketTreeMinimum(fixupNode);
      }
      if (head->right == eraseTarget) {
        head->right = IsParticleBucketTreeSentinel(fixupNode) ? fixupParent : GetParticleBucketTreeMaximum(fixupNode);
      }
    } else {
      ParticleBucketTreeEntryNodeRuntime* const successor = next;
      fixupNode = successor->right;

      if (successor == eraseTarget->right) {
        fixupParent = successor;
      } else {
        fixupParent = successor->parent;
        if (!IsParticleBucketTreeSentinel(fixupNode)) {
          fixupNode->parent = fixupParent;
        }
        fixupParent->left = fixupNode;

        successor->right = eraseTarget->right;
        successor->right->parent = successor;
      }

      if (head->parent == eraseTarget) {
        head->parent = successor;
      } else if (eraseTarget->parent->left == eraseTarget) {
        eraseTarget->parent->left = successor;
      } else {
        eraseTarget->parent->right = successor;
      }

      successor->parent = eraseTarget->parent;
      successor->left = eraseTarget->left;
      successor->left->parent = successor;
      std::swap(successor->color, eraseTarget->color);
    }

    if (eraseTarget->color == 1U) {
      FixupParticleBucketTreeAfterKeyNodeErase(treeRuntime, fixupNode, fixupParent);
    }

    moho::ResetParticleBucketKeyResources(eraseTarget->key);
    ::operator delete(eraseTarget);
    if (treeRuntime.size != 0U) {
      --treeRuntime.size;
    }
  }

  /**
   * Address: 0x0049D520 (FUN_0049D520, sub_49D520)
   *
   * What it does:
   * Erases one trail-bucket map key node by iterator, preserving red-black
   * invariants and map begin/end sentinel links.
   */
  void EraseTrailBucketTreeKeyNode(
    moho::TrailBucketTreeRuntime& treeRuntime,
    TrailBucketTreeEntryNodeRuntime* const eraseTarget
  )
  {
    TrailBucketTreeEntryNodeRuntime* const head = AsTrailBucketEntryNode(treeRuntime.head);
    if (IsTrailBucketTreeSentinel(eraseTarget) || IsTrailBucketTreeSentinel(head)) {
      throw std::out_of_range("invalid map/set<T> iterator");
    }

    TrailBucketTreeEntryNodeRuntime* const next = GetNextTrailBucketTreeNode(eraseTarget);
    TrailBucketTreeEntryNodeRuntime* fixupNode = nullptr;
    TrailBucketTreeEntryNodeRuntime* fixupParent = nullptr;

    if (IsTrailBucketTreeSentinel(eraseTarget->left)) {
      fixupNode = eraseTarget->right;
      fixupParent = eraseTarget->parent;
      if (!IsTrailBucketTreeSentinel(fixupNode)) {
        fixupNode->parent = fixupParent;
      }

      if (head->parent == eraseTarget) {
        head->parent = fixupNode;
      } else if (fixupParent->left == eraseTarget) {
        fixupParent->left = fixupNode;
      } else {
        fixupParent->right = fixupNode;
      }

      if (head->left == eraseTarget) {
        head->left = IsTrailBucketTreeSentinel(fixupNode) ? fixupParent : GetTrailBucketTreeMinimum(fixupNode);
      }
      if (head->right == eraseTarget) {
        head->right = IsTrailBucketTreeSentinel(fixupNode) ? fixupParent : GetTrailBucketTreeMaximum(fixupNode);
      }
    } else if (IsTrailBucketTreeSentinel(eraseTarget->right)) {
      fixupNode = eraseTarget->left;
      fixupParent = eraseTarget->parent;
      if (!IsTrailBucketTreeSentinel(fixupNode)) {
        fixupNode->parent = fixupParent;
      }

      if (head->parent == eraseTarget) {
        head->parent = fixupNode;
      } else if (fixupParent->left == eraseTarget) {
        fixupParent->left = fixupNode;
      } else {
        fixupParent->right = fixupNode;
      }

      if (head->left == eraseTarget) {
        head->left = IsTrailBucketTreeSentinel(fixupNode) ? fixupParent : GetTrailBucketTreeMinimum(fixupNode);
      }
      if (head->right == eraseTarget) {
        head->right = IsTrailBucketTreeSentinel(fixupNode) ? fixupParent : GetTrailBucketTreeMaximum(fixupNode);
      }
    } else {
      TrailBucketTreeEntryNodeRuntime* const successor = next;
      fixupNode = successor->right;

      if (successor == eraseTarget->right) {
        fixupParent = successor;
      } else {
        fixupParent = successor->parent;
        if (!IsTrailBucketTreeSentinel(fixupNode)) {
          fixupNode->parent = fixupParent;
        }
        fixupParent->left = fixupNode;

        successor->right = eraseTarget->right;
        successor->right->parent = successor;
      }

      if (head->parent == eraseTarget) {
        head->parent = successor;
      } else if (eraseTarget->parent->left == eraseTarget) {
        eraseTarget->parent->left = successor;
      } else {
        eraseTarget->parent->right = successor;
      }

      successor->parent = eraseTarget->parent;
      successor->left = eraseTarget->left;
      successor->left->parent = successor;
      std::swap(successor->color, eraseTarget->color);
    }

    if (eraseTarget->color == 1U) {
      FixupTrailBucketTreeAfterKeyNodeErase(treeRuntime, fixupNode, fixupParent);
    }

    moho::ResetTrailBucketKeyResources(eraseTarget->key);
    ::operator delete(eraseTarget);
    if (treeRuntime.size != 0U) {
      --treeRuntime.size;
    }
  }

  /**
   * Address: 0x0049C6E0 (FUN_0049C6E0, sub_49C6E0)
   *
   * What it does:
   * Erases one particle-bucket tree iterator range and stores the successor
   * iterator for caller traversal.
   */
  ParticleBucketTreeEntryNodeRuntime** EraseParticleBucketTreeNodeRangeAndStoreIterator(
    moho::ParticleBucketTreeRuntime& treeRuntime,
    ParticleBucketTreeEntryNodeRuntime** const outIterator,
    ParticleBucketTreeEntryNodeRuntime* eraseBegin,
    const ParticleBucketTreeEntryNodeRuntime* const eraseEnd
  )
  {
    ParticleBucketTreeEntryNodeRuntime* const head = AsParticleBucketEntryNode(treeRuntime.head);
    if (head == nullptr) {
      *outIterator = nullptr;
      return outIterator;
    }

    while (eraseBegin != eraseEnd) {
      ParticleBucketTreeEntryNodeRuntime* const eraseTarget = eraseBegin;
      eraseBegin = GetNextParticleBucketTreeNode(eraseBegin);
      EraseParticleBucketTreeKeyNode(treeRuntime, eraseTarget);
    }

    *outIterator = eraseBegin;
    return outIterator;
  }

  /**
   * Address: 0x0049CA30 (FUN_0049CA30, sub_49CA30)
   *
   * What it does:
   * Erases one trail-bucket tree iterator range and stores the successor
   * iterator for caller traversal.
   */
  TrailBucketTreeEntryNodeRuntime** EraseTrailBucketTreeNodeRangeAndStoreIterator(
    moho::TrailBucketTreeRuntime& treeRuntime,
    TrailBucketTreeEntryNodeRuntime** const outIterator,
    TrailBucketTreeEntryNodeRuntime* eraseBegin,
    const TrailBucketTreeEntryNodeRuntime* const eraseEnd
  )
  {
    TrailBucketTreeEntryNodeRuntime* const head = AsTrailBucketEntryNode(treeRuntime.head);
    if (head == nullptr) {
      *outIterator = nullptr;
      return outIterator;
    }

    while (eraseBegin != eraseEnd) {
      TrailBucketTreeEntryNodeRuntime* const eraseTarget = eraseBegin;
      eraseBegin = GetNextTrailBucketTreeNode(eraseBegin);
      EraseTrailBucketTreeKeyNode(treeRuntime, eraseTarget);
    }

    *outIterator = eraseBegin;
    return outIterator;
  }

  void RecomputeParticleBucketTreeMinMax(moho::ParticleBucketTreeRuntime& treeRuntime) noexcept
  {
    ParticleBucketTreeEntryNodeRuntime* const head = AsParticleBucketEntryNode(treeRuntime.head);
    if (head == nullptr || IsParticleBucketTreeSentinel(head->parent)) {
      if (head != nullptr) {
        head->left = head;
        head->right = head;
      }
      return;
    }

    head->left = GetParticleBucketTreeMinimum(head->parent);
    head->right = GetParticleBucketTreeMaximum(head->parent);
  }

  void RecomputeTrailBucketTreeMinMax(moho::TrailBucketTreeRuntime& treeRuntime) noexcept
  {
    TrailBucketTreeEntryNodeRuntime* const head = AsTrailBucketEntryNode(treeRuntime.head);
    if (head == nullptr || IsTrailBucketTreeSentinel(head->parent)) {
      if (head != nullptr) {
        head->left = head;
        head->right = head;
      }
      return;
    }

    head->left = GetTrailBucketTreeMinimum(head->parent);
    head->right = GetTrailBucketTreeMaximum(head->parent);
  }

  /**
   * Address: 0x0049ECD0 (FUN_0049ECD0, sub_49ECD0)
   *
   * What it does:
   * Allocates raw storage for `count` particle-bucket tree entry nodes and
   * throws `std::bad_alloc` on legacy overflow guard failure.
   */
  [[nodiscard]] void* AllocateParticleBucketTreeEntryNodeArrayOrThrow(const std::uint32_t elementCount)
  {
    constexpr std::uint32_t kMaxElementCount =
      std::numeric_limits<std::uint32_t>::max() / sizeof(ParticleBucketTreeEntryNodeRuntime);
    if (elementCount > kMaxElementCount) {
      throw std::bad_alloc{};
    }

    return ::operator new(static_cast<std::size_t>(elementCount) * sizeof(ParticleBucketTreeEntryNodeRuntime));
  }

  /**
   * Address: 0x0049ED20 (FUN_0049ED20, sub_49ED20)
   *
   * What it does:
   * Allocates raw storage for `count` trail-bucket tree entry nodes and throws
   * `std::bad_alloc` on legacy overflow guard failure.
   */
  [[nodiscard]] void* AllocateTrailBucketTreeEntryNodeArrayOrThrow(const std::uint32_t elementCount)
  {
    constexpr std::uint32_t kMaxElementCount =
      std::numeric_limits<std::uint32_t>::max() / sizeof(TrailBucketTreeEntryNodeRuntime);
    if (elementCount > kMaxElementCount) {
      throw std::bad_alloc{};
    }

    return ::operator new(static_cast<std::size_t>(elementCount) * sizeof(TrailBucketTreeEntryNodeRuntime));
  }

  /**
   * Address: 0x0049DA30 (FUN_0049DA30, sub_49DA30)
   *
   * What it does:
   * Allocates raw storage for one particle-bucket tree node lane.
   */
  [[nodiscard]] void* AllocateSingleParticleBucketTreeNodeStorage()
  {
    return AllocateParticleBucketTreeEntryNodeArrayOrThrow(1U);
  }

  /**
   * Address: 0x0049DBC0 (FUN_0049DBC0, sub_49DBC0)
   *
   * What it does:
   * Initializes one particle-bucket tree node in caller-provided storage from
   * link and payload lanes, then marks it as non-sentinel.
   */
  [[nodiscard]] ParticleBucketTreeEntryNodeRuntime* InitializeParticleBucketTreeEntryNodeWithLinksAndPayload(
    ParticleBucketTreeEntryNodeRuntime* const outNode,
    ParticleBucketTreeEntryNodeRuntime* const left,
    ParticleBucketTreeEntryNodeRuntime* const parent,
    ParticleBucketTreeEntryNodeRuntime* const right,
    const moho::ParticleBucketKeyRuntime& key,
    moho::ParticleRenderBucketRuntime* const bucket
  ) noexcept
  {
    if (outNode == nullptr) {
      return nullptr;
    }

    outNode->left = left;
    outNode->parent = parent;
    outNode->right = right;
    ::new (static_cast<void*>(&outNode->key)) moho::ParticleBucketKeyRuntime{};
    (void)moho::CopyParticleBucketKey(&outNode->key, &key);
    outNode->bucket = bucket;
    outNode->color = 0U;
    outNode->isNil = 0U;
    outNode->padding4E = 0U;
    return outNode;
  }

  /**
   * Address: 0x0049DB00 (FUN_0049DB00, sub_49DB00)
   *
   * What it does:
   * Allocates raw storage for one trail-bucket tree node lane.
   */
  [[nodiscard]] void* AllocateSingleTrailBucketTreeNodeStorage()
  {
    return AllocateTrailBucketTreeEntryNodeArrayOrThrow(1U);
  }

  /**
   * Address: 0x0049DBF0 (FUN_0049DBF0, sub_49DBF0)
   *
   * What it does:
   * Initializes one trail-bucket tree node in caller-provided storage from
   * link and payload lanes, then marks it as non-sentinel.
   */
  [[nodiscard]] TrailBucketTreeEntryNodeRuntime* InitializeTrailBucketTreeEntryNodeWithLinksAndPayload(
    TrailBucketTreeEntryNodeRuntime* const outNode,
    TrailBucketTreeEntryNodeRuntime* const left,
    TrailBucketTreeEntryNodeRuntime* const parent,
    TrailBucketTreeEntryNodeRuntime* const right,
    const moho::TrailBucketKeyRuntime& key,
    moho::TrailRenderBucketRuntime* const bucket
  ) noexcept
  {
    if (outNode == nullptr) {
      return nullptr;
    }

    outNode->left = left;
    outNode->parent = parent;
    outNode->right = right;
    ::new (static_cast<void*>(&outNode->key)) moho::TrailBucketKeyRuntime{};
    (void)moho::CopyTrailBucketKey(&outNode->key, &key);
    outNode->bucket = bucket;
    outNode->color = 0U;
    outNode->isNil = 0U;
    outNode->padding46 = 0U;
    return outNode;
  }

  /**
   * Address: 0x0049D430 (FUN_0049D430, sub_49D430)
   *
   * What it does:
   * Allocates one particle-bucket tree entry node, binds tree links, copies
   * key/value payload lanes, and marks the node as non-sentinel.
   */
  [[nodiscard]] ParticleBucketTreeEntryNodeRuntime* AllocateParticleBucketTreeEntryNodeWithLinks(
    const moho::ParticleBucketKeyRuntime& key,
    moho::ParticleRenderBucketRuntime* const bucket,
    ParticleBucketTreeEntryNodeRuntime* const left,
    ParticleBucketTreeEntryNodeRuntime* const parent,
    ParticleBucketTreeEntryNodeRuntime* const right
  )
  {
    auto* const node =
      static_cast<ParticleBucketTreeEntryNodeRuntime*>(AllocateSingleParticleBucketTreeNodeStorage());
    return InitializeParticleBucketTreeEntryNodeWithLinksAndPayload(node, left, parent, right, key, bucket);
  }

  /**
   * Address: 0x0049D880 (FUN_0049D880, sub_49D880)
   *
   * What it does:
   * Allocates one trail-bucket tree entry node, binds tree links, copies
   * key/value payload lanes, and marks the node as non-sentinel.
   */
  [[nodiscard]] TrailBucketTreeEntryNodeRuntime* AllocateTrailBucketTreeEntryNodeWithLinks(
    const moho::TrailBucketKeyRuntime& key,
    moho::TrailRenderBucketRuntime* const bucket,
    TrailBucketTreeEntryNodeRuntime* const left,
    TrailBucketTreeEntryNodeRuntime* const parent,
    TrailBucketTreeEntryNodeRuntime* const right
  )
  {
    auto* const node = static_cast<TrailBucketTreeEntryNodeRuntime*>(AllocateSingleTrailBucketTreeNodeStorage());
    return InitializeTrailBucketTreeEntryNodeWithLinksAndPayload(node, left, parent, right, key, bucket);
  }

  [[nodiscard]] ParticleBucketTreeEntryNodeRuntime* InsertParticleBucketTreeEntry(
    moho::ParticleBucketTreeRuntime& treeRuntime,
    const moho::ParticleBucketKeyRuntime& key,
    moho::ParticleRenderBucketRuntime* const bucket
  )
  {
    ParticleBucketTreeEntryNodeRuntime* const head = AsParticleBucketEntryNode(treeRuntime.head);
    if (head == nullptr) {
      return nullptr;
    }

    auto* const inserted = AllocateParticleBucketTreeEntryNodeWithLinks(key, bucket, head, head, head);

    ParticleBucketTreeEntryNodeRuntime* parent = head;
    ParticleBucketTreeEntryNodeRuntime* node = head->parent;
    bool insertAsLeftChild = true;
    while (!IsParticleBucketTreeSentinel(node)) {
      parent = node;
      if (!moho::IsParticleBucketKeyRhsLessThanLhs(key, node->key)) {
        node = node->left;
        insertAsLeftChild = true;
      } else {
        node = node->right;
        insertAsLeftChild = false;
      }
    }

    inserted->parent = parent;
    if (parent == head) {
      head->parent = inserted;
    } else if (insertAsLeftChild) {
      parent->left = inserted;
    } else {
      parent->right = inserted;
    }

    ++treeRuntime.size;
    FixupParticleBucketTreeAfterInsert(treeRuntime, inserted);
    RecomputeParticleBucketTreeMinMax(treeRuntime);
    return inserted;
  }

  /**
   * Address: 0x0049C7A0 (FUN_0049C7A0, sub_49C7A0)
   *
   * What it does:
   * Inserts one particle-bucket node using the legacy hinted insert contract
   * and returns the inserted iterator node lane.
   */
  [[nodiscard]] ParticleBucketTreeEntryNodeRuntime* InsertParticleBucketTreeEntryAtHint(
    moho::ParticleBucketTreeRuntime& treeRuntime,
    ParticleBucketTreeEntryNodeRuntime* const /*hintNode*/,
    const bool /*insertAsLeftChild*/,
    const moho::ParticleBucketKeyRuntime& key,
    moho::ParticleRenderBucketRuntime* const bucket
  )
  {
    return InsertParticleBucketTreeEntry(treeRuntime, key, bucket);
  }

  [[nodiscard]] TrailBucketTreeEntryNodeRuntime* InsertTrailBucketTreeEntry(
    moho::TrailBucketTreeRuntime& treeRuntime,
    const moho::TrailBucketKeyRuntime& key,
    moho::TrailRenderBucketRuntime* const bucket
  )
  {
    TrailBucketTreeEntryNodeRuntime* const head = AsTrailBucketEntryNode(treeRuntime.head);
    if (head == nullptr) {
      return nullptr;
    }

    auto* const inserted = AllocateTrailBucketTreeEntryNodeWithLinks(key, bucket, head, head, head);

    TrailBucketTreeEntryNodeRuntime* parent = head;
    TrailBucketTreeEntryNodeRuntime* node = head->parent;
    bool insertAsLeftChild = true;
    while (!IsTrailBucketTreeSentinel(node)) {
      parent = node;
      if (!moho::IsTrailBucketKeyRhsLessThanLhs(key, node->key)) {
        node = node->left;
        insertAsLeftChild = true;
      } else {
        node = node->right;
        insertAsLeftChild = false;
      }
    }

    inserted->parent = parent;
    if (parent == head) {
      head->parent = inserted;
    } else if (insertAsLeftChild) {
      parent->left = inserted;
    } else {
      parent->right = inserted;
    }

    ++treeRuntime.size;
    FixupTrailBucketTreeAfterInsert(treeRuntime, inserted);
    RecomputeTrailBucketTreeMinMax(treeRuntime);
    return inserted;
  }

  /**
   * Address: 0x0049CAF0 (FUN_0049CAF0, sub_49CAF0)
   *
   * What it does:
   * Inserts one trail-bucket node using the legacy hinted insert contract and
   * returns the inserted iterator node lane.
   */
  [[nodiscard]] TrailBucketTreeEntryNodeRuntime* InsertTrailBucketTreeEntryAtHint(
    moho::TrailBucketTreeRuntime& treeRuntime,
    TrailBucketTreeEntryNodeRuntime* const /*hintNode*/,
    const bool /*insertAsLeftChild*/,
    const moho::TrailBucketKeyRuntime& key,
    moho::TrailRenderBucketRuntime* const bucket
  )
  {
    return InsertTrailBucketTreeEntry(treeRuntime, key, bucket);
  }

  /**
   * Address: 0x0049A820 (FUN_0049A820, sub_49A820)
   *
   * What it does:
   * Throws on one null ptr-map insertion payload using the legacy message
   * contract.
   */
  void EnsurePtrMapInsertPayloadNotNull(void* const payload)
  {
    if (payload == nullptr) {
      throw std::runtime_error("Null pointer in ptr_map_adapter::insert()");
    }
  }

  /**
   * Address: 0x0049AA60 (FUN_0049AA60, sub_49AA60)
   *
   * What it does:
   * Duplicate ptr-map null payload guard helper retained for binary parity.
   */
  void EnsurePtrMapInsertPayloadNotNullDuplicate(void* const payload)
  {
    EnsurePtrMapInsertPayloadNotNull(payload);
  }

  /**
   * Address: 0x0049A870 (FUN_0049A870, sub_49A870)
   *
   * What it does:
   * Resolves one unique particle-bucket insert position, returning either the
   * existing equivalent node (`inserted = 0`) or one newly inserted node
   * (`inserted = 1`).
   */
  PointerByteFlagPairRuntime* InsertParticleBucketEntryOrResolveDuplicate(
    moho::ParticleBucketTreeRuntime& treeRuntime,
    PointerByteFlagPairRuntime* const outInsertResult,
    const moho::ParticleBucketKeyRuntime& key,
    moho::ParticleRenderBucketRuntime* const bucket
  )
  {
    ParticleBucketTreeEntryNodeRuntime* const head = AsParticleBucketEntryNode(treeRuntime.head);
    if (head == nullptr) {
      outInsertResult->pointer = nullptr;
      outInsertResult->flag = 0U;
      return outInsertResult;
    }

    ParticleBucketTreeEntryNodeRuntime* candidate = LowerBoundParticleBucketNode(treeRuntime, key);
    bool keyComparesBeforeCandidate = true;
    if (!IsParticleBucketTreeSentinel(candidate)) {
      keyComparesBeforeCandidate = moho::IsParticleBucketKeyRhsLessThanLhs(candidate->key, key);
    }

    ParticleBucketTreeEntryNodeRuntime* compareNode = candidate;
    if (keyComparesBeforeCandidate) {
      if (candidate == head->left) {
        outInsertResult->pointer = InsertParticleBucketTreeEntryAtHint(treeRuntime, candidate, true, key, bucket);
        outInsertResult->flag = 1U;
        return outInsertResult;
      }

      compareNode = GetPreviousParticleBucketTreeNode(candidate);
    }

    if (moho::IsParticleBucketKeyRhsLessThanLhs(key, compareNode->key)) {
      outInsertResult->pointer = InsertParticleBucketTreeEntryAtHint(treeRuntime, compareNode, false, key, bucket);
      outInsertResult->flag = 1U;
    } else {
      outInsertResult->pointer = compareNode;
      outInsertResult->flag = 0U;
    }

    return outInsertResult;
  }

  /**
   * Address: 0x0049AAB0 (FUN_0049AAB0, sub_49AAB0)
   *
   * What it does:
   * Resolves one unique trail-bucket insert position, returning either the
   * existing equivalent node (`inserted = 0`) or one newly inserted node
   * (`inserted = 1`).
   */
  PointerByteFlagPairRuntime* InsertTrailBucketEntryOrResolveDuplicate(
    moho::TrailBucketTreeRuntime& treeRuntime,
    PointerByteFlagPairRuntime* const outInsertResult,
    const moho::TrailBucketKeyRuntime& key,
    moho::TrailRenderBucketRuntime* const bucket
  )
  {
    TrailBucketTreeEntryNodeRuntime* const head = AsTrailBucketEntryNode(treeRuntime.head);
    if (head == nullptr) {
      outInsertResult->pointer = nullptr;
      outInsertResult->flag = 0U;
      return outInsertResult;
    }

    TrailBucketTreeEntryNodeRuntime* candidate = LowerBoundTrailBucketNode(treeRuntime, key);
    bool keyComparesBeforeCandidate = true;
    if (!IsTrailBucketTreeSentinel(candidate)) {
      keyComparesBeforeCandidate = moho::IsTrailBucketKeyRhsLessThanLhs(candidate->key, key);
    }

    TrailBucketTreeEntryNodeRuntime* compareNode = candidate;
    if (keyComparesBeforeCandidate) {
      if (candidate == head->left) {
        outInsertResult->pointer = InsertTrailBucketTreeEntryAtHint(treeRuntime, candidate, true, key, bucket);
        outInsertResult->flag = 1U;
        return outInsertResult;
      }

      compareNode = GetPreviousTrailBucketTreeNode(candidate);
    }

    if (moho::IsTrailBucketKeyRhsLessThanLhs(key, compareNode->key)) {
      outInsertResult->pointer = InsertTrailBucketTreeEntryAtHint(treeRuntime, compareNode, false, key, bucket);
      outInsertResult->flag = 1U;
    } else {
      outInsertResult->pointer = compareNode;
      outInsertResult->flag = 0U;
    }

    return outInsertResult;
  }

  /**
   * Address: 0x0049EEA0 (FUN_0049EEA0, sub_49EEA0)
   *
   * What it does:
   * Destroys one particle-bucket payload lane and releases the owning heap
   * block when present.
   */
  void DestroyAndDeleteParticleRenderBucket(moho::ParticleRenderBucketRuntime* const bucket) noexcept
  {
    if (bucket == nullptr) {
      return;
    }

    moho::DestroyParticleRenderBucket(*bucket);
    ::operator delete(bucket);
  }

  /**
   * Address: 0x0049EEC0 (FUN_0049EEC0, sub_49EEC0)
   *
   * What it does:
   * Destroys one trail-bucket payload lane and releases the owning heap block
   * when present.
   */
  void DestroyAndDeleteTrailRenderBucket(moho::TrailRenderBucketRuntime* const bucket) noexcept
  {
    if (bucket == nullptr) {
      return;
    }

    moho::DestroyTrailRenderBucket(*bucket);
    ::operator delete(bucket);
  }

  /**
   * Address: 0x004981C0 (FUN_004981C0, boost::ptr_map_adapter::insert)
   *
   * What it does:
   * Inserts one owned particle-bucket payload into the particle-bucket tree,
   * returning `(iterator-node, inserted)` and deleting the payload when the key
   * already exists.
   */
  PointerByteFlagPairRuntime* InsertOwnedParticleBucketByKey(
    moho::ParticleBucketTreeRuntime& treeRuntime,
    PointerByteFlagPairRuntime* const outInsertResult,
    const moho::ParticleBucketKeyRuntime& key,
    moho::ParticleRenderBucketRuntime* bucket
  )
  {
    EnsurePtrMapInsertPayloadNotNull(bucket);

    (void)InsertParticleBucketEntryOrResolveDuplicate(treeRuntime, outInsertResult, key, bucket);
    if (outInsertResult->flag == 0U) {
      DestroyAndDeleteParticleRenderBucket(bucket);
    }
    return outInsertResult;
  }

  /**
   * Address: 0x00498470 (FUN_00498470, sub_498470)
   *
   * What it does:
   * Inserts one owned trail-bucket payload into the trail-bucket tree,
   * returning `(iterator-node, inserted)` and deleting the payload when the key
   * already exists.
   */
  PointerByteFlagPairRuntime* InsertOwnedTrailBucketByKey(
    moho::TrailBucketTreeRuntime& treeRuntime,
    PointerByteFlagPairRuntime* const outInsertResult,
    const moho::TrailBucketKeyRuntime& key,
    moho::TrailRenderBucketRuntime* bucket
  )
  {
    EnsurePtrMapInsertPayloadNotNullDuplicate(bucket);

    (void)InsertTrailBucketEntryOrResolveDuplicate(treeRuntime, outInsertResult, key, bucket);
    if (outInsertResult->flag == 0U) {
      DestroyAndDeleteTrailRenderBucket(bucket);
    }
    return outInsertResult;
  }

  /**
   * Address: 0x0049A970 (FUN_0049A970, sub_49A970)
   *
   * What it does:
   * Recursively destroys one particle-bucket key-node subtree (right branch
   * first, then left spine), releasing key resources per node.
   */
  void DestroyParticleBucketKeyNodeSubtreeOnly(
    ParticleBucketTreeEntryNodeRuntime* node
  ) noexcept
  {
    while (!IsParticleBucketTreeSentinel(node)) {
      DestroyParticleBucketKeyNodeSubtreeOnly(node->right);
      ParticleBucketTreeEntryNodeRuntime* const next = node->left;
      moho::ResetParticleBucketKeyResources(node->key);
      ::operator delete(node);
      node = next;
    }
  }

  /**
   * Address: 0x0049AC10 (FUN_0049AC10, sub_49AC10)
   *
   * What it does:
   * Recursively destroys one trail-bucket key-node subtree (right branch
   * first, then left spine), releasing key resources per node.
   */
  void DestroyTrailBucketKeyNodeSubtreeOnly(TrailBucketTreeEntryNodeRuntime* node) noexcept
  {
    while (!IsTrailBucketTreeSentinel(node)) {
      DestroyTrailBucketKeyNodeSubtreeOnly(node->right);
      TrailBucketTreeEntryNodeRuntime* const next = node->left;
      moho::ResetTrailBucketKeyResources(node->key);
      ::operator delete(node);
      node = next;
    }
  }

  /**
   * Address: 0x0049A9B0 (FUN_0049A9B0, sub_49A9B0)
   *
   * What it does:
   * Returns the head-node pointer lane from one particle-bucket tree header.
   */
  [[nodiscard]] moho::ParticleBucketTreeNodeRuntime* ReadParticleBucketTreeHeadNodeFromHeader(
    const moho::ParticleBucketTreeRuntime& treeRuntime
  ) noexcept
  {
    return treeRuntime.head;
  }

  /**
   * Address: 0x0049AC50 (FUN_0049AC50, sub_49AC50)
   *
   * What it does:
   * Returns the head-node pointer lane from one trail-bucket tree header.
   */
  [[nodiscard]] moho::TrailBucketTreeNodeRuntime* ReadTrailBucketTreeHeadNodeFromHeader(
    const moho::TrailBucketTreeRuntime& treeRuntime
  ) noexcept
  {
    return treeRuntime.head;
  }

  /**
   * Address: 0x0049AA10 (FUN_0049AA10, sub_49AA10)
   *
   * What it does:
   * Comparator thunk forwarding to the recovered particle-bucket key ordering
   * predicate.
   */
  [[nodiscard]] bool CompareParticleBucketKeysThunk(
    const moho::ParticleBucketKeyRuntime& lhs,
    const moho::ParticleBucketKeyRuntime& rhs
  ) noexcept
  {
    return moho::IsParticleBucketKeyRhsLessThanLhs(lhs, rhs);
  }

  /**
   * Address: 0x0049ACB0 (FUN_0049ACB0, sub_49ACB0)
   *
   * What it does:
   * Comparator thunk forwarding to the recovered trail-bucket key ordering
   * predicate.
   */
  [[nodiscard]] bool CompareTrailBucketKeysThunk(
    const moho::TrailBucketKeyRuntime& lhs,
    const moho::TrailBucketKeyRuntime& rhs
  ) noexcept
  {
    return moho::IsTrailBucketKeyRhsLessThanLhs(lhs, rhs);
  }

  /**
   * Address: 0x0049DA20 (FUN_0049DA20, sub_49DA20)
   *
   * What it does:
   * Returns one fixed legacy map helper constant (`0x03FFFFFF`).
   */
  std::uint32_t GetLegacyMapHelperConstant_0x03FFFFFF_DuplicateA() noexcept
  {
    return 0x03FFFFFFU;
  }

  /**
   * Address: 0x0049D0C0 (FUN_0049D0C0, sub_49D0C0)
   *
   * What it does:
   * Returns one fixed legacy map helper constant (`0x03FFFFFF`).
  */
  std::uint32_t GetLegacyMapHelperConstant_0x03FFFFFF() noexcept
  {
    return 0x03FFFFFFU;
  }

  /**
   * Address: 0x0049D510 (FUN_0049D510, sub_49D510)
   *
   * What it does:
   * Returns one fixed legacy map helper constant (`0x04924924`).
   */
  std::uint32_t GetLegacyMapHelperConstant_0x04924924() noexcept
  {
    return 0x04924924U;
  }

  /**
   * Address: 0x0049DAF0 (FUN_0049DAF0, sub_49DAF0)
   *
   * What it does:
   * Returns one fixed legacy map helper constant (`0x04924924`).
   */
  std::uint32_t GetLegacyMapHelperConstant_0x04924924_DuplicateA() noexcept
  {
    return 0x04924924U;
  }

  /**
   * Address: 0x0049EF50 (FUN_0049EF50, sub_49EF50)
   *
   * What it does:
   * Returns whether one legacy string equals one NUL-terminated C-string by
   * exact length+payload comparison.
   */
  bool IsMsvc8StringEqualToCStringExact(const msvc8::string& lhs, const char* const rhs)
  {
    const std::size_t rhsLength = std::strlen(rhs);
    if (lhs.size() != rhsLength) {
      return false;
    }

    return rhsLength == 0U || std::memcmp(lhs.data(), rhs, rhsLength) == 0;
  }

  void DestroyWorldParticleForVectorTailLocal(moho::SWorldParticle& particle) noexcept;

  /**
   * Address: 0x0049F390 (FUN_0049F390, sub_49F390)
   *
   * What it does:
   * Initializes one particle-bucket tree header with a fresh sentinel head.
   */
  moho::ParticleBucketTreeRuntime* InitializeParticleBucketTreeWithFreshHead(
    moho::ParticleBucketTreeRuntime* const treeRuntime
  )
  {
    if (treeRuntime == nullptr) {
      return nullptr;
    }

    treeRuntime->head = AllocateParticleBucketTreeHeadNode();
    treeRuntime->size = 0U;
    return treeRuntime;
  }

  /**
   * Address: 0x0049F3C0 (FUN_0049F3C0, sub_49F3C0)
   *
   * What it does:
   * Destroys and deletes one mapped particle-bucket payload from one tree node
   * when present.
   */
  void DestroyParticleBucketNodeMappedBucketIfPresent(
    ParticleBucketTreeEntryNodeRuntime* const node
  ) noexcept
  {
    if (node == nullptr) {
      return;
    }

    DestroyAndDeleteParticleRenderBucket(node->bucket);
  }

  /**
   * Address: 0x0049F3F0 (FUN_0049F3F0, sub_49F3F0)
   *
   * What it does:
   * Initializes one trail-bucket tree header with a fresh sentinel head.
   */
  moho::TrailBucketTreeRuntime* InitializeTrailBucketTreeWithFreshHead(
    moho::TrailBucketTreeRuntime* const treeRuntime
  )
  {
    if (treeRuntime == nullptr) {
      return nullptr;
    }

    treeRuntime->head = AllocateTrailBucketTreeHeadNode();
    treeRuntime->size = 0U;
    return treeRuntime;
  }

  /**
   * Address: 0x0049F420 (FUN_0049F420, sub_49F420)
   *
   * What it does:
   * Destroys and deletes one mapped trail-bucket payload from one tree node
   * when present.
   */
  void DestroyTrailBucketNodeMappedBucketIfPresent(
    TrailBucketTreeEntryNodeRuntime* const node
  ) noexcept
  {
    if (node == nullptr) {
      return;
    }

    DestroyAndDeleteTrailRenderBucket(node->bucket);
  }

  struct PointerWithFieldAt3CRuntime
  {
    std::uint8_t padding00_3B[0x3C];
    std::uint32_t field3C;
  };

  static_assert(sizeof(PointerWithFieldAt3CRuntime) == 0x40, "PointerWithFieldAt3CRuntime size must be 0x40");

  struct PointerWithFieldAt34Runtime
  {
    std::uint8_t padding00_33[0x34];
    std::uint32_t field34;
  };

  static_assert(sizeof(PointerWithFieldAt34Runtime) == 0x38, "PointerWithFieldAt34Runtime size must be 0x38");

  /**
   * Address: 0x0049FA70 (FUN_0049FA70, sub_49FA70)
   *
   * What it does:
   * Duplicate particle-bucket destroy+delete thunk.
   */
  void DestroyAndDeleteParticleRenderBucketDuplicateA(
    moho::ParticleRenderBucketRuntime* const bucket
  ) noexcept
  {
    DestroyAndDeleteParticleRenderBucket(bucket);
  }

  /**
   * Address: 0x0049FA90 (FUN_0049FA90, sub_49FA90)
   *
   * What it does:
   * Duplicate trail-bucket destroy+delete thunk.
   */
  void DestroyAndDeleteTrailRenderBucketDuplicateA(
    moho::TrailRenderBucketRuntime* const bucket
  ) noexcept
  {
    DestroyAndDeleteTrailRenderBucket(bucket);
  }

  /**
   * Address: 0x004A0060 (FUN_004A0060, sub_4A0060)
   *
   * What it does:
   * Duplicate particle-bucket destroy+delete thunk.
   */
  void DestroyAndDeleteParticleRenderBucketDuplicateB(
    moho::ParticleRenderBucketRuntime* const bucket
  ) noexcept
  {
    DestroyAndDeleteParticleRenderBucket(bucket);
  }

  /**
   * Address: 0x004A0080 (FUN_004A0080, sub_4A0080)
   *
   * What it does:
   * Duplicate trail-bucket destroy+delete thunk.
   */
  void DestroyAndDeleteTrailRenderBucketDuplicateB(
    moho::TrailRenderBucketRuntime* const bucket
  ) noexcept
  {
    DestroyAndDeleteTrailRenderBucket(bucket);
  }

  /**
   * Address: 0x004A01F0 (FUN_004A01F0, sub_4A01F0)
   *
   * What it does:
   * Duplicate particle-bucket tree-header initialization with fresh head
   * sentinel allocation.
   */
  moho::ParticleBucketTreeRuntime* InitializeParticleBucketTreeWithFreshHeadDuplicateA(
    moho::ParticleBucketTreeRuntime* const treeRuntime
  )
  {
    return InitializeParticleBucketTreeWithFreshHead(treeRuntime);
  }

  /**
   * Address: 0x004A0230 (FUN_004A0230, sub_4A0230)
   *
   * What it does:
   * Duplicate trail-bucket tree-header initialization with fresh head sentinel
   * allocation.
   */
  moho::TrailBucketTreeRuntime* InitializeTrailBucketTreeWithFreshHeadDuplicateA(
    moho::TrailBucketTreeRuntime* const treeRuntime
  )
  {
    return InitializeTrailBucketTreeWithFreshHead(treeRuntime);
  }

  /**
   * Address: 0x004A0260 (FUN_004A0260, sub_4A0260)
   *
   * What it does:
   * Returns one mapped trail-bucket payload pointer from one tree entry-node.
   */
  moho::TrailRenderBucketRuntime* ReadTrailBucketEntryNodeMappedBucket(
    TrailBucketTreeEntryNodeRuntime* const node
  ) noexcept
  {
    return node->bucket;
  }

  /**
   * Address: 0x004A0580 (FUN_004A0580, sub_4A0580)
   *
   * What it does:
   * Duplicate particle-bucket destroy+delete thunk.
   */
  void DestroyAndDeleteParticleRenderBucketDuplicateC(
    moho::ParticleRenderBucketRuntime* const bucket
  ) noexcept
  {
    DestroyAndDeleteParticleRenderBucket(bucket);
  }

  /**
   * Address: 0x004A05A0 (FUN_004A05A0, sub_4A05A0)
   *
   * What it does:
   * Duplicate trail-bucket destroy+delete thunk.
   */
  void DestroyAndDeleteTrailRenderBucketDuplicateC(
    moho::TrailRenderBucketRuntime* const bucket
  ) noexcept
  {
    DestroyAndDeleteTrailRenderBucket(bucket);
  }

  /**
   * Address: 0x004A0750 (FUN_004A0750, sub_4A0750)
   *
   * What it does:
   * Duplicate particle-bucket tree-header initialization with fresh sentinel
   * head allocation.
   */
  moho::ParticleBucketTreeRuntime* InitializeParticleBucketTreeWithFreshHeadDuplicateB(
    moho::ParticleBucketTreeRuntime* const treeRuntime
  )
  {
    return InitializeParticleBucketTreeWithFreshHeadDuplicateA(treeRuntime);
  }

  /**
   * Address: 0x004A0790 (FUN_004A0790, sub_4A0790)
   *
   * What it does:
   * Duplicate trail-bucket tree-header initialization with fresh sentinel head
   * allocation.
   */
  moho::TrailBucketTreeRuntime* InitializeTrailBucketTreeWithFreshHeadDuplicateB(
    moho::TrailBucketTreeRuntime* const treeRuntime
  )
  {
    return InitializeTrailBucketTreeWithFreshHeadDuplicateA(treeRuntime);
  }

  /**
   * Address: 0x004A07D0 (FUN_004A07D0, sub_4A07D0)
   *
   * What it does:
   * Duplicate particle-bucket tree-header initialization with fresh sentinel
   * head allocation.
   */
  moho::ParticleBucketTreeRuntime* InitializeParticleBucketTreeWithFreshHeadDuplicateC(
    moho::ParticleBucketTreeRuntime* const treeRuntime
  )
  {
    return InitializeParticleBucketTreeWithFreshHeadDuplicateA(treeRuntime);
  }

  /**
   * Address: 0x004A0800 (FUN_004A0800, sub_4A0800)
   *
   * What it does:
   * Duplicate trail-bucket tree-header initialization with fresh sentinel head
   * allocation.
   */
  moho::TrailBucketTreeRuntime* InitializeTrailBucketTreeWithFreshHeadDuplicateC(
    moho::TrailBucketTreeRuntime* const treeRuntime
  )
  {
    return InitializeTrailBucketTreeWithFreshHeadDuplicateA(treeRuntime);
  }

  /**
   * Address: 0x004A0830 (FUN_004A0830, sub_4A0830)
   *
   * What it does:
   * Initializes one particle-bucket tree header and returns the resulting head
   * sentinel node.
   */
  moho::ParticleBucketTreeNodeRuntime* InitializeParticleBucketTreeAndReturnHead(
    moho::ParticleBucketTreeRuntime* const treeRuntime
  )
  {
    InitializeParticleBucketTreeWithFreshHeadDuplicateA(treeRuntime);
    return treeRuntime->head;
  }

  /**
   * Address: 0x004A0880 (FUN_004A0880, sub_4A0880)
   *
   * What it does:
   * Initializes one trail-bucket tree header and returns the resulting head
   * sentinel node.
   */
  moho::TrailBucketTreeNodeRuntime* InitializeTrailBucketTreeAndReturnHead(
    moho::TrailBucketTreeRuntime* const treeRuntime
  )
  {
    InitializeTrailBucketTreeWithFreshHeadDuplicateA(treeRuntime);
    return treeRuntime->head;
  }

  /**
   * Address: 0x004A08D0 (FUN_004A08D0, sub_4A08D0)
   *
   * What it does:
   * Allocates one particle-bucket tree node and initializes link lanes to null
   * with default black/non-sentinel flags.
   */
  moho::ParticleBucketTreeNodeRuntime* AllocateParticleBucketTreeNodeWithNullLinksBlack()
  {
    auto* const node = static_cast<moho::ParticleBucketTreeNodeRuntime*>(
      AllocateParticleBucketTreeEntryNodeArrayOrThrow(1U)
    );
    node->left = nullptr;
    node->parent = nullptr;
    node->right = nullptr;
    node->color = 1U;
    node->isNil = 0U;
    return node;
  }

  /**
   * Address: 0x004A0920 (FUN_004A0920, sub_4A0920)
   *
   * What it does:
   * Allocates one trail-bucket tree node and initializes link lanes to null
   * with default black/non-sentinel flags.
   */
  moho::TrailBucketTreeNodeRuntime* AllocateTrailBucketTreeNodeWithNullLinksBlack()
  {
    auto* const node = static_cast<moho::TrailBucketTreeNodeRuntime*>(
      AllocateTrailBucketTreeEntryNodeArrayOrThrow(1U)
    );
    node->left = nullptr;
    node->parent = nullptr;
    node->right = nullptr;
    node->color = 1U;
    node->isNil = 0U;
    return node;
  }

  /**
   * Address: 0x004A0AF0 (FUN_004A0AF0, sub_4A0AF0)
   *
   * What it does:
   * Duplicate particle-bucket destroy+delete thunk.
   */
  void DestroyAndDeleteParticleRenderBucketDuplicateD(
    moho::ParticleRenderBucketRuntime* const bucket
  ) noexcept
  {
    DestroyAndDeleteParticleRenderBucket(bucket);
  }

  /**
   * Address: 0x004A0B10 (FUN_004A0B10, sub_4A0B10)
   *
   * What it does:
   * Duplicate trail-bucket destroy+delete thunk.
   */
  void DestroyAndDeleteTrailRenderBucketDuplicateD(
    moho::TrailRenderBucketRuntime* const bucket
  ) noexcept
  {
    DestroyAndDeleteTrailRenderBucket(bucket);
  }

  /**
   * Address: 0x004A0B90 (FUN_004A0B90, sub_4A0B90)
   *
   * What it does:
   * Destroys and deletes one particle-bucket payload and returns the input
   * pointer.
   */
  moho::ParticleRenderBucketRuntime* DestroyAndDeleteParticleRenderBucketAndReturnInput(
    moho::ParticleRenderBucketRuntime* const bucket
  ) noexcept
  {
    moho::DestroyParticleRenderBucket(*bucket);
    ::operator delete(bucket);
    return bucket;
  }

  /**
   * Address: 0x004A0BB0 (FUN_004A0BB0, sub_4A0BB0)
   *
   * What it does:
   * Destroys and deletes one trail-bucket payload and returns the input
   * pointer.
   */
  moho::TrailRenderBucketRuntime* DestroyAndDeleteTrailRenderBucketAndReturnInput(
    moho::TrailRenderBucketRuntime* const bucket
  ) noexcept
  {
    moho::DestroyTrailRenderBucket(*bucket);
    ::operator delete(bucket);
    return bucket;
  }

  /**
   * Address: 0x0049DDC0 (FUN_0049DDC0, func_StrCmp)
   *
   * What it does:
   * Returns whether one legacy string and one C-string differ by value.
   */
  bool AreMsvc8StringAndCStringDifferent(
    const msvc8::string& lhs,
    const char* const rhs
  ) noexcept
  {
    if (rhs == nullptr) {
      return lhs.size() != 0U;
    }

    const std::size_t rhsLength = std::strlen(rhs);
    if (lhs.size() != rhsLength) {
      return true;
    }

    if (rhsLength == 0U) {
      return false;
    }

    return std::memcmp(lhs.data(), rhs, rhsLength) != 0;
  }

} // namespace

namespace moho
{
  ShaderVar& shaderVarParticleViewMatrix = AccessParticleShaderVarSlot<0x010A8440u>();
  ShaderVar& shaderVarParticleProjection = AccessParticleShaderVarSlot<0x010A82D8u>();
  ShaderVar& shaderVarParticleWorldToProjection = AccessParticleShaderVarSlot<0x010A83F8u>();
  ShaderVar& shaderVarParticleInverseViewMatrix = AccessParticleShaderVarSlot<0x010A8638u>();
  ShaderVar& shaderVarParticleParticleSystemPosition = AccessParticleShaderVarSlot<0x010A8368u>();
  ShaderVar& shaderVarParticleTime = AccessParticleShaderVarSlot<0x010A8560u>();
  ShaderVar& shaderVarParticleParticleSystemShape = AccessParticleShaderVarSlot<0x010A84D0u>();
  ShaderVar& shaderVarParticleParticleSpread = AccessParticleShaderVarSlot<0x010A8290u>();
  ShaderVar& shaderVarParticleParticleSpeed = AccessParticleShaderVarSlot<0x010A85A8u>();
  ShaderVar& shaderVarParticleParticleSystemHeight = AccessParticleShaderVarSlot<0x010A8518u>();
  ShaderVar& shaderVarParticleParticleSize = AccessParticleShaderVarSlot<0x010A8488u>();
  ShaderVar& shaderVarParticleDragEnabled = AccessParticleShaderVarSlot<0x010A83B0u>();
  ShaderVar& shaderVarParticleDragCoeff = AccessParticleShaderVarSlot<0x010A86C8u>();
  ShaderVar& shaderVarParticleInvDragCoeff = AccessParticleShaderVarSlot<0x010A8320u>();
  ShaderVar& shaderVarParticleInvDragCoeffSq = AccessParticleShaderVarSlot<0x010A8718u>();
  ShaderVar& shaderVarParticleBackgroundTexture = AccessParticleShaderVarSlot<0x010A85F0u>();
  ShaderVar& shaderVarParticleParticleTexture0 = AccessParticleShaderVarSlot<0x010A8680u>();
  ShaderVar& shaderVarParticleParticleTexture1 = AccessParticleShaderVarSlot<0x010A8760u>();
  float efx_ParticleWaterSurface = 0.0F;

  CWorldParticles sWorldParticles{};

  /**
   * Address: 0x00495440 (FUN_00495440, sub_495440)
   *
   * What it does:
   * Returns the global world-particles singleton used by engine render/update
   * paths.
   */
  CWorldParticles* GetGlobalWorldParticles() noexcept
  {
    return &sWorldParticles;
  }

  ID3DIndexSheet* GetSharedTrailQuadIndexSheet() noexcept
  {
    return sSharedTrailQuadIndexSheet;
  }

  /**
   * What it does:
   * Releases the shared trail-quad index-sheet singleton and clears its global
   * ownership lane.
   */
  void DestroySharedTrailQuadIndexSheet() noexcept
  {
    if (sSharedTrailQuadIndexSheet == nullptr) {
      return;
    }

    delete sSharedTrailQuadIndexSheet;
    sSharedTrailQuadIndexSheet = nullptr;
  }

  /**
   * Address: 0x004986F0 (FUN_004986F0, func_CreateIndexSheet1)
   *
   * What it does:
   * Rebuilds the shared trail-quad index sheet and populates one 4-vertex /
   * 6-index quad pattern for `0x4000` quads.
   */
  int RebuildSharedTrailQuadIndexSheet()
  {
    CD3DDevice* const device = D3D_GetDevice();
    ID3DDeviceResources* const resources = device->GetResources();

    CD3DIndexSheet* const newSheet = resources->CreateIndexSheet(false, kSharedTrailIndexSheetSize);
    if (newSheet != sSharedTrailQuadIndexSheet && sSharedTrailQuadIndexSheet != nullptr) {
      delete sSharedTrailQuadIndexSheet;
    }
    sSharedTrailQuadIndexSheet = newSheet;

    if (sSharedTrailQuadIndexSheet == nullptr) {
      return 0;
    }

    const std::uint32_t indexCount = sSharedTrailQuadIndexSheet->GetSize();
    std::int16_t* const mappedIndices = sSharedTrailQuadIndexSheet->Lock(0U, indexCount, false, false);
    if (mappedIndices == nullptr) {
      return 0;
    }

    for (std::uint32_t quadIndex = 0U; quadIndex < kSharedTrailQuadCount; ++quadIndex) {
      const std::uint16_t baseVertex = static_cast<std::uint16_t>(quadIndex * 4U);
      const std::uint32_t indexBase = quadIndex * kIndicesPerTrailQuad;

      mappedIndices[indexBase + 0U] = static_cast<std::int16_t>(baseVertex + 0U);
      mappedIndices[indexBase + 1U] = static_cast<std::int16_t>(baseVertex + 1U);
      mappedIndices[indexBase + 2U] = static_cast<std::int16_t>(baseVertex + 2U);
      mappedIndices[indexBase + 3U] = static_cast<std::int16_t>(baseVertex + 0U);
      mappedIndices[indexBase + 4U] = static_cast<std::int16_t>(baseVertex + 2U);
      mappedIndices[indexBase + 5U] = static_cast<std::int16_t>(baseVertex + 3U);
    }

    sSharedTrailQuadIndexSheet->Unlock();
    return 1;
  }

  /**
   * Address: 0x004925E0 (FUN_004925E0)
   * Mangled: ??0CWorldParticles@Moho@@QAE@XZ
   *
   * What it does:
   * Initializes global world-particle pool/map sentinel lanes and key scratch
   * storage.
   */
  CWorldParticles::CWorldParticles()
  {
    // mParticleBuffers, mAvailableParticleBuffers and mTrailSegmentPool are
    // built by their member constructors: the binary buys the two list heads
    // through 0x00497D00 (`_Buy_head`) and the set head through 0x0049C620
    // before this body runs.
    auto& runtime = reinterpret_cast<CWorldParticlesRuntimeView&>(*this);

    InitializeParticleBucketTree(runtime.particleBuckets);
    InitializeParticleBucketTree(runtime.refractingParticleBuckets);
    InitializeTrailBucketTree(runtime.trailBuckets);

    new (&runtime.particleBucketLookupKey) ParticleBucketKeyRuntime{};
    runtime.cachedParticleBucket = nullptr;
    new (&runtime.trailBucketLookupKey) TrailBucketKeyRuntime{};
    runtime.cachedTrailBucket = nullptr;

    mBeatsSincePause = 0;
    mInstantiated = false;
    mBeams.mVertexSheet = nullptr;
    mBeams.mBuckets.clear();
  }

  /**
   * Address: 0x00492780 (FUN_00492780)
   * Mangled: ??1CWorldParticles@Moho@@QAE@XZ
   *
   * What it does:
   * Tears down the singleton world-particles state, including beam buckets
   * and pooled render storage.
   */
  CWorldParticles::~CWorldParticles()
  {
    auto& runtime = reinterpret_cast<CWorldParticlesRuntimeView&>(*this);

    DestroyWorldParticlesSingleton();

    ShutdownBeamBuckets();
    ResetTrailBucketKeyResources(runtime.trailBucketLookupKey);
    ResetParticleBucketKeyResources(runtime.particleBucketLookupKey);

    ReleaseTrailBucketTreeStorage(runtime.trailBuckets);
    ReleaseParticleBucketTreeStorage(runtime.refractingParticleBuckets);
    ReleaseParticleBucketTreeStorage(runtime.particleBuckets);
    // mTrailSegmentPool (`erase(begin(), end())` 0x0049A6C0 + head free),
    // mAvailableParticleBuffers and mParticleBuffers (`_Tidy` 0x00495F30 +
    // head free) are destroyed by their member destructors after this body.
  }

  ParticleBuffer* CWorldParticles::AcquireParticleBuffer()
  {
    if (mAvailableParticleBuffers.empty()) {
      return nullptr;
    }

    ParticleBuffer* const particleBuffer = mAvailableParticleBuffers.front();
    mAvailableParticleBuffers.pop_front();
    return particleBuffer;
  }

  /**
   * Address: 0x00492CA0 (FUN_00492CA0, sub_492CA0)
   *
   * What it does:
   * Returns one particle buffer to the available pool
   * (`mAvailableParticleBuffers.push_back`: `_Buynode` 0x0049A570 and
   * `_Incsize` 0x0049A5B0 on Vector.h).
   */
  void CWorldParticles::ReleaseParticleBuffer(ParticleBuffer* const particleBuffer)
  {
    mAvailableParticleBuffers.push_back(particleBuffer);
  }

  /**
   * Address: 0x00492CE0 (FUN_00492CE0, sub_492CE0)
   *
   * What it does:
   * Takes the lowest-addressed pooled trail-segment buffer out of
   * `mTrailSegmentPool`; `nullptr` when the pool is empty.
   */
  TrailSegmentBufferRuntime* CWorldParticles::AcquireTrailSegmentBuffer()
  {
    if (mTrailSegmentPool.empty()) {
      return nullptr;
    }

    // The binary takes the leftmost node, keeps its buffer and erases it,
    // discarding the successor the erase hands back.
    const auto first = mTrailSegmentPool.begin();
    TrailSegmentBufferRuntime* const segmentBuffer = *first;
    (void)mTrailSegmentPool.erase(first);
    return segmentBuffer;
  }

  /**
   * Address: 0x00492D10 (FUN_00492D10, sub_492D10)
   *
   * What it does:
   * Returns one trail-segment buffer to `mTrailSegmentPool`
   * (`set::insert`, 0x00496000 on RbTree.h).
   */
  void CWorldParticles::ReleaseTrailSegmentBuffer(TrailSegmentBufferRuntime* const segmentBuffer)
  {
    (void)mTrailSegmentPool.insert(segmentBuffer);
  }

  /**
   * Address: 0x00492D30 (FUN_00492D30)
   * Mangled: ?AddBeam@CWorldParticles@Moho@@UAEXPBUSWorldBeam@2@@Z
   *
   * What it does:
   * Inserts one beam into the persistent beam render-bucket map.
   */
  void CWorldParticles::AddBeam(const SWorldBeam& beam)
  {
    AddBeamToTextureBuckets(mBeams.mBuckets, beam);
  }

  /**
   * Address: 0x00494930 (FUN_00494930, Moho::CWorldParticles::AddWorldParticle)
   *
   * What it does:
   * Resolves/creates one world-particle render bucket and appends one world
   * particle payload into its pending vector.
   */
  void CWorldParticles::AddWorldParticle(
    const SWorldParticle& particle,
    ParticleRenderBucketRuntime** const bucketCacheSlot
  )
  {
    if (mBeatsSincePause > 5) {
      return;
    }

    Init();
    if (bucketCacheSlot != nullptr && *bucketCacheSlot != nullptr) {
      (*bucketCacheSlot)->pendingParticles.push_back(particle);
      return;
    }

    auto& runtime = reinterpret_cast<CWorldParticlesRuntimeView&>(*this);
    ParticleBucketKeyRuntime lookupKey{};
    (void)InitializeParticleBucketKeyFromWorldParticle(&lookupKey, particle);

    if (static_cast<std::int32_t>(particle.mBlendMode) == 5) {
      ParticleBucketTreeNodeRuntime* candidateNode = nullptr;
      (void)ResolveParticleBucketCandidateOrHead(
        lookupKey,
        &candidateNode,
        runtime.refractingParticleBuckets
      );

      if (candidateNode == runtime.refractingParticleBuckets.head) {
        // Must be constructed, not just allocated: the bucket owns two
        // shared_ptr texture handles, an msvc8::string and two vectors, and
        // InitializeParticleRenderBucketFromWorldParticle's first act is to
        // `reset()` those handles. On raw `operator new` storage that resets a
        // garbage control block. `new T()` emits the same
        // `operator new(sizeof(T))` the binary calls, plus the construction the
        // binary's own constructor emission performs.
        auto* const newBucket = new ParticleRenderBucketRuntime();
        (void)InitializeParticleRenderBucketFromWorldParticle(*newBucket, particle, this);

        PointerByteFlagPairRuntime insertResult{};
        (void)InsertOwnedParticleBucketByKey(
          runtime.refractingParticleBuckets,
          &insertResult,
          lookupKey,
          newBucket
        );
        candidateNode = reinterpret_cast<ParticleBucketTreeNodeRuntime*>(insertResult.pointer);
      }

      AsParticleBucketEntryNode(candidateNode)->bucket->pendingParticles.push_back(particle);
      ResetParticleBucketKeyResources(lookupKey);
      return;
    }

    if (runtime.cachedParticleBucket != nullptr &&
        AreParticleBucketKeysEquivalent(runtime.particleBucketLookupKey, lookupKey)) {
      runtime.cachedParticleBucket->pendingParticles.push_back(particle);
      ResetParticleBucketKeyResources(lookupKey);
      return;
    }

    ParticleBucketTreeNodeRuntime* candidateNode = nullptr;
    (void)ResolveParticleBucketCandidateOrHead(
      lookupKey,
      &candidateNode,
      runtime.particleBuckets
    );

    if (candidateNode == runtime.particleBuckets.head) {
      // Constructed, not merely allocated -- see the refracting-bucket site
      // above for why raw storage faults inside the initializer's `reset()`.
      auto* const newBucket = new ParticleRenderBucketRuntime();
      (void)InitializeParticleRenderBucketFromWorldParticle(*newBucket, particle, this);

      PointerByteFlagPairRuntime insertResult{};
      (void)InsertOwnedParticleBucketByKey(
        runtime.particleBuckets,
        &insertResult,
        lookupKey,
        newBucket
      );
      candidateNode = reinterpret_cast<ParticleBucketTreeNodeRuntime*>(insertResult.pointer);
    }

    ParticleRenderBucketRuntime* const bucket = AsParticleBucketEntryNode(candidateNode)->bucket;
    bucket->pendingParticles.push_back(particle);
    (void)CopyParticleBucketKey(&runtime.particleBucketLookupKey, &lookupKey);
    runtime.cachedParticleBucket = bucket;

    if (bucketCacheSlot != nullptr) {
      *bucketCacheSlot = bucket;
    }

    ResetParticleBucketKeyResources(lookupKey);
  }

  /**
   * Address: 0x00494C20 (FUN_00494C20, Moho::CWorldParticles::AddTrail)
   *
   * What it does:
   * Resolves/creates one trail render bucket and appends one trail payload into
   * its pending vector.
   */
  void CWorldParticles::AddTrail(
    const TrailRuntimeView& trail,
    TrailRenderBucketRuntime** const bucketCacheSlot
  )
  {
    if (mBeatsSincePause > 5) {
      return;
    }

    Init();
    if (bucketCacheSlot != nullptr && *bucketCacheSlot != nullptr) {
      (*bucketCacheSlot)->pendingTrails.push_back(trail);
      return;
    }

    auto& runtime = reinterpret_cast<CWorldParticlesRuntimeView&>(*this);
    TrailBucketKeyRuntime lookupKey{};
    (void)InitializeTrailBucketKeyFromTrail(&lookupKey, trail);

    if (runtime.cachedTrailBucket != nullptr &&
        AreTrailBucketKeysEquivalent(runtime.trailBucketLookupKey, lookupKey)) {
      runtime.cachedTrailBucket->pendingTrails.push_back(trail);
      ResetTrailBucketKeyResources(lookupKey);
      return;
    }

    TrailBucketTreeNodeRuntime* candidateNode = nullptr;
    (void)ResolveTrailBucketCandidateOrHead(
      lookupKey,
      &candidateNode,
      runtime.trailBuckets
    );

    if (candidateNode == runtime.trailBuckets.head) {
      // Constructed, not merely allocated -- same defect as the particle
      // buckets above. InitializeTrailRenderBucketFromTrail resets two
      // shared_ptr texture handles and assigns into `tag`, and on raw
      // `operator new` storage that releases a garbage control block and frees
      // a garbage string buffer.
      auto* const newBucket = new TrailRenderBucketRuntime();
      (void)InitializeTrailRenderBucketFromTrail(*newBucket, trail, this);

      PointerByteFlagPairRuntime insertResult{};
      (void)InsertOwnedTrailBucketByKey(
        runtime.trailBuckets,
        &insertResult,
        lookupKey,
        newBucket
      );
      candidateNode = reinterpret_cast<TrailBucketTreeNodeRuntime*>(insertResult.pointer);
    }

    TrailRenderBucketRuntime* const bucket = AsTrailBucketEntryNode(candidateNode)->bucket;
    bucket->pendingTrails.push_back(trail);
    (void)CopyTrailBucketKey(&runtime.trailBucketLookupKey, &lookupKey);
    runtime.cachedTrailBucket = bucket;

    if (bucketCacheSlot != nullptr) {
      *bucketCacheSlot = bucket;
    }

    ResetTrailBucketKeyResources(lookupKey);
  }

  /**
   * Address: 0x00492D50 (FUN_00492D50)
   * Mangled: ?AddParticles@CWorldParticles@Moho@@UAEXPBUSParticleBuffer@2@@Z
   *
   * What it does:
   * Dispatches one submit-buffer payload into world-particle, trail, and beam
   * append paths in original order.
   */
  void CWorldParticles::AddParticles(const SParticleBuffer& batch)
  {
    for (const SWorldParticle& particle : batch.mParticles) {
      AddWorldParticle(particle, nullptr);
    }

    for (const TrailRuntimeView& trail : batch.mTrails) {
      AddTrail(trail, nullptr);
    }

    for (const SWorldBeam& beam : batch.mBeams) {
      AddBeam(beam);
    }
  }

  /**
   * Address: 0x00492E30 (FUN_00492E30)
   * Mangled: ?AdvancementBeat@CWorldParticles@Moho@@UAEXXZ
   *
   * What it does:
   * Advances beat counter and clears transient beam bucket contents.
   */
  void CWorldParticles::AdvancementBeat()
  {
    ++mBeatsSincePause;
    mBeams.mBuckets.clear();
  }

  /**
   * Address: 0x00495080 (FUN_00495080)
   *
   * What it does:
   * Sets particle camera shader variables, optionally renders beams, then
   * renders particle buckets on the correct side of the water-surface gate.
   */
  char CWorldParticles::RenderEffects(
    GeomCamera3* const camera,
    const char renderWaterSurface,
    const char suppressTLight,
    const int tick,
    const float frameAlpha
  )
  {
    Init();
    mBeatsSincePause = 0;

    CD3DDevice* const device = D3D_GetDevice();
    device->SelectFxFile("particle");

    BindParticleCameraShaderState(camera, tick, frameAlpha);

    if (renderWaterSurface == 0) {
      device->SetColorWriteState(true, true);

      (void)DrawBeamParticle(mBeams, frameAlpha, suppressTLight != 0);

      device->SetColorWriteState(true, false);
    }

    auto& runtime = reinterpret_cast<CWorldParticlesRuntimeView&>(*this);
    char renderResult = 0;
    const auto renderAboveSurface = renderWaterSurface == 0;
    const float waterSurface = efx_ParticleWaterSurface;

    auto* const particleHead = runtime.particleBuckets.head;
    if (particleHead != nullptr) {
      auto* node = reinterpret_cast<ParticleBucketTreeEntryNodeRuntime*>(particleHead->left);
      while (node != nullptr && node != reinterpret_cast<ParticleBucketTreeEntryNodeRuntime*>(particleHead)) {
        if (renderAboveSurface) {
          if (node->key.sortScalar >= waterSurface && node->bucket != nullptr) {
            (void)moho::RenderParticleBucket(*node->bucket, static_cast<float>(tick), suppressTLight != 0);
          }
        } else {
          if (node->key.sortScalar > waterSurface) {
            break;
          }
          if (node->bucket != nullptr) {
            (void)moho::RenderParticleBucket(*node->bucket, static_cast<float>(tick), suppressTLight != 0);
          }
        }

        node = GetNextParticleBucketTreeNode(node);
      }
    }

    auto* const trailHead = runtime.trailBuckets.head;
    if (trailHead != nullptr) {
      auto* node = reinterpret_cast<TrailBucketTreeEntryNodeRuntime*>(trailHead->left);
      while (node != nullptr && node != reinterpret_cast<TrailBucketTreeEntryNodeRuntime*>(trailHead)) {
        if (renderAboveSurface) {
          if (node->key.sortScalar >= waterSurface && node->bucket != nullptr) {
            renderResult = static_cast<char>(
              moho::RenderTrailBucket(*node->bucket, static_cast<float>(tick), suppressTLight != 0)
            );
          }
        } else {
          if (node->key.sortScalar > waterSurface) {
            break;
          }
          if (node->bucket != nullptr) {
            renderResult = static_cast<char>(
              moho::RenderTrailBucket(*node->bucket, static_cast<float>(tick), suppressTLight != 0)
            );
          }
        }

        node = GetNextTrailBucketTreeNode(node);
      }
    }

    return renderResult;
  }

  /**
   * Address: 0x004952A0 (FUN_004952A0)
   *
   * What it does:
   * Renders the refracting particle-bucket lane with the particle background
   * texture bound and camera shader state initialized.
   */
  void CWorldParticles::RenderRefractingEffects(
    GeomCamera3* const camera,
    const int tick,
    const float frameDelta,
    const boost::shared_ptr<ID3DRenderTarget>& backgroundTexture
  )
  {
    Init();

    CD3DDevice* const device = D3D_GetDevice();
    device->SelectFxFile("particle");

    BindParticleCameraShaderState(camera, tick, frameDelta);
    if (shaderVarParticleBackgroundTexture.Exists()) {
      shaderVarParticleBackgroundTexture.SetRenderTargetTexture(backgroundTexture);
    }

    auto& runtime = reinterpret_cast<CWorldParticlesRuntimeView&>(*this);
    auto* const head = runtime.refractingParticleBuckets.head;
    if (head == nullptr) {
      return;
    }

    auto* node = reinterpret_cast<ParticleBucketTreeEntryNodeRuntime*>(head->left);
    while (node != nullptr && node != reinterpret_cast<ParticleBucketTreeEntryNodeRuntime*>(head)) {
      if (node->bucket != nullptr) {
        (void)moho::RenderParticleBucket(*node->bucket, static_cast<float>(tick), false);
      }

      node = GetNextParticleBucketTreeNode(node);
    }
  }

  /**
   * Address: 0x004928A0 (FUN_004928A0)
   *
   * What it does:
   * Lazily allocates particle and trail pooled buffers used by world-particle
   * render bucket upload paths.
   */
  void CWorldParticles::Init()
  {
    if (mInstantiated) {
      return;
    }

    mInstantiated = true;

    CD3DDevice* const device = D3D_GetDevice();
    ID3DDeviceResources* const resources = device->GetResources();
    CD3DVertexFormat* const trailVertexFormat = resources->GetVertexFormat(kTrailVertexFormatToken);

    for (int bufferIndex = 0; bufferIndex < kPooledParticleBufferCount; ++bufferIndex) {
      auto* const particleBuffer = new ParticleBuffer();
      particleBuffer->Shutdown();
      particleBuffer->mMaxParticles = kParticleBufferCapacity;

      mAvailableParticleBuffers.push_back(particleBuffer);
      mParticleBuffers.push_back(particleBuffer);
    }

    for (int bufferIndex = 0; bufferIndex < kPooledTrailSegmentBufferCount; ++bufferIndex) {
      auto* const segmentBuffer = static_cast<TrailSegmentBufferRuntime*>(
        ::operator new(sizeof(TrailSegmentBufferRuntime))
      );
      std::memset(segmentBuffer, 0, sizeof(TrailSegmentBufferRuntime));

      segmentBuffer->maxSegments = kTrailSegmentCapacity;
      segmentBuffer->vertexSheet = resources->NewVertexSheet(
        kTrailVertexSheetUsageToken,
        kTrailVertexSheetFrequencyToken,
        trailVertexFormat
      );

      if (sSharedTrailQuadIndexSheet == nullptr) {
        (void)RebuildSharedTrailQuadIndexSheet();
      }

      (void)mTrailSegmentPool.insert(segmentBuffer);
    }
  }

  /**
   * Address: 0x00493090 (FUN_00493090, sub_493090)
   *
   * What it does:
   * Releases beam-bucket map resources and destroys the retained beam vertex
   * sheet lane.
   */
  void CWorldParticles::ShutdownBeamBuckets()
  {
    DestroyBeamTextureBucketMap(mBeams.mBuckets);

    if (mBeams.mVertexSheet != nullptr) {
      delete mBeams.mVertexSheet;
      mBeams.mVertexSheet = nullptr;
    }
  }

  /**
   * Address: 0x00494E10 (FUN_00494E10)
   *
   * What it does:
   * Clears the runtime particle, refracting-particle, and trail bucket lanes
   * owned by one world-particles instance.
   */
  void ResetWorldParticlesRuntimeState(CWorldParticles& worldParticles)
  {
    auto& runtime = reinterpret_cast<CWorldParticlesRuntimeView&>(worldParticles);

    if (auto* const particleHead = AsParticleBucketEntryNode(runtime.particleBuckets.head); particleHead != nullptr) {
      (void)DestroyParticleBucketPayloadRange(particleHead->left, particleHead);
      DestroyParticleBucketKeyNodeSubtreeOnly(particleHead->parent);
      particleHead->parent = particleHead;
      particleHead->left = particleHead;
      particleHead->right = particleHead;
      runtime.particleBuckets.size = 0U;
    }

    if (auto* const refractingHead = AsParticleBucketEntryNode(runtime.refractingParticleBuckets.head);
        refractingHead != nullptr) {
      (void)DestroyParticleBucketPayloadRange(refractingHead->left, refractingHead);
      DestroyParticleBucketKeyNodeSubtreeOnly(refractingHead->parent);
      refractingHead->parent = refractingHead;
      refractingHead->left = refractingHead;
      refractingHead->right = refractingHead;
      runtime.refractingParticleBuckets.size = 0U;
    }

    if (auto* const trailHead = AsTrailBucketEntryNode(runtime.trailBuckets.head); trailHead != nullptr) {
      (void)DestroyTrailBucketPayloadRange(trailHead->left, trailHead);
      DestroyTrailBucketKeyNodeSubtreeOnly(trailHead->parent);
      trailHead->parent = trailHead;
      trailHead->left = trailHead;
      trailHead->right = trailHead;
      runtime.trailBuckets.size = 0U;
    }

    runtime.cachedParticleBucket = nullptr;
    runtime.cachedTrailBucket = nullptr;
    ResetParticleBucketKeyResources(runtime.particleBucketLookupKey);
    ResetTrailBucketKeyResources(runtime.trailBucketLookupKey);
    worldParticles.mBeams.mBuckets.clear();
  }

  /**
   * Address: 0x00492AC0 (FUN_00492AC0)
   *
   * What it does:
   * Destroys the world-particles singleton runtime storage and resets the
   * pooled bucket/list state.
   */
  void DestroyWorldParticlesSingleton()
  {
    for (ParticleBuffer* const particleBuffer : sWorldParticles.mParticleBuffers) {
      delete particleBuffer;
    }
    sWorldParticles.mParticleBuffers.clear();
    sWorldParticles.mAvailableParticleBuffers.clear();

    ReleaseTrailSegmentPoolBuffers(sWorldParticles.mTrailSegmentPool);
    sWorldParticles.mTrailSegmentPool.clear();

    sWorldParticles.mBeatsSincePause = 0;
    sWorldParticles.mInstantiated = false;
  }

  /**
   * Address: 0x00492E70 (FUN_00492E70)
   *
   * What it does:
   * Returns the global world-particles singleton after restoring the base
   * interface lane used by legacy exit paths.
   */
  [[nodiscard]] CWorldParticles* GetLegacyWorldParticlesSingleton() noexcept
  {
    return &sWorldParticles;
  }
} // namespace moho
