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

    // The three bucket maps live inside this object's raw storage, reached
    // through the runtime view, so their constructors (which buy the header
    // sentinel) have to run explicitly -- the binary inlines exactly that.
    new (&runtime.particleBuckets) ParticleBucketMap();
    new (&runtime.refractingParticleBuckets) ParticleBucketMap();
    new (&runtime.trailBuckets) TrailBucketMap();

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

    runtime.trailBuckets.~TrailBucketMap();
    runtime.refractingParticleBuckets.~ParticleBucketMap();
    runtime.particleBuckets.~ParticleBucketMap();
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
      auto bucketEntry = runtime.refractingParticleBuckets.find(lookupKey);
      if (bucketEntry == runtime.refractingParticleBuckets.end()) {
        // Must be constructed, not just allocated: the bucket owns two
        // shared_ptr texture handles, an msvc8::string and two vectors, and
        // InitializeParticleRenderBucketFromWorldParticle's first act is to
        // `reset()` those handles.
        auto* const newBucket = new ParticleRenderBucketRuntime();
        (void)InitializeParticleRenderBucketFromWorldParticle(*newBucket, particle, this);
        bucketEntry = runtime.refractingParticleBuckets.insert({lookupKey, newBucket}).first;
      }

      bucketEntry->second->pendingParticles.push_back(particle);
      ResetParticleBucketKeyResources(lookupKey);
      return;
    }

    if (runtime.cachedParticleBucket != nullptr &&
        AreParticleBucketKeysEquivalent(runtime.particleBucketLookupKey, lookupKey)) {
      runtime.cachedParticleBucket->pendingParticles.push_back(particle);
      ResetParticleBucketKeyResources(lookupKey);
      return;
    }

    auto bucketEntry = runtime.particleBuckets.find(lookupKey);
    if (bucketEntry == runtime.particleBuckets.end()) {
      auto* const newBucket = new ParticleRenderBucketRuntime();
      (void)InitializeParticleRenderBucketFromWorldParticle(*newBucket, particle, this);
      bucketEntry = runtime.particleBuckets.insert({lookupKey, newBucket}).first;
    }

    ParticleRenderBucketRuntime* const bucket = bucketEntry->second;
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

    auto bucketEntry = runtime.trailBuckets.find(lookupKey);
    if (bucketEntry == runtime.trailBuckets.end()) {
      auto* const newBucket = new TrailRenderBucketRuntime();
      (void)InitializeTrailRenderBucketFromTrail(*newBucket, trail, this);
      bucketEntry = runtime.trailBuckets.insert({lookupKey, newBucket}).first;
    }

    TrailRenderBucketRuntime* const bucket = bucketEntry->second;
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

    for (const auto& [bucketKey, bucket] : runtime.particleBuckets) {
      if (renderAboveSurface) {
        if (bucketKey.sortScalar >= waterSurface && bucket != nullptr) {
          (void)moho::RenderParticleBucket(*bucket, static_cast<float>(tick), suppressTLight != 0);
        }
      } else {
        if (bucketKey.sortScalar > waterSurface) {
          break;
        }
        if (bucket != nullptr) {
          (void)moho::RenderParticleBucket(*bucket, static_cast<float>(tick), suppressTLight != 0);
        }
      }
    }

    for (const auto& [bucketKey, bucket] : runtime.trailBuckets) {
      if (renderAboveSurface) {
        if (bucketKey.sortScalar >= waterSurface && bucket != nullptr) {
          renderResult = static_cast<char>(
            moho::RenderTrailBucket(*bucket, static_cast<float>(tick), suppressTLight != 0)
          );
        }
      } else {
        if (bucketKey.sortScalar > waterSurface) {
          break;
        }
        if (bucket != nullptr) {
          renderResult = static_cast<char>(
            moho::RenderTrailBucket(*bucket, static_cast<float>(tick), suppressTLight != 0)
          );
        }
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
    for (const auto& [bucketKey, bucket] : runtime.refractingParticleBuckets) {
      (void)bucketKey;
      if (bucket != nullptr) {
        (void)moho::RenderParticleBucket(*bucket, static_cast<float>(tick), false);
      }
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
    // The shipped body runs the map's destructor here rather than `clear()`:
    // the header node is freed and `head_`/`size_` left null, so the buckets
    // stay dead until the next `BeamBucketContainerRuntime` is constructed.
    mBeams.mBuckets.~BeamTextureBucketMapRuntime();

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

    // Each entry owns its bucket, so the payload goes before the node.
    for (const auto& [bucketKey, bucket] : runtime.particleBuckets) {
      (void)bucketKey;
      DestroyParticleRenderBucket(*bucket);
      ::operator delete(bucket);
    }
    runtime.particleBuckets.clear();

    for (const auto& [bucketKey, bucket] : runtime.refractingParticleBuckets) {
      (void)bucketKey;
      DestroyParticleRenderBucket(*bucket);
      ::operator delete(bucket);
    }
    runtime.refractingParticleBuckets.clear();

    for (const auto& [bucketKey, bucket] : runtime.trailBuckets) {
      (void)bucketKey;
      DestroyTrailRenderBucket(*bucket);
      ::operator delete(bucket);
    }
    runtime.trailBuckets.clear();

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
