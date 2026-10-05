#include "moho/particles/CWorldParticles.h"

#include <cstring>
#include <cstdlib>
#include <cstdio>
#include <limits>
#include <new>
#include <stdexcept>
#include <string>
#include <utility>

#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/BoostWrappers.h"
#include "legacy/containers/AutoPtr.h"
#include "gpg/gal/EffectVariable.hpp"
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
  // The eighteen particle shader-vars below are defined ahead of the
  // bootstrap object further down in this file: C++ constructs a translation
  // unit's namespace-scope objects in definition order, so each one is
  // default-constructed before its registrar runs `RegisterShaderVar` on it.
  // No other translation unit reads them during static initialization.

  /**
   * Address: 0x00BF00A0 (FUN_00BF00A0, dynamic atexit destructor for `shaderVarParticleViewMatrix`)
   *
   * What it does:
   * The particle `ViewMatrix` shader-var (binary global 0x010A8440).
   */
  ShaderVar shaderVarParticleViewMatrix;

  /**
   * Address: 0x00BF00C0 (FUN_00BF00C0, dynamic atexit destructor for `shaderVarParticleProjection`)
   *
   * What it does:
   * The particle `Projection` shader-var (binary global 0x010A82D8).
   */
  ShaderVar shaderVarParticleProjection;

  /**
   * Address: 0x00BF0090 (FUN_00BF0090, dynamic atexit destructor for `shaderVarParticleWorldToProjection`)
   *
   * What it does:
   * The particle `WorldToProjection` shader-var (binary global 0x010A83F8).
   */
  ShaderVar shaderVarParticleWorldToProjection;

  /**
   * Address: 0x00BF00B0 (FUN_00BF00B0, dynamic atexit destructor for `shaderVarParticleInverseViewMatrix`)
   *
   * What it does:
   * The particle `InverseViewMatrix` shader-var (binary global 0x010A8638).
   */
  ShaderVar shaderVarParticleInverseViewMatrix;

  /**
   * Address: 0x00BF00D0 (FUN_00BF00D0, dynamic atexit destructor for `shaderVarParticleParticleSystemPosition`)
   *
   * What it does:
   * The particle `ParticleSystemPosition` shader-var (binary global 0x010A8368).
   */
  ShaderVar shaderVarParticleParticleSystemPosition;

  /**
   * Address: 0x00BF00E0 (FUN_00BF00E0, dynamic atexit destructor for `shaderVarParticleTime`)
   *
   * What it does:
   * The particle `time` shader-var (binary global 0x010A8560).
   */
  ShaderVar shaderVarParticleTime;

  /**
   * Address: 0x00BF00F0 (FUN_00BF00F0, dynamic atexit destructor for `shaderVarParticleParticleSystemShape`)
   *
   * What it does:
   * The particle `ParticleSystemShape` shader-var (binary global 0x010A84D0).
   */
  ShaderVar shaderVarParticleParticleSystemShape;

  /**
   * Address: 0x00BF0100 (FUN_00BF0100, dynamic atexit destructor for `shaderVarParticleParticleSpread`)
   *
   * What it does:
   * The particle `ParticleSpread` shader-var (binary global 0x010A8290).
   */
  ShaderVar shaderVarParticleParticleSpread;

  /**
   * Address: 0x00BF0110 (FUN_00BF0110, dynamic atexit destructor for `shaderVarParticleParticleSpeed`)
   *
   * What it does:
   * The particle `ParticleSpeed` shader-var (binary global 0x010A85A8).
   */
  ShaderVar shaderVarParticleParticleSpeed;

  /**
   * Address: 0x00BF0120 (FUN_00BF0120, dynamic atexit destructor for `shaderVarParticleParticleSystemHeight`)
   *
   * What it does:
   * The particle `ParticleSystemHeight` shader-var (binary global 0x010A8518).
   */
  ShaderVar shaderVarParticleParticleSystemHeight;

  /**
   * Address: 0x00BF0130 (FUN_00BF0130, dynamic atexit destructor for `shaderVarParticleParticleSize`)
   *
   * What it does:
   * The particle `ParticleSize` shader-var (binary global 0x010A8488).
   */
  ShaderVar shaderVarParticleParticleSize;

  /**
   * Address: 0x00BF0140 (FUN_00BF0140, dynamic atexit destructor for `shaderVarParticleDragEnabled`)
   *
   * What it does:
   * The particle `DragEnabled` shader-var (binary global 0x010A83B0).
   */
  ShaderVar shaderVarParticleDragEnabled;

  /**
   * Address: 0x00BF0150 (FUN_00BF0150, dynamic atexit destructor for `shaderVarParticleDragCoeff`)
   *
   * What it does:
   * The particle `DragCoeff` shader-var (binary global 0x010A86C8).
   */
  ShaderVar shaderVarParticleDragCoeff;

  /**
   * Address: 0x00BF0160 (FUN_00BF0160, dynamic atexit destructor for `shaderVarParticleInvDragCoeff`)
   *
   * What it does:
   * The particle `invDragCoeff` shader-var (binary global 0x010A8320).
   */
  ShaderVar shaderVarParticleInvDragCoeff;

  /**
   * Address: 0x00BF0170 (FUN_00BF0170, dynamic atexit destructor for `shaderVarParticleInvDragCoeffSq`)
   *
   * What it does:
   * The particle `invDragCoeffSq` shader-var (binary global 0x010A8718).
   */
  ShaderVar shaderVarParticleInvDragCoeffSq;

  /**
   * Address: 0x00BF0180 (FUN_00BF0180, dynamic atexit destructor for `shaderVarParticleBackgroundTexture`)
   *
   * What it does:
   * The particle `BackgroundTexture` shader-var (binary global 0x010A85F0).
   */
  ShaderVar shaderVarParticleBackgroundTexture;

  /**
   * Address: 0x00BF0190 (FUN_00BF0190, dynamic atexit destructor for `shaderVarParticleParticleTexture0`)
   *
   * What it does:
   * The particle `ParticleTexture0` shader-var (binary global 0x010A8680).
   */
  ShaderVar shaderVarParticleParticleTexture0;

  /**
   * Address: 0x00BF01A0 (FUN_00BF01A0, dynamic atexit destructor for `shaderVarParticleParticleTexture1`)
   *
   * What it does:
   * The particle `ParticleTexture1` shader-var (binary global 0x010A8760).
   */
  ShaderVar shaderVarParticleParticleTexture1;

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

  /**
   * Address: 0x00BC57F0 (FUN_00BC57F0, dynamic initializer for `sSharedTrailQuadIndexSheet`)
   * Address: 0x00BF01B0 (FUN_00BF01B0, dynamic atexit destructor for `sSharedTrailQuadIndexSheet`)
   *
   * What it does:
   * Owns the shared trail-quad index sheet (binary global 0x010A828C).
   */
  msvc8::auto_ptr<moho::ID3DIndexSheet> sSharedTrailQuadIndexSheet;

  /**
   * Address: 0x00BC5570 (FUN_00BC5570, dynamic initializer for `gTConVar_efx_ParticleWaterSurface`)
   * Address: 0x00BF0060 (FUN_00BF0060, dynamic atexit destructor for `gTConVar_efx_ParticleWaterSurface`)
   */
  moho::TConVar<float> gTConVar_efx_ParticleWaterSurface(
    "efx_ParticleWaterSurface",
    "Sort order at which particles start rendering under water",
    &moho::efx_ParticleWaterSurface
  );

  /**
   * Address: 0x00BC55B0 (FUN_00BC55B0, register_ShaderVarParticleWorldToProjection)
   */
  void register_ShaderVarParticleWorldToProjection()
  {
    moho::RegisterShaderVar("WorldToProjection", &moho::shaderVarParticleWorldToProjection, "particle");
  }

  /**
   * Address: 0x00BC55D0 (FUN_00BC55D0, register_ShaderVarParticleViewMatrix)
   */
  void register_ShaderVarParticleViewMatrix()
  {
    moho::RegisterShaderVar("ViewMatrix", &moho::shaderVarParticleViewMatrix, "particle");
  }

  /**
   * Address: 0x00BC55F0 (FUN_00BC55F0, register_ShaderVarParticleInverseViewMatrix)
   */
  void register_ShaderVarParticleInverseViewMatrix()
  {
    moho::RegisterShaderVar("InverseViewMatrix", &moho::shaderVarParticleInverseViewMatrix, "particle");
  }

  /**
   * Address: 0x00BC5610 (FUN_00BC5610, register_ShaderVarParticleProjection)
   */
  void register_ShaderVarParticleProjection()
  {
    moho::RegisterShaderVar("Projection", &moho::shaderVarParticleProjection, "particle");
  }

  /**
   * Address: 0x00BC5630 (FUN_00BC5630, register_ShaderVarParticleParticleSystemPosition)
   */
  void register_ShaderVarParticleParticleSystemPosition()
  {
    moho::RegisterShaderVar("ParticleSystemPosition", &moho::shaderVarParticleParticleSystemPosition, "particle");
  }

  /**
   * Address: 0x00BC5650 (FUN_00BC5650, register_ShaderVarParticleTime)
   */
  void register_ShaderVarParticleTime()
  {
    moho::RegisterShaderVar("time", &moho::shaderVarParticleTime, "particle");
  }

  /**
   * Address: 0x00BC5670 (FUN_00BC5670, register_ShaderVarParticleParticleSystemShape)
   */
  void register_ShaderVarParticleParticleSystemShape()
  {
    moho::RegisterShaderVar("ParticleSystemShape", &moho::shaderVarParticleParticleSystemShape, "particle");
  }

  /**
   * Address: 0x00BC5690 (FUN_00BC5690, register_ShaderVarParticleParticleSpread)
   */
  void register_ShaderVarParticleParticleSpread()
  {
    moho::RegisterShaderVar("ParticleSpread", &moho::shaderVarParticleParticleSpread, "particle");
  }

  /**
   * Address: 0x00BC56B0 (FUN_00BC56B0, register_ShaderVarParticleParticleSpeed)
   */
  void register_ShaderVarParticleParticleSpeed()
  {
    moho::RegisterShaderVar("ParticleSpeed", &moho::shaderVarParticleParticleSpeed, "particle");
  }

  /**
   * Address: 0x00BC56D0 (FUN_00BC56D0, register_ShaderVarParticleParticleSystemHeight)
   */
  void register_ShaderVarParticleParticleSystemHeight()
  {
    moho::RegisterShaderVar("ParticleSystemHeight", &moho::shaderVarParticleParticleSystemHeight, "particle");
  }

  /**
   * Address: 0x00BC56F0 (FUN_00BC56F0, register_ShaderVarParticleParticleSize)
   */
  void register_ShaderVarParticleParticleSize()
  {
    moho::RegisterShaderVar("ParticleSize", &moho::shaderVarParticleParticleSize, "particle");
  }

  /**
   * Address: 0x00BC5710 (FUN_00BC5710, register_ShaderVarParticleDragEnabled)
   */
  void register_ShaderVarParticleDragEnabled()
  {
    moho::RegisterShaderVar("DragEnabled", &moho::shaderVarParticleDragEnabled, "particle");
  }

  /**
   * Address: 0x00BC5730 (FUN_00BC5730, register_ShaderVarParticleDragCoeff)
   */
  void register_ShaderVarParticleDragCoeff()
  {
    moho::RegisterShaderVar("DragCoeff", &moho::shaderVarParticleDragCoeff, "particle");
  }

  /**
   * Address: 0x00BC5750 (FUN_00BC5750, register_ShaderVarParticleInvDragCoeff)
   */
  void register_ShaderVarParticleInvDragCoeff()
  {
    moho::RegisterShaderVar("invDragCoeff", &moho::shaderVarParticleInvDragCoeff, "particle");
  }

  /**
   * Address: 0x00BC5770 (FUN_00BC5770, register_ShaderVarParticleInvDragCoeffSq)
   */
  void register_ShaderVarParticleInvDragCoeffSq()
  {
    moho::RegisterShaderVar("invDragCoeffSq", &moho::shaderVarParticleInvDragCoeffSq, "particle");
  }

  /**
   * Address: 0x00BC5790 (FUN_00BC5790, register_ShaderVarParticleBackgroundTexture)
   */
  void register_ShaderVarParticleBackgroundTexture()
  {
    moho::RegisterShaderVar("BackgroundTexture", &moho::shaderVarParticleBackgroundTexture, "particle");
  }

  /**
   * Address: 0x00BC57B0 (FUN_00BC57B0, register_ShaderVarParticleParticleTexture0)
   */
  void register_ShaderVarParticleParticleTexture0()
  {
    moho::RegisterShaderVar("ParticleTexture0", &moho::shaderVarParticleParticleTexture0, "particle");
  }

  /**
   * Address: 0x00BC57D0 (FUN_00BC57D0, register_ShaderVarParticleParticleTexture1)
   */
  void register_ShaderVarParticleParticleTexture1()
  {
    moho::RegisterShaderVar("ParticleTexture1", &moho::shaderVarParticleParticleTexture1, "particle");
  }

  struct ParticleShaderVarBootstrap
  {
    ParticleShaderVarBootstrap()
    {
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

    // TEMPORARY PROBE -- particle draw-time constant triage: everything the
    // sim produces is verified correct (FXTRAIL/FXATTACH), so an on-screen
    // offset must come from these binds. Reports, once per session, whether
    // each particle shader variable resolved and what time value it received.
    // Delete when resolved.
    {
      static bool sReported = false;
      if (!sReported) {
        sReported = true;
        std::FILE* const sink = std::fopen("faf_diag.log", "a");
        if (sink != nullptr) {
          std::fprintf(
            sink,
            "[FXBIND] time=%.3f view=%d proj=%d vp=%d invView=%d\n",
            time,
            moho::shaderVarParticleViewMatrix.Exists() ? 1 : 0,
            moho::shaderVarParticleProjection.Exists() ? 1 : 0,
            moho::shaderVarParticleWorldToProjection.Exists() ? 1 : 0,
            moho::shaderVarParticleInverseViewMatrix.Exists() ? 1 : 0
          );
          std::fclose(sink);
        }
      }
    }
  }

  /**
   * Frees the buffers the pool owns. The binary recurses the tree and deletes
   * each node as it goes; with a real container the node teardown belongs to
   * the container, so only the owned payloads are released here.
   */
  void ReleaseTrailSegmentPoolBuffers(moho::TrailSegmentPool& pool) noexcept
  {
    for (moho::STrailSegmentBuffer* const segmentBuffer : pool) {
      if (segmentBuffer == nullptr) {
        continue;
      }

      delete segmentBuffer->vertexSheet;
      segmentBuffer->vertexSheet = nullptr;
      ::operator delete(segmentBuffer);
    }
  }

  constexpr std::uint32_t kLegacyDwordVectorMaxCount = 0x3FFFFFFFU;

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

  [[nodiscard]] moho::SParticleBucketKey* InitializeParticleBucketKeyFromWorldParticle(
    moho::SParticleBucketKey* const key,
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
    key->dragEnabled = particle.mDragEnabled;

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

  // 0x0049EE50 / 0x0049E0B0 (particle) and 0x0049EE80 / 0x0049E1F0 (trail) are
  // the copy constructors MSVC emits for `msvc8::map<Key, Bucket*>::value_type`
  // on the insert path -- a `std::pair<const Key, Bucket*>` whose first member
  // is the 0x3C / 0x34 bucket key. They were transcribed here as
  // `ParticleBucketKeyValueRuntime` / `TrailBucketKeyValueRuntime` plus four
  // free `CopyConstruct*` helpers, two of which had no caller at all. Cited on
  // `msvc8::map::insert(const value_type&)` (legacy/containers/Map.h) and
  // removed; the source line that produces them is the `buckets[key] = bucket`
  // in `CWorldParticles`.

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
  void DestroyAndDeleteParticleRenderBucket(moho::SParticleRenderBucket* const bucket) noexcept
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
  void DestroyAndDeleteTrailRenderBucket(moho::STrailRenderBucket* const bucket) noexcept
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
    const moho::SParticleBucketKey& lhs,
    const moho::SParticleBucketKey& rhs
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
    const moho::STrailBucketKey& lhs,
    const moho::STrailBucketKey& rhs
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
   * Address: 0x0049FA70 (FUN_0049FA70, sub_49FA70)
   *
   * What it does:
   * Duplicate particle-bucket destroy+delete thunk.
   */
  void DestroyAndDeleteParticleRenderBucketDuplicateA(
    moho::SParticleRenderBucket* const bucket
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
    moho::STrailRenderBucket* const bucket
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
    moho::SParticleRenderBucket* const bucket
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
    moho::STrailRenderBucket* const bucket
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
    moho::SParticleRenderBucket* const bucket
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
    moho::STrailRenderBucket* const bucket
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
    moho::SParticleRenderBucket* const bucket
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
    moho::STrailRenderBucket* const bucket
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
  moho::SParticleRenderBucket* DestroyAndDeleteParticleRenderBucketAndReturnInput(
    moho::SParticleRenderBucket* const bucket
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
  moho::STrailRenderBucket* DestroyAndDeleteTrailRenderBucketAndReturnInput(
    moho::STrailRenderBucket* const bucket
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
    return sSharedTrailQuadIndexSheet.get();
  }

  /**
   * What it does:
   * Releases the shared trail-quad index-sheet singleton and clears its global
   * ownership lane.
   */
  void DestroySharedTrailQuadIndexSheet() noexcept
  {
    sSharedTrailQuadIndexSheet.reset();
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

    sSharedTrailQuadIndexSheet =
      msvc8::auto_ptr<ID3DIndexSheet>(resources->CreateIndexSheet(false, kSharedTrailIndexSheetSize));

    if (sSharedTrailQuadIndexSheet.get() == nullptr) {
      return 0;
    }

    const std::uint32_t indexCount = sSharedTrailQuadIndexSheet->GetSize();
    std::int16_t* const mappedIndices = sSharedTrailQuadIndexSheet->Lock(0U, indexCount, false, false);
    if (mappedIndices == nullptr) {
      return 0;
    }

    // The sheet is filled BACK TO FRONT: quad 0's six indices go in the LAST
    // slot, quad 1's in the one below it, and so on. 0x004986F0 starts its
    // write cursor near the end of the locked buffer and steps it down by
    // `12` bytes - six 16-bit indices - per quad (`v7 -= 12`), while the
    // quad's own vertex numbers (`4q .. 4q+3`) count up.
    //
    // That ordering is what makes `DrawTrailSegmentBatch` (0x004967E0) work:
    // it draws `6 * segmentCount` indices starting at
    // `6 * (0x4000 - segmentCount)`, i.e. the TAIL of the sheet, which holds
    // exactly quads 0..segmentCount-1. Filling front to front instead left
    // that tail holding quads 0x4000-N..0x3FFF, whose vertex numbers run to
    // ~65532 - thousands of vertices past the end of the trail's own buffer -
    // so every ribbon quad collapsed and a polytrail rendered as a line of
    // disconnected specks instead of a continuous strip.
    for (std::uint32_t quadIndex = 0U; quadIndex < kSharedTrailQuadCount; ++quadIndex) {
      const std::uint16_t baseVertex = static_cast<std::uint16_t>(quadIndex * 4U);
      const std::uint32_t indexBase = (kSharedTrailQuadCount - 1U - quadIndex) * kIndicesPerTrailQuad;

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
    // Every member above is built by its own constructor before this body runs
    // -- the two list heads through 0x00497D00 (`_Buy_head`), the set head
    // through 0x0049C620, the three bucket maps' header sentinels likewise, and
    // the two lookup keys' string and handle lanes. The binary inlines all of
    // it here, which is what it looks like when a constructor's member list is
    // the whole story.
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
    DestroyWorldParticlesSingleton();

    // What followed here -- release the trail lookup key, then the particle
    // lookup key, then the three bucket maps -- is reverse declaration order,
    // so it is the member teardown MSVC emits, not a source line
    // (CLAUDE.md RULE ONE). `ResetParticleBucketKeyResources` (0x00492EF0) and
    // its trail twin (0x00492FC0) are those keys' implicit destructors; they
    // stay named because the scratch-key lookups below call them deliberately.
    // mBeams (0x00493090), mTrailSegmentPool (`erase(begin(), end())`
    // 0x0049A6C0 + head free), mAvailableParticleBuffers and mParticleBuffers
    // (`_Tidy` 0x00495F30 + head free) are destroyed by their member
    // destructors after this body.
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
  STrailSegmentBuffer* CWorldParticles::AcquireTrailSegmentBuffer()
  {
    if (mTrailSegmentPool.empty()) {
      return nullptr;
    }

    // The binary takes the leftmost node, keeps its buffer and erases it,
    // discarding the successor the erase hands back.
    const auto first = mTrailSegmentPool.begin();
    STrailSegmentBuffer* const segmentBuffer = *first;
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
  void CWorldParticles::ReleaseTrailSegmentBuffer(STrailSegmentBuffer* const segmentBuffer)
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
    SParticleRenderBucket** const bucketCacheSlot
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

    SParticleBucketKey lookupKey{};
    (void)InitializeParticleBucketKeyFromWorldParticle(&lookupKey, particle);

    if (static_cast<std::int32_t>(particle.mBlendMode) == 5) {
      auto bucketEntry = mRefractingParticleBuckets.find(lookupKey);
      if (bucketEntry == mRefractingParticleBuckets.end()) {
        // Must be constructed, not just allocated: the bucket owns two
        // shared_ptr texture handles, an msvc8::string and two vectors, and
        // InitializeParticleRenderBucketFromWorldParticle's first act is to
        // `reset()` those handles.
        auto* const newBucket = new SParticleRenderBucket();
        (void)InitializeParticleRenderBucketFromWorldParticle(*newBucket, particle, this);
        bucketEntry = mRefractingParticleBuckets.insert({lookupKey, newBucket}).first;
      }

      bucketEntry->second->pendingParticles.push_back(particle);
      ResetParticleBucketKeyResources(lookupKey);
      return;
    }

    if (mCachedParticleBucket != nullptr &&
        AreParticleBucketKeysEquivalent(mParticleBucketLookupKey, lookupKey)) {
      mCachedParticleBucket->pendingParticles.push_back(particle);
      ResetParticleBucketKeyResources(lookupKey);
      return;
    }

    auto bucketEntry = mParticleBuckets.find(lookupKey);
    if (bucketEntry == mParticleBuckets.end()) {
      auto* const newBucket = new SParticleRenderBucket();
      (void)InitializeParticleRenderBucketFromWorldParticle(*newBucket, particle, this);
      bucketEntry = mParticleBuckets.insert({lookupKey, newBucket}).first;
    }

    SParticleRenderBucket* const bucket = bucketEntry->second;
    bucket->pendingParticles.push_back(particle);
    (void)CopyParticleBucketKey(&mParticleBucketLookupKey, &lookupKey);
    mCachedParticleBucket = bucket;

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
    const SWorldTrail& trail,
    STrailRenderBucket** const bucketCacheSlot
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

    STrailBucketKey lookupKey{};
    (void)InitializeTrailBucketKeyFromTrail(&lookupKey, trail);

    if (mCachedTrailBucket != nullptr &&
        AreTrailBucketKeysEquivalent(mTrailBucketLookupKey, lookupKey)) {
      mCachedTrailBucket->pendingTrails.push_back(trail);
      ResetTrailBucketKeyResources(lookupKey);
      return;
    }

    auto bucketEntry = mTrailBuckets.find(lookupKey);
    if (bucketEntry == mTrailBuckets.end()) {
      auto* const newBucket = new STrailRenderBucket();
      (void)InitializeTrailRenderBucketFromTrail(*newBucket, trail, this);
      bucketEntry = mTrailBuckets.insert({lookupKey, newBucket}).first;
    }

    STrailRenderBucket* const bucket = bucketEntry->second;
    bucket->pendingTrails.push_back(trail);
    (void)CopyTrailBucketKey(&mTrailBucketLookupKey, &lookupKey);
    mCachedTrailBucket = bucket;

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

    for (const SWorldTrail& trail : batch.mTrails) {
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

    char renderResult = 0;
    const auto renderAboveSurface = renderWaterSurface == 0;
    const float waterSurface = efx_ParticleWaterSurface;

    for (const auto& [bucketKey, bucket] : mParticleBuckets) {
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

    for (const auto& [bucketKey, bucket] : mTrailBuckets) {
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

    for (const auto& [bucketKey, bucket] : mRefractingParticleBuckets) {
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
      auto* const segmentBuffer = static_cast<STrailSegmentBuffer*>(
        ::operator new(sizeof(STrailSegmentBuffer))
      );
      std::memset(segmentBuffer, 0, sizeof(STrailSegmentBuffer));

      segmentBuffer->maxSegments = kTrailSegmentCapacity;
      segmentBuffer->vertexSheet = resources->NewVertexSheet(
        kTrailVertexSheetUsageToken,
        kTrailVertexSheetFrequencyToken,
        trailVertexFormat
      );

      if (sSharedTrailQuadIndexSheet.get() == nullptr) {
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
  /**
   * Address: 0x00494E10 (FUN_00494E10)
   * Slot: 0 (see the header for the byte-verified vtable order)
   *
   * What it does:
   * Clears the runtime particle, refracting-particle, and trail bucket lanes
   * owned by one world-particles instance.
   */
  void CWorldParticles::ClearRenderBuckets()
  {
    CWorldParticles& worldParticles = *this;
    CWorldParticles& runtime = worldParticles;

    // Each entry owns its bucket, so the payload goes before the node.
    for (const auto& [bucketKey, bucket] : mParticleBuckets) {
      (void)bucketKey;
      DestroyParticleRenderBucket(*bucket);
      ::operator delete(bucket);
    }
    mParticleBuckets.clear();

    for (const auto& [bucketKey, bucket] : mRefractingParticleBuckets) {
      (void)bucketKey;
      DestroyParticleRenderBucket(*bucket);
      ::operator delete(bucket);
    }
    mRefractingParticleBuckets.clear();

    for (const auto& [bucketKey, bucket] : mTrailBuckets) {
      (void)bucketKey;
      DestroyTrailRenderBucket(*bucket);
      ::operator delete(bucket);
    }
    mTrailBuckets.clear();

    mCachedParticleBucket = nullptr;
    mCachedTrailBucket = nullptr;
    ResetParticleBucketKeyResources(mParticleBucketLookupKey);
    ResetTrailBucketKeyResources(mTrailBucketLookupKey);
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
