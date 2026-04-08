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
  constexpr std::uint32_t kLegacyListMaxSize = 0x3FFFFFFFU;

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

  [[maybe_unused]] ParticleShaderVarBootstrap gParticleShaderVarBootstrap;

  template <typename TValue>
  [[nodiscard]] std::size_t RenderBucketVectorCount(
    const moho::RenderBucketVectorRuntime<TValue>& vector
  ) noexcept
  {
    if (vector.begin == nullptr || vector.end == nullptr || vector.end < vector.begin) {
      return 0U;
    }

    return static_cast<std::size_t>(vector.end - vector.begin);
  }

  template <typename TValue>
  [[nodiscard]] std::size_t RenderBucketVectorCapacity(
    const moho::RenderBucketVectorRuntime<TValue>& vector
  ) noexcept
  {
    if (vector.begin == nullptr || vector.capacityEnd == nullptr || vector.capacityEnd < vector.begin) {
      return 0U;
    }

    return static_cast<std::size_t>(vector.capacityEnd - vector.begin);
  }

  template <typename TValue>
  TValue* AppendRenderBucketVectorValue(
    moho::RenderBucketVectorRuntime<TValue>& vector,
    const TValue& value
  )
  {
    const std::size_t size = RenderBucketVectorCount(vector);
    const std::size_t capacity = RenderBucketVectorCapacity(vector);

    if (size >= kLegacyVectorMaxCount) {
      throw std::length_error("vector<T> too long");
    }

    if (size == capacity) {
      std::size_t newCapacity = capacity != 0U ? capacity + (capacity / 2U) : 1U;
      if (newCapacity < size + 1U) {
        newCapacity = size + 1U;
      }
      if (newCapacity > kLegacyVectorMaxCount) {
        newCapacity = kLegacyVectorMaxCount;
      }
      if (newCapacity < size + 1U ||
          newCapacity > (std::numeric_limits<std::size_t>::max() / sizeof(TValue))) {
        throw std::length_error("vector<T> too long");
      }

      auto* const newStorage = static_cast<TValue*>(::operator new(newCapacity * sizeof(TValue)));
      std::size_t constructedCount = 0U;
      try {
        for (; constructedCount < size; ++constructedCount) {
          ::new (static_cast<void*>(newStorage + constructedCount)) TValue(vector.begin[constructedCount]);
        }
      } catch (...) {
        while (constructedCount != 0U) {
          --constructedCount;
          (newStorage + constructedCount)->~TValue();
        }
        ::operator delete(newStorage);
        throw;
      }

      if (vector.begin != nullptr) {
        for (TValue* element = vector.begin; element != vector.end; ++element) {
          element->~TValue();
        }
        ::operator delete(vector.begin);
      }

      vector.begin = newStorage;
      vector.end = newStorage + size;
      vector.capacityEnd = newStorage + newCapacity;
    }

    ::new (static_cast<void*>(vector.end)) TValue(value);
    ++vector.end;
    return vector.end - 1;
  }

  [[nodiscard]] const char* ResolveParticleTechniqueSuffix(
    const std::int32_t blendMode,
    const bool allowRefract,
    const int assertLine
  )
  {
    switch (blendMode) {
      case 0:
        return "_ALPHABLEND";
      case 1:
        return "_MODULATEINVERSE";
      case 2:
        return "_MODULATE2XINVERSE";
      case 3:
        return "_ADD";
      case 4:
        return "_PREMODALPHA";
      case 5:
        if (allowRefract) {
          return "_REFRACT";
        }
        break;
      default:
        break;
    }

    gpg::HandleAssertFailure(kUnreachableAssertText, assertLine, kParticleRendererSourcePath);
    return "_ALPHABLEND";
  }

  void BindParticleTextureShaderVar(
    moho::ShaderVar& shaderVar,
    const moho::CParticleTexture::TextureResourceHandle& textureResource
  )
  {
    boost::shared_ptr<gpg::gal::TextureD3D9> textureHandle;
    if (textureResource != nullptr) {
      textureResource->GetTexture(textureHandle);
    }

    boost::weak_ptr<gpg::gal::TextureD3D9> weakTexture(textureHandle);
    shaderVar.GetTexture(weakTexture);
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

  void DestroyParticleBufferPoolListNodes(
    moho::ParticleBufferPoolListRuntime& listRuntime,
    const bool destroyValues
  )
  {
    if (listRuntime.head == nullptr) {
      listRuntime.size = 0U;
      return;
    }

    auto* const head = listRuntime.head;
    auto* node = head->next;
    while (node != nullptr && node != head) {
      auto* const next = node->next;
      if (destroyValues && node->value != nullptr) {
        delete node->value;
        node->value = nullptr;
      }

      ::operator delete(node);
      node = next;
    }

    head->next = head;
    head->prev = head;
    head->value = nullptr;
    listRuntime.size = 0U;
  }

  void DestroyTrailSegmentPoolNodesRecursive(
    moho::TrailSegmentPoolNodeRuntime* const node,
    moho::TrailSegmentPoolNodeRuntime* const head
  ) noexcept
  {
    if (node == nullptr || node == head || node->isNil != 0U) {
      return;
    }

    DestroyTrailSegmentPoolNodesRecursive(node->left, head);
    DestroyTrailSegmentPoolNodesRecursive(node->right, head);

    if (node->segmentBuffer != nullptr) {
      if (node->segmentBuffer->vertexSheet != nullptr) {
        delete node->segmentBuffer->vertexSheet;
        node->segmentBuffer->vertexSheet = nullptr;
      }
      ::operator delete(node->segmentBuffer);
      node->segmentBuffer = nullptr;
    }

    ::operator delete(node);
  }

  void ResetTrailSegmentPool(moho::TrailSegmentPoolRuntime& poolRuntime) noexcept
  {
    moho::TrailSegmentPoolNodeRuntime* const head = poolRuntime.head;
    if (head == nullptr) {
      poolRuntime.size = 0U;
      return;
    }

    DestroyTrailSegmentPoolNodesRecursive(head->left, head);
    head->left = head;
    head->parent = head;
    head->right = head;
    head->segmentBuffer = nullptr;
    head->color = 1U;
    head->isNil = 1U;
    head->padding12 = 0U;
    poolRuntime.size = 0U;
  }

  void ReleaseParticleBufferPoolListStorage(
    moho::ParticleBufferPoolListRuntime& listRuntime
  ) noexcept
  {
    if (listRuntime.head == nullptr) {
      listRuntime.size = 0U;
      return;
    }

    DestroyParticleBufferPoolListNodes(listRuntime, false);
    ::operator delete(listRuntime.head);
    listRuntime.head = nullptr;
    listRuntime.size = 0U;
  }

  void ReleaseTrailSegmentPoolStorage(
    moho::TrailSegmentPoolRuntime& poolRuntime
  ) noexcept
  {
    moho::TrailSegmentPoolNodeRuntime* const head = poolRuntime.head;
    if (head == nullptr) {
      poolRuntime.size = 0U;
      return;
    }

    DestroyTrailSegmentPoolNodesRecursive(head->left, head);
    ::operator delete(head);
    poolRuntime.head = nullptr;
    poolRuntime.size = 0U;
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
  [[maybe_unused]] moho::ParticleBucketKeyRuntime* GetParticleBucketEntryNodeKeySlotA(
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
  [[maybe_unused]] moho::ParticleBucketKeyRuntime* GetParticleBucketEntryNodeKeySlotB(
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
  [[maybe_unused]] moho::TrailBucketKeyRuntime* GetTrailBucketEntryNodeKeySlotA(
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
  [[maybe_unused]] moho::TrailBucketKeyRuntime* GetTrailBucketEntryNodeKeySlotB(
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

  [[maybe_unused]] void DestroyParticleBucketTreeNodesRecursive(
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

  [[maybe_unused]] void DestroyParticleBucketTreeNodesRecursive(
    moho::ParticleBucketTreeNodeRuntime* const node,
    moho::ParticleBucketTreeNodeRuntime* const head
  ) noexcept
  {
    DestroyParticleBucketTreeNodesRecursive(
      reinterpret_cast<ParticleBucketTreeEntryNodeRuntime*>(node),
      reinterpret_cast<ParticleBucketTreeEntryNodeRuntime*>(head)
    );
  }

  [[maybe_unused]] void DestroyTrailBucketTreeNodesRecursive(
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

  [[maybe_unused]] void DestroyTrailBucketTreeNodesRecursive(
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
  [[maybe_unused]] void ReleaseParticleBucketTreeStorage(
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
  [[maybe_unused]] void ReleaseTrailBucketTreeStorage(
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
   * Address: 0x00497D00 (FUN_00497D00, sub_497D00)
   *
   * What it does:
   * Allocates one self-linked list-head node lane for legacy intrusive
   * particle-buffer pools.
   */
  [[nodiscard]] moho::ParticleBufferPoolNodeRuntime* AllocateParticleBufferPoolHeadNode()
  {
    auto* const head = static_cast<moho::ParticleBufferPoolNodeRuntime*>(
      ::operator new(sizeof(moho::ParticleBufferPoolNodeRuntime))
    );
    head->next = head;
    head->prev = head;
    head->value = nullptr;
    return head;
  }

  /**
   * Address: 0x00497D50 (FUN_00497D50, nullsub_558)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  void NoOpHelperThunkC() noexcept {}

  /**
   * Address: 0x00497D70 (FUN_00497D70, nullsub_559)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  void NoOpHelperThunkD() noexcept {}

  /**
   * Address: 0x00497DB0 (FUN_00497DB0, nullsub_560)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  void NoOpHelperThunkE() noexcept {}

  /**
   * Address: 0x00498000 (FUN_00498000, sub_498000)
   *
   * What it does:
   * Reads one 32-bit value from offset `+0x04` of caller storage.
   */
  [[nodiscard]] std::uint32_t ReadDwordAtOffset4FromSlot(const std::uint32_t* const valueBase) noexcept
  {
    return valueBase[1];
  }

  /**
   * Address: 0x00498140 (FUN_00498140, nullsub_561)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  void NoOpHelperThunkF() noexcept {}

  /**
   * Address: 0x00498150 (FUN_00498150, nullsub_562)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  void NoOpHelperThunkG() noexcept {}

  /**
   * Address: 0x00498180 (FUN_00498180, nullsub_563)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  void NoOpHelperThunkH() noexcept {}

  /**
   * Address: 0x00498300 (FUN_00498300, nullsub_564)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  void NoOpHelperThunkI() noexcept {}

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
   */
  moho::ParticleBucketTreeNodeRuntime** ResolveParticleBucketCandidateOrHeadDuplicate(
    const moho::ParticleBucketKeyRuntime& key,
    moho::ParticleBucketTreeNodeRuntime** const outNode,
    const moho::ParticleBucketTreeRuntime& treeRuntime
  ) noexcept
  {
    return ResolveParticleBucketCandidateOrHead(key, outNode, treeRuntime);
  }

  /**
   * Address: 0x004983F0 (FUN_004983F0, sub_4983F0)
   *
   * What it does:
   * Copies one pointer-slot value into caller-provided output storage.
   */
  [[nodiscard]] void** CopyPointerSlotValueA(void** const outPointerSlot, void* const* const sourcePointerSlot) noexcept
  {
    *outPointerSlot = *sourcePointerSlot;
    return outPointerSlot;
  }

  /**
   * Address: 0x00498400 (FUN_00498400, nullsub_565)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  void NoOpHelperThunkJ() noexcept {}

  /**
   * Address: 0x00498410 (FUN_00498410, nullsub_566)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  void NoOpHelperThunkK() noexcept {}

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
   * Address: 0x00498430 (FUN_00498430, sub_498430)
   *
   * What it does:
   * Writes `(pointer, flag)` into one caller-provided pair lane.
   */
  PointerFlagPairRuntime* WritePointerFlagPair(
    PointerFlagPairRuntime* const outPair,
    void* const pointer,
    const std::uint32_t flag
  ) noexcept
  {
    outPair->pointer = pointer;
    outPair->flag = flag;
    return outPair;
  }

  /**
   * Address: 0x004985B0 (FUN_004985B0, nullsub_567)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  void NoOpHelperThunkL() noexcept {}

  /**
   * Address: 0x0049C980 (FUN_0049C980, nullsub_604)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkAG() noexcept {}

  /**
   * Address: 0x0049C9B0 (FUN_0049C9B0, nullsub_605)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkAH() noexcept {}

  /**
   * Address: 0x0049C9D0 (FUN_0049C9D0, sub_49C9D0)
   *
   * What it does:
   * Writes one pointer-slot value into caller-provided output storage.
   */
  [[nodiscard]] void** CopyPointerSlotValueC(
    void** const outPointerSlot,
    void* const pointerValue
  ) noexcept
  {
    *outPointerSlot = pointerValue;
    return outPointerSlot;
  }

  /**
   * Address: 0x0049C9F0 (FUN_0049C9F0, nullsub_606)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkAI() noexcept {}

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
   */
  moho::TrailBucketTreeNodeRuntime** ResolveTrailBucketCandidateOrHeadDuplicate(
    const moho::TrailBucketKeyRuntime& key,
    moho::TrailBucketTreeNodeRuntime** const outNode,
    const moho::TrailBucketTreeRuntime& treeRuntime
  ) noexcept
  {
    return ResolveTrailBucketCandidateOrHead(key, outNode, treeRuntime);
  }

  /**
   * Address: 0x004986A0 (FUN_004986A0, sub_4986A0)
   *
   * What it does:
   * Copies one pointer-slot value into caller-provided output storage.
   */
  [[nodiscard]] void** CopyPointerSlotValueB(void** const outPointerSlot, void* const* const sourcePointerSlot) noexcept
  {
    *outPointerSlot = *sourcePointerSlot;
    return outPointerSlot;
  }

  /**
   * Address: 0x004986B0 (FUN_004986B0, nullsub_568)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  void NoOpHelperThunkM() noexcept {}

  /**
   * Address: 0x004986C0 (FUN_004986C0, nullsub_569)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  void NoOpHelperThunkN() noexcept {}

  /**
   * Address: 0x004986E0 (FUN_004986E0, sub_4986E0)
   *
   * What it does:
   * Writes one duplicate `(pointer, flag)` pair into caller storage.
   */
  PointerFlagPairRuntime* WritePointerFlagPairDuplicate(
    PointerFlagPairRuntime* const outPair,
    void* const pointer,
    const std::uint32_t flag
  ) noexcept
  {
    outPair->pointer = pointer;
    outPair->flag = flag;
    return outPair;
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

  /**
   * Address: 0x00498820 (FUN_00498820, sub_498820)
   *
   * What it does:
   * Writes one `(pointer, inserted-flag)` pair from caller slots into output
   * storage.
   */
  PointerByteFlagPairRuntime* WritePointerByteFlagPairFromSlots(
    PointerByteFlagPairRuntime* const outPair,
    void* const* const pointerSlot,
    const std::uint8_t* const flagSlot
  ) noexcept
  {
    outPair->pointer = *pointerSlot;
    outPair->flag = *flagSlot;
    return outPair;
  }

  /**
   * Address: 0x0049EE20 (FUN_0049EE20, sub_49EE20)
   *
   * What it does:
   * Duplicate `(pointer, inserted-flag)` lane writer retained for callsite
   * parity.
   */
  [[maybe_unused]] PointerByteFlagPairRuntime* WritePointerByteFlagPairFromSlotsDuplicateA(
    PointerByteFlagPairRuntime* const outPair,
    void* const* const pointerSlot,
    const std::uint8_t* const flagSlot
  ) noexcept
  {
    outPair->pointer = *pointerSlot;
    outPair->flag = *flagSlot;
    return outPair;
  }

  /**
   * Address: 0x0049EE30 (FUN_0049EE30, sub_49EE30)
   *
   * What it does:
   * Duplicate `(pointer, inserted-flag)` lane writer retained for callsite
   * parity.
   */
  [[maybe_unused]] PointerByteFlagPairRuntime* WritePointerByteFlagPairFromSlotsDuplicateB(
    PointerByteFlagPairRuntime* const outPair,
    void* const* const pointerSlot,
    const std::uint8_t* const flagSlot
  ) noexcept
  {
    outPair->pointer = *pointerSlot;
    outPair->flag = *flagSlot;
    return outPair;
  }

  /**
   * Address: 0x00498830 (FUN_00498830, sub_498830)
   *
   * What it does:
   * Writes one pointer value into caller-provided output slot.
   */
  void** WritePointerSlotValueC(void** const outPointerSlot, void* const pointer) noexcept
  {
    *outPointerSlot = pointer;
    return outPointerSlot;
  }

  /**
   * Address: 0x00498880 (FUN_00498880, sub_498880)
   *
   * What it does:
   * Reads one pointer value from caller-provided slot.
   */
  [[nodiscard]] void* ReadPointerSlotValueC(void* const* const pointerSlot) noexcept
  {
    return *pointerSlot;
  }

  /**
   * Address: 0x00498890 (FUN_00498890, sub_498890)
   *
   * What it does:
   * Writes one pointer value into caller-provided output slot.
   */
  void** WritePointerSlotValueD(void** const outPointerSlot, void* const pointer) noexcept
  {
    *outPointerSlot = pointer;
    return outPointerSlot;
  }

  /**
   * Address: 0x0049EE40 (FUN_0049EE40, sub_49EE40)
   *
   * What it does:
   * Duplicate pointer-slot writer retained for callsite parity.
   */
  [[maybe_unused]] void** WritePointerSlotValueE(void** const outPointerSlot, void* const pointer) noexcept
  {
    *outPointerSlot = pointer;
    return outPointerSlot;
  }

  /**
   * Address: 0x0049EE70 (FUN_0049EE70, sub_49EE70)
   *
   * What it does:
   * Duplicate pointer-slot writer retained for callsite parity.
   */
  [[maybe_unused]] void** WritePointerSlotValueF(void** const outPointerSlot, void* const pointer) noexcept
  {
    *outPointerSlot = pointer;
    return outPointerSlot;
  }

  /**
   * Address: 0x0049EF00 (FUN_0049EF00, sub_49EF00)
   *
   * What it does:
   * Duplicate pointer-slot writer retained for callsite parity.
   */
  [[maybe_unused]] void** WritePointerSlotValueG(void** const outPointerSlot, void* const pointer) noexcept
  {
    *outPointerSlot = pointer;
    return outPointerSlot;
  }

  /**
   * Address: 0x0049EF10 (FUN_0049EF10, sub_49EF10)
   *
   * What it does:
   * Duplicate pointer-slot writer retained for callsite parity.
   */
  [[maybe_unused]] void** WritePointerSlotValueH(void** const outPointerSlot, void* const pointer) noexcept
  {
    *outPointerSlot = pointer;
    return outPointerSlot;
  }

  /**
   * Address: 0x004988B0 (FUN_004988B0, sub_4988B0)
   *
   * What it does:
   * Rebinds one pointer-to-pointer slot to the next indirect pointer lane.
   */
  void*** AdvanceIndirectPointerSlot(void*** const slot) noexcept
  {
    *slot = reinterpret_cast<void**>(**slot);
    return slot;
  }

  /**
   * Address: 0x004988D0 (FUN_004988D0, sub_4988D0)
   *
   * What it does:
   * Reads one pointer value from caller-provided slot.
   */
  [[nodiscard]] void* ReadPointerSlotValueD(void* const* const pointerSlot) noexcept
  {
    return *pointerSlot;
  }

  /**
   * Address: 0x00498A20 (FUN_00498A20, nullsub_570)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  void NoOpHelperThunkO(const std::uint32_t /*unused*/) noexcept {}

  /**
   * Address: 0x00498A30 (FUN_00498A30, nullsub_571)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  void NoOpHelperThunkP() noexcept {}

  /**
   * Address: 0x00498B40 (FUN_00498B40, nullsub_572)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  void NoOpHelperThunkQ() noexcept {}

  /**
   * What it does:
   * Legacy `vector<uint32_t>` runtime lane used by adjacent helper thunks.
   */
  struct LegacyDwordVectorRuntime
  {
    std::uint32_t iteratorProxy = 0U; // +0x00
    std::uint32_t* begin = nullptr;   // +0x04
    std::uint32_t* end = nullptr;     // +0x08
    std::uint32_t* capacityEnd = nullptr; // +0x0C
  };

  static_assert(
    offsetof(LegacyDwordVectorRuntime, begin) == 0x04,
    "LegacyDwordVectorRuntime::begin offset must be 0x04"
  );
  static_assert(
    offsetof(LegacyDwordVectorRuntime, end) == 0x08,
    "LegacyDwordVectorRuntime::end offset must be 0x08"
  );
  static_assert(
    offsetof(LegacyDwordVectorRuntime, capacityEnd) == 0x0C,
    "LegacyDwordVectorRuntime::capacityEnd offset must be 0x0C"
  );
  static_assert(sizeof(LegacyDwordVectorRuntime) == 0x10, "LegacyDwordVectorRuntime size must be 0x10");

  constexpr std::uint32_t kLegacyDwordVectorMaxCount = 0x3FFFFFFFU;

  [[nodiscard]] std::uint32_t* AllocateLegacyDwordVectorStorage(const std::uint32_t elementCount)
  {
    if (elementCount == 0U) {
      return static_cast<std::uint32_t*>(::operator new(0));
    }

    return static_cast<std::uint32_t*>(::operator new(static_cast<std::size_t>(elementCount) * sizeof(std::uint32_t)));
  }

  /**
   * Address: 0x00498AA0 (FUN_00498AA0, sub_498AA0)
   *
   * What it does:
   * Moves one `uint32_t` tail range inside one legacy vector lane and writes
   * the destination iterator into caller output storage.
   */
  std::uint32_t** MoveDwordVectorTailAndExportDestination(
    LegacyDwordVectorRuntime& vectorRuntime,
    std::uint32_t** const outIterator,
    std::uint32_t* const destination,
    const std::uint32_t* const source
  ) noexcept
  {
    if (destination != source) {
      const std::size_t copyCount = static_cast<std::size_t>(vectorRuntime.end - source);
      if (copyCount != 0U) {
        std::memmove(destination, source, copyCount * sizeof(std::uint32_t));
      }
      vectorRuntime.end = destination + copyCount;
    }

    *outIterator = destination;
    return outIterator;
  }

  /**
   * Address: 0x00498AF0 (FUN_00498AF0, sub_498AF0)
   *
   * What it does:
   * Initializes one legacy `vector<uint32_t>` lane with requested capacity and
   * overflow guard.
   */
  bool InitializeLegacyDwordVectorStorageA(
    LegacyDwordVectorRuntime& vectorRuntime,
    const std::uint32_t requestedCapacity
  )
  {
    if (requestedCapacity > kLegacyDwordVectorMaxCount) {
      throw std::length_error("vector<T> too long");
    }

    std::uint32_t* const storage = AllocateLegacyDwordVectorStorage(requestedCapacity);
    vectorRuntime.begin = storage;
    vectorRuntime.end = storage;
    vectorRuntime.capacityEnd = storage + requestedCapacity;
    return true;
  }

  /**
   * Address: 0x00498B80 (FUN_00498B80, sub_498B80)
   *
   * What it does:
   * Fills one `uint32_t` range with one scalar value loaded from caller slot
   * and returns the end iterator.
   */
  [[nodiscard]] std::uint32_t* FillDwordRangeFromScalarSlotA(
    const std::uint32_t* const valueSlot,
    std::uint32_t* destination,
    std::int32_t count
  ) noexcept
  {
    while (count > 0) {
      *destination++ = *valueSlot;
      --count;
    }
    return destination;
  }

  /**
   * Address: 0x00498BB0 (FUN_00498BB0, nullsub_573)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  void NoOpHelperThunkR(const std::uint32_t /*unused*/) noexcept {}

  /**
   * Address: 0x00498BC0 (FUN_00498BC0, nullsub_574)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  void NoOpHelperThunkS() noexcept {}

  /**
   * Address: 0x00498BE0 (FUN_00498BE0, sub_498BE0)
   *
   * What it does:
   * Writes one `uint32_t` scalar value into caller-provided output slot.
   */
  std::uint32_t* WriteScalarDwordSlotA(std::uint32_t* const outValueSlot, const std::uint32_t value) noexcept
  {
    *outValueSlot = value;
    return outValueSlot;
  }

  /**
   * Address: 0x00498BF0 (FUN_00498BF0, sub_498BF0)
   *
   * What it does:
   * Reads one `uint32_t` scalar value from caller-provided slot.
   */
  [[nodiscard]] std::uint32_t ReadScalarDwordSlotA(const std::uint32_t* const valueSlot) noexcept
  {
    return *valueSlot;
  }

  /**
   * Address: 0x00498C30 (FUN_00498C30, sub_498C30)
   *
   * What it does:
   * Duplicate `uint32_t` slot writer helper retained for callsite parity.
   */
  std::uint32_t* WriteScalarDwordSlotB(std::uint32_t* const outValueSlot, const std::uint32_t value) noexcept
  {
    *outValueSlot = value;
    return outValueSlot;
  }

  /**
   * Address: 0x00498C40 (FUN_00498C40, sub_498C40)
   *
   * What it does:
   * Duplicate `uint32_t` slot reader helper retained for callsite parity.
   */
  [[nodiscard]] std::uint32_t ReadScalarDwordSlotB(const std::uint32_t* const valueSlot) noexcept
  {
    return *valueSlot;
  }

  /**
   * Address: 0x00498C80 (FUN_00498C80, sub_498C80)
   *
   * What it does:
   * Duplicate `uint32_t` slot writer helper retained for callsite parity.
   */
  std::uint32_t* WriteScalarDwordSlotC(std::uint32_t* const outValueSlot, const std::uint32_t value) noexcept
  {
    *outValueSlot = value;
    return outValueSlot;
  }

  /**
   * Address: 0x00498CA0 (FUN_00498CA0, sub_498CA0)
   *
   * What it does:
   * Duplicate `uint32_t` slot reader helper retained for callsite parity.
   */
  [[nodiscard]] std::uint32_t ReadScalarDwordSlotC(const std::uint32_t* const valueSlot) noexcept
  {
    return *valueSlot;
  }

  /**
   * Address: 0x00498E10 (FUN_00498E10, nullsub_575)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  void NoOpHelperThunkT(const std::uint32_t /*unused*/) noexcept {}

  /**
   * Address: 0x00498E20 (FUN_00498E20, nullsub_576)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  void NoOpHelperThunkU() noexcept {}

  /**
   * Address: 0x00498E90 (FUN_00498E90, sub_498E90)
   *
   * What it does:
   * Resets one legacy vector end iterator back to begin when the vector is
   * non-empty.
   */
  void ResetLegacyDwordVectorEndToBegin(LegacyDwordVectorRuntime& vectorRuntime) noexcept
  {
    if (vectorRuntime.begin != vectorRuntime.end) {
      vectorRuntime.end = vectorRuntime.begin;
    }
  }

  /**
   * Address: 0x00498ED0 (FUN_00498ED0, sub_498ED0)
   *
   * What it does:
   * Duplicate legacy `vector<uint32_t>` storage initializer with overflow
   * guard.
   */
  bool InitializeLegacyDwordVectorStorageB(
    LegacyDwordVectorRuntime& vectorRuntime,
    const std::uint32_t requestedCapacity
  )
  {
    if (requestedCapacity > kLegacyDwordVectorMaxCount) {
      throw std::length_error("vector<T> too long");
    }

    std::uint32_t* const storage = AllocateLegacyDwordVectorStorage(requestedCapacity);
    vectorRuntime.begin = storage;
    vectorRuntime.end = storage;
    vectorRuntime.capacityEnd = storage + requestedCapacity;
    return true;
  }

  /**
   * Address: 0x00498F20 (FUN_00498F20, nullsub_577)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  void NoOpHelperThunkV() noexcept {}

  /**
   * Address: 0x00498F60 (FUN_00498F60, sub_498F60)
   *
   * What it does:
   * Duplicate range-fill helper that writes one scalar `uint32_t` to each
   * element and returns the end iterator.
   */
  [[nodiscard]] std::uint32_t* FillDwordRangeFromScalarSlotB(
    const std::uint32_t* const valueSlot,
    std::uint32_t* destination,
    std::int32_t count
  ) noexcept
  {
    while (count > 0) {
      *destination++ = *valueSlot;
      --count;
    }
    return destination;
  }

  /**
   * Address: 0x00498F90 (FUN_00498F90, nullsub_578)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  void NoOpHelperThunkW(const std::uint32_t /*unused*/) noexcept {}

  /**
   * Address: 0x00498FA0 (FUN_00498FA0, nullsub_579)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  void NoOpHelperThunkX() noexcept {}

  /**
   * Address: 0x00498FC0 (FUN_00498FC0, sub_498FC0)
   *
   * What it does:
   * Duplicate `uint32_t` slot writer helper retained for callsite parity.
   */
  std::uint32_t* WriteScalarDwordSlotD(std::uint32_t* const outValueSlot, const std::uint32_t value) noexcept
  {
    *outValueSlot = value;
    return outValueSlot;
  }

  /**
   * Address: 0x00498FD0 (FUN_00498FD0, sub_498FD0)
   *
   * What it does:
   * Duplicate `uint32_t` slot reader helper retained for callsite parity.
   */
  [[nodiscard]] std::uint32_t ReadScalarDwordSlotD(const std::uint32_t* const valueSlot) noexcept
  {
    return *valueSlot;
  }

  /**
   * Address: 0x00499010 (FUN_00499010, sub_499010)
   *
   * What it does:
   * Writes one 32-bit scalar value into caller-provided slot and returns that
   * slot pointer.
   */
  std::uint32_t* WriteScalarDwordSlotE(std::uint32_t* const outValueSlot, const std::uint32_t value) noexcept
  {
    *outValueSlot = value;
    return outValueSlot;
  }

  /**
   * Address: 0x00499020 (FUN_00499020, sub_499020)
   *
   * What it does:
   * Reads one 32-bit scalar value from caller-provided slot.
   */
  [[nodiscard]] std::uint32_t ReadScalarDwordSlotE(const std::uint32_t* const valueSlot) noexcept
  {
    return *valueSlot;
  }

  /**
   * Address: 0x00499060 (FUN_00499060, sub_499060)
   *
   * What it does:
   * Duplicate 32-bit scalar slot writer retained for callsite parity.
   */
  std::uint32_t* WriteScalarDwordSlotF(std::uint32_t* const outValueSlot, const std::uint32_t value) noexcept
  {
    *outValueSlot = value;
    return outValueSlot;
  }

  /**
   * Address: 0x00499080 (FUN_00499080, sub_499080)
   *
   * What it does:
   * Duplicate 32-bit scalar slot reader retained for callsite parity.
   */
  [[nodiscard]] std::uint32_t ReadScalarDwordSlotF(const std::uint32_t* const valueSlot) noexcept
  {
    return *valueSlot;
  }

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
   * Address: 0x00499240 (FUN_00499240, sub_499240)
   *
   * What it does:
   * Returns one fixed legacy magic constant used by adjacent vector helpers.
   */
  [[nodiscard]] std::uint32_t GetLegacyDivisionMagicConstant_0x1D41D41() noexcept
  {
    return 0x01D41D41U;
  }

  /**
   * Address: 0x00499560 (FUN_00499560, sub_499560)
   *
   * What it does:
   * Throws `std::length_error` with the legacy vector overflow message.
   */
  [[noreturn]] void ThrowLegacyVectorTooLong()
  {
    throw std::length_error("vector<T> too long");
  }

  /**
   * Address: 0x004995E0 (FUN_004995E0, nullsub_580)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  void NoOpHelperThunkY() noexcept {}

  /**
   * Address: 0x00499620 (FUN_00499620, sub_499620)
   *
   * What it does:
   * Returns one fixed legacy magic constant used by adjacent growth/division
   * helper paths.
   */
  [[nodiscard]] std::uint32_t GetLegacyDivisionMagicConstant_0x2AAAAAA() noexcept
  {
    return 0x02AAAAAAU;
  }

  /**
   * Address: 0x00499910 (FUN_00499910, sub_499910)
   *
   * What it does:
   * Duplicate vector-overflow throw helper retained for callsite parity.
   */
  [[noreturn]] void ThrowLegacyVectorTooLongDuplicateA()
  {
    ThrowLegacyVectorTooLong();
  }

  /**
   * Address: 0x00499990 (FUN_00499990, nullsub_581)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  void NoOpHelperThunkZ() noexcept {}

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
   * Address: 0x004999D0 (FUN_004999D0, sub_4999D0)
   *
   * What it does:
   * Exports the second dword lane (`+0x04`) from one triple-dword runtime
   * block into caller storage.
   */
  std::uint32_t* ExportLegacyTripleDwordValue1(
    std::uint32_t* const outValueSlot,
    const LegacyTripleDwordRuntime& source
  ) noexcept
  {
    *outValueSlot = source.value1;
    return outValueSlot;
  }

  /**
   * Address: 0x004999E0 (FUN_004999E0, sub_4999E0)
   *
   * What it does:
   * Exports the third dword lane (`+0x08`) from one triple-dword runtime block
   * into caller storage.
   */
  std::uint32_t* ExportLegacyTripleDwordValue2(
    std::uint32_t* const outValueSlot,
    const LegacyTripleDwordRuntime& source
  ) noexcept
  {
    *outValueSlot = source.value2;
    return outValueSlot;
  }

  /**
   * Address: 0x004999F0 (FUN_004999F0, sub_4999F0)
   *
   * What it does:
   * Returns one fixed legacy magic constant used by adjacent growth/division
   * helper paths.
   */
  [[nodiscard]] std::uint32_t GetLegacyDivisionMagicConstant_0x1414141() noexcept
  {
    return 0x01414141U;
  }

  /**
   * Address: 0x00499D50 (FUN_00499D50, sub_499D50)
   *
   * What it does:
   * Duplicate vector-overflow throw helper retained for callsite parity.
   */
  [[noreturn]] void ThrowLegacyVectorTooLongDuplicateB()
  {
    ThrowLegacyVectorTooLong();
  }

  /**
   * Address: 0x0049C680 (FUN_0049C680, sub_49C680)
   *
   * What it does:
   * Allocates one raw trail-segment pool node lane.
   */
  [[nodiscard]] moho::TrailSegmentPoolNodeRuntime* AllocateTrailSegmentPoolNodeRaw()
  {
    return static_cast<moho::TrailSegmentPoolNodeRuntime*>(
      ::operator new(sizeof(moho::TrailSegmentPoolNodeRuntime))
    );
  }

  /**
   * Address: 0x0049C620 (FUN_0049C620, sub_49C620)
   *
   * What it does:
   * Allocates one trail-segment pool node and initializes the three link lanes
   * to null with default black/non-sentinel flags.
   */
  [[nodiscard]] moho::TrailSegmentPoolNodeRuntime* AllocateTrailSegmentPoolNodeWithNullLinksBlack()
  {
    moho::TrailSegmentPoolNodeRuntime* const node = AllocateTrailSegmentPoolNodeRaw();
    node->left = nullptr;
    node->parent = nullptr;
    node->right = nullptr;
    node->segmentBuffer = nullptr;
    node->color = 1U;
    node->isNil = 0U;
    node->padding12 = 0U;
    return node;
  }

  /**
   * Address: 0x0049C660 (FUN_0049C660, nullsub_602)
   *
   * What it does:
   * No-op stdcall helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkStdcallB(const std::uint32_t /*unused*/) noexcept {}

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

  /**
   * Address: 0x0049C6A0 (FUN_0049C6A0, nullsub_603)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkAF() noexcept {}

  [[nodiscard]] moho::TrailSegmentPoolNodeRuntime* AllocateTrailSegmentPoolHeadNode()
  {
    auto* const head = AllocateTrailSegmentPoolNodeWithNullLinksBlack();
    head->left = head;
    head->parent = head;
    head->right = head;
    head->segmentBuffer = nullptr;
    head->color = 1U;
    head->isNil = 1U;
    head->padding12 = 0U;
    return head;
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

  void InitializeParticleBufferPoolList(moho::ParticleBufferPoolListRuntime& listRuntime)
  {
    if (listRuntime.head == nullptr) {
      listRuntime.head = AllocateParticleBufferPoolHeadNode();
    } else {
      listRuntime.head->next = listRuntime.head;
      listRuntime.head->prev = listRuntime.head;
      listRuntime.head->value = nullptr;
    }
    listRuntime.size = 0U;
  }

  void InitializeTrailSegmentPool(moho::TrailSegmentPoolRuntime& poolRuntime)
  {
    if (poolRuntime.head == nullptr) {
      poolRuntime.head = AllocateTrailSegmentPoolHeadNode();
    } else {
      poolRuntime.head->left = poolRuntime.head;
      poolRuntime.head->parent = poolRuntime.head;
      poolRuntime.head->right = poolRuntime.head;
      poolRuntime.head->segmentBuffer = nullptr;
      poolRuntime.head->color = 1U;
      poolRuntime.head->isNil = 1U;
      poolRuntime.head->padding12 = 0U;
    }
    poolRuntime.size = 0U;
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
  [[maybe_unused]] ParticleBucketTreeEntryNodeRuntime* MoveParticleBucketIteratorToNext(
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
  [[maybe_unused]] TrailBucketTreeEntryNodeRuntime* MoveTrailBucketIteratorToNext(
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
  [[maybe_unused]] ParticleBucketTreeEntryNodeRuntime* MoveParticleBucketIteratorToNextDuplicate(
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
  [[maybe_unused]] TrailBucketTreeEntryNodeRuntime* MoveTrailBucketIteratorToNextDuplicate(
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
  [[maybe_unused]] ParticleBucketTreeEntryNodeRuntime* MoveParticleBucketIteratorToNextDuplicateB(
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
  [[maybe_unused]] TrailBucketTreeEntryNodeRuntime* MoveTrailBucketIteratorToNextDuplicateB(
    TrailBucketTreeEntryNodeRuntime** const inOutNode
  ) noexcept
  {
    return MoveTrailBucketIteratorToNext(inOutNode);
  }

  /**
   * Address: 0x0049E050 (FUN_0049E050, nullsub_625)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkAT() noexcept {}

  /**
   * Address: 0x0049E060 (FUN_0049E060, nullsub_626)
   *
   * What it does:
   * Duplicate no-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkAU() noexcept {}

  /**
   * Address: 0x0049E0A0 (FUN_0049E0A0, sub_49E0A0)
   *
   * What it does:
   * Writes one pointer-sized scalar value into caller-provided output storage.
   */
  std::uintptr_t* WritePointerSizedScalar(std::uintptr_t* const outValue, const std::uintptr_t value) noexcept
  {
    *outValue = value;
    return outValue;
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
  [[maybe_unused]] ParticleBucketKeyValueRuntime* CopyConstructParticleBucketKeyValueFromKeyAndBucketSlot(
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
  [[maybe_unused]] ParticleBucketKeyValueRuntime* CopyConstructParticleBucketKeyValueAndReleaseSource(
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
   * Address: 0x0049E140 (FUN_0049E140, sub_49E140)
   *
   * What it does:
   * Writes one compact `(pointer, byte-flag)` lane into caller storage.
   */
  [[maybe_unused]] PointerByteFlagPairRuntime* WritePointerByteFlagPairDirectA(
    PointerByteFlagPairRuntime* const outPair,
    void* const pointer,
    const std::uint8_t flag
  ) noexcept
  {
    outPair->pointer = pointer;
    outPair->flag = flag;
    return outPair;
  }

  /**
   * What it does:
   * Compact `(uint32, uint32)` lane used by adjacent slot-writer thunks.
   */
  struct DwordPairRuntime
  {
    std::uint32_t value0 = 0U; // +0x00
    std::uint32_t value1 = 0U; // +0x04
  };

  static_assert(offsetof(DwordPairRuntime, value1) == 0x04, "DwordPairRuntime::value1 offset must be 0x04");
  static_assert(sizeof(DwordPairRuntime) == 0x08, "DwordPairRuntime size must be 0x08");

  /**
   * Address: 0x0049E1A0 (FUN_0049E1A0, sub_49E1A0)
   *
   * What it does:
   * Writes two dword lanes into caller output storage.
   */
  [[maybe_unused]] DwordPairRuntime* WriteDwordPairRuntimeA(
    DwordPairRuntime* const outPair,
    const std::uint32_t value0,
    const std::uint32_t value1
  ) noexcept
  {
    outPair->value0 = value0;
    outPair->value1 = value1;
    return outPair;
  }

  /**
   * Address: 0x0049E1E0 (FUN_0049E1E0, sub_49E1E0)
   *
   * What it does:
   * Writes one dword lane into caller output storage.
   */
  [[maybe_unused]] std::uint32_t* WriteDwordSlotFromRegisterLike(
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
  [[maybe_unused]] TrailBucketKeyValueRuntime* CopyConstructTrailBucketKeyValueFromKeyAndBucketSlot(
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
  [[maybe_unused]] TrailBucketKeyValueRuntime* CopyConstructTrailBucketKeyValueAndReleaseSource(
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
   * Address: 0x0049E280 (FUN_0049E280, sub_49E280)
   *
   * What it does:
   * Duplicate compact `(pointer, byte-flag)` lane writer.
   */
  [[maybe_unused]] PointerByteFlagPairRuntime* WritePointerByteFlagPairDirectB(
    PointerByteFlagPairRuntime* const outPair,
    void* const pointer,
    const std::uint8_t flag
  ) noexcept
  {
    return WritePointerByteFlagPairDirectA(outPair, pointer, flag);
  }

  /**
   * Address: 0x0049E2E0 (FUN_0049E2E0, sub_49E2E0)
   *
   * What it does:
   * Duplicate two-dword lane writer.
   */
  [[maybe_unused]] DwordPairRuntime* WriteDwordPairRuntimeB(
    DwordPairRuntime* const outPair,
    const std::uint32_t value0,
    const std::uint32_t value1
  ) noexcept
  {
    return WriteDwordPairRuntimeA(outPair, value0, value1);
  }

  /**
   * Address: 0x0049E150 (FUN_0049E150, sub_49E150)
   *
   * What it does:
   * Walks one particle-bucket node iterator range, destroying mapped bucket
   * payloads while preserving key-node ownership for caller erase helpers.
   */
  [[maybe_unused]] ParticleBucketTreeEntryNodeRuntime* DestroyParticleBucketPayloadRange(
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
  [[maybe_unused]] TrailBucketTreeEntryNodeRuntime* DestroyTrailBucketPayloadRange(
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
   * Address: 0x0049E330 (FUN_0049E330, nullsub_627)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkAV() noexcept {}

  /**
   * Address: 0x0049E3A0 (FUN_0049E3A0, nullsub_628)
   *
   * What it does:
   * Duplicate no-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkAW() noexcept {}

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
   * Address: 0x0049AA50 (FUN_0049AA50, sub_49AA50)
   *
   * What it does:
   * Reads one 32-bit scalar directly from caller-provided storage.
   */
  [[nodiscard]] std::uint32_t ReadDwordSlotValueDirectA(const std::uint32_t* const valueSlot) noexcept
  {
    return *valueSlot;
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
  [[maybe_unused]] void DestroyAndDeleteParticleRenderBucket(moho::ParticleRenderBucketRuntime* const bucket) noexcept
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
  [[maybe_unused]] void DestroyAndDeleteTrailRenderBucket(moho::TrailRenderBucketRuntime* const bucket) noexcept
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
   * Address: 0x0049AA20 (FUN_0049AA20, sub_49AA20)
   *
   * What it does:
   * Copies one 32-bit scalar from source slot into caller output storage.
   */
  std::uint32_t* CopyDwordSlotValueFromPointer(
    std::uint32_t* const outValue,
    const std::uint32_t* const sourceValue
  ) noexcept
  {
    *outValue = *sourceValue;
    return outValue;
  }

  /**
   * Address: 0x0049AA30 (FUN_0049AA30, sub_49AA30)
   *
   * What it does:
   * Writes one 32-bit scalar into caller output storage.
   */
  std::uint32_t* WriteDwordSlotValueDirect(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    *outValue = value;
    return outValue;
  }

  /**
   * Address: 0x0049ACC0 (FUN_0049ACC0, sub_49ACC0)
   *
   * What it does:
   * Duplicate 32-bit scalar copy helper retained for binary parity.
   */
  std::uint32_t* CopyDwordSlotValueFromPointerDuplicate(
    std::uint32_t* const outValue,
    const std::uint32_t* const sourceValue
  ) noexcept
  {
    *outValue = *sourceValue;
    return outValue;
  }

  /**
   * Address: 0x0049ACD0 (FUN_0049ACD0, sub_49ACD0)
   *
   * What it does:
   * Duplicate 32-bit scalar write helper retained for binary parity.
   */
  std::uint32_t* WriteDwordSlotValueDirectDuplicateA(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    *outValue = value;
    return outValue;
  }

  /**
   * Address: 0x0049ACF0 (FUN_0049ACF0, sub_49ACF0)
   *
   * What it does:
   * Reads one duplicate 32-bit scalar lane from caller-provided storage.
   */
  [[nodiscard]] std::uint32_t ReadDwordSlotValueDirectB(const std::uint32_t* const valueSlot) noexcept
  {
    return *valueSlot;
  }

  /**
   * Address: 0x0049AD00 (FUN_0049AD00, sub_49AD00)
   *
   * What it does:
   * Writes one duplicate 32-bit scalar lane into caller-provided storage.
   */
  std::uint32_t* WriteDwordSlotValueDirectDuplicateB(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    *outValue = value;
    return outValue;
  }

  /**
   * Address: 0x0049CD30 (FUN_0049CD30, nullsub_607)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkAJ() noexcept {}

  /**
   * Address: 0x0049CD60 (FUN_0049CD60, nullsub_608)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkAK() noexcept {}

  /**
   * Address: 0x0049CD80 (FUN_0049CD80, sub_49CD80)
   *
   * What it does:
   * Writes one duplicate 32-bit scalar lane into caller-provided storage.
   */
  [[maybe_unused]] std::uint32_t* WriteDwordSlotValueDirectDuplicateC(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    *outValue = value;
    return outValue;
  }

  /**
   * Address: 0x0049CE00 (FUN_0049CE00, sub_49CE00)
   *
   * What it does:
   * Returns one fixed legacy max-count constant (`0x1FFFFFFF`).
   */
  [[maybe_unused]] std::uint32_t GetLegacyMaxElementCount_0x1FFFFFFF_TrailA() noexcept
  {
    return 0x1FFFFFFFU;
  }

  /**
   * Address: 0x0049CE10 (FUN_0049CE10, sub_49CE10)
   *
   * What it does:
   * Returns one fixed legacy max-count constant (`0x3FFFFFFF`).
   */
  [[maybe_unused]] std::uint32_t GetLegacyMaxElementCount_0x3FFFFFFF_TrailA() noexcept
  {
    return 0x3FFFFFFFU;
  }

  /**
   * Address: 0x0049CE70 (FUN_0049CE70, sub_49CE70)
   *
   * What it does:
   * Duplicate legacy max-count constant helper (`0x1FFFFFFF`).
   */
  [[maybe_unused]] std::uint32_t GetLegacyMaxElementCount_0x1FFFFFFF_TrailB() noexcept
  {
    return 0x1FFFFFFFU;
  }

  /**
   * Address: 0x0049CE80 (FUN_0049CE80, sub_49CE80)
   *
   * What it does:
   * Duplicate legacy max-count constant helper (`0x3FFFFFFF`).
   */
  [[maybe_unused]] std::uint32_t GetLegacyMaxElementCount_0x3FFFFFFF_TrailB() noexcept
  {
    return 0x3FFFFFFFU;
  }

  /**
   * Address: 0x0049CEF0 (FUN_0049CEF0, sub_49CEF0)
   *
   * What it does:
   * Writes one duplicate 32-bit scalar lane into caller-provided storage.
   */
  [[maybe_unused]] std::uint32_t* WriteDwordSlotValueDirectDuplicateD(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    *outValue = value;
    return outValue;
  }

  /**
   * Address: 0x0049D050 (FUN_0049D050, nullsub_613)
   *
   * What it does:
   * No-op stdcall helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkStdcallD(const std::uint32_t /*unused*/) noexcept {}

  /**
   * Address: 0x0049D080 (FUN_0049D080, sub_49D080)
   *
   * What it does:
   * Returns one fixed legacy max-count constant (`0x3FFFFFFF`).
   */
  [[maybe_unused]] std::uint32_t GetLegacyMaxElementCount_0x3FFFFFFF_TrailC() noexcept
  {
    return 0x3FFFFFFFU;
  }

  /**
   * Address: 0x0049D090 (FUN_0049D090, nullsub_614)
   *
   * What it does:
   * No-op stdcall helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkStdcallE(const std::uint32_t /*unused*/) noexcept {}

  /**
   * Address: 0x0049DA20 (FUN_0049DA20, sub_49DA20)
   *
   * What it does:
   * Returns one fixed legacy map helper constant (`0x03FFFFFF`).
   */
  [[maybe_unused]] std::uint32_t GetLegacyMapHelperConstant_0x03FFFFFF_DuplicateA() noexcept
  {
    return 0x03FFFFFFU;
  }

  /**
   * Address: 0x0049D0C0 (FUN_0049D0C0, sub_49D0C0)
   *
   * What it does:
   * Returns one fixed legacy map helper constant (`0x03FFFFFF`).
  */
  [[maybe_unused]] std::uint32_t GetLegacyMapHelperConstant_0x03FFFFFF() noexcept
  {
    return 0x03FFFFFFU;
  }

  /**
   * Address: 0x0049D510 (FUN_0049D510, sub_49D510)
   *
   * What it does:
   * Returns one fixed legacy map helper constant (`0x04924924`).
   */
  [[maybe_unused]] std::uint32_t GetLegacyMapHelperConstant_0x04924924() noexcept
  {
    return 0x04924924U;
  }

  /**
   * Address: 0x0049DAF0 (FUN_0049DAF0, sub_49DAF0)
   *
   * What it does:
   * Returns one fixed legacy map helper constant (`0x04924924`).
   */
  [[maybe_unused]] std::uint32_t GetLegacyMapHelperConstant_0x04924924_DuplicateA() noexcept
  {
    return 0x04924924U;
  }

  /**
   * Address: 0x0049DB80 (FUN_0049DB80, nullsub_621)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkAP() noexcept {}

  /**
   * Address: 0x0049DB90 (FUN_0049DB90, nullsub_622)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkAQ() noexcept {}

  /**
   * Address: 0x0049DBA0 (FUN_0049DBA0, nullsub_623)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkAR() noexcept {}

  /**
   * Address: 0x0049DBB0 (FUN_0049DBB0, nullsub_624)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkAS() noexcept {}

  /**
   * Address: 0x0049EC90 (FUN_0049EC90, nullsub_641)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkAX() noexcept {}

  /**
   * Address: 0x0049ECB0 (FUN_0049ECB0, nullsub_642)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkAY() noexcept {}

  /**
   * Address: 0x0049EF40 (FUN_0049EF40, sub_49EF40)
   *
   * What it does:
   * Compares one compact pointer+flag pair by its packed dword at offset
   * `+0x04`.
   */
  [[maybe_unused]] bool IsPointerByteFlagPairOffset4LessThan(
    const PointerByteFlagPairRuntime& lhs,
    const PointerByteFlagPairRuntime& rhs
  ) noexcept
  {
    std::uint32_t lhsPacked = 0U;
    std::uint32_t rhsPacked = 0U;
    std::memcpy(&lhsPacked, &lhs.flag, sizeof(lhsPacked));
    std::memcpy(&rhsPacked, &rhs.flag, sizeof(rhsPacked));
    return lhsPacked < rhsPacked;
  }

  /**
   * Address: 0x0049EF50 (FUN_0049EF50, sub_49EF50)
   *
   * What it does:
   * Returns whether one legacy string equals one NUL-terminated C-string by
   * exact length+payload comparison.
   */
  [[maybe_unused]] bool IsMsvc8StringEqualToCStringExact(const msvc8::string& lhs, const char* const rhs)
  {
    const std::size_t rhsLength = std::strlen(rhs);
    if (lhs.size() != rhsLength) {
      return false;
    }

    return rhsLength == 0U || std::memcmp(lhs.data(), rhs, rhsLength) == 0;
  }

  /**
   * Address: 0x0049EF80 (FUN_0049EF80, sub_49EF80)
   *
   * What it does:
   * Returns whether two dword slots store equal values.
   */
  [[maybe_unused]] bool AreDwordSlotsEqualA(const std::uint32_t* const lhs, const std::uint32_t* const rhs) noexcept
  {
    return *lhs == *rhs;
  }

  /**
   * Address: 0x0049EF90 (FUN_0049EF90, sub_49EF90)
   *
   * What it does:
   * Duplicate dword-slot equality comparator retained for callsite parity.
   */
  [[maybe_unused]] bool AreDwordSlotsEqualB(const std::uint32_t* const lhs, const std::uint32_t* const rhs) noexcept
  {
    return *lhs == *rhs;
  }

  /**
   * Address: 0x0049EFA0 (FUN_0049EFA0, nullsub_643)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkAZ() noexcept {}

  /**
   * Address: 0x0049EFB0 (FUN_0049EFB0, sub_49EFB0)
   *
   * What it does:
   * Returns byte lane `+1` from one packed dword value.
   */
  [[maybe_unused]] std::uint8_t ReadSecondByteFromDwordA(const std::uint32_t value) noexcept
  {
    return static_cast<std::uint8_t>((value >> 8U) & 0xFFU);
  }

  void CopyAssignWorldParticleForVectorMoveLocal(
    const moho::SWorldParticle& source,
    moho::SWorldParticle& destination
  ) noexcept;

  void CopyConstructWorldParticleForVectorMoveLocal(
    const moho::SWorldParticle& source,
    moho::SWorldParticle& destination
  );

  void DestroyWorldParticleForVectorTailLocal(moho::SWorldParticle& particle) noexcept;

  void CopyTrailRuntimeViewForVectorMoveLocal(
    const moho::TrailRuntimeView& source,
    moho::TrailRuntimeView& destination
  ) noexcept;

  void CopyConstructTrailRuntimeViewForVectorMoveLocal(
    const moho::TrailRuntimeView& source,
    moho::TrailRuntimeView& destination
  ) noexcept;

  void CopyWorldBeamForVectorMoveLocal(
    const moho::SWorldBeam& source,
    moho::SWorldBeam& destination
  ) noexcept;

  void CopyConstructWorldBeamForVectorMoveLocal(
    const moho::SWorldBeam& source,
    moho::SWorldBeam& destination
  ) noexcept;

  /**
   * Address: 0x0049EFC0 (FUN_0049EFC0, sub_49EFC0)
   *
   * What it does:
   * Copies one world-particle range into pre-constructed destination storage and
   * returns destination end.
   */
  [[maybe_unused]] moho::SWorldParticle* CopyAssignedWorldParticleRangeAndReturnEnd(
    moho::SWorldParticle* destination,
    const moho::SWorldParticle* sourceBegin,
    const moho::SWorldParticle* const sourceEnd
  )
  {
    while (sourceBegin != sourceEnd) {
      CopyAssignWorldParticleForVectorMoveLocal(*sourceBegin, *destination);
      ++destination;
      ++sourceBegin;
    }
    return destination;
  }

  /**
   * Address: 0x0049EFF0 (FUN_0049EFF0, nullsub_644)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkBA() noexcept {}

  /**
   * Address: 0x0049F000 (FUN_0049F000, sub_49F000)
   *
   * What it does:
   * Duplicate packed-dword byte-lane (`+1`) reader.
   */
  [[maybe_unused]] std::uint8_t ReadSecondByteFromDwordB(const std::uint32_t value) noexcept
  {
    return static_cast<std::uint8_t>((value >> 8U) & 0xFFU);
  }

  /**
   * Address: 0x0049F010 (FUN_0049F010, sub_49F010)
   *
   * What it does:
   * Copies one trail-runtime range into pre-constructed destination storage and
   * returns destination end.
   */
  [[maybe_unused]] moho::TrailRuntimeView* CopyAssignedTrailRuntimeRangeAndReturnEnd(
    moho::TrailRuntimeView* destination,
    const moho::TrailRuntimeView* sourceBegin,
    const moho::TrailRuntimeView* const sourceEnd
  )
  {
    while (sourceBegin != sourceEnd) {
      CopyTrailRuntimeViewForVectorMoveLocal(*sourceBegin, *destination);
      ++destination;
      ++sourceBegin;
    }
    return destination;
  }

  /**
   * Address: 0x0049F040 (FUN_0049F040, nullsub_645)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkBB() noexcept {}

  /**
   * Address: 0x0049F050 (FUN_0049F050, sub_49F050)
   *
   * What it does:
   * Duplicate packed-dword byte-lane (`+1`) reader.
   */
  [[maybe_unused]] std::uint8_t ReadSecondByteFromDwordC(const std::uint32_t value) noexcept
  {
    return static_cast<std::uint8_t>((value >> 8U) & 0xFFU);
  }

  /**
   * Address: 0x0049F060 (FUN_0049F060, sub_49F060)
   *
   * What it does:
   * Moves `dwordCount` dword elements and returns caller-provided token.
   */
  [[maybe_unused]] std::uintptr_t MoveDwordRangeByCountAndReturnTokenA(
    const std::uint32_t* const source,
    std::uint32_t* const destination,
    const std::uint32_t dwordCount,
    const std::uintptr_t returnToken
  ) noexcept
  {
    const std::size_t byteCount = static_cast<std::size_t>(dwordCount) * sizeof(std::uint32_t);
    memmove_s(destination, byteCount, source, byteCount);
    return returnToken;
  }

  /**
   * Address: 0x0049F080 (FUN_0049F080, sub_49F080)
   *
   * What it does:
   * Moves one dword range identified by begin/end pointers and returns
   * destination end.
   */
  [[maybe_unused]] std::uint32_t* MoveDwordRangeByEndPointerAndReturnEndA(
    std::uint32_t* const destination,
    const std::uint32_t* const sourceBegin,
    const std::uint32_t* const sourceEnd
  ) noexcept
  {
    const std::size_t dwordCount = static_cast<std::size_t>(sourceEnd - sourceBegin);
    const std::size_t byteCount = dwordCount * sizeof(std::uint32_t);
    if (byteCount != 0U) {
      memmove_s(destination, byteCount, sourceBegin, byteCount);
    }
    return destination + dwordCount;
  }

  /**
   * Address: 0x0049F0B0 (FUN_0049F0B0, nullsub_646)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkBC() noexcept {}

  /**
   * Address: 0x0049F0C0 (FUN_0049F0C0, sub_49F0C0)
   *
   * What it does:
   * Duplicate packed-dword byte-lane (`+1`) reader.
   */
  [[maybe_unused]] std::uint8_t ReadSecondByteFromDwordD(const std::uint32_t value) noexcept
  {
    return static_cast<std::uint8_t>((value >> 8U) & 0xFFU);
  }

  /**
   * Address: 0x0049F0D0 (FUN_0049F0D0, sub_49F0D0)
   *
   * What it does:
   * Duplicate dword-range move-by-count helper that returns caller token.
   */
  [[maybe_unused]] std::uintptr_t MoveDwordRangeByCountAndReturnTokenB(
    const std::uint32_t* const source,
    std::uint32_t* const destination,
    const std::uint32_t dwordCount,
    const std::uintptr_t returnToken
  ) noexcept
  {
    return MoveDwordRangeByCountAndReturnTokenA(source, destination, dwordCount, returnToken);
  }

  /**
   * Address: 0x0049F0F0 (FUN_0049F0F0, sub_49F0F0)
   *
   * What it does:
   * Duplicate dword-range move-by-end-pointer helper.
   */
  [[maybe_unused]] std::uint32_t* MoveDwordRangeByEndPointerAndReturnEndB(
    std::uint32_t* const destination,
    const std::uint32_t* const sourceBegin,
    const std::uint32_t* const sourceEnd
  ) noexcept
  {
    return MoveDwordRangeByEndPointerAndReturnEndA(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x0049F120 (FUN_0049F120, sub_49F120)
   *
   * What it does:
   * Destroys one contiguous world-particle range.
   */
  [[maybe_unused]] void DestroyWorldParticleRange(
    moho::SWorldParticle* begin,
    moho::SWorldParticle* const end
  ) noexcept
  {
    while (begin != end) {
      DestroyWorldParticleForVectorTailLocal(*begin);
      ++begin;
    }
  }

  /**
   * Address: 0x0049F140 (FUN_0049F140, sub_49F140)
   *
   * What it does:
   * Copy-constructs `count` world-particle instances from one source particle
   * into destination storage with rollback on constructor failure.
   */
  [[maybe_unused]] void CopyConstructWorldParticleFillCountOrRollback(
    const moho::SWorldParticle& source,
    std::uint32_t count,
    moho::SWorldParticle* destination
  )
  {
    moho::SWorldParticle* const rollbackBegin = destination;
    moho::SWorldParticle* write = destination;

    try {
      while (count != 0U) {
        if (write != nullptr) {
          CopyConstructWorldParticleForVectorMoveLocal(source, *write);
        }
        ++write;
        --count;
      }
    } catch (...) {
      DestroyWorldParticleRange(rollbackBegin, write);
      throw;
    }
  }

  /**
   * Address: 0x0049DF80 (FUN_0049DF80, sub_49DF80)
   *
   * What it does:
   * Thin forwarding wrapper for world-particle fill-count copy construction.
   */
  [[maybe_unused]] void ForwardCopyConstructWorldParticleFillCount(
    const moho::SWorldParticle& source,
    const std::uint32_t count,
    moho::SWorldParticle* const destination
  )
  {
    CopyConstructWorldParticleFillCountOrRollback(source, count, destination);
  }

  void AddReferenceParticleTextureIfPresentLocal(moho::CParticleTexture* const texture) noexcept
  {
    if (texture != nullptr) {
      texture->AddReferenceAtomic();
    }
  }

  void CopyAssignWorldParticleForVectorMoveLocal(
    const moho::SWorldParticle& source,
    moho::SWorldParticle& destination
  ) noexcept
  {
    static_assert(
      offsetof(moho::SWorldParticle, mTexture) == 0x5C,
      "SWorldParticle::mTexture offset must remain stable for runtime copy helpers."
    );

    std::memcpy(
      static_cast<void*>(&destination),
      static_cast<const void*>(&source),
      offsetof(moho::SWorldParticle, mTexture)
    );

    (void)moho::AssignCountedParticleTexturePtr(&destination.mTexture, source.mTexture.tex);
    (void)moho::AssignCountedParticleTexturePtr(&destination.mRampTexture, source.mRampTexture.tex);
    destination.mTypeTag = source.mTypeTag;
    destination.mArmyIndex = source.mArmyIndex;
    destination.mBlendMode = source.mBlendMode;
    destination.mZMode = source.mZMode;
  }

  void CopyConstructWorldParticleForVectorMoveLocal(
    const moho::SWorldParticle& source,
    moho::SWorldParticle& destination
  )
  {
    static_assert(
      offsetof(moho::SWorldParticle, mTexture) == 0x5C,
      "SWorldParticle::mTexture offset must remain stable for runtime copy helpers."
    );

    std::memcpy(
      static_cast<void*>(&destination),
      static_cast<const void*>(&source),
      offsetof(moho::SWorldParticle, mTexture)
    );

    destination.mTexture.tex = source.mTexture.tex;
    AddReferenceParticleTextureIfPresentLocal(destination.mTexture.tex);
    destination.mRampTexture.tex = source.mRampTexture.tex;
    AddReferenceParticleTextureIfPresentLocal(destination.mRampTexture.tex);

    ::new (static_cast<void*>(&destination.mTypeTag)) msvc8::string();
    destination.mTypeTag = source.mTypeTag;
    destination.mArmyIndex = source.mArmyIndex;
    destination.mBlendMode = source.mBlendMode;
    destination.mZMode = source.mZMode;
  }

  void DestroyWorldParticleForVectorTailLocal(moho::SWorldParticle& particle) noexcept
  {
    particle.mTypeTag.~string();
    moho::ResetCountedParticleTexturePtr(particle.mRampTexture);
    moho::ResetCountedParticleTexturePtr(particle.mTexture);
  }

  void AssignTrailRuntimeTextureLaneLocal(
    moho::CParticleTexture*& destination,
    moho::CParticleTexture* const source
  ) noexcept
  {
    if (destination == source) {
      return;
    }

    if (destination != nullptr) {
      destination->ReleaseReferenceAtomic();
    }
    destination = source;
    if (source != nullptr) {
      source->AddReferenceAtomic();
    }
  }

  void CopyTrailRuntimeViewForVectorMoveLocal(
    const moho::TrailRuntimeView& source,
    moho::TrailRuntimeView& destination
  ) noexcept
  {
    std::memcpy(destination.unknownPrefix, source.unknownPrefix, sizeof(destination.unknownPrefix));
    destination.sortScalar = source.sortScalar;
    std::memcpy(destination.unknown4C, source.unknown4C, sizeof(destination.unknown4C));
    AssignTrailRuntimeTextureLaneLocal(destination.texture0, source.texture0);
    AssignTrailRuntimeTextureLaneLocal(destination.texture1, source.texture1);
    destination.tag = source.tag;
    destination.uvScalar = source.uvScalar;
  }

  void CopyConstructTrailRuntimeViewForVectorMoveLocal(
    const moho::TrailRuntimeView& source,
    moho::TrailRuntimeView& destination
  ) noexcept
  {
    std::memcpy(
      static_cast<void*>(&destination),
      static_cast<const void*>(&source),
      offsetof(moho::TrailRuntimeView, texture0)
    );

    destination.texture0 = source.texture0;
    AddReferenceParticleTextureIfPresentLocal(destination.texture0);
    destination.texture1 = source.texture1;
    AddReferenceParticleTextureIfPresentLocal(destination.texture1);
    destination.tag = source.tag;
    destination.uvScalar = source.uvScalar;
  }

  void DestroyTrailRuntimeViewForVectorTailLocal(moho::TrailRuntimeView& trail) noexcept
  {
    AssignTrailRuntimeTextureLaneLocal(trail.texture0, nullptr);
    AssignTrailRuntimeTextureLaneLocal(trail.texture1, nullptr);
  }

  void CopyWorldBeamForVectorMoveLocal(
    const moho::SWorldBeam& source,
    moho::SWorldBeam& destination
  ) noexcept
  {
    destination.mCurStart = source.mCurStart;
    destination.mLastStart = source.mLastStart;
    destination.mFromStart = source.mFromStart;
    destination.mCurEnd = source.mCurEnd;
    destination.mLastEnd = source.mLastEnd;
    destination.mLastInterpolation = source.mLastInterpolation;
    destination.mStart = source.mStart;
    destination.mEnd = source.mEnd;
    destination.mWidth = source.mWidth;
    destination.mStartColor = source.mStartColor;
    destination.mEndColor = source.mEndColor;
    (void)moho::AssignCountedParticleTexturePtr(&destination.mTexture1, source.mTexture1.tex);
    (void)moho::AssignCountedParticleTexturePtr(&destination.mTexture2, source.mTexture2.tex);
    destination.mUShift = source.mUShift;
    destination.mVShift = source.mVShift;
    destination.mRepeatRate = source.mRepeatRate;
    destination.mBlendMode = source.mBlendMode;
  }

  void CopyConstructWorldBeamForVectorMoveLocal(
    const moho::SWorldBeam& source,
    moho::SWorldBeam& destination
  ) noexcept
  {
    std::memcpy(
      static_cast<void*>(&destination),
      static_cast<const void*>(&source),
      offsetof(moho::SWorldBeam, mTexture1)
    );

    destination.mTexture1.tex = source.mTexture1.tex;
    AddReferenceParticleTextureIfPresentLocal(destination.mTexture1.tex);
    destination.mTexture2.tex = source.mTexture2.tex;
    AddReferenceParticleTextureIfPresentLocal(destination.mTexture2.tex);
    destination.mUShift = source.mUShift;
    destination.mVShift = source.mVShift;
    destination.mRepeatRate = source.mRepeatRate;
    destination.mBlendMode = source.mBlendMode;
  }

  void DestroyWorldBeamForVectorTailLocal(moho::SWorldBeam& beam) noexcept
  {
    moho::ResetCountedParticleTexturePtr(beam.mTexture1);
    moho::ResetCountedParticleTexturePtr(beam.mTexture2);
  }

  void DestroyWorldBeamRangeForVectorTailLocal(
    moho::SWorldBeam* begin,
    const moho::SWorldBeam* const end
  ) noexcept
  {
    while (begin != end) {
      DestroyWorldBeamForVectorTailLocal(*begin);
      ++begin;
    }
  }

  /**
   * Address: 0x0049F1D0 (FUN_0049F1D0, sub_49F1D0)
   *
   * What it does:
   * Destroys one contiguous trail-runtime range.
   */
  [[maybe_unused]] void DestroyTrailRuntimeViewRangeForVectorTail(
    moho::TrailRuntimeView* begin,
    const moho::TrailRuntimeView* const end
  ) noexcept
  {
    while (begin != end) {
      DestroyTrailRuntimeViewForVectorTailLocal(*begin);
      ++begin;
    }
  }

  /**
   * Address: 0x0049F1F0 (FUN_0049F1F0, sub_49F1F0)
   *
   * What it does:
   * Copy-constructs `count` trail-runtime lanes from one source payload into
   * contiguous destination storage.
   */
  [[maybe_unused]] moho::TrailRuntimeView* CopyConstructTrailRuntimeFillCount(
    moho::TrailRuntimeView* destination,
    std::uint32_t count,
    const moho::TrailRuntimeView& source
  ) noexcept
  {
    moho::TrailRuntimeView* write = destination;
    while (count != 0U) {
      if (write != nullptr) {
        CopyConstructTrailRuntimeViewForVectorMoveLocal(source, *write);
      }
      ++write;
      --count;
    }
    return write;
  }

  /**
   * Address: 0x0049DFC0 (FUN_0049DFC0, sub_49DFC0)
   *
   * What it does:
   * Thin forwarding wrapper for trail-runtime fill-count copy construction.
   */
  [[maybe_unused]] moho::TrailRuntimeView* ForwardCopyConstructTrailRuntimeFillCount(
    moho::TrailRuntimeView* const destination,
    const std::uint32_t count,
    const moho::TrailRuntimeView& source
  ) noexcept
  {
    return CopyConstructTrailRuntimeFillCount(destination, count, source);
  }

  /**
   * Address: 0x004A0150 (FUN_004A0150, sub_4A0150)
   *
   * What it does:
   * Copy-constructs one world-beam range (`[sourceBegin, sourceEnd)`) into
   * destination storage with rollback on copy failure.
   */
  [[maybe_unused]] void CopyConstructWorldBeamRangeOrRollback(
    const moho::SWorldBeam* sourceBegin,
    const moho::SWorldBeam* const sourceEnd,
    moho::SWorldBeam* destination
  )
  {
    moho::SWorldBeam* const rollbackBegin = destination;
    moho::SWorldBeam* write = destination;
    const moho::SWorldBeam* read = sourceBegin;

    try {
      while (read != sourceEnd) {
        if (write != nullptr) {
          CopyConstructWorldBeamForVectorMoveLocal(*read, *write);
        }
        ++write;
        ++read;
      }
    } catch (...) {
      DestroyWorldBeamRangeForVectorTailLocal(rollbackBegin, write);
      throw;
    }
  }

  /**
   * Address: 0x0049DFE0 (FUN_0049DFE0, sub_49DFE0)
   *
   * What it does:
   * Thin forwarding wrapper for world-beam range copy construction.
   */
  [[maybe_unused]] void ForwardCopyConstructWorldBeamRange(
    const moho::SWorldBeam* const sourceBegin,
    const moho::SWorldBeam* const sourceEnd,
    moho::SWorldBeam* const destination
  )
  {
    CopyConstructWorldBeamRangeOrRollback(sourceBegin, sourceEnd, destination);
  }

  /**
   * Address: 0x0049F220 (FUN_0049F220, sub_49F220)
   *
   * What it does:
   * Wrapper thunk for world-beam range copy-construction with rollback.
   */
  [[maybe_unused]] void CopyConstructWorldBeamRangeOrRollbackThunk(
    moho::SWorldBeam* const destination,
    const moho::SWorldBeam* const sourceBegin,
    const moho::SWorldBeam* const sourceEnd
  )
  {
    CopyConstructWorldBeamRangeOrRollback(sourceBegin, sourceEnd, destination);
  }

  /**
   * Address: 0x0049F250 (FUN_0049F250, nullsub_647)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkBD() noexcept {}

  /**
   * Address: 0x0049F260 (FUN_0049F260, sub_49F260)
   *
   * What it does:
   * Duplicate packed-dword byte-lane (`+1`) reader.
   */
  [[maybe_unused]] std::uint8_t ReadSecondByteFromDwordE(const std::uint32_t value) noexcept
  {
    return static_cast<std::uint8_t>((value >> 8U) & 0xFFU);
  }

  /**
   * Address: 0x0049F270 (FUN_0049F270, sub_49F270)
   *
   * What it does:
   * Copy-constructs `count` world-beam instances from one source payload into
   * destination storage with rollback on copy failure.
   */
  [[maybe_unused]] void CopyConstructWorldBeamFillCountOrRollback(
    const moho::SWorldBeam& source,
    std::uint32_t count,
    moho::SWorldBeam* destination
  )
  {
    moho::SWorldBeam* const rollbackBegin = destination;
    moho::SWorldBeam* write = destination;

    try {
      while (count != 0U) {
        if (write != nullptr) {
          CopyConstructWorldBeamForVectorMoveLocal(source, *write);
        }
        ++write;
        --count;
      }
    } catch (...) {
      DestroyWorldBeamRangeForVectorTailLocal(rollbackBegin, write);
      throw;
    }
  }

  /**
   * Address: 0x0049E010 (FUN_0049E010, sub_49E010)
   *
   * What it does:
   * Thin forwarding wrapper for world-beam fill-count copy construction.
   */
  [[maybe_unused]] void ForwardCopyConstructWorldBeamFillCount(
    const moho::SWorldBeam& source,
    const std::uint32_t count,
    moho::SWorldBeam* const destination
  )
  {
    CopyConstructWorldBeamFillCountOrRollback(source, count, destination);
  }

  /**
   * Address: 0x0049F300 (FUN_0049F300, sub_49F300)
   *
   * What it does:
   * Duplicate packed-dword byte-lane (`+1`) reader.
   */
  [[maybe_unused]] std::uint8_t ReadSecondByteFromDwordF(const std::uint32_t value) noexcept
  {
    return static_cast<std::uint8_t>((value >> 8U) & 0xFFU);
  }

  /**
   * Address: 0x0049F310 (FUN_0049F310, sub_49F310)
   *
   * What it does:
   * Writes one repeated 15-float lane into `count` destination blocks and
   * returns destination end.
   */
  [[maybe_unused]] float* FillFifteenFloatLaneAndReturnEnd(
    float* destination,
    std::uint32_t count,
    const float* const sourceLane
  ) noexcept
  {
    float* write = destination;
    while (count != 0U) {
      if (write != nullptr) {
        for (std::size_t i = 0U; i < 15U; ++i) {
          write[i] = sourceLane[i];
        }
      }
      write += 15;
      --count;
    }
    return write;
  }

  /**
   * Address: 0x0049E030 (FUN_0049E030, sub_49E030)
   *
   * What it does:
   * Thin forwarding wrapper for 15-float-lane fill helper.
   */
  [[maybe_unused]] float* ForwardFillFifteenFloatLane(
    float* const destination,
    const std::uint32_t count,
    const float* const sourceLane
  ) noexcept
  {
    return FillFifteenFloatLaneAndReturnEnd(destination, count, sourceLane);
  }

  /**
   * Address: 0x0049F390 (FUN_0049F390, sub_49F390)
   *
   * What it does:
   * Initializes one particle-bucket tree header with a fresh sentinel head.
   */
  [[maybe_unused]] moho::ParticleBucketTreeRuntime* InitializeParticleBucketTreeWithFreshHead(
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
  [[maybe_unused]] void DestroyParticleBucketNodeMappedBucketIfPresent(
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
  [[maybe_unused]] moho::TrailBucketTreeRuntime* InitializeTrailBucketTreeWithFreshHead(
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
  [[maybe_unused]] void DestroyTrailBucketNodeMappedBucketIfPresent(
    TrailBucketTreeEntryNodeRuntime* const node
  ) noexcept
  {
    if (node == nullptr) {
      return;
    }

    DestroyAndDeleteTrailRenderBucket(node->bucket);
  }

  /**
   * Address: 0x0049F450 (FUN_0049F450, nullsub_648)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkBE() noexcept {}

  /**
   * Address: 0x0049F460 (FUN_0049F460, sub_49F460)
   *
   * What it does:
   * Duplicate packed-dword byte-lane (`+1`) reader.
   */
  [[maybe_unused]] std::uint8_t ReadSecondByteFromDwordG(const std::uint32_t value) noexcept
  {
    return static_cast<std::uint8_t>((value >> 8U) & 0xFFU);
  }

  /**
   * Address: 0x0049F470 (FUN_0049F470, sub_49F470)
   *
   * What it does:
   * Copies one dword-pair range (`[sourceBegin, sourceEnd)`) and returns
   * destination end.
   */
  [[maybe_unused]] DwordPairRuntime* CopyDwordPairRangeAndReturnEnd(
    DwordPairRuntime* destination,
    const DwordPairRuntime* sourceBegin,
    const DwordPairRuntime* const sourceEnd
  ) noexcept
  {
    while (sourceBegin != sourceEnd) {
      destination->value0 = sourceBegin->value0;
      destination->value1 = sourceBegin->value1;
      ++destination;
      ++sourceBegin;
    }
    return destination;
  }

  /**
   * Address: 0x0049F490 (FUN_0049F490, sub_49F490)
   *
   * What it does:
   * Writes one repeated dword-pair value across `count` destination elements.
   */
  [[maybe_unused]] DwordPairRuntime* FillDwordPairRangeFromSingleValue(
    DwordPairRuntime* destination,
    const DwordPairRuntime& sourceValue,
    std::uint32_t count
  ) noexcept
  {
    while (count != 0U) {
      if (destination != nullptr) {
        destination->value0 = sourceValue.value0;
        destination->value1 = sourceValue.value1;
      }
      ++destination;
      --count;
    }
    return destination;
  }

  /**
   * Address: 0x0049E310 (FUN_0049E310, sub_49E310)
   *
   * What it does:
   * Thin forwarding wrapper for dword-pair fill helper.
   */
  [[maybe_unused]] DwordPairRuntime* ForwardFillDwordPairRange(
    DwordPairRuntime* const destination,
    const DwordPairRuntime& sourceValue,
    const std::uint32_t count
  ) noexcept
  {
    return FillDwordPairRangeFromSingleValue(destination, sourceValue, count);
  }

  /**
   * Address: 0x0049F4B0 (FUN_0049F4B0, nullsub_649)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkBF() noexcept {}

  /**
   * Address: 0x0049F4C0 (FUN_0049F4C0, sub_49F4C0)
   *
   * What it does:
   * Writes one repeated dword value across `count` destination elements.
   */
  [[maybe_unused]] std::uint32_t* FillDwordRangeFromSingleValue(
    std::uint32_t* destination,
    const std::uint32_t value,
    std::uint32_t count
  ) noexcept
  {
    while (count != 0U) {
      *destination = value;
      ++destination;
      --count;
    }
    return destination;
  }

  /**
   * Address: 0x0049F4E0 (FUN_0049F4E0, nullsub_650)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkBG() noexcept {}

  /**
   * Address: 0x0049F4F0 (FUN_0049F4F0, sub_49F4F0)
   *
   * What it does:
   * Duplicate packed-dword byte-lane (`+1`) reader.
   */
  [[maybe_unused]] std::uint8_t ReadSecondByteFromDwordH(const std::uint32_t value) noexcept
  {
    return static_cast<std::uint8_t>((value >> 8U) & 0xFFU);
  }

  void CopyConstructWorldParticleRangeOrRollbackLocal(
    const moho::SWorldParticle* sourceBegin,
    const moho::SWorldParticle* const sourceEnd,
    moho::SWorldParticle* destination
  )
  {
    moho::SWorldParticle* const rollbackBegin = destination;
    moho::SWorldParticle* write = destination;
    const moho::SWorldParticle* read = sourceBegin;

    try {
      while (read != sourceEnd) {
        if (write != nullptr) {
          CopyConstructWorldParticleForVectorMoveLocal(*read, *write);
        }
        ++read;
        ++write;
      }
    } catch (...) {
      DestroyWorldParticleRange(rollbackBegin, write);
      throw;
    }
  }

  [[nodiscard]] moho::TrailRuntimeView* CopyConstructTrailRuntimeRangeAndReturnEndLocal(
    moho::TrailRuntimeView* destination,
    const moho::TrailRuntimeView* sourceBegin,
    const moho::TrailRuntimeView* const sourceEnd
  ) noexcept
  {
    while (sourceBegin != sourceEnd) {
      if (destination != nullptr) {
        CopyConstructTrailRuntimeViewForVectorMoveLocal(*sourceBegin, *destination);
      }
      ++sourceBegin;
      ++destination;
    }
    return destination;
  }

  [[nodiscard]] float* CopyFifteenFloatLaneRangeAndReturnEndLocal(
    float* destination,
    const float* sourceBegin,
    const float* const sourceEnd
  ) noexcept
  {
    while (sourceBegin != sourceEnd) {
      if (destination != nullptr) {
        for (std::size_t i = 0U; i < 15U; ++i) {
          destination[i] = sourceBegin[i];
        }
      }
      sourceBegin += 15;
      destination += 15;
    }
    return destination;
  }

  [[nodiscard]] float* CopyBackwardFifteenFloatLaneRangeAndReturnBeginLocal(
    float* destinationEnd,
    const float* const sourceBegin,
    const float* sourceEnd
  ) noexcept
  {
    while (sourceEnd != sourceBegin) {
      sourceEnd -= 15;
      destinationEnd -= 15;
      for (std::size_t i = 0U; i < 15U; ++i) {
        destinationEnd[i] = sourceEnd[i];
      }
    }
    return destinationEnd;
  }

  [[nodiscard]] DwordPairRuntime* CopyDwordPairRangeWithNullableDestinationAndReturnEndLocal(
    DwordPairRuntime* destination,
    const DwordPairRuntime* sourceBegin,
    const DwordPairRuntime* const sourceEnd
  ) noexcept
  {
    while (sourceBegin != sourceEnd) {
      if (destination != nullptr) {
        destination->value0 = sourceBegin->value0;
        destination->value1 = sourceBegin->value1;
      }
      ++sourceBegin;
      ++destination;
    }
    return destination;
  }

  [[nodiscard]] DwordPairRuntime* CopyBackwardDwordPairRangeAndReturnBeginLocal(
    DwordPairRuntime* destinationEnd,
    const DwordPairRuntime* const sourceBegin,
    const DwordPairRuntime* sourceEnd
  ) noexcept
  {
    while (sourceEnd != sourceBegin) {
      --sourceEnd;
      --destinationEnd;
      destinationEnd->value0 = sourceEnd->value0;
      destinationEnd->value1 = sourceEnd->value1;
    }
    return destinationEnd;
  }

  [[nodiscard]] std::uint32_t* FillDwordRangeFromPointerValueByEndPointerLocal(
    std::uint32_t* destinationBegin,
    const std::uint32_t* const destinationEnd,
    const std::uint32_t* const sourceValue
  ) noexcept
  {
    if (destinationBegin != destinationEnd) {
      const std::uint32_t value = *sourceValue;
      do {
        *destinationBegin = value;
        ++destinationBegin;
      } while (destinationBegin != destinationEnd);
    }
    return destinationBegin;
  }

  /**
   * Address: 0x0049F500 (FUN_0049F500, sub_49F500)
   *
   * What it does:
   * Duplicate dword-pair range copier that returns destination end.
   */
  [[maybe_unused]] DwordPairRuntime* CopyDwordPairRangeAndReturnEndDuplicateC(
    DwordPairRuntime* destination,
    const DwordPairRuntime* sourceBegin,
    const DwordPairRuntime* const sourceEnd
  ) noexcept
  {
    return CopyDwordPairRangeAndReturnEnd(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x0049F520 (FUN_0049F520, sub_49F520)
   *
   * What it does:
   * Duplicate dword-pair fill helper that writes one repeated source value.
   */
  [[maybe_unused]] DwordPairRuntime* FillDwordPairRangeFromSingleValueDuplicateB(
    DwordPairRuntime* destination,
    const DwordPairRuntime& sourceValue,
    std::uint32_t count
  ) noexcept
  {
    while (count != 0U) {
      if (destination != nullptr) {
        destination->value0 = sourceValue.value0;
        destination->value1 = sourceValue.value1;
      }
      ++destination;
      --count;
    }
    return destination;
  }

  /**
   * Address: 0x0049E380 (FUN_0049E380, sub_49E380)
   *
   * What it does:
   * Thin forwarding wrapper for duplicate dword-pair fill helper lane.
   */
  [[maybe_unused]] DwordPairRuntime* ForwardFillDwordPairRangeDuplicate(
    DwordPairRuntime* const destination,
    const DwordPairRuntime& sourceValue,
    const std::uint32_t count
  ) noexcept
  {
    return FillDwordPairRangeFromSingleValueDuplicateB(destination, sourceValue, count);
  }

  /**
   * Address: 0x0049F540 (FUN_0049F540, nullsub_651)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkBH() noexcept {}

  /**
   * Address: 0x0049F550 (FUN_0049F550, sub_49F550)
   *
   * What it does:
   * Writes one repeated dword source value across `count` destination elements
   * and returns remaining count.
   */
  [[maybe_unused]] std::uint32_t FillDwordRangeFromPointerValueAndReturnRemaining(
    std::uint32_t count,
    const std::uint32_t* const sourceValue,
    std::uint32_t* destination
  ) noexcept
  {
    while (count != 0U) {
      *destination = *sourceValue;
      --count;
      ++destination;
    }
    return count;
  }

  /**
   * Address: 0x0049F570 (FUN_0049F570, sub_49F570)
   *
   * What it does:
   * Calling-convention bridge thunk for world-particle range copy-construction
   * with rollback.
   */
  [[maybe_unused]] void CopyConstructWorldParticleRangeOrRollbackBridgeThunk(
    moho::SWorldParticle* destination,
    const moho::SWorldParticle* sourceBegin,
    const moho::SWorldParticle* const sourceEnd
  )
  {
    CopyConstructWorldParticleRangeOrRollbackLocal(sourceBegin, sourceEnd, destination);
  }

  /**
   * Address: 0x0049F5A0 (FUN_0049F5A0, sub_49F5A0)
   *
   * What it does:
   * Assign-fills one world-particle range from one source particle.
   */
  [[maybe_unused]] moho::SWorldParticle* FillWorldParticleAssignedRangeFromSingleValue(
    moho::SWorldParticle* destinationBegin,
    moho::SWorldParticle* const destinationEnd,
    const moho::SWorldParticle& source
  ) noexcept
  {
    while (destinationBegin != destinationEnd) {
      CopyAssignWorldParticleForVectorMoveLocal(source, *destinationBegin);
      ++destinationBegin;
    }
    return destinationBegin;
  }

  /**
   * Address: 0x0049F5D0 (FUN_0049F5D0, sub_49F5D0)
   *
   * What it does:
   * Duplicate packed-dword byte-lane (`+1`) reader.
   */
  [[maybe_unused]] std::uint8_t ReadSecondByteFromDwordI(const std::uint32_t value) noexcept
  {
    return static_cast<std::uint8_t>((value >> 8U) & 0xFFU);
  }

  /**
   * Address: 0x0049F5E0 (FUN_0049F5E0, sub_49F5E0)
   *
   * What it does:
   * Assign-copy-backward helper for one world-particle range.
   */
  [[maybe_unused]] moho::SWorldParticle* CopyBackwardWorldParticleAssignedRange(
    const moho::SWorldParticle* sourceBegin,
    const moho::SWorldParticle* sourceEnd,
    moho::SWorldParticle* destinationEnd
  ) noexcept
  {
    while (sourceBegin != sourceEnd) {
      --sourceEnd;
      --destinationEnd;
      CopyAssignWorldParticleForVectorMoveLocal(*sourceEnd, *destinationEnd);
    }
    return destinationEnd;
  }

  /**
   * Address: 0x0049F610 (FUN_0049F610, sub_49F610)
   *
   * What it does:
   * Calling-convention bridge thunk for trail-runtime range copy-construction.
   */
  [[maybe_unused]] moho::TrailRuntimeView* CopyConstructTrailRuntimeRangeBridgeThunk(
    moho::TrailRuntimeView* destination,
    const moho::TrailRuntimeView* sourceBegin,
    const moho::TrailRuntimeView* const sourceEnd
  ) noexcept
  {
    return CopyConstructTrailRuntimeRangeAndReturnEndLocal(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x0049F630 (FUN_0049F630, sub_49F630)
   *
   * What it does:
   * Assign-fills one trail-runtime range from one source lane.
   */
  [[maybe_unused]] moho::TrailRuntimeView* FillTrailRuntimeAssignedRangeFromSingleValue(
    moho::TrailRuntimeView* destinationBegin,
    moho::TrailRuntimeView* const destinationEnd,
    const moho::TrailRuntimeView& source
  ) noexcept
  {
    while (destinationBegin != destinationEnd) {
      CopyTrailRuntimeViewForVectorMoveLocal(source, *destinationBegin);
      ++destinationBegin;
    }
    return destinationBegin;
  }

  /**
   * Address: 0x0049F650 (FUN_0049F650, sub_49F650)
   *
   * What it does:
   * Duplicate packed-dword byte-lane (`+1`) reader.
   */
  [[maybe_unused]] std::uint8_t ReadSecondByteFromDwordJ(const std::uint32_t value) noexcept
  {
    return static_cast<std::uint8_t>((value >> 8U) & 0xFFU);
  }

  /**
   * Address: 0x0049F660 (FUN_0049F660, sub_49F660)
   *
   * What it does:
   * Assign-copy-backward helper for one trail-runtime range.
   */
  [[maybe_unused]] moho::TrailRuntimeView* CopyBackwardTrailRuntimeAssignedRange(
    const moho::TrailRuntimeView* sourceBegin,
    const moho::TrailRuntimeView* sourceEnd,
    moho::TrailRuntimeView* destinationEnd
  ) noexcept
  {
    while (sourceBegin != sourceEnd) {
      --sourceEnd;
      --destinationEnd;
      CopyTrailRuntimeViewForVectorMoveLocal(*sourceEnd, *destinationEnd);
    }
    return destinationEnd;
  }

  /**
   * Address: 0x0049F690 (FUN_0049F690, sub_49F690)
   *
   * What it does:
   * Destroys one contiguous world-beam range by resetting both texture lanes.
   */
  [[maybe_unused]] void DestroyWorldBeamRangeByTextureLaneReset(
    moho::SWorldBeam* begin,
    const moho::SWorldBeam* const end
  ) noexcept
  {
    while (begin != end) {
      DestroyWorldBeamForVectorTailLocal(*begin);
      ++begin;
    }
  }

  /**
   * Address: 0x0049F6C0 (FUN_0049F6C0, sub_49F6C0)
   *
   * What it does:
   * Calling-convention bridge thunk for world-beam range copy-construction
   * with rollback.
   */
  [[maybe_unused]] void CopyConstructWorldBeamRangeOrRollbackBridgeThunk(
    moho::SWorldBeam* destination,
    const moho::SWorldBeam* sourceBegin,
    const moho::SWorldBeam* const sourceEnd
  )
  {
    CopyConstructWorldBeamRangeOrRollback(sourceBegin, sourceEnd, destination);
  }

  /**
   * Address: 0x0049F6F0 (FUN_0049F6F0, sub_49F6F0)
   *
   * What it does:
   * Assign-fills one world-beam range from one source beam.
   */
  [[maybe_unused]] moho::SWorldBeam* FillWorldBeamAssignedRangeFromSingleValue(
    moho::SWorldBeam* destinationBegin,
    moho::SWorldBeam* const destinationEnd,
    const moho::SWorldBeam& source
  ) noexcept
  {
    while (destinationBegin != destinationEnd) {
      CopyWorldBeamForVectorMoveLocal(source, *destinationBegin);
      ++destinationBegin;
    }
    return destinationBegin;
  }

  /**
   * Address: 0x0049F720 (FUN_0049F720, sub_49F720)
   *
   * What it does:
   * Duplicate packed-dword byte-lane (`+1`) reader.
   */
  [[maybe_unused]] std::uint8_t ReadSecondByteFromDwordK(const std::uint32_t value) noexcept
  {
    return static_cast<std::uint8_t>((value >> 8U) & 0xFFU);
  }

  /**
   * Address: 0x0049F730 (FUN_0049F730, sub_49F730)
   *
   * What it does:
   * Assign-copy-backward helper for one world-beam range.
   */
  [[maybe_unused]] moho::SWorldBeam* CopyBackwardWorldBeamAssignedRange(
    const moho::SWorldBeam* sourceBegin,
    const moho::SWorldBeam* sourceEnd,
    moho::SWorldBeam* destinationEnd
  ) noexcept
  {
    while (sourceBegin != sourceEnd) {
      --sourceEnd;
      --destinationEnd;
      CopyWorldBeamForVectorMoveLocal(*sourceEnd, *destinationEnd);
    }
    return destinationEnd;
  }

  /**
   * Address: 0x0049F760 (FUN_0049F760, nullsub_652)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkBI() noexcept {}

  /**
   * Address: 0x0049F770 (FUN_0049F770, sub_49F770)
   *
   * What it does:
   * Calling-convention bridge thunk for 15-float-lane range copying.
   */
  [[maybe_unused]] float* CopyFifteenFloatLaneRangeBridgeThunk(
    float* destination,
    const float* sourceBegin,
    const float* const sourceEnd
  ) noexcept
  {
    return CopyFifteenFloatLaneRangeAndReturnEndLocal(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x0049F790 (FUN_0049F790, sub_49F790)
   *
   * What it does:
   * Fills each 15-float lane in one destination pointer range from one source
   * lane value.
   */
  [[maybe_unused]] void FillFifteenFloatLaneForPointerRange(
    float* destinationBegin,
    const float* const sourceLane,
    const float* const destinationEnd
  ) noexcept
  {
    while (destinationBegin != destinationEnd) {
      for (std::size_t i = 0U; i < 15U; ++i) {
        destinationBegin[i] = sourceLane[i];
      }
      destinationBegin += 15;
    }
  }

  /**
   * Address: 0x0049F800 (FUN_0049F800, nullsub_653)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkBJ() noexcept {}

  /**
   * Address: 0x0049F810 (FUN_0049F810, sub_49F810)
   *
   * What it does:
   * Duplicate packed-dword byte-lane (`+1`) reader.
   */
  [[maybe_unused]] std::uint8_t ReadSecondByteFromDwordL(const std::uint32_t value) noexcept
  {
    return static_cast<std::uint8_t>((value >> 8U) & 0xFFU);
  }

  /**
   * Address: 0x0049F820 (FUN_0049F820, sub_49F820)
   *
   * What it does:
   * Calling-convention bridge thunk for reverse copying one 15-float-lane
   * range; returns destination begin.
   */
  [[maybe_unused]] float* CopyBackwardFifteenFloatLaneRangeBridgeThunk(
    float* destinationEnd,
    const float* sourceEnd,
    const float* const sourceBegin
  ) noexcept
  {
    return CopyBackwardFifteenFloatLaneRangeAndReturnBeginLocal(destinationEnd, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x0049F850 (FUN_0049F850, nullsub_654)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkBK() noexcept {}

  /**
   * Address: 0x0049F860 (FUN_0049F860, sub_49F860)
   *
   * What it does:
   * Calling-convention bridge thunk for nullable dword-pair range copy.
   */
  [[maybe_unused]] DwordPairRuntime* CopyDwordPairRangeNullableBridgeThunkA(
    DwordPairRuntime* destination,
    const DwordPairRuntime* sourceEnd,
    const DwordPairRuntime* const sourceBegin
  ) noexcept
  {
    return CopyDwordPairRangeWithNullableDestinationAndReturnEndLocal(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x0049F880 (FUN_0049F880, sub_49F880)
   *
   * What it does:
   * Writes one repeated dword-pair source value into
   * `[destinationBegin, destinationEnd)`.
   */
  [[maybe_unused]] DwordPairRuntime* FillDwordPairRangeFromSingleValueByEndPointerA(
    DwordPairRuntime* destinationBegin,
    const DwordPairRuntime* const destinationEnd,
    const DwordPairRuntime& sourceValue
  ) noexcept
  {
    while (destinationBegin != destinationEnd) {
      destinationBegin->value0 = sourceValue.value0;
      destinationBegin->value1 = sourceValue.value1;
      ++destinationBegin;
    }
    return destinationBegin;
  }

  /**
   * Address: 0x0049F8A0 (FUN_0049F8A0, sub_49F8A0)
   *
   * What it does:
   * Duplicate packed-dword byte-lane (`+1`) reader.
   */
  [[maybe_unused]] std::uint8_t ReadSecondByteFromDwordM(const std::uint32_t value) noexcept
  {
    return static_cast<std::uint8_t>((value >> 8U) & 0xFFU);
  }

  /**
   * Address: 0x0049F8B0 (FUN_0049F8B0, sub_49F8B0)
   *
   * What it does:
   * Copies one dword-pair range backward and returns destination begin.
   */
  [[maybe_unused]] DwordPairRuntime* CopyBackwardDwordPairRangeAndReturnBeginA(
    DwordPairRuntime* destinationEnd,
    const DwordPairRuntime* const sourceBegin,
    const DwordPairRuntime* sourceEnd
  ) noexcept
  {
    return CopyBackwardDwordPairRangeAndReturnBeginLocal(destinationEnd, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x0049F8D0 (FUN_0049F8D0, sub_49F8D0)
   *
   * What it does:
   * Duplicate dword-range move-by-end-pointer helper.
   */
  [[maybe_unused]] std::uint32_t* MoveDwordRangeByEndPointerAndReturnEndC(
    std::uint32_t* const destination,
    const std::uint32_t* const sourceBegin,
    const std::uint32_t* const sourceEnd
  ) noexcept
  {
    return MoveDwordRangeByEndPointerAndReturnEndA(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x0049F900 (FUN_0049F900, sub_49F900)
   *
   * What it does:
   * Writes one repeated dword source value into
   * `[destinationBegin, destinationEnd)`.
   */
  [[maybe_unused]] std::uint32_t* FillDwordRangeFromPointerValueByEndPointerA(
    std::uint32_t* destinationBegin,
    const std::uint32_t* const destinationEnd,
    const std::uint32_t* const sourceValue
  ) noexcept
  {
    return FillDwordRangeFromPointerValueByEndPointerLocal(destinationBegin, destinationEnd, sourceValue);
  }

  /**
   * Address: 0x0049F910 (FUN_0049F910, sub_49F910)
   *
   * What it does:
   * Duplicate packed-dword byte-lane (`+1`) reader.
   */
  [[maybe_unused]] std::uint8_t ReadSecondByteFromDwordN(const std::uint32_t value) noexcept
  {
    return static_cast<std::uint8_t>((value >> 8U) & 0xFFU);
  }

  /**
   * Address: 0x0049F920 (FUN_0049F920, sub_49F920)
   *
   * What it does:
   * Moves one dword range into the tail ending at `destinationEnd` and returns
   * destination begin.
   */
  [[maybe_unused]] std::uint32_t* MoveDwordRangeIntoTailAndReturnBegin(
    const std::uint32_t* const sourceEnd,
    std::uint32_t* const destinationEnd,
    const std::uint32_t* const sourceBegin
  ) noexcept
  {
    const std::ptrdiff_t dwordCount = sourceEnd - sourceBegin;
    std::uint32_t* const destinationBegin = destinationEnd - dwordCount;
    if (dwordCount > 0) {
      const std::size_t byteCount = static_cast<std::size_t>(dwordCount) * sizeof(std::uint32_t);
      memmove_s(destinationBegin, byteCount, sourceBegin, byteCount);
    }
    return destinationBegin;
  }

  /**
   * Address: 0x0049F950 (FUN_0049F950, nullsub_655)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkBL() noexcept {}

  /**
   * Address: 0x0049F960 (FUN_0049F960, sub_49F960)
   *
   * What it does:
   * Duplicate nullable dword-pair range copy bridge thunk.
   */
  [[maybe_unused]] DwordPairRuntime* CopyDwordPairRangeNullableBridgeThunkB(
    DwordPairRuntime* destination,
    const DwordPairRuntime* sourceEnd,
    const DwordPairRuntime* const sourceBegin
  ) noexcept
  {
    return CopyDwordPairRangeWithNullableDestinationAndReturnEndLocal(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x0049F980 (FUN_0049F980, sub_49F980)
   *
   * What it does:
   * Duplicate dword-pair fill helper using destination begin/end pointers.
   */
  [[maybe_unused]] DwordPairRuntime* FillDwordPairRangeFromSingleValueByEndPointerB(
    DwordPairRuntime* destinationBegin,
    const DwordPairRuntime* const destinationEnd,
    const DwordPairRuntime& sourceValue
  ) noexcept
  {
    return FillDwordPairRangeFromSingleValueByEndPointerA(destinationBegin, destinationEnd, sourceValue);
  }

  /**
   * Address: 0x0049F9A0 (FUN_0049F9A0, sub_49F9A0)
   *
   * What it does:
   * Duplicate packed-dword byte-lane (`+1`) reader.
   */
  [[maybe_unused]] std::uint8_t ReadSecondByteFromDwordO(const std::uint32_t value) noexcept
  {
    return static_cast<std::uint8_t>((value >> 8U) & 0xFFU);
  }

  /**
   * Address: 0x0049F9B0 (FUN_0049F9B0, sub_49F9B0)
   *
   * What it does:
   * Duplicate backward dword-pair range copier.
   */
  [[maybe_unused]] DwordPairRuntime* CopyBackwardDwordPairRangeAndReturnBeginB(
    DwordPairRuntime* destinationEnd,
    const DwordPairRuntime* const sourceBegin,
    const DwordPairRuntime* sourceEnd
  ) noexcept
  {
    return CopyBackwardDwordPairRangeAndReturnBeginLocal(destinationEnd, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x0049F9D0 (FUN_0049F9D0, sub_49F9D0)
   *
   * What it does:
   * Duplicate dword-range move-by-end-pointer helper.
   */
  [[maybe_unused]] std::uint32_t* MoveDwordRangeByEndPointerAndReturnEndD(
    std::uint32_t* const destination,
    const std::uint32_t* const sourceBegin,
    const std::uint32_t* const sourceEnd
  ) noexcept
  {
    return MoveDwordRangeByEndPointerAndReturnEndA(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x0049FA00 (FUN_0049FA00, sub_49FA00)
   *
   * What it does:
   * Duplicate dword fill helper using destination begin/end pointers.
   */
  [[maybe_unused]] std::uint32_t* FillDwordRangeFromPointerValueByEndPointerB(
    std::uint32_t* destinationBegin,
    const std::uint32_t* const destinationEnd,
    const std::uint32_t* const sourceValue
  ) noexcept
  {
    return FillDwordRangeFromPointerValueByEndPointerLocal(destinationBegin, destinationEnd, sourceValue);
  }

  /**
   * Address: 0x0049FA10 (FUN_0049FA10, sub_49FA10)
   *
   * What it does:
   * Duplicate packed-dword byte-lane (`+1`) reader.
   */
  [[maybe_unused]] std::uint8_t ReadSecondByteFromDwordP(const std::uint32_t value) noexcept
  {
    return static_cast<std::uint8_t>((value >> 8U) & 0xFFU);
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

  [[nodiscard]] float* CopySingleFifteenFloatLaneAndReturnDestinationLocal(
    float* const destination,
    const float* const source
  ) noexcept
  {
    for (std::size_t i = 0U; i < 15U; ++i) {
      destination[i] = source[i];
    }
    return destination;
  }

  [[nodiscard]] DwordPairRuntime* CopySingleDwordPairAndReturnDestinationLocal(
    DwordPairRuntime* const destination,
    const DwordPairRuntime& source
  ) noexcept
  {
    destination->value0 = source.value0;
    destination->value1 = source.value1;
    return destination;
  }

  /**
   * Address: 0x0049FA20 (FUN_0049FA20, sub_49FA20)
   *
   * What it does:
   * Duplicate dword tail-move helper that returns destination begin.
   */
  [[maybe_unused]] std::uint32_t* MoveDwordRangeIntoTailAndReturnBeginDuplicateA(
    const std::uint32_t* const sourceEnd,
    std::uint32_t* const destinationEnd,
    const std::uint32_t* const sourceBegin
  ) noexcept
  {
    return MoveDwordRangeIntoTailAndReturnBegin(sourceEnd, destinationEnd, sourceBegin);
  }

  /**
   * Address: 0x0049FA50 (FUN_0049FA50, sub_49FA50)
   *
   * What it does:
   * Builds one dword-pair from object pointer plus the field lane at `+0x3C`.
   */
  [[maybe_unused]] DwordPairRuntime* BuildPointerAndField3CPair(
    DwordPairRuntime* const destination,
    const PointerWithFieldAt3CRuntime* const sourceObject
  ) noexcept
  {
    static_assert(sizeof(std::uintptr_t) == sizeof(std::uint32_t), "BuildPointerAndField3CPair assumes 32-bit pointers.");
    destination->value0 = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(sourceObject));
    destination->value1 = sourceObject->field3C;
    return destination;
  }

  /**
   * Address: 0x0049FA60 (FUN_0049FA60, sub_49FA60)
   *
   * What it does:
   * Builds one dword-pair from object pointer plus the field lane at `+0x34`.
   */
  [[maybe_unused]] DwordPairRuntime* BuildPointerAndField34Pair(
    DwordPairRuntime* const destination,
    const PointerWithFieldAt34Runtime* const sourceObject
  ) noexcept
  {
    static_assert(sizeof(std::uintptr_t) == sizeof(std::uint32_t), "BuildPointerAndField34Pair assumes 32-bit pointers.");
    destination->value0 = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(sourceObject));
    destination->value1 = sourceObject->field34;
    return destination;
  }

  /**
   * Address: 0x0049FA70 (FUN_0049FA70, sub_49FA70)
   *
   * What it does:
   * Duplicate particle-bucket destroy+delete thunk.
   */
  [[maybe_unused]] void DestroyAndDeleteParticleRenderBucketDuplicateA(
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
  [[maybe_unused]] void DestroyAndDeleteTrailRenderBucketDuplicateA(
    moho::TrailRenderBucketRuntime* const bucket
  ) noexcept
  {
    DestroyAndDeleteTrailRenderBucket(bucket);
  }

  /**
   * Address: 0x0049FAB0 (FUN_0049FAB0, sub_49FAB0)
   *
   * What it does:
   * Assign-copies one world-particle payload into pre-constructed storage.
   */
  [[maybe_unused]] moho::SWorldParticle* CopyAssignWorldParticleAndReturnDestination(
    const moho::SWorldParticle& source,
    moho::SWorldParticle* const destination
  ) noexcept
  {
    CopyAssignWorldParticleForVectorMoveLocal(source, *destination);
    return destination;
  }

  /**
   * Address: 0x0049FBF0 (FUN_0049FBF0, sub_49FBF0)
   *
   * What it does:
   * Assign-copies one trail-runtime payload into pre-constructed storage.
   */
  [[maybe_unused]] moho::TrailRuntimeView* CopyAssignTrailRuntimeAndReturnDestination(
    const moho::TrailRuntimeView& source,
    moho::TrailRuntimeView* const destination
  ) noexcept
  {
    CopyTrailRuntimeViewForVectorMoveLocal(source, *destination);
    return destination;
  }

  /**
   * Address: 0x0049FCF0 (FUN_0049FCF0, sub_49FCF0)
   *
   * What it does:
   * Assign-copies one world-beam payload into pre-constructed storage.
   */
  [[maybe_unused]] moho::SWorldBeam* CopyAssignWorldBeamAndReturnDestination(
    const moho::SWorldBeam& source,
    moho::SWorldBeam* const destination
  ) noexcept
  {
    CopyWorldBeamForVectorMoveLocal(source, *destination);
    return destination;
  }

  /**
   * Address: 0x0049FEF0 (FUN_0049FEF0, sub_49FEF0)
   *
   * What it does:
   * Copy-copies one 15-float lane into destination storage.
   */
  [[maybe_unused]] float* CopySingleFifteenFloatLaneAndReturnDestination(
    float* const destination,
    const float* const source
  ) noexcept
  {
    return CopySingleFifteenFloatLaneAndReturnDestinationLocal(destination, source);
  }

  /**
   * Address: 0x0049FF50 (FUN_0049FF50, sub_49FF50)
   *
   * What it does:
   * Conditionally copy-constructs one world-particle when destination is valid.
   */
  [[maybe_unused]] moho::SWorldParticle* CopyConstructWorldParticleIfDestinationPresent(
    moho::SWorldParticle* const destination,
    const moho::SWorldParticle& source
  )
  {
    if (destination != nullptr) {
      CopyConstructWorldParticleForVectorMoveLocal(source, *destination);
    }
    return destination;
  }

  /**
   * Address: 0x0049FFA0 (FUN_0049FFA0, sub_49FFA0)
   *
   * What it does:
   * Destroys one world-particle payload in place.
   */
  [[maybe_unused]] void DestroyWorldParticleInPlace(moho::SWorldParticle* const particle) noexcept
  {
    DestroyWorldParticleForVectorTailLocal(*particle);
  }

  /**
   * Address: 0x0049FFB0 (FUN_0049FFB0, sub_49FFB0)
   *
   * What it does:
   * Conditionally assign-copies one trail-runtime payload when destination is
   * valid.
   */
  [[maybe_unused]] moho::TrailRuntimeView* CopyAssignTrailRuntimeIfDestinationPresent(
    moho::TrailRuntimeView* const destination,
    const moho::TrailRuntimeView& source
  ) noexcept
  {
    if (destination != nullptr) {
      CopyTrailRuntimeViewForVectorMoveLocal(source, *destination);
    }
    return destination;
  }

  /**
   * Address: 0x0049FFC0 (FUN_0049FFC0, sub_49FFC0)
   *
   * What it does:
   * Destroys one trail payload in place.
   */
  [[maybe_unused]] void DestroyTrailRuntimeInPlace(moho::TrailRuntimeView* const trail) noexcept
  {
    DestroyTrailRuntimeViewForVectorTailLocal(*trail);
  }

  /**
   * Address: 0x0049FFD0 (FUN_0049FFD0, sub_49FFD0)
   *
   * What it does:
   * Conditionally assign-copies one world-beam payload when destination is
   * valid.
   */
  [[maybe_unused]] moho::SWorldBeam* CopyAssignWorldBeamIfDestinationPresent(
    moho::SWorldBeam* const destination,
    const moho::SWorldBeam& source
  ) noexcept
  {
    if (destination != nullptr) {
      CopyWorldBeamForVectorMoveLocal(source, *destination);
    }
    return destination;
  }

  /**
   * Address: 0x004A0020 (FUN_004A0020, sub_4A0020)
   *
   * What it does:
   * Destroys both counted texture lanes in one world-beam payload.
   */
  [[maybe_unused]] void DestroyWorldBeamTextureLanesInPlace(moho::SWorldBeam* const beam) noexcept
  {
    DestroyWorldBeamForVectorTailLocal(*beam);
  }

  /**
   * Address: 0x004A0040 (FUN_004A0040, sub_4A0040)
   *
   * What it does:
   * Conditionally copies one 15-float lane when destination is valid.
   */
  [[maybe_unused]] float* CopySingleFifteenFloatLaneIfDestinationPresent(
    float* const destination,
    const float* const source
  ) noexcept
  {
    if (destination != nullptr) {
      CopySingleFifteenFloatLaneAndReturnDestinationLocal(destination, source);
    }
    return destination;
  }

  /**
   * Address: 0x004A0050 (FUN_004A0050, nullsub_656)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkBM() noexcept {}

  /**
   * Address: 0x004A0060 (FUN_004A0060, sub_4A0060)
   *
   * What it does:
   * Duplicate particle-bucket destroy+delete thunk.
   */
  [[maybe_unused]] void DestroyAndDeleteParticleRenderBucketDuplicateB(
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
  [[maybe_unused]] void DestroyAndDeleteTrailRenderBucketDuplicateB(
    moho::TrailRenderBucketRuntime* const bucket
  ) noexcept
  {
    DestroyAndDeleteTrailRenderBucket(bucket);
  }

  /**
   * Address: 0x004A00A0 (FUN_004A00A0, sub_4A00A0)
   *
   * What it does:
   * Conditionally copies one dword-pair when destination is valid.
   */
  [[maybe_unused]] DwordPairRuntime* CopySingleDwordPairIfDestinationPresent(
    DwordPairRuntime* const destination,
    const DwordPairRuntime& source
  ) noexcept
  {
    if (destination != nullptr) {
      CopySingleDwordPairAndReturnDestinationLocal(destination, source);
    }
    return destination;
  }

  /**
   * Address: 0x004A00B0 (FUN_004A00B0, nullsub_657)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkBN() noexcept {}

  /**
   * Address: 0x004A00C0 (FUN_004A00C0, sub_4A00C0)
   *
   * What it does:
   * Duplicate conditional dword-pair copy helper.
   */
  [[maybe_unused]] DwordPairRuntime* CopySingleDwordPairIfDestinationPresentDuplicateA(
    DwordPairRuntime* const destination,
    const DwordPairRuntime& source
  ) noexcept
  {
    return CopySingleDwordPairIfDestinationPresent(destination, source);
  }

  /**
   * Address: 0x004A00D0 (FUN_004A00D0, nullsub_658)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkBO() noexcept {}

  /**
   * Address: 0x004A00E0 (FUN_004A00E0, sub_4A00E0)
   *
   * What it does:
   * Duplicate dword-slot equality comparator.
   */
  [[maybe_unused]] bool AreDwordSlotsEqualC(
    const std::uint32_t* const lhs,
    const std::uint32_t* const rhs
  ) noexcept
  {
    return AreDwordSlotsEqualA(lhs, rhs);
  }

  /**
   * Address: 0x004A00F0 (FUN_004A00F0, sub_4A00F0)
   *
   * What it does:
   * Duplicate dword-slot equality comparator.
   */
  [[maybe_unused]] bool AreDwordSlotsEqualD(
    const std::uint32_t* const lhs,
    const std::uint32_t* const rhs
  ) noexcept
  {
    return AreDwordSlotsEqualB(lhs, rhs);
  }

  /**
   * Address: 0x004A0100 (FUN_004A0100, sub_4A0100)
   *
   * What it does:
   * Duplicate dword-range move-by-count helper that returns caller token.
   */
  [[maybe_unused]] std::uintptr_t MoveDwordRangeByCountAndReturnTokenC(
    const std::uint32_t* const source,
    std::uint32_t* const destination,
    const std::uint32_t dwordCount,
    const std::uintptr_t returnToken
  ) noexcept
  {
    return MoveDwordRangeByCountAndReturnTokenA(source, destination, dwordCount, returnToken);
  }

  /**
   * Address: 0x004A0120 (FUN_004A0120, sub_4A0120)
   *
   * What it does:
   * Duplicate dword-range move-by-count helper that returns caller token.
   */
  [[maybe_unused]] std::uintptr_t MoveDwordRangeByCountAndReturnTokenD(
    const std::uint32_t* const source,
    std::uint32_t* const destination,
    const std::uint32_t dwordCount,
    const std::uintptr_t returnToken
  ) noexcept
  {
    return MoveDwordRangeByCountAndReturnTokenB(source, destination, dwordCount, returnToken);
  }

  /**
   * Address: 0x004A0140 (FUN_004A0140, sub_4A0140)
   *
   * What it does:
   * Duplicate packed-dword byte-lane (`+1`) reader.
   */
  [[maybe_unused]] std::uint8_t ReadSecondByteFromDwordQ(const std::uint32_t value) noexcept
  {
    return ReadSecondByteFromDwordP(value);
  }

  /**
   * Address: 0x004A01F0 (FUN_004A01F0, sub_4A01F0)
   *
   * What it does:
   * Duplicate particle-bucket tree-header initialization with fresh head
   * sentinel allocation.
   */
  [[maybe_unused]] moho::ParticleBucketTreeRuntime* InitializeParticleBucketTreeWithFreshHeadDuplicateA(
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
  [[maybe_unused]] moho::TrailBucketTreeRuntime* InitializeTrailBucketTreeWithFreshHeadDuplicateA(
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
  [[maybe_unused]] moho::TrailRenderBucketRuntime* ReadTrailBucketEntryNodeMappedBucket(
    TrailBucketTreeEntryNodeRuntime* const node
  ) noexcept
  {
    return node->bucket;
  }

  /**
   * Address: 0x004A0270 (FUN_004A0270, sub_4A0270)
   *
   * What it does:
   * Duplicate dword-range fill helper that writes one source slot value.
   */
  [[maybe_unused]] std::uint32_t FillDwordRangeFromPointerValueAndReturnRemainingDuplicateA(
    std::uint32_t count,
    const std::uint32_t* const sourceValue,
    std::uint32_t* const destination
  ) noexcept
  {
    return FillDwordRangeFromPointerValueAndReturnRemaining(count, sourceValue, destination);
  }

  /**
   * Address: 0x004A0290 (FUN_004A0290, sub_4A0290)
   *
   * What it does:
   * Duplicate dword-range fill helper that writes one source slot value.
   */
  [[maybe_unused]] std::uint32_t FillDwordRangeFromPointerValueAndReturnRemainingDuplicateB(
    std::uint32_t count,
    const std::uint32_t* const sourceValue,
    std::uint32_t* const destination
  ) noexcept
  {
    return FillDwordRangeFromPointerValueAndReturnRemaining(count, sourceValue, destination);
  }

  /**
   * Address: 0x004A02B0 (FUN_004A02B0, sub_4A02B0)
   *
   * What it does:
   * Calling-convention bridge thunk for world-particle range copy-construction
   * with rollback.
   */
  [[maybe_unused]] void CopyConstructWorldParticleRangeOrRollbackBridgeThunkDuplicateA(
    moho::SWorldParticle* const destination,
    const moho::SWorldParticle* const sourceBegin,
    const moho::SWorldParticle* const sourceEnd
  )
  {
    CopyConstructWorldParticleRangeOrRollbackLocal(sourceBegin, sourceEnd, destination);
  }

  /**
   * Address: 0x004A02E0 (FUN_004A02E0, sub_4A02E0)
   *
   * What it does:
   * Duplicate backward assign-copy helper for one world-particle range.
   */
  [[maybe_unused]] moho::SWorldParticle* CopyBackwardWorldParticleAssignedRangeDuplicateA(
    const moho::SWorldParticle* const sourceBegin,
    const moho::SWorldParticle* const sourceEnd,
    moho::SWorldParticle* const destinationEnd
  ) noexcept
  {
    return CopyBackwardWorldParticleAssignedRange(sourceBegin, sourceEnd, destinationEnd);
  }

  /**
   * Address: 0x004A0310 (FUN_004A0310, sub_4A0310)
   *
   * What it does:
   * Calling-convention bridge thunk for trail-runtime range copy-construction.
   */
  [[maybe_unused]] moho::TrailRuntimeView* CopyConstructTrailRuntimeRangeBridgeThunkDuplicateA(
    moho::TrailRuntimeView* const destination,
    const moho::TrailRuntimeView* const sourceBegin,
    const moho::TrailRuntimeView* const sourceEnd
  ) noexcept
  {
    return CopyConstructTrailRuntimeRangeAndReturnEndLocal(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x004A0330 (FUN_004A0330, sub_4A0330)
   *
   * What it does:
   * Duplicate backward assign-copy helper for one trail-runtime range.
   */
  [[maybe_unused]] moho::TrailRuntimeView* CopyBackwardTrailRuntimeAssignedRangeDuplicateA(
    const moho::TrailRuntimeView* const sourceBegin,
    const moho::TrailRuntimeView* const sourceEnd,
    moho::TrailRuntimeView* const destinationEnd
  ) noexcept
  {
    return CopyBackwardTrailRuntimeAssignedRange(sourceBegin, sourceEnd, destinationEnd);
  }

  /**
   * Address: 0x004A0360 (FUN_004A0360, sub_4A0360)
   *
   * What it does:
   * Calling-convention bridge thunk for world-beam range copy-construction
   * with rollback.
   */
  [[maybe_unused]] void CopyConstructWorldBeamRangeOrRollbackBridgeThunkDuplicateA(
    moho::SWorldBeam* const destination,
    const moho::SWorldBeam* const sourceBegin,
    const moho::SWorldBeam* const sourceEnd
  )
  {
    CopyConstructWorldBeamRangeOrRollback(sourceBegin, sourceEnd, destination);
  }

  /**
   * Address: 0x004A0390 (FUN_004A0390, sub_4A0390)
   *
   * What it does:
   * Duplicate backward assign-copy helper for one world-beam range.
   */
  [[maybe_unused]] moho::SWorldBeam* CopyBackwardWorldBeamAssignedRangeDuplicateA(
    const moho::SWorldBeam* const sourceBegin,
    const moho::SWorldBeam* const sourceEnd,
    moho::SWorldBeam* const destinationEnd
  ) noexcept
  {
    return CopyBackwardWorldBeamAssignedRange(sourceBegin, sourceEnd, destinationEnd);
  }

  [[nodiscard]] std::uint32_t* MoveDwordRangeByCountAndReturnDestinationLocal(
    const std::uint32_t* const source,
    const std::uint32_t dwordCount,
    std::uint32_t* const destination
  ) noexcept
  {
    const std::size_t byteCount = static_cast<std::size_t>(dwordCount) * sizeof(std::uint32_t);
    memmove_s(destination, byteCount, source, byteCount);
    return destination;
  }

  /**
   * Address: 0x004A03C0 (FUN_004A03C0, sub_4A03C0)
   *
   * What it does:
   * Duplicate calling-convention bridge thunk for nullable 15-float-lane range
   * copy.
   */
  [[maybe_unused]] float* CopyFifteenFloatLaneRangeBridgeThunkDuplicateA(
    float* const destination,
    const float* const sourceBegin,
    const float* const sourceEnd
  ) noexcept
  {
    return CopyFifteenFloatLaneRangeAndReturnEndLocal(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x004A03E0 (FUN_004A03E0, sub_4A03E0)
   *
   * What it does:
   * Duplicate calling-convention bridge thunk for backward 15-float-lane range
   * copy.
   */
  [[maybe_unused]] float* CopyBackwardFifteenFloatLaneRangeBridgeThunkDuplicateA(
    float* const destinationEnd,
    const float* const sourceEnd,
    const float* const sourceBegin
  ) noexcept
  {
    return CopyBackwardFifteenFloatLaneRangeAndReturnBeginLocal(destinationEnd, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x004A0460 (FUN_004A0460, sub_4A0460)
   *
   * What it does:
   * Duplicate calling-convention bridge thunk for nullable dword-pair range
   * copy.
   */
  [[maybe_unused]] DwordPairRuntime* CopyDwordPairRangeNullableBridgeThunkDuplicateC(
    DwordPairRuntime* const destination,
    const DwordPairRuntime* const sourceEnd,
    const DwordPairRuntime* const sourceBegin
  ) noexcept
  {
    return CopyDwordPairRangeWithNullableDestinationAndReturnEndLocal(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x004A0480 (FUN_004A0480, sub_4A0480)
   *
   * What it does:
   * Duplicate backward dword-pair range copy helper.
   */
  [[maybe_unused]] DwordPairRuntime* CopyBackwardDwordPairRangeAndReturnBeginDuplicateC(
    DwordPairRuntime* const destinationEnd,
    const DwordPairRuntime* const sourceBegin,
    const DwordPairRuntime* const sourceEnd
  ) noexcept
  {
    return CopyBackwardDwordPairRangeAndReturnBeginLocal(destinationEnd, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x004A04A0 (FUN_004A04A0, sub_4A04A0)
   *
   * What it does:
   * Duplicate dword-range move-by-end-pointer helper.
   */
  [[maybe_unused]] std::uint32_t* MoveDwordRangeByEndPointerAndReturnEndDuplicateE(
    std::uint32_t* const destination,
    const std::uint32_t* const sourceBegin,
    const std::uint32_t* const sourceEnd
  ) noexcept
  {
    return MoveDwordRangeByEndPointerAndReturnEndA(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x004A04D0 (FUN_004A04D0, sub_4A04D0)
   *
   * What it does:
   * Moves one dword range by element count and returns destination begin.
   */
  [[maybe_unused]] std::uint32_t* MoveDwordRangeByCountAndReturnDestinationDuplicateA(
    const std::uint32_t* const source,
    const std::uint32_t dwordCount,
    std::uint32_t* const destination
  ) noexcept
  {
    return MoveDwordRangeByCountAndReturnDestinationLocal(source, dwordCount, destination);
  }

  /**
   * Address: 0x004A04F0 (FUN_004A04F0, sub_4A04F0)
   *
   * What it does:
   * Duplicate calling-convention bridge thunk for nullable dword-pair range
   * copy.
   */
  [[maybe_unused]] DwordPairRuntime* CopyDwordPairRangeNullableBridgeThunkDuplicateD(
    DwordPairRuntime* const destination,
    const DwordPairRuntime* const sourceEnd,
    const DwordPairRuntime* const sourceBegin
  ) noexcept
  {
    return CopyDwordPairRangeWithNullableDestinationAndReturnEndLocal(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x004A0510 (FUN_004A0510, sub_4A0510)
   *
   * What it does:
   * Duplicate backward dword-pair range copy helper.
   */
  [[maybe_unused]] DwordPairRuntime* CopyBackwardDwordPairRangeAndReturnBeginDuplicateD(
    DwordPairRuntime* const destinationEnd,
    const DwordPairRuntime* const sourceBegin,
    const DwordPairRuntime* const sourceEnd
  ) noexcept
  {
    return CopyBackwardDwordPairRangeAndReturnBeginLocal(destinationEnd, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x004A0530 (FUN_004A0530, sub_4A0530)
   *
   * What it does:
   * Duplicate dword-range move-by-end-pointer helper.
   */
  [[maybe_unused]] std::uint32_t* MoveDwordRangeByEndPointerAndReturnEndDuplicateF(
    std::uint32_t* const destination,
    const std::uint32_t* const sourceBegin,
    const std::uint32_t* const sourceEnd
  ) noexcept
  {
    return MoveDwordRangeByEndPointerAndReturnEndA(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x004A0560 (FUN_004A0560, sub_4A0560)
   *
   * What it does:
   * Duplicate dword-range move-by-count helper returning destination begin.
   */
  [[maybe_unused]] std::uint32_t* MoveDwordRangeByCountAndReturnDestinationDuplicateB(
    const std::uint32_t* const source,
    const std::uint32_t dwordCount,
    std::uint32_t* const destination
  ) noexcept
  {
    return MoveDwordRangeByCountAndReturnDestinationLocal(source, dwordCount, destination);
  }

  /**
   * Address: 0x004A0580 (FUN_004A0580, sub_4A0580)
   *
   * What it does:
   * Duplicate particle-bucket destroy+delete thunk.
   */
  [[maybe_unused]] void DestroyAndDeleteParticleRenderBucketDuplicateC(
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
  [[maybe_unused]] void DestroyAndDeleteTrailRenderBucketDuplicateC(
    moho::TrailRenderBucketRuntime* const bucket
  ) noexcept
  {
    DestroyAndDeleteTrailRenderBucket(bucket);
  }

  /**
   * Address: 0x004A05C0 (FUN_004A05C0, sub_4A05C0)
   *
   * What it does:
   * Conditionally copy-constructs one world-particle when destination is
   * valid.
   */
  [[maybe_unused]] moho::SWorldParticle* CopyConstructWorldParticleIfDestinationPresentDuplicateA(
    const moho::SWorldParticle& source,
    moho::SWorldParticle* const destination
  )
  {
    if (destination != nullptr) {
      CopyConstructWorldParticleForVectorMoveLocal(source, *destination);
    }
    return destination;
  }

  /**
   * Address: 0x004A0610 (FUN_004A0610, sub_4A0610)
   *
   * What it does:
   * Duplicate world-particle in-place destructor thunk.
   */
  [[maybe_unused]] void DestroyWorldParticleInPlaceDuplicateA(moho::SWorldParticle* const particle) noexcept
  {
    DestroyWorldParticleForVectorTailLocal(*particle);
  }

  /**
   * Address: 0x004A0620 (FUN_004A0620, sub_4A0620)
   *
   * What it does:
   * Conditionally copy-constructs one trail-runtime payload when destination is
   * valid.
   */
  [[maybe_unused]] moho::TrailRuntimeView* CopyConstructTrailRuntimeIfDestinationPresent(
    moho::TrailRuntimeView* const destination,
    const moho::TrailRuntimeView& source
  ) noexcept
  {
    if (destination != nullptr) {
      CopyConstructTrailRuntimeViewForVectorMoveLocal(source, *destination);
    }
    return destination;
  }

  /**
   * Address: 0x004A0630 (FUN_004A0630, sub_4A0630)
   *
   * What it does:
   * Duplicate trail-runtime in-place destructor thunk.
   */
  [[maybe_unused]] void DestroyTrailRuntimeInPlaceDuplicateA(moho::TrailRuntimeView* const trail) noexcept
  {
    DestroyTrailRuntimeViewForVectorTailLocal(*trail);
  }

  /**
   * Address: 0x004A0640 (FUN_004A0640, sub_4A0640)
   *
   * What it does:
   * Conditionally copy-constructs one world-beam payload when destination is
   * valid.
   */
  [[maybe_unused]] moho::SWorldBeam* CopyConstructWorldBeamIfDestinationPresentDuplicateA(
    const moho::SWorldBeam& source,
    moho::SWorldBeam* const destination
  )
  {
    if (destination != nullptr) {
      CopyConstructWorldBeamForVectorMoveLocal(source, *destination);
    }
    return destination;
  }

  /**
   * Address: 0x004A0690 (FUN_004A0690, sub_4A0690)
   *
   * What it does:
   * Duplicate world-beam texture-lane destructor thunk.
   */
  [[maybe_unused]] void DestroyWorldBeamTextureLanesInPlaceDuplicateA(moho::SWorldBeam* const beam) noexcept
  {
    DestroyWorldBeamForVectorTailLocal(*beam);
  }

  /**
   * Address: 0x004A06B0 (FUN_004A06B0, sub_4A06B0)
   *
   * What it does:
   * Conditionally copies one 15-float lane when destination is valid.
   */
  [[maybe_unused]] float* CopySingleFifteenFloatLaneIfDestinationPresentDuplicateA(
    float* const destination,
    const float* const source
  ) noexcept
  {
    if (destination != nullptr) {
      CopySingleFifteenFloatLaneAndReturnDestinationLocal(destination, source);
    }
    return destination;
  }

  /**
   * Address: 0x004A06C0 (FUN_004A06C0, nullsub_659)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkBP() noexcept {}

  /**
   * Address: 0x004A06D0 (FUN_004A06D0, sub_4A06D0)
   *
   * What it does:
   * Duplicate conditional dword-pair copy helper.
   */
  [[maybe_unused]] DwordPairRuntime* CopySingleDwordPairIfDestinationPresentDuplicateB(
    DwordPairRuntime* const destination,
    const DwordPairRuntime& source
  ) noexcept
  {
    return CopySingleDwordPairIfDestinationPresent(destination, source);
  }

  /**
   * Address: 0x004A06E0 (FUN_004A06E0, nullsub_660)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkBQ() noexcept {}

  /**
   * Address: 0x004A06F0 (FUN_004A06F0, sub_4A06F0)
   *
   * What it does:
   * Duplicate conditional dword-pair copy helper.
   */
  [[maybe_unused]] DwordPairRuntime* CopySingleDwordPairIfDestinationPresentDuplicateC(
    DwordPairRuntime* const destination,
    const DwordPairRuntime& source
  ) noexcept
  {
    return CopySingleDwordPairIfDestinationPresent(destination, source);
  }

  /**
   * Address: 0x004A0700 (FUN_004A0700, nullsub_661)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkBR() noexcept {}

  /**
   * Address: 0x004A0710 (FUN_004A0710, sub_4A0710)
   *
   * What it does:
   * Destroys one world-particle payload and returns the input slot pointer.
   */
  [[maybe_unused]] moho::SWorldParticle* DestroyWorldParticleInPlaceAndReturnSelf(
    moho::SWorldParticle* const particle
  ) noexcept
  {
    DestroyWorldParticleForVectorTailLocal(*particle);
    return particle;
  }

  /**
   * Address: 0x004A0720 (FUN_004A0720, sub_4A0720)
   *
   * What it does:
   * Destroys one trail-runtime payload and returns the input slot pointer.
   */
  [[maybe_unused]] moho::TrailRuntimeView* DestroyTrailRuntimeInPlaceAndReturnSelf(
    moho::TrailRuntimeView* const trail
  ) noexcept
  {
    DestroyTrailRuntimeViewForVectorTailLocal(*trail);
    return trail;
  }

  /**
   * Address: 0x004A0730 (FUN_004A0730, sub_4A0730)
   *
   * What it does:
   * Destroys the two counted world-beam texture lanes and returns the beam
   * slot pointer.
   */
  [[maybe_unused]] moho::SWorldBeam* DestroyWorldBeamTextureLanesInPlaceAndReturnSelf(
    moho::SWorldBeam* const beam
  ) noexcept
  {
    DestroyWorldBeamForVectorTailLocal(*beam);
    return beam;
  }

  /**
   * Address: 0x004A0750 (FUN_004A0750, sub_4A0750)
   *
   * What it does:
   * Duplicate particle-bucket tree-header initialization with fresh sentinel
   * head allocation.
   */
  [[maybe_unused]] moho::ParticleBucketTreeRuntime* InitializeParticleBucketTreeWithFreshHeadDuplicateB(
    moho::ParticleBucketTreeRuntime* const treeRuntime
  )
  {
    return InitializeParticleBucketTreeWithFreshHeadDuplicateA(treeRuntime);
  }

  /**
   * Address: 0x004A0780 (FUN_004A0780, nullsub_662)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkBS() noexcept {}

  /**
   * Address: 0x004A0790 (FUN_004A0790, sub_4A0790)
   *
   * What it does:
   * Duplicate trail-bucket tree-header initialization with fresh sentinel head
   * allocation.
   */
  [[maybe_unused]] moho::TrailBucketTreeRuntime* InitializeTrailBucketTreeWithFreshHeadDuplicateB(
    moho::TrailBucketTreeRuntime* const treeRuntime
  )
  {
    return InitializeTrailBucketTreeWithFreshHeadDuplicateA(treeRuntime);
  }

  /**
   * Address: 0x004A07C0 (FUN_004A07C0, nullsub_663)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkBT() noexcept {}

  /**
   * Address: 0x004A07D0 (FUN_004A07D0, sub_4A07D0)
   *
   * What it does:
   * Duplicate particle-bucket tree-header initialization with fresh sentinel
   * head allocation.
   */
  [[maybe_unused]] moho::ParticleBucketTreeRuntime* InitializeParticleBucketTreeWithFreshHeadDuplicateC(
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
  [[maybe_unused]] moho::TrailBucketTreeRuntime* InitializeTrailBucketTreeWithFreshHeadDuplicateC(
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
  [[maybe_unused]] moho::ParticleBucketTreeNodeRuntime* InitializeParticleBucketTreeAndReturnHead(
    moho::ParticleBucketTreeRuntime* const treeRuntime
  )
  {
    InitializeParticleBucketTreeWithFreshHeadDuplicateA(treeRuntime);
    return treeRuntime->head;
  }

  /**
   * Address: 0x004A0860 (FUN_004A0860, nullsub_664)
   *
   * What it does:
   * No-op stdcall helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkStdcallH(const std::uint32_t /*unused*/) noexcept {}

  /**
   * Address: 0x004A0870 (FUN_004A0870, nullsub_665)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkBU() noexcept {}

  /**
   * Address: 0x004A0880 (FUN_004A0880, sub_4A0880)
   *
   * What it does:
   * Initializes one trail-bucket tree header and returns the resulting head
   * sentinel node.
   */
  [[maybe_unused]] moho::TrailBucketTreeNodeRuntime* InitializeTrailBucketTreeAndReturnHead(
    moho::TrailBucketTreeRuntime* const treeRuntime
  )
  {
    InitializeTrailBucketTreeWithFreshHeadDuplicateA(treeRuntime);
    return treeRuntime->head;
  }

  /**
   * Address: 0x004A08B0 (FUN_004A08B0, nullsub_666)
   *
   * What it does:
   * No-op stdcall helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkStdcallI(const std::uint32_t /*unused*/) noexcept {}

  /**
   * Address: 0x004A08C0 (FUN_004A08C0, nullsub_667)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkBV() noexcept {}

  /**
   * Address: 0x004A08D0 (FUN_004A08D0, sub_4A08D0)
   *
   * What it does:
   * Allocates one particle-bucket tree node and initializes link lanes to null
   * with default black/non-sentinel flags.
   */
  [[maybe_unused]] moho::ParticleBucketTreeNodeRuntime* AllocateParticleBucketTreeNodeWithNullLinksBlack()
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
   * Address: 0x004A0910 (FUN_004A0910, nullsub_668)
   *
   * What it does:
   * No-op stdcall helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkStdcallJ(const std::uint32_t /*unused*/) noexcept {}

  /**
   * Address: 0x004A0920 (FUN_004A0920, sub_4A0920)
   *
   * What it does:
   * Allocates one trail-bucket tree node and initializes link lanes to null
   * with default black/non-sentinel flags.
   */
  [[maybe_unused]] moho::TrailBucketTreeNodeRuntime* AllocateTrailBucketTreeNodeWithNullLinksBlack()
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
   * Address: 0x004A0960 (FUN_004A0960, nullsub_669)
   *
   * What it does:
   * No-op stdcall helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkStdcallK(const std::uint32_t /*unused*/) noexcept {}

  /**
   * Address: 0x004A0970 (FUN_004A0970, nullsub_670)
   *
   * What it does:
   * No-op stdcall helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkStdcallL(const std::uint32_t /*unused*/) noexcept {}

  /**
   * Address: 0x004A0980 (FUN_004A0980, sub_4A0980)
   *
   * What it does:
   * Conditionally copies one dword lane when destination is valid.
   */
  [[maybe_unused]] std::uint32_t* CopySingleDwordSlotIfDestinationPresentDuplicateA(
    std::uint32_t* const destination,
    const std::uint32_t* const sourceSlot
  ) noexcept
  {
    if (destination != nullptr) {
      *destination = *sourceSlot;
    }
    return destination;
  }

  /**
   * Address: 0x004A0990 (FUN_004A0990, nullsub_671)
   *
   * What it does:
   * No-op stdcall helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkStdcallM(const std::uint32_t /*unused*/) noexcept {}

  /**
   * Address: 0x004A09A0 (FUN_004A09A0, sub_4A09A0)
   *
   * What it does:
   * Duplicate conditional dword-lane copy helper.
   */
  [[maybe_unused]] std::uint32_t* CopySingleDwordSlotIfDestinationPresentDuplicateB(
    std::uint32_t* const destination,
    const std::uint32_t* const sourceSlot
  ) noexcept
  {
    return CopySingleDwordSlotIfDestinationPresentDuplicateA(destination, sourceSlot);
  }

  /**
   * Address: 0x004A09B0 (FUN_004A09B0, nullsub_672)
   *
   * What it does:
   * No-op stdcall helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkStdcallN(const std::uint32_t /*unused*/) noexcept {}

  /**
   * Address: 0x004A09C0 (FUN_004A09C0, nullsub_673)
   *
   * What it does:
   * No-op stdcall helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkStdcallO(const std::uint32_t /*unused*/) noexcept {}

  /**
   * Address: 0x004A09D0 (FUN_004A09D0, nullsub_674)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkBW() noexcept {}

  /**
   * Address: 0x004A09E0 (FUN_004A09E0, sub_4A09E0)
   *
   * What it does:
   * Duplicate dword-range fill helper that writes one source slot value.
   */
  [[maybe_unused]] std::uint32_t FillDwordRangeFromPointerValueAndReturnRemainingDuplicateC(
    std::uint32_t count,
    const std::uint32_t* const sourceValue,
    std::uint32_t* const destination
  ) noexcept
  {
    return FillDwordRangeFromPointerValueAndReturnRemaining(count, sourceValue, destination);
  }

  /**
   * Address: 0x004A0A00 (FUN_004A0A00, nullsub_675)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkBX() noexcept {}

  /**
   * Address: 0x004A0A10 (FUN_004A0A10, sub_4A0A10)
   *
   * What it does:
   * Duplicate dword-range fill helper that writes one source slot value.
   */
  [[maybe_unused]] std::uint32_t FillDwordRangeFromPointerValueAndReturnRemainingDuplicateD(
    std::uint32_t count,
    const std::uint32_t* const sourceValue,
    std::uint32_t* const destination
  ) noexcept
  {
    return FillDwordRangeFromPointerValueAndReturnRemaining(count, sourceValue, destination);
  }

  /**
   * Address: 0x004A0A30 (FUN_004A0A30, sub_4A0A30)
   *
   * What it does:
   * Duplicate calling-convention bridge thunk for world-particle range
   * copy-construction with rollback.
   */
  [[maybe_unused]] void CopyConstructWorldParticleRangeOrRollbackBridgeThunkDuplicateB(
    moho::SWorldParticle* const destination,
    const moho::SWorldParticle* const sourceBegin,
    const moho::SWorldParticle* const sourceEnd
  )
  {
    CopyConstructWorldParticleRangeOrRollbackLocal(sourceBegin, sourceEnd, destination);
  }

  /**
   * Address: 0x004A0A50 (FUN_004A0A50, sub_4A0A50)
   *
   * What it does:
   * Duplicate calling-convention bridge thunk for trail-runtime range
   * copy-construction.
   */
  [[maybe_unused]] moho::TrailRuntimeView* CopyConstructTrailRuntimeRangeBridgeThunkDuplicateB(
    moho::TrailRuntimeView* const destination,
    const moho::TrailRuntimeView* const sourceBegin,
    const moho::TrailRuntimeView* const sourceEnd
  ) noexcept
  {
    return CopyConstructTrailRuntimeRangeAndReturnEndLocal(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x004A0A70 (FUN_004A0A70, sub_4A0A70)
   *
   * What it does:
   * Duplicate calling-convention bridge thunk for world-beam range
   * copy-construction with rollback.
   */
  [[maybe_unused]] void CopyConstructWorldBeamRangeOrRollbackBridgeThunkDuplicateB(
    moho::SWorldBeam* const destination,
    const moho::SWorldBeam* const sourceBegin,
    const moho::SWorldBeam* const sourceEnd
  )
  {
    CopyConstructWorldBeamRangeOrRollback(sourceBegin, sourceEnd, destination);
  }

  /**
   * Address: 0x004A0A90 (FUN_004A0A90, sub_4A0A90)
   *
   * What it does:
   * Duplicate calling-convention bridge thunk for nullable 15-float-lane range
   * copy.
   */
  [[maybe_unused]] float* CopyFifteenFloatLaneRangeBridgeThunkDuplicateB(
    float* const destination,
    const float* const sourceBegin,
    const float* const sourceEnd
  ) noexcept
  {
    return CopyFifteenFloatLaneRangeAndReturnEndLocal(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x004A0AB0 (FUN_004A0AB0, sub_4A0AB0)
   *
   * What it does:
   * Duplicate calling-convention bridge thunk for nullable dword-pair range
   * copy.
   */
  [[maybe_unused]] DwordPairRuntime* CopyDwordPairRangeNullableBridgeThunkDuplicateE(
    DwordPairRuntime* const destination,
    const DwordPairRuntime* const sourceEnd,
    const DwordPairRuntime* const sourceBegin
  ) noexcept
  {
    return CopyDwordPairRangeWithNullableDestinationAndReturnEndLocal(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x004A0AD0 (FUN_004A0AD0, sub_4A0AD0)
   *
   * What it does:
   * Duplicate calling-convention bridge thunk for nullable dword-pair range
   * copy.
   */
  [[maybe_unused]] DwordPairRuntime* CopyDwordPairRangeNullableBridgeThunkDuplicateF(
    DwordPairRuntime* const destination,
    const DwordPairRuntime* const sourceEnd,
    const DwordPairRuntime* const sourceBegin
  ) noexcept
  {
    return CopyDwordPairRangeWithNullableDestinationAndReturnEndLocal(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x004A0AF0 (FUN_004A0AF0, sub_4A0AF0)
   *
   * What it does:
   * Duplicate particle-bucket destroy+delete thunk.
   */
  [[maybe_unused]] void DestroyAndDeleteParticleRenderBucketDuplicateD(
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
  [[maybe_unused]] void DestroyAndDeleteTrailRenderBucketDuplicateD(
    moho::TrailRenderBucketRuntime* const bucket
  ) noexcept
  {
    DestroyAndDeleteTrailRenderBucket(bucket);
  }

  /**
   * Address: 0x004A0B30 (FUN_004A0B30, nullsub_676)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkBY() noexcept {}

  /**
   * Address: 0x004A0B40 (FUN_004A0B40, nullsub_677)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkBZ() noexcept {}

  /**
   * Address: 0x004A0B50 (FUN_004A0B50, nullsub_678)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkCA() noexcept {}

  /**
   * Address: 0x004A0B60 (FUN_004A0B60, sub_4A0B60)
   *
   * What it does:
   * Duplicate conditional dword-lane copy helper.
   */
  [[maybe_unused]] std::uint32_t* CopySingleDwordSlotIfDestinationPresentDuplicateC(
    std::uint32_t* const destination,
    const std::uint32_t* const sourceSlot
  ) noexcept
  {
    return CopySingleDwordSlotIfDestinationPresentDuplicateA(destination, sourceSlot);
  }

  /**
   * Address: 0x004A0B70 (FUN_004A0B70, nullsub_679)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkCB() noexcept {}

  /**
   * Address: 0x004A0B80 (FUN_004A0B80, sub_4A0B80)
   *
   * What it does:
   * Duplicate conditional dword-lane copy helper.
   */
  [[maybe_unused]] std::uint32_t* CopySingleDwordSlotIfDestinationPresentDuplicateD(
    std::uint32_t* const destination,
    const std::uint32_t* const sourceSlot
  ) noexcept
  {
    return CopySingleDwordSlotIfDestinationPresentDuplicateA(destination, sourceSlot);
  }

  /**
   * Address: 0x004A0B90 (FUN_004A0B90, sub_4A0B90)
   *
   * What it does:
   * Destroys and deletes one particle-bucket payload and returns the input
   * pointer.
   */
  [[maybe_unused]] moho::ParticleRenderBucketRuntime* DestroyAndDeleteParticleRenderBucketAndReturnInput(
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
  [[maybe_unused]] moho::TrailRenderBucketRuntime* DestroyAndDeleteTrailRenderBucketAndReturnInput(
    moho::TrailRenderBucketRuntime* const bucket
  ) noexcept
  {
    moho::DestroyTrailRenderBucket(*bucket);
    ::operator delete(bucket);
    return bucket;
  }

  /**
   * Address: 0x004A0BD0 (FUN_004A0BD0, sub_4A0BD0)
   *
   * What it does:
   * Duplicate dword-range fill helper that writes one source slot value.
   */
  [[maybe_unused]] std::uint32_t FillDwordRangeFromPointerValueAndReturnRemainingDuplicateE(
    std::uint32_t count,
    const std::uint32_t* const sourceValue,
    std::uint32_t* const destination
  ) noexcept
  {
    return FillDwordRangeFromPointerValueAndReturnRemaining(count, sourceValue, destination);
  }

  /**
   * Address: 0x004A0BF0 (FUN_004A0BF0, sub_4A0BF0)
   *
   * What it does:
   * Duplicate dword-range fill helper that writes one source slot value.
   */
  [[maybe_unused]] std::uint32_t FillDwordRangeFromPointerValueAndReturnRemainingDuplicateF(
    std::uint32_t count,
    const std::uint32_t* const sourceValue,
    std::uint32_t* const destination
  ) noexcept
  {
    return FillDwordRangeFromPointerValueAndReturnRemaining(count, sourceValue, destination);
  }

  /**
   * Address: 0x004A0C10 (FUN_004A0C10, sub_4A0C10)
   *
   * What it does:
   * Copy-constructs one world-particle range into destination storage with
   * rollback on constructor failure and returns destination end.
   */
  [[maybe_unused]] moho::SWorldParticle* CopyConstructWorldParticleRangeOrRollbackCore(
    moho::SWorldParticle* const destination,
    const moho::SWorldParticle* const sourceBegin,
    const moho::SWorldParticle* const sourceEnd
  )
  {
    CopyConstructWorldParticleRangeOrRollbackLocal(sourceBegin, sourceEnd, destination);
    return destination + (sourceEnd - sourceBegin);
  }

  /**
   * Address: 0x0049E3D0 (FUN_0049E3D0, sub_49E3D0)
   *
   * What it does:
   * Thin forwarding wrapper for world-particle range copy construction core.
   */
  [[maybe_unused]] moho::SWorldParticle* ForwardCopyConstructWorldParticleRange(
    moho::SWorldParticle* const destination,
    const moho::SWorldParticle* const sourceBegin,
    const moho::SWorldParticle* const sourceEnd
  )
  {
    return CopyConstructWorldParticleRangeOrRollbackCore(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x004A0CB0 (FUN_004A0CB0, sub_4A0CB0)
   *
   * What it does:
   * Copy-constructs one trail-runtime range into destination storage when
   * destination is present and returns destination end.
   */
  [[maybe_unused]] moho::TrailRuntimeView* CopyConstructTrailRuntimeRangeAndReturnEndCore(
    moho::TrailRuntimeView* const destination,
    const moho::TrailRuntimeView* const sourceBegin,
    const moho::TrailRuntimeView* const sourceEnd
  ) noexcept
  {
    return CopyConstructTrailRuntimeRangeAndReturnEndLocal(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x004A0CE0 (FUN_004A0CE0, sub_4A0CE0)
   *
   * What it does:
   * Copy-constructs one world-beam range into destination storage with rollback
   * on constructor failure and returns destination end.
   */
  [[maybe_unused]] moho::SWorldBeam* CopyConstructWorldBeamRangeOrRollbackCore(
    moho::SWorldBeam* const destination,
    const moho::SWorldBeam* const sourceBegin,
    const moho::SWorldBeam* const sourceEnd
  )
  {
    CopyConstructWorldBeamRangeOrRollback(sourceBegin, sourceEnd, destination);
    return destination + (sourceEnd - sourceBegin);
  }

  /**
   * Address: 0x004A0D80 (FUN_004A0D80, sub_4A0D80)
   *
   * What it does:
   * Copies one 15-float-lane range into nullable destination storage and
   * returns destination end.
   */
  [[maybe_unused]] float* CopyFifteenFloatLaneRangeAndReturnEndCore(
    float* const destination,
    const float* const sourceBegin,
    const float* const sourceEnd
  ) noexcept
  {
    return CopyFifteenFloatLaneRangeAndReturnEndLocal(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x004A0E00 (FUN_004A0E00, sub_4A0E00)
   *
   * What it does:
   * Copies one nullable dword-pair range and returns destination end.
   */
  [[maybe_unused]] DwordPairRuntime* CopyDwordPairRangeNullableAndReturnEndCoreA(
    DwordPairRuntime* const destination,
    const DwordPairRuntime* const sourceBegin,
    const DwordPairRuntime* const sourceEnd
  ) noexcept
  {
    return CopyDwordPairRangeWithNullableDestinationAndReturnEndLocal(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x004A0E20 (FUN_004A0E20, sub_4A0E20)
   *
   * What it does:
   * Duplicate nullable dword-pair range copy helper.
   */
  [[maybe_unused]] DwordPairRuntime* CopyDwordPairRangeNullableAndReturnEndCoreB(
    DwordPairRuntime* const destination,
    const DwordPairRuntime* const sourceBegin,
    const DwordPairRuntime* const sourceEnd
  ) noexcept
  {
    return CopyDwordPairRangeNullableAndReturnEndCoreA(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x004A0E40 (FUN_004A0E40, sub_4A0E40)
   *
   * What it does:
   * Lexicographically compares `count` 16-bit lanes and returns `-1/0/1`.
   */
  [[maybe_unused]] int CompareWordRangeLexicographicallyA(
    const std::uint16_t* lhs,
    std::uint32_t count,
    const std::uint16_t* rhs
  ) noexcept
  {
    while (count != 0U) {
      if (*lhs != *rhs) {
        return (*lhs < *rhs) ? -1 : 1;
      }
      ++lhs;
      ++rhs;
      --count;
    }
    return 0;
  }

  /**
   * Address: 0x004A0E70 (FUN_004A0E70, sub_4A0E70)
   *
   * What it does:
   * Duplicate 16-bit-lane lexicographic comparator.
   */
  [[maybe_unused]] int CompareWordRangeLexicographicallyB(
    const std::uint16_t* lhs,
    std::uint32_t count,
    const std::uint16_t* rhs
  ) noexcept
  {
    return CompareWordRangeLexicographicallyA(lhs, count, rhs);
  }

  /**
   * Address: 0x004A0EA0 (FUN_004A0EA0, sub_4A0EA0)
   *
   * What it does:
   * Returns the length of one zero-terminated 16-bit string.
   */
  [[maybe_unused]] std::int32_t GetZeroTerminatedWordStringLength(const std::uint16_t* text) noexcept
  {
    const std::uint16_t* cursor = text;
    while (*cursor != 0U) {
      ++cursor;
    }
    return static_cast<std::int32_t>(cursor - text);
  }

  /**
   * Address: 0x0049DDC0 (FUN_0049DDC0, func_StrCmp)
   *
   * What it does:
   * Returns whether one legacy string and one C-string differ by value.
   */
  [[maybe_unused]] bool AreMsvc8StringAndCStringDifferent(
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

  /**
   * Address: 0x0049D980 (FUN_0049D980, nullsub_615)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
  */
  [[maybe_unused]] void NoOpHelperThunkAL() noexcept {}

  /**
   * Address: 0x0049D990 (FUN_0049D990, nullsub_616)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkAM() noexcept {}

  /**
   * Address: 0x0049D9A0 (FUN_0049D9A0, nullsub_617)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkAN() noexcept {}

  /**
   * Address: 0x0049D9B0 (FUN_0049D9B0, nullsub_618)
   *
   * What it does:
   * No-op helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkAO() noexcept {}

  /**
   * Address: 0x0049D9C0 (FUN_0049D9C0, nullsub_619)
   *
   * What it does:
   * No-op stdcall helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkStdcallF(const std::uint32_t /*unused*/) noexcept {}

  /**
   * Address: 0x0049D9D0 (FUN_0049D9D0, nullsub_620)
   *
   * What it does:
   * No-op stdcall helper thunk retained for binary parity.
   */
  [[maybe_unused]] void NoOpHelperThunkStdcallG(const std::uint32_t /*unused*/) noexcept {}

  void AppendParticleBufferToPoolList(
    moho::ParticleBufferPoolListRuntime& poolRuntime,
    moho::ParticleBuffer* const particleBuffer
  )
  {
    if (poolRuntime.head == nullptr) {
      return;
    }

    auto* const node = static_cast<moho::ParticleBufferPoolNodeRuntime*>(
      ::operator new(sizeof(moho::ParticleBufferPoolNodeRuntime))
    );
    node->next = poolRuntime.head;
    node->prev = poolRuntime.head->prev;
    node->value = particleBuffer;

    if (poolRuntime.size < kLegacyListMaxSize) {
      ++poolRuntime.size;
    }

    poolRuntime.head->prev = node;
    node->prev->next = node;
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
    auto& runtime = reinterpret_cast<CWorldParticlesRuntimeView&>(*this);

    InitializeParticleBufferPoolList(runtime.allParticleBuffers);
    InitializeParticleBufferPoolList(runtime.availableParticleBuffers);
    InitializeTrailSegmentPool(runtime.trailSegmentPool);

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

    ReleaseTrailSegmentPoolStorage(runtime.trailSegmentPool);
    ReleaseParticleBufferPoolListStorage(runtime.availableParticleBuffers);
    ReleaseParticleBufferPoolListStorage(runtime.allParticleBuffers);
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
      (void)AppendRenderBucketVectorValue((*bucketCacheSlot)->pendingParticles, particle);
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
        auto* const newBucket = static_cast<ParticleRenderBucketRuntime*>(
          ::operator new(sizeof(ParticleRenderBucketRuntime))
        );
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

      (void)AppendRenderBucketVectorValue(AsParticleBucketEntryNode(candidateNode)->bucket->pendingParticles, particle);
      ResetParticleBucketKeyResources(lookupKey);
      return;
    }

    if (runtime.cachedParticleBucket != nullptr &&
        AreParticleBucketKeysEquivalent(runtime.particleBucketLookupKey, lookupKey)) {
      (void)AppendRenderBucketVectorValue(runtime.cachedParticleBucket->pendingParticles, particle);
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
      auto* const newBucket = static_cast<ParticleRenderBucketRuntime*>(
        ::operator new(sizeof(ParticleRenderBucketRuntime))
      );
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
    (void)AppendRenderBucketVectorValue(bucket->pendingParticles, particle);
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
      (void)AppendRenderBucketVectorValue((*bucketCacheSlot)->pendingTrails, trail);
      return;
    }

    auto& runtime = reinterpret_cast<CWorldParticlesRuntimeView&>(*this);
    TrailBucketKeyRuntime lookupKey{};
    (void)InitializeTrailBucketKeyFromTrail(&lookupKey, trail);

    if (runtime.cachedTrailBucket != nullptr &&
        AreTrailBucketKeysEquivalent(runtime.trailBucketLookupKey, lookupKey)) {
      (void)AppendRenderBucketVectorValue(runtime.cachedTrailBucket->pendingTrails, trail);
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
      auto* const newBucket = static_cast<TrailRenderBucketRuntime*>(
        ::operator new(sizeof(TrailRenderBucketRuntime))
      );
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
    (void)AppendRenderBucketVectorValue(bucket->pendingTrails, trail);
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
  void CWorldParticles::AddParticles(const ParticleSubmitBufferRuntimeView& batch)
  {
    if (batch.particlesBegin != nullptr && batch.particlesEnd != nullptr) {
      for (const SWorldParticle* particle = batch.particlesBegin; particle != batch.particlesEnd; ++particle) {
        AddWorldParticle(*particle, nullptr);
      }
    }

    if (batch.trailsBegin != nullptr && batch.trailsEnd != nullptr) {
      for (const TrailRuntimeView* trail = batch.trailsBegin; trail != batch.trailsEnd; ++trail) {
        AddTrail(*trail, nullptr);
      }
    }

    if (batch.beamsBegin != nullptr && batch.beamsEnd != nullptr) {
      for (const SWorldBeam* beam = batch.beamsBegin; beam != batch.beamsEnd; ++beam) {
        AddBeam(*beam);
      }
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
    boost::weak_ptr<gpg::gal::TextureD3D9> backgroundTexture
  )
  {
    Init();

    CD3DDevice* const device = D3D_GetDevice();
    device->SelectFxFile("particle");

    BindParticleCameraShaderState(camera, tick, frameDelta);
    if (shaderVarParticleBackgroundTexture.Exists()) {
      shaderVarParticleBackgroundTexture.GetTexture(backgroundTexture);
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

    auto& runtime = reinterpret_cast<CWorldParticlesRuntimeView&>(*this);
    InitializeParticleBufferPoolList(runtime.allParticleBuffers);
    InitializeParticleBufferPoolList(runtime.availableParticleBuffers);
    InitializeTrailSegmentPool(runtime.trailSegmentPool);

    CD3DDevice* const device = D3D_GetDevice();
    ID3DDeviceResources* const resources = device->GetResources();
    CD3DVertexFormat* const trailVertexFormat = resources->GetVertexFormat(kTrailVertexFormatToken);

    for (int bufferIndex = 0; bufferIndex < kPooledParticleBufferCount; ++bufferIndex) {
      auto* const particleBuffer = new ParticleBuffer();
      particleBuffer->Shutdown();
      particleBuffer->mMaxParticles = kParticleBufferCapacity;

      AppendParticleBufferToPoolList(runtime.availableParticleBuffers, particleBuffer);
      AppendParticleBufferToPoolList(runtime.allParticleBuffers, particleBuffer);
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

      ReturnTrailSegmentBufferToOwnerPool(this, segmentBuffer);
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
    auto& runtime = reinterpret_cast<CWorldParticlesRuntimeView&>(sWorldParticles);

    if (runtime.allParticleBuffers.head != nullptr) {
      auto* const head = runtime.allParticleBuffers.head;
      for (auto* node = head->next; node != nullptr && node != head; node = node->next) {
        if (node->value != nullptr) {
          delete node->value;
          node->value = nullptr;
        }
      }
    }

    DestroyParticleBufferPoolListNodes(runtime.availableParticleBuffers, false);
    DestroyParticleBufferPoolListNodes(runtime.allParticleBuffers, false);
    ResetTrailSegmentPool(runtime.trailSegmentPool);

    runtime.beatsSincePause = 0;
    runtime.instantiated = false;
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
