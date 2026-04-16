#include "moho/render/d3d/ShaderVar.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>

#include "gpg/gal/backends/d3d9/EffectD3D9.hpp"
#include "gpg/gal/backends/d3d9/EffectVariableD3D9.hpp"
#include "gpg/gal/backends/d3d9/TextureD3D9.hpp"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/textures/CD3DDynamicTextureSheet.h"

namespace
{
  template <std::uintptr_t SlotAddress>
  struct ShaderVarSlot;

#define DEFINE_SHADER_VAR_SLOT(SLOT_ADDRESS) \
  template <> \
  struct ShaderVarSlot<SLOT_ADDRESS> \
  { \
    alignas(moho::ShaderVar) static std::byte storage[sizeof(moho::ShaderVar)]; \
    static bool constructed; \
  }; \
  alignas(moho::ShaderVar) std::byte ShaderVarSlot<SLOT_ADDRESS>::storage[sizeof(moho::ShaderVar)]{}; \
  bool ShaderVarSlot<SLOT_ADDRESS>::constructed = false

  DEFINE_SHADER_VAR_SLOT(0x010A7840u);
  DEFINE_SHADER_VAR_SLOT(0x010A78D0u);
  DEFINE_SHADER_VAR_SLOT(0x010A7888u);

#undef DEFINE_SHADER_VAR_SLOT

  template <std::uintptr_t SlotAddress>
  [[nodiscard]] moho::ShaderVar& AccessShaderVarSlot() noexcept
  {
    auto* const slot = reinterpret_cast<moho::ShaderVar*>(ShaderVarSlot<SlotAddress>::storage);
    if (!ShaderVarSlot<SlotAddress>::constructed) {
      ::new (static_cast<void*>(slot)) moho::ShaderVar();
      ShaderVarSlot<SlotAddress>::constructed = true;
    }
    return *slot;
  }

  template <std::uintptr_t SlotAddress>
  void DestroyShaderVarSlot() noexcept
  {
    if (!ShaderVarSlot<SlotAddress>::constructed) {
      return;
    }

    AccessShaderVarSlot<SlotAddress>().~ShaderVar();
    ShaderVarSlot<SlotAddress>::constructed = false;
  }

  [[nodiscard]] moho::CD3DEffect* ResolveOwnerEffect(const moho::ShaderVar& shaderVar) noexcept
  {
    return reinterpret_cast<moho::CD3DEffect*>(shaderVar.mEffectLink.mLinkLane);
  }

  /**
   * Address: 0x0043A970 (FUN_0043A970, sub_43A970)
   *
   * What it does:
   * Rebinds one shader-var attached-link lane to a new owner effect, updating
   * intrusive list linkage on both detach and attach paths.
   */
  moho::ShaderVar& RelinkShaderVarEffect(moho::ShaderVar& shaderVar, moho::CD3DEffect* const effect) noexcept
  {
    moho::CD3DEffect* const currentOwner = ResolveOwnerEffect(shaderVar);
    if (currentOwner != effect) {
      if (currentOwner != nullptr) {
        moho::CD3DEffect::AttachedLink** it = &currentOwner->mAttachedLinks;
        while (*it != &shaderVar.mEffectLink) {
          it = &((*it)->mNext);
        }
        *it = shaderVar.mEffectLink.mNext;
      }

      shaderVar.mEffectLink.mLinkLane = reinterpret_cast<moho::CD3DEffect::AttachedLink*>(effect);
      if (effect != nullptr) {
        shaderVar.mEffectLink.mNext = effect->mAttachedLinks;
        effect->mAttachedLinks = &shaderVar.mEffectLink;
      } else {
        shaderVar.mEffectLink.mNext = nullptr;
      }
    }

    return shaderVar;
  }

  template <std::uintptr_t SlotAddress>
  void RegisterPrimBatcherShaderVar(const char* const variableName, void (*cleanupFn)())
  {
    moho::ShaderVar& slot = AccessShaderVarSlot<SlotAddress>();
    moho::RegisterShaderVar(variableName, &slot, "primbatcher");
    (void)std::atexit(cleanupFn);
  }

  struct PrimBatcherShaderVarBootstrap
  {
    PrimBatcherShaderVarBootstrap()
    {
      moho::register_ShaderVarPrimBatcherCompositeMatrix();
      moho::register_ShaderVarPrimBatcherTexture1();
      moho::register_ShaderVarPrimBatcherAlphaMultiplier();
    }
  };

  [[maybe_unused]] PrimBatcherShaderVarBootstrap gPrimBatcherShaderVarBootstrap;
} // namespace

namespace moho
{
  [[nodiscard]] ShaderVar& GetPrimBatcherCompositeMatrixShaderVar()
  {
    return AccessShaderVarSlot<0x010A7840u>();
  }

  [[nodiscard]] ShaderVar& GetPrimBatcherTexture1ShaderVar()
  {
    return AccessShaderVarSlot<0x010A78D0u>();
  }

  [[nodiscard]] ShaderVar& GetPrimBatcherAlphaMultiplierShaderVar()
  {
    return AccessShaderVarSlot<0x010A7888u>();
  }

  /**
   * Address: 0x00438000 (FUN_00438000, func_register_ShaderVar)
   *
   * What it does:
   * Initializes one shader-var slot with variable/effect-file names and clears
   * effect/effect-variable link state.
   */
  ShaderVar* RegisterShaderVar(
    const char* const variableName, ShaderVar* const shaderVar, const char* const effectFileName
  )
  {
    if (shaderVar == nullptr) {
      return nullptr;
    }

    const char* const safeVariableName = (variableName != nullptr) ? variableName : "";
    const char* const safeEffectFileName = (effectFileName != nullptr) ? effectFileName : "";

    shaderVar->mVariableName.tidy(true, 0U);
    shaderVar->mVariableName.assign_owned(safeVariableName);

    shaderVar->mEffectFileName.tidy(true, 0U);
    shaderVar->mEffectFileName.assign_owned(safeEffectFileName);

    shaderVar->mEffectLink.mLinkLane = nullptr;
    shaderVar->mEffectLink.mNext = nullptr;
    shaderVar->mEffectVariable.reset();
    return shaderVar;
  }

  /**
   * Address: 0x007E9040 (FUN_007E9040, func_register_ShaderVar_5)
   *
   * What it does:
   * Adapts the caller order `(effectFileName, variableName, shaderVar)` to the
   * canonical shader-var registration lane and returns the same shader-var slot.
   */
  ShaderVar* RegisterShaderVarFromEffectFileFirst(
    const char* const effectFileName,
    const char* const variableName,
    ShaderVar* const shaderVar
  )
  {
    RegisterShaderVar(variableName, shaderVar, effectFileName);
    return shaderVar;
  }

  /**
   * Address: 0x00437ED0 (FUN_00437ED0, struct_ShaderVar::Exists)
   *
   * What it does:
   * Ensures this shader-var is attached to one loaded effect, resolves the
   * effect-variable lane on first attach, and reports availability.
   */
  bool ShaderVar::Exists()
  {
    if (ResolveOwnerEffect(*this) != nullptr) {
      return true;
    }

    if (!mEffectFileName.empty()) {
      CD3DDevice* const device = D3D_GetDevice();
      if (device != nullptr) {
        ID3DDeviceResources* const resources = device->GetResources();
        RelinkShaderVarEffect(*this, resources != nullptr ? resources->FindEffect(mEffectFileName.c_str()) : nullptr);
      }
    }

    CD3DEffect* const effect = ResolveOwnerEffect(*this);
    if (effect == nullptr) {
      return false;
    }

    boost::shared_ptr<gpg::gal::EffectD3D9> baseEffect = effect->GetBaseEffect();
    mEffectVariable = baseEffect->SetMatrix(mVariableName.c_str());
    return mEffectVariable.get() != nullptr;
  }

  /**
   * Address: 0x00438140 (FUN_00438140, struct_ShaderVar::GetTexture)
   *
   * What it does:
   * Resolves this shader-var if needed and pushes one optional texture handle
   * into the bound effect-variable lane.
   */
  ShaderVar* ShaderVar::GetTexture(const boost::shared_ptr<CD3DDynamicTextureSheet>& textureSheet)
  {
    if (Exists()) {
      CD3DDynamicTextureSheet::TextureHandle textureHandle{};
      if (textureSheet != nullptr) {
        textureSheet->GetTexture(textureHandle);
      }
      mEffectVariable->SetTexture(textureHandle);
    }

    return this;
  }

  /**
   * Address: 0x00491280 (FUN_00491280, sub_491280)
   *
   * What it does:
   * Resolves this shader-var if needed and binds one weak texture handle to
   * the backing effect-variable lane.
   */
  ShaderVar* ShaderVar::GetTexture(const boost::weak_ptr<gpg::gal::TextureD3D9>& textureHandle)
  {
    if (!Exists()) {
      return this;
    }

    boost::shared_ptr<gpg::gal::TextureD3D9> resolvedTexture = textureHandle.lock();
    mEffectVariable->SetTexture(resolvedTexture);
    return this;
  }

  /**
   * Address: 0x004380D0 (FUN_004380D0, struct_ShaderVar::SetFloat)
   *
   * What it does:
   * Guards on `Exists()` and forwards one float value to the bound
   * effect variable.
   */
  ShaderVar* ShaderVar::SetFloat(const float value)
  {
    if (Exists()) {
      mEffectVariable->SetFloat(value);
    }
    return this;
  }

  /**
   * Address: 0x00438100 (FUN_00438100, struct_ShaderVar::SetMatrix4x4)
   *
   * What it does:
   * Guards on `Exists()` and forwards one 4x4 matrix pointer to the bound
   * effect variable.
   */
  ShaderVar* ShaderVar::SetMatrix4x4(const void* const matrix4x4)
  {
    if (Exists()) {
      mEffectVariable->SetMatrix4x4(matrix4x4);
    }
    return this;
  }

  /**
   * Address: 0x004381B0 (FUN_004381B0, ??1struct_ShaderVar@@QAE@@Z)
   *
   * What it does:
   * Releases the cached effect-variable handle, detaches from the owning
   * effect's attached-link list, and clears both cached strings.
   */
  ShaderVar::~ShaderVar()
  {
    mEffectVariable.reset();
    RelinkShaderVarEffect(*this, nullptr);

    mEffectFileName.tidy(true, 0U);
    mVariableName.tidy(true, 0U);
  }

  /**
   * Address: 0x00BEF140 (FUN_00BEF140, sub_BEF140)
   *
   * What it does:
   * Runs the prim-batcher `CompositeMatrix` shader-var destructor at process
   * exit.
   */
  void cleanup_ShaderVarPrimBatcherCompositeMatrix()
  {
    DestroyShaderVarSlot<0x010A7840u>();
  }

  /**
   * Address: 0x00BC3FF0 (FUN_00BC3FF0, register_ShaderVarPrimBatcherCompositeMatrix)
   *
   * What it does:
   * Registers the prim-batcher `CompositeMatrix` shader-var and its exit cleanup
   * thunk.
   */
  void register_ShaderVarPrimBatcherCompositeMatrix()
  {
    RegisterPrimBatcherShaderVar<0x010A7840u>("CompositeMatrix", &cleanup_ShaderVarPrimBatcherCompositeMatrix);
  }

  /**
   * Address: 0x00BEF150 (FUN_00BEF150, sub_BEF150)
   *
   * What it does:
   * Runs the prim-batcher `Texture1` shader-var destructor at process exit.
   */
  void cleanup_ShaderVarPrimBatcherTexture1()
  {
    DestroyShaderVarSlot<0x010A78D0u>();
  }

  /**
   * Address: 0x00BC4010 (FUN_00BC4010, register_ShaderVarPrimBatcherTexture1)
   *
   * What it does:
   * Registers the prim-batcher `Texture1` shader-var and its exit cleanup thunk.
   */
  void register_ShaderVarPrimBatcherTexture1()
  {
    RegisterPrimBatcherShaderVar<0x010A78D0u>("Texture1", &cleanup_ShaderVarPrimBatcherTexture1);
  }

  /**
   * Address: 0x00BEF160 (FUN_00BEF160, sub_BEF160)
   *
   * What it does:
   * Runs the prim-batcher `AlphaMultiplier` shader-var destructor at process
   * exit.
   */
  void cleanup_ShaderVarPrimBatcherAlphaMultiplier()
  {
    DestroyShaderVarSlot<0x010A7888u>();
  }

  /**
   * Address: 0x00BC4030 (FUN_00BC4030, register_ShaderVarPrimBatcherAlphaMultiplier)
   *
   * What it does:
   * Registers the prim-batcher `AlphaMultiplier` shader-var and its exit cleanup
   * thunk.
   */
  void register_ShaderVarPrimBatcherAlphaMultiplier()
  {
    RegisterPrimBatcherShaderVar<0x010A7888u>("AlphaMultiplier", &cleanup_ShaderVarPrimBatcherAlphaMultiplier);
  }
} // namespace moho
