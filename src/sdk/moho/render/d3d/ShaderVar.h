#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "boost/weak_ptr.h"
#include "legacy/containers/String.h"
#include "moho/render/d3d/CD3DEffectTechnique.h"

namespace gpg::gal
{
  class EffectVariableD3D9;
  class TextureD3D9;
} // namespace gpg::gal

namespace moho
{
  class CD3DDynamicTextureSheet;

  struct ShaderVar
  {
    /**
     * Address: 0x004381B0 (FUN_004381B0, ??1struct_ShaderVar@@QAE@@Z)
     *
     * What it does:
     * Releases the cached effect-variable handle, detaches from the owning
     * effect's attached-link list, and clears both cached strings.
     */
    ~ShaderVar();

    /**
     * Address: 0x00437ED0 (FUN_00437ED0, struct_ShaderVar::Exists)
     *
     * What it does:
     * Ensures this shader-var is attached to one loaded effect, resolves the
     * effect-variable lane on first attach, and reports availability.
     */
    [[nodiscard]] bool Exists();

    /**
     * Address: 0x00438140 (FUN_00438140, struct_ShaderVar::GetTexture)
     *
     * What it does:
     * Resolves this shader-var if needed and pushes one optional texture handle
     * into the bound effect-variable lane.
     */
    ShaderVar* GetTexture(const boost::shared_ptr<CD3DDynamicTextureSheet>& textureSheet);

    /**
     * Address: 0x00491280 (FUN_00491280, sub_491280)
     *
     * What it does:
     * Resolves this shader-var if needed and binds one weak texture handle to
     * the backing effect-variable lane.
     */
    ShaderVar* GetTexture(const boost::weak_ptr<gpg::gal::TextureD3D9>& textureHandle);

    /**
     * Address: 0x004380D0 (FUN_004380D0, struct_ShaderVar::SetFloat)
     *
     * What it does:
     * If the shader-var has a bound effect variable, writes one float value
     * into it through the effect-variable virtual dispatch.
     */
    ShaderVar* SetFloat(float value);

    /**
     * Address: 0x00438100 (FUN_00438100, struct_ShaderVar::SetMatrix4x4)
     *
     * What it does:
     * If the shader-var has a bound effect variable, writes one 4x4 matrix
     * pointer into it through the effect-variable virtual dispatch.
     */
    ShaderVar* SetMatrix4x4(const void* matrix4x4);

  public:
    msvc8::string mVariableName{};                             // +0x00
    msvc8::string mEffectFileName{};                           // +0x1C
    CD3DEffect::AttachedLink mEffectLink{};                    // +0x38
    boost::shared_ptr<gpg::gal::EffectVariableD3D9> mEffectVariable{}; // +0x40
  };

  static_assert(offsetof(ShaderVar, mVariableName) == 0x00, "moho::ShaderVar::mVariableName offset must be 0x00");
  static_assert(offsetof(ShaderVar, mEffectFileName) == 0x1C, "moho::ShaderVar::mEffectFileName offset must be 0x1C");
  static_assert(offsetof(ShaderVar, mEffectLink) == 0x38, "moho::ShaderVar::mEffectLink offset must be 0x38");
  static_assert(offsetof(ShaderVar, mEffectVariable) == 0x40, "moho::ShaderVar::mEffectVariable offset must be 0x40");
  static_assert(sizeof(ShaderVar) == 0x48, "moho::ShaderVar size must be 0x48");

  /**
   * Address: 0x00438000 (FUN_00438000, func_register_ShaderVar)
   *
   * What it does:
   * Initializes one shader-var slot with variable/effect-file names and clears
   * effect/effect-variable link state.
   */
  ShaderVar* RegisterShaderVar(const char* variableName, ShaderVar* shaderVar, const char* effectFileName);

  /**
   * Address: 0x007E9040 (FUN_007E9040, func_register_ShaderVar_5)
   *
   * What it does:
   * Forwards one `(effectFileName, variableName, shaderVar)` call-shape to
   * `RegisterShaderVar(variableName, shaderVar, effectFileName)` and returns
   * the shader-var slot.
   */
  ShaderVar* RegisterShaderVarFromEffectFileFirst(
    const char* effectFileName,
    const char* variableName,
    ShaderVar* shaderVar
  );

  /**
   * Address: 0x00BC3FF0 (FUN_00BC3FF0, register_ShaderVarPrimBatcherCompositeMatrix)
   *
   * What it does:
   * Registers the prim-batcher `CompositeMatrix` shader-var and its exit cleanup
   * thunk.
   */
  void register_ShaderVarPrimBatcherCompositeMatrix();

  /**
   * Address: 0x00BC4010 (FUN_00BC4010, register_ShaderVarPrimBatcherTexture1)
   *
   * What it does:
   * Registers the prim-batcher `Texture1` shader-var and its exit cleanup thunk.
   */
  void register_ShaderVarPrimBatcherTexture1();

  /**
   * Address: 0x00BC4030 (FUN_00BC4030, register_ShaderVarPrimBatcherAlphaMultiplier)
   *
   * What it does:
   * Registers the prim-batcher `AlphaMultiplier` shader-var and its exit cleanup
   * thunk.
   */
  void register_ShaderVarPrimBatcherAlphaMultiplier();

  /**
   * Address: 0x00BEF140 (FUN_00BEF140, sub_BEF140)
   *
   * What it does:
   * Runs the prim-batcher `CompositeMatrix` shader-var destructor at process
   * exit.
   */
  void cleanup_ShaderVarPrimBatcherCompositeMatrix();

  /**
   * Address: 0x00BEF150 (FUN_00BEF150, sub_BEF150)
   *
   * What it does:
   * Runs the prim-batcher `Texture1` shader-var destructor at process exit.
   */
  void cleanup_ShaderVarPrimBatcherTexture1();

  /**
   * Address: 0x00BEF160 (FUN_00BEF160, sub_BEF160)
   *
   * What it does:
   * Runs the prim-batcher `AlphaMultiplier` shader-var destructor at process
   * exit.
   */
  void cleanup_ShaderVarPrimBatcherAlphaMultiplier();

  [[nodiscard]] ShaderVar& GetPrimBatcherCompositeMatrixShaderVar();
  [[nodiscard]] ShaderVar& GetPrimBatcherTexture1ShaderVar();
  [[nodiscard]] ShaderVar& GetPrimBatcherAlphaMultiplierShaderVar();
} // namespace moho
