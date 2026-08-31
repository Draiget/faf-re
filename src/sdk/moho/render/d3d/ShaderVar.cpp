#include "moho/render/d3d/ShaderVar.h"

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>

#include "gpg/gal/Error.hpp"
#include "gpg/gal/backends/d3d9/EffectD3D9.hpp"
#include "gpg/gal/backends/d3d9/EffectVariableD3D9.hpp"
#include "gpg/gal/backends/d3d9/TextureD3D9.hpp"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/ID3DRenderTarget.h"
#include "moho/render/ID3DTextureSheet.h"
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
  DEFINE_SHADER_VAR_SLOT(0x010C0630u);
  DEFINE_SHADER_VAR_SLOT(0x010C02D0u);

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

  struct TerrainCommonShaderVarBootstrap
  {
    TerrainCommonShaderVarBootstrap()
    {
      moho::register_ShaderVarTerrainHeightScale();
      moho::register_ShaderVarTerrainTime();
    }
  };

  [[maybe_unused]] TerrainCommonShaderVarBootstrap gTerrainCommonShaderVarBootstrap;
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
   * Standalone terrain shader-var globals bound by every TerrainCommon
   * fidelity class's Func3 override (`shaderVarTerrainHeightScale`/
   * `shaderVarTerrainTime` in the binary - direct symbol references, not
   * members of `TerrainShaderVarSet`, confirmed via `mov esi, offset
   * shaderVarTerrainHeightScale` at 0x00800550/0x0080057D in
   * HighFidelityTerrain::Func3's disassembly).
   */
  [[nodiscard]] ShaderVar& GetTerrainHeightScaleShaderVar()
  {
    return AccessShaderVarSlot<0x010C0630u>();
  }

  [[nodiscard]] ShaderVar& GetTerrainTimeShaderVar()
  {
    return AccessShaderVarSlot<0x010C02D0u>();
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
   *
   * Fidelity note: the binary's own lookup (`EffectD3D9::SetMatrix`, really
   * a by-name parameter resolver -- FUN_00941D70) unconditionally throws
   * `gpg::gal::Error` when the named parameter is absent from the bound
   * effect (confirmed from its raw .asm: `cmp edi, ebx` / `jnz` on the
   * returned handle, no null-tolerant path). `ShaderVar::Exists()` itself
   * sets up no catch of its own -- its SEH frame (`SEH_437ED0`) only unwinds
   * the two local `boost::shared_ptr`s, matching the plain non-exceptional
   * return paths already in this function's decompile. Live testing against
   * the currently-installed FAForever asset set (effects.nx2) shows real
   * effect files that genuinely lack parameters this engine code expects
   * -- e.g. `water2.fx` here has none of WaterColor/WaterLerp/FresnelBias/
   * FresnelPower/UnitReflectionAmount/SkyReflectionAmount/NormalRepeatRate/
   * Normal1-4Movement/SunShininess/SunReflectionAmount/SunDirection, byte-
   * verified absent from its source text (not merely dead-stripped by the
   * effect compiler) -- so the literal 2007 throw-on-miss behavior crashes
   * the whole process on the very first water-rendering frame
   * (HighFidelityWater::RenderWaterSurface -> SetShaderVarMem -> here), and
   * the same defect already crashed terrain rendering once (fixed in
   * 6823547b / b65f910b) before this water instance surfaced. `Exists()`'s
   * own name and every calling convention across this codebase (terrain,
   * water, and the GetTexture() below) already assume a safe, non-throwing
   * bool check -- that split-brain (safe contract wrapping an unsafe
   * primitive) is the actual bug. Catching here, at the one choke point
   * every caller already funnels through, keeps every other call site
   * exactly as recovered and matches the documented design intent instead
   * of the letter of one binary snapshot tested against different content.
   *
   * Second-order fallout from that same catch, found live via
   * HighFidelityWater::RenderWaterSurface -> SetShaderVarMem crashing on
   * frame 2: the fast path below (`owner effect linked -> return true`) is
   * the binary's own early-out, and in 2007 it was sound -- every parameter
   * referenced by engine code shipped in its effect file, so "linked" and
   * "mEffectVariable resolved" were the same fact. The catch above breaks
   * that invariant: the first Exists() call for a missing parameter links
   * the owner effect via RelinkShaderVarEffect() *before* the failing
   * SetMatrix(), catches, and returns false with mEffectVariable still
   * empty. Every later call for that same shader-var (every subsequent
   * frame, for a per-frame water write) then hits this fast path, finds the
   * effect already linked, and returned `true` unconditionally -- handing
   * SetShaderVarMem/GetTexture/etc. a still-empty mEffectVariable to
   * dereference. Requiring the cached variable too, not just the link,
   * keeps the fast path's intent (skip a re-resolve once we know the
   * answer) while making the cached answer match what was actually cached.
   */
  bool ShaderVar::Exists()
  {
    if (ResolveOwnerEffect(*this) != nullptr) {
      return mEffectVariable.get() != nullptr;
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
    try {
      mEffectVariable = baseEffect->SetMatrix(mVariableName.c_str());
    } catch (const gpg::gal::Error&) {
      return false;
    }
    return mEffectVariable.get() != nullptr;
  }

  /**
   * Address: 0x00438140 (FUN_00438140, struct_ShaderVar::GetTexture)
   *
   * What it does:
   * Resolves this shader-var if needed and pushes one optional texture handle
   * into the bound effect-variable lane.
   */
  ShaderVar* ShaderVar::GetTexture(const boost::shared_ptr<ID3DTextureSheet>& textureSheet)
  {
    if (Exists()) {
      ID3DTextureSheet::TextureHandle textureHandle{};
      if (textureSheet != nullptr) {
        textureSheet->GetTexture(textureHandle);
      }
      mEffectVariable->SetTexture(textureHandle);
    }

    return this;
  }

  /**
   * Address: 0x00491280 (FUN_00491280)
   *
   * What it does:
   * Resolves this shader-var if needed, asks the render target for its GAL
   * surface and binds that surface to the effect variable. A null render target
   * binds an empty surface handle.
   *
   * The binary reads only the handle's px word (0x00491299 `mov ecx, [eax]`),
   * calls vtable slot 2 of that object (0x004912AA `mov edx, [edx+8]`) - which
   * is ID3DRenderTarget::GetSurface, writing a
   * boost::shared_ptr<gpg::gal::RenderTargetD3D9> into an 8-byte temporary -
   * and hands that temporary to effect-variable vtable slot 3 (0x004912B5
   * `mov edx, [eax+0Ch]`), the render-target binder. The null branch at
   * 0x004912C6 zeroes the same temporary and calls the same slot, so both paths
   * bind, they only differ in what.
   */
  ShaderVar* ShaderVar::SetRenderTargetTexture(const boost::shared_ptr<ID3DRenderTarget>& renderTarget)
  {
    if (Exists()) {
      ID3DRenderTarget::SurfaceHandle surfaceHandle{};
      if (renderTarget != nullptr) {
        renderTarget->GetSurface(surfaceHandle);
      }
      mEffectVariable->Func3(surfaceHandle);
    }

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

  /**
   * Address: 0x00BE2F70 (FUN_00BE2F70, register_ShaderVarTerrainHeightScale)
   * Cleanup: 0x00C056A0 (registered via atexit)
   *
   * What it does:
   * Runs the terrain height-scale shader-var destructor at process exit.
   * The registrar's own disassembly (0x00BE2F70) confirms the registration
   * key is the bare effect-parameter name `"HeightScale"`, not
   * `"TerrainHeightScale"` -- the earlier note conflated IDA's own label for
   * the global slot (`shaderVarTerrainHeightScale`, referenced by address in
   * HighFidelityTerrain::Func3 at 0x00800550) with the runtime lookup string,
   * which is a different thing entirely. `terrain.fx` (effects.nx2) declares
   * the parameter as `float HeightScale;` with no prefix, confirming this by
   * the shipped asset too. The stale key made `ShaderVar::Exists()` throw
   * uncaught on every terrain render (`EffectD3D9::SetMatrix`/
   * `GetParameterByName` finds nothing and calls `ThrowGalError`), crashing
   * the process on the first painted frame.
   */
  void cleanup_ShaderVarTerrainHeightScale()
  {
    DestroyShaderVarSlot<0x010C0630u>();
  }

  void register_ShaderVarTerrainHeightScale()
  {
    ShaderVar& slot = AccessShaderVarSlot<0x010C0630u>();
    RegisterShaderVar("HeightScale", &slot, "terrain");
    (void)std::atexit(&cleanup_ShaderVarTerrainHeightScale);
  }

  /**
   * Address: 0x00BE2FB0 (FUN_00BE2FB0, register_ShaderVarTerrainTime)
   * Cleanup: 0x00C056C0 (registered via atexit)
   *
   * What it does:
   * Runs the terrain time shader-var destructor at process exit. Same
   * mislabeled-evidence bug as `cleanup_ShaderVarTerrainHeightScale`: the
   * registrar's own disassembly (0x00BE2FB0) shows the registration key is
   * `"Time"`, matching `terrain.fx`'s `float Time;` -- not `"TerrainTime"`.
   */
  void cleanup_ShaderVarTerrainTime()
  {
    DestroyShaderVarSlot<0x010C02D0u>();
  }

  void register_ShaderVarTerrainTime()
  {
    ShaderVar& slot = AccessShaderVarSlot<0x010C02D0u>();
    RegisterShaderVar("Time", &slot, "terrain");
    (void)std::atexit(&cleanup_ShaderVarTerrainTime);
  }

  /**
   * Address: 0x010BF4E0 (?shaderVarFrameGlowCopyAdd@Moho@@3UstructShaderVar@@A)
   *
   * What it does:
   * The glow-copy strength CBloomRenderer::DoBloom binds (0x007F526A, then
   * reads .effectVar.var at +0x40). It sits in the zero-fill tail of .data,
   * so the shipped image starts it default-constructed.
   *
   * Declared extern where it is used but defined nowhere, so the /FORCE link
   * bound it to a null and DoBloom faulted calling Exists() on it.
   */
  ShaderVar shaderVarFrameGlowCopyAdd;

} // namespace moho
