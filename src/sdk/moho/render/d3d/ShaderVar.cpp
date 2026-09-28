#include "moho/render/d3d/ShaderVar.h"

#include <cstddef>
#include <cstdint>

#include "gpg/gal/Error.hpp"
#include "gpg/gal/Effect.hpp"
#include "gpg/gal/EffectVariable.hpp"
#include "gpg/gal/backends/d3d9/TextureD3D9.hpp"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/ID3DRenderTarget.h"
#include "moho/render/ID3DTextureSheet.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/textures/CD3DDynamicTextureSheet.h"

namespace moho
{
  // The six globals below are defined ahead of the bootstrap objects further
  // down in this file: C++ constructs a translation unit's namespace-scope
  // objects in definition order, so each one is default-constructed before
  // its registrar runs `RegisterShaderVar` on it. No other translation unit
  // reads them during static initialization.

  /**
   * Address: 0x00BEF140 (FUN_00BEF140, dynamic atexit destructor for `shaderVarPrimBatcherCompositeMatrix`)
   *
   * What it does:
   * The prim-batcher `CompositeMatrix` shader-var (binary global 0x010A7840).
   */
  ShaderVar shaderVarPrimBatcherCompositeMatrix;

  /**
   * Address: 0x00BEF150 (FUN_00BEF150, dynamic atexit destructor for `shaderVarPrimBatcherTexture1`)
   *
   * What it does:
   * The prim-batcher `Texture1` shader-var (binary global 0x010A78D0).
   */
  ShaderVar shaderVarPrimBatcherTexture1;

  /**
   * Address: 0x00BEF160 (FUN_00BEF160, dynamic atexit destructor for `shaderVarPrimBatcherAlphaMultiplier`)
   *
   * What it does:
   * The prim-batcher `AlphaMultiplier` shader-var (binary global 0x010A7888).
   */
  ShaderVar shaderVarPrimBatcherAlphaMultiplier;

  /**
   * Address: 0x00C07480 (FUN_00C07480, dynamic atexit destructor for `shaderVarPrimBatcherTime`)
   *
   * What it does:
   * The prim-batcher `time` shader-var (binary global 0x010C4340).
   */
  ShaderVar shaderVarPrimBatcherTime;

  /**
   * Address: 0x00C056A0 (FUN_00C056A0, dynamic atexit destructor for `shaderVarTerrainHeightScale`)
   *
   * What it does:
   * The terrain `HeightScale` shader-var (binary global 0x010C0630), bound by
   * every TerrainCommon fidelity class's Func3 override (`mov esi, offset
   * shaderVarTerrainHeightScale` at 0x00800550 in HighFidelityTerrain::Func3).
   */
  ShaderVar shaderVarTerrainHeightScale;

  /**
   * Address: 0x00C056C0 (FUN_00C056C0, dynamic atexit destructor for `shaderVarTerrainTime`)
   *
   * What it does:
   * The terrain `Time` shader-var (binary global 0x010C02D0), bound next to
   * `shaderVarTerrainHeightScale` (0x0080057D in HighFidelityTerrain::Func3).
   */
  ShaderVar shaderVarTerrainTime;
} // namespace moho

namespace
{
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

  struct PrimBatcherShaderVarBootstrap
  {
    PrimBatcherShaderVarBootstrap()
    {
      moho::register_ShaderVarPrimBatcherCompositeMatrix();
      moho::register_ShaderVarPrimBatcherTexture1();
      moho::register_ShaderVarPrimBatcherAlphaMultiplier();
      moho::register_ShaderVarPrimBatcherTime();
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
   * Fidelity note: the binary's own lookup (`EffectD3D9::GetVariable`,
   * FUN_00941D70) unconditionally throws
   * `gpg::gal::Error` when the named parameter is absent from the bound
   * effect (confirmed from its raw .asm: `cmp edi, ebx` / `jnz` on the
   * returned handle, no null-tolerant path). `ShaderVar::Exists()` itself
   * sets up no catch of its own -- its SEH frame (`SEH_437ED0`) only unwinds
   * the two local `boost::shared_ptr`s, matching the plain non-exceptional
   * return paths already in this function's decompile.
   *
   * The catch below is NOT in the binary. It went in when the first
   * water-rendering frame threw here, on the theory that FAF's `water2.fx`
   * lacks WaterColor/WaterLerp/FresnelBias/... . That theory was wrong: the
   * shader declares `waterColor`, `waterLerp`, `fresnelBias`, ... exactly as
   * the binary's registration thunks spell them (0x00BE3520..0x00BE36C0), and
   * the throws came from our own mis-cased names, since corrected along with
   * terrain's `e_x`/`e_y`/`size_source`. Every one of the binary's 195
   * RegisterShaderVar (0x00438000) name/effect pairs now matches the source
   * byte for byte, and retail runs these assets without throwing, so the
   * catch has no known trigger left. What it does do is turn any future
   * misspelling into a silently unbound parameter instead of a GAL error;
   * that is how the water2 names went unnoticed.
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

    boost::shared_ptr<gpg::gal::Effect> baseEffect = effect->GetBaseEffect();
    try {
      mEffectVariable = baseEffect->GetVariable(mVariableName.c_str());
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
   * boost::shared_ptr<gpg::gal::RenderTarget> into an 8-byte temporary -
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
      mEffectVariable->SetRenderTarget(surfaceHandle);
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
  ShaderVar* ShaderVar::SetMatrix4x4(const gpg::gal::Matrix* const matrix)
  {
    if (Exists()) {
      mEffectVariable->SetMatrix4x4(matrix);
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
   * Address: 0x00BC3FF0 (FUN_00BC3FF0, register_ShaderVarPrimBatcherCompositeMatrix)
   *
   * What it does:
   * Registers the prim-batcher `CompositeMatrix` shader-var.
   */
  void register_ShaderVarPrimBatcherCompositeMatrix()
  {
    RegisterShaderVar("CompositeMatrix", &shaderVarPrimBatcherCompositeMatrix, "primbatcher");
  }

  /**
   * Address: 0x00BC4010 (FUN_00BC4010, register_ShaderVarPrimBatcherTexture1)
   *
   * What it does:
   * Registers the prim-batcher `Texture1` shader-var.
   */
  void register_ShaderVarPrimBatcherTexture1()
  {
    RegisterShaderVar("Texture1", &shaderVarPrimBatcherTexture1, "primbatcher");
  }

  /**
   * Address: 0x00BC4030 (FUN_00BC4030, register_ShaderVarPrimBatcherAlphaMultiplier)
   *
   * What it does:
   * Registers the prim-batcher `AlphaMultiplier` shader-var.
   */
  void register_ShaderVarPrimBatcherAlphaMultiplier()
  {
    RegisterShaderVar("AlphaMultiplier", &shaderVarPrimBatcherAlphaMultiplier, "primbatcher");
  }

  /**
   * Address: 0x00BE6050 (FUN_00BE6050, register_ShaderVarPrimBatcherTime)
   *
   * What it does:
   * Registers the prim-batcher `time` shader-var (lowercase in the binary's
   * `.rdata` string, unlike its `CompositeMatrix`/`Texture1`/
   * `AlphaMultiplier` siblings).
   */
  void register_ShaderVarPrimBatcherTime()
  {
    RegisterShaderVar("time", &shaderVarPrimBatcherTime, "primbatcher");
  }

  /**
   * Address: 0x00BE2F70 (FUN_00BE2F70, register_ShaderVarTerrainHeightScale)
   *
   * What it does:
   * Registers the terrain height-scale shader-var. The registrar's own
   * disassembly (0x00BE2F70) confirms the registration key is the bare
   * effect-parameter name `"HeightScale"`, not `"TerrainHeightScale"` -- the
   * earlier note conflated IDA's own label for the global
   * (`shaderVarTerrainHeightScale`, referenced by address in
   * HighFidelityTerrain::Func3 at 0x00800550) with the runtime lookup string,
   * which is a different thing entirely. `terrain.fx` (effects.nx2) declares
   * the parameter as `float HeightScale;` with no prefix, confirming this by
   * the shipped asset too. The stale key made `ShaderVar::Exists()` throw
   * uncaught on every terrain render (`EffectD3D9::GetVariable`/
   * `GetParameterByName` finds nothing and calls `ThrowGalError`), crashing
   * the process on the first painted frame.
   */
  void register_ShaderVarTerrainHeightScale()
  {
    RegisterShaderVar("HeightScale", &shaderVarTerrainHeightScale, "terrain");
  }

  /**
   * Address: 0x00BE2FB0 (FUN_00BE2FB0, register_ShaderVarTerrainTime)
   *
   * What it does:
   * Registers the terrain time shader-var. Same mislabeled-evidence bug as
   * `register_ShaderVarTerrainHeightScale`: the registrar's own disassembly
   * (0x00BE2FB0) shows the registration key is `"Time"`, matching
   * `terrain.fx`'s `float Time;` -- not `"TerrainTime"`.
   */
  void register_ShaderVarTerrainTime()
  {
    RegisterShaderVar("Time", &shaderVarTerrainTime, "terrain");
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

  /**
   * Address: 0x00BE12A0 (FUN_00BE12A0, register_ShaderVarFrameGlowCopyAdd)
   *
   * What it does:
   * Registers `shaderVarFrameGlowCopyAdd` under the HLSL name `"GlowCopyAdd"`
   * in the `"frame"` effect scope -- the registration `DoBloom`'s
   * `shaderVarFrameGlowCopyAdd.Exists()` check depends on. No per-field
   * exit-cleanup is modeled here, matching every other plain-global member
   * of this file's `frame`/`terrain`/`water2`/`mesh` shader-var sets (see
   * `MeshShaderVarSet`, `TerrainShaderVarSet`, `WaterShaderVars.cpp`,
   * `CRenFrame.cpp`), none of which track individual `atexit` cleanup for
   * their `RegisterShaderVar` calls.
   */
  void register_ShaderVarFrameGlowCopyAdd()
  {
    RegisterShaderVar("GlowCopyAdd", &shaderVarFrameGlowCopyAdd, "frame");
  }

  namespace
  {
    struct FrameGlowCopyAddShaderVarBootstrap
    {
      FrameGlowCopyAddShaderVarBootstrap() { moho::register_ShaderVarFrameGlowCopyAdd(); }
    };

    [[maybe_unused]] FrameGlowCopyAddShaderVarBootstrap gFrameGlowCopyAddShaderVarBootstrap;
  } // namespace

} // namespace moho
