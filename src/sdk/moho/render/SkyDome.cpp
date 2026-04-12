#include "moho/render/SkyDome.h"

#include <cstring>

#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DEffectTechnique.h"

namespace moho
{
  /**
   * Address: 0x008149E0 (FUN_008149E0, ??0SkyDome@Moho@@QAE@XZ)
   *
   * What it does:
   * Initializes all sky dome rendering state to defaults — horizon/sky colors,
   * texture paths, zero-initialized shared_ptr resource handles, and copies
   * static cirrus data.
   */
  SkyDome::SkyDome()
    : mHorizonLookupPath("/textures/environment/horizonLookup.dds")
    , mCirrusTexPath("/textures/environment/cirrus000.dds")
  {
  }

  /**
   * Address: 0x008177B0 (FUN_008177B0, ?CreateRenderAbility@SkyDome@Moho@@AAEXXZ)
   *
   * What it does:
   * Loads all textures, creates the dome vertex format, builds dome and decal
   * vertex/index buffers from the current sky parameters.
   */
  void SkyDome::CreateRenderAbility()
  {
    CreateTextures();
    CreateDomeFormat();
    CreateDomeVertexBuffer(mSkyParams.x, mSkyParams.y, mSkyParams.z, mWidth, mHeight);
    CreateDomeIndexBuffer(mWidth, mHeight);
    // CreateDecalFormat / CreateDecalVertexBuffers / CreateDecalIndexBuffer
    // are referenced in the binary at this site but their declarations and
    // bodies are still pending another agent's recovery pass on SkyDome decal
    // geometry. Re-enable when those helpers land in SkyDome.h/.cpp.
  }

  /**
   * Address: 0x00817810 (FUN_00817810, ?GetEffect@SkyDome@Moho@@AAE?AV?$shared_ptr@VEffect@gal@gpg@@@boost@@XZ)
   *
   * What it does:
   * Looks up the "sky" shader effect from the active D3D device resources.
   */
  boost::shared_ptr<gpg::gal::Effect> SkyDome::GetEffect()
  {
    // The binary returns the same shared_ptr backing-store that
    // CD3DEffect::GetBaseEffect() does, but the recovered SDK currently models
    // EffectD3D9 and Effect as unrelated `gpg::gal::*` classes (no shared
    // base) so the implicit upcast of `shared_ptr<EffectD3D9>` to
    // `shared_ptr<Effect>` doesn't compile. Re-enable the lookup once the
    // Effect / EffectD3D9 inheritance is recovered.
    (void)D3D_GetDevice()->GetResources()->FindEffect("sky");
    return {};
  }
} // namespace moho
