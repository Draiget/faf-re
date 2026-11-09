// Engine addition (dedicated-server plan WPL.4, WPR.11): CParticleTexture::GetTexture,
// which loads the texture through the render device's resource cache, moved unchanged
// out of moho/resource/CParticleTexture.cpp: only particle and beam drawing asks for it.
#include "moho/resource/CParticleTexture.h"

#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/d3d/CD3DDevice.h"

namespace moho
{
  /**
   * Address: 0x0048EEF0 (FUN_0048EEF0, Moho::CParticleTexture::GetTexture)
   *
   * boost::shared_ptr<RD3DTextureResource> &
   *
   * What it does:
   * Lazily resolves one texture resource from device resources by path and
   * returns retained shared ownership.
   */
  CParticleTexture::TextureResourceHandle&
  CParticleTexture::GetTexture(TextureResourceHandle& outTexture)
  {
    if (!mTextureResource) {
      CD3DDevice* const device = D3D_GetDevice();
      if (device != nullptr) {
        if (ID3DDeviceResources* const resources = device->GetResources(); resources != nullptr) {
          TextureResourceHandle loadedTexture{};
          resources->GetTexture(loadedTexture, mTexturePath.c_str(), 0, true);
          mTextureResource = loadedTexture;
        }
      }
    }

    outTexture = mTextureResource;
    return outTexture;
  }

} // namespace moho
