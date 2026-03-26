#include "moho/resource/CParticleTexture.h"

#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/d3d/CD3DDevice.h"

namespace moho
{
  gpg::RType* CParticleTexture::sType = nullptr;

  /**
   * Address: 0x0048EC60 (FUN_0048EC60, Moho::CParticleTexture::CParticleTexture)
   */
  CParticleTexture::CParticleTexture(const char* const texturePath)
    : CountedObject()
    , mTexturePath()
    , mTextureResource()
  {
    mTexturePath.assign_owned(texturePath != nullptr ? texturePath : "");
  }

  /**
   * Address: 0x0048ECF0 (FUN_0048ECF0, Moho::CParticleTexture::dtr thunk)
   * Address: 0x0048ED10 (FUN_0048ED10, Moho::CParticleTexture::~CParticleTexture body)
   */
  CParticleTexture::~CParticleTexture()
  {
    mTextureResource.reset();
    mTexturePath.tidy(true, 0u);
  }

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
