#pragma once

#include <cstddef>

#include "boost/shared_ptr.h"
#include "legacy/containers/String.h"
#include "moho/misc/CountedObject.h"

namespace gpg
{
  class RType;
}

namespace moho
{
  class RD3DTextureResource;

  class CParticleTexture : public CountedObject
  {
  public:
    using TextureResourceHandle = boost::shared_ptr<RD3DTextureResource>;

    static gpg::RType* sType;

    /**
     * Address: 0x0048EC60 (FUN_0048EC60, Moho::CParticleTexture::CParticleTexture)
     */
    explicit CParticleTexture(const char* texturePath);

    /**
     * Address: 0x0048ECF0 (FUN_0048ECF0, Moho::CParticleTexture::dtr thunk)
     * Address: 0x0048ED10 (FUN_0048ED10, Moho::CParticleTexture::~CParticleTexture body)
     */
    ~CParticleTexture() override;

    /**
     * Address: 0x0048EEF0 (FUN_0048EEF0, Moho::CParticleTexture::GetTexture)
     *
     * boost::shared_ptr<RD3DTextureResource> &
     *
     * What it does:
     * Lazily resolves one texture resource from device resources by path and
     * returns retained shared ownership.
     */
    TextureResourceHandle& GetTexture(TextureResourceHandle& outTexture);

  public:
    msvc8::string mTexturePath;             // +0x08
    TextureResourceHandle mTextureResource; // +0x24
  };

  static_assert(
    sizeof(CParticleTexture::TextureResourceHandle) == 0x08,
    "CParticleTexture::TextureResourceHandle size must be 0x08"
  );
  static_assert(offsetof(CParticleTexture, mTexturePath) == 0x08, "CParticleTexture::mTexturePath offset must be 0x08");
  static_assert(
    offsetof(CParticleTexture, mTextureResource) == 0x24, "CParticleTexture::mTextureResource offset must be 0x24"
  );
  static_assert(sizeof(CParticleTexture) == 0x2C, "CParticleTexture size must be 0x2C");
} // namespace moho
