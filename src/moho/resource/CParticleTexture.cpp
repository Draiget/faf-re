#include "moho/resource/CParticleTexture.h"

#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"

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

namespace moho
{
  void CParticleTexture::MemberConstruct(gpg::ReadArchive& archive, const int, const gpg::RRef&, gpg::SerConstructResult& result)
  {
    msvc8::string path;
    archive.ReadString(&path);
    result.SetUnowned(gpg::MakeRRef(new CParticleTexture(path.c_str())), 1u);
  }

  void CParticleTexture::MemberSaveConstructArgs(
    gpg::WriteArchive& archive, const int, const gpg::RRef&, gpg::SerSaveConstructArgsResult& result
  )
  {
    archive.WriteString(&mTexturePath);
    result.SetUnowned(1u);
  }

  /**
   * `gpg::SerSaveConstructHelper<CParticleTexture>`, vtable 0x00E06260.
   *
   * Address: 0x00BC5270 (FUN_00BC5270 -- constructs the global and registers its destructor.)
   * Address: 0x00BEFDD0 (FUN_00BEFDD0 -- the global's destructor.)
   * Address: 0x0048F9B0 (FUN_0048F9B0 -- `Init`.)
   * Address: 0x0048F010 (FUN_0048F010 -- `SaveConstructArgs`, a forward to `MemberSaveConstructArgs`.)
   */
  struct CParticleTextureSaveConstruct : gpg::SerSaveConstructHelper<CParticleTexture>
  {};

  /**
   * `gpg::SerConstructHelper<CParticleTexture>`, vtable 0x00E06270.
   *
   * Address: 0x00BC52A0 (FUN_00BC52A0 -- constructs the global and registers its destructor.)
   * Address: 0x00BEFE00 (FUN_00BEFE00 -- the global's destructor.)
   * Address: 0x0048FA30 (FUN_0048FA30 -- `Init`.)
   * Address: 0x0048F140 (FUN_0048F140 -- `Construct`, `MemberConstruct` inlined.)
   * Address: 0x0048FFB0 (FUN_0048FFB0 -- `Delete`.)
   */
  struct CParticleTextureConstruct : gpg::SerConstructHelper<CParticleTexture>
  {};
} // namespace moho

namespace
{
  // Address: 0x010A7F88 -- process-global `CParticleTextureSaveConstruct` singleton.
  moho::CParticleTextureSaveConstruct gCParticleTextureSaveConstruct;

  // Address: 0x010A8024 -- process-global `CParticleTextureConstruct` singleton.
  moho::CParticleTextureConstruct gCParticleTextureConstruct;
} // namespace
