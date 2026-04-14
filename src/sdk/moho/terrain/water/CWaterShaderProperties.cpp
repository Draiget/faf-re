#include "moho/terrain/water/CWaterShaderProperties.h"

#include <boost/detail/sp_counted_base.hpp>

#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/textures/CD3DDynamicTextureSheet.h"
#include "moho/render/d3d/RD3DTextureResource.h"

namespace moho
{

/**
 * Address: 0x0089F9A0 (FUN_0089F9A0)
 * Mangled: ??1CWaterShaderProperties@Moho@@UAE@XZ
 *
 * IDA signature:
 * void __thiscall Moho::CWaterShaderProperties::~CWaterShaderProperties(int this);
 *
 * What it does:
 * Resets the vtable pointer, calls releaseTextures() to atomically drop all
 * six texture sheet reference counts, then runs the eh_vector_destructor
 * on mTextures[0..3] (no-op after releaseTextures zeroes all pi_ fields),
 * and finally destroys the six msvc8::string members via eh_vector_destructor
 * and explicit SSO/heap teardown.
 *
 * In the binary, mTextures[4] and mTextures[5] are released manually before
 * the eh_vector loop; in C++ recovery these are already null after
 * releaseTextures() and the loop becomes a no-op.
 *
 * The destructor is virtual (UAE mangling); callers arrive via vtable or
 * as a direct non-virtual call from a derived-class destructor.
 */
CWaterShaderProperties::~CWaterShaderProperties()
{
  releaseTextures();

  // After releaseTextures() all mTextures entries have pi=null and px=null.
  // The remaining string members (mWaterRamp, mWaterCubemap, mShaderNames[])
  // require explicit tidy to release any heap-allocated buffers.  The binary
  // uses eh_vector_destructor_iterator and direct SSO teardown; we call tidy()
  // directly here to match the same observable side-effects.
  mWaterRamp.tidy();
  mWaterCubemap.tidy();
  for (auto& s : mShaderNames) {
    s.tidy();
  }
}

/**
 * Address: 0x008A0740 (FUN_008A0740)
 * Mangled: ?releaseTextures@CWaterShaderProperties@Moho@@QAEXXZ
 *
 * IDA signature:
 * void __usercall Moho::CWaterShaderProperties::releaseTextures(
 *   Moho::CWaterShaderProperties *a1@<esi>);
 *
 * What it does:
 * Iterates mTextures[0..5] in order, zeroes the sheet pointer and atomically
 * decrements the shared control block use-count, calling dispose/destroy when
 * the count reaches zero.  This mirrors the binary's open-coded
 * boost::shared_ptr release loop.
 */
void CWaterShaderProperties::releaseTextures()
{
  for (auto& entry : mTextures) {
    entry.px = nullptr;
    boost::detail::sp_counted_base* const pi = entry.pi;
    entry.pi = nullptr;
    if (pi != nullptr) {
      pi->release();
    }
  }
}

/**
 * Address: 0x0089FD70 (FUN_0089FD70)
 * Mangled: ?GetWaterRamp@CWaterShaderProperties@Moho@@QBE?AV?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@XZ
 *
 * What it does:
 * Lazily resolves one water-ramp texture resource and caches its shared-owner
 * lane at `mTextures[5]`, then returns one retained shared texture-sheet
 * handle to the caller.
 */
boost::shared_ptr<ID3DTextureSheet> CWaterShaderProperties::GetWaterRamp() const
{
  if (mTextures[5].px == nullptr) {
    if (CD3DDevice* const device = D3D_GetDevice(); device != nullptr) {
      if (ID3DDeviceResources* const resources = device->GetResources(); resources != nullptr) {
        ID3DDeviceResources::TextureResourceHandle loadedTexture{};
        resources->GetTexture(loadedTexture, mWaterRamp.c_str(), 0, true);

        const boost::SharedPtrRaw<RD3DTextureResource> loadedRaw =
          boost::SharedPtrRawFromSharedBorrow(loadedTexture);

        boost::SharedPtrRaw<ID3DTextureSheet> resolvedTexture{};
        resolvedTexture.px = static_cast<ID3DTextureSheet*>(loadedRaw.px);
        resolvedTexture.pi = loadedRaw.pi;
        mTextures[5].assign_retain(resolvedTexture);
      }
    }
  }

  return boost::SharedPtrFromRawRetained(mTextures[5]);
}

/**
 * Address: 0x0089FC40 (FUN_0089FC40, ?GetCubeMap@CWaterShaderProperties@Moho@@QBE?AV?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@XZ)
 * Mangled: ?GetCubeMap@CWaterShaderProperties@Moho@@QBE?AV?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@XZ
 *
 * What it does:
 * Lazily resolves one water-cubemap texture and caches its shared-owner lane
 * at `mTextures[4]`, then returns one retained shared texture-sheet handle to
 * the caller.
 */
boost::shared_ptr<ID3DTextureSheet> CWaterShaderProperties::GetCubeMap() const
{
  if (mTextures[4].px == nullptr) {
    if (CD3DDevice* const device = D3D_GetDevice(); device != nullptr) {
      if (ID3DDeviceResources* const resources = device->GetResources(); resources != nullptr) {
        ID3DDeviceResources::TextureResourceHandle loadedTexture{};
        resources->GetTexture(loadedTexture, mWaterCubemap.c_str(), 0, true);

        const boost::SharedPtrRaw<RD3DTextureResource> loadedRaw =
          boost::SharedPtrRawFromSharedBorrow(loadedTexture);

        boost::SharedPtrRaw<ID3DTextureSheet> resolvedTexture{};
        resolvedTexture.px = static_cast<ID3DTextureSheet*>(loadedRaw.px);
        resolvedTexture.pi = loadedRaw.pi;
        mTextures[4].assign_retain(resolvedTexture);
      }
    }
  }

  return boost::SharedPtrFromRawRetained(mTextures[4]);
}

/**
 * Address: 0x0089FB00 (FUN_0089FB00, ?GetNormalMap@CWaterShaderProperties@Moho@@QBE?AV?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@H@Z)
 * Mangled: ?GetNormalMap@CWaterShaderProperties@Moho@@QBE?AV?$shared_ptr@VID3DTextureSheet@Moho@@@boost@@H@Z
 *
 * What it does:
 * Lazily resolves one indexed normal-map texture from `mShaderNames[index]`,
 * caches it in `mTextures[index]`, and returns one retained shared texture
 * sheet handle.
 */
boost::shared_ptr<ID3DTextureSheet> CWaterShaderProperties::GetNormalMap(const int index) const
{
  boost::SharedPtrRaw<ID3DTextureSheet>& cachedTexture = mTextures[index];
  if (cachedTexture.px == nullptr) {
    if (CD3DDevice* const device = D3D_GetDevice(); device != nullptr) {
      if (ID3DDeviceResources* const resources = device->GetResources(); resources != nullptr) {
        ID3DDeviceResources::TextureResourceHandle loadedTexture{};
        resources->GetTexture(loadedTexture, mShaderNames[index].c_str(), 0, true);

        const boost::SharedPtrRaw<RD3DTextureResource> loadedRaw =
          boost::SharedPtrRawFromSharedBorrow(loadedTexture);

        boost::SharedPtrRaw<ID3DTextureSheet> resolvedTexture{};
        resolvedTexture.px = static_cast<ID3DTextureSheet*>(loadedRaw.px);
        resolvedTexture.pi = loadedRaw.pi;
        cachedTexture.assign_retain(resolvedTexture);
      }
    }
  }

  return boost::SharedPtrFromRawRetained(cachedTexture);
}

} // namespace moho
