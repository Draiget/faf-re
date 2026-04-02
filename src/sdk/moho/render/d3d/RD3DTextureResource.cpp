#include "moho/render/d3d/RD3DTextureResource.h"

#include "gpg/core/streams/MemBufferStream.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "gpg/gal/backends/d3d9/DeviceD3D9.hpp"
#include "gpg/gal/backends/d3d9/TextureD3D9.hpp"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/ID3DDeviceResources.h"
#include "moho/render/d3d/CD3DDevice.h"

namespace moho
{
  gpg::RType* RD3DTextureResource::sType = nullptr;

  namespace
  {
    constexpr std::uint32_t kTextureSourceArchive = 1u;
    constexpr std::uint32_t kTextureUsageStatic = 1u;
    constexpr const char* kUnreachableExpr = "Reached the supposably unreachable.";
    constexpr const char* kTextureSourcePath = "c:\\work\\rts\\main\\code\\src\\core\\D3DRes.cpp";
  } // namespace

  /**
   * Address: 0x0043D710 (FUN_0043D710)
   *
   * const char *
   *
   * What it does:
   * Initializes intrusive resource links and seeds texture context from location.
   */
  RD3DTextureResource::RD3DTextureResource(const char* const location)
    : mResources()
    , mContext()
    , mBaseTex()
  {
    mContext.location_.assign_owned(location != nullptr ? location : "");
  }

  /**
   * Address: 0x0043D7A0 (FUN_0043D7A0)
   *
   * const char *,void *,std::size_t
   *
   * What it does:
   * Initializes one archive-backed texture context from in-memory bytes.
   */
  RD3DTextureResource::RD3DTextureResource(const char* const location, void* const data, const std::size_t size)
    : mResources()
    , mContext()
    , mBaseTex()
  {
    mContext.source_ = kTextureSourceArchive;
    mContext.location_.assign_owned(location != nullptr ? location : "");
    mContext.SetDataBuffer(gpg::CopyMemBuffer(data, size));
  }

  /**
   * Address: 0x0043D780 (FUN_0043D780, deleting thunk)
   * Address: 0x0043D980 (FUN_0043D980, non-deleting body)
   *
   * What it does:
   * Releases retained base texture ownership, destroys context state, and unlinks
   * this resource from intrusive tracking list.
   */
  RD3DTextureResource::~RD3DTextureResource()
  {
    mBaseTex.reset();
    mResources.ListUnlink();
  }

  /**
   * Address: 0x0043DA20 (FUN_0043DA20)
   *
   * gpg::MemBuffer<const char>
   *
   * What it does:
   * Copies caller-provided texture-bytes payload into retained context data lane.
   */
  bool RD3DTextureResource::Init(gpg::MemBuffer<const char> data)
  {
    mContext.SetDataBuffer(data);
    return true;
  }

  /**
   * Address: 0x0043DBC0 (FUN_0043DBC0, Moho::RD3DTextureResource::ReloadTexture)
   */
  void RD3DTextureResource::ReloadTexture()
  {
    const gpg::MemBuffer<const char> textureBytes = DISK_MemoryMapFile(mContext.location_.c_str());
    if (textureBytes.mBegin == nullptr) {
      return;
    }

    mBaseTex.reset();
    Init(textureBytes);
    LoadTexture();
  }

  /**
   * Address: 0x0043DAA0 (FUN_0043DAA0)
   *
   * What it does:
   * Builds retained base texture from context data on first use and clears source bytes.
   */
  bool RD3DTextureResource::LoadTexture()
  {
    if (mBaseTex.get() != nullptr) {
      return true;
    }

    if (mContext.dataBegin_ == 0) {
      return false;
    }

    mContext.format_ = 0;
    mContext.usage_ = kTextureUsageStatic;
    mContext.source_ = kTextureSourceArchive;

    CD3DDevice* const device = D3D_GetDevice();
    if (device == nullptr) {
      gpg::Warnf("Unable to load texture: %s", mContext.location_.c_str());
      return false;
    }

    if (ID3DDeviceResources* const resources = device->GetResources(); resources != nullptr) {
      mContext.reserved0x50_ = static_cast<std::uint32_t>(resources->GetSkipMipLevels());
    }

    gpg::gal::DeviceD3D9* const deviceD3D9 = device->GetDeviceD3D9();
    if (deviceD3D9 == nullptr) {
      gpg::Warnf("Unable to load texture: %s", mContext.location_.c_str());
      return false;
    }

    try {
      TextureHandle createdTexture{};
      deviceD3D9->CreateTexture(&createdTexture, &mContext);
      mBaseTex = createdTexture;
      mContext.ClearDataBuffer();
      return mBaseTex.get() != nullptr;
    } catch (...) {
      gpg::Warnf("Unable to load texture: %s", mContext.location_.c_str());
      return false;
    }
  }

  /**
   * Address: 0x0043DD20 (FUN_0043DD20)
   *
   * Wm3::Vector3f *
   *
   * What it does:
   * Loads base texture on demand and returns current width/height as float vector.
   */
  Wm3::Vector3f* RD3DTextureResource::GetDimensions(Wm3::Vector3f* const outDimensions)
  {
    if (outDimensions == nullptr) {
      return nullptr;
    }

    if (!LoadTexture() || mBaseTex.get() == nullptr) {
      outDimensions->x = 0.0f;
      outDimensions->y = 0.0f;
      outDimensions->z = 0.0f;
      return outDimensions;
    }

    const gpg::gal::TextureContext* const context = mBaseTex->GetContext();
    outDimensions->x = static_cast<float>(context->width_);
    outDimensions->y = static_cast<float>(context->height_);
    outDimensions->z = 0.0f;
    return outDimensions;
  }

  /**
   * Address: 0x0043DD70 (FUN_0043DD70)
   *
   * Wm3::Vector2i *
   *
   * What it does:
   * Loads base texture on demand and returns original integer width/height.
   */
  Wm3::Vector2i* RD3DTextureResource::GetOriginalDimensions(Wm3::Vector2i* const outDimensions)
  {
    if (outDimensions == nullptr) {
      return nullptr;
    }

    if (!LoadTexture() || mBaseTex.get() == nullptr) {
      outDimensions->x = 0;
      outDimensions->y = 0;
      return outDimensions;
    }

    const gpg::gal::TextureContext* const context = mBaseTex->GetContext();
    outDimensions->x = static_cast<int>(context->width_);
    outDimensions->y = static_cast<int>(context->height_);
    return outDimensions;
  }

  /**
   * Address: 0x0043DDB0 (FUN_0043DDB0)
   *
   * What it does:
   * Loads base texture on demand and returns retained byte-size metadata.
   */
  int RD3DTextureResource::GetTextureSizeInBytes()
  {
    if (!LoadTexture() || mBaseTex.get() == nullptr) {
      return 0;
    }

    return static_cast<int>(mBaseTex->GetContext()->reserved0x50_);
  }

  /**
   * Address: 0x0043DDD0 (FUN_0043DDD0)
   *
   * boost::shared_ptr<gpg::gal::TextureD3D9> &
   *
   * What it does:
   * Loads base texture on demand and copies retained texture ownership.
   */
  RD3DTextureResource::TextureHandle& RD3DTextureResource::GetTexture(TextureHandle& outTexture)
  {
    LoadTexture();
    outTexture = mBaseTex;
    return outTexture;
  }

  /**
   * Address: 0x0043DE10 (FUN_0043DE10)
   *
   * std::uint32_t *,void **
   *
   * What it does:
   * Preserves unreachable lock lane after forcing lazy texture load.
   */
  bool RD3DTextureResource::Lock(std::uint32_t* const, void** const)
  {
    LoadTexture();
    gpg::HandleAssertFailure(kUnreachableExpr, 189, kTextureSourcePath);
    return false;
  }

  /**
   * Address: 0x0043DE30 (FUN_0043DE30)
   *
   * RECT const *,std::uint32_t *,void **
   *
   * What it does:
   * Preserves unreachable rect-lock lane after forcing lazy texture load.
   */
  bool RD3DTextureResource::LockRect(const RECT* const, std::uint32_t* const, void** const)
  {
    LoadTexture();
    gpg::HandleAssertFailure(kUnreachableExpr, 195, kTextureSourcePath);
    return false;
  }

  /**
   * Address: 0x0043DE50 (FUN_0043DE50)
   *
   * What it does:
   * Preserves unreachable unlock lane after forcing lazy texture load.
   */
  bool RD3DTextureResource::Unlock()
  {
    LoadTexture();
    gpg::HandleAssertFailure(kUnreachableExpr, 202, kTextureSourcePath);
    return false;
  }

  /**
   * Address: 0x0043DE70 (FUN_0043DE70)
   *
   * gpg::BinaryReader *
   *
   * What it does:
   * Preserves unreachable archive-load lane after forcing lazy texture load.
   */
  bool RD3DTextureResource::ReadFromArchive(gpg::BinaryReader* const)
  {
    LoadTexture();
    gpg::HandleAssertFailure(kUnreachableExpr, 208, kTextureSourcePath);
    return false;
  }

  /**
   * Address: 0x0043DE90 (FUN_0043DE90)
   *
   * gpg::Stream *,bool
   *
   * What it does:
   * Preserves unreachable archive-save lane after forcing lazy texture load.
   */
  bool RD3DTextureResource::SaveToArchive(gpg::Stream* const, const bool)
  {
    LoadTexture();
    gpg::HandleAssertFailure(kUnreachableExpr, 214, kTextureSourcePath);
    return false;
  }
} // namespace moho
