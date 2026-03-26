#include "CD3DDynamicTextureSheet.h"

#include "gpg/core/streams/BinaryReader.h"
#include "gpg/core/streams/Stream.h"
#include "gpg/gal/D3D9Utils.h"
#include "gpg/gal/backends/d3d9/DeviceD3D9.hpp"
#include "gpg/gal/backends/d3d9/TextureD3D9.hpp"
#include "moho/render/d3d/CD3DDevice.h"

namespace moho
{
  namespace
  {
    constexpr std::uint32_t kTextureSourceArchive = 1u;
    constexpr std::uint32_t kTextureSourceDevice = 2u;
    constexpr std::uint32_t kTextureUsageStatic = 1u;
    constexpr std::uint32_t kTextureUsageDynamic = 2u;
    constexpr std::uint32_t kDefaultMipmapLevels = 1u;
  } // namespace

  CD3DDynamicTextureSheet::CD3DDynamicTextureSheet()
    : mLink()
    , mDevice(nullptr)
    , mTexture()
    , mContext()
    , mArchiveTextureMode(false)
    , mPad6D{}
  {
    mContext.source_ = kTextureSourceDevice;
    mContext.width_ = 0;
    mContext.height_ = 0;
    mContext.format_ = 0;
    mContext.mipmapLevels_ = kDefaultMipmapLevels;
    mContext.usage_ = kTextureUsageStatic;
  }

  /**
   * Address: 0x0043CF90 (FUN_0043CF90, deleting thunk)
   * Address: 0x0043CED0 (FUN_0043CED0, non-deleting body)
   *
   * What it does:
   * Releases retained texture/context ownership and unlinks this sheet from
   * its intrusive list.
   */
  CD3DDynamicTextureSheet::~CD3DDynamicTextureSheet()
  {
    mTexture.reset();
    mLink.ListUnlink();
  }

  /**
   * Address: 0x0043E630 (FUN_0043E630)
   *
   * Wm3::Vector3f *
   *
   * What it does:
   * Copies retained texture width/height into caller output.
   */
  Wm3::Vector3f* CD3DDynamicTextureSheet::GetDimensions(Wm3::Vector3f* const outDimensions)
  {
    if (outDimensions == nullptr) {
      return nullptr;
    }

    const gpg::gal::TextureContext* context = &mContext;
    if (auto* const texture = mTexture.get(); texture != nullptr) {
      context = texture->GetContext();
    }

    outDimensions->x = static_cast<float>(context->width_);
    outDimensions->y = static_cast<float>(context->height_);
    outDimensions->z = 0.0f;
    return outDimensions;
  }

  /**
   * Address: 0x0043CF70 (FUN_0043CF70)
   *
   * Wm3::Vector2i *
   *
   * What it does:
   * Writes zeroed original-dimensions payload into caller output lane.
   */
  Wm3::Vector2i* CD3DDynamicTextureSheet::GetOriginalDimensions(Wm3::Vector2i* const outDimensions)
  {
    if (outDimensions == nullptr) {
      return nullptr;
    }

    outDimensions->x = 0;
    outDimensions->y = 0;
    return outDimensions;
  }

  /**
   * Address: 0x0043E680 (FUN_0043E680)
   *
   * What it does:
   * Returns retained texture byte-size metadata from wrapped texture context.
   */
  int CD3DDynamicTextureSheet::GetTextureSizeInBytes()
  {
    if (auto* const texture = mTexture.get(); texture != nullptr) {
      return static_cast<int>(texture->GetContext()->reserved0x50_);
    }
    return 0;
  }

  /**
   * Address: 0x0043E690 (FUN_0043E690)
   *
   * boost::shared_ptr<gpg::gal::TextureD3D9> &
   *
   * What it does:
   * Copies retained texture ownership into caller storage.
   */
  CD3DDynamicTextureSheet::TextureHandle& CD3DDynamicTextureSheet::GetTexture(TextureHandle& outTexture)
  {
    outTexture = mTexture;
    return outTexture;
  }

  /**
   * Address: 0x0043E6C0 (FUN_0043E6C0)
   *
   * std::uint32_t *,void **
   *
   * What it does:
   * Locks the full texture level and returns mapped pitch + byte pointer.
   */
  bool CD3DDynamicTextureSheet::Lock(std::uint32_t* const outPitch, void** const outBits)
  {
    if (outPitch == nullptr || outBits == nullptr || mTexture.get() == nullptr) {
      return false;
    }

    RECT fullRect{};
    gpg::gal::TextureLockRect lockRect{};

    auto* const context = mTexture->GetContext();
    const auto lockFlags = static_cast<int>(
      context->usage_ == kTextureUsageDynamic ? gpg::gal::MohoD3DLockFlags::Discard : gpg::gal::MohoD3DLockFlags::None
    );

    mTexture->Lock(&lockRect, 0, &fullRect, lockFlags);
    *outPitch = static_cast<std::uint32_t>(lockRect.pitch);
    *outBits = lockRect.bits;

    return true;
  }

  /**
   * Address: 0x0043E7A0 (FUN_0043E7A0)
   *
   * RECT const *,std::uint32_t *,void **
   *
   * What it does:
   * Locks one caller-provided texture rectangle and returns pitch + byte pointer.
   */
  bool CD3DDynamicTextureSheet::LockRect(
    const RECT* const rect,
    std::uint32_t* const outPitch,
    void** const outBits
  )
  {
    if (rect == nullptr || outPitch == nullptr || outBits == nullptr || mTexture.get() == nullptr) {
      return false;
    }

    RECT lockRectRegion = *rect;
    gpg::gal::TextureLockRect lockRect{};
    mTexture->Lock(&lockRect, 0, &lockRectRegion, 0);
    *outPitch = static_cast<std::uint32_t>(lockRect.pitch);
    *outBits = lockRect.bits;
    return true;
  }

  /**
   * Address: 0x0043E870 (FUN_0043E870)
   *
   * What it does:
   * Unlocks retained texture level 0.
   */
  bool CD3DDynamicTextureSheet::Unlock()
  {
    if (mTexture.get() == nullptr) {
      return false;
    }
    mTexture->Unlock(0);
    return true;
  }

  /**
   * Address: 0x0043E8E0 (FUN_0043E8E0)
   *
   * gpg::BinaryReader *
   *
   * What it does:
   * Reads raw texture bytes from archive and recreates the wrapped texture.
   */
  bool CD3DDynamicTextureSheet::ReadFromArchive(gpg::BinaryReader* const reader)
  {
    if (reader == nullptr) {
      return false;
    }

    std::uint32_t byteCount = 0;
    reader->Read(reinterpret_cast<char*>(&byteCount), sizeof(byteCount));

    gpg::MemBuffer<char> textureBytes = gpg::AllocMemBuffer(byteCount);
    if (byteCount != 0) {
      reader->Read(textureBytes.data(), byteCount);
    }

    mContext.SetDataBuffer(textureBytes);
    mContext.source_ = kTextureSourceArchive;
    return CreateTexture();
  }

  /**
   * Address: 0x0043EAA0 (FUN_0043EAA0)
   *
   * gpg::Stream *,bool
   *
   * What it does:
   * Saves retained texture bytes to stream, with optional byte-count prefix.
   */
  bool CD3DDynamicTextureSheet::SaveToArchive(gpg::Stream* const stream, const bool writeSizeHeader)
  {
    if (stream == nullptr || mTexture.get() == nullptr) {
      return false;
    }

    gpg::MemBuffer<char> textureBytes{};
    mTexture->SaveToBuffer(&textureBytes);

    const std::uint32_t byteCount = static_cast<std::uint32_t>(textureBytes.Size());
    if (writeSizeHeader) {
      stream->Write(byteCount);
    }

    if (byteCount != 0) {
      stream->Write(textureBytes.data(), byteCount);
    }

    return true;
  }

  /**
   * Address: 0x00442940 (FUN_00442940)
   *
   * What it does:
   * Recreates retained texture ownership from the current texture context.
   */
  bool CD3DDynamicTextureSheet::CreateTexture()
  {
    if (mDevice == nullptr) {
      mTexture.reset();
      return false;
    }

    gpg::gal::DeviceD3D9* const deviceD3D9 = mDevice->GetDeviceD3D9();
    if (deviceD3D9 == nullptr) {
      mTexture.reset();
      return false;
    }

    deviceD3D9->CreateTexture(&mTexture, &mContext);
    return mTexture.get() != nullptr;
  }
} // namespace moho
