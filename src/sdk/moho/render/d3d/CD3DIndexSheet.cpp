#include "CD3DIndexSheet.h"

#include "gpg/gal/D3D9Utils.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/backends/d3d9/DeviceD3D9.hpp"
#include "moho/render/d3d/CD3DDevice.h"

namespace moho
{
  namespace
  {
    constexpr std::uint32_t kIndexContextFormatToken16Bit = 1;
    constexpr std::uint32_t kIndexContextTypeStatic = 1;
    constexpr std::uint32_t kIndexContextTypeDynamic = 2;
    constexpr std::uint32_t kIndexElementSizeBytes = 2;
  } // namespace

  /**
   * Address: 0x0043F520 (FUN_0043F520)
   *
   * CD3DDevice *,int,bool
   *
   * What it does:
   * Initializes list links and index-buffer context metadata, then optionally
   * creates the backing gal index buffer when a device is present.
   */
  CD3DIndexSheet::CD3DIndexSheet(
    CD3DDevice* const device,
    const std::uint32_t size,
    const bool dynamicUsage
  )
    : mLink()
    , mDevice(device)
    , mBuffer()
    , mContext()
  {
    mContext.format_ = kIndexContextFormatToken16Bit;
    mContext.size_ = size;
    mContext.type_ = dynamicUsage ? kIndexContextTypeDynamic : kIndexContextTypeStatic;

    if (mDevice != nullptr) {
      CreateBuffer();
    }
  }

  /**
   * Address: 0x0043F5B0 (FUN_0043F5B0, deleting thunk)
   * Address: 0x0043F620 (FUN_0043F620, non-deleting body)
   *
   * What it does:
   * Releases retained index-buffer ownership, destroys embedded context state,
   * and unlinks this node from its intrusive ring.
   */
  CD3DIndexSheet::~CD3DIndexSheet()
  {
    mBuffer.reset();
    mLink.ListUnlink();
  }

  /**
   * Address: 0x0043F870 (FUN_0043F870)
   *
   * What it does:
   * Deletes this wrapper instance through the virtual destructor path.
   */
  void CD3DIndexSheet::Destroy()
  {
    delete this;
  }

  /**
   * Address: 0x0043F880 (FUN_0043F880)
   *
   * What it does:
   * Returns the owning D3D device wrapper lane.
   */
  CD3DDevice* CD3DIndexSheet::GetDevice()
  {
    return mDevice;
  }

  /**
   * Address: 0x0043F850 (FUN_0043F850)
   *
   * What it does:
   * Returns true when retained index-buffer context type equals static token `1`.
   */
  bool CD3DIndexSheet::IsStaticBufferType() const
  {
    return mBuffer.get()->GetContextBuffer()->type_ == kIndexContextTypeStatic;
  }

  /**
   * Address: 0x00940660 (FUN_00940660, func_DeviceCreateIndexBuffer)
   *
   * What it does:
   * Forwards one index-buffer creation request through the active GAL device
   * singleton and returns `outBuffer`.
   */
  CD3DIndexSheet::BufferHandle* CD3DIndexSheet::CreateIndexBufferOnActiveDevice(
    BufferHandle* const outBuffer,
    gpg::gal::IndexBufferContext* const context
  )
  {
    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    auto* const deviceD3D9 = reinterpret_cast<gpg::gal::DeviceD3D9*>(device);
    deviceD3D9->CreateIndexBuffer(outBuffer, context);
    return outBuffer;
  }

  /**
   * Address: 0x0043F890 (FUN_0043F890)
   *
   * What it does:
   * Returns true when retained index-buffer context type differs from token `1`.
   */
  bool CD3DIndexSheet::Func3()
  {
    return !IsStaticBufferType();
  }

  /**
   * Address: 0x0043F8B0 (FUN_0043F8B0)
   *
   * boost::shared_ptr<gpg::gal::IndexBufferD3D9> &
   *
   * What it does:
   * Copies retained index-buffer ownership into caller storage.
   */
  CD3DIndexSheet::BufferHandle& CD3DIndexSheet::GetBuffer(BufferHandle& outBuffer)
  {
    outBuffer = mBuffer;
    return outBuffer;
  }

  /**
   * Address: 0x0043F900 (FUN_0043F900)
   *
   * What it does:
   * Returns retained index count from the backing buffer context.
   */
  std::uint32_t CD3DIndexSheet::GetSize() const
  {
    return mBuffer.get()->GetContextBuffer()->size_;
  }

  /**
   * Address: 0x0043F910 (FUN_0043F910)
   *
   * std::uint32_t
   *
   * What it does:
   * Recreates the backing index buffer when the requested size differs.
   */
  bool CD3DIndexSheet::SetSize(const std::uint32_t size)
  {
    if (size == mBuffer.get()->GetContextBuffer()->size_) {
      return true;
    }

    DestroyBuffer();
    mContext.size_ = size;
    return CreateBuffer();
  }

  /**
   * Address: 0x0043F950 (FUN_0043F950)
   *
   * std::uint32_t,std::uint32_t,bool,bool
   *
   * What it does:
   * Locks one index range in units of 16-bit indices and returns mapped data.
   */
  std::int16_t* CD3DIndexSheet::Lock(
    const std::uint32_t startIndex,
    const std::uint32_t indexCount,
    const bool readOnly,
    const bool discard
  )
  {
    gpg::gal::IndexBufferD3D9* const indexBuffer = mBuffer.get();
    if (indexBuffer == nullptr) {
      return nullptr;
    }

    std::uint32_t lockFlags = 0;
    if (readOnly) {
      lockFlags = static_cast<std::uint32_t>(gpg::gal::MohoD3DLockFlags::ReadOnly);
    }
    if (discard) {
      lockFlags |= static_cast<std::uint32_t>(gpg::gal::MohoD3DLockFlags::Discard);
    }

    return indexBuffer->Lock(
      kIndexElementSizeBytes * startIndex,
      kIndexElementSizeBytes * indexCount,
      static_cast<gpg::gal::MohoD3DLockFlags>(lockFlags)
    );
  }

  /**
   * Address: 0x0043FA00 (FUN_0043FA00)
   *
   * What it does:
   * Unlocks the retained index buffer when present.
   */
  void CD3DIndexSheet::Unlock()
  {
    if (gpg::gal::IndexBufferD3D9* const indexBuffer = mBuffer.get(); indexBuffer != nullptr) {
      indexBuffer->Unlock();
    }
  }

  /**
   * Address: 0x0043FA10 (FUN_0043FA10)
   *
   * What it does:
   * Binds retained index-buffer ownership on the current D3D9 device lane.
   */
  void CD3DIndexSheet::SetBufferIndices()
  {
    gpg::gal::DeviceD3D9* const deviceD3D9 = mDevice->GetDeviceD3D9();
    if (deviceD3D9 != nullptr) {
      deviceD3D9->SetBufferIndices(mBuffer);
    }
  }

  /**
   * Address: 0x0043F700 (FUN_0043F700)
   *
   * What it does:
   * Creates one gal index-buffer wrapper from retained context metadata.
   */
  bool CD3DIndexSheet::CreateBuffer()
  {
    if (mBuffer.get() == nullptr) {
      (void)CreateIndexBufferOnActiveDevice(&mBuffer, &mContext);
    }

    return true;
  }

  /**
   * Address: 0x0043F810 (FUN_0043F810)
   *
   * What it does:
   * Drops retained index-buffer ownership and clears handle state.
   */
  void CD3DIndexSheet::DestroyBuffer()
  {
    mBuffer.reset();
  }
} // namespace moho
