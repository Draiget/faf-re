#include "CD3DVertexStream.h"

#include "gpg/gal/D3D9Utils.h"
#include "gpg/gal/Device.hpp"
#include "gpg/gal/backends/d3d9/DeviceD3D9.hpp"

namespace moho
{
  namespace
  {
    constexpr std::uint32_t kVertexContextTypeDefault = 1;
    constexpr std::uint32_t kVertexContextUsageStatic = 1;
    constexpr std::uint32_t kVertexContextUsageDynamic = 2;
  } // namespace

  /**
   * Address: 0x0043FA60 (FUN_0043FA60)
   *
   * CD3DDevice *,int,int,bool
   *
   * What it does:
   * Initializes vertex-buffer context metadata and clears retained buffer
   * ownership state.
   */
  CD3DVertexStream::CD3DVertexStream(
    CD3DDevice* const device,
    const std::uint32_t width,
    const std::uint32_t strideBytes,
    const bool dynamicUsage
  )
    : mDevice(device)
    , mContext()
    , mBuffer()
  {
    mContext.type_ = kVertexContextTypeDefault;
    mContext.usage_ = dynamicUsage ? kVertexContextUsageDynamic : kVertexContextUsageStatic;
    mContext.width_ = width;
    mContext.height_ = strideBytes;
  }

  /**
   * Address: 0x0043FAE0 (FUN_0043FAE0, deleting thunk)
   * Address: 0x0043FB50 (FUN_0043FB50, non-deleting body)
   *
   * What it does:
   * Releases retained vertex-buffer ownership and destroys embedded context state.
   */
  CD3DVertexStream::~CD3DVertexStream()
  {
    ReleaseBufferHandle();
  }

  /**
   * Address: 0x0043FD60 (FUN_0043FD60)
   *
   * boost::shared_ptr<gpg::gal::VertexBufferD3D9> &
   *
   * What it does:
   * Copies retained vertex-buffer ownership into caller storage.
   */
  CD3DVertexStream::BufferHandle& CD3DVertexStream::GetBuffer(BufferHandle& outBuffer)
  {
    outBuffer = mBuffer;
    return outBuffer;
  }

  /**
   * Address: 0x0043FDB0 (FUN_0043FDB0)
   *
   * int,int,bool,bool
   *
   * What it does:
   * Locks one vertex range using context stride and returns mapped data.
   */
  void* CD3DVertexStream::Lock(
    const int startVertex,
    const int vertexCount,
    const bool readOnly,
    const bool discard
  )
  {
    const std::uint32_t strideBytes = mBuffer.get()->GetContext()->height_;

    std::uint32_t lockFlags = 0;
    if (readOnly) {
      lockFlags = static_cast<std::uint32_t>(gpg::gal::MohoD3DLockFlags::ReadOnly);
    }
    if (discard) {
      lockFlags |= static_cast<std::uint32_t>(gpg::gal::MohoD3DLockFlags::Discard);
    }

    const int byteOffset = startVertex * static_cast<int>(strideBytes);
    const int byteSize = vertexCount * static_cast<int>(strideBytes);

    return mBuffer.get()->Lock(
      static_cast<std::uint32_t>(byteOffset),
      static_cast<std::uint32_t>(byteSize),
      static_cast<gpg::gal::MohoD3DLockFlags>(lockFlags)
    );
  }

  /**
   * Address: 0x0043FE50 (FUN_0043FE50)
   *
   * What it does:
   * Unlocks the retained vertex buffer when present.
   */
  void CD3DVertexStream::Unlock()
  {
    if (gpg::gal::VertexBufferD3D9* const vertexBuffer = mBuffer.get(); vertexBuffer != nullptr) {
      vertexBuffer->Unlock();
    }
  }

  /**
   * Address: 0x0043FD20 (FUN_0043FD20, sub_43FD20)
   *
   * What it does:
   * Releases retained vertex-buffer ownership and clears handle lanes.
   */
  void CD3DVertexStream::ReleaseBufferHandle()
  {
    mBuffer.reset();
  }

  /**
   * Address: 0x009408D0 (FUN_009408D0, func_CreateVertexBuffer)
   *
   * What it does:
   * Forwards one vertex-buffer creation request through the active GAL device
   * singleton and returns `outBuffer`.
   */
  CD3DVertexStream::BufferHandle* CD3DVertexStream::CreateVertexBufferOnActiveDevice(
    BufferHandle* const outBuffer,
    gpg::gal::VertexBufferContext* const context
  )
  {
    gpg::gal::Device* const device = gpg::gal::Device::GetInstance();
    auto* const deviceD3D9 = reinterpret_cast<gpg::gal::DeviceD3D9*>(device);
    deviceD3D9->CreateVertexBuffer(outBuffer, context);
    return outBuffer;
  }

  /**
   * Address: 0x0043FC20 (FUN_0043FC20)
   *
   * What it does:
   * Creates one gal vertex-buffer wrapper from retained context metadata.
   */
  bool CD3DVertexStream::CreateBuffer()
  {
    if (mBuffer.get() == nullptr) {
      if (mContext.width_ == 0) {
        return false;
      }

      (void)CreateVertexBufferOnActiveDevice(&mBuffer, &mContext);
    }

    return true;
  }
} // namespace moho
