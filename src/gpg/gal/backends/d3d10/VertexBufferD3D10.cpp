#include "gpg/gal/backends/d3d10/D3D10Private.h"

namespace gpg::gal
{

  /**
   * Address: 0x0094D990 (FUN_0094D990)
   *
   * What it does:
   * Initializes one empty D3D10 vertex-buffer wrapper with default context and
   * cleared native/staging/lock tracking lanes.
   */
  VertexBufferD3D10::VertexBufferD3D10()
    : context_()
    , nativeBuffer_(nullptr)
    , stagingBuffer_(nullptr)
    , nativeDevice_(nullptr)
    , locked_(false)
    , lockPadding_{}
    , mappedData_(nullptr)
  {}

  /**
   * Address: 0x0094DB50 (FUN_0094DB50)
   *
   * VertexBufferContext const *,void *,void *,void *
   *
   * What it does:
   * Initializes one D3D10 vertex-buffer wrapper from context + native/staging handles.
   */
  VertexBufferD3D10::VertexBufferD3D10(
    const VertexBufferContext* const context,
    ID3D10Device* const nativeDevice,
    ID3D10Buffer* const nativeBuffer,
    ID3D10Buffer* const stagingBuffer
  )
    : context_()
    , nativeBuffer_(nullptr)
    , stagingBuffer_(nullptr)
    , nativeDevice_(nullptr)
    , locked_(false)
    , lockPadding_{}
    , mappedData_(nullptr)
  {
    DestroyState();
    context_.type_ = context->type_;
    context_.usage_ = context->usage_;
    context_.vertexCount_ = context->vertexCount_;
    context_.stride_ = context->stride_;
    nativeBuffer_ = nativeBuffer;
    stagingBuffer_ = stagingBuffer;
    nativeDevice_ = nativeDevice;
    if (nativeDevice_ != nullptr) {
      nativeDevice_->AddRef();
    }
  }

  /**
   * Address: 0x0094DA80 (FUN_0094DA80)
   * Address: 0x0094DB30 (FUN_0094DB30, slot 0: the scalar deleting destructor)
   *
   * What it does:
   * Releases the device buffers and resets the context, then the
   * `VertexBuffer` base destructor runs (inlined, 0x0094DAC3).
   */
  VertexBufferD3D10::~VertexBufferD3D10()
  {
    DestroyState();
  }

  /**
   * Address: 0x0094D9F0 (FUN_0094D9F0)
   *
   * What it does:
   * Returns the context the buffer was created from.
   */
  VertexBufferContext* VertexBufferD3D10::GetContext()
  {
    return &context_;
  }

  /**
   * Address: 0x0094DC00 (FUN_0094DC00)
   *
   * std::uint32_t,std::uint32_t,unsigned int
   *
   * What it does:
   * Maps the staging buffer with recovered map-flag conversion and returns
   * mapped pointer plus caller byte offset.
   */
  void* VertexBufferD3D10::Lock(const unsigned int offset, const unsigned int size, const MohoD3DLockFlags lockFlags)
  {
    static_cast<void>(size);

    if (nativeBuffer_ == nullptr) {
      ThrowGalError("VertexBufferD3D10.cpp", 57, "attempt to map invalid vertex buffer");
    }

    if (stagingBuffer_ == nullptr) {
      ThrowGalError("VertexBufferD3D10.cpp", 58, "attempt to map invalid vertex buffer");
    }

    if (locked_) {
      ThrowGalError("VertexBufferD3D10.cpp", 59, "vertex buffer map/unmap mismatch");
    }

    const auto flags = static_cast<unsigned int>(lockFlags);
    unsigned int mapMode = ((flags * 2U) | (flags >> 1U)) & 3U;
    if (mapMode == 0U) {
      mapMode = 2U;
    }

    const HRESULT result = stagingBuffer_->Map(static_cast<D3D10_MAP>(mapMode), 0U, &mappedData_);
    if (result < 0) {
      ThrowGalErrorFromHresult("VertexBufferD3D10.cpp", 71, result);
    }

    locked_ = true;
    auto* const mappedBytes = reinterpret_cast<std::uint8_t*>(mappedData_);
    return mappedBytes + offset;
  }

  /**
   * Address: 0x0094DE30 (FUN_0094DE30)
   *
   * What it does:
   * Unmaps the staging lane and dispatches one native copy from staging to GPU buffer.
   */
  void VertexBufferD3D10::Unlock()
  {
    if (nativeBuffer_ == nullptr) {
      ThrowGalError("VertexBufferD3D10.cpp", 79, "attempt to unlock invalid vertex buffer");
    }

    if (!locked_) {
      ThrowGalError("VertexBufferD3D10.cpp", 80, "vertex buffer lock/unlock mismatch");
    }

    stagingBuffer_->Unmap();
    nativeDevice_->CopySubresourceRegion(nativeBuffer_, 0U, 0U, 0U, 0U, stagingBuffer_, 0U, nullptr);

    locked_ = false;
    mappedData_ = nullptr;
  }

  /**
   * Address: 0x0094DA00 (FUN_0094DA00)
   *
   * What it does:
   * Releases retained D3D10 buffer/device lanes and resets context metadata.
   */
  void VertexBufferD3D10::DestroyState()
  {
    SafeRelease(nativeBuffer_);
    SafeRelease(stagingBuffer_);
    SafeRelease(nativeDevice_);
    locked_ = false;
    mappedData_ = nullptr;

    const VertexBufferContext resetContext{};
    context_.type_ = resetContext.type_;
    context_.usage_ = resetContext.usage_;
    context_.vertexCount_ = resetContext.vertexCount_;
    context_.stride_ = resetContext.stride_;
  }

  /**
   * Address: 0x0094DF90 (FUN_0094DF90)
   *
   * What it does:
   * Validates and returns the retained native vertex-buffer handle lane.
   */
  ID3D10Buffer* VertexBufferD3D10::GetNativeBufferOrThrow()
  {
    if (nativeBuffer_ == nullptr) {
      ThrowGalError("VertexBufferD3D10.cpp", 115, "invalid vertex buffer");
    }

    return nativeBuffer_;
  }
}

