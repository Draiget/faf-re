#include "gpg/gal/backends/d3d10/D3D10Private.h"

namespace gpg::gal
{

  /**
   * Address: 0x00901B80 (FUN_00901B80)
   *
   * What it does:
   * Initializes one empty D3D10 index-buffer wrapper with default context and
   * cleared native/staging/lock tracking lanes.
   */
  IndexBufferD3D10::IndexBufferD3D10()
    : context_()
    , nativeBuffer_(nullptr)
    , stagingBuffer_(nullptr)
    , nativeDevice_(nullptr)
    , locked_(false)
    , lockPadding_{}
    , mappedData_(nullptr)
  {}

  /**
   * Address: 0x00901D60 (FUN_00901D60)
   *
   * IndexBufferContext const *,void *,void *,void *
   *
   * What it does:
   * Initializes one D3D10 index-buffer wrapper from context + native/staging handles.
   */
  IndexBufferD3D10::IndexBufferD3D10(
    const IndexBufferContext* const context,
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
    context_.format_ = context->format_;
    context_.size_ = context->size_;
    context_.type_ = context->type_;
    nativeBuffer_ = nativeBuffer;
    stagingBuffer_ = stagingBuffer;
    nativeDevice_ = nativeDevice;
    if (nativeDevice_ != nullptr) {
      nativeDevice_->AddRef();
    }
  }

  /**
   * Address: 0x00901C90 (FUN_00901C90)
   * Address: 0x00901D40 (FUN_00901D40, slot 0: the scalar deleting destructor)
   *
   * What it does:
   * Releases the device buffers and resets the context, then the
   * `IndexBuffer` base destructor runs (inlined, 0x00901CD3).
   */
  IndexBufferD3D10::~IndexBufferD3D10()
  {
    DestroyState();
  }

  /**
   * Address: 0x00901BE0 (FUN_00901BE0)
   *
   * What it does:
   * Returns the context the buffer was created from.
   */
  IndexBufferContext* IndexBufferD3D10::GetContext()
  {
    return &context_;
  }

  /**
   * Address: 0x00901E00 (FUN_00901E00)
   *
   * std::uint32_t,std::uint32_t,unsigned int
   *
   * What it does:
   * Maps the staging buffer with recovered map-flag conversion and returns mapped data.
   */
  std::int16_t*
  IndexBufferD3D10::Lock(const unsigned int offset, const unsigned int size, const MohoD3DLockFlags lockFlags)
  {
    static_cast<void>(offset);
    static_cast<void>(size);

    if (nativeBuffer_ == nullptr) {
      ThrowGalError("IndexBufferD3D10.cpp", 57, "attempt to map invalid vertex buffer");
    }

    if (stagingBuffer_ == nullptr) {
      ThrowGalError("IndexBufferD3D10.cpp", 58, "attempt to map invalid vertex buffer");
    }

    if (locked_) {
      ThrowGalError("IndexBufferD3D10.cpp", 59, "vertex buffer map/unmap mismatch");
    }

    const auto flags = static_cast<unsigned int>(lockFlags);
    unsigned int mapMode = ((flags * 2U) | (flags >> 1U)) & 3U;
    if (mapMode == 0U) {
      mapMode = 2U;
    }

    const HRESULT result = stagingBuffer_->Map(static_cast<D3D10_MAP>(mapMode), 0U, &mappedData_);
    if (result < 0) {
      ThrowGalErrorFromHresult("IndexBufferD3D10.cpp", 71, result);
    }

    locked_ = true;
    return reinterpret_cast<std::int16_t*>(mappedData_);
  }

  /**
   * Address: 0x00902020 (FUN_00902020)
   *
   * What it does:
   * Unmaps the staging lane and dispatches one native copy from staging to GPU buffer.
   */
  void IndexBufferD3D10::Unlock()
  {
    if (nativeBuffer_ == nullptr) {
      ThrowGalError("IndexBufferD3D10.cpp", 79, "attempt to unlock invalid vertex buffer");
    }

    if (!locked_) {
      ThrowGalError("IndexBufferD3D10.cpp", 80, "vertex buffer lock/unlock mismatch");
    }

    stagingBuffer_->Unmap();
    nativeDevice_->CopySubresourceRegion(nativeBuffer_, 0U, 0U, 0U, 0U, stagingBuffer_, 0U, nullptr);

    locked_ = false;
    mappedData_ = nullptr;
  }

  /**
   * Address: 0x00901C10 (FUN_00901C10)
   *
   * What it does:
   * Releases retained D3D10 buffer/device lanes and resets context metadata.
   */
  void IndexBufferD3D10::DestroyState()
  {
    SafeRelease(nativeBuffer_);
    SafeRelease(stagingBuffer_);
    SafeRelease(nativeDevice_);
    locked_ = false;
    mappedData_ = nullptr;

    const IndexBufferContext resetContext{};
    context_.format_ = resetContext.format_;
    context_.size_ = resetContext.size_;
    context_.type_ = resetContext.type_;
  }

  /**
   * Address: 0x00902180 (FUN_00902180)
   *
   * What it does:
   * Validates and returns the retained native index-buffer handle lane.
   */
  ID3D10Buffer* IndexBufferD3D10::GetNativeBufferOrThrow()
  {
    if (nativeBuffer_ == nullptr) {
      ThrowGalError("IndexBufferD3D10.cpp", 115, "invalid index buffer");
    }

    return nativeBuffer_;
  }
}

