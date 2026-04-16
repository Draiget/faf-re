// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/gal/IndexBufferContext.hpp"

namespace gpg {
namespace gal {
    /**
     * VFTABLE: 0x00D43654
     * COL:  0x00E51060
     * Source hints:
     *  - c:\work\rts\main\code\src\libs\gpggal\IndexBufferD3D10.cpp
     */
    class IndexBufferD3D10 {
    public:
      /**
       * Address: 0x00901B80 (FUN_00901B80)
       *
       * What it does:
       * Initializes one empty D3D10 index-buffer wrapper with default context
       * and cleared native/staging/lock tracking lanes.
       */
      IndexBufferD3D10();

      /**
       * Address: 0x00901D60 (FUN_00901D60)
       *
       * IndexBufferContext const *,void *,void *,void *
       *
       * What it does:
       * Initializes one D3D10 index-buffer wrapper from context + native/staging handles.
       */
      IndexBufferD3D10(
          const IndexBufferContext* context,
          void* nativeDevice,
          void* nativeBuffer,
          void* stagingBuffer
      );
      /**
       * Address: 0x00901D40 (FUN_00901D40)
       *
       * What it does:
       * Owns the deleting-destructor path and delegates body lanes to `FUN_00901C90`.
       */
      virtual ~IndexBufferD3D10();
      /**
       * Address: 0x00901BE0 (FUN_00901BE0)
       *
       * What it does:
       * Returns the embedded index-buffer context lane at `this+0x04`.
       */
      virtual IndexBufferContext* GetContextBuffer();
      /**
       * Address: 0x00901E00 (FUN_00901E00)
       *
       * std::uint32_t,std::uint32_t,unsigned int
       *
       * What it does:
       * Maps the staging buffer with recovered map-flag conversion and returns mapped data.
       */
      virtual std::int16_t* Lock(std::uint32_t offset, std::uint32_t size, unsigned int lockFlags);

      /**
       * Address: 0x00902020 (FUN_00902020)
       *
       * What it does:
       * Unmaps the staging lane and dispatches one native copy from staging to GPU buffer.
       */
      virtual int Unlock();

      /**
       * Address: 0x00901C10 (FUN_00901C10)
       *
       * What it does:
       * Releases retained D3D10 buffer/device lanes and resets context metadata.
       */
      void DestroyState();

      /**
       * Address: 0x00902180 (FUN_00902180)
       *
       * What it does:
       * Validates and returns the retained native index-buffer handle lane.
       */
      void* GetNativeBufferOrThrow();

    public:
      IndexBufferContext context_{}; // +0x04
      void* nativeBuffer_ = nullptr; // +0x14
      void* stagingBuffer_ = nullptr; // +0x18
      void* nativeDevice_ = nullptr;  // +0x1C
      bool locked_ = false;           // +0x20
      std::uint8_t lockPadding_[3]{}; // +0x21
      void* mappedData_ = nullptr;    // +0x24
    };

    static_assert(offsetof(IndexBufferD3D10, context_) == 0x04, "IndexBufferD3D10::context_ offset must be 0x04");
    static_assert(offsetof(IndexBufferD3D10, nativeBuffer_) == 0x14, "IndexBufferD3D10::nativeBuffer_ offset must be 0x14");
    static_assert(offsetof(IndexBufferD3D10, stagingBuffer_) == 0x18, "IndexBufferD3D10::stagingBuffer_ offset must be 0x18");
    static_assert(offsetof(IndexBufferD3D10, nativeDevice_) == 0x1C, "IndexBufferD3D10::nativeDevice_ offset must be 0x1C");
    static_assert(offsetof(IndexBufferD3D10, locked_) == 0x20, "IndexBufferD3D10::locked_ offset must be 0x20");
    static_assert(offsetof(IndexBufferD3D10, mappedData_) == 0x24, "IndexBufferD3D10::mappedData_ offset must be 0x24");
    static_assert(sizeof(IndexBufferD3D10) == 0x28, "IndexBufferD3D10 size must be 0x28");
} // namespace gal
} // namespace gpg
