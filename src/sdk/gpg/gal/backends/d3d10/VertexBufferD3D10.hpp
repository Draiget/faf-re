// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/gal/VertexBufferContext.hpp"

namespace gpg {
namespace gal {
    /**
     * VFTABLE: 0x00D489B0
     * COL:  0x00E539E0
     * Source hints:
     *  - c:\work\rts\main\code\src\libs\gpggal\VertexBufferD3D10.cpp
     */
    class VertexBufferD3D10 {
    public:
      /**
       * Address: 0x0094DB50 (FUN_0094DB50)
       *
       * VertexBufferContext const *,void *,void *,void *
       *
       * What it does:
       * Initializes one D3D10 vertex-buffer wrapper from context + native/staging handles.
       */
      VertexBufferD3D10(
          const VertexBufferContext* context,
          void* nativeDevice,
          void* nativeBuffer,
          void* stagingBuffer
      );
      /**
       * Address: 0x0094DB30 (FUN_0094DB30)
       *
       * What it does:
       * Owns the deleting-destructor path and delegates body lanes to `FUN_0094DA80`.
       */
      virtual ~VertexBufferD3D10();
      /**
       * Address: 0x0094D9F0 (FUN_0094D9F0)
       *
       * What it does:
       * Returns the embedded vertex-buffer context lane at `this+0x04`.
       */
      virtual VertexBufferContext* GetContext();
      /**
       * Address: 0x0094DC00 (FUN_0094DC00)
       *
       * std::uint32_t,std::uint32_t,unsigned int
       *
       * What it does:
       * Maps the staging buffer with recovered map-flag conversion and returns
       * mapped pointer plus caller byte offset.
       */
      virtual void* Lock(std::uint32_t offset, std::uint32_t size, unsigned int lockFlags);

      /**
       * Address: 0x0094DE30 (FUN_0094DE30)
       *
       * What it does:
       * Unmaps the staging lane and dispatches one native copy from staging to GPU buffer.
       */
      virtual int Unlock();

      /**
       * Address: 0x0094DA00 (FUN_0094DA00)
       *
       * What it does:
       * Releases retained D3D10 buffer/device lanes and resets context metadata.
       */
      void DestroyState();

      /**
       * Address: 0x0094DF90 (FUN_0094DF90)
       *
       * What it does:
       * Validates and returns the retained native vertex-buffer handle lane.
       */
      void* GetNativeBufferOrThrow();

    public:
      VertexBufferContext context_{}; // +0x04
      void* nativeBuffer_ = nullptr;  // +0x18
      void* stagingBuffer_ = nullptr; // +0x1C
      void* nativeDevice_ = nullptr;  // +0x20
      bool locked_ = false;           // +0x24
      std::uint8_t lockPadding_[3]{}; // +0x25
      void* mappedData_ = nullptr;    // +0x28
    };

    static_assert(offsetof(VertexBufferD3D10, context_) == 0x04, "VertexBufferD3D10::context_ offset must be 0x04");
    static_assert(offsetof(VertexBufferD3D10, nativeBuffer_) == 0x18, "VertexBufferD3D10::nativeBuffer_ offset must be 0x18");
    static_assert(offsetof(VertexBufferD3D10, stagingBuffer_) == 0x1C, "VertexBufferD3D10::stagingBuffer_ offset must be 0x1C");
    static_assert(offsetof(VertexBufferD3D10, nativeDevice_) == 0x20, "VertexBufferD3D10::nativeDevice_ offset must be 0x20");
    static_assert(offsetof(VertexBufferD3D10, locked_) == 0x24, "VertexBufferD3D10::locked_ offset must be 0x24");
    static_assert(offsetof(VertexBufferD3D10, mappedData_) == 0x28, "VertexBufferD3D10::mappedData_ offset must be 0x28");
    static_assert(sizeof(VertexBufferD3D10) == 0x2C, "VertexBufferD3D10 size must be 0x2C");
} // namespace gal
} // namespace gpg
