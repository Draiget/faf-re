#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/gal/D3D9Utils.h"
#include "gpg/gal/IndexBufferContext.hpp"

namespace gpg::gal
{
    /**
     * VFTABLE: 0x00D42DAC
     * COL:  0x00E509CC
     * Source hints:
     *  - c:\work\rts\main\code\src\libs\gpggal\IndexBufferD3D9.cpp
     */
    class IndexBufferD3D9
    {
    public:
        /**
         * Address: 0x008F4B90 (FUN_008F4B90)
         *
         * What it does:
         * Initializes one empty D3D9 index-buffer wrapper with default context
         * and cleared native/lock tracking lanes.
         */
        IndexBufferD3D9();

        /**
         * Address: 0x008F4DA0 (FUN_008F4DA0)
         *
         * What it does:
         * Initializes one D3D9 index-buffer wrapper and binds the provided
         * context/native buffer payload.
         */
        IndexBufferD3D9(const IndexBufferContext* context, void* d3dIndexBuffer);

        /**
         * Address: 0x008F4D80 (FUN_008F4D80)
         *
         * What it does:
         * Owns the deleting-destructor path and delegates to `FUN_008F4C80` body semantics.
         */
        virtual ~IndexBufferD3D9();

        /**
         * Address: 0x008F4BE0 (FUN_008F4BE0)
         *
         * What it does:
         * Returns the embedded index-buffer context block at `this+0x04`.
         */
        virtual IndexBufferContext* GetContextBuffer();

        /**
         * Address: 0x008F4E10 (FUN_008F4E10)
         *
         * What it does:
         * Locks the underlying D3D9 index buffer and returns mapped index data.
         */
        virtual std::int16_t* Lock(unsigned int offset, unsigned int size, MohoD3DLockFlags lockFlags);

        /**
         * Address: 0x008F4FF0 (FUN_008F4FF0)
         *
         * What it does:
         * Unlocks the underlying D3D9 index buffer and clears lock-tracking state.
         */
        virtual HRESULT Unlock();

        /**
         * Address: 0x008F5190 (FUN_008F5190, gpg::gal::IndexBufferD3D9::GetBuffer)
         *
         * What it does:
         * Returns the retained D3D9 index-buffer handle and throws when unset.
         */
        void* GetBuffer();

        /**
         * Address: 0x008F4D10 (FUN_008F4D10, gpg::gal::IndexBufferD3D9::SetBuffer)
         *
         * What it does:
         * Releases any previous native index-buffer handle, resets context lanes,
         * then assigns one new context + native buffer payload.
         */
        std::uint32_t SetBuffer(const IndexBufferContext* context, void* d3dIndexBuffer);

    public:
        IndexBufferContext context_{};        // +0x04
        void* d3dIndexBuffer_ = nullptr;      // +0x14
        bool locked_ = false;                 // +0x18
        std::uint8_t lockPadding_[3]{};       // +0x19
        std::int16_t* indexData_ = nullptr;   // +0x1C
    };

    static_assert(offsetof(IndexBufferD3D9, context_) == 0x04, "IndexBufferD3D9::context_ offset must be 0x04");
    static_assert(offsetof(IndexBufferD3D9, d3dIndexBuffer_) == 0x14, "IndexBufferD3D9::d3dIndexBuffer_ offset must be 0x14");
    static_assert(offsetof(IndexBufferD3D9, locked_) == 0x18, "IndexBufferD3D9::locked_ offset must be 0x18");
    static_assert(offsetof(IndexBufferD3D9, indexData_) == 0x1C, "IndexBufferD3D9::indexData_ offset must be 0x1C");
    static_assert(sizeof(IndexBufferD3D9) == 0x20, "IndexBufferD3D9 size must be 0x20");
}
