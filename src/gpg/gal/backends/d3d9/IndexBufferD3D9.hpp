#pragma once

#include <cstddef>
#include <cstdint>

#include <d3d9.h>

#include "gpg/gal/D3D9Utils.h"
#include "gpg/gal/IndexBuffer.hpp"
#include "gpg/gal/IndexBufferContext.hpp"

namespace gpg::gal
{
    /**
     * VFTABLE: 0x00D42DAC
     * COL:  0x00E509CC
     * Source hints:
     *  - c:\work\rts\main\code\src\libs\gpggal\IndexBufferD3D9.cpp
     */
    class IndexBufferD3D9 : public IndexBuffer
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
        IndexBufferD3D9(const IndexBufferContext* context, IDirect3DIndexBuffer9* d3dIndexBuffer);

        /**
         * Address: 0x008F4C80 (FUN_008F4C80)
         * Address: 0x008F4D80 (FUN_008F4D80, slot 0: the scalar deleting destructor)
         *
         * What it does:
         * Releases the native index buffer and resets the context.
         */
        ~IndexBufferD3D9() override;

        /**
         * Address: 0x008F4BE0 (FUN_008F4BE0)
         * Slot: 1
         *
         * What it does:
         * Returns the context the buffer was created from.
         */
        IndexBufferContext* GetContext() override;

        /**
         * Address: 0x008F4E10 (FUN_008F4E10)
         * Slot: 2
         *
         * What it does:
         * Locks the underlying D3D9 index buffer and returns mapped index data.
         */
        std::int16_t* Lock(unsigned int offset, unsigned int size, MohoD3DLockFlags lockFlags) override;

        /**
         * Address: 0x008F4FF0 (FUN_008F4FF0)
         * Slot: 3
         *
         * What it does:
         * Unlocks the underlying D3D9 index buffer and clears lock-tracking state.
         */
        void Unlock() override;

        /**
         * Address: 0x008F5190 (FUN_008F5190, gpg::gal::IndexBufferD3D9::GetBuffer)
         *
         * What it does:
         * Returns the retained D3D9 index-buffer handle and throws when unset.
         */
        IDirect3DIndexBuffer9* GetBuffer();

        /**
         * Address: 0x008F4D10 (FUN_008F4D10, gpg::gal::IndexBufferD3D9::SetBuffer)
         *
         * What it does:
         * Releases any previous native index-buffer handle, resets context lanes,
         * then assigns one new context + native buffer payload.
         */
        std::uint32_t SetBuffer(const IndexBufferContext* context, IDirect3DIndexBuffer9* d3dIndexBuffer);

        /**
         * Address: 0x008F4C30 (FUN_008F4C30)
         *
         * What it does:
         * Releases the native index buffer and restores the default context.
         */
        void ResetBufferState();

    public:
        IndexBufferContext context_{};        // +0x04
        IDirect3DIndexBuffer9* d3dIndexBuffer_ = nullptr; // +0x14
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
