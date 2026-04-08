#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/gal/D3D9Utils.h"
#include "gpg/gal/VertexBufferContext.hpp"

namespace gpg::gal
{
    /**
     * VFTABLE: 0x00D42F1C
     * COL:  0x00E50B04
     * Source hints:
     *  - c:\work\rts\main\code\src\libs\gpggal\VertexBufferD3D9.cpp
     */
    class VertexBufferD3D9
    {
    public:
        /**
         * Address: 0x008F58C0 (FUN_008F58C0)
         *
         * What it does:
         * Owns the deleting-destructor thunk path for vertex-buffer wrappers.
         */
        virtual ~VertexBufferD3D9();

        /**
         * Address: 0x008F5700 (FUN_008F5700)
         *
         * What it does:
         * Returns the embedded vertex-buffer context block at `this+0x04`.
         */
        virtual VertexBufferContext* GetContext();

        /**
         * Address: 0x008F5950 (FUN_008F5950)
         *
         * What it does:
         * Locks the underlying D3D9 vertex buffer and returns mapped vertex data.
         */
        virtual void* Lock(unsigned int offset, unsigned int size, MohoD3DLockFlags lockFlags);

        /**
         * Address: 0x008F5B40 (FUN_008F5B40)
         *
         * What it does:
         * Unlocks the underlying D3D9 vertex buffer and clears lock-tracking state.
         */
        virtual HRESULT Unlock();

        /**
         * Address: 0x008F5CE0 (FUN_008F5CE0, gpg::gal::VertexBufferD3D9::GetD3D)
         *
         * What it does:
         * Returns the retained D3D9 vertex-buffer handle and throws when unset.
         */
        void* GetD3D();

    public:
        VertexBufferContext context_{}; // +0x04
        void* d3dVertexBuffer_ = nullptr; // +0x18
        bool locked_ = false; // +0x1C
        std::uint8_t lockPadding_[3]{}; // +0x1D
        void* mappedData_ = nullptr; // +0x20
    };

    static_assert(offsetof(VertexBufferD3D9, context_) == 0x04, "VertexBufferD3D9::context_ offset must be 0x04");
    static_assert(offsetof(VertexBufferD3D9, d3dVertexBuffer_) == 0x18, "VertexBufferD3D9::d3dVertexBuffer_ offset must be 0x18");
    static_assert(offsetof(VertexBufferD3D9, locked_) == 0x1C, "VertexBufferD3D9::locked_ offset must be 0x1C");
    static_assert(offsetof(VertexBufferD3D9, mappedData_) == 0x20, "VertexBufferD3D9::mappedData_ offset must be 0x20");
    static_assert(sizeof(VertexBufferD3D9) == 0x24, "VertexBufferD3D9 size must be 0x24");
}
