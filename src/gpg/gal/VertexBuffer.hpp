#pragma once

#include "boost/noncopyable.hpp"
#include "boost/shared_ptr.h"
#include "gpg/gal/D3D9Utils.h"

namespace gpg::gal
{
    class VertexBufferContext;

    /**
     * VFTABLE: 0x00D42F08
     * COL:  0x00E50AB8
     *
     * One vertex buffer as the engine sees it: its creation context and a
     * lock/unlock pair. `Device::CreateVertexBuffer` (slot 15) hands one out,
     * `Device::SetVertexBuffer` (slot 41) binds it. Both backends keep the
     * context at +0x04, so slot 1 is `lea eax, [ecx+4]; ret` in each
     * (0x008F5700, 0x0094D9F0).
     */
    class VertexBuffer : private boost::noncopyable
    {
    public:
        /**
         * Address: 0x008F56A0 (FUN_008F56A0, gpg::gal::VertexBuffer::VertexBuffer)
         *
         * What it does:
         * Installs the abstract vertex-buffer vtable.
         */
        VertexBuffer();

        /**
         * Address: 0x008F5690
         * Slot: 0 (`_purecall` in the base's own table)
         *
         * What it does:
         * Reinstalls the abstract vertex-buffer vtable.
         */
        virtual ~VertexBuffer() = 0;

        /**
         * Address: 0x009408D0 (FUN_009408D0, func_CreateVertexBuffer)
         *
         * What it does:
         * Creates one vertex buffer on the active device (slot 15,
         * `[vtbl+0x3C]`).
         */
        static boost::shared_ptr<VertexBuffer> Create(const VertexBufferContext& context);

        /**
         * Slot: 1
         *
         * What it does:
         * Returns the context the buffer was created from.
         */
        virtual VertexBufferContext* GetContext() = 0;

        /**
         * Slot: 2
         *
         * What it does:
         * Maps `size` bytes from byte `offset` (0/0 maps the whole buffer) and
         * returns the first mapped byte.
         */
        virtual void* Lock(unsigned int offset, unsigned int size, MohoD3DLockFlags lockFlags) = 0;

        /**
         * Slot: 3
         *
         * What it does:
         * Releases the mapping `Lock` returned.
         */
        virtual void Unlock() = 0;
    };

    static_assert(sizeof(VertexBuffer) == 0x04, "VertexBuffer size must be 0x04");
} // namespace gpg::gal
