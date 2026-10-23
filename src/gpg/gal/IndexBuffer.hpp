#pragma once

#include <cstdint>

#include "boost/noncopyable.hpp"
#include "boost/shared_ptr.h"
#include "gpg/gal/D3D9Utils.h"

namespace gpg::gal
{
    class IndexBufferContext;

    /**
     * VFTABLE: 0x00D42D98
     * COL:  0x00E50980
     *
     * One index buffer: its creation context and a lock/unlock pair.
     * `Device::CreateIndexBuffer` (slot 16) hands one out,
     * `Device::SetBufferIndices` (slot 42) binds it. Both backends keep the
     * context at +0x04 (slot 1 is `lea eax, [ecx+4]; ret` in each, 0x008F4BE0
     * and 0x00901BE0).
     */
    class IndexBuffer : private boost::noncopyable
    {
    public:
        /**
         * Address: 0x008F4B80 (FUN_008F4B80)
         *
         * What it does:
         * Installs the abstract index-buffer vtable.
         */
        IndexBuffer();

        /**
         * Address: 0x008F4B70
         * Slot: 0 (`_purecall` in the base's own table)
         *
         * What it does:
         * Reinstalls the abstract index-buffer vtable.
         */
        virtual ~IndexBuffer() = 0;

        /**
         * Address: 0x00940660 (FUN_00940660, func_DeviceCreateIndexBuffer)
         *
         * What it does:
         * Creates one index buffer on the active device (slot 16,
         * `[vtbl+0x40]`).
         */
        static boost::shared_ptr<IndexBuffer> Create(const IndexBufferContext& context);

        /**
         * Slot: 1
         *
         * What it does:
         * Returns the context the buffer was created from.
         */
        virtual IndexBufferContext* GetContext() = 0;

        /**
         * Slot: 2
         *
         * What it does:
         * Maps `size` bytes from byte `offset` (0/0 maps the whole buffer) and
         * returns the first mapped index.
         */
        virtual std::int16_t* Lock(unsigned int offset, unsigned int size, MohoD3DLockFlags lockFlags) = 0;

        /**
         * Slot: 3
         *
         * What it does:
         * Releases the mapping `Lock` returned.
         */
        virtual void Unlock() = 0;
    };

    static_assert(sizeof(IndexBuffer) == 0x04, "IndexBuffer size must be 0x04");
} // namespace gpg::gal
