#pragma once

#include <cstddef>
#include <cstdint>

namespace gpg::gal
{
    /**
     * VFTABLE: 0x00D47C78
     * COL:     0x00E53110
     */
    class IndexBufferContext
    {
    public:
        /**
         * Address: 0x009405F0 (FUN_009405F0)
         *
         * What it does:
         * Initializes index-buffer context metadata lanes to zero.
         */
        IndexBufferContext();

        /**
         * Address: 0x00940640 (FUN_00940640)
         *
         * What it does:
         * Owns the scalar-deleting destructor thunk for index-buffer context handles.
         */
        virtual ~IndexBufferContext();

    public:
        std::uint32_t format_ = 0; // +0x04
        std::uint32_t size_ = 0;   // +0x08
        std::uint32_t type_ = 0;   // +0x0C
    };

    static_assert(offsetof(IndexBufferContext, format_) == 0x04, "IndexBufferContext::format_ offset must be 0x04");
    static_assert(offsetof(IndexBufferContext, size_) == 0x08, "IndexBufferContext::size_ offset must be 0x08");
    static_assert(offsetof(IndexBufferContext, type_) == 0x0C, "IndexBufferContext::type_ offset must be 0x0C");
    static_assert(sizeof(IndexBufferContext) == 0x10, "IndexBufferContext size must be 0x10");
}
