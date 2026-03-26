#pragma once

#include <cstddef>
#include <cstdint>

namespace gpg::gal
{
    /**
     * VFTABLE: 0x00D47C80
     * COL:     0x00E53158
     */
    class VertexBufferContext
    {
    public:
        /**
         * Address: 0x00940850 (FUN_00940850)
         *
         * What it does:
         * Initializes vertex-buffer context metadata lanes to zero.
         */
        VertexBufferContext();

        /**
         * Address: 0x009408B0 (FUN_009408B0)
         *
         * What it does:
         * Owns the scalar-deleting destructor thunk for vertex-buffer context handles.
         */
        virtual ~VertexBufferContext();

    public:
        std::uint32_t type_ = 0;   // +0x04
        std::uint32_t usage_ = 0;  // +0x08
        std::uint32_t width_ = 0;  // +0x0C
        std::uint32_t height_ = 0; // +0x10
    };

    static_assert(offsetof(VertexBufferContext, type_) == 0x04, "VertexBufferContext::type_ offset must be 0x04");
    static_assert(offsetof(VertexBufferContext, usage_) == 0x08, "VertexBufferContext::usage_ offset must be 0x08");
    static_assert(offsetof(VertexBufferContext, width_) == 0x0C, "VertexBufferContext::width_ offset must be 0x0C");
    static_assert(offsetof(VertexBufferContext, height_) == 0x10, "VertexBufferContext::height_ offset must be 0x10");
    static_assert(sizeof(VertexBufferContext) == 0x14, "VertexBufferContext size must be 0x14");
}
