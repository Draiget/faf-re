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
         * Address: 0x00940870 (FUN_00940870, gpg::gal::VertexBufferContext::VertexBufferContext)
         *
         * What it does:
         * Initializes vertex-buffer context lanes from explicit
         * `width/height/type/usage` payload values.
         */
        VertexBufferContext(std::uint32_t width, std::uint32_t height, std::uint32_t type, std::uint32_t usage);

        /**
         * Address: 0x009408A0 (FUN_009408A0, gpg::gal::VertexBufferContext::~VertexBufferContext)
         * Address: 0x009408B0 (FUN_009408B0, scalar deleting destructor thunk)
         *
         * What it does:
         * Restores the vftable lane and owns the deleting-destructor thunk path
         * for vertex-buffer context handles.
         */
        virtual ~VertexBufferContext();

        /**
         * Address: 0x008F5710 (FUN_008F5710)
         *
         * What it does:
         * Copies vertex-buffer metadata payload lanes from another context.
         */
        VertexBufferContext& AssignFrom(const VertexBufferContext& other);

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
