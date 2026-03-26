#pragma once

#include <cstddef>
#include <cstdint>

namespace gpg::gal
{
    struct VertexStreamStrideStorage
    {
        void* firstIterator_ = nullptr;        // +0x00
        std::uint32_t* begin_ = nullptr;       // +0x04
        std::uint32_t* end_ = nullptr;         // +0x08
        std::uint32_t* capacityEnd_ = nullptr; // +0x0C
    };

    /**
     * VFTABLE: 0x00D449AC
     * COL:  0x00E51284
     */
    class VertexFormatD3D10
    {
    public:
        /**
         * Address: 0x009045E0 (FUN_009045E0)
         *
         * unsigned int,void *
         *
         * What it does:
         * Initializes one D3D10 vertex-format wrapper from a format token and
         * retained declaration handle, then rebuilds per-stream stride lanes.
         */
        VertexFormatD3D10(std::uint32_t format, void* vertexDeclaration);

        /**
         * Address: 0x00904260 (FUN_00904260)
         *
         * What it does:
         * Owns the deleting-destructor path and delegates body lanes to
         * `FUN_009041E0`.
         */
        virtual ~VertexFormatD3D10();

        /**
         * Address: 0x00904280 (FUN_00904280)
         *
         * What it does:
         * Validates that the retained declaration handle is bound and returns it.
         */
        void* ValidateLayoutOrThrow();

        /**
         * Address: 0x00904500 (FUN_00904500)
         *
         * unsigned int,void *
         *
         * What it does:
         * Rebinds declaration state and rebuilds per-stream stride lanes from
         * static vertex-element layout tables for the selected format.
         */
        std::uint32_t Initialize(std::uint32_t format, void* vertexDeclaration);

    public:
        std::uint32_t format_ = 0x17U;              // +0x04
        VertexStreamStrideStorage streamStrides_{}; // +0x08
        void* vertexDeclaration_ = nullptr;         // +0x18
    };

    static_assert(sizeof(VertexStreamStrideStorage) == 0x10, "VertexStreamStrideStorage size must be 0x10");
    static_assert(offsetof(VertexFormatD3D10, format_) == 0x04, "VertexFormatD3D10::format_ offset must be 0x04");
    static_assert(offsetof(VertexFormatD3D10, streamStrides_) == 0x08, "VertexFormatD3D10::streamStrides_ offset must be 0x08");
    static_assert(offsetof(VertexFormatD3D10, vertexDeclaration_) == 0x18, "VertexFormatD3D10::vertexDeclaration_ offset must be 0x18");
    static_assert(sizeof(VertexFormatD3D10) == 0x1C, "VertexFormatD3D10 size must be 0x1C");
}
