#pragma once

#include <cstddef>
#include <cstdint>

namespace gpg::gal
{
    /**
     * VFTABLE: 0x00D48754
     * COL:     0x00E53770
     */
    class VertexFormatD3D9
    {
    public:
        /**
         * Address: 0x0094AD40 (FUN_0094AD40)
         *
         * What it does:
         * Owns the scalar-deleting destructor thunk for D3D9 vertex-format wrappers.
         */
        virtual ~VertexFormatD3D9();

        /**
         * Address: 0x0094AD60 (FUN_0094AD60, gpg::gal::VertexFormatD3D9::GetDeclaration)
         *
         * What it does:
         * Returns the retained D3D9 vertex-declaration handle and throws when unset.
         */
        void* GetDeclaration();

    public:
        std::uint32_t formatCode_;                    // +0x04
        void* elementArrayProxy_;                     // +0x08
        std::uint32_t* elementArrayBegin_;            // +0x0C
        std::uint32_t* elementArrayEnd_;              // +0x10
        std::uint32_t* elementArrayCapacityEnd_;      // +0x14
        void* vertexDeclaration_;                     // +0x18
    };

    static_assert(offsetof(VertexFormatD3D9, formatCode_) == 0x04, "VertexFormatD3D9::formatCode_ offset must be 0x04");
    static_assert(offsetof(VertexFormatD3D9, elementArrayProxy_) == 0x08, "VertexFormatD3D9::elementArrayProxy_ offset must be 0x08");
    static_assert(offsetof(VertexFormatD3D9, elementArrayBegin_) == 0x0C, "VertexFormatD3D9::elementArrayBegin_ offset must be 0x0C");
    static_assert(offsetof(VertexFormatD3D9, elementArrayEnd_) == 0x10, "VertexFormatD3D9::elementArrayEnd_ offset must be 0x10");
    static_assert(
        offsetof(VertexFormatD3D9, elementArrayCapacityEnd_) == 0x14,
        "VertexFormatD3D9::elementArrayCapacityEnd_ offset must be 0x14"
    );
    static_assert(offsetof(VertexFormatD3D9, vertexDeclaration_) == 0x18, "VertexFormatD3D9::vertexDeclaration_ offset must be 0x18");
    static_assert(sizeof(VertexFormatD3D9) == 0x1C, "VertexFormatD3D9 size must be 0x1C");
}
