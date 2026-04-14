#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/Vector.h"

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
         * Address: 0x0094B0A0 (FUN_0094B0A0, gpg::gal::VertexFormatD3D9::VertexFormatD3D9)
         *
         * What it does:
         * Initializes one D3D9 vertex-format wrapper and applies caller format
         * code plus native declaration payload.
         */
        VertexFormatD3D9(std::uint32_t formatCode, void* vertexDeclaration);

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

        /**
         * Address: 0x0094AC90 (FUN_0094AC90)
         *
         * What it does:
         * Releases the retained vertex-declaration handle and restores the
         * default format code lane (`0x17`).
         */
        void ResetDeclarationState();

        /**
         * Address: 0x0094AEF0 (FUN_0094AEF0)
         *
         * What it does:
         * Applies one format/declaration payload and rebuilds per-stream stride
         * lanes from the recovered D3D vertex-element table.
         */
        void SetFormatDeclaration(std::uint32_t formatCode, void* vertexDeclaration);

    public:
        std::uint32_t formatCode_;                    // +0x04
        msvc8::vector<std::uint32_t> elementStrideByStream_; // +0x08
        void* vertexDeclaration_;                     // +0x18
    };

    static_assert(offsetof(VertexFormatD3D9, formatCode_) == 0x04, "VertexFormatD3D9::formatCode_ offset must be 0x04");
    static_assert(offsetof(VertexFormatD3D9, elementStrideByStream_) == 0x08, "VertexFormatD3D9::elementStrideByStream_ offset must be 0x08");
    static_assert(offsetof(VertexFormatD3D9, vertexDeclaration_) == 0x18, "VertexFormatD3D9::vertexDeclaration_ offset must be 0x18");
    static_assert(sizeof(VertexFormatD3D9) == 0x1C, "VertexFormatD3D9 size must be 0x1C");
}
