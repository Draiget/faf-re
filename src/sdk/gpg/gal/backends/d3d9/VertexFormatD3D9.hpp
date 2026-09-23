#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/gal/VertexFormat.hpp"

namespace gpg::gal
{
    /**
     * VFTABLE: 0x00D48754
     * COL:     0x00E53770
     *
     * The D3D9 vertex format: the base's format code and stream strides plus
     * the `IDirect3DVertexDeclaration9` built from that format's element
     * table.
     */
    class VertexFormatD3D9 : public VertexFormat
    {
    public:
        /**
         * Address: 0x0094AED0 (FUN_0094AED0)
         *
         * What it does:
         * Default-constructs an empty format (no declaration, format code 0x17).
         */
        VertexFormatD3D9();

        /**
         * Address: 0x0094B0A0 (FUN_0094B0A0, gpg::gal::VertexFormatD3D9::VertexFormatD3D9)
         *
         * What it does:
         * Adopts `vertexDeclaration` as the declaration for format `formatCode`
         * and computes the per-stream strides.
         */
        VertexFormatD3D9(std::uint32_t formatCode, void* vertexDeclaration);

        /**
         * Address: 0x0094ACC0 (FUN_0094ACC0)
         * Address: 0x0094AD40 (FUN_0094AD40, slot 0: the scalar deleting destructor)
         *
         * What it does:
         * Releases the declaration and resets the format code.
         */
        ~VertexFormatD3D9() override;

        /**
         * Address: 0x0094AD60 (FUN_0094AD60, gpg::gal::VertexFormatD3D9::GetDeclaration)
         *
         * What it does:
         * Returns the declaration, throwing "invalid vertex format" when unset.
         */
        void* GetDeclaration();

        /**
         * Address: 0x0094AC90 (FUN_0094AC90)
         *
         * What it does:
         * Releases the declaration and restores format code 0x17.
         */
        void ResetDeclarationState();

        /**
         * Address: 0x0094AEF0 (FUN_0094AEF0)
         *
         * What it does:
         * Replaces the declaration and format code and rebuilds the stream
         * strides from the format's element table.
         */
        void SetFormatDeclaration(std::uint32_t formatCode, void* vertexDeclaration);

    public:
        void* vertexDeclaration_; // +0x18 IDirect3DVertexDeclaration9*
    };

    static_assert(offsetof(VertexFormatD3D9, vertexDeclaration_) == 0x18, "VertexFormatD3D9::vertexDeclaration_ offset must be 0x18");
    static_assert(sizeof(VertexFormatD3D9) == 0x1C, "VertexFormatD3D9 size must be 0x1C");
}
