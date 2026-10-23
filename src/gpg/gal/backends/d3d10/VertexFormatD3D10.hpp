#pragma once

#include <cstddef>
#include <cstdint>

#include <d3d10.h>

#include "gpg/gal/VertexFormat.hpp"

namespace gpg::gal
{
    /**
     * VFTABLE: 0x00D449AC
     * COL:  0x00E51284
     *
     * The D3D10 vertex format: the base's format code and stream strides plus
     * the `ID3D10InputLayout` built against the signature effect.
     */
    class VertexFormatD3D10 : public VertexFormat
    {
    public:
        /**
         * Address: 0x009045E0 (FUN_009045E0)
         *
         * What it does:
         * Adopts `vertexDeclaration` as the input layout for format `format`
         * and computes the per-stream strides.
         */
        VertexFormatD3D10(std::uint32_t format, ID3D10InputLayout* vertexDeclaration);

        /**
         * Address: 0x009041E0 (FUN_009041E0)
         * Address: 0x00904260 (FUN_00904260, slot 0: the scalar deleting destructor)
         *
         * What it does:
         * Releases the input layout and resets the format code.
         */
        ~VertexFormatD3D10() override;

        /**
         * Address: 0x00904280 (FUN_00904280)
         *
         * What it does:
         * Returns the input layout, throwing "invalid vertex layout" when unset.
         */
        ID3D10InputLayout* ValidateLayoutOrThrow();

        /**
         * Address: 0x00904500 (FUN_00904500)
         *
         * What it does:
         * Replaces the input layout and format code and rebuilds the stream
         * strides from the format's element table.
         */
        std::uint32_t Initialize(std::uint32_t format, ID3D10InputLayout* vertexDeclaration);

        /**
         * Address: 0x00904180 (FUN_00904180)
         *
         * What it does:
         * Releases the input layout and restores format code 0x17.
         */
        void ResetDeclaration();

    public:
        ID3D10InputLayout* vertexDeclaration_ = nullptr; // +0x18
    };

    static_assert(offsetof(VertexFormatD3D10, vertexDeclaration_) == 0x18, "VertexFormatD3D10::vertexDeclaration_ offset must be 0x18");
    static_assert(sizeof(VertexFormatD3D10) == 0x1C, "VertexFormatD3D10 size must be 0x1C");
}
