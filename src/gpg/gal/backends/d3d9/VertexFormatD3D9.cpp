#include "gpg/gal/backends/d3d9/D3D9Private.h"

namespace gpg::gal
{
namespace
{

        /**
         * Address: 0x0094ABF0 (FUN_0094ABF0)
         *
         * What it does:
         * Maps one D3D declaration type token to the element byte-width used
         * when accumulating stream strides.
         */
        [[nodiscard]] std::uint32_t GetVertexElementTypeSizeBytes(const std::uint8_t elementType) noexcept
        {
            switch (elementType)
            {
            case 0U:
            case 4U:
            case 5U:
            case 6U:
            case 8U:
            case 9U:
            case 11U:
            case 13U:
            case 14U:
            case 15U:
                return 4U;
            case 1U:
            case 7U:
            case 10U:
            case 12U:
            case 16U:
                return 8U;
            case 2U:
                return 12U;
            case 3U:
                return 16U;
            default:
                return 0U;
            }
        }

        static constexpr D3DVERTEXELEMENT9 kVertexElementEndSentinel = D3DDECL_END();

        [[nodiscard]] bool IsVertexElementEndSentinel(const D3DVERTEXELEMENT9& element) noexcept
        {
            return (element.Stream == kVertexElementEndSentinel.Stream) &&
                   (element.Offset == kVertexElementEndSentinel.Offset) &&
                   (element.Type == kVertexElementEndSentinel.Type) &&
                   (element.Method == kVertexElementEndSentinel.Method) &&
                   (element.Usage == kVertexElementEndSentinel.Usage) &&
                   (element.UsageIndex == kVertexElementEndSentinel.UsageIndex);
        }
}


    /**
     * Address: 0x0094AED0 (FUN_0094AED0)
     *
     * What it does:
     * Default-constructs an empty format: no declaration, format code `0x17`
     * (the "no format" code the destructor also leaves behind).
     */
    VertexFormatD3D9::VertexFormatD3D9()
        : vertexDeclaration_(nullptr)
    {
        formatCode_ = 0x17U;
    }

    /**
     * Address: 0x0094B0A0 (FUN_0094B0A0, gpg::gal::VertexFormatD3D9::VertexFormatD3D9)
     *
     * What it does:
     * Adopts `vertexDeclaration` as the declaration for format `formatCode`
     * and computes the per-stream strides.
     */
    VertexFormatD3D9::VertexFormatD3D9(const std::uint32_t formatCode, IDirect3DVertexDeclaration9* const vertexDeclaration)
        : vertexDeclaration_(nullptr)
    {
        SetFormatDeclaration(formatCode, vertexDeclaration);
    }

    /**
     * Address: 0x0094AEF0 (FUN_0094AEF0)
     *
     * What it does:
     * Replaces the declaration and format code, then rebuilds the byte stride
     * of every stream the format's element table reads (each stream's stride
     * is its furthest element end).
     */
    void VertexFormatD3D9::SetFormatDeclaration(
        const std::uint32_t formatCode, IDirect3DVertexDeclaration9* const vertexDeclaration
    )
    {
        SafeRelease(vertexDeclaration_);
        vertexDeclaration_ = vertexDeclaration;
        formatCode_ = formatCode;

        const D3DVERTEXELEMENT9* const elementTable = GetVertexFormatElementsOrThrow(formatCode);
        std::size_t declarationElementCount = 0U;
        while (!IsVertexElementEndSentinel(elementTable[declarationElementCount]))
        {
            ++declarationElementCount;
        }

        streamStrides_.clear();
        for (std::size_t elementIndex = 0U; elementIndex < declarationElementCount; ++elementIndex)
        {
            const D3DVERTEXELEMENT9& element = elementTable[elementIndex];
            const std::size_t streamIndex = static_cast<std::size_t>(element.Stream);
            if (streamStrides_.size() <= streamIndex)
            {
                streamStrides_.resize(streamIndex + 1U, 0U);
            }

            const std::uint32_t elementEndOffset =
                static_cast<std::uint32_t>(element.Offset) + GetVertexElementTypeSizeBytes(element.Type);
            std::uint32_t& streamStride = streamStrides_[streamIndex];
            if (streamStride < elementEndOffset)
            {
                streamStride = elementEndOffset;
            }
        }
    }

    /**
     * Address: 0x0094ACC0 (FUN_0094ACC0)
     * Address: 0x0094AD40 (FUN_0094AD40, slot 0: the scalar deleting destructor)
     *
     * What it does:
     * Releases the declaration and leaves format code `0x17`, then the
     * `VertexFormat` base destructor frees the stride vector (inlined,
     * 0x0094AD03..0x0094AD23).
     */
    VertexFormatD3D9::~VertexFormatD3D9()
    {
        ResetDeclarationState();
    }

    /**
     * Address: 0x0094AC90 (FUN_0094AC90)
     *
     * What it does:
     * Releases the retained vertex-declaration handle and restores the
     * default format code lane (`0x17`).
     */
    void VertexFormatD3D9::ResetDeclarationState()
    {
        SafeRelease(vertexDeclaration_);
        formatCode_ = 0x17U;
    }

    /**
     * Address: 0x0094AD60 (FUN_0094AD60, gpg::gal::VertexFormatD3D9::GetDeclaration)
     *
     * What it does:
     * Returns the retained D3D9 vertex-declaration handle and throws when unset.
     */
    IDirect3DVertexDeclaration9* VertexFormatD3D9::GetDeclaration()
    {
        if (vertexDeclaration_ == nullptr)
        {
            ThrowGalError("VertexFormatD3D9.cpp", 120, "invalid vertex format");
        }

        return vertexDeclaration_;
    }
}

