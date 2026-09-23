#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/noncopyable.hpp"
#include "boost/shared_ptr.h"
#include "legacy/containers/Vector.h"

namespace gpg::gal
{
    /**
     * VFTABLE: 0x00D449A4
     * COL:  0x00E51238
     *
     * A vertex declaration as the device binds it: the gal vertex-format code
     * and the byte stride of every vertex stream the declaration reads. Both
     * backends derive from it and add their native declaration object at
     * +0x18 (`IDirect3DVertexDeclaration9` / `ID3D10InputLayout`).
     *
     * The two fields belong to this class, not to the backends: the base
     * constructor (0x009044C0) builds the stride vector, and each backend
     * destructor ends by reinstalling this vtable and freeing that vector
     * (0x0094AD03..0x0094AD23 on D3D9) - the inlined `~VertexFormat`.
     */
    class VertexFormat : private boost::noncopyable
    {
    public:
        /**
         * Address: 0x009044C0 (FUN_009044C0, gpg::gal::VertexFormat::VertexFormat)
         *
         * What it does:
         * Installs the base vtable and constructs the empty stride vector. The
         * format code is left for the backend to set.
         */
        VertexFormat();

        /**
         * Address: 0x009041B0
         * Slot: 0 (`_purecall` in the base's own table)
         *
         * What it does:
         * Frees the stride vector. Both backend destructors inline it.
         */
        virtual ~VertexFormat() = 0;

        /**
         * Address: 0x00940900 (FUN_00940900)
         *
         * What it does:
         * Creates gal vertex format `formatCode` on the active device (slot 14,
         * `[vtbl+0x38]`). `CD3DVertexFormat`'s constructor is its caller
         * (0x0043CFE6).
         */
        static boost::shared_ptr<VertexFormat> Create(std::uint32_t formatCode);

        std::uint32_t formatCode_;                   // +0x04
        msvc8::vector<std::uint32_t> streamStrides_; // +0x08 byte stride per vertex stream
    };

    static_assert(offsetof(VertexFormat, formatCode_) == 0x04, "VertexFormat::formatCode_ offset must be 0x04");
    static_assert(offsetof(VertexFormat, streamStrides_) == 0x08, "VertexFormat::streamStrides_ offset must be 0x08");
    static_assert(sizeof(VertexFormat) == 0x18, "VertexFormat size must be 0x18");
} // namespace gpg::gal
