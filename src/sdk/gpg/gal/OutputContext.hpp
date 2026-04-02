#pragma once

#include <cstdint>

#include "boost/shared_ptr.h"
#include "gpg/gal/CubeRenderTargetContext.hpp"
#include "gpg/gal/RenderTargetContext.hpp"
#include "gpg/gal/TextureContext.hpp"

namespace gpg::gal
{
    /**
     * VFTABLE: 0x00D42180
     * COL:     0x00E5EB7C
     */
    class OutputContext
    {
    public:
        using CubeTargetHandle = boost::shared_ptr<CubeRenderTargetContext>;
        using SurfaceHandle = boost::shared_ptr<RenderTargetContext>;
        using TextureHandle = boost::shared_ptr<TextureContext>;

        OutputContext();

        /**
         * Address: 0x00430160 (FUN_00430160)
         *
         * OutputContext const &
         *
         * What it does:
         * Copies one output-context payload and retains shared-handle ownership.
         */
        OutputContext(const OutputContext& other);

        /**
         * Address: 0x008E8250 (FUN_008E8250)
         *
         * What it does:
         * Owns the vector/scalar deleting-destructor thunk path for OutputContext.
         */
        virtual ~OutputContext();

        CubeTargetHandle cubeTarget;  // +0x04
        std::int32_t face;            // +0x0C
        SurfaceHandle surface;        // +0x10
        TextureHandle texture;        // +0x18
    };

    static_assert(sizeof(OutputContext) == 0x20, "OutputContext size must be 0x20");
}
