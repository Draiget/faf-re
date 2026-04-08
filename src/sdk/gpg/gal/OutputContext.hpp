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

        /**
         * Address: 0x008E77B0 (FUN_008E77B0, gpg::gal::OutputContextInit)
         *
         * What it does:
         * Initializes one output-context payload with null shared-handle lanes
         * while leaving the scalar `face` lane uninitialized.
         */
        OutputContext();

        /**
         * Address: 0x008E77D0 (FUN_008E77D0)
         *
         * SurfaceHandle,TextureHandle
         *
         * What it does:
         * Initializes one output-context payload, clears cube-target handles,
         * and retains caller-provided surface/texture handle ownership.
         */
        OutputContext(SurfaceHandle surfaceHandle, TextureHandle textureHandle);

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
         * Address: 0x008E76D0 (FUN_008E76D0, gpg::gal::OutputContext::~OutputContext)
         * Address: 0x008E8250 (FUN_008E8250)
         *
         * What it does:
         * Releases retained texture/surface/cube-target shared-handle lanes and
         * owns the scalar/vector deleting-destructor thunk dispatch path.
         */
        virtual ~OutputContext();

        CubeTargetHandle cubeTarget;  // +0x04
        std::int32_t face;            // +0x0C
        SurfaceHandle surface;        // +0x10
        TextureHandle texture;        // +0x18
    };

    static_assert(sizeof(OutputContext) == 0x20, "OutputContext size must be 0x20");
}
