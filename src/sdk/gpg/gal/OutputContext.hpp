#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "gpg/gal/CubeRenderTarget.hpp"
#include "gpg/gal/DepthStencilTarget.hpp"
#include "gpg/gal/RenderTarget.hpp"

namespace gpg::gal
{
    /**
     * VFTABLE: 0x00D42180
     * COL:     0x00E5EB7C
     *
     * Where the device draws: either a 2D colour target (`surface`) or one face
     * of a cube target (`cubeTarget` + `face`), plus the depth/stencil target
     * that goes with it. `Device::ClearTarget` binds one; each device head owns
     * one built around its back buffer.
     */
    class OutputContext
    {
    public:
        /**
         * Address: 0x008E77B0 (FUN_008E77B0, gpg::gal::OutputContextInit)
         *
         * What it does:
         * Initializes one output context with empty target handles, leaving
         * `face` uninitialized.
         */
        OutputContext();

        /**
         * Address: 0x008E77D0 (FUN_008E77D0)
         *
         * What it does:
         * Binds a 2D colour target and its depth/stencil target; the cube
         * handle stays empty. Both handles arrive by value (`ret 0x10`).
         */
        OutputContext(boost::shared_ptr<RenderTarget> surface, boost::shared_ptr<DepthStencilTarget> depthStencil);

        /**
         * Address: 0x008E78C0 (FUN_008E78C0)
         *
         * What it does:
         * Binds one face of a cube target and its depth/stencil target; the 2D
         * surface handle stays empty. `ret 0x14`: two handles and the face.
         */
        OutputContext(
            boost::shared_ptr<CubeRenderTarget> cubeTarget,
            std::int32_t face,
            boost::shared_ptr<DepthStencilTarget> depthStencil
        );

        /**
         * Address: 0x00430160 (FUN_00430160)
         *
         * What it does:
         * Copies one output context, retaining every target handle.
         */
        OutputContext(const OutputContext& other);

        /**
         * Address: 0x008E76D0 (FUN_008E76D0, gpg::gal::OutputContext::~OutputContext)
         * Address: 0x008E8250 (FUN_008E8250)
         *
         * What it does:
         * Releases the three target handles; 0x008E8250 is the scalar/vector
         * deleting destructor.
         */
        virtual ~OutputContext();

        OutputContext& operator=(const OutputContext&) = default;

        boost::shared_ptr<CubeRenderTarget> cubeTarget;     // +0x04
        std::int32_t face;                                  // +0x0C
        boost::shared_ptr<RenderTarget> surface;            // +0x10
        boost::shared_ptr<DepthStencilTarget> depthStencil; // +0x18
    };

    static_assert(offsetof(OutputContext, cubeTarget) == 0x04, "OutputContext::cubeTarget offset must be 0x04");
    static_assert(offsetof(OutputContext, face) == 0x0C, "OutputContext::face offset must be 0x0C");
    static_assert(offsetof(OutputContext, surface) == 0x10, "OutputContext::surface offset must be 0x10");
    static_assert(offsetof(OutputContext, depthStencil) == 0x18, "OutputContext::depthStencil offset must be 0x18");
    static_assert(sizeof(OutputContext) == 0x20, "OutputContext size must be 0x20");
}
