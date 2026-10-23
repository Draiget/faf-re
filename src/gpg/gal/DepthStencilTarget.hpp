#pragma once

#include "boost/noncopyable.hpp"
#include "boost/shared_ptr.h"

namespace gpg::gal
{
    class DepthStencilTargetContext;

    /**
     * VFTABLE: 0x00D421B8
     * COL:  0x00E50470
     *
     * The backend-neutral depth/stencil target. `DepthStencilTargetD3D9`
     * (vtable 0x00D421C4) and `DepthStencilTargetD3D10` (0x00D487D0)
     * implement it; `OutputContext::depthStencil` holds one, and the shipped
     * symbols carry it as `boost::shared_ptr<DepthStencilTarget>`.
     */
    class DepthStencilTarget : private boost::noncopyable
    {
    public:
        /**
         * Address: 0x008E7EA0 (FUN_008E7EA0)
         *
         * What it does:
         * Installs the abstract depth-stencil-target vtable.
         */
        DepthStencilTarget();

        /**
         * Address: 0x008E7E90 (FUN_008E7E90)
         * Slot: 0 (`_purecall` in the base table, so the destructor is pure)
         *
         * What it does:
         * Reinstalls the abstract vtable. The out-of-line body is what the
         * derived constructors' unwind funclets call (0x00B58E33 for
         * `DepthStencilTargetD3D9`, 0x00B5E873 for `DepthStencilTargetD3D10`);
         * the derived destructors inline it.
         */
        virtual ~DepthStencilTarget() = 0;

        /**
         * Address: 0x0093F010 (FUN_0093F010)
         *
         * What it does:
         * Creates one depth/stencil target on the active device - slot 13
         * (`[vtbl+0x34]`) of `Device::GetInstance()`.
         */
        static boost::shared_ptr<DepthStencilTarget> Create(const DepthStencilTargetContext& context);

        /**
         * Slot: 1
         *
         * What it does:
         * Returns the creation descriptor the target was built from.
         */
        virtual DepthStencilTargetContext* GetContext() = 0;
    };

    static_assert(sizeof(DepthStencilTarget) == 0x04, "DepthStencilTarget size must be 0x04");
} // namespace gpg::gal
