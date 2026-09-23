#pragma once

#include "boost/noncopyable.hpp"

namespace gpg::gal
{
    /**
     * VFTABLE: 0x00D436F0
     * COL:  0x00E510B0
     *
     * The backend's fixed-function and default render state. The interface
     * is only its destructor; `Device::GetPipelineState` (slot 8) hands out
     * the device's instance, and each backend keeps its own state objects
     * behind it.
     */
    class PipelineState : private boost::noncopyable
    {
    public:
        /**
         * Address: 0x00902240 (FUN_00902240)
         *
         * What it does:
         * Installs the abstract pipeline-state vtable.
         */
        PipelineState();

        /**
         * Address: 0x00902230 (FUN_00902230)
         * Slot: 0 (`_purecall` in the base's own table)
         *
         * What it does:
         * Reinstalls the abstract pipeline-state vtable.
         */
        virtual ~PipelineState() = 0;
    };

    static_assert(sizeof(PipelineState) == 0x04, "PipelineState size must be 0x04");
} // namespace gpg::gal
