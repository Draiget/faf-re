#pragma once

#include <cstddef>
#include <cstdint>

namespace gpg::gal
{
    class StateManagerD3D9;

    /**
     * VFTABLE: 0x00D47F6C
     * COL:     0x00E5353C
     */
    class PipelineStateD3D9
    {
    public:
        /**
         * Address: 0x00949F80 (FUN_00949F80)
         *
         * What it does:
         * Initializes pipeline-state defaults and constructs one retained D3D9
         * state-manager instance for the supplied native device.
         */
        explicit PipelineStateD3D9(void* nativeDevice);

        /**
         * Address: 0x00946F10 (FUN_00946F10)
         *
         * What it does:
         * Owns the scalar-deleting destructor thunk for D3D9 pipeline-state wrappers.
         */
        virtual ~PipelineStateD3D9();

        /**
         * Address: 0x00946310 (FUN_00946310)
         *
         * What it does:
         * Returns the retained D3D9 effect state-manager interface pointer.
         */
        StateManagerD3D9* GetStateManager();

        /**
         * Address: 0x009460A0 (FUN_009460A0)
         *
         * bool,void const *,float,float,int
         *
         * What it does:
         * Applies fog enable/disable state and projection-fog payload lanes on the
         * retained state manager.
         */
        void SetFogState(
            bool enable,
            const void* projection,
            float fogStart,
            float fogEnd,
            int fogColor
        );

        /**
         * Address: 0x009461C0 (FUN_009461C0)
         *
         * What it does:
         * Selects and applies recovered D3D9 fill mode for wireframe toggle lanes.
         */
        int SetWireframeState(bool enabled);

        /**
         * Address: 0x009461F0 (FUN_009461F0)
         *
         * What it does:
         * Rebuilds and applies retained color-write mask from two recovered toggle
         * lanes.
         */
        int SetColorWriteState(bool arg1, bool arg2);

        /**
         * Address: 0x00946260 (FUN_00946260)
         *
         * What it does:
         * Reapplies retained technique begin-state render-state defaults.
         */
        void BeginTechnique();

        /**
         * Address: 0x00946300 (FUN_00946300)
         *
         * What it does:
         * Preserves the binary no-op end-technique lane.
         */
        void EndTechnique();

        /**
         * Address: 0x00946240 (FUN_00946240)
         *
         * What it does:
         * Clears all 16 texture stages through the retained D3D9 state manager.
         */
        int ClearTextures();

        /**
         * Address: 0x00945730 (FUN_00945730)
         *
         * What it does:
         * Reapplies the baseline D3D9 render/sampler/texture-stage state matrix.
         */
        int InitState();

    public:
        void* stateManager_ = nullptr;          // +0x04
        std::uint32_t colorWriteEnable_ = 0x0F; // +0x08
    };

    static_assert(offsetof(PipelineStateD3D9, stateManager_) == 0x04, "PipelineStateD3D9::stateManager_ offset must be 0x04");
    static_assert(offsetof(PipelineStateD3D9, colorWriteEnable_) == 0x08, "PipelineStateD3D9::colorWriteEnable_ offset must be 0x08");
    static_assert(sizeof(PipelineStateD3D9) == 0x0C, "PipelineStateD3D9 size must be 0x0C");
}
