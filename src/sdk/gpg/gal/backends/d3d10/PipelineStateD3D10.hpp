#pragma once

#include <cstddef>
#include <cstdint>

#include <d3d10.h>

namespace gpg::gal
{
    /**
     * VFTABLE: 0x00D436F8
     * COL:     0x00E510FC
     */
    class PipelineStateD3D10
    {
    public:
        /**
         * Address: 0x00902CA0 (FUN_00902CA0)
         *
         * ID3D10Device *
         *
         * What it does:
         * Initializes one pipeline-state bundle from a native D3D10 device and
         * builds both recovered startup state packs.
         */
        explicit PipelineStateD3D10(ID3D10Device* device);

        /**
         * Address: 0x009024F0 (FUN_009024F0)
         *
         * What it does:
         * Creates the primary rasterizer/depth-stencil/blend/sampler state pack.
         */
        void CreateState1();

        /**
         * Address: 0x00902940 (FUN_00902940)
         *
         * What it does:
         * Creates the secondary rasterizer/depth-stencil/blend state pack.
         */
        void CreateState2();

        /**
         * Address: 0x00902250 (FUN_00902250)
         *
         * What it does:
         * Applies the primary recovered pipeline-state pack onto the native
         * D3D10 device.
         */
        void SetDeviceState();

        /**
         * Address: 0x009024D0 (FUN_009024D0)
         *
         * What it does:
         * Owns the scalar-deleting destructor thunk and releases retained
         * D3D10 pipeline-state COM handles.
         */
        virtual ~PipelineStateD3D10();

    public:
        ID3D10Device* device_ = nullptr;                         // +0x04
        std::uint32_t samplerFilterToken_ = 15U;                // +0x08
        ID3D10RasterizerState* rasterizerState1_ = nullptr;     // +0x0C
        ID3D10DepthStencilState* depthStencilState1_ = nullptr; // +0x10
        ID3D10BlendState* blendState1_ = nullptr;               // +0x14
        ID3D10SamplerState* samplerState1_ = nullptr;           // +0x18
        ID3D10RasterizerState* rasterizerState2_ = nullptr;     // +0x1C
        ID3D10DepthStencilState* depthStencilState2_ = nullptr; // +0x20
        ID3D10BlendState* blendState2_ = nullptr;               // +0x24
    };

    static_assert(offsetof(PipelineStateD3D10, device_) == 0x04, "PipelineStateD3D10::device_ offset must be 0x04");
    static_assert(
        offsetof(PipelineStateD3D10, samplerFilterToken_) == 0x08,
        "PipelineStateD3D10::samplerFilterToken_ offset must be 0x08"
    );
    static_assert(
        offsetof(PipelineStateD3D10, rasterizerState1_) == 0x0C,
        "PipelineStateD3D10::rasterizerState1_ offset must be 0x0C"
    );
    static_assert(
        offsetof(PipelineStateD3D10, depthStencilState1_) == 0x10,
        "PipelineStateD3D10::depthStencilState1_ offset must be 0x10"
    );
    static_assert(
        offsetof(PipelineStateD3D10, blendState1_) == 0x14,
        "PipelineStateD3D10::blendState1_ offset must be 0x14"
    );
    static_assert(
        offsetof(PipelineStateD3D10, samplerState1_) == 0x18,
        "PipelineStateD3D10::samplerState1_ offset must be 0x18"
    );
    static_assert(
        offsetof(PipelineStateD3D10, rasterizerState2_) == 0x1C,
        "PipelineStateD3D10::rasterizerState2_ offset must be 0x1C"
    );
    static_assert(
        offsetof(PipelineStateD3D10, depthStencilState2_) == 0x20,
        "PipelineStateD3D10::depthStencilState2_ offset must be 0x20"
    );
    static_assert(
        offsetof(PipelineStateD3D10, blendState2_) == 0x24,
        "PipelineStateD3D10::blendState2_ offset must be 0x24"
    );
    static_assert(sizeof(PipelineStateD3D10) == 0x28, "PipelineStateD3D10 size must be 0x28");
}
