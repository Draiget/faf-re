#pragma once

#include "gpg/gal/D3D9Utils.h"
#include "gpg/gal/StateCache_D3DRENDERSTATETYPE.hpp"
#include "gpg/gal/StateCache_D3DSAMPLERSTATETYPE.hpp"
#include "gpg/gal/StateCache_D3DTEXTURESTAGESTATETYPE.hpp"
#include "platform/Platform.h"

namespace gpg::gal
{
    /**
     * VFTABLE: 0x00D47F8C
     * COL:     0x00E53664
     */
    class StateManagerD3D9
    {
    public:
        using render_state_type = d3d9::RenderState;
        using sampler_state_type = d3d9::SamplerState;
        using texture_stage_state_type = d3d9::TextureStageState;

        /**
         * Address: 0x00948280 (FUN_00948280)
         *
         * What it does:
         * Binds one native D3D9 device pointer and initializes state-cache lanes.
         */
        explicit StateManagerD3D9(void* device);

        /**
         * Address: 0x00948340 (FUN_00948340)
         * Mangled: ?QueryInterface@StateManagerD3D9@gal@gpg@@UAGJABU_GUID@@PAPAX@Z
         *
         * What it does:
         * Supports COM-style interface negotiation for IUnknown and the
         * state-manager interface IID.
         */
        virtual HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** outObject);

        /**
         * Address: 0x009483A0 (FUN_009483A0)
         * Mangled: ?AddRef@StateManagerD3D9@gal@gpg@@UAGKXZ
         *
         * What it does:
         * Increments and returns the intrusive COM-style reference count.
         */
        virtual ULONG STDMETHODCALLTYPE AddRef();

        /**
         * Address: 0x009483C0 (FUN_009483C0)
         * Mangled: ?Release@StateManagerD3D9@gal@gpg@@UAGKXZ
         *
         * What it does:
         * Decrements reference count and destroys the object when it reaches 0.
         */
        virtual ULONG STDMETHODCALLTYPE Release();

        /**
         * Address: 0x009484D0 (FUN_009484D0)
         * Mangled: ?SetTransform@StateManagerD3D9@gal@gpg@@UAGJW4_D3DTRANSFORMSTATETYPE@@PBV_D3DMATRIX@@@Z
         *
         * What it does:
         * Forwards transform state updates directly to the D3D9 device.
         */
        virtual HRESULT STDMETHODCALLTYPE SetTransform(unsigned int transformState, const void* matrix);

        /**
         * Address: 0x009484F0 (FUN_009484F0)
         * Mangled: ?SetMaterial@StateManagerD3D9@gal@gpg@@UAGJPBV_D3DMATERIAL9@@@Z
         *
         * What it does:
         * Forwards material updates directly to the D3D9 device.
         */
        virtual HRESULT STDMETHODCALLTYPE SetMaterial(const void* material);

        /**
         * Address: 0x00948510 (FUN_00948510)
         * Mangled: ?SetLight@StateManagerD3D9@gal@gpg@@UAGJKPBV_D3DLIGHT9@@@Z
         *
         * What it does:
         * Forwards indexed light updates directly to the D3D9 device.
         */
        virtual HRESULT STDMETHODCALLTYPE SetLight(unsigned int lightIndex, const void* light);

        /**
         * Address: 0x00948530 (FUN_00948530)
         * Mangled: ?LightEnable@StateManagerD3D9@gal@gpg@@UAGJKH@Z
         *
         * What it does:
         * Forwards indexed light enable/disable state to the D3D9 device.
         */
        virtual HRESULT STDMETHODCALLTYPE LightEnable(unsigned int lightIndex, int enabled);

        /**
         * Address: 0x00949DA0 (FUN_00949DA0)
         * Mangled: ?SetRenderState@StateManagerD3D9@gal@gpg@@UAGJW4_D3DRENDERSTATETYPE@@K@Z
         *
         * What it does:
         * Caches a render-state value and forwards to D3D9 only when changed.
         */
        virtual HRESULT STDMETHODCALLTYPE SetRenderState(render_state_type state, unsigned int value);

        /**
         * Address: 0x00948420 (FUN_00948420)
         * Mangled: ?SetTexture@StateManagerD3D9@gal@gpg@@UAGJKPAVIDirect3DBaseTexture9@@@Z
         *
         * What it does:
         * Forwards stage-texture binding calls directly to the D3D9 device.
         */
        virtual HRESULT STDMETHODCALLTYPE SetTexture(unsigned int stageIndex, void* texture);

        /**
         * Address: 0x00949E50 (FUN_00949E50)
         * Mangled: ?SetTextureStageState@StateManagerD3D9@gal@gpg@@UAGJKW4_D3DTEXTURESTAGESTATETYPE@@K@Z
         *
         * What it does:
         * Caches per-stage texture-stage state values for stages [0,7].
         */
        virtual HRESULT STDMETHODCALLTYPE SetTextureStageState(
            unsigned int stageIndex,
            texture_stage_state_type state,
            unsigned int value
        );

        /**
         * Address: 0x00949DF0 (FUN_00949DF0)
         * Mangled: ?SetSamplerState@StateManagerD3D9@gal@gpg@@UAGJKW4_D3DSAMPLERSTATETYPE@@K@Z
         *
         * What it does:
         * Caches per-sampler state values for samplers [0,15].
         */
        virtual HRESULT STDMETHODCALLTYPE SetSamplerState(
            unsigned int samplerIndex,
            sampler_state_type state,
            unsigned int value
        );

        /**
         * Address: 0x00948550 (FUN_00948550)
         *
         * What it does:
         * Forwards N-patch tessellation mode directly to the backend device.
         */
        virtual HRESULT STDMETHODCALLTYPE SetNPatchMode(float nPatchSegments);

        /**
         * Address: 0x009484A0 (FUN_009484A0)
         * Mangled: ?SetFVF@StateManagerD3D9@gal@gpg@@UAGJK@Z
         *
         * What it does:
         * Caches active FVF value and forwards only on change.
         */
        virtual HRESULT STDMETHODCALLTYPE SetFVF(unsigned int fvf);

        /**
         * Address: 0x00948440 (FUN_00948440)
         * Mangled: ?SetVertexShader@StateManagerD3D9@gal@gpg@@UAGJPAVIDirect3DVertexShader9@@@Z
         *
         * What it does:
         * Caches active vertex-shader pointer and forwards only on change.
         */
        virtual HRESULT STDMETHODCALLTYPE SetVertexShader(void* vertexShader);

        /**
         * Address: 0x00948570 (FUN_00948570)
         *
         * What it does:
         * Forwards packed float4 constant uploads for the active vertex shader.
         */
        virtual HRESULT STDMETHODCALLTYPE SetVertexShaderConstantF(
            unsigned int startRegister,
            const float* constants,
            unsigned int vector4Count
        );

        /**
         * Address: 0x00948590 (FUN_00948590)
         *
         * What it does:
         * Forwards packed int4 constant uploads for the active vertex shader.
         */
        virtual HRESULT STDMETHODCALLTYPE SetVertexShaderConstantI(
            unsigned int startRegister,
            const int* constants,
            unsigned int vector4Count
        );

        /**
         * Address: 0x009485B0 (FUN_009485B0)
         *
         * What it does:
         * Forwards boolean constant uploads for the active vertex shader.
         */
        virtual HRESULT STDMETHODCALLTYPE SetVertexShaderConstantB(
            unsigned int startRegister,
            const int* constants,
            unsigned int boolCount
        );

        /**
         * Address: 0x00948470 (FUN_00948470)
         * Mangled: ?SetPixelShader@StateManagerD3D9@gal@gpg@@UAGJPAVIDirect3DPixelShader9@@@Z
         *
         * What it does:
         * Caches active pixel-shader pointer and forwards only on change.
         */
        virtual HRESULT STDMETHODCALLTYPE SetPixelShader(void* pixelShader);

        /**
         * Address: 0x009485D0 (FUN_009485D0)
         *
         * What it does:
         * Forwards packed float4 constant uploads for the active pixel shader.
         */
        virtual HRESULT STDMETHODCALLTYPE SetPixelShaderConstantF(
            unsigned int startRegister,
            const float* constants,
            unsigned int vector4Count
        );

        /**
         * Address: 0x009485F0 (FUN_009485F0)
         *
         * What it does:
         * Forwards packed int4 constant uploads for the active pixel shader.
         */
        virtual HRESULT STDMETHODCALLTYPE SetPixelShaderConstantI(
            unsigned int startRegister,
            const int* constants,
            unsigned int vector4Count
        );

        /**
         * Address: 0x00948610 (FUN_00948610)
         *
         * What it does:
         * Forwards boolean constant uploads for the active pixel shader.
         */
        virtual HRESULT STDMETHODCALLTYPE SetPixelShaderConstantB(
            unsigned int startRegister,
            const int* constants,
            unsigned int boolCount
        );

        /**
         * Address: 0x00949F60 (FUN_00949F60)
         * Mangled: ??_GStateManagerD3D9@gal@gpg@@UAEPAXI@Z
         *
         * What it does:
         * Tears down cache bookkeeping and vectorized cache members.
         */
        virtual ~StateManagerD3D9();

        /**
         * Address: 0x00948400 (FUN_00948400)
         * Mangled: ?SetRenderStateFlt@StateManagerD3D9@gal@gpg@@UAGJW4_D3DRENDERSTATETYPE@@M@Z
         *
         * What it does:
         * Bit-casts float payload and dispatches through SetRenderState.
         */
        virtual HRESULT STDMETHODCALLTYPE SetRenderStateFlt(render_state_type state, float value);

        /**
         * Address: 0x00948410 (FUN_00948410)
         * Mangled: ?SetTextureStageStateFlt@StateManagerD3D9@gal@gpg@@UAGJKW4_D3DTEXTURESTAGESTATETYPE@@M@Z
         *
         * What it does:
         * Bit-casts float payload and dispatches through SetTextureStageState.
         */
        virtual HRESULT STDMETHODCALLTYPE SetTextureStageStateFlt(
            unsigned int stageIndex,
            texture_stage_state_type state,
            float value
        );

    protected:
        volatile LONG uses_ = 0;                                              // +0x04
        void* device_ = nullptr;                                              // +0x08
        StateCache<d3d9::RenderState, unsigned int> renderStateCache_{};      // +0x0C
        StateCache<_D3DSAMPLERSTATETYPE, unsigned int> samplerStateCache_[16];         // +0x1C
        StateCache<_D3DTEXTURESTAGESTATETYPE, unsigned int> textureStageStateCache_[8]; // +0x11C
        void* activeVertexShader_ = nullptr;                                  // +0x19C
        void* activePixelShader_ = nullptr;                                   // +0x1A0
        unsigned int activeFvf_ = 0;                                          // +0x1A4
    };
}
