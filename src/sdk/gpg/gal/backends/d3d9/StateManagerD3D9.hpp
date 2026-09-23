#pragma once

#include <cstddef>

#include <d3dx9effect.h>

#include "gpg/gal/StateCache.h"
#include "platform/Platform.h"

namespace gpg::gal
{
    /**
     * VFTABLE: 0x00D47F8C
     * COL:     0x00E53664
     *
     * The state manager every D3DX effect is given (`SetStateManager`, slot
     * 71): D3DX routes each state an effect pass sets through it, and it drops
     * the ones the device already holds.
     */
    class StateManagerD3D9 : public ID3DXEffectStateManager
    {
    public:
        /**
         * Address: 0x00948280 (FUN_00948280)
         *
         * What it does:
         * Binds one native D3D9 device pointer and initializes state-cache lanes.
         */
        explicit StateManagerD3D9(IDirect3DDevice9* device);

        /**
         * Address: 0x00948340 (FUN_00948340)
         * Mangled: ?QueryInterface@StateManagerD3D9@gal@gpg@@UAGJABU_GUID@@PAPAX@Z
         *
         * What it does:
         * Supports COM-style interface negotiation for IUnknown and the
         * state-manager interface IID.
         */
        HRESULT STDMETHODCALLTYPE QueryInterface(REFIID riid, void** outObject) override;

        /**
         * Address: 0x009483A0 (FUN_009483A0)
         * Mangled: ?AddRef@StateManagerD3D9@gal@gpg@@UAGKXZ
         *
         * What it does:
         * Increments and returns the intrusive COM-style reference count.
         */
        ULONG STDMETHODCALLTYPE AddRef() override;

        /**
         * Address: 0x009483C0 (FUN_009483C0)
         * Mangled: ?Release@StateManagerD3D9@gal@gpg@@UAGKXZ
         *
         * What it does:
         * Decrements reference count and destroys the object when it reaches 0.
         */
        ULONG STDMETHODCALLTYPE Release() override;

        /**
         * Address: 0x009484D0 (FUN_009484D0)
         * Mangled: ?SetTransform@StateManagerD3D9@gal@gpg@@UAGJW4_D3DTRANSFORMSTATETYPE@@PBV_D3DMATRIX@@@Z
         *
         * What it does:
         * Forwards transform state updates directly to the D3D9 device.
         */
        HRESULT STDMETHODCALLTYPE SetTransform(D3DTRANSFORMSTATETYPE state, const D3DMATRIX* matrix) override;

        /**
         * Address: 0x009484F0 (FUN_009484F0)
         * Mangled: ?SetMaterial@StateManagerD3D9@gal@gpg@@UAGJPBV_D3DMATERIAL9@@@Z
         *
         * What it does:
         * Forwards material updates directly to the D3D9 device.
         */
        HRESULT STDMETHODCALLTYPE SetMaterial(const D3DMATERIAL9* material) override;

        /**
         * Address: 0x00948510 (FUN_00948510)
         * Mangled: ?SetLight@StateManagerD3D9@gal@gpg@@UAGJKPBV_D3DLIGHT9@@@Z
         *
         * What it does:
         * Forwards indexed light updates directly to the D3D9 device.
         */
        HRESULT STDMETHODCALLTYPE SetLight(DWORD index, const D3DLIGHT9* light) override;

        /**
         * Address: 0x00948530 (FUN_00948530)
         * Mangled: ?LightEnable@StateManagerD3D9@gal@gpg@@UAGJKH@Z
         *
         * What it does:
         * Forwards indexed light enable/disable state to the D3D9 device.
         */
        HRESULT STDMETHODCALLTYPE LightEnable(DWORD index, BOOL enable) override;

        /**
         * Address: 0x00949DA0 (FUN_00949DA0)
         * Mangled: ?SetRenderState@StateManagerD3D9@gal@gpg@@UAGJW4_D3DRENDERSTATETYPE@@K@Z
         *
         * What it does:
         * Caches a render-state value and forwards to D3D9 only when changed.
         */
        HRESULT STDMETHODCALLTYPE SetRenderState(D3DRENDERSTATETYPE state, DWORD value) override;

        /**
         * Address: 0x00948420 (FUN_00948420)
         * Mangled: ?SetTexture@StateManagerD3D9@gal@gpg@@UAGJKPAVIDirect3DBaseTexture9@@@Z
         *
         * What it does:
         * Forwards stage-texture binding calls directly to the D3D9 device.
         */
        HRESULT STDMETHODCALLTYPE SetTexture(DWORD stage, IDirect3DBaseTexture9* texture) override;

        /**
         * Address: 0x00949E50 (FUN_00949E50)
         * Mangled: ?SetTextureStageState@StateManagerD3D9@gal@gpg@@UAGJKW4_D3DTEXTURESTAGESTATETYPE@@K@Z
         *
         * What it does:
         * Caches per-stage texture-stage state values for stages [0,7].
         */
        HRESULT STDMETHODCALLTYPE SetTextureStageState(DWORD stage, D3DTEXTURESTAGESTATETYPE type, DWORD value) override;

        /**
         * Address: 0x00949DF0 (FUN_00949DF0)
         * Mangled: ?SetSamplerState@StateManagerD3D9@gal@gpg@@UAGJKW4_D3DSAMPLERSTATETYPE@@K@Z
         *
         * What it does:
         * Caches per-sampler state values for samplers [0,15].
         */
        HRESULT STDMETHODCALLTYPE SetSamplerState(DWORD sampler, D3DSAMPLERSTATETYPE type, DWORD value) override;

        /**
         * Address: 0x00948550 (FUN_00948550)
         *
         * What it does:
         * Forwards N-patch tessellation mode directly to the backend device.
         */
        HRESULT STDMETHODCALLTYPE SetNPatchMode(FLOAT numSegments) override;

        /**
         * Address: 0x009484A0 (FUN_009484A0)
         * Mangled: ?SetFVF@StateManagerD3D9@gal@gpg@@UAGJK@Z
         *
         * What it does:
         * Caches active FVF value and forwards only on change.
         */
        HRESULT STDMETHODCALLTYPE SetFVF(DWORD fvf) override;

        /**
         * Address: 0x00948440 (FUN_00948440)
         * Mangled: ?SetVertexShader@StateManagerD3D9@gal@gpg@@UAGJPAVIDirect3DVertexShader9@@@Z
         *
         * What it does:
         * Caches active vertex-shader pointer and forwards only on change.
         */
        HRESULT STDMETHODCALLTYPE SetVertexShader(IDirect3DVertexShader9* shader) override;

        /**
         * Address: 0x00948570 (FUN_00948570)
         *
         * What it does:
         * Forwards packed float4 constant uploads for the active vertex shader.
         */
        HRESULT STDMETHODCALLTYPE SetVertexShaderConstantF(
            UINT registerIndex, const FLOAT* constantData, UINT registerCount
        ) override;

        /**
         * Address: 0x00948590 (FUN_00948590)
         *
         * What it does:
         * Forwards packed int4 constant uploads for the active vertex shader.
         */
        HRESULT STDMETHODCALLTYPE SetVertexShaderConstantI(
            UINT registerIndex, const INT* constantData, UINT registerCount
        ) override;

        /**
         * Address: 0x009485B0 (FUN_009485B0)
         *
         * What it does:
         * Forwards boolean constant uploads for the active vertex shader.
         */
        HRESULT STDMETHODCALLTYPE SetVertexShaderConstantB(
            UINT registerIndex, const BOOL* constantData, UINT registerCount
        ) override;

        /**
         * Address: 0x00948470 (FUN_00948470)
         * Mangled: ?SetPixelShader@StateManagerD3D9@gal@gpg@@UAGJPAVIDirect3DPixelShader9@@@Z
         *
         * What it does:
         * Caches active pixel-shader pointer and forwards only on change.
         */
        HRESULT STDMETHODCALLTYPE SetPixelShader(IDirect3DPixelShader9* shader) override;

        /**
         * Address: 0x009485D0 (FUN_009485D0)
         *
         * What it does:
         * Forwards packed float4 constant uploads for the active pixel shader.
         */
        HRESULT STDMETHODCALLTYPE SetPixelShaderConstantF(
            UINT registerIndex, const FLOAT* constantData, UINT registerCount
        ) override;

        /**
         * Address: 0x009485F0 (FUN_009485F0)
         *
         * What it does:
         * Forwards packed int4 constant uploads for the active pixel shader.
         */
        HRESULT STDMETHODCALLTYPE SetPixelShaderConstantI(
            UINT registerIndex, const INT* constantData, UINT registerCount
        ) override;

        /**
         * Address: 0x00948610 (FUN_00948610)
         *
         * What it does:
         * Forwards boolean constant uploads for the active pixel shader.
         */
        HRESULT STDMETHODCALLTYPE SetPixelShaderConstantB(
            UINT registerIndex, const BOOL* constantData, UINT registerCount
        ) override;

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
        virtual HRESULT STDMETHODCALLTYPE SetRenderStateFlt(D3DRENDERSTATETYPE state, float value);

        /**
         * Address: 0x00948410 (FUN_00948410)
         * Mangled: ?SetTextureStageStateFlt@StateManagerD3D9@gal@gpg@@UAGJKW4_D3DTEXTURESTAGESTATETYPE@@M@Z
         *
         * What it does:
         * Bit-casts float payload and dispatches through SetTextureStageState.
         */
        virtual HRESULT STDMETHODCALLTYPE SetTextureStageStateFlt(DWORD stage, D3DTEXTURESTAGESTATETYPE type, float value);

    protected:
        volatile LONG uses_ = 0;                                                    // +0x04
        IDirect3DDevice9* device_ = nullptr;                                        // +0x08
        StateCache<_D3DRENDERSTATETYPE, unsigned int> renderStateCache_;            // +0x0C
        StateCache<_D3DSAMPLERSTATETYPE, unsigned int> samplerStateCache_[16];      // +0x1C
        StateCache<_D3DTEXTURESTAGESTATETYPE, unsigned int> textureStageStateCache_[8]; // +0x11C
        IDirect3DVertexShader9* activeVertexShader_ = nullptr;                      // +0x19C
        IDirect3DPixelShader9* activePixelShader_ = nullptr;                        // +0x1A0
        DWORD activeFvf_ = 0;                                                       // +0x1A4

        friend struct StateManagerD3D9LayoutVerifier;
    };

    struct StateManagerD3D9LayoutVerifier
    {
        static_assert(offsetof(StateManagerD3D9, device_) == 0x08, "StateManagerD3D9::device_ offset must be 0x08");
        static_assert(offsetof(StateManagerD3D9, renderStateCache_) == 0x0C, "StateManagerD3D9::renderStateCache_ offset must be 0x0C");
        static_assert(offsetof(StateManagerD3D9, samplerStateCache_) == 0x1C, "StateManagerD3D9::samplerStateCache_ offset must be 0x1C");
        static_assert(offsetof(StateManagerD3D9, textureStageStateCache_) == 0x11C, "StateManagerD3D9::textureStageStateCache_ offset must be 0x11C");
        static_assert(offsetof(StateManagerD3D9, activeVertexShader_) == 0x19C, "StateManagerD3D9::activeVertexShader_ offset must be 0x19C");
        static_assert(offsetof(StateManagerD3D9, activeFvf_) == 0x1A4, "StateManagerD3D9::activeFvf_ offset must be 0x1A4");
        static_assert(sizeof(StateManagerD3D9) == 0x1A8, "StateManagerD3D9 size must be 0x1A8");
    };
}
