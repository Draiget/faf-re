#include "gpg/gal/backends/d3d9/D3D9Private.h"

namespace gpg::gal
{

    /**
     * Address: 0x009460A0 (FUN_009460A0)
     *
     * bool,void const *,float,float,int
     *
     * What it does:
     * Applies fog enable/disable state and projection-fog payload lanes on the
     * retained state manager.
     */
    void PipelineStateD3D9::SetFogState(
        const bool enable,
        const Matrix* const projection,
        const float fogStart,
        const float fogEnd,
        const int fogColor
    )
    {
        StateManagerD3D9* const stateManager = GetStateManager();
        if (enable)
        {
            static_cast<void>(stateManager->SetTransform(D3DTS_PROJECTION, reinterpret_cast<const D3DMATRIX*>(projection)));
            static_cast<void>(stateManager->SetRenderState(
                D3DRS_FOGENABLE,
                1U
            ));
            static_cast<void>(stateManager->SetRenderState(
                D3DRS_RANGEFOGENABLE,
                1U
            ));
            static_cast<void>(stateManager->SetRenderState(
                D3DRS_FOGCOLOR,
                static_cast<unsigned int>(fogColor)
            ));
            static_cast<void>(stateManager->SetRenderState(
                D3DRS_FOGTABLEMODE,
                D3DFOG_LINEAR
            ));
            static_cast<void>(stateManager->SetRenderState(
                D3DRS_FOGSTART,
                std::bit_cast<unsigned int>(fogStart)
            ));
            static_cast<void>(stateManager->SetRenderState(
                D3DRS_FOGEND,
                std::bit_cast<unsigned int>(fogEnd)
            ));
            return;
        }

        static_cast<void>(stateManager->SetRenderState(
            D3DRS_FOGENABLE,
            0U
        ));

        D3DMATRIX projectionIdentity = {};
        projectionIdentity._11 = 1.0f;
        projectionIdentity._22 = 1.0f;
        projectionIdentity._33 = 1.0f;
        projectionIdentity._44 = 1.0f;
        static_cast<void>(stateManager->SetTransform(D3DTS_PROJECTION, &projectionIdentity));
    }

    /**
     * Address: 0x009461C0 (FUN_009461C0)
     *
     * What it does:
     * Selects and applies recovered D3D9 fill mode for wireframe toggle lanes.
     */
    int PipelineStateD3D9::SetWireframeState(const bool enabled)
    {
        const unsigned int fillMode = enabled ? D3DFILL_WIREFRAME : D3DFILL_SOLID;
        return GetStateManager()->SetRenderState(
            D3DRS_FILLMODE,
            fillMode
        );
    }

    /**
     * Address: 0x009461F0 (FUN_009461F0)
     *
     * What it does:
     * Rebuilds and applies retained color-write mask from two recovered toggle
     * lanes.
     */
    int PipelineStateD3D9::SetColorWriteState(const bool arg1, const bool arg2)
    {
        if (arg1)
        {
            colorWriteEnable_ = arg2 ? 0x0FU : 0x07U;
        }
        else
        {
            colorWriteEnable_ = arg2 ? 0x08U : 0x0FU;
        }

        return GetStateManager()->SetRenderState(
            D3DRS_COLORWRITEENABLE,
            colorWriteEnable_
        );
    }

    /**
     * Address: 0x00946260 (FUN_00946260)
     *
     * What it does:
     * Reapplies retained technique begin-state render-state defaults.
     */
    void PipelineStateD3D9::BeginTechnique()
    {
        StateManagerD3D9* const stateManager = GetStateManager();
        static_cast<void>(stateManager->SetRenderState(
            D3DRS_COLORWRITEENABLE,
            colorWriteEnable_
        ));
        static_cast<void>(stateManager->SetRenderState(
            D3DRS_ALPHABLENDENABLE,
            0U
        ));
        static_cast<void>(stateManager->SetRenderState(
            D3DRS_ALPHATESTENABLE,
            0U
        ));
        static_cast<void>(stateManager->SetRenderState(
            D3DRS_STENCILENABLE,
            0U
        ));
        static_cast<void>(stateManager->SetRenderState(
            D3DRS_ZENABLE,
            1U
        ));
        static_cast<void>(stateManager->SetRenderState(
            D3DRS_ZFUNC,
            D3DCMP_LESSEQUAL
        ));
        static_cast<void>(stateManager->SetRenderState(
            D3DRS_ZWRITEENABLE,
            1U
        ));
        static_cast<void>(stateManager->SetRenderState(
            D3DRS_DEPTHBIAS,
            0U
        ));
        static_cast<void>(stateManager->SetRenderState(
            D3DRS_CULLMODE,
            D3DCULL_NONE
        ));
    }

    /**
     * Address: 0x00946300 (FUN_00946300)
     *
     * What it does:
     * Preserves the binary no-op end-technique lane.
     */
    void PipelineStateD3D9::EndTechnique() {}

    /**
     * Address: 0x00946240 (FUN_00946240)
     *
     * What it does:
     * Clears all 16 texture stages through the retained D3D9 state manager.
     */
    int PipelineStateD3D9::ClearTextures()
    {
        StateManagerD3D9* const stateManager = GetStateManager();
        int result = 0;
        for (unsigned int stageIndex = 0; stageIndex < 16U; ++stageIndex)
        {
            result = stateManager->SetTexture(stageIndex, nullptr);
        }
        return result;
    }

    /**
     * Address: 0x00946310 (FUN_00946310)
     *
     * What it does:
     * Returns the retained D3D9 state-manager interface pointer.
     */
    StateManagerD3D9* PipelineStateD3D9::GetStateManager()
    {
        return stateManager_;
    }

    /**
     * Address: 0x00949F80 (FUN_00949F80)
     *
     * What it does:
     * Initializes pipeline-state defaults and binds one state-manager instance
     * to the supplied native D3D9 device.
     */
    PipelineStateD3D9::PipelineStateD3D9(IDirect3DDevice9* const nativeDevice)
    {
        stateManager_ = nullptr;
        colorWriteEnable_ = 0x0FU;

        stateManager_ = new StateManagerD3D9(nativeDevice);
        if (stateManager_ != nullptr)
        {
            stateManager_->AddRef();
        }
    }

    /**
     * Address: 0x00945730 (FUN_00945730)
     *
     * What it does:
     * Reapplies baseline D3D9 render/sampler/texture-stage state defaults.
     */
    int PipelineStateD3D9::InitState()
    {
        auto* const stateManager = GetStateManager();
        if (stateManager == nullptr)
        {
            return -1;
        }

        const auto setRenderState = [stateManager](const unsigned int state, const unsigned int value) {
            static_cast<void>(stateManager->SetRenderState(static_cast<D3DRENDERSTATETYPE>(state), value));
        };
        const auto setRenderStateFlt = [stateManager](const unsigned int state, const float value) {
            static_cast<void>(stateManager->SetRenderStateFlt(static_cast<D3DRENDERSTATETYPE>(state), value));
        };
        const auto setSamplerState = [stateManager](
                                         const unsigned int sampler,
                                         const unsigned int state,
                                         const unsigned int value
                                     ) {
            static_cast<void>(
                stateManager->SetSamplerState(sampler, static_cast<D3DSAMPLERSTATETYPE>(state), value)
            );
        };
        const auto setTextureStageState = [stateManager](
                                               const unsigned int stage,
                                               const unsigned int state,
                                               const unsigned int value
                                           ) {
            return stateManager->SetTextureStageState(
                stage,
                static_cast<D3DTEXTURESTAGESTATETYPE>(state),
                value
            );
        };
        const auto setTextureStageStateFlt = [stateManager](
                                                  const unsigned int stage,
                                                  const unsigned int state,
                                                  const float value
                                              ) {
            static_cast<void>(
                stateManager->SetTextureStageStateFlt(
                    stage,
                    static_cast<D3DTEXTURESTAGESTATETYPE>(state),
                    value
                )
            );
        };

        static constexpr struct RenderStateInit final
        {
            unsigned int state = 0U;
            unsigned int value = 0U;
        } kRenderStates[] = {
            {7U, 1U},
            {8U, 3U},
            {9U, 2U},
            {14U, 1U},
            {15U, 0U},
            {16U, 1U},
            {19U, 2U},
            {20U, 1U},
            {22U, 1U},
            {23U, 8U},
            {24U, 0U},
            {25U, 8U},
            {26U, 0U},
            {27U, 0U},
            {28U, 0U},
            {29U, 0U},
            {34U, 0U},
            {35U, 0U},
            {48U, 0U},
            {52U, 0U},
            {53U, 1U},
            {54U, 1U},
            {55U, 1U},
            {56U, 8U},
            {57U, 0U},
            {58U, 0xFFFFFFFFU},
            {59U, 0xFFFFFFFFU},
            {60U, 0U},
            {128U, 0U},
            {129U, 0U},
            {130U, 0U},
            {131U, 0U},
            {132U, 0U},
            {133U, 0U},
            {134U, 0U},
            {135U, 0U},
            {136U, 1U},
            {137U, 1U},
            {139U, 0U},
            {140U, 0U},
            {141U, 1U},
            {142U, 0U},
            {143U, 1U},
            {145U, 1U},
            {146U, 2U},
            {147U, 0U},
            {148U, 0U},
            {151U, 0U},
            {152U, 0U},
            {156U, 0U},
            {157U, 0U},
            {161U, 1U},
            {162U, 0xFFFFFFFFU},
            {163U, 0U},
            {167U, 0U},
            {168U, 0x0FU},
            {171U, 1U},
            {172U, 3U},
            {173U, 1U},
            {174U, 0U},
            {176U, 0U},
            {184U, 0U},
            {185U, 0U},
            {186U, 1U},
            {187U, 1U},
            {188U, 1U},
            {189U, 8U},
            {190U, 0x0FU},
            {191U, 0x0FU},
            {192U, 0x0FU},
            {193U, 0xFFFFFFFFU},
            {194U, 0U},
            {198U, 0U},
            {199U, 0U},
            {200U, 0U},
            {201U, 0U},
            {202U, 0U},
            {203U, 0U},
            {204U, 0U},
            {205U, 0U},
            {206U, 0U},
            {207U, 2U},
            {208U, 1U},
            {209U, 1U},
        };

        static constexpr struct RenderStateFloatInit final
        {
            unsigned int state = 0U;
            float value = 0.0f;
        } kRenderStateFloats[] = {
            {36U, 0.0f},
            {37U, 1.0f},
            {38U, 1.0f},
            {154U, 1.0f},
            {155U, 1.0f},
            {158U, 1.0f},
            {159U, 0.0f},
            {160U, 0.0f},
            {166U, 64.0f},
            {170U, 0.0f},
            {175U, 0.0f},
            {178U, 1.0f},
            {179U, 1.0f},
            {180U, 1.0f},
            {181U, 1.0f},
            {182U, 1.0f},
            {183U, 1.0f},
            {195U, 0.0f},
        };

        for (const auto& state : kRenderStates)
        {
            setRenderState(state.state, state.value);
        }

        for (const auto& state : kRenderStateFloats)
        {
            setRenderStateFlt(state.state, state.value);
        }

        for (unsigned int sampler = 0U; sampler < 16U; ++sampler)
        {
            setSamplerState(sampler, 1U, 1U);
            setSamplerState(sampler, 2U, 1U);
            setSamplerState(sampler, 3U, 1U);
            setSamplerState(sampler, 4U, 0U);
            setSamplerState(sampler, 5U, 2U);
            setSamplerState(sampler, 6U, 2U);
            setSamplerState(sampler, 7U, 0U);
            setSamplerState(sampler, 8U, 0U);
            setSamplerState(sampler, 9U, 0U);
            setSamplerState(sampler, 10U, 1U);
            setSamplerState(sampler, 11U, 0U);
            setSamplerState(sampler, 12U, 0U);
            setSamplerState(sampler, 13U, 256U);
        }

        for (unsigned int stage = 0U; stage < 8U; ++stage)
        {
            static_cast<void>(setTextureStageState(stage, 1U, 1U));
            static_cast<void>(setTextureStageState(stage, 2U, 2U));
            static_cast<void>(setTextureStageState(stage, 3U, 1U));
            static_cast<void>(setTextureStageState(stage, 4U, 1U));
            static_cast<void>(setTextureStageState(stage, 5U, 2U));
            static_cast<void>(setTextureStageState(stage, 6U, 1U));
            setTextureStageStateFlt(stage, 7U, 0.0f);
            setTextureStageStateFlt(stage, 8U, 0.0f);
            setTextureStageStateFlt(stage, 9U, 0.0f);
            setTextureStageStateFlt(stage, 10U, 0.0f);
            static_cast<void>(setTextureStageState(stage, 11U, stage));
            setTextureStageStateFlt(stage, 22U, 0.0f);
            setTextureStageStateFlt(stage, 23U, 0.0f);
            static_cast<void>(setTextureStageState(stage, 24U, 0U));
            static_cast<void>(setTextureStageState(stage, 26U, 1U));
            static_cast<void>(setTextureStageState(stage, 27U, 1U));
            static_cast<void>(setTextureStageState(stage, 28U, 1U));
            static_cast<void>(setTextureStageState(stage, 32U, 0U));
        }

        static_cast<void>(setTextureStageState(0U, 1U, 4U));
        return setTextureStageState(0U, 4U, 2U);
    }

    /**
     * Address: 0x00946BE0 (FUN_00946BE0)
     * Address: 0x00946F10 (FUN_00946F10, slot 0: the scalar deleting destructor)
     *
     * What it does:
     * Releases the effect state manager, then the `PipelineState` base
     * destructor runs (inlined, 0x00946C27).
     */
    PipelineStateD3D9::~PipelineStateD3D9()
    {
        SafeRelease(stateManager_);
    }
}

