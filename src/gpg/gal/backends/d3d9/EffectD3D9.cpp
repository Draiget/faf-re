#include "gpg/gal/backends/d3d9/D3D9Private.h"

namespace gpg::gal
{

    /**
     * Address: 0x00942EE0 (FUN_00942EE0)
     *
     * What it does:
     * Starts from an empty context (0x0093FBE0) and a null effect, then
     * adopts `context` and `effect` through `SetEffect`.
     */
    EffectD3D9::EffectD3D9(const EffectContext& context, ID3DXEffect* const effect)
    {
        SetEffect(context, effect);
    }

    /**
     * Address: 0x00942DD0 (FUN_00942DD0)
     * Address: 0x00942EC0 (FUN_00942EC0, the scalar deleting destructor)
     *
     * What it does:
     * `Reset()`. The context then goes as a member (0x0093F950), and the
     * `Effect` base and the weak-this as bases.
     */
    EffectD3D9::~EffectD3D9()
    {
        Reset();
    }

    /**
     * Address: 0x00942D60 (FUN_00942D60)
     *
     * What it does:
     * Releases the D3DX effect and assigns an empty context over the current
     * one: a temporary `EffectContext` (0x0093FBE0), `operator=` (0x00942CF0),
     * and the temporary's destructor (0x0093F950).
     */
    void EffectD3D9::Reset()
    {
        SafeRelease(dxEffect_);
        effectContext_ = EffectContext();
    }

    /**
     * Address: 0x00942E50 (FUN_00942E50)
     *
     * What it does:
     * Resets, copies `context` (0x00942CF0), adopts `effect`, then empties the
     * copied source buffer -- the effect keeps the settings but not the bytes.
     */
    void EffectD3D9::SetEffect(const EffectContext& context, ID3DXEffect* const effect)
    {
        Reset();
        effectContext_ = context;
        dxEffect_ = effect;
        effectContext_.mSourceBuffer.Reset();
    }

    /**
     * Address: 0x009415B0 (FUN_009415B0)
     *
     * What it does:
     * Returns the embedded effect-context lane.
     */
    EffectContext* EffectD3D9::GetContext()
    {
        return &effectContext_;
    }

    /**
     * Address: 0x00942350 (FUN_00942350)
     *
     * What it does:
     * Returns the retained D3DX effect interface and throws when missing.
     */
    ID3DXEffect* EffectD3D9::GetDxEffect()
    {
        if (dxEffect_ == nullptr)
        {
            ThrowGalError("EffectD3D9.cpp", 137, "attempt to retrieve invalid effect");
        }

        return dxEffect_;
    }

    /**
     * Address: 0x00942920 (FUN_00942920)
     *
     * What it does:
     * Walks the valid techniques (`FindNextValidTechnique`) and appends a
     * wrapper for each -- `push_back` 0x00942860 on the temporary
     * `shared_ptr<EffectTechnique>`, whose constructor the binary inlines
     * around `shared_count(EffectTechniqueD3D9*)` 0x009417B0.
     */
    void EffectD3D9::GetTechniques(fa::vector<boost::shared_ptr<EffectTechnique>>& outTechniques)
    {
        if (dxEffect_ == nullptr)
        {
            ThrowGalError("EffectD3D9.cpp", 58, "invalid effect");
        }

        D3DXHANDLE technique = nullptr;
        HRESULT result = dxEffect_->FindNextValidTechnique(nullptr, &technique);
        while (SUCCEEDED(result) && technique != nullptr)
        {
            D3DXTECHNIQUE_DESC description{};
            result = dxEffect_->GetTechniqueDesc(technique, &description);
            if (FAILED(result))
            {
                ThrowGalErrorFromHresult("EffectD3D9.cpp", 66, result);
            }

            outTechniques.push_back(boost::shared_ptr<EffectTechnique>(
                new EffectTechniqueD3D9(description.Name, boost::SharedFromThis(*this), technique)
            ));
            result = dxEffect_->FindNextValidTechnique(technique, &technique);
        }
    }

    /**
     * Address: 0x00941D70 (FUN_00941D70)
     *
     * What it does:
     * Wraps the effect parameter called `variableName`, handing the wrapper
     * `shared_from_this()` (0x00941B90) as its effect; throws when the effect
     * or the parameter is missing.
     */
    boost::shared_ptr<EffectVariable> EffectD3D9::GetVariable(const char* const variableName)
    {
        if (dxEffect_ == nullptr)
        {
            ThrowGalError("EffectD3D9.cpp", 76, "invalid effect");
        }

        const D3DXHANDLE parameterHandle = dxEffect_->GetParameterByName(nullptr, variableName);
        if (parameterHandle == nullptr)
        {
            char message[512] = {};
            std::snprintf(
                message,
                sizeof(message),
                "invalid effect variable requested: %s",
                (variableName != nullptr) ? variableName : ""
            );
            ThrowGalError("EffectD3D9.cpp", 79, message);
        }

        return boost::shared_ptr<EffectVariable>(
            new EffectVariableD3D9(variableName, boost::SharedFromThis(*this), parameterHandle)
        );
    }

    /**
     * Address: 0x00941F60 (FUN_00941F60)
     *
     * What it does:
     * Wraps the technique called `techniqueName`, handing the wrapper
     * `shared_from_this()` as its effect; throws when the effect or the
     * technique is missing.
     */
    boost::shared_ptr<EffectTechnique> EffectD3D9::GetTechnique(const char* const techniqueName)
    {
        if (dxEffect_ == nullptr)
        {
            ThrowGalError("EffectD3D9.cpp", 86, "invalid effect");
        }

        const D3DXHANDLE techniqueHandle = dxEffect_->GetTechniqueByName(techniqueName);
        if (techniqueHandle == nullptr)
        {
            char message[512] = {};
            std::snprintf(
                message,
                sizeof(message),
                "invalid effect technique requested: %s",
                (techniqueName != nullptr) ? techniqueName : ""
            );
            ThrowGalError("EffectD3D9.cpp", 89, message);
        }

        return boost::shared_ptr<EffectTechnique>(
            new EffectTechniqueD3D9(techniqueName, boost::SharedFromThis(*this), techniqueHandle)
        );
    }

    /**
     * Address: 0x00942150 (FUN_00942150)
     *
     * What it does:
     * Rebinds the effect state manager from current pipeline state and forwards reset notification to D3DX.
     */
    void EffectD3D9::OnReset()
    {
        if (dxEffect_ == nullptr)
        {
            ThrowGalError("EffectD3D9.cpp", 96, "invalid effect");
        }

        const boost::shared_ptr<PipelineState> pipelineState = Device::GetInstance()->GetPipelineState();

        StateManagerD3D9* const stateManager = static_cast<PipelineStateD3D9*>(pipelineState.get())->GetStateManager();
        static_cast<void>(dxEffect_->SetStateManager(stateManager));
        static_cast<void>(dxEffect_->OnResetDevice());
    }

    /**
     * Address: 0x00942290 (FUN_00942290)
     *
     * What it does:
     * Forwards device-lost notification to the retained D3DX effect.
     */
    void EffectD3D9::OnLost()
    {
        if (dxEffect_ == nullptr)
        {
            ThrowGalError("EffectD3D9.cpp", 108, "invalid effect");
        }

        static_cast<void>(dxEffect_->OnLostDevice());
    }
}

