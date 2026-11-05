#include "gpg/gal/backends/d3d9/D3D9Private.h"

namespace gpg::gal
{
namespace
{

        /**
         * The active backend device whenever any D3D9 body in this file runs.
         *
         * These bodies reach `Device::GetInstance()`, which is typed as the
         * abstract base. The methods they need (`GetPipelineState`,
         * `CreateVertexFormat`, ...) are declared only on `DeviceD3D9`, so the
         * call has to go through the backend type. This used to be done by
         * hand-indexing the vtable (`vtable[8]`, `vtable[14]`, ...), which was
         * doubly wrong: the base declares those slots as no-arg `purecallN()`
         * stubs, so the backend methods never actually override them - the
         * compiler appends them past the base's 50 slots and the stub still
         * sits at the indexed position. Dispatching `vtable[8]` therefore
         * called an empty `void purecall8()`: the output parameter was left
         * untouched, and because a `__thiscall` callee pops its own arguments,
         * the no-arg stub popped 0 bytes where the caller pushed 4 and the
         * debug CRT's `_RTC_CheckEsp` trapped on return.
         *
         * `Device::InitCursor` (Device.cpp) resolves the same problem the same
         * way. See the note on `Device::CreateEffect` for the one slot whose
         * signature was hoisted onto the base instead.
         */
        [[nodiscard]] DeviceD3D9& ActiveDeviceD3D9()
        {
            return *static_cast<DeviceD3D9*>(Device::GetInstance());
        }

        /**
         * The lock-and-check every `EffectTechniqueD3D9` entry point opens
         * with: the out-of-line `weak_ptr<EffectD3D9>::lock` emission (cited on
         * `boost::LockWeak`), then "attempt to use invalid effect" from the
         * caller's line when the effect is gone.
         */
        boost::shared_ptr<EffectD3D9> LockEffectOrThrow(
            const boost::weak_ptr<EffectD3D9>& weakEffect,
            const int line
        )
        {
            boost::shared_ptr<EffectD3D9> effect = boost::LockWeak(weakEffect);
            if (!effect)
            {
                ThrowGalError("EffectTechniqueD3D9.cpp", line, "attempt to use invalid effect");
            }

            return effect;
        }
}


    /**
     * Address: 0x008F3AC0 (FUN_008F3AC0, ??0EffectTechniqueD3D9@gal@gpg@@QAE@@Z)
     *
     * What it does:
     * Keeps `name`, a weak reference to `effect` and the technique handle;
     * throws "invalid effect specified" (EffectTechniqueD3D9.cpp:36) when the
     * effect has already expired. The name is taken as given: the binary
     * runs `strlen` on it without a null check.
     */
    EffectTechniqueD3D9::EffectTechniqueD3D9(
        const char* const name,
        const boost::shared_ptr<EffectD3D9> effect,
        const D3DXHANDLE handle
    )
        : name_(name),
          effect_(effect),
          handle_(handle)
    {
        if (effect_.expired())
        {
            ThrowGalError("EffectTechniqueD3D9.cpp", 36, "invalid effect specified");
        }
    }

    /**
     * Address: 0x008F3A20 (FUN_008F3A20, ??1EffectTechniqueD3D9@gal@gpg@@QAE@XZ)
     * Address: 0x008F3AA0 (FUN_008F3AA0, the scalar deleting destructor)
     *
     * What it does:
     * Nothing of its own. The weak effect reference and the name go as
     * members, then the `EffectTechnique` base; the handle and the begin/end
     * flag are left as they are.
     */
    EffectTechniqueD3D9::~EffectTechniqueD3D9() = default;

    /**
     * Address: 0x008F3850 (FUN_008F3850)
     *
     * What it does:
     * Returns the local technique-name string lane.
     */
    fa::string* EffectTechniqueD3D9::GetName()
    {
        return &name_;
    }

    /**
     * Address: 0x008F3C40 (FUN_008F3C40)
     *
     * What it does:
     * Validates begin/end state, binds this technique on the effect, then begins the technique pass chain.
     */
    int EffectTechniqueD3D9::BeginTechnique()
    {
        if (beginEndActive_)
        {
            ThrowGalError("EffectTechniqueD3D9.cpp", 50, "effect technique begin/end mismatch");
        }

        boost::shared_ptr<EffectD3D9> effect = LockEffectOrThrow(effect_, 53);
        ID3DXEffect* const dxEffect = effect->GetDxEffect();
        const HRESULT setTechniqueResult = dxEffect->SetTechnique(handle_);
        if (setTechniqueResult < 0)
        {
            ThrowGalErrorFromHresult("EffectTechniqueD3D9.cpp", 58, setTechniqueResult);
        }

        ActiveDeviceD3D9().BeginTechnique();

        unsigned int passCount = 0U;
        const HRESULT beginResult = dxEffect->Begin(&passCount, 1U);
        if (beginResult < 0)
        {
            ThrowGalErrorFromHresult("EffectTechniqueD3D9.cpp", 67, beginResult);
        }

        beginEndActive_ = true;
        return static_cast<int>(passCount);
    }

    /**
     * Address: 0x008F3EA0 (FUN_008F3EA0)
     *
     * What it does:
     * Validates begin/end state, ends the active technique, and clears local begin/end tracking.
     */
    void EffectTechniqueD3D9::EndTechnique()
    {
        if (!beginEndActive_)
        {
            ThrowGalError("EffectTechniqueD3D9.cpp", 76, "effect technique begin/end mismatch");
        }

        boost::shared_ptr<EffectD3D9> effect = LockEffectOrThrow(effect_, 79);
        const HRESULT result = effect->GetDxEffect()->End();
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectTechniqueD3D9.cpp", 84, result);
        }

        ActiveDeviceD3D9().EndTechnique();
        beginEndActive_ = false;
    }

    /**
     * Address: 0x008F4080 (FUN_008F4080)
     *
     * What it does:
     * Begins the selected pass on the active technique.
     */
    void EffectTechniqueD3D9::BeginPass(const int pass)
    {
        if (!beginEndActive_)
        {
            ThrowGalError("EffectTechniqueD3D9.cpp", 94, "effect technique begin/end mismatch");
        }

        boost::shared_ptr<EffectD3D9> effect = LockEffectOrThrow(effect_, 97);
        const HRESULT result = effect->GetDxEffect()->BeginPass(static_cast<unsigned int>(pass));
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectTechniqueD3D9.cpp", 102, result);
        }
        RecordStateChange(); // FAF instrumentation (gpg/gal/DrawStatistics.h); not in the binary.
    }

    /**
     * Address: 0x008F4260 (FUN_008F4260)
     *
     * What it does:
     * Ends the currently active pass on the technique.
     */
    void EffectTechniqueD3D9::EndPass()
    {
        if (!beginEndActive_)
        {
            ThrowGalError("EffectTechniqueD3D9.cpp", 107, "effect technique begin/end mismatch");
        }

        boost::shared_ptr<EffectD3D9> effect = LockEffectOrThrow(effect_, 110);
        const HRESULT result = effect->GetDxEffect()->EndPass();
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectTechniqueD3D9.cpp", 115, result);
        }
    }

    /**
     * FAF addition, not in the shipped binary.
     *
     * What it does:
     * Commits the effect parameters changed inside the active pass. D3DX only
     * applies parameters at `BeginPass`, so a caller that sets new values
     * between draws of one pass has to commit them before each draw. The line
     * numbers are 0: there is no original source line to cite.
     */
    void EffectTechniqueD3D9::CommitChanges()
    {
        if (!beginEndActive_)
        {
            ThrowGalError("EffectTechniqueD3D9.cpp", 0, "effect technique begin/end mismatch");
        }

        boost::shared_ptr<EffectD3D9> effect = LockEffectOrThrow(effect_, 0);
        const HRESULT result = effect->GetDxEffect()->CommitChanges();
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectTechniqueD3D9.cpp", 0, result);
        }
    }

    /**
     * Address: 0x008F4430 (FUN_008F4430)
     *
     * What it does:
     * Looks up and reads a bool annotation from the active technique.
     */
    bool EffectTechniqueD3D9::GetAnnotationBool(bool* const outValue, const fa::string& annotationName)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectOrThrow(effect_, 121);
        ID3DXEffect* const dxEffect = effect->GetDxEffect();
        const D3DXHANDLE annotationHandle = dxEffect->GetAnnotationByName(handle_, annotationName.c_str());
        if (annotationHandle == nullptr)
        {
            return false;
        }

        int rawValue = 0;
        const HRESULT result = dxEffect->GetBool(annotationHandle, &rawValue);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectTechniqueD3D9.cpp", 131, result);
        }

        *outValue = (rawValue == 1);
        return true;
    }

    /**
     * Address: 0x008F4600 (FUN_008F4600)
     *
     * What it does:
     * Looks up and reads an integer annotation from the active technique.
     */
    bool EffectTechniqueD3D9::GetAnnotationInt(int* const outValue, const fa::string& annotationName)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectOrThrow(effect_, 141);
        ID3DXEffect* const dxEffect = effect->GetDxEffect();
        const D3DXHANDLE annotationHandle = dxEffect->GetAnnotationByName(handle_, annotationName.c_str());
        if (annotationHandle == nullptr)
        {
            return false;
        }

        const HRESULT result = dxEffect->GetInt(annotationHandle, outValue);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectTechniqueD3D9.cpp", 150, result);
        }

        return true;
    }

    /**
     * Address: 0x008F47C0 (FUN_008F47C0)
     *
     * What it does:
     * Looks up and reads a float annotation from the active technique.
     */
    bool EffectTechniqueD3D9::GetAnnotationFloat(float* const outValue, const fa::string& annotationName)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectOrThrow(effect_, 158);
        ID3DXEffect* const dxEffect = effect->GetDxEffect();
        const D3DXHANDLE annotationHandle = dxEffect->GetAnnotationByName(handle_, annotationName.c_str());
        if (annotationHandle == nullptr)
        {
            return false;
        }

        const HRESULT result = dxEffect->GetFloat(annotationHandle, outValue);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectTechniqueD3D9.cpp", 167, result);
        }

        return true;
    }

    /**
     * Address: 0x008F4980 (FUN_008F4980)
     *
     * What it does:
     * Looks up and reads a string annotation from the active technique.
     */
    bool EffectTechniqueD3D9::GetAnnotationString(fa::string* const outValue, const fa::string& annotationName)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectOrThrow(effect_, 175);
        ID3DXEffect* const dxEffect = effect->GetDxEffect();
        const D3DXHANDLE annotationHandle = dxEffect->GetAnnotationByName(handle_, annotationName.c_str());
        if (annotationHandle == nullptr)
        {
            return false;
        }

        const char* annotationText = nullptr;
        const HRESULT result = dxEffect->GetString(annotationHandle, &annotationText);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectTechniqueD3D9.cpp", 185, result);
        }

        outValue->assign_owned(annotationText != nullptr ? annotationText : "");
        return true;
    }
}

