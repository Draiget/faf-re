#include "gpg/gal/backends/d3d9/D3D9Private.h"

namespace gpg::gal
{
namespace
{

        /**
         * The same lock-and-check for the `EffectVariableD3D9` entry points.
         */
        boost::shared_ptr<EffectD3D9> LockEffectVariableOrThrow(
            const boost::weak_ptr<EffectD3D9>& weakEffect,
            const int line
        )
        {
            boost::shared_ptr<EffectD3D9> effect = boost::LockWeak(weakEffect);
            if (!effect)
            {
                ThrowGalError("EffectVariableD3D9.cpp", line, "attempt to use invalid effect");
            }

            return effect;
        }
}


    /**
     * Address: 0x00943060 (FUN_00943060)
     *
     * What it does:
     * Keeps `name`, a weak reference to `effect` and the parameter handle;
     * throws "invalid effect specified" (EffectVariableD3D9.cpp:37) when the
     * effect has already expired.
     */
    EffectVariableD3D9::EffectVariableD3D9(
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
            ThrowGalError("EffectVariableD3D9.cpp", 37, "invalid effect specified");
        }
    }

    /**
     * Address: 0x00942FC0 (FUN_00942FC0)
     * Address: 0x00943040 (FUN_00943040, the scalar deleting destructor)
     *
     * What it does:
     * Nothing of its own: the weak effect reference and the name go as
     * members, then the `EffectVariable` base.
     */
    EffectVariableD3D9::~EffectVariableD3D9() = default;

    /**
     * Address: 0x00942F80 (FUN_00942F80)
     *
     * What it does:
     * Returns the parameter name.
     */
    fa::string* EffectVariableD3D9::GetName()
    {
        return &name_;
    }

    /**
     * Address: 0x009431E0 (FUN_009431E0)
     *
     * What it does:
     * Writes one boolean parameter into the backing D3DX effect variable handle.
     */
    void EffectVariableD3D9::SetBool(const bool value)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectVariableOrThrow(effect_, 52);
        const HRESULT result = effect->GetDxEffect()->SetBool(handle_, value ? TRUE : FALSE);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectVariableD3D9.cpp", 57, result);
        }
    }

    /**
     * Address: 0x009433A0 (FUN_009433A0)
     *
     * What it does:
     * Writes one integer parameter into the backing D3DX effect variable handle.
     */
    void EffectVariableD3D9::SetInt(const int value)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectVariableOrThrow(effect_, 63);
        const HRESULT result = effect->GetDxEffect()->SetInt(handle_, value);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectVariableD3D9.cpp", 68, result);
        }
    }

    /**
     * Address: 0x00943710 (FUN_00943710)
     *
     * What it does:
     * Writes a single vector4 payload into the backing D3DX effect variable handle.
     */
    void EffectVariableD3D9::SetVector(const float* const vector4)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectVariableOrThrow(effect_, 85);
        const HRESULT result = effect->GetDxEffect()->SetVector(handle_, reinterpret_cast<const D3DXVECTOR4*>(vector4));
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectVariableD3D9.cpp", 90, result);
        }
    }

    /**
     * Address: 0x009438D0 (FUN_009438D0)
     *
     * What it does:
     * `ID3DXEffect::SetVectorArray` on this parameter, with the address of the
     * `vectors4` parameter itself as the data (`lea edx, [esp+0xA8]` at
     * 0x00943990, where slots 6, 7 and 12 load their pointer). D3DX therefore
     * reads the pointer and the stack above it, not the caller's vectors. The
     * D3D10 twin makes the same slip; nothing in the binary calls the slot.
     */
    void EffectVariableD3D9::SetVectorArray(const std::uint32_t count, const float* const vectors4)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectVariableOrThrow(effect_, 96);
        const HRESULT result =
            effect->GetDxEffect()->SetVectorArray(handle_, reinterpret_cast<const D3DXVECTOR4*>(&vectors4), count);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectVariableD3D9.cpp", 101, result);
        }
    }

    /**
     * Address: 0x00943550 (FUN_00943550)
     *
     * What it does:
     * Writes one float parameter into the backing D3DX effect variable handle.
     */
    void EffectVariableD3D9::SetFloat(const float value)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectVariableOrThrow(effect_, 74);
        const HRESULT result = effect->GetDxEffect()->SetFloat(handle_, value);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectVariableD3D9.cpp", 79, result);
        }
    }

    /**
     * Address: 0x00943A90 (FUN_00943A90)
     *
     * What it does:
     * Writes a float-array payload into the backing D3DX effect variable handle.
     */
    void EffectVariableD3D9::SetFloatArray(const std::uint32_t count, const float* const values)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectVariableOrThrow(effect_, 107);
        const HRESULT result = effect->GetDxEffect()->SetFloatArray(handle_, values, count);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectVariableD3D9.cpp", 112, result);
        }
    }

    /**
     * Address: 0x00943C50 (FUN_00943C50)
     *
     * What it does:
     * Writes an untyped byte payload into the backing D3DX effect variable handle.
     */
    void EffectVariableD3D9::SetValue(const void* const data, const std::uint32_t byteCount)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectVariableOrThrow(effect_, 118);
        const HRESULT result = effect->GetDxEffect()->SetValue(handle_, data, byteCount);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectVariableD3D9.cpp", 123, result);
        }
    }

    /**
     * Address: 0x00943E10 (FUN_00943E10)
     *
     * What it does:
     * Writes a 4x4 matrix payload into the backing D3DX effect variable handle.
     */
    void EffectVariableD3D9::SetMatrix4x4(const Matrix* const matrix)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectVariableOrThrow(effect_, 129);
        const HRESULT result = effect->GetDxEffect()->SetMatrix(handle_, reinterpret_cast<const D3DXMATRIX*>(matrix));
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectVariableD3D9.cpp", 134, result);
        }
    }

    /**
     * Address: 0x00943FD0 (FUN_00943FD0)
     *
     * What it does:
     * Writes a matrix-array payload into the backing D3DX effect variable handle.
     */
    void EffectVariableD3D9::SetMatrixArray(const std::uint32_t count, const Matrix* const matrices)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectVariableOrThrow(effect_, 140);
        const HRESULT result =
            effect->GetDxEffect()->SetMatrixArray(handle_, reinterpret_cast<const D3DXMATRIX*>(matrices), count);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectVariableD3D9.cpp", 145, result);
        }
    }

    /**
     * Address: 0x009441A0 (FUN_009441A0)
     *
     * What it does:
     * Binds a texture wrapper lane (2D/volume/cube) to the backing D3DX effect parameter.
     */
    void EffectVariableD3D9::SetTexture(const boost::shared_ptr<Texture> texture)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectVariableOrThrow(effect_, 151);
        IDirect3DBaseTexture9* textureHandle = nullptr;

        if (texture)
        {
            auto* const textureD3D9 = static_cast<TextureD3D9*>(texture.get());
            textureHandle = textureD3D9->GetTexture1();
            if (textureHandle == nullptr)
            {
                textureHandle = textureD3D9->GetTexture2();
            }
            if (textureHandle == nullptr)
            {
                textureHandle = textureD3D9->GetTexture3();
            }
        }

        const HRESULT result = effect->GetDxEffect()->SetTexture(handle_, textureHandle);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectVariableD3D9.cpp", 183, result);
        }
    }

    /**
     * Address: 0x00944420 (FUN_00944420)
     *
     * What it does:
     * Binds a colour render target's texture (`RenderTargetD3D9::GetTexture`,
     * not its surface) to this effect parameter; a null target unbinds it.
     */
    void EffectVariableD3D9::SetRenderTarget(const boost::shared_ptr<RenderTarget> renderTarget)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectVariableOrThrow(effect_, 189);
        IDirect3DTexture9* const textureHandle =
            (renderTarget.get() != nullptr) ? static_cast<RenderTargetD3D9*>(renderTarget.get())->GetTexture() : nullptr;

        const HRESULT result = effect->GetDxEffect()->SetTexture(handle_, textureHandle);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectVariableD3D9.cpp", 201, result);
        }
    }

    /**
     * Address: 0x00944630 (FUN_00944630)
     *
     * What it does:
     * Binds a cube render target's texture (`CubeRenderTargetD3D9::GetTexture`,
     * 0x00941270, called at 0x00944705) to this effect parameter; a null
     * target unbinds it.
     */
    void EffectVariableD3D9::SetCubeRenderTarget(const boost::shared_ptr<CubeRenderTarget> cubeTarget)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectVariableOrThrow(effect_, 207);
        IDirect3DCubeTexture9* const textureHandle =
            (cubeTarget.get() != nullptr) ? static_cast<CubeRenderTargetD3D9*>(cubeTarget.get())->GetTexture() : nullptr;

        const HRESULT result = effect->GetDxEffect()->SetTexture(handle_, textureHandle);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectVariableD3D9.cpp", 219, result);
        }
    }

    /**
     * Address: 0x00944840 (FUN_00944840)
     *
     * What it does:
     * Retrieves a boolean annotation from this parameter handle by name.
     */
    bool EffectVariableD3D9::GetAnnotationBool(bool* const outValue, const fa::string& annotationName)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectVariableOrThrow(effect_, 225);
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
            ThrowGalErrorFromHresult("EffectVariableD3D9.cpp", 235, result);
        }

        *outValue = (rawValue == 1);
        return true;
    }

    /**
     * Address: 0x00944A10 (FUN_00944A10)
     *
     * What it does:
     * Retrieves an integer annotation from this parameter handle by name.
     */
    bool EffectVariableD3D9::GetAnnotationInt(int* const outValue, const fa::string& annotationName)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectVariableOrThrow(effect_, 245);
        ID3DXEffect* const dxEffect = effect->GetDxEffect();
        const D3DXHANDLE annotationHandle = dxEffect->GetAnnotationByName(handle_, annotationName.c_str());
        if (annotationHandle == nullptr)
        {
            return false;
        }

        const HRESULT result = dxEffect->GetInt(annotationHandle, outValue);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectVariableD3D9.cpp", 254, result);
        }

        return true;
    }

    /**
     * Address: 0x00944BD0 (FUN_00944BD0)
     *
     * What it does:
     * Retrieves a float annotation from this parameter handle by name.
     */
    bool EffectVariableD3D9::GetAnnotationFloat(float* const outValue, const fa::string& annotationName)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectVariableOrThrow(effect_, 262);
        ID3DXEffect* const dxEffect = effect->GetDxEffect();
        const D3DXHANDLE annotationHandle = dxEffect->GetAnnotationByName(handle_, annotationName.c_str());
        if (annotationHandle == nullptr)
        {
            return false;
        }

        const HRESULT result = dxEffect->GetFloat(annotationHandle, outValue);
        if (result < 0)
        {
            ThrowGalErrorFromHresult("EffectVariableD3D9.cpp", 271, result);
        }

        return true;
    }

    /**
     * Address: 0x00944D90 (FUN_00944D90)
     *
     * What it does:
     * Retrieves a string annotation from this parameter handle by name.
     */
    bool EffectVariableD3D9::GetAnnotationString(fa::string* const outValue, const fa::string& annotationName)
    {
        boost::shared_ptr<EffectD3D9> effect = LockEffectVariableOrThrow(effect_, 279);
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
            ThrowGalErrorFromHresult("EffectVariableD3D9.cpp", 289, result);
        }

        outValue->assign_owned(annotationText != nullptr ? annotationText : "");
        return true;
    }
}

