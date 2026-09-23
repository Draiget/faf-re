#pragma once

#include <cstddef>
#include <cstdint>

#include <d3dx9effect.h>

#include "boost/shared_ptr.h"
#include "boost/weak_ptr.h"
#include "gpg/gal/EffectVariable.hpp"
#include "legacy/containers/String.h"

namespace gpg::gal
{
    class EffectD3D9;

    /**
     * VFTABLE: 0x00D47E94
     * COL:  0x00E5340C
     * Source hints:
     *  - c:\work\rts\main\code\src\libs\gpggal\EffectVariableD3D9.cpp
     *
     * One effect parameter. Like the technique wrapper it holds its effect
     * weakly and locks it on every call.
     */
    class EffectVariableD3D9 : public EffectVariable
    {
    public:
        /**
         * Address: 0x00943060 (FUN_00943060)
         *
         * What it does:
         * Keeps `name`, a weak reference to `effect` and the parameter handle;
         * throws "invalid effect specified" (line 37) when the effect is
         * already gone.
         */
        EffectVariableD3D9(const char* name, boost::shared_ptr<EffectD3D9> effect, D3DXHANDLE handle);

        /**
         * Address: 0x00942FC0 (FUN_00942FC0)
         * Address: 0x00943040 (FUN_00943040, the scalar deleting destructor)
         * Slot: 0
         *
         * What it does:
         * Nothing of its own: the weak effect reference and the name go as
         * members, then the `EffectVariable` base.
         */
        ~EffectVariableD3D9() override;

        /**
         * Address: 0x00942F80 (FUN_00942F80)
         * Slot: 1
         *
         * What it does:
         * Returns the parameter name.
         */
        msvc8::string* GetName() override;

        /**
         * Address: 0x00944630 (FUN_00944630)
         * Slot: 2
         *
         * What it does:
         * Binds a cube render target's texture to this parameter (a null
         * target unbinds it).
         */
        void SetCubeRenderTarget(boost::shared_ptr<CubeRenderTarget> cubeTarget) override;

        /**
         * Address: 0x00944420 (FUN_00944420)
         * Slot: 3
         *
         * What it does:
         * Binds a colour render target's texture to this parameter (a null
         * target unbinds it).
         */
        void SetRenderTarget(boost::shared_ptr<RenderTarget> renderTarget) override;

        /**
         * Address: 0x009441A0 (FUN_009441A0)
         * Slot: 4
         *
         * What it does:
         * Binds a texture (2D, volume or cube) to this parameter.
         */
        void SetTexture(boost::shared_ptr<Texture> texture) override;

        /**
         * Address: 0x00943E10 (FUN_00943E10)
         * Slot: 5
         *
         * What it does:
         * `ID3DXEffect::SetMatrix` on this parameter.
         */
        void SetMatrix4x4(const Matrix* matrix) override;

        /**
         * Address: 0x00943A90 (FUN_00943A90)
         * Slot: 6
         *
         * What it does:
         * `ID3DXEffect::SetFloatArray` on this parameter.
         */
        void SetFloatArray(std::uint32_t count, const float* values) override;

        /**
         * Address: 0x00943710 (FUN_00943710)
         * Slot: 7
         *
         * What it does:
         * `ID3DXEffect::SetVector` on this parameter.
         */
        void SetVector(const float* vector4) override;

        /**
         * Address: 0x00943C50 (FUN_00943C50)
         * Slot: 8
         *
         * What it does:
         * `ID3DXEffect::SetValue` on this parameter.
         */
        void SetValue(const void* data, std::uint32_t byteCount) override;

        /**
         * Address: 0x00943550 (FUN_00943550)
         * Slot: 9
         *
         * What it does:
         * `ID3DXEffect::SetFloat` on this parameter.
         */
        void SetFloat(float value) override;

        /**
         * Address: 0x009433A0 (FUN_009433A0)
         * Slot: 10
         *
         * What it does:
         * `ID3DXEffect::SetInt` on this parameter.
         */
        void SetInt(int value) override;

        /**
         * Address: 0x009431E0 (FUN_009431E0)
         * Slot: 11
         *
         * What it does:
         * `ID3DXEffect::SetBool` on this parameter.
         */
        void SetBool(bool value) override;

        /**
         * Address: 0x00943FD0 (FUN_00943FD0)
         * Slot: 12
         *
         * What it does:
         * `ID3DXEffect::SetMatrixArray` on this parameter.
         */
        void SetMatrixArray(std::uint32_t count, const Matrix* matrices) override;

        /**
         * Address: 0x009438D0 (FUN_009438D0)
         * Slot: 13
         *
         * What it does:
         * `ID3DXEffect::SetVectorArray` on this parameter -- handed the address
         * of the `vectors4` parameter itself, not its value (see the body).
         */
        void SetVectorArray(std::uint32_t count, const float* vectors4) override;

        /**
         * Address: 0x00944840 (FUN_00944840)
         * Slot: 14
         *
         * What it does:
         * Reads the parameter's bool annotation `annotationName`.
         */
        bool GetAnnotationBool(bool* outValue, const msvc8::string& annotationName) override;

        /**
         * Address: 0x00944A10 (FUN_00944A10)
         * Slot: 15
         *
         * What it does:
         * Reads the parameter's int annotation `annotationName`.
         */
        bool GetAnnotationInt(int* outValue, const msvc8::string& annotationName) override;

        /**
         * Address: 0x00944BD0 (FUN_00944BD0)
         * Slot: 16
         *
         * What it does:
         * Reads the parameter's float annotation `annotationName`.
         */
        bool GetAnnotationFloat(float* outValue, const msvc8::string& annotationName) override;

        /**
         * Address: 0x00944D90 (FUN_00944D90)
         * Slot: 17
         *
         * What it does:
         * Reads the parameter's string annotation `annotationName`.
         */
        bool GetAnnotationString(msvc8::string* outValue, const msvc8::string& annotationName) override;

    public:
        msvc8::string name_;                 // +0x04
        boost::weak_ptr<EffectD3D9> effect_; // +0x20
        D3DXHANDLE handle_ = nullptr;        // +0x28
    };

    static_assert(offsetof(EffectVariableD3D9, name_) == 0x04, "EffectVariableD3D9::name_ offset must be 0x04");
    static_assert(offsetof(EffectVariableD3D9, effect_) == 0x20, "EffectVariableD3D9::effect_ offset must be 0x20");
    static_assert(offsetof(EffectVariableD3D9, handle_) == 0x28, "EffectVariableD3D9::handle_ offset must be 0x28");
    static_assert(sizeof(EffectVariableD3D9) == 0x2C, "EffectVariableD3D9 size must be 0x2C");
} // namespace gpg::gal
