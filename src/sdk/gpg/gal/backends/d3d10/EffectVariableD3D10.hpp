#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "gpg/gal/EffectVariable.hpp"
#include "legacy/containers/String.h"

namespace gpg::gal
{
    /**
     * VFTABLE: 0x00D488DC
     * COL:  0x00E538F8
     * Source hints:
     *  - c:\work\rts\main\code\src\libs\gpggal\EffectVariableD3D10.cpp
     */
    class EffectVariableD3D10 : public EffectVariable
    {
    public:
        /**
         * Address: 0x0094C1F0 (FUN_0094C1F0)
         *
         * char const *,void *,void *
         *
         * What it does:
         * Keeps the variable name and handles and AddRefs the native effect;
         * throws "invalid effect specified" when there is no effect.
         */
        EffectVariableD3D10(const char* name, void* dxEffect, void* variableHandle);

        /**
         * Address: 0x0094C150 (FUN_0094C150)
         * Address: 0x0094C1D0 (FUN_0094C1D0, the scalar deleting destructor)
         * Slot: 0
         *
         * What it does:
         * Releases the native effect; the name then goes as a member.
         */
        ~EffectVariableD3D10() override;

        /**
         * Address: 0x0094C0E0 (FUN_0094C0E0)
         * Slot: 1
         *
         * What it does:
         * Returns the variable name.
         */
        msvc8::string* GetName() override;

        /**
         * Address: 0x0094C0F0 (FUN_0094C0F0)
         * Slot: 2
         *
         * What it does:
         * Nothing: D3D10 has no cube render targets to bind. The by-value
         * `shared_ptr` is released on return.
         */
        void SetCubeRenderTarget(boost::shared_ptr<CubeRenderTarget> cubeTarget) override;

        /**
         * Address: 0x0094CD00 (FUN_0094CD00)
         * Slot: 3
         *
         * What it does:
         * Binds a render target's shader-resource view to this variable.
         */
        void SetRenderTarget(boost::shared_ptr<RenderTarget> renderTarget) override;

        /**
         * Address: 0x0094CBB0 (FUN_0094CBB0)
         * Slot: 4
         *
         * What it does:
         * Binds a texture's shader-resource view to this variable.
         */
        void SetTexture(boost::shared_ptr<Texture> texture) override;

        /**
         * Address: 0x0094C9B0 (FUN_0094C9B0)
         * Slot: 5
         *
         * What it does:
         * `AsMatrix()->SetMatrix` on this variable.
         */
        void SetMatrix4x4(const Matrix* matrix) override;

        /**
         * Address: 0x0094C7D0 (FUN_0094C7D0)
         * Slot: 6
         *
         * What it does:
         * Writes `count` floats as raw bytes (`SetRawValue`, `count * 4`).
         */
        void SetFloatArray(std::uint32_t count, const float* values) override;

        /**
         * Address: 0x0094C5E0 (FUN_0094C5E0)
         * Slot: 7
         *
         * What it does:
         * `AsVector()->SetFloatVector` on this variable.
         */
        void SetVector(const float* vector4) override;

        /**
         * Address: 0x0094C8C0 (FUN_0094C8C0)
         * Slot: 8
         *
         * What it does:
         * Writes `byteCount` raw bytes (`SetRawValue`).
         */
        void SetValue(const void* data, std::uint32_t byteCount) override;

        /**
         * Address: 0x0094C4F0 (FUN_0094C4F0)
         * Slot: 9
         *
         * What it does:
         * `AsScalar()->SetFloat` on this variable.
         */
        void SetFloat(float value) override;

        /**
         * Address: 0x0094C400 (FUN_0094C400)
         * Slot: 10
         *
         * What it does:
         * `AsScalar()->SetInt` on this variable.
         */
        void SetInt(int value) override;

        /**
         * Address: 0x0094C310 (FUN_0094C310)
         * Slot: 11
         *
         * What it does:
         * `AsScalar()->SetBool` on this variable.
         */
        void SetBool(bool value) override;

        /**
         * Address: 0x0094CAA0 (FUN_0094CAA0)
         * Slot: 12
         *
         * What it does:
         * `AsMatrix()->SetMatrixArray`, falling back to raw bytes when that
         * fails (see the body for the argument it passes).
         */
        void SetMatrixArray(std::uint32_t count, const Matrix* matrices) override;

        /**
         * Address: 0x0094C6D0 (FUN_0094C6D0)
         * Slot: 13
         *
         * What it does:
         * `AsVector()->SetFloatVectorArray` (see the body for the argument it
         * passes).
         */
        void SetVectorArray(std::uint32_t count, const float* vectors4) override;

        /**
         * Address: 0x0094CE50 (FUN_0094CE50)
         * Slot: 14
         *
         * What it does:
         * Reads the variable's bool annotation `annotationName`.
         */
        bool GetAnnotationBool(bool* outValue, const msvc8::string& annotationName) override;

        /**
         * Address: 0x0094CFE0 (FUN_0094CFE0)
         * Slot: 15
         *
         * What it does:
         * Reads the variable's int annotation `annotationName`.
         */
        bool GetAnnotationInt(int* outValue, const msvc8::string& annotationName) override;

        /**
         * Address: 0x0094D150 (FUN_0094D150)
         * Slot: 16
         *
         * What it does:
         * Reads the variable's float annotation `annotationName`.
         */
        bool GetAnnotationFloat(float* outValue, const msvc8::string& annotationName) override;

        /**
         * Address: 0x0094D2C0 (FUN_0094D2C0)
         * Slot: 17
         *
         * What it does:
         * Reads the variable's string annotation `annotationName`.
         */
        bool GetAnnotationString(msvc8::string* outValue, const msvc8::string& annotationName) override;

    public:
        msvc8::string name_{};           // +0x04
        void* dxEffect_ = nullptr;       // +0x20
        void* variableHandle_ = nullptr; // +0x24
    };

    static_assert(offsetof(EffectVariableD3D10, name_) == 0x04, "EffectVariableD3D10::name_ offset must be 0x04");
    static_assert(offsetof(EffectVariableD3D10, dxEffect_) == 0x20, "EffectVariableD3D10::dxEffect_ offset must be 0x20");
    static_assert(offsetof(EffectVariableD3D10, variableHandle_) == 0x24, "EffectVariableD3D10::variableHandle_ offset must be 0x24");
    static_assert(sizeof(EffectVariableD3D10) == 0x28, "EffectVariableD3D10 size must be 0x28");
} // namespace gpg::gal
