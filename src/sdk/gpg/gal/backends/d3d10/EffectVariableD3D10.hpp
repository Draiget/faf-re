#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "legacy/containers/String.h"

namespace gpg::gal
{
    class CubeRenderTargetD3D10;
    class RenderTargetD3D10;
    class TextureD3D10;

    /**
     * VFTABLE: 0x00D488DC
     * COL:  0x00E538F8
     * Source hints:
     *  - c:\work\rts\main\code\src\libs\gpggal\EffectVariableD3D10.cpp
     */
    class EffectVariableD3D10
    {
    public:
        /**
         * Address: 0x0094C1F0 (FUN_0094C1F0)
         *
         * char const *,void *,void *
         *
         * What it does:
         * Initializes a D3D10 effect-variable wrapper and retains one reference on
         * the backing effect interface.
         */
        EffectVariableD3D10(const char* name, void* dxEffect, void* variableHandle);

        /**
         * Address: 0x0094C1D0 (FUN_0094C1D0)
         *
         * What it does:
         * Owns the deleting-destructor thunk path and delegates to `FUN_0094C150`.
         */
        virtual ~EffectVariableD3D10();

        /**
         * Address: 0x0094C0E0 (FUN_0094C0E0)
         *
         * What it does:
         * Returns the local variable-name string lane.
         */
        virtual msvc8::string* GetName();

        /**
         * Address: 0x0094C0F0 (FUN_0094C0F0)
         *
         * What it does:
         * D3D10 cube render-target slot keeps an empty body and only owns by-value
         * `shared_ptr` release semantics.
         */
        virtual void Func2(boost::shared_ptr<CubeRenderTargetD3D10> cubeRenderTarget);

        /**
         * Address: 0x0094CD00 (FUN_0094CD00)
         *
         * What it does:
         * Binds a render-target-backed shader-resource view into this effect slot.
         */
        virtual void Func3(boost::shared_ptr<RenderTargetD3D10> renderTarget);

        /**
         * Address: 0x0094CBB0 (FUN_0094CBB0)
         *
         * What it does:
         * Binds a texture shader-resource view into this effect slot.
         */
        virtual void SetTexture(boost::shared_ptr<TextureD3D10> texture);

        /**
         * Address: 0x0094C9B0 (FUN_0094C9B0)
         *
         * What it does:
         * Converts to matrix lane and writes one matrix payload.
         */
        virtual void SetMatrix4x4(const void* matrix4x4);

        /**
         * Address: 0x0094C7D0 (FUN_0094C7D0)
         *
         * int,void const *
         *
         * What it does:
         * Writes raw value payload bytes (`floatCount * 4`) from caller memory.
         */
        virtual void SetMem(int floatCount, const void* values);

        /**
         * Address: 0x0094C5E0 (FUN_0094C5E0)
         *
         * What it does:
         * Converts to vector lane and writes one vector payload.
         */
        virtual void SetVector(const void* value);

        /**
         * Address: 0x0094C8C0 (FUN_0094C8C0)
         *
         * void const *,int
         *
         * What it does:
         * Writes raw value payload bytes from caller memory (`byteCount`).
         */
        virtual void SetPtr(const void* data, int byteCount);

        /**
         * Address: 0x0094C4F0 (FUN_0094C4F0)
         *
         * What it does:
         * Converts to scalar lane and writes a float value.
         */
        virtual void SetFloat(float value);

        /**
         * Address: 0x0094C400 (FUN_0094C400)
         *
         * What it does:
         * Converts to scalar lane and writes an integer value.
         */
        virtual void SetInt(int value);

        /**
         * Address: 0x0094C310 (FUN_0094C310)
         *
         * What it does:
         * Converts to scalar lane and writes a boolean value.
         */
        virtual void SetBool(bool value);

        /**
         * Address: 0x0094CAA0 (FUN_0094CAA0)
         *
         * int,void const *
         *
         * What it does:
         * Writes count-based matrix/float payload through matrix lane with
         * raw-value fallback.
         */
        virtual void Func8(int valueCount, const void* values);

        /**
         * Address: 0x0094C6D0 (FUN_0094C6D0)
         *
         * int,unsigned int
         *
         * What it does:
         * Writes vector-lane payload bytes using one 32-bit value lane.
         */
        virtual void Func9(int valueCount, std::uint32_t value);

        /**
         * Address: 0x0094CE50 (FUN_0094CE50)
         *
         * What it does:
         * Reads a boolean annotation by name from this variable handle.
         */
        virtual bool GetAnnotationBool(bool* outValue, const msvc8::string& annotationName);

        /**
         * Address: 0x0094CFE0 (FUN_0094CFE0)
         *
         * What it does:
         * Reads an integer annotation by name from this variable handle.
         */
        virtual bool GetAnnotationInt(int* outValue, const msvc8::string& annotationName);

        /**
         * Address: 0x0094D150 (FUN_0094D150)
         *
         * What it does:
         * Reads a float annotation by name from this variable handle.
         */
        virtual bool GetAnnotationFloat(float* outValue, const msvc8::string& annotationName);

        /**
         * Address: 0x0094D2C0 (FUN_0094D2C0)
         *
         * What it does:
         * Reads a string annotation by name from this variable handle.
         */
        virtual bool GetAnnotationString(msvc8::string* outValue, const msvc8::string& annotationName);

    public:
        msvc8::string name_{};           // +0x04
        void* dxEffect_ = nullptr;       // +0x20
        void* variableHandle_ = nullptr; // +0x24
    };

    static_assert(offsetof(EffectVariableD3D10, name_) == 0x04, "EffectVariableD3D10::name_ offset must be 0x04");
    static_assert(offsetof(EffectVariableD3D10, dxEffect_) == 0x20, "EffectVariableD3D10::dxEffect_ offset must be 0x20");
    static_assert(offsetof(EffectVariableD3D10, variableHandle_) == 0x24, "EffectVariableD3D10::variableHandle_ offset must be 0x24");
    static_assert(sizeof(EffectVariableD3D10) == 0x28, "EffectVariableD3D10 size must be 0x28");
}
