#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "boost/weak_ptr.h"
#include "legacy/containers/String.h"

namespace gpg::gal
{
    class CubeRenderTargetD3D9;
    class EffectD3D9;
    class RenderTargetD3D9;
    class TextureD3D9;

    /**
     * VFTABLE: 0x00D47E94
     * COL:  0x00E5340C
     * Source hints:
     *  - c:\work\rts\main\code\src\libs\gpggal\EffectVariableD3D9.cpp
     */
    class EffectVariableD3D9
    {
    public:
        /**
         * Address: 0x00943060 (FUN_00943060)
         *
         * What it does:
         * Stores variable name/effect weak-reference/parameter handle and validates effect liveness.
         */
        EffectVariableD3D9(const char* variableName, const boost::weak_ptr<EffectD3D9>& effect, void* handle);

        /**
         * Address: 0x00943040 (FUN_00943040)
         *
         * What it does:
         * Owns the deleting-destructor path and delegates to `FUN_00942FC0` body semantics.
         */
        virtual ~EffectVariableD3D9();

        /**
         * Address: 0x00942F80 (FUN_00942F80)
         * Slot: 1
         * Demangled: gpg::gal::EffectVariableD3D9::Func1
         *
         * What it does:
         * Returns the local variable-name string lane.
         */
        virtual msvc8::string* Func1();

        /**
         * Address: 0x00944630 (FUN_00944630)
         * Slot: 2
         * Demangled: gpg::gal::EffectVariableD3D9::Func2
         *
         * What it does:
         * Binds a cube-render-target texture lane to the backing D3DX effect parameter.
         */
        virtual void Func2(boost::shared_ptr<CubeRenderTargetD3D9> cubeRenderTarget);

        /**
         * Address: 0x00944420 (FUN_00944420)
         * Slot: 3
         * Demangled: gpg::gal::EffectVariableD3D9::Func3
         *
         * What it does:
         * Binds a render-target surface lane to the backing D3DX effect parameter.
         */
        virtual void Func3(boost::shared_ptr<RenderTargetD3D9> renderTarget);

        /**
         * Address: 0x009441A0 (FUN_009441A0)
         * Slot: 4
         * Demangled: gpg::gal::EffectVariableD3D9::SetTexture
         *
         * What it does:
         * Binds a texture wrapper lane (2D/volume/cube) to the backing D3DX effect parameter.
         */
        virtual void SetTexture(boost::shared_ptr<TextureD3D9> texture);

        /**
         * Address: 0x00943E10 (FUN_00943E10)
         * Slot: 5
         * Demangled: gpg::gal::EffectVariableD3D9::SetMatrix4x4
         */
        virtual void SetMatrix4x4(const void* matrix4x4);

        /**
         * Address: 0x00943A90 (FUN_00943A90)
         * Slot: 6
         * Demangled: gpg::gal::EffectVariableD3D9::SetMem
         */
        virtual void SetMem(std::uint32_t floatCount, const float* values);

        /**
         * Address: 0x00943710 (FUN_00943710)
         * Slot: 7
         * Demangled: gpg::gal::EffectVariableD3D9::Func4
         *
         * What it does:
         * Writes a single vector4 payload into the backing D3DX effect variable handle.
         */
        virtual void Func4(const void* vector4);

        /**
         * Address: 0x00943C50 (FUN_00943C50)
         * Slot: 8
         * Demangled: gpg::gal::EffectVariableD3D9::SetPtr
         */
        virtual void SetPtr(const void* data, std::uint32_t byteCount);

        /**
         * Address: 0x00943550 (FUN_00943550)
         * Slot: 9
         * Demangled: gpg::gal::EffectVariableD3D9::SetFloat
         */
        virtual void SetFloat(float value);

        /**
         * Address: 0x009433A0 (FUN_009433A0)
         * Slot: 10
         * Demangled: gpg::gal::EffectVariableD3D9::Func6
         *
         * What it does:
         * Writes one integer parameter into the backing D3DX effect variable handle.
         */
        virtual void Func6(int value);

        /**
         * Address: 0x009431E0 (FUN_009431E0)
         * Slot: 11
         * Demangled: gpg::gal::EffectVariableD3D9::Func7
         *
         * What it does:
         * Writes one boolean parameter into the backing D3DX effect variable handle.
         */
        virtual void Func7(bool value);

        /**
         * Address: 0x00943FD0 (FUN_00943FD0)
         * Slot: 12
         * Demangled: gpg::gal::EffectVariableD3D9::Func8
         *
         * What it does:
         * Writes a matrix-array payload into the backing D3DX effect variable handle.
         */
        virtual void Func8(std::uint32_t matrixCount, const void* matrices4x4);

        /**
         * Address: 0x009438D0 (FUN_009438D0)
         * Slot: 13
         * Demangled: gpg::gal::EffectVariableD3D9::Func9
         *
         * What it does:
         * Writes a vector-array payload into the backing D3DX effect variable handle.
         */
        virtual void Func9(std::uint32_t vectorCount, const void* vectors4);

        /**
         * Address: 0x00944840 (FUN_00944840)
         * Slot: 14
         * Demangled: gpg::gal::EffectVariableD3D9::Func10
         *
         * What it does:
         * Retrieves a boolean annotation from this parameter handle by name.
         */
        virtual bool Func10(bool* outValue, const msvc8::string& annotationName);

        /**
         * Address: 0x00944A10 (FUN_00944A10)
         * Slot: 15
         * Demangled: gpg::gal::EffectVariableD3D9::Func11
         *
         * What it does:
         * Retrieves an integer annotation from this parameter handle by name.
         */
        virtual bool Func11(int* outValue, const msvc8::string& annotationName);

        /**
         * Address: 0x00944BD0 (FUN_00944BD0)
         * Slot: 16
         * Demangled: gpg::gal::EffectVariableD3D9::Func12
         *
         * What it does:
         * Retrieves a float annotation from this parameter handle by name.
         */
        virtual bool Func12(float* outValue, const msvc8::string& annotationName);

        /**
         * Address: 0x00944D90 (FUN_00944D90)
         * Slot: 17
         * Demangled: gpg::gal::EffectVariableD3D9::Func13
         *
         * What it does:
         * Retrieves a string annotation from this parameter handle by name.
         */
        virtual bool Func13(msvc8::string* outValue, const msvc8::string& annotationName);

    public:
        msvc8::string name_{};                 // +0x04
        boost::weak_ptr<EffectD3D9> effect_{}; // +0x20
        void* handle_ = nullptr;               // +0x28
    };

    static_assert(offsetof(EffectVariableD3D9, name_) == 0x04, "EffectVariableD3D9::name_ offset must be 0x04");
    static_assert(offsetof(EffectVariableD3D9, effect_) == 0x20, "EffectVariableD3D9::effect_ offset must be 0x20");
    static_assert(offsetof(EffectVariableD3D9, handle_) == 0x28, "EffectVariableD3D9::handle_ offset must be 0x28");
    static_assert(sizeof(EffectVariableD3D9) == 0x2C, "EffectVariableD3D9 size must be 0x2C");
}
