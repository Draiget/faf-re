#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/String.h"

namespace gpg::gal
{
    /**
     * VFTABLE: 0x00D435CC
     * COL:  0x00E51010
     * Source hints:
     *  - c:\work\rts\main\code\src\libs\gpggal\EffectTechniqueD3D10.cpp
     */
    class EffectTechniqueD3D10
    {
    public:
        /**
         * Address: 0x00900FF0 (FUN_00900FF0)
         *
         * char const *,void *,void *
         *
         * What it does:
         * Initializes a D3D10 technique wrapper from name/effect/technique handles and
         * retains one reference on the backing effect interface.
         */
        EffectTechniqueD3D10(const char* name, void* dxEffect, void* techniqueHandle);

        /**
         * Address: 0x00900FD0 (FUN_00900FD0)
         *
         * What it does:
         * Owns the deleting-destructor thunk path and releases retained effect/name state.
         */
        virtual ~EffectTechniqueD3D10();

        /**
         * Address: 0x00900EF0 (FUN_00900EF0)
         *
         * What it does:
         * Returns the local technique-name string lane.
         */
        virtual msvc8::string* GetName();

        /**
         * Address: 0x00901110 (FUN_00901110)
         *
         * What it does:
         * Begins this technique on the active device and returns pass count from technique desc.
         */
        virtual int BeginTechnique();

        /**
         * Address: 0x00901290 (FUN_00901290)
         *
         * What it does:
         * Ends the active technique lane and clears begin/end tracking state.
         */
        virtual void EndTechnique();

        /**
         * Address: 0x00901360 (FUN_00901360)
         *
         * What it does:
         * Applies the selected technique pass on the active technique.
         */
        virtual void BeginPass(int pass);

        /**
         * Address: 0x009014D0 (FUN_009014D0)
         *
         * What it does:
         * Validates begin/end pass sequencing for the active technique.
         */
        virtual void EndPass();

        /**
         * Address: 0x00901580 (FUN_00901580)
         *
         * What it does:
         * Reads a boolean annotation by name from the active technique handle.
         */
        virtual bool GetAnnotationBool(bool* outValue, const msvc8::string& annotationName);

        /**
         * Address: 0x00901710 (FUN_00901710)
         *
         * What it does:
         * Reads an integer annotation by name from the active technique handle.
         */
        virtual bool GetAnnotationInt(int* outValue, const msvc8::string& annotationName);

        /**
         * Address: 0x00901880 (FUN_00901880)
         *
         * What it does:
         * Reads a float annotation by name from the active technique handle.
         */
        virtual bool GetAnnotationFloat(float* outValue, const msvc8::string& annotationName);

        /**
         * Address: 0x009019F0 (FUN_009019F0)
         *
         * What it does:
         * Reads a string annotation by name from the active technique handle.
         */
        virtual bool GetAnnotationString(msvc8::string* outValue, const msvc8::string& annotationName);

    public:
        msvc8::string name_{};              // +0x04
        void* dxEffect_ = nullptr;          // +0x20
        void* techniqueHandle_ = nullptr;   // +0x24
        bool beginEndActive_ = false;       // +0x28
        std::uint8_t beginEndPadding_[3]{}; // +0x29
    };

    static_assert(offsetof(EffectTechniqueD3D10, name_) == 0x04, "EffectTechniqueD3D10::name_ offset must be 0x04");
    static_assert(offsetof(EffectTechniqueD3D10, dxEffect_) == 0x20, "EffectTechniqueD3D10::dxEffect_ offset must be 0x20");
    static_assert(offsetof(EffectTechniqueD3D10, techniqueHandle_) == 0x24, "EffectTechniqueD3D10::techniqueHandle_ offset must be 0x24");
    static_assert(offsetof(EffectTechniqueD3D10, beginEndActive_) == 0x28, "EffectTechniqueD3D10::beginEndActive_ offset must be 0x28");
    static_assert(sizeof(EffectTechniqueD3D10) == 0x2C, "EffectTechniqueD3D10 size must be 0x2C");
}
