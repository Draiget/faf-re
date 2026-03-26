#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/weak_ptr.h"
#include "legacy/containers/String.h"

namespace gpg::gal
{
    class EffectD3D9;

    /**
     * VFTABLE: 0x00D42CCC
     * COL:  0x00E50930
     * Source hints:
     *  - c:\work\rts\main\code\src\libs\gpggal\EffectTechniqueD3D9.cpp
     */
    class EffectTechniqueD3D9
    {
    public:
        /**
         * Address: 0x008F3AA0 (FUN_008F3AA0)
         *
         * What it does:
         * Owns the deleting-destructor path and delegates to `FUN_008F3A20` body semantics.
         */
        virtual ~EffectTechniqueD3D9();

        /**
         * Address: 0x008F3850 (FUN_008F3850)
         *
         * What it does:
         * Returns the local technique-name string lane.
         */
        virtual msvc8::string* GetName();

        /**
         * Address: 0x008F3C40 (FUN_008F3C40)
         *
         * What it does:
         * Activates this technique and begins the effect technique pass chain.
         */
        virtual int BeginTechnique();

        /**
         * Address: 0x008F3EA0 (FUN_008F3EA0)
         *
         * What it does:
         * Ends the active technique pass chain and clears begin/end tracking state.
         */
        virtual void EndTechnique();

        /**
         * Address: 0x008F4080 (FUN_008F4080)
         *
         * What it does:
         * Begins a pass on the currently active technique.
         */
        virtual void BeginPass(int pass);

        /**
         * Address: 0x008F4260 (FUN_008F4260)
         *
         * What it does:
         * Ends the active pass on the currently active technique.
         */
        virtual void EndPass();

        /**
         * Address: 0x008F4430 (FUN_008F4430)
         *
         * What it does:
         * Retrieves a boolean technique annotation by name.
         */
        virtual bool GetAnnotationBool(bool* outValue, const msvc8::string& annotationName);

        /**
         * Address: 0x008F4600 (FUN_008F4600)
         *
         * What it does:
         * Retrieves an integer technique annotation by name.
         */
        virtual bool GetAnnotationInt(int* outValue, const msvc8::string& annotationName);

        /**
         * Address: 0x008F47C0 (FUN_008F47C0)
         *
         * What it does:
         * Retrieves a float technique annotation by name.
         */
        virtual bool GetAnnotationFloat(float* outValue, const msvc8::string& annotationName);

        /**
         * Address: 0x008F4980 (FUN_008F4980)
         *
         * What it does:
         * Retrieves a string technique annotation by name.
         */
        virtual bool GetAnnotationString(msvc8::string* outValue, const msvc8::string& annotationName);

    public:
        msvc8::string name_{};                 // +0x04
        boost::weak_ptr<EffectD3D9> effect_{}; // +0x20
        void* handle_ = nullptr;               // +0x28
        bool beginEndActive_ = false;          // +0x2C
        std::uint8_t beginEndPadding_[3]{};    // +0x2D
    };

    static_assert(offsetof(EffectTechniqueD3D9, name_) == 0x04, "EffectTechniqueD3D9::name_ offset must be 0x04");
    static_assert(offsetof(EffectTechniqueD3D9, effect_) == 0x20, "EffectTechniqueD3D9::effect_ offset must be 0x20");
    static_assert(offsetof(EffectTechniqueD3D9, handle_) == 0x28, "EffectTechniqueD3D9::handle_ offset must be 0x28");
    static_assert(offsetof(EffectTechniqueD3D9, beginEndActive_) == 0x2C, "EffectTechniqueD3D9::beginEndActive_ offset must be 0x2C");
    static_assert(sizeof(EffectTechniqueD3D9) == 0x30, "EffectTechniqueD3D9 size must be 0x30");
}
