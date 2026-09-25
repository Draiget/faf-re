#pragma once

#include <cstddef>
#include <cstdint>

#include <d3d10.h>

#include "gpg/gal/EffectTechnique.hpp"
#include "legacy/containers/String.h"

namespace gpg::gal
{
    /**
     * VFTABLE: 0x00D435CC
     * COL:  0x00E51010
     * Source hints:
     *  - c:\work\rts\main\code\src\libs\gpggal\EffectTechniqueD3D10.cpp
     */
    class EffectTechniqueD3D10 : public EffectTechnique
    {
    public:
        /**
         * Address: 0x00900FF0 (FUN_00900FF0)
         *
         * char const *,void *,void *
         *
         * What it does:
         * Keeps the technique name and handles and AddRefs the native effect;
         * throws "invalid effect specified" when there is no effect.
         */
        EffectTechniqueD3D10(const char* name, ID3D10Effect* dxEffect, ID3D10EffectTechnique* techniqueHandle);

        /**
         * Address: 0x00900F50 (FUN_00900F50)
         * Address: 0x00900FD0 (FUN_00900FD0, the scalar deleting destructor)
         * Slot: 0
         *
         * What it does:
         * Releases the native effect; the name then goes as a member.
         */
        ~EffectTechniqueD3D10() override;

        /**
         * Address: 0x00900EF0 (FUN_00900EF0)
         * Slot: 1
         *
         * What it does:
         * Returns the technique name.
         */
        msvc8::string* GetName() override;

        /**
         * Address: 0x00901110 (FUN_00901110)
         * Slot: 2
         *
         * What it does:
         * Begins this technique on the active device and returns its pass count.
         */
        int BeginTechnique() override;

        /**
         * Address: 0x00901290 (FUN_00901290)
         * Slot: 3
         *
         * What it does:
         * Ends the technique and clears the begin/end tracking.
         */
        void EndTechnique() override;

        /**
         * Address: 0x00901360 (FUN_00901360)
         * Slot: 4
         *
         * What it does:
         * Applies pass `pass` of the technique.
         */
        void BeginPass(int pass) override;

        /**
         * Address: 0x009014D0 (FUN_009014D0)
         * Slot: 5
         *
         * What it does:
         * Checks the begin/end sequencing; D3D10 has nothing to end per pass.
         */
        void EndPass() override;

        /**
         * Address: 0x00901580 (FUN_00901580)
         * Slot: 6
         *
         * What it does:
         * Reads the technique's bool annotation `annotationName`.
         */
        bool GetAnnotationBool(bool* outValue, const msvc8::string& annotationName) override;

        /**
         * Address: 0x00901710 (FUN_00901710)
         * Slot: 7
         *
         * What it does:
         * Reads the technique's int annotation `annotationName`.
         */
        bool GetAnnotationInt(int* outValue, const msvc8::string& annotationName) override;

        /**
         * Address: 0x00901880 (FUN_00901880)
         * Slot: 8
         *
         * What it does:
         * Reads the technique's float annotation `annotationName`.
         */
        bool GetAnnotationFloat(float* outValue, const msvc8::string& annotationName) override;

        /**
         * Address: 0x009019F0 (FUN_009019F0)
         * Slot: 9
         *
         * What it does:
         * Reads the technique's string annotation `annotationName`.
         */
        bool GetAnnotationString(msvc8::string* outValue, const msvc8::string& annotationName) override;

    public:
        msvc8::string name_{};              // +0x04
        ID3D10Effect* dxEffect_ = nullptr;                   // +0x20 held (AddRef) while the wrapper lives
        ID3D10EffectTechnique* techniqueHandle_ = nullptr;   // +0x24 owned by the effect
        bool beginEndActive_ = false;       // +0x28
        std::uint8_t beginEndPadding_[3]{}; // +0x29
    };

    static_assert(offsetof(EffectTechniqueD3D10, name_) == 0x04, "EffectTechniqueD3D10::name_ offset must be 0x04");
    static_assert(offsetof(EffectTechniqueD3D10, dxEffect_) == 0x20, "EffectTechniqueD3D10::dxEffect_ offset must be 0x20");
    static_assert(offsetof(EffectTechniqueD3D10, techniqueHandle_) == 0x24, "EffectTechniqueD3D10::techniqueHandle_ offset must be 0x24");
    static_assert(offsetof(EffectTechniqueD3D10, beginEndActive_) == 0x28, "EffectTechniqueD3D10::beginEndActive_ offset must be 0x28");
    static_assert(sizeof(EffectTechniqueD3D10) == 0x2C, "EffectTechniqueD3D10 size must be 0x2C");
} // namespace gpg::gal
