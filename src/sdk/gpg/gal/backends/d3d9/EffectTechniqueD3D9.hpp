#pragma once

#include <cstddef>
#include <cstdint>

#include <d3dx9effect.h>

#include "boost/shared_ptr.h"
#include "boost/weak_ptr.h"
#include "gpg/gal/EffectTechnique.hpp"
#include "legacy/containers/String.h"

namespace gpg::gal
{
    class EffectD3D9;

    /**
     * VFTABLE: 0x00D42CCC
     * COL:  0x00E50930
     * Source hints:
     *  - c:\work\rts\main\code\src\libs\gpggal\EffectTechniqueD3D9.cpp
     *
     * Holds its effect weakly and locks it on every call, so a technique that
     * outlives its effect throws "attempt to use invalid effect" instead of
     * touching a released `ID3DXEffect`.
     */
    class EffectTechniqueD3D9 : public EffectTechnique
    {
    public:
        /**
         * Address: 0x008F3AC0 (FUN_008F3AC0, ??0EffectTechniqueD3D9@gal@gpg@@QAE@@Z)
         *
         * What it does:
         * Keeps `name`, a weak reference to `effect` and the technique handle;
         * throws "invalid effect specified" (line 36) when the effect is
         * already gone. The by-value `effect` is what `shared_from_this()`
         * builds at the `EffectD3D9` call sites.
         */
        EffectTechniqueD3D9(const char* name, boost::shared_ptr<EffectD3D9> effect, D3DXHANDLE handle);

        /**
         * Address: 0x008F3A20 (FUN_008F3A20, ??1EffectTechniqueD3D9@gal@gpg@@QAE@XZ)
         * Address: 0x008F3AA0 (FUN_008F3AA0, the scalar deleting destructor)
         * Slot: 0
         *
         * What it does:
         * Nothing of its own: the weak effect reference and the name go as
         * members, then the `EffectTechnique` base.
         */
        ~EffectTechniqueD3D9() override;

        /**
         * Address: 0x008F3850 (FUN_008F3850)
         * Slot: 1
         *
         * What it does:
         * Returns the technique name.
         */
        msvc8::string* GetName() override;

        /**
         * Address: 0x008F3C40 (FUN_008F3C40)
         * Slot: 2
         *
         * What it does:
         * Makes this the effect's technique and begins it; returns the number
         * of passes.
         */
        int BeginTechnique() override;

        /**
         * Address: 0x008F3EA0 (FUN_008F3EA0)
         * Slot: 3
         *
         * What it does:
         * Ends the technique and clears the begin/end tracking.
         */
        void EndTechnique() override;

        /**
         * Address: 0x008F4080 (FUN_008F4080)
         * Slot: 4
         *
         * What it does:
         * Begins pass `pass` of the active technique.
         */
        void BeginPass(int pass) override;

        /**
         * Address: 0x008F4260 (FUN_008F4260)
         * Slot: 5
         *
         * What it does:
         * Ends the active pass.
         */
        void EndPass() override;

        /**
         * Address: 0x008F4430 (FUN_008F4430)
         * Slot: 6
         *
         * What it does:
         * Reads the technique's bool annotation `annotationName`.
         */
        bool GetAnnotationBool(bool* outValue, const msvc8::string& annotationName) override;

        /**
         * Address: 0x008F4600 (FUN_008F4600)
         * Slot: 7
         *
         * What it does:
         * Reads the technique's int annotation `annotationName`.
         */
        bool GetAnnotationInt(int* outValue, const msvc8::string& annotationName) override;

        /**
         * Address: 0x008F47C0 (FUN_008F47C0)
         * Slot: 8
         *
         * What it does:
         * Reads the technique's float annotation `annotationName`.
         */
        bool GetAnnotationFloat(float* outValue, const msvc8::string& annotationName) override;

        /**
         * Address: 0x008F4980 (FUN_008F4980)
         * Slot: 9
         *
         * What it does:
         * Reads the technique's string annotation `annotationName`.
         */
        bool GetAnnotationString(msvc8::string* outValue, const msvc8::string& annotationName) override;

    public:
        msvc8::string name_;                 // +0x04
        boost::weak_ptr<EffectD3D9> effect_; // +0x20
        D3DXHANDLE handle_ = nullptr;        // +0x28
        bool beginEndActive_ = false;        // +0x2C
        std::uint8_t beginEndPadding_[3]{};  // +0x2D
    };

    static_assert(offsetof(EffectTechniqueD3D9, name_) == 0x04, "EffectTechniqueD3D9::name_ offset must be 0x04");
    static_assert(offsetof(EffectTechniqueD3D9, effect_) == 0x20, "EffectTechniqueD3D9::effect_ offset must be 0x20");
    static_assert(offsetof(EffectTechniqueD3D9, handle_) == 0x28, "EffectTechniqueD3D9::handle_ offset must be 0x28");
    static_assert(offsetof(EffectTechniqueD3D9, beginEndActive_) == 0x2C, "EffectTechniqueD3D9::beginEndActive_ offset must be 0x2C");
    static_assert(sizeof(EffectTechniqueD3D9) == 0x30, "EffectTechniqueD3D9 size must be 0x30");
} // namespace gpg::gal
