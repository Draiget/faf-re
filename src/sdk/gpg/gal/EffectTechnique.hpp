#pragma once

#include "boost/noncopyable.hpp"
#include "legacy/containers/String.h"

namespace gpg::gal
{
    /**
     * VFTABLE: 0x00D42CA0
     * COL:  0x00E508E4
     *
     * One technique of an Effect: begin it, run its passes, end it.
     * Backends: EffectTechniqueD3D9 (0x00D42CCC), EffectTechniqueD3D10
     * (0x00D435CC).
     */
    class EffectTechnique : private boost::noncopyable
    {
    public:
        /**
         * Address: 0x008F3820 (FUN_008F3820)
         *
         * What it does:
         * Installs the abstract technique vtable.
         */
        EffectTechnique();

        /**
         * Address: 0x008F3810 (FUN_008F3810)
         * Slot: 0
         *
         * What it does:
         * Reinstalls the abstract technique vtable; both backend destructors
         * inline it (0x008F3A8D, 0x00900FB9).
         */
        virtual ~EffectTechnique() = 0;

        /**
         * Slot: 1
         *
         * What it does:
         * The technique's name in the effect.
         */
        virtual msvc8::string* GetName() = 0;

        /**
         * Slot: 2
         *
         * What it does:
         * Makes this the effect's technique and begins it; returns the number
         * of passes.
         */
        virtual int BeginTechnique() = 0;

        /**
         * Slot: 3
         *
         * What it does:
         * Ends the technique `BeginTechnique` began.
         */
        virtual void EndTechnique() = 0;

        /**
         * Slot: 4
         *
         * What it does:
         * Begins pass `pass`.
         */
        virtual void BeginPass(int pass) = 0;

        /**
         * Slot: 5
         *
         * What it does:
         * Ends the current pass.
         */
        virtual void EndPass() = 0;

        /**
         * Slot: 6
         *
         * What it does:
         * Reads the technique's bool annotation `annotationName`; false when
         * it has none.
         */
        virtual bool GetAnnotationBool(bool* outValue, const msvc8::string& annotationName) = 0;

        /**
         * Slot: 7
         *
         * What it does:
         * Reads the technique's int annotation `annotationName`.
         */
        virtual bool GetAnnotationInt(int* outValue, const msvc8::string& annotationName) = 0;

        /**
         * Slot: 8
         *
         * What it does:
         * Reads the technique's float annotation `annotationName`.
         */
        virtual bool GetAnnotationFloat(float* outValue, const msvc8::string& annotationName) = 0;

        /**
         * Slot: 9
         *
         * What it does:
         * Reads the technique's string annotation `annotationName`.
         */
        virtual bool GetAnnotationString(msvc8::string* outValue, const msvc8::string& annotationName) = 0;
    };

    static_assert(sizeof(EffectTechnique) == 0x4, "gpg::gal::EffectTechnique size must be 0x4");
} // namespace gpg::gal
