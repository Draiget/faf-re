#pragma once

#include "boost/noncopyable.hpp"
#include "boost/shared_ptr.h"
#include "legacy/containers/Vector.h"

namespace gpg::gal
{
    class EffectContext;
    class EffectTechnique;
    class EffectVariable;

    /**
     * VFTABLE: 0x00D47D24
     * COL:  0x00E53238
     *
     * One compiled effect: its techniques and variables are looked up by
     * name. Backends: EffectD3D9 (0x00D47D6C), EffectD3D10 (0x00D4885C).
     */
    class Effect : private boost::noncopyable
    {
    public:
        /**
         * Address: 0x009415A0 (FUN_009415A0)
         *
         * What it does:
         * Installs the abstract effect vtable.
         */
        Effect();

        /**
         * Address: 0x0093F5B0 (FUN_0093F5B0)
         * Mangled: ?Create@Effect@gal@gpg@@SA?AV?$shared_ptr@VEffect@gal@gpg@@@boost@@ABVEffectContext@23@@Z
         *
         * What it does:
         * Has the active device build the effect `context` describes.
         */
        static boost::shared_ptr<Effect> Create(const EffectContext& context);

        /**
         * Address: 0x00941590 (FUN_00941590)
         * Slot: 0
         *
         * What it does:
         * Reinstalls the abstract effect vtable; both backend destructors
         * inline it (0x00942E0F, 0x0094BFC1).
         */
        virtual ~Effect() = 0;

        /**
         * Slot: 1
         *
         * What it does:
         * The context the effect was built from.
         */
        virtual EffectContext* GetContext() = 0;

        /**
         * Slot: 2
         *
         * What it does:
         * Appends every technique the device can run to `outTechniques`.
         */
        virtual void GetTechniques(msvc8::vector<boost::shared_ptr<EffectTechnique>>& outTechniques) = 0;

        /**
         * Slot: 3
         *
         * What it does:
         * The variable (effect parameter) called `name`; throws when there is
         * none.
         */
        virtual boost::shared_ptr<EffectVariable> GetVariable(const char* name) = 0;

        /**
         * Slot: 4
         *
         * What it does:
         * The technique called `name`; throws when there is none.
         */
        virtual boost::shared_ptr<EffectTechnique> GetTechnique(const char* name) = 0;

        /**
         * Slot: 5
         *
         * What it does:
         * Re-acquires device resources after a device reset.
         */
        virtual void OnReset() = 0;

        /**
         * Slot: 6
         *
         * What it does:
         * Releases device resources before a device reset.
         */
        virtual void OnLost() = 0;
    };

    static_assert(sizeof(Effect) == 0x4, "gpg::gal::Effect size must be 0x4");
} // namespace gpg::gal
