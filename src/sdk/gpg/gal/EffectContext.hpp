#pragma once

namespace gpg::gal
{
    /**
     * VFTABLE: 0x00D434D8
     * COL:     0x00E50FC8
     */
    class EffectContext
    {
    public:
        /**
         * Address: 0x008FE8B0 (FUN_008FE8B0)
         *
         * What it does:
         * Owns the scalar-deleting destructor thunk for effect-context interface instances.
         */
        virtual ~EffectContext();
    };

    static_assert(sizeof(EffectContext) == 0x4, "EffectContext size must be 0x4");
}
