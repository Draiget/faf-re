#pragma once

namespace gpg::gal
{
    /**
     * VFTABLE: 0x00D47B30
     * COL:     0x00E53080
     */
    class DrawContext
    {
    public:
        /**
         * Address: 0x0093F140 (FUN_0093F140)
         *
         * What it does:
         * Owns the scalar-deleting destructor thunk for draw-context interface instances.
         */
        virtual ~DrawContext();
    };

    static_assert(sizeof(DrawContext) == 0x4, "DrawContext size must be 0x4");
}
