#pragma once

namespace gpg::gal
{
    /**
     * VFTABLE: 0x00D47B38
     * COL:     0x00E530C8
     */
    class DrawIndexedContext
    {
    public:
        /**
         * Address: 0x0093F160 (FUN_0093F160)
         *
         * What it does:
         * Owns the scalar-deleting destructor thunk for draw-indexed context instances.
         */
        virtual ~DrawIndexedContext();
    };

    static_assert(sizeof(DrawIndexedContext) == 0x4, "DrawIndexedContext size must be 0x4");
}
