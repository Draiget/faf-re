#pragma once

namespace gpg::gal
{
    /**
     * VFTABLE: 0x00D47C88
     * COL:     0x00E531A0
     */
    class Class
    {
    public:
        /**
         * Address: 0x00940930 (FUN_00940930)
         *
         * What it does:
         * Initializes one abstract `gal::Class` base lane by installing the class
         * vtable.
         */
        Class();

        /**
         * Address: 0x00940950 (FUN_00940950)
         *
         * What it does:
         * Owns the scalar-deleting destructor thunk for gal::Class instances.
         */
        virtual ~Class();
    };

    static_assert(sizeof(Class) == 0x4, "Class size must be 0x4");
}
