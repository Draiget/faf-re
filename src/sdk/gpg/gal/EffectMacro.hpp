#pragma once

#include <cstddef>

#include "legacy/containers/String.h"

namespace gpg::gal
{
    /**
     * VFTABLE: 0x00D43178
     * COL:     0x00E50F30
     */
    class EffectMacro
    {
    public:
        /**
         * Address: 0x008FAA20 (FUN_008FAA20)
         *
         * What it does:
         * Owns the scalar-deleting destructor thunk for effect macro entries.
         */
        virtual ~EffectMacro();

    public:
        msvc8::string keyText_;   // +0x04
        msvc8::string valueText_; // +0x20
    };

    static_assert(offsetof(EffectMacro, keyText_) == 0x04, "EffectMacro::keyText_ offset must be 0x04");
    static_assert(offsetof(EffectMacro, valueText_) == 0x20, "EffectMacro::valueText_ offset must be 0x20");
    static_assert(sizeof(EffectMacro) == 0x3C, "EffectMacro size must be 0x3C");
}
