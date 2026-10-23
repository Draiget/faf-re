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
        EffectMacro() = default;

        /**
         * Address: 0x008FA9A0 (FUN_008FA9A0)
         *
         * What it does:
         * Copy-constructs one effect-macro entry by assigning both key/value
         * text lanes from source.
         */
        EffectMacro(const EffectMacro& other);

        /**
         * Address: 0x0093F8B0 (FUN_0093F8B0)
         *
         * What it does:
         * Constructs one effect-macro entry from raw C-string key/value pairs.
         */
        EffectMacro(const char* keyText, const char* valueText);

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
