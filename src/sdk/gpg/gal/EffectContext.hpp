#pragma once

#include "gpg/core/containers/String.h"
#include "legacy/containers/Vector.h"

namespace gpg
{
    template <class T>
    class MemBuffer;
}

namespace gpg::gal
{
    class EffectMacro;

    /**
     * VFTABLE: 0x00D434D8
     * COL:     0x00E50FC8
     */
    class EffectContext
    {
    public:
        EffectContext() = default;

        /**
         * Address: 0x009428F0 (FUN_009428F0)
         *
         * bool,gpg::StrArg,gpg::StrArg,gpg::MemBuffer<char> const &,std::vector<gpg::gal::EffectMacro> const &
         *
         * What it does:
         * Initializes effect-source/cache paths, source-buffer ownership, and
         * effect-macro lanes for one effect-creation request.
         */
        EffectContext(
            bool useCachePayload,
            gpg::StrArg sourcePath,
            gpg::StrArg cachePath,
            const gpg::MemBuffer<char>& sourceBuffer,
            const msvc8::vector<EffectMacro>& macros
        );

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
