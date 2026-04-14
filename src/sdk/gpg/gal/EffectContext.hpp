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
        /**
         * Address: 0x0093FBE0 (FUN_0093FBE0, gpg::gal::EffectContext::EffectContext)
         *
         * What it does:
         * Initializes effect-context source/cache paths, source-buffer ownership,
         * and macro-vector lanes to empty defaults.
         */
        EffectContext();

        /**
         * Address: 0x008FE7E0 (FUN_008FE7E0, gpg::gal::EffectContext::EffectContext)
         *
         * What it does:
         * Copies effect-context source/cache paths, source-buffer shared-count
         * ownership, and macro-vector lanes from another context.
         */
        EffectContext(const EffectContext& other);

        /**
         * Address: 0x0093FD90 (FUN_0093FD90, gpg::gal::EffectContext::EffectContext)
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
         * Address: 0x0093F950 (FUN_0093F950, gpg::gal::EffectContext::~EffectContext)
         * Address: 0x008FE8B0 (FUN_008FE8B0, scalar deleting destructor thunk owner)
         *
         * What it does:
         * Releases effect-context macro/source lanes and services deleting
         * destructor thunk ownership.
         */
        virtual ~EffectContext();
    };

    static_assert(sizeof(EffectContext) == 0x4, "EffectContext size must be 0x4");
}
