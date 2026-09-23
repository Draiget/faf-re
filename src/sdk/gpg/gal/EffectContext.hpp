#pragma once

#include <cstdint>

#include "gpg/core/containers/String.h"
#include "gpg/core/streams/MemBufferStream.h"
#include "gpg/gal/EffectMacro.hpp"
#include "legacy/containers/Vector.h"

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
         * Address: 0x00942CF0 (FUN_00942CF0, gpg::gal::EffectContext::operator=)
         *
         * What it does:
         * Member-wise assignment behind a self-check: source type, cache flag,
         * both paths, the shared source buffer and the macro list. One body,
         * called by both backends -- the D3D9 effect paths (0x00942D60,
         * 0x00942E50) and the D3D10 effect reset/assign (0x0094BF10,
         * 0x0094BFE0).
         */
        EffectContext& operator=(const EffectContext& other);

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

        /**
         * Address: 0x009402D0 (FUN_009402D0, gpg::gal::EffectContext::DefineMacro)
         *
         * IDA signature:
         * int __thiscall gpg::gal::EffectContext::DefineMacro(
         *     gpg::gal::EffectContext *this, char *name, char *value);
         *
         * What it does:
         * Adds one effect-macro key/value pair to this context's macro vector,
         * throwing `gpg::gal::Error("duplicate effect macro definition")` from
         * `Effect.cpp:76` when an entry with the same key already exists.
         */
        void DefineMacro(const char* name, const char* value);

        // The vptr the virtual destructor above installs occupies +0x00, so the
        // declared state starts at +0x04. The three constructors in
        // ContextInterfaces.cpp fix the rest: `mSourceType` is 0 for the default
        // context and 2 for the payload one (0x0093FD90), `mUseCache` is the
        // byte at +0x08, the two 0x1C `msvc8::string` lanes follow at +0x0C and
        // +0x28, and the four words at +0x44 are one `MemBuffer<char>` -
        // `mData.px`, `mData.pi` (the lane that takes `add_ref_copy()` and
        // `release()`), `mBegin`, `mEnd`. The 0x10 macro vector closes the
        // object at +0x54.
        std::uint32_t mSourceType{};             // +0x04
        bool mUseCache{};                        // +0x08
        msvc8::string mSourcePath;               // +0x0C
        msvc8::string mCachePath;                // +0x28
        gpg::MemBuffer<char> mSourceBuffer;      // +0x44
        msvc8::vector<EffectMacro> mMacros;      // +0x54
    };

    static_assert(offsetof(EffectContext, mSourceType) == 0x04, "EffectContext::mSourceType offset must be 0x04");
    static_assert(offsetof(EffectContext, mUseCache) == 0x08, "EffectContext::mUseCache offset must be 0x08");
    static_assert(offsetof(EffectContext, mSourcePath) == 0x0C, "EffectContext::mSourcePath offset must be 0x0C");
    static_assert(offsetof(EffectContext, mCachePath) == 0x28, "EffectContext::mCachePath offset must be 0x28");
    static_assert(offsetof(EffectContext, mSourceBuffer) == 0x44, "EffectContext::mSourceBuffer offset must be 0x44");
    static_assert(offsetof(EffectContext, mMacros) == 0x54, "EffectContext::mMacros offset must be 0x54");
    static_assert(sizeof(EffectContext) == 0x64, "EffectContext size must be 0x64");
}
