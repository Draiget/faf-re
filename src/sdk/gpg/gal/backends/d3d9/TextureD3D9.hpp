#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/streams/MemBufferStream.h"
#include "gpg/gal/D3D9Utils.h"
#include "gpg/gal/Texture.hpp"
#include "gpg/gal/TextureContext.hpp"

namespace gpg::gal
{
    /**
     * VFTABLE: 0x00D481D4
     * COL:  0x00E53720
     * Source hints:
     *  - c:\work\rts\main\code\src\libs\gpggal\TextureD3D9.cpp
     */
    class TextureD3D9 : public Texture
    {
    public:
        /**
         * Address: 0x0094A030 (FUN_0094A030)
         *
         * What it does:
         * Initializes vtable/context/resource state for a new D3D9 texture wrapper.
         */
        TextureD3D9();

        /**
         * Address: 0x0094AB80 (FUN_0094AB80)
         *
         * What it does:
         * Initializes one texture wrapper and binds caller context plus
         * one native texture payload.
         */
        TextureD3D9(const TextureContext* context, void* texture);

        /**
         * Address: 0x0094AB60 (FUN_0094AB60)
         *
         * What it does:
         * Owns the deleting-destructor path and delegates to `FUN_0094AA90` body semantics.
         */
        ~TextureD3D9() override;

        /**
         * Address: 0x0094A080 (FUN_0094A080)
         *
         * What it does:
         * Returns the embedded texture-context state block at `this+0x04`.
         */
        TextureContext* GetContext() override;

        /**
         * Address: 0x0094A150 (FUN_0094A150)
         *
         * What it does:
         * Locks one level of the 2D texture (the whole level when `rect` is
         * empty) and returns the mapping.
         */
        TextureLockRect Lock(int level, const RECT& rect, int flags) override;

        /**
         * Address: 0x0094A090 (FUN_0094A090)
         *
         * What it does:
         * Releases one mapping: `Unlock(lock.level)` through the vtable.
         */
        int Unlock(TextureLockRect lock) override;

        /**
         * Address: 0x0094A410 (FUN_0094A410)
         *
         * What it does:
         * Unlocks the active texture level and clears lock-tracking state.
         */
        int Unlock(int level) override;

        /**
         * Address: 0x0094A630 (FUN_0094A630)
         *
         * What it does:
         * Serializes level-0 texture surface bytes into the caller-provided memory buffer.
         */
        void SaveToBuffer(gpg::MemBuffer<char>* outBuffer) override;

        /**
         * Address: 0x0094A0A0 (FUN_0094A0A0)
         *
         * What it does:
         * Returns the retained D3D texture pointer when the context type is 2D (`1`).
         */
        void* GetTexture1() const;

        /**
         * Address: 0x0094A0B0 (FUN_0094A0B0)
         *
         * What it does:
         * Returns the retained D3D texture pointer when the context type is volume (`2`).
         */
        void* GetTexture2() const;

        /**
         * Address: 0x0094A0C0 (FUN_0094A0C0)
         *
         * What it does:
         * Returns the retained D3D texture pointer when the context type is cube (`3`).
         */
        void* GetTexture3() const;

        /**
         * Address: 0x0094A980 (FUN_0094A980)
         *
         * What it does:
         * Resets texture resources and reinitializes context state.
         */
        void Reset();

        /**
         * Address: 0x0094AAF0 (FUN_0094AAF0)
         *
         * What it does:
         * Resets prior texture state, copies caller context metadata, assigns a
         * new native texture handle, and clears copied source-data lanes.
         */
        void SetTexture(const TextureContext* context, void* texture);

    public:
        TextureContext context_{}; // +0x04
        void* texture_ = nullptr;  // +0x58
        bool locking_ = false;     // +0x5C
        std::uint8_t lockPadding_[3]{}; // +0x5D
        int level_ = 0;            // +0x60
    };

    static_assert(offsetof(TextureD3D9, context_) == 0x04, "TextureD3D9::context_ offset must be 0x04");
    static_assert(offsetof(TextureD3D9, texture_) == 0x58, "TextureD3D9::texture_ offset must be 0x58");
    static_assert(offsetof(TextureD3D9, locking_) == 0x5C, "TextureD3D9::locking_ offset must be 0x5C");
    static_assert(offsetof(TextureD3D9, level_) == 0x60, "TextureD3D9::level_ offset must be 0x60");
    static_assert(sizeof(TextureD3D9) == 0x64, "TextureD3D9 size must be 0x64");
}
