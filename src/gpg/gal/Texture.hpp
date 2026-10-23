#pragma once

#include <cstddef>

#include "boost/noncopyable.hpp"
#include "boost/shared_ptr.h"
#include "gpg/core/streams/MemBufferStream.h"
#include "platform/Platform.h"

namespace gpg::gal
{
    class TextureContext;

    /**
     * One mapped mip level: what `Texture::Lock` hands back and
     * `Texture::Unlock(TextureLockRect)` takes to release it. `flags` are the
     * gal lock flags the caller asked for (on D3D9 bit 0 becomes
     * `D3DLOCK_DISCARD`, bit 1 `D3DLOCK_READONLY` - 0x0094A355..0x0094A36A);
     * `pitch` and `bits` are the mapped row pitch and first texel. Both
     * backends fill it in field order (0x0094A3E2..0x0094A3FB on D3D9).
     */
    struct TextureLockRect
    {
        int flags = 0;        // +0x00
        int level = 0;        // +0x04
        int pitch = 0;        // +0x08
        void* bits = nullptr; // +0x0C
    };

    static_assert(offsetof(TextureLockRect, level) == 0x04, "TextureLockRect::level offset must be 0x04");
    static_assert(offsetof(TextureLockRect, pitch) == 0x08, "TextureLockRect::pitch offset must be 0x08");
    static_assert(offsetof(TextureLockRect, bits) == 0x0C, "TextureLockRect::bits offset must be 0x0C");
    static_assert(sizeof(TextureLockRect) == 0x10, "TextureLockRect size must be 0x10");

    /**
     * VFTABLE: 0x00D43AFC
     * COL:  0x00E5119C
     *
     * The backend-neutral texture. `TextureD3D9` (vtable 0x00D481D4) and
     * `TextureD3D10` (0x00D43B18) implement it; everything above the backends
     * holds one as `boost::shared_ptr<Texture>` - e.g. the shipped
     * `?SheetGetBaseTexture@RD3DTextureResource@Moho@@UAE?AV?$shared_ptr@VTexture@gal@gpg@@@boost@@XZ`.
     */
    class Texture : private boost::noncopyable
    {
    public:
        /**
         * Address: 0x00903300 (FUN_00903300)
         *
         * What it does:
         * Installs the abstract texture vtable.
         */
        Texture();

        /**
         * Slot: 0 (`_purecall` in the base table, so the destructor is pure)
         *
         * What it does:
         * Derived destructors reinstall 0x00D43AFC as their last step
         * (0x00903E51 in `TextureD3D10`, 0x0094AAD1 in `TextureD3D9`).
         */
        virtual ~Texture() = 0;

        /**
         * Address: 0x008E7C50 (FUN_008E7C50)
         *
         * What it does:
         * Creates one texture on the active device - slot 10 (`[vtbl+0x28]`)
         * of `Device::GetInstance()`.
         */
        static boost::shared_ptr<Texture> Create(const TextureContext& context);

        /**
         * Slot: 1
         *
         * What it does:
         * Returns the descriptor the texture was built from.
         */
        virtual TextureContext* GetContext() = 0;

        /**
         * Slot: 2
         *
         * What it does:
         * Maps mip `level` (the whole level when `rect` is empty) and returns
         * the mapping. The rect is always read, never null-tested.
         */
        virtual TextureLockRect Lock(int level, const RECT& rect, int flags) = 0;

        /**
         * Slot: 4
         *
         * What it does:
         * Releases the mapping `Lock` returned: forwards `lock.level` to slot 3
         * (0x00903390 / 0x0094A090, `ret 0x10` - the rect arrives by value).
         *
         * Slots 3 and 4 are one overloaded name; MSVC lays overloaded virtuals
         * out in reverse declaration order, so this one is declared first.
         */
        virtual int Unlock(TextureLockRect lock) = 0;

        /**
         * Slot: 3
         *
         * What it does:
         * Unmaps mip `level`.
         */
        virtual int Unlock(int level) = 0;

        /**
         * Slot: 5
         *
         * What it does:
         * Serializes the texture into `outBuffer`.
         */
        virtual void SaveToBuffer(gpg::MemBuffer<char>* outBuffer) = 0;
    };

    static_assert(sizeof(Texture) == 0x04, "Texture size must be 0x04");
} // namespace gpg::gal
