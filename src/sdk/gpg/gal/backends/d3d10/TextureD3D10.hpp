#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/streams/MemBufferStream.h"
#include "gpg/gal/TextureContext.hpp"
#include "platform/Platform.h"

namespace gpg::gal
{
    struct TextureLockRectD3D10
    {
        int flags = 0;       // +0x00
        int level = 0;       // +0x04
        int pitch = 0;       // +0x08
        void* bits = nullptr; // +0x0C
    };

    /**
     * VFTABLE: 0x00D43B18
     * COL:  0x00E511E8
     * Source hints:
     *  - c:\work\rts\main\code\src\libs\gpggal\TextureD3D10.cpp
     */
    class TextureD3D10
    {
    public:
        /**
         * Address: 0x00903310 (FUN_00903310)
         *
         * What it does:
         * Initializes vtable/context lanes and clears retained texture lock/state members.
         */
        TextureD3D10();

        /**
         * Address: 0x00904050 (FUN_00904050)
         *
         * TextureContext const *,void *,void *
         *
         * What it does:
         * Initializes one D3D10 texture wrapper from caller context + retained texture/SRV
         * handles, then rebuilds mip/format-dependent lock state.
         */
        TextureD3D10(const TextureContext* context, void* texture, void* shaderResourceView);

        /**
         * Address: 0x00904030 (FUN_00904030)
         *
         * What it does:
         * Owns the deleting-destructor path and delegates body lanes to `FUN_00903E10`.
         */
        virtual ~TextureD3D10();

        /**
         * Address: 0x00903370 (FUN_00903370)
         *
         * What it does:
         * Returns the embedded texture-context lane at `this+0x04`.
         */
        virtual TextureContext* GetContext();

        /**
         * Address: 0x00903410 (FUN_00903410)
         *
         * What it does:
         * Maps one texture level and writes map metadata (`flags/level/pitch/bits`)
         * into caller output and cached per-level lock lanes.
         */
        virtual TextureLockRectD3D10* Lock(TextureLockRectD3D10* outRect, int level, const RECT* rect, int flags);

        /**
         * Address: 0x00903700 (FUN_00903700)
         *
         * What it does:
         * Unmaps one texture level and clears lock-tracking state lanes.
         */
        virtual int Unlock(int level);

        /**
         * Address: 0x00903390 (FUN_00903390)
         *
         * What it does:
         * Forwards to vtable-slot unlock path using the second stack argument.
         */
        virtual int Func1(int arg1, int level, int arg3, int arg4);

        /**
         * Address: 0x009038D0 (FUN_009038D0)
         *
         * What it does:
         * Serializes texture bytes into the caller-provided memory buffer.
         */
        virtual void SaveToBuffer(gpg::MemBuffer<char>* outBuffer);

        /**
         * Address: 0x00903CA0 (FUN_00903CA0)
         *
         * What it does:
         * Validates and returns the retained shader-resource-view lane.
         */
        void* GetShaderResourceViewOrThrow();

        /**
         * Address: 0x00903BE0 (FUN_00903BE0)
         *
         * What it does:
         * Validates and returns the retained texture lane.
         */
        void* GetTextureOrThrow();

        /**
         * Address: 0x00903D60 (FUN_00903D60)
         *
         * What it does:
         * Releases retained texture/state resources and resets texture context lanes.
         */
        void DestroyState();

        /**
         * Address: 0x00903E70 (FUN_00903E70)
         *
         * TextureContext const *,void *,void *
         *
         * What it does:
         * Rebuilds texture wrapper state from caller context + texture/SRV handles and
         * allocates per-level lock-history storage.
         */
        void InitializeState(const TextureContext* context, void* texture, void* shaderResourceView);

    public:
        TextureContext context_{};                // +0x04
        void* texture_ = nullptr;                 // +0x58
        void* stagingTexture_ = nullptr;          // +0x5C
        void* shaderResourceView_ = nullptr;      // +0x60
        bool lockActive_ = false;                 // +0x64
        std::uint8_t lockPadding_[3]{};           // +0x65
        int lockLevel_ = 0;                       // +0x68
        TextureLockRectD3D10* lockHistory_ = nullptr; // +0x6C
        int contextFormatBackup_ = 0;             // +0x70
    };

    static_assert(sizeof(TextureLockRectD3D10) == 0x10, "TextureLockRectD3D10 size must be 0x10");
    static_assert(offsetof(TextureD3D10, context_) == 0x04, "TextureD3D10::context_ offset must be 0x04");
    static_assert(offsetof(TextureD3D10, texture_) == 0x58, "TextureD3D10::texture_ offset must be 0x58");
    static_assert(offsetof(TextureD3D10, stagingTexture_) == 0x5C, "TextureD3D10::stagingTexture_ offset must be 0x5C");
    static_assert(offsetof(TextureD3D10, shaderResourceView_) == 0x60, "TextureD3D10::shaderResourceView_ offset must be 0x60");
    static_assert(offsetof(TextureD3D10, lockActive_) == 0x64, "TextureD3D10::lockActive_ offset must be 0x64");
    static_assert(offsetof(TextureD3D10, lockLevel_) == 0x68, "TextureD3D10::lockLevel_ offset must be 0x68");
    static_assert(offsetof(TextureD3D10, lockHistory_) == 0x6C, "TextureD3D10::lockHistory_ offset must be 0x6C");
    static_assert(offsetof(TextureD3D10, contextFormatBackup_) == 0x70, "TextureD3D10::contextFormatBackup_ offset must be 0x70");
    static_assert(sizeof(TextureD3D10) == 0x74, "TextureD3D10 size must be 0x74");
}
