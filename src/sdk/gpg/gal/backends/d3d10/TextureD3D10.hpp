#pragma once

#include <cstddef>
#include <cstdint>

#include <d3d10.h>

#include "gpg/core/streams/MemBufferStream.h"
#include "gpg/gal/Texture.hpp"
#include "gpg/gal/TextureContext.hpp"
#include "platform/Platform.h"

namespace gpg::gal
{
    /**
     * VFTABLE: 0x00D43B18
     * COL:  0x00E511E8
     * Source hints:
     *  - c:\work\rts\main\code\src\libs\gpggal\TextureD3D10.cpp
     */
    class TextureD3D10 : public Texture
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
        TextureD3D10(
            const TextureContext* context, ID3D10Texture2D* texture, ID3D10ShaderResourceView* shaderResourceView
        );

        /**
         * Address: 0x00904030 (FUN_00904030)
         *
         * What it does:
         * Owns the deleting-destructor path and delegates body lanes to `FUN_00903E10`.
         */
        ~TextureD3D10() override;

        /**
         * Address: 0x00903370 (FUN_00903370)
         *
         * What it does:
         * Returns the embedded texture-context lane at `this+0x04`.
         */
        TextureContext* GetContext() override;

        /**
         * Address: 0x00903410 (FUN_00903410)
         *
         * What it does:
         * Maps one texture level (the rect is ignored - D3D10 maps whole
         * levels), records the mapping in `lockHistory_[level]` and returns it.
         */
        TextureLockRect Lock(int level, const RECT& rect, int flags) override;

        /**
         * Address: 0x00903390 (FUN_00903390)
         *
         * What it does:
         * Releases one mapping: `Unlock(lock.level)` through the vtable.
         */
        int Unlock(TextureLockRect lock) override;

        /**
         * Address: 0x00903700 (FUN_00903700)
         *
         * What it does:
         * Unmaps one texture level and clears lock-tracking state lanes.
         */
        int Unlock(int level) override;

        /**
         * Address: 0x009038D0 (FUN_009038D0)
         *
         * What it does:
         * Serializes texture bytes into the caller-provided memory buffer.
         */
        void SaveToBuffer(gpg::MemBuffer<char>* outBuffer) override;

        /**
         * Address: 0x00903CA0 (FUN_00903CA0)
         *
         * What it does:
         * Validates and returns the retained shader-resource-view lane.
         */
        ID3D10ShaderResourceView* GetShaderResourceViewOrThrow();

        /**
         * Address: 0x00903BE0 (FUN_00903BE0)
         *
         * What it does:
         * Validates and returns the retained texture lane.
         */
        ID3D10Texture2D* GetTextureOrThrow();

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
        void InitializeState(
            const TextureContext* context, ID3D10Texture2D* texture, ID3D10ShaderResourceView* shaderResourceView
        );

    public:
        TextureContext context_{};                // +0x04
        ID3D10Texture2D* texture_ = nullptr;                     // +0x58
        ID3D10Texture2D* stagingTexture_ = nullptr;              // +0x5C
        ID3D10ShaderResourceView* shaderResourceView_ = nullptr; // +0x60
        bool lockActive_ = false;                 // +0x64
        std::uint8_t lockPadding_[3]{};           // +0x65
        int lockLevel_ = 0;                       // +0x68
        TextureLockRect* lockHistory_ = nullptr;  // +0x6C
        int contextFormatBackup_ = 0;             // +0x70
    };

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
