#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"
#include "gpg/gal/Texture.hpp"
#include "platform/Platform.h"

namespace gpg::gal
{
    /**
     * VFTABLE: 0x00D47B20
     * COL:     0x00E52FF0
     *
     * A hardware cursor image: the hotspot and the texture holding the pixels.
     * `CD3DDevice::SetCursor` (0x0042EB40) fills one in place - hotspot into
     * +0x04/+0x08, the texture handle into +0x0C/+0x10 with a use-count
     * retain - and hands it to `Device::SetCursor`.
     */
    class CursorContext
    {
    public:
        /**
         * Address: 0x0093EEA0 (FUN_0093EEA0, __imp_??0CursorContext@gal@gpg@@QAE@XZ)
         *
         * What it does:
         * Initializes a zero hotspot and an empty texture handle.
         */
        CursorContext();

        /**
         * Address: 0x0093EF20 (FUN_0093EF20)
         *
         * What it does:
         * Copies the two hotspot ints out of `hotspot` and retains the by-value
         * texture handle (`ret 0xC`: one pointer, one 8-byte handle). The
         * binary keeps the body but nothing calls it; the hotspot's declared
         * type is not observable, `POINT` has its layout.
         */
        CursorContext(const POINT& hotspot, boost::shared_ptr<Texture> texture);

        /**
         * Address: 0x0093EE60 (FUN_0093EE60, __imp_??1CursorContext@gal@gpg@@UAE@XZ)
         * Address: 0x0093EEC0 (FUN_0093EEC0, scalar deleting destructor)
         *
         * What it does:
         * Releases the texture handle.
         */
        virtual ~CursorContext();

    public:
        std::int32_t hotspotX_ = 0;           // +0x04
        std::int32_t hotspotY_ = 0;           // +0x08
        boost::shared_ptr<Texture> texture_;  // +0x0C
    };

    static_assert(offsetof(CursorContext, hotspotX_) == 0x04, "CursorContext::hotspotX_ offset must be 0x04");
    static_assert(offsetof(CursorContext, hotspotY_) == 0x08, "CursorContext::hotspotY_ offset must be 0x08");
    static_assert(offsetof(CursorContext, texture_) == 0x0C, "CursorContext::texture_ offset must be 0x0C");
    static_assert(sizeof(CursorContext) == 0x14, "CursorContext size must be 0x14");
}
