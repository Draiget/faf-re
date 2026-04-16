#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"

namespace gpg::gal
{
    struct CursorPixelSourceRuntime;

    /**
     * VFTABLE: 0x00D47B20
     * COL:     0x00E52FF0
     */
    class CursorContext
    {
    public:
        /**
         * Address: 0x0093EEA0 (FUN_0093EEA0, __imp_??0CursorContext@gal@gpg@@QAE@XZ)
         *
         * What it does:
         * Initializes cursor hotspot/pixel-source/control lanes to zero/null.
         */
        CursorContext();

        /**
         * Address: 0x0093EF20 (FUN_0093EF20)
         *
         * int,int,CursorPixelSourceRuntime *,boost::detail::sp_counted_base *
         *
         * What it does:
         * Initializes hotspot/pixel-source lanes from caller payload and
         * preserves legacy shared-count transfer side effects on cursor control.
         */
        CursorContext(
            std::int32_t hotspotX,
            std::int32_t hotspotY,
            CursorPixelSourceRuntime* pixelSource,
            boost::detail::sp_counted_base* cursorControl
        );

        /**
         * Address: 0x0093EEC0 (FUN_0093EEC0)
         *
         * What it does:
         * Releases the retained cursor-control shared-count block during destruction.
         */
        virtual ~CursorContext();

    public:
        std::int32_t hotspotX_ = 0;                    // +0x04
        std::int32_t hotspotY_ = 0;                    // +0x08
        CursorPixelSourceRuntime* pixelSource_ = nullptr; // +0x0C
        boost::detail::sp_counted_base* cursorControl_ = nullptr; // +0x10
    };

    static_assert(offsetof(CursorContext, hotspotX_) == 0x04, "CursorContext::hotspotX_ offset must be 0x04");
    static_assert(offsetof(CursorContext, hotspotY_) == 0x08, "CursorContext::hotspotY_ offset must be 0x08");
    static_assert(offsetof(CursorContext, pixelSource_) == 0x0C, "CursorContext::pixelSource_ offset must be 0x0C");
    static_assert(offsetof(CursorContext, cursorControl_) == 0x10, "CursorContext::cursorControl_ offset must be 0x10");
    static_assert(sizeof(CursorContext) == 0x14, "CursorContext size must be 0x14");
}
