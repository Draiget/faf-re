#pragma once

#include <cstddef>

namespace gpg::gal
{
    class CursorContext;

    /**
     * VFTABLE: 0x00D43018
     * COL:  0x00E50C38
     */
    class CursorD3D10
    {
    public:
        /**
         * Address: 0x008F8090 (FUN_008F8090)
         *
         * What it does:
         * Initializes one cursor wrapper and clears retained native handle lanes.
         */
        CursorD3D10();

        /**
         * Address: 0x008F8360 (FUN_008F8360)
         *
         * What it does:
         * Owns the deleting-destructor path and delegates cleanup body semantics.
         */
        virtual ~CursorD3D10();

        /**
         * Address: 0x008F80D0 (FUN_008F80D0)
         *
         * What it does:
         * Restores the previous native cursor, destroys retained icon state, and
         * clears both cursor/icon handle lanes.
         */
        void Destroy();

        /**
         * Address: 0x008F83B0 (FUN_008F83B0)
         *
         * CursorContext const *
         *
         * What it does:
         * Rebuilds icon/cursor state from one cursor context and applies the icon
         * as the current native cursor.
         */
        void* SetCursor(const CursorContext* context);

        /**
         * Address: 0x008F8430 (FUN_008F8430)
         *
         * What it does:
         * Validates icon initialization and applies the retained icon as current cursor.
         */
        void* InitCursor();

        /**
         * Address: 0x008F84F0 (FUN_008F84F0)
         *
         * bool
         *
         * What it does:
         * Validates icon initialization and drives native `ShowCursor` count loops
         * for hide/show transitions.
         */
        int ShowCursor(bool show);

    public:
        void* cursorHandle_ = nullptr; // +0x04
        void* iconHandle_ = nullptr;   // +0x08
    };

    static_assert(offsetof(CursorD3D10, cursorHandle_) == 0x04, "CursorD3D10::cursorHandle_ offset must be 0x04");
    static_assert(offsetof(CursorD3D10, iconHandle_) == 0x08, "CursorD3D10::iconHandle_ offset must be 0x08");
    static_assert(sizeof(CursorD3D10) == 0x0C, "CursorD3D10 size must be 0x0C");
}
