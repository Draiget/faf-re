// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once
#include <cstdint>

#include "moho/ai/CAiSiloBuildImpl.h"
#include "moho/misc/WeakObject.h"

namespace moho { class Unit; class UserUnit; } // forward decl

namespace moho {
    /**
     * VFTABLE: 0x00E2A514
     * COL:  0x00E83F24
     */
    class IUnit : public WeakObject
    {
    public:
        /**
         * Address: 0x006A48C0
         * Slot: 0
         * Demangled: public: virtual class Unit const near * __thiscall IUnit::IsUnit(void)const
         */
        virtual Unit const* IsUnit() const = 0;

        /**
         * Address: 0x006A48B0
         * Slot: 1
         * Demangled: public: virtual class Unit near * __thiscall IUnit::IsUnit(void)
         */
        virtual Unit* IsUnit() = 0;

        /**
         * Address: 0x006A48E0
         * Slot: 2
         * Demangled: public: virtual class UserUnit const near * __thiscall IUnit::IsUserUnit(void)const
         */
        virtual UserUnit const* IsUserUnit() const = 0;

        /**
         * Address: 0x006A48D0
         * Slot: 3
         * Demangled: public: virtual class UserUnit near * __thiscall IUnit::IsUserUnit(void)
         */
        virtual UserUnit* IsUserUnit() = 0;

        /**
         * Address: 0x00A82547
         * Slot: 4
         * Demangled: _purecall
         */
        virtual void purecall4() = 0;

        /**
         * Address: 0x00A82547
         * Slot: 5
         * Demangled: _purecall
         */
        virtual void purecall5() = 0;

        /**
         * Address: 0x00A82547
         * Slot: 6
         * Demangled: _purecall
         */
        virtual void purecall6() = 0;

        /**
         * Address: 0x00A82547
         * Slot: 7
         * Demangled: _purecall
         */
        virtual void purecall7() = 0;

        /**
         * Address: 0x00A82547
         * Slot: 8
         * Demangled: _purecall
         */
        virtual void purecall8() = 0;

        /**
         * Address: 0x00A82547
         * Slot: 9
         * Demangled: _purecall
         */
        virtual void purecall9() = 0;

        /**
         * Address: 0x00A82547
         * Slot: 10
         * Demangled: _purecall
         */
        virtual void purecall10() = 0;

        /**
         * Address: 0x00A82547
         * Slot: 11
         * Demangled: _purecall
         */
        virtual void purecall11() = 0;

        /**
         * Address: 0x00A82547
         * Slot: 12
         * Demangled: _purecall
         */
        virtual void purecall12() = 0;

        /**
         * Address: 0x00A82547
         * Slot: 13
         * Demangled: _purecall
         */
        virtual void purecall13() = 0;

        /**
         * Address: 0x00A82547
         * Slot: 14
         * Demangled: _purecall
         */
        virtual void purecall14() = 0;

        /**
         * Address: 0x00A82547
         * Slot: 15
         * Demangled: _purecall
         */
        virtual void purecall15() = 0;

        /**
         * Address: 0x00A82547
         * Slot: 16
         * Demangled: _purecall
         */
        virtual void purecall16() = 0;

        /**
         * Address: 0x00A82547
         * Slot: 17
         * Demangled: _purecall
         */
        virtual void purecall17() = 0;

        /**
         * Address: 0x00A82547
         * Slot: 18
         * Demangled: _purecall
         */
        virtual void purecall18() = 0;

        /**
         * Address: 0x00A82547
         * Slot: 19
         * Demangled: _purecall
         */
        virtual void purecall19() = 0;

        /**
         * Address: 0x00A82547
         * Slot: 20
         * Demangled: _purecall
         */
        virtual void purecall20() = 0;

        /**
         * Address: 0x00A82547
         * Slot: 21
         * Demangled: _purecall
         */
        virtual void purecall21() = 0;
    };

    static_assert(sizeof(IUnit) == 0x08, "IUnit head must be 8 bytes");
} 
