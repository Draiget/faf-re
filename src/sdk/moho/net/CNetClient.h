// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once

#include "CClientBase.h"

namespace moho
{
    /**
     * VFTABLE: 0x00E16CF4
     * COL:  0x00E6AD78
     */
    class CNetClient : public CClientBase
	{
    public:
        /**
         * Address: 0x0053B930
         * Slot: 0
         * Demangled: Moho::CClientBase::dtr
         */
        virtual ~CNetClient();
        /**
         * Address: 0x0053C960
         * Slot: 1
         * Demangled: Moho::CClientBase::NoEjectionPending
         */
        virtual bool NoEjectionPending() = 0;
        /**
         * Address: 0x0053DC30
         * Slot: 2
         * Demangled: Moho::CNetClient::Func2
         */
        virtual void Func2() = 0;
        /**
         * Address: 0x0053DCC0
         * Slot: 3
         * Demangled: Moho::CNetClient::Func3
         */
        virtual void Func3() = 0;
        /**
         * Address: 0x0053CA60
         * Slot: 4
         * Demangled: Moho::CClientBase::Func4
         */
        virtual void Func4() = 0;
        /**
         * Address: 0x0053CA90
         * Slot: 5
         * Demangled: Moho::CClientBase::Func5
         */
        virtual void Func5() = 0;
        /**
         * Address: 0x0053CAD0
         * Slot: 6
         * Demangled: Moho::CClientBase::Func6
         */
        virtual void Func6() = 0;
        /**
         * Address: 0x0053DD60
         * Slot: 7
         * Demangled: Moho::CNetClient:Process
         */
        virtual void CNetClient_Process() = 0;
        /**
         * Address: 0x0053C9A0
         * Slot: 8
         * Demangled: Moho::CClientBase::Func7
         */
        virtual void Func7() = 0;
        /**
         * Address: 0x0053CA20
         * Slot: 9
         * Demangled: Moho::CClientBase::Func8
         */
        virtual void Func8() = 0;
        /**
         * Address: 0x0053CB10
         * Slot: 10
         * Demangled: Moho::CClientBase::Eject
         */
        virtual void Eject() = 0;
        /**
         * Address: 0x0053CC60
         * Slot: 11
         * Demangled: Moho::CClientBase::Func9
         */
        virtual void Func9() = 0;
        /**
         * Address: 0x0053CDC0
         * Slot: 12
         * Demangled: Moho::CClientBase::Func10
         */
        virtual void Func10() = 0;
        /**
         * Address: 0x0053BC20
         * Slot: 13
         * Demangled: Moho::CNetClient::Func11
         */
        virtual void Func11() = 0;
        /**
         * Address: 0x0053DE20
         * Slot: 14
         * Demangled: Moho::CNetClient::Open
         */
        virtual void Open() = 0;
        /**
         * Address: 0x0053DE50
         * Slot: 15
         * Demangled: Moho::CNetClient::Debug
         */
        virtual void Debug() = 0;
    };
} // namespace moho
