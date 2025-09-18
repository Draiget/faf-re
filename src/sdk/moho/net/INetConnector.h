#pragma once

#include "General.h"
#include "platform/Platform.h"

namespace moho
{
	class CNetUDPConnection;

    /**
     * VFTABLE: 0x00E03CB0
     * COL:  0x00E6081C
     */
	class INetConnector
	{
	public:
        /**
	     * Address: 0x0047EAE0
	     * Slot: 0
	     * Demangled: public: __thiscall Moho::INetConnector::~INetConnector()
	     */
        virtual ~INetConnector() = default;

        /**
         * Address: 0x00A82547
         * Slot: 1
         * Demangled: _purecall
         */
        virtual void Destroy() = 0;

        /**
         * Address: 0x00A82547
         * Slot: 2
         * Demangled: _purecall
         */
        virtual ENetProtocolType GetProtocol() = 0;

        /**
         * Address: 0x00A82547
         * Slot: 3
         * Demangled: _purecall
         */
        virtual u_short GetLocalPort() = 0;

        /**
         * Address: 0x00A82547
         * Slot: 4
         * Demangled: _purecall
         */
        virtual CNetUDPConnection* Connect(u_long address, u_short port) = 0;

        /**
         * Address: 0x00A82547
         * Slot: 5
         * Demangled: _purecall
         */
        virtual bool FindNextAddr(u_long& outAddress, u_short& outPort) = 0;

        /**
         * Address: 0x00A82547
         * Slot: 6
         * Demangled: _purecall
         */
        virtual void Accept() = 0;

        /**
         * Address: 0x00A82547
         * Slot: 7
         * Demangled: _purecall
         */
        virtual int Reject(u_long address, u_short port) = 0;

        /**
         * Address: 0x00A82547
         * Slot: 8
         * Demangled: _purecall
         */
        virtual void Pull() = 0;

        /**
         * Address: 0x00A82547
         * Slot: 9
         * Demangled: _purecall
         */
        virtual void Push() = 0;

        /**
         * Address: 0x00A82547
         * Slot: 10
         * Demangled: _purecall
         */
        virtual void SelectEvent() = 0;

        /**
         * Address: 0x0047EAD0
         * Slot: 11
         * Demangled: Moho::INetConnector::Debug
         */
        virtual void Debug() = 0;

        /**
         * Address: 0x00A82547
         * Slot: 12
         * Demangled: _purecall
         */
        virtual SendStampView& SnapshotSendStamps(SendStampView& out, int windowMs) = 0;
	};
}
