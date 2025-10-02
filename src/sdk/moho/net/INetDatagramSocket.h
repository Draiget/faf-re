#pragma once

#include "platform/Platform.h"

namespace moho 
{
	class INetDatagramHandler;
	struct CMessage;

	/**
     * VFTABLE: 0x00E03ED0
     * COL:  0x00E60900
     */
    class INetDatagramSocket
    {
    public:
        /**
         * Address: 0x0047EF40
         * Slot: 0
         * Demangled: public: __thiscall Moho::INetDatagramSocket::~INetDatagramSocket()
         */
        virtual ~INetDatagramSocket() = default;

        /**
         * Address: 0x00A82547
         * Slot: 1
         */
        virtual void SendDefault(CMessage* message, u_short) = 0;

        /**
         * Address: 0x00A82547
         * Slot: 2
         */
        virtual void Send(CMessage*, u_long address, u_short port) = 0;

        /**
         * Address: 0x00A82547
         * Slot: 3
         */
        virtual void Pull() = 0;

        /**
         * Address: 0x00A82547
         * Slot: 4
         */
        virtual HANDLE CreateEvent() = 0;
    };

    /**
     * Address: 0x0047F360
     *
     * @param port 
     * @param handler 
     * @return 
     */
    INetDatagramSocket* NET_OpenDatagramSocket(u_short port, INetDatagramHandler* handler); 

}
