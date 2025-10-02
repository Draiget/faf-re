#pragma once

#include "platform/Platform.h"

namespace moho
{
	class INetDatagramSocket;
	struct CMessage;

	/**
     * VFTABLE: 0x00E3EC88
     * COL:  0x00E97764
     */
    class INetDatagramHandler
    {
    public:
        /**
         * Address: 0x00A82547
         * Slot: 0
         */
        virtual void Pull(CMessage* msg, INetDatagramSocket*, u_long address, u_short port) = 0;
    };
    static_assert(sizeof(INetDatagramHandler) == 4, "INetDatagramHandler size should be 4");
} 
