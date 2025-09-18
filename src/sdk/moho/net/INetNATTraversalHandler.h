#pragma once
#include "CMessage.h"
#include "boost/sp_counted_base.h"

namespace moho
{
	/**
	 * VFTABLE: 0x00E060C8
	 * COL:		0x00E60E9C
	 */
	class INetNATTraversalHandler
	{
	public:
		/**
		 * Address: 0x00A82547
		 * Slot: 0
		 */
		virtual void Func1(CMessage* msg) = 0;

		/**
		 * Address: 0x00A82547
		 * Slot: 1
		 */
		virtual void ReceivePacket(u_long addr, u_short port, void* dat, size_t size) = 0;
	};
}
