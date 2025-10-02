#pragma once

#include "INetNATTraversalHandler.h"
#include "boost/shared_ptr.h"

namespace moho
{
	/**
	 * VFTABLE: 0x00E3D740
	 * COL:		0x00E969A4
	 */
	class INetNATTraversalProvider
	{
	public:
		/**
		 * Address: 0x00A82547
		 * Slot: 0
		 */
		virtual void SetHandler(int port, boost::shared_ptr<INetNATTraversalHandler>* handler) = 0;

		/**
		 * Address: 0x00A82547
		 * Slot: 1
		 */
		virtual void ReceivePacket(u_long address, u_short port, const char* dat, size_t size) = 0;
	};
}
