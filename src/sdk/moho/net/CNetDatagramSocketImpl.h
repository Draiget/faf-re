#pragma once
#include "INetDatagramSocket.h"

namespace moho
{
	/**
	 * VFTABLE: 0x00E03EE8
	 * COL:		0x00E608B4
	 *
	 * Log/code strings:
	 *  - CNetDatagramSocketImpl::Send: send() failed: %s
	 *  - CNetBroadcastSocketImpl::Pull: recv() failed: %s
	 */
	class CNetDatagramSocketImpl :
		public INetDatagramSocket
	{
	public:
		/**
		 * Address: 0x0047F050
		 */
		~CNetDatagramSocketImpl() override;

		/**
		 * Address: 0x0047F0D0
		 *
		 * @param msg 
		 * @param port 
		 */
		void SendDefault(CMessage* msg, u_short port) override;

		/**
		 * Address: 0x0047F0F0
		 *
		 * @param address 
		 * @param port 
		 */
		void Send(CMessage*, u_long address, u_short port) override;

		/**
		 * Address: 0x0047F190
		 */
		void Pull() override;

		/**
		 * Address: 0x0047F330
		 * @return 
		 */
		HANDLE CreateEvent() override;

		/**
		 * Address: 0x0047F44E
		 *
		 * @param handler 
		 * @param sock 
		 */
		CNetDatagramSocketImpl(INetDatagramHandler* handler, SOCKET sock);

	private:
		INetDatagramHandler* mDatagramHandler;
		SOCKET mSocket;
		HANDLE mEvent;
	};
	static_assert(sizeof(CNetDatagramSocketImpl) == 0x10, "CNetDatagramSocketImpl must be 0x10");
}
