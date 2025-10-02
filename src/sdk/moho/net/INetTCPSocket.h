#pragma once
#include "gpg/core/streams/Stream.h"
#include "gpg/core/utils/BoostUtils.h"

namespace moho
{
	/**
	 * VFTABLE: 0x00E044E4
	 * COL:		0x00E60AD0
	 */
	class INetTCPSocket :
		public gpg::Stream,
		public boost::noncopyable_::noncopyable
	{
	public:
		/**
		 * Slot: 10
		 * @return 
		 */
		virtual u_short GetPort() = 0;

		/**
		 * Slot: 11
		 * @return
		 */
		virtual u_long GetPeerAddr() = 0;

		/**
		 * Slot: 12
		 * @return
		 */
		virtual u_short GetPeerPort() = 0;

		/**
		 * Address: 0x004827E0
		 */
		INetTCPSocket() = default;

	private:
		SOCKET mSocket;
	};
}
