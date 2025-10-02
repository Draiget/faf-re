#pragma once

#include "platform/Platform.h"

namespace moho
{
	class INetTCPSocket;

	/**
	 * VFTABLE: 0x00E0451C
	 * COL:		0x00E60A88
	 */
	class INetTCPServer
	{
	public:
		virtual ~INetTCPServer() = default; // 0x00482750
		virtual u_short GetLocalPort() = 0;
		virtual INetTCPSocket* Accept() = 0;
		virtual void CloseSocket() = 0;

		INetTCPServer() = default; // 0x00482740
	};
}