#include "INetDatagramSocket.h"

#include "CNetDatagramSocketImpl.h"
#include "Common.h"
#include "gpg/core/utils/Logging.h"
using namespace moho;

INetDatagramSocket* moho::NET_OpenDatagramSocket(const u_short port, INetDatagramHandler* handler) {
    if (!NET_Init()) {
	    return nullptr;
    }

    SOCKET sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
	    gpg::Logf("NET_OpenDatagramSocket: socket() failed: %s", NET_GetWinsockErrorString());
        return nullptr;
    }

    // SO_BROADCAST = 1
    {
        BOOL on = TRUE;
        if (setsockopt(sock, SOL_SOCKET, SO_BROADCAST,
            reinterpret_cast<const char*>(&on), sizeof(on)) == SOCKET_ERROR)
        {
	        gpg::Logf("NET_OpenDatagramSocket: setsockopt(SO_BROADCAST) failed: %s", NET_GetWinsockErrorString());
            closesocket(sock);
            return nullptr;
        }
    }

    // Non-blocking
    {
        u_long nb = 1;
        if (ioctlsocket(sock, FIONBIO, &nb) == SOCKET_ERROR) {
	        gpg::Logf("NET_OpenDatagramSocket: ioctlsocket(FIONBIO) failed: %s", NET_GetWinsockErrorString());
            closesocket(sock);
            return nullptr;
        }
    }

    // Bind to 0.0.0.0:port
    sockaddr_in name{};
    name.sin_family = AF_INET;
    name.sin_port = htons(port);
    name.sin_addr.s_addr = htonl(INADDR_ANY);
    if (bind(sock, reinterpret_cast<const sockaddr*>(&name), sizeof(name)) == SOCKET_ERROR)
    {
	    gpg::Logf("NET_OpenDatagramSocket: bind() failed: %s", NET_GetWinsockErrorString());
        closesocket(sock);
        return nullptr;
    }

    // Construct impl (matches 16-byte layout in the binary)
    const auto impl = new CNetDatagramSocketImpl(handler, sock);
    if (!impl) {
        closesocket(sock);
        return nullptr;
    }
    return impl;
}
