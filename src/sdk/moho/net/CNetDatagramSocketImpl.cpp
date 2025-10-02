#include "CNetDatagramSocketImpl.h"

#include "CMessage.h"
#include "Common.h"
#include "INetDatagramHandler.h"
#include "gpg/core/utils/Logging.h"
using namespace moho;

// 0x0047F050
CNetDatagramSocketImpl::~CNetDatagramSocketImpl() {
	closesocket(mSocket);
	if (mEvent) {
		WSACloseEvent(mEvent);
	}
}

// 0x0047F0D0
void CNetDatagramSocketImpl::SendDefault(CMessage* msg, const u_short port) {
	Send(msg, -1, port);
}

// 0x0047F0F0
void CNetDatagramSocketImpl::Send(CMessage* msg, const u_long address, const u_short port) {
	if (!msg) {
		gpg::Logf("CNetDatagramSocketImpl::Send: null payload pointer.");
		return;
	}

	const auto len = msg->GetSize();

	sockaddr_in to{};
	to.sin_family = AF_INET;
	to.sin_port = htons(port);
	to.sin_addr.s_addr = htonl(address);

	const int sent = sendto(mSocket, msg->mBuff.start_, len, 0,
		reinterpret_cast<const sockaddr*>(&to), sizeof(to));

	if (sent >= 0) {
		if (sent < len) {
			gpg::Logf("CNetDatagramSocketImpl::Send: msg truncated, only %d of %d bytes sent.", sent, len);
		}
	} else {
		gpg::Logf("CNetDatagramSocketImpl::Send: send() failed: %s", NET_GetWinsockErrorString());
	}
}

// 0x0047F190
void CNetDatagramSocketImpl::Pull() {
	if (mEvent) {
		WSAResetEvent(mEvent);
	}

    static constexpr int bufCap = 2048;
    char buf[bufCap];

    sockaddr_in from{};
    int fromLen = sizeof(from);

    int n = recvfrom(mSocket, buf, bufCap, 0, reinterpret_cast<sockaddr*>(&from), &fromLen);
    if (n >= 0) {
        CMessage tmp{};
        do {
            tmp.mBuff.Resize(n, 0);
            memcpy(tmp.mBuff.start_, buf, static_cast<size_t>(n));

            const u_short peerPort = ntohs(from.sin_port);
            const u_long peerAddress = ntohl(from.sin_addr.s_addr);

            // Callback
            if (mDatagramHandler != nullptr) {
                mDatagramHandler->Pull(&tmp, this, peerAddress, peerPort);
            }

            tmp.Clear();

            std::memset(&from, 0, sizeof(from));
            n = recvfrom(mSocket, buf, bufCap, 0, reinterpret_cast<sockaddr*>(&from), &fromLen);
        } while (n >= 0);
    }

    if (WSAGetLastError() != WSAEWOULDBLOCK) {
        gpg::Logf("CNetDatagramSocketImpl::Pull: recv() failed: %s", NET_GetWinsockErrorString());
    }
}

// 0x0047F330
HANDLE CNetDatagramSocketImpl::CreateEvent() {
    if (!mEvent) {
	    const HANDLE h = WSACreateEvent();
        mEvent = h;
        WSAEventSelect(mSocket, h, FD_READ);
    }
    return mEvent;
}

// 0x0047F44E
CNetDatagramSocketImpl::CNetDatagramSocketImpl(INetDatagramHandler* handler, const SOCKET sock) :
	mDatagramHandler(handler),
	mSocket(sock),
	mEvent(nullptr)
{
}
