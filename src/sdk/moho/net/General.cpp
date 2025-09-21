#include "General.h"

#include "CHostManager.h"
#include "CNetUDPConnector.h"
#include "gpg/core/containers/String.h"
using namespace moho;

extern int32_t net_DebugLevel = 0;

void moho::NetPacketStateToStr(const EPacketState state, msvc8::string& out) {
	switch (state) {
	case ACK:
        out = "ACK";
        return;
	case KEEPALIVE:
        out = "ACK";
        return;
	case GOODBYE:
        out = "ACK";
        return;
	case ANSWER:
        out = "ACK";
        return;
	case CONNECT:
        out = "ACK";
        return;
	case DATA:
        out = "ACK";
        return;
	case NATTRAVERSAL:
        out = "ACK";
        return;
	case RESETSERIAL:
        out = "ACK";
        return;
	case SERIALRESET:
        out = "ACK";
        return;
	default:
        out = gpg::STR_Printf("%02x", static_cast<uint8_t>(state));
	}
}

const char* moho::NetConnectionStateToStr(const ENetConnectionState state) {
	switch (state) {
	case ACK:
        return "ACK";
	case KEEPALIVE:
        return "KEEPALIVE";
	case GOODBYE:
        return "GOODBYE";
	case ANSWER:
        return "ANSWER";
	case CONNECT:
        return "CONNECT";
	case DATA:
        return "DATA";
	case NATTRAVERSAL:
        return "NATTRAVERSAL";
	case RESETSERIAL:
        return "RESETSERIAL";
	case SERIALRESET:
        return "SERIALRESET";
	default:
        return "???";
	}
}

SendStampView SendStampBuffer::GetBetween(const uint64_t startTime, const uint64_t endTime) {
    uint64_t dur = endTime - startTime;
    unsigned int len;
    if (mEnd < mStart) {
        len = mEnd - mStart + 4096;
    } else {
        len = mEnd - mStart;
    }
    unsigned int start = 0;
    unsigned int end = len;
    while (start < end) {
        unsigned int cur = (end + start) / 2;
        if (Get(cur).time >= dur) {
            end = cur;
        } else {
            start = cur + 1;
        }
    }

    SendStampView out{ dur, end };
    out.items.reserve(len - end);
    for (auto i = end; i < len; ++i) {
        out.items.push_back(Get(i));
    }
    return out;
}

void SendStampBuffer::Reset() {
    mEnd = 0;
    mStart = 0;
}

uint32_t SendStampBuffer::Push(const int dir, const LONGLONG timeUs, const int size) noexcept {
    // If advancing start would collide with end, drop the oldest.
    const std::uint32_t next = (mStart + 1u) & static_cast<std::uint32_t>(cap);
    if (next == mEnd) {
        mEnd = (mEnd + 1u) & static_cast<std::uint32_t>(cap);
    }

    // Prepare entry (a1a in the asm)
    SendStamp s;
    s.time = timeUs;
    s.direction = dir;
    s.size = size;

    return EmplaceAndAdvance(s);
}

void SendStampBuffer::Add(const int direction, const LONGLONG time, const int size) {
    if ((mEnd + 1) % cap == mStart) {
        mStart = (mStart + 1) % cap;
    }

    SendStamp s;
    s.time = time;
    s.direction = direction;
    s.size = size;
    Append(&s);
}

void SendStampBuffer::Append(const SendStamp* s) {
    const auto pos = &mDat[mEnd];
    if (pos != nullptr) {
        *pos = *s;
    }
    mEnd = (mEnd + 1) % cap;
}

bool moho::NET_Init() {
#if defined(_WIN32)
    static bool sWinsockInitialized = false;
    if (!sWinsockInitialized) {
        WSAData wsaData;
        if (::WSAStartup(MAKEWORD(1, 1), &wsaData)) {
            gpg::Logf("Net_Init(): WSAStartup failed: %s", NET_GetWinsockErrorString());
        } else {
            sWinsockInitialized = true;
        }
    }
    return sWinsockInitialized;
#else
    return false;
#endif
}

INetConnector* moho::NET_MakeUDPConnector(const u_short port, boost::weak_ptr<INetNATTraversalProvider> prov) {
    if (!NET_Init()) {
        return nullptr;
    }
    SOCKET sock = ::socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock == INVALID_SOCKET) {
        if (net_DebugLevel != 0) {
            gpg::Logf("NET_MakeUDPConnector: socket() failed: %s", NET_GetWinsockErrorString());
        }
        return nullptr;
    }
    u_long argp = 1;
    if (::ioctlsocket(sock, FIONBIO, &argp) == SOCKET_ERROR) {
        if (net_DebugLevel != 0) {
            gpg::Logf("NET_MakeUDPConnector: ioctlsocket(FIONBIO) failed: %s", NET_GetWinsockErrorString());
        }
        ::closesocket(sock);
        return nullptr;
    }
    sockaddr_in name;
    name.sin_family = AF_INET;
    name.sin_port = ::htons(port);
    name.sin_addr.S_un.S_addr = ::htonl(0);
    if (::bind(sock, (SOCKADDR*)&name, sizeof(name)) == SOCKET_ERROR) {
        if (net_DebugLevel != 0) {
            gpg::Logf("NET_MakeUDPConnector: bind(%d) failed: %s", port, NET_GetWinsockErrorString());
        }
        ::closesocket(sock);
        return nullptr;
    }
    return new CNetUDPConnector{ sock, prov };
}


CHostManager* moho::NET_GetHostManager() {
    static CHostManager manager;
    return &manager;
}

msvc8::string moho::NET_GetHostName(const u_long address) {
	const auto manager = NET_GetHostManager();
    return manager->GetHostName(address);
}

const char* moho::NET_GetWinsockErrorString() noexcept {
#if defined(_WIN32)
    const int e = ::WSAGetLastError();
    if (e == 0) {
        return "NOERROR";
    }

    // DNS/host resolution extended codes first (match original control flow)
    switch (e) {
    case WSAHOST_NOT_FOUND: return "WSAHOST_NOT_FOUND";   // 11001
    case WSATRY_AGAIN:      return "WSATRY_AGAIN";        // 11002
    case WSANO_RECOVERY:    return "WSANO_RECOVERY";      // 11003
    case WSANO_DATA:        return "WSANO_DATA";          // 11004
    }

    // Core Winsock error set mirrored from the original switch
    switch (e) {
    case WSAEINTR:           return "WSAEINTR";            // 10004 (0x2714)
    case WSAEBADF:           return "WSAEBADF";            // 10009 (0x2719)
    case WSAEACCES:          return "WSAEACCES";           // 10013 (0x271D)
    case WSAEFAULT:          return "WSAEFAULT";           // 10014 (0x271E)
    case WSAEINVAL:          return "WSAEINVAL";           // 10022 (0x2726)
    case WSAEMFILE:          return "WSAEMFILE";           // 10024 (0x2728)
    case WSAEWOULDBLOCK:     return "WSAEWOULDBLOCK";      // 10035 (0x2733)
    case WSAEINPROGRESS:     return "WSAEINPROGRESS";      // 10036 (0x2734)
    case WSAEALREADY:        return "WSAEALREADY";         // 10037 (0x2735)
    case WSAENOTSOCK:        return "WSAENOTSOCK";         // 10038 (0x2736)
    case WSAEDESTADDRREQ:    return "WSAEDESTADDRREQ";     // 10039 (0x2737)
    case WSAEMSGSIZE:        return "WSAEMSGSIZE";         // 10040 (0x2738)
    case WSAEPROTOTYPE:      return "WSAEPROTOTYPE";       // 10041 (0x2739)
    case WSAENOPROTOOPT:     return "WSAENOPROTOOPT";      // 10042 (0x273A)
    case WSAEPROTONOSUPPORT: return "WSAEPROTONOSUPPORT";  // 10043 (0x273B)
    case WSAESOCKTNOSUPPORT: return "WSAESOCKTNOSUPPORT";  // 10044 (0x273C)
    case WSAEOPNOTSUPP:      return "WSAEOPNOTSUPP";       // 10045 (0x273D)
    case WSAEPFNOSUPPORT:    return "WSAEPFNOSUPPORT";     // 10046 (0x273E)
    case WSAEAFNOSUPPORT:    return "WSAEAFNOSUPPORT";     // 10047 (0x273F)
    case WSAEADDRINUSE:      return "WSAEADDRINUSE";       // 10048 (0x2740)
    case WSAEADDRNOTAVAIL:   return "WSAEADDRNOTAVAIL";    // 10049 (0x2741)
    case WSAENETDOWN:        return "WSAENETDOWN";         // 10050 (0x2742)
    case WSAENETUNREACH:     return "WSAENETUNREACH";      // 10051 (0x2743)
    case WSAENETRESET:       return "WSAENETRESET";        // 10052 (0x2744)
    case WSAECONNABORTED:    return "WSAECONNABORTED";     // 10053 (0x2745)
    case WSAECONNRESET:      return "WSAECONNRESET";       // 10054 (0x2746)
    case WSAENOBUFS:         return "WSAENOBUFS";          // 10055 (0x2747)
    case WSAEISCONN:         return "WSAEISCONN";          // 10056 (0x2748)
    case WSAENOTCONN:        return "WSAENOTCONN";         // 10057 (0x2749)
    case WSAESHUTDOWN:       return "WSAESHUTDOWN";        // 10058 (0x274A)
    case WSAETOOMANYREFS:    return "WSAETOOMANYREFS";     // 10059 (0x274B)
    case WSAETIMEDOUT:       return "WSAETIMEDOUT";        // 10060 (0x274C)
    case WSAECONNREFUSED:    return "WSAECONNREFUSED";     // 10061 (0x274D)
    case WSAELOOP:           return "WSAELOOP";            // 10062 (0x274E)
    case WSAENAMETOOLONG:    return "WSAENAMETOOLONG";     // 10063 (0x274F)
    case WSAEHOSTDOWN:       return "WSAEHOSTDOWN";        // 10064 (0x2750)
    case WSAEHOSTUNREACH:    return "WSAEHOSTUNREACH";     // 10065 (0x2751)
    case WSAENOTEMPTY:       return "WSAENOTEMPTY";        // 10066 (0x2752)
    case WSAEPROCLIM:        return "WSAEPROCLIM";         // 10067 (0x2753)
    case WSAEUSERS:          return "WSAEUSERS";           // 10068 (0x2754)
    case WSAEDQUOT:          return "WSAEDQUOT";           // 10069 (0x2755)
    case WSAESTALE:          return "WSAESTALE";           // 10070 (0x2756)
    case WSAEREMOTE:         return "WSAEREMOTE";          // 10071 (0x2757)
    case WSASYSNOTREADY:     return "WSASYSNOTREADY";      // 10091 (0x276B)
    case WSAVERNOTSUPPORTED: return "WSAVERNOTSUPPORTED";  // 10092 (0x276C)
    case WSANOTINITIALISED:  return "WSANOTINITIALISED";   // 10093 (0x276D)
    case WSAEDISCON:         return "WSAEDISCON";          // 10101 (0x2775)
    default:                 return "UNKNOWN";
    }
#else
    // Non-Windows build: no Winsock -> stable stub.
    return "NO_WINSOCK";
#endif
}

msvc8::string moho::NET_GetDottedOctetFromUInt32(const uint32_t number) {
    return gpg::STR_Printf(
        "%d.%d.%d.%d", 
        HIWORD(HIBYTE(number)),
        HIWORD(LOBYTE(number)),
        HIBYTE(number),
        LOBYTE(number));
}
