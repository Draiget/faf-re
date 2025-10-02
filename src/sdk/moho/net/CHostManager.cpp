#include "CHostManager.h"

#include "Common.h"
#include "gpg/core/containers/String.h"
using namespace moho;

msvc8::string moho::NET_GetDottedOctetFromUInt32(const u_long host) {
    const std::uint32_t x = host;
    return gpg::STR_Printf("%d.%d.%d.%d", (x >> 24) & 0xFF, (x >> 16) & 0xFF, (x >> 8) & 0xFF, x & 0xFF);
}

uint32_t moho::NET_GetUInt32FromDottedOcted(const msvc8::string& host) {
    if (host.empty()) {
	    return 0;
    }

    auto p = reinterpret_cast<const unsigned char*>(host.c_str());
    std::uint32_t acc = 0;
    int parts = 0;

    // skip leading spaces
    while (*p && std::isspace(*p)) ++p;
    if (!*p) return 0;

    for (;;)
    {
        // skip spaces before token
        while (*p && std::isspace(*p)) ++p;

        // parse decimal token 0..255
        unsigned value = 0;
        int nDigits = 0;
        while (*p && std::isdigit(*p)) {
            value = value * 10u + static_cast<unsigned>(*p - '0');
            if (value > 255u) return 0;
            ++p;
            ++nDigits;
        }
        if (nDigits == 0) {
	        return 0;
        }

        acc = (acc << 8) | value;
        ++parts;
        if (parts > 4) {
	        return 0;
        }

        // skip spaces after token
        while (*p && std::isspace(*p)) ++p;

        if (*p == '.') {
            ++p; // next octet
            continue;
        }

        // allow trailing spaces; anything else is invalid
        while (*p && std::isspace(*p)) {
	        ++p;
        }
        return *p ? 0u : acc;
    }
}

bool moho::NET_GetAddrInfo(const char* str, const u_short defaultPort, const bool isTcp, u_long& address, u_short& port) {
    if (!str || !address || !port) {
	    return false;
    }

    const char* last = std::strrchr(str, ':');

    std::string host;
    std::string service;
    if (last) {
        host.assign(str, last);   // [str, last)
        service.assign(last + 1); // after ':'
    } else {
        host.assign(str);
        char buf[16] = { 0 };
        std::snprintf(buf, sizeof(buf), "%u", static_cast<unsigned>(defaultPort));
        service.assign(buf);
    }

    ADDRINFOA hints = {};
    hints.ai_family = AF_INET;
    hints.ai_socktype = (isTcp != 0) ? SOCK_STREAM : SOCK_DGRAM;
    hints.ai_protocol = (isTcp != 0) ? IPPROTO_TCP : IPPROTO_UDP;

    ADDRINFOA* res = nullptr;
    const int ret = getaddrinfo(host.c_str(), service.c_str(), &hints, &res);
    if (ret != 0 || !res) {
        const char* msg = gai_strerrorA(ret);

        gpg::Logf("getaddrinfo(%s,%s) failed: %s [ret=%d]",
            host.c_str(), service.c_str(), msg, ret);

        if (res) {
	        freeaddrinfo(res);
        }
        return false;
    }

    // take the first AF_INET result
    const ADDRINFOA* cur = res;
    while (cur && cur->ai_family != AF_INET) cur = cur->ai_next;
    if (!cur || !cur->ai_addr || cur->ai_addrlen < sizeof(sockaddr_in)) {
        freeaddrinfo(res);
        return false;
    }

    auto sin = reinterpret_cast<const sockaddr_in*>(cur->ai_addr);
    address = ntohl(sin->sin_addr.s_addr);  // host order
    port = ntohs(sin->sin_port);            // host order (original used htons)

    freeaddrinfo(res);
    return true;
}

msvc8::string CHostManager::GetHostName(u_long host) {
    NET_Init();

    {
        boost::mutex::scoped_lock g(mLock);
        const auto it = mHosts.find(host);
        if (it != mHosts.end()) {
            Touch(it->second);
            return it->second.mName;
        }
    }

    {
        const msvc8::string name = ResolveHostName(host);
        boost::mutex::scoped_lock g(mLock);
        auto [it, inserted] = mHosts.emplace(host, Host{});
        Host& h = it->second;
        h.mName = name;

        if (inserted) {
            // New entry goes to MRU front: pass NODE (object itself)
            mHostList.push_front(&h);
            EvictIfNeeded();
        } else {
            // Already present: move to MRU front
            Touch(h);
        }
        return h.mName;
    }
}

void CHostManager::Touch(Host& h) noexcept {
    // Node is the object itself when Host derives the node
    auto& node = static_cast<TDatListItem<Host, void>&>(h);
    node.ListUnlink();
    node.ListLinkAfter(&mHostList);

    if (h.mVal != INT_MAX) {
	    ++h.mVal;
    }
}

void CHostManager::EvictIfNeeded() noexcept {
    while (mHosts.size() > kMaxEntries) {
        if (mHostList.empty()) {
	        break;
        }

        // Take tail node via iterator (end() is sentinel; --end gives last node)
        auto it = mHostList.end();
        // now at last node
        --it;
        // node pointer (TDatListItem<Host,void>*)
        auto* n = it.node(); 

        // Safety: sentinel check (sentinel is the head itself)
        if (n == static_cast<TDatListItem<Host, void>*>(&mHostList)) {
	        break;
        }

        const auto lru = static_cast<Host*>(n); // node -> owner when owner derives node

        // Always unlink node first to keep list consistent
        n->ListUnlink();

        // Erase from map by value (linear scan, N <= 0x4C)
        auto mapIt = FindByValue(lru);
        if (mapIt != mHosts.end()) {
            mHosts.erase(mapIt);
        }
    }
}

msvc8::string CHostManager::ResolveHostName(const u_long host) {
    sockaddr_in sa{};
    sa.sin_family = AF_INET;
    sa.sin_port = htons(0);
    sa.sin_addr.s_addr = htonl(host);

    char node[0x401]{}; // 1025 bytes as in the binary
    char serv[0x20]{};  // 32   bytes as in the binary

    const int rv = getnameinfo(reinterpret_cast<const sockaddr*>(&sa),
        sizeof(sa),
        node, sizeof(node),
        serv, sizeof(serv),
        NI_NUMERICSERV);

    if (rv != 0) {
        gpg::Logf("NET_GetHostName: getnameinfo() failed: %s", NET_GetWinsockErrorString());
        return NET_GetDottedOctetFromUInt32(host);
    }
    return msvc8::string{ node };
}
