#include "CHostManager.h"

#include <cstring>

#include "Common.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Logging.h"

using namespace moho;

/**
 * Address: 0x0047FF10 (FUN_0047FF10)
 * Mangled: ?NET_GetAddrInfo@Moho@@YA_NVStrArg@gpg@@G_NAAIAAG@Z
 *
 * gpg::StrArg, unsigned short, bool, unsigned int &, unsigned short &
 *
 * What it does:
 * Resolves "host[:port]" via getaddrinfo(AF_INET), returning host-order IPv4 and port.
 */
bool moho::NET_GetAddrInfo(const char* str, const u_short defaultPort, const bool isTcp, u_long& address, u_short& port)
{
  if (!str) {
    return false;
  }

  NET_Init();

  msvc8::string nodeName;
  msvc8::string serviceName;
  const char* const lastColon = std::strrchr(str, ':');

  if (lastColon != nullptr) {
    nodeName.assign(str, static_cast<std::size_t>(lastColon - str));
    serviceName.assign(lastColon + 1, std::strlen(lastColon + 1));
  } else {
    nodeName = msvc8::string{str};
    serviceName = gpg::STR_Printf("%d", defaultPort);
  }

  ADDRINFOA hints{};
  hints.ai_family = AF_INET;
  hints.ai_socktype = isTcp ? SOCK_STREAM : SOCK_DGRAM;
  hints.ai_protocol = isTcp ? IPPROTO_TCP : IPPROTO_UDP;

  ADDRINFOA* result = nullptr;
  const int rc = getaddrinfo(nodeName.c_str(), serviceName.c_str(), &hints, &result);
  if (rc != 0 || result == nullptr) {
    wchar_t wideError[0x400]{};
    char narrowError[0x400]{};

    FormatMessageW(
      FORMAT_MESSAGE_MAX_WIDTH_MASK | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
      nullptr,
      static_cast<DWORD>(rc),
      0x400,
      wideError,
      0x400,
      nullptr
    );

    if (wideError[0] != L'\0') {
      WideCharToMultiByte(CP_ACP, 0, wideError, -1, narrowError, sizeof(narrowError), nullptr, nullptr);
    }

    gpg::Logf(
      "getaddrinfo(%s,%s) failed: %s [ret=%d]",
      nodeName.c_str(),
      serviceName.c_str(),
      narrowError[0] != '\0' ? narrowError : "UNKNOWN",
      rc
    );

    if (result != nullptr) {
      freeaddrinfo(result);
    }
    return false;
  }

  const auto* const sin = reinterpret_cast<const sockaddr_in*>(result->ai_addr);
  if (sin == nullptr) {
    freeaddrinfo(result);
    return false;
  }

  address = ntohl(sin->sin_addr.s_addr);
  port = htons(sin->sin_port);
  freeaddrinfo(result);
  return true;
}

/**
 * Address: 0x0047FBE0 (FUN_0047FBE0)
 *
 * uint32_t
 *
 * What it does:
 * Returns cached hostname for host-order IPv4 address and refreshes MRU order.
 * On miss, resolves name, inserts a new cache entry, and evicts LRU entries past cap.
 */
msvc8::string CHostManager::GetHostName(const std::uint32_t host)
{
  {
    boost::mutex::scoped_lock lock(mLock);
    const auto it = mHosts.find(host);
    if (it != mHosts.end()) {
      Touch(it->second);
      return it->second.mName;
    }
  }

  NET_Init();
  const msvc8::string resolvedName = ResolveHostName(host);

  boost::mutex::scoped_lock lock(mLock);
  const auto [it, inserted] = mHosts.emplace(host, Host{});
  Host& entry = it->second;

  if (inserted) {
    entry.mName = resolvedName;
    entry.mMapNodeBackLink = static_cast<void*>(&(*it));
    mHostList.push_front(&entry);
    EvictIfNeeded();
  } else {
    Touch(entry);
  }

  return entry.mName;
}

msvc8::string& CHostManager::GetHostName(const std::uint32_t host, msvc8::string& out)
{
  out = GetHostName(host);
  return out;
}

void CHostManager::Touch(Host& h) noexcept
{
  auto& node = static_cast<TDatListItem<Host, void>&>(h);
  node.ListUnlink();
  node.ListLinkAfter(&mHostList);
}

void CHostManager::EvictIfNeeded() noexcept
{
  while (mHosts.size() > kMaxEntries) {
    if (mHostList.empty()) {
      break;
    }

    auto listIt = mHostList.end();
    --listIt;
    auto* node = listIt.node();
    if (node == static_cast<TDatListItem<Host, void>*>(&mHostList)) {
      break;
    }

    auto* lru = static_cast<Host*>(node);
    node->ListUnlink();

    auto mapIt = FindByValue(lru);
    if (mapIt != mHosts.end()) {
      mHosts.erase(mapIt);
    }
  }
}

auto CHostManager::FindByValue(const Host* h) -> std::map<std::uint32_t, Host>::iterator
{
  for (auto it = mHosts.begin(); it != mHosts.end(); ++it) {
    if (&it->second == h) {
      return it;
    }
  }
  return mHosts.end();
}

msvc8::string CHostManager::ResolveHostName(const std::uint32_t host)
{
  sockaddr_in sockAddr{};
  sockAddr.sin_family = AF_INET;
  sockAddr.sin_port = htons(0);
  sockAddr.sin_addr.s_addr = htonl(host);

  char nodeBuffer[0x401]{};
  char serviceBuffer[0x20]{};

  const int rc = getnameinfo(
    reinterpret_cast<const sockaddr*>(&sockAddr),
    sizeof(sockAddr),
    nodeBuffer,
    sizeof(nodeBuffer),
    serviceBuffer,
    sizeof(serviceBuffer),
    NI_NUMERICSERV
  );

  if (rc != 0) {
    gpg::Logf("NET_GetHostName: getnameinfo() failed: %s", NET_GetWinsockErrorString());
    return NET_GetDottedOctetFromUInt32(host);
  }

  return msvc8::string{nodeBuffer};
}
