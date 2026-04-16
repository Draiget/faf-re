#include "CHostManager.h"

#include <cstring>

#include "Common.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Logging.h"

using namespace moho;

namespace
{
  /**
   * Address: 0x0047F560 (FUN_0047F560)
   *
   * What it does:
   * Formats one Win32 system message into a reusable wide-buffer lane.
   */
  [[nodiscard]] WCHAR* FormatSystemMessageWide(const DWORD messageId) noexcept
  {
    static WCHAR messageFormatBuffer[0x400]{};
    FormatMessageW(
      FORMAT_MESSAGE_MAX_WIDTH_MASK | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
      nullptr,
      messageId,
      0x400,
      messageFormatBuffer,
      0x400,
      nullptr
    );
    return messageFormatBuffer;
  }
} // namespace

/**
 * Address: 0x0047F8A0 (FUN_0047F8A0, struct_Host::struct_Host)
 */
Host::Host(const msvc8::string& name)
  : TDatListItem<Host, void>{}
  , mName{}
  , mMapNodeBackLink(nullptr)
{
  mName = name;
}

/**
 * Address: 0x0047FBA0 (FUN_0047FBA0)
 */
void Host::ResetNameAndUnlink() noexcept
{
  // 0x0047FBA0 explicitly resets dynamic string storage back to inline lane.
  mName.tidy(true, 0);
  auto& node = static_cast<TDatListItem<Host, void>&>(*this);
  node.ListUnlink();
}

/**
 * Address: 0x0047FB50 (FUN_0047FB50, struct_Host::operator delete)
 */
void Host::DestroyHeapNode(Host* const host) noexcept
{
  if (host == nullptr) {
    return;
  }

  host->ResetNameAndUnlink();
  delete host;
}

/**
 * Address: 0x0047F900 (FUN_0047F900, sHostManager::sHostManager)
 */
CHostManager::CHostManager() = default;

/**
 * Address: 0x0047FA40 (FUN_0047FA40, sHostManager::~sHostManager)
 */
CHostManager::~CHostManager()
{
  while (!mHostList.empty()) {
    auto* const front = static_cast<Host*>(mHostList.mNext);
    auto it = FindByValue(front);
    if (it != mHosts.end()) {
      Host* const owned = it->second;
      mHosts.erase(it);
      Host::DestroyHeapNode(owned);
      continue;
    }

    Host::DestroyHeapNode(front);
  }

  mHostList.ListResetLinks();
  mHosts.clear();
}

/**
 * Address: 0x00BEF9F0 (FUN_00BEF9F0, ??1sHostManager@Moho@@QAE@@Z)
 *
 * What it does:
 * Thunk lane that forwards one host-manager teardown request into
 * `FUN_0047FA40`.
 */
[[maybe_unused]] void DestroyHostManagerRuntimeAdapter(CHostManager* const manager) noexcept
{
  if (manager != nullptr) {
    manager->~CHostManager();
  }
}

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
    char narrowError[0x400]{};
    const wchar_t* const wideError = FormatSystemMessageWide(static_cast<DWORD>(rc));

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
    if (it != mHosts.end() && it->second != nullptr) {
      Touch(*it->second);
      return it->second->mName;
    }
  }

  NET_Init();
  const msvc8::string resolvedName = ResolveHostName(host);
  Host* const pendingHost = new Host(resolvedName);

  boost::mutex::scoped_lock lock(mLock);
  const auto [it, inserted] = mHosts.emplace(host, pendingHost);

  if (inserted) {
    Host* const insertedHost = it->second;
    insertedHost->mMapNodeBackLink = static_cast<void*>(&(*it));
    Touch(*insertedHost);
    EvictIfNeeded();
    return resolvedName;
  }

  // Match FA behavior: racing duplicate insert deletes pending host and returns
  // the freshly resolved name rather than reloading from the cache entry.
  Host::DestroyHeapNode(pendingHost);
  return resolvedName;
}

msvc8::string& CHostManager::GetHostName(const std::uint32_t host, msvc8::string& out)
{
  out = GetHostName(host);
  return out;
}

void CHostManager::Touch(Host& h) noexcept
{
  auto& node = static_cast<TDatListItem<Host, void>&>(h);
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

    auto* const lru = static_cast<Host*>(node);
    auto mapIt = FindByValue(lru);
    if (mapIt != mHosts.end()) {
      Host* const owned = mapIt->second;
      mHosts.erase(mapIt);
      Host::DestroyHeapNode(owned);
      continue;
    }

    Host::DestroyHeapNode(lru);
  }
}

auto CHostManager::FindByValue(const Host* h) -> CHostManager::HostMap::iterator
{
  for (auto it = mHosts.begin(); it != mHosts.end(); ++it) {
    if (it->second == h) {
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
