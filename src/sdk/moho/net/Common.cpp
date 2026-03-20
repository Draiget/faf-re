#include "Common.h"

#include <algorithm>
#include <cmath>
#include <cstdlib>
#include <new>

#include "CHostManager.h"
#include "CNetTCPConnector.h"
#include "CNetUDPConnector.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/utils/Logging.h"
#include "NetConVars.h"
using namespace moho;

NetSpeeds::NetSpeeds()
  : vals{}
  , v1(0)
  , head(0)
  , tail(0)
{}

NetSpeeds::~NetSpeeds() = default;

int NetSpeeds::Append(const float sample) noexcept
{
  const int next = (tail + 1) % 25;
  if (next == head) {
    head = (head + 1) % 25;
  }
  vals[tail] = sample;
  const int wrapped = (tail + 1) / 25;
  tail = next;
  return wrapped;
}

float NetSpeeds::Median() const noexcept
{
  float tmp[25];
  int i = 0;
  int h = head;
  const int t = tail;
  while (h != t) {
    tmp[i++] = vals[h];
    h = (h + 1) % 25;
  }
  if (i == 0) {
    return 0.0f;
  }
  std::sort(tmp, tmp + i);
  return tmp[i / 2];
}

float NetSpeeds::Jitter(const float center) const noexcept
{
  float tmp[25];
  int i = 0;
  int h = head;
  const int t = tail;
  while (h != t) {
    tmp[i++] = std::fabs(vals[h] - center);
    h = (h + 1) % 25;
  }
  if (i == 0) {
    return 0.0f;
  }
  std::sort(tmp, tmp + i);
  return tmp[i / 2];
}

/**
 * Address: 0x0047D1D0
 * NOTE: Inlined
 *
 * What it does:
 * Initializes a send-stamp view for the requested [from, to] time window.
 */
SSendStampView::SSendStampView(const uint64_t start, const uint64_t end)
  : items{}
  , from(start)
  , to(end)
{}

void moho::ENetworkPlayerStateToStr(const ENetworkPlayerState state, msvc8::string& out)
{
  if (state >= ENetworkPlayerState::_Last) {
    out = gpg::STR_Printf("%d", static_cast<int32_t>(state));
    return;
  }

  switch (state) {
  case ENetworkPlayerState::kUnknown:
    out = "Unknown";
    return;
  case ENetworkPlayerState::kConnecting:
    out = "Connecting";
    return;
  case ENetworkPlayerState::kConnected:
    out = "Connected";
    return;
  case ENetworkPlayerState::kPending:
    out = "Pending";
    return;
  case ENetworkPlayerState::kWaitingJoin:
    out = "WaitingJoin";
    return;
  case ENetworkPlayerState::kEstablished:
    out = "Established";
    return;
  case ENetworkPlayerState::kDisconnected:
    out = "Disconnected";
  default:;
  }
}

void moho::NetPacketTypeToStr(const EPacketType state, msvc8::string& out)
{
  switch (state) {
  case PT_Connect:
    out = "CONNECT";
    return;
  case PT_Answer:
    out = "ANSWER";
    return;
  case PT_ResetSerial:
    out = "RESETSERIAL";
    return;
  case PT_SerialReset:
    out = "SERIALRESET";
    return;
  case PT_Data:
    out = "DATA";
    return;
  case PT_Ack:
    out = "ACK";
    return;
  case PT_KeepAlive:
    out = "KEEPALIVE";
    return;
  case PT_Goodbye:
    out = "GOODBYE";
    return;
  case PT_NATTraversal:
    out = "NATTRAVERSAL";
    return;
  default:
    out = gpg::STR_Printf("%02x", static_cast<uint8_t>(state));
  }
}

const char* moho::NetConnectionStateToStr(const ENetConnectionState state)
{
  switch (state) {
  case kNetStatePending:
    return "PENDING";
  case kNetStateConnecting:
    return "CONNECTING";
  case kNetStateAnswering:
    return "ANSWERING";
  case kNetStateEstablishing:
    return "ESTABLISHING";
  case kNetStateTimedOut:
    return "TIMEDOUT";
  case kNetStateErrored:
    return "ERRORED";
  default:
    return "???";
  }
}

SSendStampView SSendStampBuffer::GetBetween(const uint64_t startTime, const uint64_t endTime)
{
  // delta = startTime - endTime (matching engine math direction)
  const uint64_t delta = startTime - endTime;

  // Compute logical length in the ring [mEnd .. mStart) with capacity 4096
  // Matches: (mEnd > mStart) ? (mStart - mEnd + 4096) : (mStart - mEnd)
  const unsigned int len = (mEnd > mStart) ? (mStart - mEnd + cap) : (mStart - mEnd);

  // Lower_bound over [0, len): first index with time >= delta
  unsigned int lo = 0, hi = len;
  while (lo < hi) {
    const unsigned int mid = (lo + hi) >> 1;
    if (Get(mid).time >= delta) {
      hi = mid;
    } else {
      lo = mid + 1;
    }
  }

  // View header matches engine: from=delta, to=startTime
  SSendStampView out{delta, startTime};

  // Reserve exactly the number of items we will push (len - lo)
  out.items.reserve(len - lo);

  // Emit tail [lo .. len)
  for (unsigned int i = lo; i < len; ++i) {
    out.items.push_back(Get(i));
  }

  return out;
}

void SSendStampBuffer::Reset()
{
  mEnd = 0;
  mStart = 0;
}

uint32_t SSendStampBuffer::Push(const int dir, const LONGLONG timeUs, const int size) noexcept
{
  constexpr uint32_t kRingMask = cap - 1u;

  // If advancing start would collide with end, drop the oldest.
  const std::uint32_t next = (mStart + 1u) & kRingMask;
  if (next == mEnd) {
    mEnd = (mEnd + 1u) & kRingMask;
  }

  // Prepare entry (a1a in the asm)
  SSendStamp s;
  s.time = timeUs;
  s.direction = dir;
  s.size = size;

  return EmplaceAndAdvance(s);
}

void SSendStampBuffer::Add(const int direction, const LONGLONG time, const int size)
{
  if ((mEnd + 1) % cap == mStart) {
    mStart = (mStart + 1) % cap;
  }

  SSendStamp s;
  s.time = time;
  s.direction = direction;
  s.size = size;
  Append(&s);
}

void SSendStampBuffer::Append(const SSendStamp* s)
{
  const auto pos = &mDat[mEnd];
  if (pos != nullptr) {
    *pos = *s;
  }
  mEnd = (mEnd + 1) % cap;
}

bool SSendStampBuffer::empty() const noexcept
{
  return mStart == mEnd;
}

uint32_t SSendStampBuffer::size() const noexcept
{
  return (mStart - mEnd) & (cap - 1u);
}

void SSendStampBuffer::push(const SSendStamp& s) noexcept
{
  constexpr uint32_t kRingMask = cap - 1u;
  mDat[mStart] = s;
  mStart = (mStart + 1u) & kRingMask;
  if (mStart == mEnd) {
    mEnd = (mEnd + 1u) & kRingMask;
  }
}

SSendStamp& SSendStampBuffer::Get(const size_t index) noexcept
{
  return mDat[(mStart + index) % cap];
}

uint32_t SSendStampBuffer::EmplaceAndAdvance(const SSendStamp& s) noexcept
{
  constexpr uint32_t kRingMask = cap - 1u;
  mDat[mStart] = s;
  mStart = (mStart + 1u) & kRingMask;
  return mStart;
}

bool moho::NET_Init()
{
  NET_RegisterConVarDefinitions();

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

INetConnector* moho::NET_MakeUDPConnector(const u_short port, boost::weak_ptr<INetNATTraversalProvider> prov)
{
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
  return new CNetUDPConnector{sock, prov};
}

/**
 * Address: 0x004849A0 (FUN_004849A0)
 *
 * What it does:
 * Creates non-blocking TCP listening connector bound to `port`.
 */
INetConnector* moho::NET_MakeTCPConnector(const u_short port)
{
  if (!NET_Init()) {
    return nullptr;
  }

  const SOCKET sock = ::socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  if (sock == INVALID_SOCKET) {
    gpg::Logf("NET_MakeConnector: socket() failed: %s", NET_GetWinsockErrorString());
    return nullptr;
  }

  u_long nonBlocking = 1;
  if (::ioctlsocket(sock, FIONBIO, &nonBlocking) == SOCKET_ERROR) {
    gpg::Logf("NET_MakeConnector: ioctlsocket(FIONBIO) failed: %s", NET_GetWinsockErrorString());
    ::closesocket(sock);
    return nullptr;
  }

  sockaddr_in name{};
  name.sin_family = AF_INET;
  name.sin_port = ::htons(port);
  name.sin_addr.s_addr = ::htonl(0);
  if (::bind(sock, reinterpret_cast<const sockaddr*>(&name), sizeof(name)) == SOCKET_ERROR) {
    gpg::Logf("NET_MakeConnector: bind(%d) failed: %s", port, NET_GetWinsockErrorString());
    ::closesocket(sock);
    return nullptr;
  }

  if (::listen(sock, SOMAXCONN) == SOCKET_ERROR) {
    gpg::Logf("NET_MakeConnector: listen() failed: %s", NET_GetWinsockErrorString());
    ::closesocket(sock);
    return nullptr;
  }

  const auto connector = new (std::nothrow) CNetTCPConnector(sock);
  if (!connector) {
    // FA/Moho behavior: allocation failure returns null without closing opened socket.
    return nullptr;
  }
  return connector;
}

/**
 * Address: 0x0047F990 (FUN_0047F990)
 *
 * What it does:
 * Returns process-global host-name cache manager, lazily initialized once.
 */
CHostManager* moho::NET_GetHostManager()
{
  static CHostManager manager;
  return &manager;
}

/**
 * Address: 0x0047FEE0 (FUN_0047FEE0)
 *
 * uint32_t
 *
 * What it does:
 * Resolves/caches a host-order IPv4 address through the global CHostManager cache.
 */
msvc8::string moho::NET_GetHostName(const u_long address)
{
  const auto manager = NET_GetHostManager();
  return manager->GetHostName(address);
}

const char* moho::NET_GetWinsockErrorString() noexcept
{
#if defined(_WIN32)
  const int e = ::WSAGetLastError();
  if (e == 0) {
    return "NOERROR";
  }

  // DNS/host resolution extended codes first (match original control flow)
  switch (e) {
  case WSAHOST_NOT_FOUND:
    return "WSAHOST_NOT_FOUND"; // 11001
  case WSATRY_AGAIN:
    return "WSATRY_AGAIN"; // 11002
  case WSANO_RECOVERY:
    return "WSANO_RECOVERY"; // 11003
  case WSANO_DATA:
    return "WSANO_DATA"; // 11004
  }

  // Core Winsock error set mirrored from the original switch
  switch (e) {
  case WSAEINTR:
    return "WSAEINTR"; // 10004 (0x2714)
  case WSAEBADF:
    return "WSAEBADF"; // 10009 (0x2719)
  case WSAEACCES:
    return "WSAEACCES"; // 10013 (0x271D)
  case WSAEFAULT:
    return "WSAEFAULT"; // 10014 (0x271E)
  case WSAEINVAL:
    return "WSAEINVAL"; // 10022 (0x2726)
  case WSAEMFILE:
    return "WSAEMFILE"; // 10024 (0x2728)
  case WSAEWOULDBLOCK:
    return "WSAEWOULDBLOCK"; // 10035 (0x2733)
  case WSAEINPROGRESS:
    return "WSAEINPROGRESS"; // 10036 (0x2734)
  case WSAEALREADY:
    return "WSAEALREADY"; // 10037 (0x2735)
  case WSAENOTSOCK:
    return "WSAENOTSOCK"; // 10038 (0x2736)
  case WSAEDESTADDRREQ:
    return "WSAEDESTADDRREQ"; // 10039 (0x2737)
  case WSAEMSGSIZE:
    return "WSAEMSGSIZE"; // 10040 (0x2738)
  case WSAEPROTOTYPE:
    return "WSAEPROTOTYPE"; // 10041 (0x2739)
  case WSAENOPROTOOPT:
    return "WSAENOPROTOOPT"; // 10042 (0x273A)
  case WSAEPROTONOSUPPORT:
    return "WSAEPROTONOSUPPORT"; // 10043 (0x273B)
  case WSAESOCKTNOSUPPORT:
    return "WSAESOCKTNOSUPPORT"; // 10044 (0x273C)
  case WSAEOPNOTSUPP:
    return "WSAEOPNOTSUPP"; // 10045 (0x273D)
  case WSAEPFNOSUPPORT:
    return "WSAEPFNOSUPPORT"; // 10046 (0x273E)
  case WSAEAFNOSUPPORT:
    return "WSAEAFNOSUPPORT"; // 10047 (0x273F)
  case WSAEADDRINUSE:
    return "WSAEADDRINUSE"; // 10048 (0x2740)
  case WSAEADDRNOTAVAIL:
    return "WSAEADDRNOTAVAIL"; // 10049 (0x2741)
  case WSAENETDOWN:
    return "WSAENETDOWN"; // 10050 (0x2742)
  case WSAENETUNREACH:
    return "WSAENETUNREACH"; // 10051 (0x2743)
  case WSAENETRESET:
    return "WSAENETRESET"; // 10052 (0x2744)
  case WSAECONNABORTED:
    return "WSAECONNABORTED"; // 10053 (0x2745)
  case WSAECONNRESET:
    return "WSAECONNRESET"; // 10054 (0x2746)
  case WSAENOBUFS:
    return "WSAENOBUFS"; // 10055 (0x2747)
  case WSAEISCONN:
    return "WSAEISCONN"; // 10056 (0x2748)
  case WSAENOTCONN:
    return "WSAENOTCONN"; // 10057 (0x2749)
  case WSAESHUTDOWN:
    return "WSAESHUTDOWN"; // 10058 (0x274A)
  case WSAETOOMANYREFS:
    return "WSAETOOMANYREFS"; // 10059 (0x274B)
  case WSAETIMEDOUT:
    return "WSAETIMEDOUT"; // 10060 (0x274C)
  case WSAECONNREFUSED:
    return "WSAECONNREFUSED"; // 10061 (0x274D)
  case WSAELOOP:
    return "WSAELOOP"; // 10062 (0x274E)
  case WSAENAMETOOLONG:
    return "WSAENAMETOOLONG"; // 10063 (0x274F)
  case WSAEHOSTDOWN:
    return "WSAEHOSTDOWN"; // 10064 (0x2750)
  case WSAEHOSTUNREACH:
    return "WSAEHOSTUNREACH"; // 10065 (0x2751)
  case WSAENOTEMPTY:
    return "WSAENOTEMPTY"; // 10066 (0x2752)
  case WSAEPROCLIM:
    return "WSAEPROCLIM"; // 10067 (0x2753)
  case WSAEUSERS:
    return "WSAEUSERS"; // 10068 (0x2754)
  case WSAEDQUOT:
    return "WSAEDQUOT"; // 10069 (0x2755)
  case WSAESTALE:
    return "WSAESTALE"; // 10070 (0x2756)
  case WSAEREMOTE:
    return "WSAEREMOTE"; // 10071 (0x2757)
  case WSASYSNOTREADY:
    return "WSASYSNOTREADY"; // 10091 (0x276B)
  case WSAVERNOTSUPPORTED:
    return "WSAVERNOTSUPPORTED"; // 10092 (0x276C)
  case WSANOTINITIALISED:
    return "WSANOTINITIALISED"; // 10093 (0x276D)
  case WSAEDISCON:
    return "WSAEDISCON"; // 10101 (0x2775)
  default:
    return "UNKNOWN";
  }
#else
  // Non-Windows build: no Winsock -> stable stub.
  return "NO_WINSOCK";
#endif
}

/**
 * Address: 0x004801C0 (FUN_004801C0)
 * Mangled: ?NET_GetDottedOctetFromUInt32@Moho@@YA?AV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@I@Z
 *
 * uint32_t
 *
 * What it does:
 * Formats host-order IPv4 as "A.B.C.D".
 */
msvc8::string moho::NET_GetDottedOctetFromUInt32(const uint32_t number)
{
  return gpg::STR_Printf(
    "%d.%d.%d.%d", (number >> 24) & 0xFF, (number >> 16) & 0xFF, (number >> 8) & 0xFF, number & 0xFF
  );
}

/**
 * Address: 0x00480200 (FUN_00480200)
 * Mangled: ?NET_GetUInt32FromDottedOcted@Moho@@YAIV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z
 *
 * msvc8::string
 *
 * What it does:
 * Splits dotted IPv4 text by '.' and folds tokens using (acc << 8) | atoi(token).
 */
uint32_t moho::NET_GetUInt32FromDottedOcted(const msvc8::string& host)
{
  uint32_t value = 0;
  const char* cursor = host.c_str();
  msvc8::string token;

  while (gpg::STR_GetToken(cursor, ".", token)) {
    value = (value << 8) | static_cast<uint32_t>(std::atoi(token.c_str()));
  }

  return value;
}

ENetProtocolType moho::NET_ProtocolFromString(const char* str)
{
  if (!str) {
    throw std::domain_error("invalid protocol (null)");
  }

  if (_stricmp(str, "None") == 0) {
    return ENetProtocolType::kNone;
  }
  if (_stricmp(str, "TCP") == 0) {
    return ENetProtocolType::kTcp;
  }
  if (_stricmp(str, "UDP") == 0) {
    return ENetProtocolType::kUdp;
  }

  const msvc8::string msg = gpg::STR_Printf("invalid protocol (\"%s\")", str);
  throw std::domain_error(msg.c_str());
}
