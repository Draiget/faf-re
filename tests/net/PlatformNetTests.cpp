// Engine addition (issue #259): platform::net's socket calls and socket events on loopback, the
// behaviour moho/net's lockstep transport relies on (src/platform/Net.h).

#include "platform/Net.h"

#include <gtest/gtest.h>

#include <Windows.h>

#include <cstring>
#include <string>

#if FAFRE_PLATFORM_POSIX
#include <fcntl.h>
#endif

namespace
{
  namespace net = platform::net;

  constexpr DWORD kSignalWaitMs = 2000;
  constexpr DWORD kQuietWaitMs = 150;

  sockaddr_in Loopback(
    const std::uint16_t port
  )
  {
    sockaddr_in address{};
    address.sin_family = AF_INET;
    address.sin_port = htons(port);
    address.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    return address;
  }

  std::uint16_t LocalPort(
    const net::Socket socket
  )
  {
    sockaddr_in address{};
    EXPECT_EQ(net::GetLocalAddress(socket, &address), 0);
    return ntohs(address.sin_port);
  }

  bool Signalled(
    const net::EventHandle event,
    const DWORD timeoutMs
  )
  {
    return ::WaitForSingleObject(event, timeoutMs) == WAIT_OBJECT_0;
  }

  /// A socket bound to 127.0.0.1 on a free port, closed at the end of the test.
  struct BoundSocket
  {
    BoundSocket(
      const int type,
      const int protocol
    )
      : socket(net::OpenSocket(AF_INET, type, protocol))
    {
      EXPECT_NE(socket, net::kInvalidSocket);
      EXPECT_EQ(net::Bind(socket, Loopback(0)), 0);
    }
    ~BoundSocket()
    {
      if (socket != net::kInvalidSocket) {
        net::CloseSocket(socket);
      }
    }
    BoundSocket(const BoundSocket&) = delete;
    BoundSocket& operator=(const BoundSocket&) = delete;

    net::Socket socket;
  };

  struct SocketEvent
  {
    SocketEvent()
      : event(net::CreateSocketEvent())
    {
      EXPECT_NE(event, nullptr);
    }
    ~SocketEvent()
    {
      net::CloseSocketEvent(event);
    }
    SocketEvent(const SocketEvent&) = delete;
    SocketEvent& operator=(const SocketEvent&) = delete;

    net::EventHandle event;
  };

  /// Receives until a datagram or stream bytes arrive (the event said they would).
  int RecvSome(
    const net::Socket socket,
    char* const buffer,
    const int length
  )
  {
    for (int attempt = 0; attempt < 200; ++attempt) {
      const int received = net::Recv(socket, buffer, length);
      if (received >= 0 || net::LastError() != net::error::kWouldBlock) {
        return received;
      }
      ::Sleep(5);
    }
    return net::kSocketError;
  }
} // namespace

TEST(
  PlatformNet,
  StartupSucceeds
)
{
  EXPECT_EQ(net::Startup(), 0);
}

TEST(
  PlatformNet,
  UdpReadEventSignalsWhenADatagramArrives
)
{
  ASSERT_EQ(net::Startup(), 0);
  BoundSocket receiver{SOCK_DGRAM, IPPROTO_UDP};
  BoundSocket sender{SOCK_DGRAM, IPPROTO_UDP};
  SocketEvent ready;

  ASSERT_EQ(net::SetNonBlocking(receiver.socket), 0);
  ASSERT_EQ(net::SelectSocketEvents(receiver.socket, ready.event, net::kEventRead), 0);

  char buffer[64]{};
  sockaddr_in from{};
  EXPECT_EQ(net::RecvFrom(receiver.socket, buffer, sizeof(buffer), &from), net::kSocketError);
  EXPECT_EQ(net::LastError(), net::error::kWouldBlock);
  EXPECT_FALSE(Signalled(ready.event, kQuietWaitMs)) << "nothing was sent yet";

  const char payload[] = "lockstep";
  ASSERT_EQ(
    net::SendTo(sender.socket, payload, sizeof(payload), Loopback(LocalPort(receiver.socket))),
    static_cast<int>(sizeof(payload))
  );
  ASSERT_TRUE(Signalled(ready.event, kSignalWaitMs));

  net::ResetSocketEvent(ready.event);
  const int received = net::RecvFrom(receiver.socket, buffer, sizeof(buffer), &from);
  ASSERT_EQ(received, static_cast<int>(sizeof(payload)));
  EXPECT_EQ(std::memcmp(buffer, payload, sizeof(payload)), 0);
  EXPECT_EQ(ntohs(from.sin_port), LocalPort(sender.socket));
  EXPECT_EQ(ntohl(from.sin_addr.s_addr), static_cast<std::uint32_t>(INADDR_LOOPBACK));

  // Drained: the read that would block re-enables the event, and nothing signals it.
  EXPECT_EQ(net::RecvFrom(receiver.socket, buffer, sizeof(buffer), &from), net::kSocketError);
  EXPECT_EQ(net::LastError(), net::error::kWouldBlock);
  EXPECT_FALSE(Signalled(ready.event, kQuietWaitMs));

  // A second datagram signals again.
  ASSERT_EQ(net::SendTo(sender.socket, payload, 4, Loopback(LocalPort(receiver.socket))), 4);
  EXPECT_TRUE(Signalled(ready.event, kSignalWaitMs));
}

TEST(
  PlatformNet,
  UdpDatagramsLeftUnreadSignalAgainAfterARead
)
{
  ASSERT_EQ(net::Startup(), 0);
  BoundSocket receiver{SOCK_DGRAM, IPPROTO_UDP};
  BoundSocket sender{SOCK_DGRAM, IPPROTO_UDP};
  SocketEvent ready;
  ASSERT_EQ(net::SelectSocketEvents(receiver.socket, ready.event, net::kEventRead), 0);

  const sockaddr_in to = Loopback(LocalPort(receiver.socket));
  ASSERT_EQ(net::SendTo(sender.socket, "a", 1, to), 1);
  ASSERT_EQ(net::SendTo(sender.socket, "b", 1, to), 1);
  ASSERT_TRUE(Signalled(ready.event, kSignalWaitMs));
  net::ResetSocketEvent(ready.event);

  // One read, one datagram still queued: Winsock re-posts the read, so the event comes back.
  char buffer[8]{};
  sockaddr_in from{};
  ASSERT_EQ(net::RecvFrom(receiver.socket, buffer, sizeof(buffer), &from), 1);
  EXPECT_TRUE(Signalled(ready.event, kSignalWaitMs));
}

TEST(
  PlatformNet,
  UdpWriteEventSignalsOnceUntilASendWouldBlock
)
{
  ASSERT_EQ(net::Startup(), 0);
  BoundSocket socket{SOCK_DGRAM, IPPROTO_UDP};
  SocketEvent ready;
  ASSERT_EQ(net::SelectSocketEvents(socket.socket, ready.event, net::kEventRead | net::kEventWrite), 0);
  EXPECT_TRUE(Signalled(ready.event, kSignalWaitMs)) << "a fresh socket can send";
  net::ResetSocketEvent(ready.event);
  EXPECT_FALSE(Signalled(ready.event, kQuietWaitMs)) << "write is reported once, as in Winsock";
}

TEST(
  PlatformNet,
  SelectSocketEventsMakesTheSocketNonBlocking
)
{
  ASSERT_EQ(net::Startup(), 0);
  BoundSocket socket{SOCK_DGRAM, IPPROTO_UDP};
  SocketEvent ready;
  ASSERT_EQ(net::SelectSocketEvents(socket.socket, ready.event, net::kEventRead), 0);
  char buffer[8]{};
  sockaddr_in from{};
  EXPECT_EQ(net::RecvFrom(socket.socket, buffer, sizeof(buffer), &from), net::kSocketError);
  EXPECT_EQ(net::LastError(), net::error::kWouldBlock);
}

TEST(
  PlatformNet,
  TcpListenConnectAcceptSendAndClose
)
{
  ASSERT_EQ(net::Startup(), 0);
  BoundSocket listener{SOCK_STREAM, IPPROTO_TCP};
  ASSERT_EQ(net::SetNonBlocking(listener.socket), 0);
  ASSERT_EQ(net::Listen(listener.socket, SOMAXCONN), 0);
  SocketEvent accepting;
  ASSERT_EQ(net::SelectSocketEvents(listener.socket, accepting.event, net::kEventAccept), 0);

  sockaddr_in none{};
  EXPECT_EQ(net::Accept(listener.socket, &none), net::kInvalidSocket);
  EXPECT_EQ(net::LastError(), net::error::kWouldBlock);
  EXPECT_FALSE(Signalled(accepting.event, kQuietWaitMs)) << "nobody connected yet";

  // The client connects without blocking, as CNetTCPConnector::Connect does.
  const net::Socket client = net::OpenSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  ASSERT_NE(client, net::kInvalidSocket);
  ASSERT_EQ(net::SetNonBlocking(client), 0);
  const int connected = net::Connect(client, Loopback(LocalPort(listener.socket)));
  if (connected != 0) {
    EXPECT_EQ(net::LastError(), net::error::kWouldBlock) << "a connect under way reads as Winsock's would-block";
  }
  SocketEvent clientReady;
  ASSERT_EQ(
    net::SelectSocketEvents(client, clientReady.event, net::kEventRead | net::kEventConnect | net::kEventClose), 0
  );
#if FAFRE_PLATFORM_POSIX
  // Winsock may have finished a loopback connect before the selection, and then posts nothing.
  ASSERT_TRUE(Signalled(clientReady.event, kSignalWaitMs)) << "connect is reported";
#endif
  net::ConnectPoll polled = net::ConnectPoll::kPending;
  for (int attempt = 0; attempt < 400 && polled == net::ConnectPoll::kPending; ++attempt) {
    polled = net::PollConnect(client);
    ::Sleep(5);
  }
  EXPECT_EQ(polled, net::ConnectPoll::kConnected);

  ASSERT_TRUE(Signalled(accepting.event, kSignalWaitMs)) << "accept is reported";
  net::ResetSocketEvent(accepting.event);
  sockaddr_in peer{};
  const net::Socket accepted = net::Accept(listener.socket, &peer);
  ASSERT_NE(accepted, net::kInvalidSocket);
  EXPECT_EQ(ntohs(peer.sin_port), LocalPort(client));
  EXPECT_FALSE(Signalled(accepting.event, kQuietWaitMs)) << "accept re-enabled, no second client";

  // The accepted socket inherits the listener's non-blocking mode, as in Winsock.
  char buffer[64]{};
  EXPECT_EQ(net::Recv(accepted, buffer, sizeof(buffer)), net::kSocketError);
  EXPECT_EQ(net::LastError(), net::error::kWouldBlock);
#if FAFRE_PLATFORM_POSIX
  EXPECT_NE(::fcntl(accepted, F_GETFL, 0) & O_NONBLOCK, 0);
#endif

  SocketEvent acceptedReady;
  ASSERT_EQ(net::SelectSocketEvents(accepted, acceptedReady.event, net::kEventRead | net::kEventClose), 0);
  const char hello[] = "hello";
  ASSERT_EQ(net::Send(client, hello, sizeof(hello)), static_cast<int>(sizeof(hello)));
  ASSERT_TRUE(Signalled(acceptedReady.event, kSignalWaitMs)) << "read is reported";
  net::ResetSocketEvent(acceptedReady.event);
  ASSERT_EQ(RecvSome(accepted, buffer, sizeof(buffer)), static_cast<int>(sizeof(hello)));
  EXPECT_EQ(std::string(buffer), "hello");

  sockaddr_in remote{};
  ASSERT_EQ(net::GetPeerAddress(accepted, &remote), 0);
  EXPECT_EQ(ntohs(remote.sin_port), LocalPort(client));

  // The client shuts its side and closes: the accepted socket reports it and reads end of stream.
  EXPECT_EQ(net::Shutdown(client, net::ShutdownHow::kSend), 0);
  EXPECT_EQ(net::CloseSocket(client), 0);
  ASSERT_TRUE(Signalled(acceptedReady.event, kSignalWaitMs)) << "close is reported";
  EXPECT_EQ(RecvSome(accepted, buffer, sizeof(buffer)), 0);

  // Sending to a closed peer fails without killing the process (no SIGPIPE).
  int sendResult = 0;
  for (int attempt = 0; attempt < 50 && sendResult >= 0; ++attempt) {
    sendResult = net::Send(accepted, hello, sizeof(hello));
    ::Sleep(5);
  }
  EXPECT_EQ(sendResult, net::kSocketError);
  EXPECT_EQ(net::CloseSocket(accepted), 0);
}

TEST(
  PlatformNet,
  TcpConnectToAClosedPortFails
)
{
  ASSERT_EQ(net::Startup(), 0);
  // A port that was free a moment ago: bind, read it, close.
  std::uint16_t port = 0;
  {
    BoundSocket probe{SOCK_STREAM, IPPROTO_TCP};
    port = LocalPort(probe.socket);
  }
  const net::Socket client = net::OpenSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  ASSERT_NE(client, net::kInvalidSocket);
  ASSERT_EQ(net::SetNonBlocking(client), 0);
  const int connected = net::Connect(client, Loopback(port));
  if (connected != 0 && net::LastError() == net::error::kWouldBlock) {
    net::ConnectPoll polled = net::ConnectPoll::kPending;
    for (int attempt = 0; attempt < 400 && polled == net::ConnectPoll::kPending; ++attempt) {
      polled = net::PollConnect(client);
      ::Sleep(5);
    }
    EXPECT_EQ(polled, net::ConnectPoll::kFailed);
  } else {
    EXPECT_EQ(connected, net::kSocketError);
    EXPECT_EQ(net::LastError(), net::error::kConnectionRefused);
  }
  net::CloseSocket(client);
}

TEST(
  PlatformNet,
  PollReadableSeesQueuedStreamBytes
)
{
  ASSERT_EQ(net::Startup(), 0);
  BoundSocket listener{SOCK_STREAM, IPPROTO_TCP};
  ASSERT_EQ(net::Listen(listener.socket, 1), 0);
  const net::Socket client = net::OpenSocket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
  ASSERT_EQ(net::Connect(client, Loopback(LocalPort(listener.socket))), 0) << "a blocking connect";
  const net::Socket accepted = net::Accept(listener.socket, nullptr);
  ASSERT_NE(accepted, net::kInvalidSocket);

  EXPECT_EQ(net::PollReadable(accepted), 0);
  ASSERT_EQ(net::Send(client, "x", 1), 1);
  int readable = 0;
  for (int attempt = 0; attempt < 200 && readable == 0; ++attempt) {
    readable = net::PollReadable(accepted);
    ::Sleep(5);
  }
  EXPECT_EQ(readable, 1);
  net::CloseSocket(client);
  net::CloseSocket(accepted);
}

TEST(
  PlatformNet,
  ClosingAnEventEndsItsSelections
)
{
  ASSERT_EQ(net::Startup(), 0);
  BoundSocket receiver{SOCK_DGRAM, IPPROTO_UDP};
  BoundSocket sender{SOCK_DGRAM, IPPROTO_UDP};
  const net::EventHandle event = net::CreateSocketEvent();
  ASSERT_NE(event, nullptr);
  ASSERT_EQ(net::SelectSocketEvents(receiver.socket, event, net::kEventRead), 0);
  ASSERT_TRUE(net::CloseSocketEvent(event));
  // Data for a socket whose event is gone must not touch the closed event.
  ASSERT_EQ(net::SendTo(sender.socket, "z", 1, Loopback(LocalPort(receiver.socket))), 1);
  ::Sleep(kQuietWaitMs);
  char buffer[4]{};
  sockaddr_in from{};
  EXPECT_EQ(net::RecvFrom(receiver.socket, buffer, sizeof(buffer), &from), 1);
}
