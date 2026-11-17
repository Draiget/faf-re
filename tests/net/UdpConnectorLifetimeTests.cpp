// The end of a UDP connector (moho/net/CNetUDPConnector.cpp). Destroy hands it to its own thread, which says goodbye
// on every connection; the thread then lets go of the connector's last owner, which deletes it, as the binary's
// does (Entry; FAF hot-patch: 0x00489F90 jumps to 0x0128C620 in .exxt, which releases the owner at 0x0128C88C), and
// the destructor closes its socket and its event. Real connectors in this process, on 127.0.0.1; a port that can be
// bound again shows a connector that is gone, and a connector made on it then is what the next lobby on that port
// makes.

#include "NetTestSupport.h"

#include "moho/net/CMessage.h"
#include "moho/net/CNetUDPConnector.h"
#include "moho/net/Common.h"
#include "moho/net/ELobbyMsg.h"
#include "moho/net/IMessageReceiver.h"
#include "moho/net/INetConnection.h"
#include "moho/net/INetConnector.h"

#include "platform/PlatformDefines.h"

#include <gtest/gtest.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <system_error>
#include <thread>
#include <vector>

#if FAFRE_PLATFORM_WINDOWS
#include <Windows.h>
#else
#include <pthread.h>
#include <unistd.h>
#endif

using namespace moho;
using net_test::Clock;
using net_test::kConnectorGoneWithin;
using net_test::PortFree;
using net_test::Pump;

namespace
{
  constexpr u_long kLoopback = 0x7F000001; // host order, as the engine passes addresses
  constexpr unsigned kMessageType = 100;   // outside the connection events, 200..209

  struct Inbox final : IMessageReceiver
  {
    std::vector<unsigned> types;

    void ReceiveMessage(
      CMessage* const message,
      CMessageDispatcher*
    ) override
    {
      types.push_back(message->GetType().raw());
    }
  };

  /// Destroys its connector from a message, inside the connector's own Pull, as a lobby's Lua can destroy the lobby,
  /// and the connector with it, from a callback. It lets go of its connection first: from Destroy on, the connector's
  /// thread deletes the connection, and with it the connection's linkage to this receiver.
  struct DestroysItsConnector final : IMessageReceiver
  {
    INetConnector* connector = nullptr;

    void ReceiveMessage(
      CMessage* const message,
      CMessageDispatcher* const dispatcher
    ) override
    {
      if (connector == nullptr || message->GetType().raw() != kMessageType) {
        return;
      }
      dispatcher->RemoveReceiver(kMessageType, kMessageType + 1, this);
      connector->Destroy();
      connector = nullptr;
    }
  };

  /// The next lobby on `port`: InternalCreateLobby makes its connector there (NET_MakeUDPConnector). That connector is
  /// destroyed again and gone before the test goes on.
  void ExpectANewConnectorOn(
    const u_short port
  )
  {
    INetConnector* const next = NET_MakeUDPConnector(port, {});
    ASSERT_NE(next, nullptr) << "no connector can be made on port " << port;
    next->Destroy();
    EXPECT_TRUE(PortFree(port, kConnectorGoneWithin)) << "port " << port << " is still bound after the next connector";
  }
} // namespace

// With no connection the thread ends at its next pass, and the connector goes with it.
TEST(
  UdpConnector,
  DestroyFreesThePort
)
{
  ASSERT_TRUE(NET_Init());
  INetConnector* const connector = NET_MakeUDPConnector(0, {});
  ASSERT_NE(connector, nullptr);
  const u_short port = connector->GetLocalPort();
  EXPECT_FALSE(PortFree(port)) << "the connector holds its port";
  connector->Destroy();
  EXPECT_TRUE(PortFree(port, kConnectorGoneWithin)) << "port " << port << " is still bound after Destroy";
  ExpectANewConnectorOn(port);
}

// A lobby that is left: its connection says goodbye, which ends the connection on the other side, and then the
// connector goes, so the next lobby can make its connector on that port.
TEST(
  UdpConnector,
  DestroyFreesThePortOnceTheConnectionsHaveSaidGoodbye
)
{
  ASSERT_TRUE(NET_Init());
  INetConnector* const leaving = NET_MakeUDPConnector(0, {});
  INetConnector* const staying = NET_MakeUDPConnector(0, {});
  ASSERT_TRUE(leaving != nullptr && staying != nullptr);
  const u_short port = leaving->GetLocalPort();
  const u_short stayingPort = staying->GetLocalPort();

  INetConnection* const outgoing = leaving->Connect(kLoopback, stayingPort);
  ASSERT_NE(outgoing, nullptr);
  u_long address = 0;
  u_short from = 0;
  const auto knocked = [&] {
    return staying->FindNextAddress(address, from);
  };
  ASSERT_TRUE(Pump(leaving, staying, knocked)) << "no CONNECT arrived";
  INetConnection* const incoming = staying->Accept(address, from);
  ASSERT_NE(incoming, nullptr);
  Inbox atLeaving;
  Inbox atStaying;
  outgoing->PushReceiver(0, 256, &atLeaving);
  incoming->PushReceiver(0, 256, &atStaying);
  const auto made = [&] {
    return !atStaying.types.empty();
  };
  ASSERT_TRUE(Pump(leaving, staying, made)) << "no connection made";
  // The staying side's stream ends first, so its own end, at the test's end, waits for no answer from one gone.
  incoming->Close();
  const unsigned endOfStream = static_cast<unsigned>(ELobbyMsg::LOBMSG_ConnLostEof);
  const auto leavingHasItsEnd = [&] {
    return !atLeaving.types.empty() && atLeaving.types.back() == endOfStream;
  };
  ASSERT_TRUE(Pump(leaving, staying, leavingHasItsEnd)) << "the staying side's end did not arrive";

  // As a lobby leaves (CLobby::~CLobby): the connection, then the connector. The receiver lets go first, as the
  // connector's thread deletes the connection from Destroy on; the staying side is pumped alone from here.
  outgoing->RemoveReceiver(0, 256, &atLeaving);
  outgoing->ScheduleDestroy();
  leaving->Push();
  leaving->Destroy();
  const auto stayingHasItsEnd = [&] {
    return atStaying.types.back() == endOfStream;
  };
  EXPECT_TRUE(Pump(staying, staying, stayingHasItsEnd)) << "the leaving side's end did not arrive";
  EXPECT_TRUE(PortFree(port, kConnectorGoneWithin)) << "port " << port << " is still bound after the goodbye";
  ExpectANewConnectorOn(port);

  incoming->RemoveReceiver(0, 256, &atStaying);
  staying->Destroy();
  EXPECT_TRUE(PortFree(stayingPort, kConnectorGoneWithin));
}

// A lobby's Lua can destroy the lobby from a message's callback: Destroy then comes inside the connector's own Pull.
// The connector still goes, once Pull is over and its connection has said goodbye, and frees its port. That goodbye
// takes a round trip after Pull, so the thread does not end while Pull's end runs: this shows nothing of the lock
// that end takes.
TEST(
  UdpConnector,
  DestroyInsideItsOwnPullFreesThePort
)
{
  ASSERT_TRUE(NET_Init());
  INetConnector* const guest = NET_MakeUDPConnector(0, {});
  INetConnector* const host = NET_MakeUDPConnector(0, {});
  ASSERT_TRUE(guest != nullptr && host != nullptr);
  const u_short guestPort = guest->GetLocalPort();
  const u_short port = host->GetLocalPort();
  INetConnection* const toHost = guest->Connect(kLoopback, port);
  ASSERT_NE(toHost, nullptr);
  u_long address = 0;
  u_short from = 0;
  const auto knocked = [&] {
    return host->FindNextAddress(address, from);
  };
  ASSERT_TRUE(Pump(host, guest, knocked)) << "no CONNECT arrived";
  DestroysItsConnector receiver;
  receiver.connector = host;
  INetConnection* const fromGuest = host->Accept(address, from);
  ASSERT_NE(fromGuest, nullptr);
  fromGuest->PushReceiver(kMessageType, kMessageType + 1, &receiver);

  CMessage message(MessageType(static_cast<std::uint8_t>(kMessageType)));
  toHost->Write(message);
  toHost->Close(); // the host's goodbye has it, so the guest's own end waits for nobody
  guest->Push();
  // Not Pump: once the receiver has destroyed the host, nothing may touch it, as its thread may delete it.
  const Clock::time_point end = Clock::now() + std::chrono::seconds(5);
  while (receiver.connector != nullptr && Clock::now() < end) {
    host->Pull();
    guest->Pull();
    std::this_thread::sleep_for(std::chrono::milliseconds(5));
  }
  ASSERT_EQ(receiver.connector, nullptr) << "the message did not arrive";
  EXPECT_TRUE(PortFree(port, kConnectorGoneWithin)) << "port " << port << " is still bound";
  ExpectANewConnectorOn(port);

  toHost->ScheduleDestroy();
  guest->Destroy();
  EXPECT_TRUE(PortFree(guestPort, kConnectorGoneWithin));
}

#if FAFRE_PLATFORM_WINDOWS
namespace
{
  /// A connector made, destroyed at once and gone (its port bound again).
  bool MakeAndEndOne()
  {
    INetConnector* const connector = NET_MakeUDPConnector(0, {});
    if (connector == nullptr) {
      return false;
    }
    const u_short port = connector->GetLocalPort();
    connector->Destroy();
    return PortFree(port, kConnectorGoneWithin);
  }
} // namespace

// What a connector opened, its socket and its event, is closed once it is gone: the process's handle count comes
// back. Each connector of a lobby or game would leave one behind otherwise.
TEST(
  UdpConnector,
  AConnectorThatIsGoneLeavesNoHandleOpen
)
{
  ASSERT_TRUE(NET_Init());
  ASSERT_TRUE(MakeAndEndOne()); // what Winsock and the first thread open once
  DWORD before = 0;
  ASSERT_TRUE(::GetProcessHandleCount(::GetCurrentProcess(), &before));
  constexpr int kConnectors = 20;
  for (int i = 0; i < kConnectors; ++i) {
    ASSERT_TRUE(MakeAndEndOne()) << "connector " << i;
  }
  // The port is free before the destructor closes the event and the thread ends: wait for the count to settle.
  DWORD after = 0;
  const Clock::time_point end = Clock::now() + std::chrono::seconds(5);
  do {
    std::this_thread::sleep_for(std::chrono::milliseconds(50));
    ASSERT_TRUE(::GetProcessHandleCount(::GetCurrentProcess(), &after));
  } while (after > before + 2 && Clock::now() < end);
  EXPECT_LE(after, before + 2) << before << " handles before " << kConnectors << " connectors, " << after << " after";
}
#endif

#if FAFRE_PLATFORM_LINUX && defined(__GLIBC__) // pthread_setattr_default_np is glibc's
namespace
{
  /// In the death test's child: a connector whose thread cannot start, as every thread started from then on asks
  /// for a stack larger than any address space. Exits 0 when the constructor threw what std::thread throws.
  [[noreturn]] void MakeAConnectorWhoseThreadDoesNotStart()
  {
    // A crash's report can wait for ever on a lock the crash left held: the alarm ends the child then.
    ::alarm(30);
    if (!NET_Init()) {
      std::_Exit(2);
    }
    // The socket poller's thread starts with the first connector, in a function that may not throw.
    if (NET_MakeUDPConnector(0, {}) == nullptr) {
      std::_Exit(3);
    }
    pthread_attr_t attributes;
    if (
      ::pthread_attr_init(&attributes) != 0 ||
      ::pthread_attr_setstacksize(&attributes, std::numeric_limits<std::size_t>::max() / 2) != 0 ||
      ::pthread_setattr_default_np(&attributes) != 0
    ) {
      std::_Exit(4);
    }
    try {
      (void)NET_MakeUDPConnector(0, {});
    } catch (const std::system_error&) {
      std::fputs("the thread did not start, and the constructor threw\n", stderr);
      std::_Exit(0);
    }
    std::fputs("the thread started after all\n", stderr);
    std::_Exit(6);
  }
} // namespace

// The connector's owner deletes it, but not one whose thread did not start: the constructor throws then, its
// unwinding runs only the members' destructors, and the new-expression frees the memory.
TEST(
  UdpConnectorDeathTest,
  AThreadThatDoesNotStartLeavesTheConnectorToItsConstructor
)
{
  GTEST_FLAG_SET(death_test_style, "threadsafe");
  EXPECT_EXIT(MakeAConnectorWhoseThreadDoesNotStart(), ::testing::ExitedWithCode(0), "the thread did not start");
}
#endif
