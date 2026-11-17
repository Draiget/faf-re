// What a lobby's host sends each player about another (LOBMSG_NewPeer, moho/net/SPeer.cpp): the Windows game's bytes,
// which every build that plays with it writes and reads. The address is a u_long in the engine, 4 bytes on Windows and
// 8 on LP64 POSIX (src/platform/posix/win32/winsock2.h).

#include "moho/net/CMessage.h"
#include "moho/net/Common.h"
#include "moho/net/ELobbyMsg.h"
#include "moho/net/INetConnection.h"
#include "moho/net/SPeer.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <string>

using namespace moho;

namespace
{
  /// Keeps what is written to it.
  class RecordingConnection final : public INetConnection
  {
  public:
    std::string written;

    u_long GetAddr() override
    {
      return 0x7F000001u;
    }
    u_short GetPort() override
    {
      return 1;
    }
    float GetPing() override
    {
      return 0.0f;
    }
    float GetTime() override
    {
      return 0.0f;
    }
    void Write(
      NetDataSpan* const data
    ) override
    {
      written.append(reinterpret_cast<const char*>(data->start), data->size());
    }
    void Close() override {}
    fa::string ToString() override
    {
      return fa::string("recorder");
    }
    void ScheduleDestroy() override {}
  };
} // namespace

// SPeer::SendInfoTo (0x007C8070): the name, then the address in 4 bytes (0x007C81CD), the port in 2 (0x007C81FC)
// and the uid in 4, as CLobby::OnNewPeer reads them (0x007C70C2, 0x007C70DC, 0x007C70F1). The address is the
// loopback's, whose name the log line SendInfoTo writes is found at once.
TEST(
  LobbyWire,
  NewPeerIsTheNameAndTenBytes
)
{
  RecordingConnection connection;
  const SPeer peer(
    fa::string("Third"), 0x01020304, 0x7F000001u, 0x1E1F, &connection, ENetworkPlayerState::kEstablished
  );
  peer.SendInfoTo(&connection);

  const std::string payload = std::string("Third\0", 6) + std::string("\x01\x00\x00\x7F", 4) +
    std::string("\x1F\x1E", 2) + std::string("\x04\x03\x02\x01", 4);
  ASSERT_EQ(connection.written.size(), 3 + payload.size());
  const auto byte = [&connection](const std::size_t at) {
    return static_cast<std::size_t>(static_cast<std::uint8_t>(connection.written[at]));
  };
  EXPECT_EQ(byte(0), static_cast<std::size_t>(ELobbyMsg::LOBMSG_NewPeer));
  EXPECT_EQ(byte(1) | (byte(2) << 8), 3 + payload.size()); // the message's size, low byte first
  EXPECT_EQ(connection.written.substr(3), payload);
}
