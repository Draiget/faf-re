// The engine's TCP stream (moho/net/CNetTCPBuf.cpp), which NET_TCPConnect and INetTCPServer::Accept make: GPGNet's
// link to the launcher, and a live replay's stream (`/replay gpgnet://...`, ReplaySessionSetup.cpp's
// OpenGPGNetSocket). Its read serves what its 2 KB buffer holds, receives straight into the caller's memory while
// 2 KB or more are left, and takes the rest through the buffer. Real sockets on 127.0.0.1: the game's end connects,
// and the launcher's end is the one the listener accepts.

#include "gpg/core/streams/BinaryReader.h"
#include "moho/net/CMessage.h"
#include "moho/net/Common.h"
#include "moho/net/ECmdStreamOp.h"
#include "moho/net/INetTCPServer.h"
#include "moho/net/INetTCPSocket.h"
#include "moho/net/NetConstants.h"

#include <gtest/gtest.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <memory>
#include <random>
#include <string>
#include <string_view>
#include <thread>

namespace
{
  constexpr u_long kLoopback = 0x7F000001; // host order, as the engine passes addresses
  constexpr std::size_t kBuffer = moho::kNetIoBufferSize;

  /// `size` letters from `seed`: a launcher's arguments are text (JSON), and a byte out of place shows.
  std::string RandomText(
    const std::size_t size,
    const unsigned seed
  )
  {
    std::mt19937 random(seed);
    std::uniform_int_distribution<int> letter('a', 'z');
    std::string text(size, '\0');
    for (char& c : text) {
      c = static_cast<char>(letter(random));
    }
    return text;
  }

  /// The game's stream to its launcher, as CGpgNetInterface connects it, and the launcher's end of it.
  class TcpStream : public ::testing::Test
  {
  protected:
    void SetUp() override
    {
      listener.reset(moho::NET_CreateTCPServer(kLoopback, 0));
      ASSERT_NE(listener.get(), nullptr);
      // The listener's backlog takes the connection before it is accepted.
      game.reset(moho::NET_TCPConnect(kLoopback, listener->GetLocalPort()));
      ASSERT_NE(game.get(), nullptr);
      launcher.reset(listener->Accept());
      ASSERT_NE(launcher.get(), nullptr);
    }

    /// String arguments as a launcher writes a message's: each its 4-byte length and its bytes, flushed together.
    void Send(
      const std::initializer_list<std::string_view> arguments
    )
    {
      for (const std::string_view argument : arguments) {
        const auto length = static_cast<std::uint32_t>(argument.size());
        launcher->Write(&length, sizeof(length));
        launcher->Write(argument.data(), argument.size());
      }
      launcher->VirtFlush();
    }

    /// Whether the game reads `sent` whole, as GPGNet reads a string argument's length and bytes
    /// (NET_DecodeSocketArg, NET_ReadLengthPrefixedArgPayload).
    ::testing::AssertionResult ArrivesWhole(
      const std::string_view sent
    )
    {
      gpg::BinaryReader reader(game.get());
      try {
        const fa::string received = moho::NET_ReadLengthPrefixedArgPayload(reader);
        if (received.view() != sent) {
          return ::testing::AssertionFailure()
            << received.size() << " bytes arrived for " << sent.size() << ", not the ones sent";
        }
        return ::testing::AssertionSuccess();
      } catch (const gpg::BinaryReader::PrematureEOF& error) {
        return ::testing::AssertionFailure() << "the read of " << sent.size() << " bytes threw " << error.what()
                                             << ", which ends GPGNet's link (CommunicationError)";
      }
    }

    std::unique_ptr<moho::INetTCPServer> listener;
    std::unique_ptr<moho::INetTCPSocket> game;
    std::unique_ptr<moho::INetTCPSocket> launcher;
  };
} // namespace

// 3 KB: its first bytes come with the length's read, and the rest, under 2 KB, with one more receive into the buffer.
TEST_F(
  TcpStream,
  AnArgumentWhoseRestFitsTheBufferArrivesWhole
)
{
  const std::string servers = RandomText(kBuffer + 1000, 1);
  Send({"Idle", servers, "Lobby"});
  EXPECT_TRUE(ArrivesWhole("Idle"));
  EXPECT_TRUE(ArrivesWhole(servers));
  EXPECT_TRUE(ArrivesWhole("Lobby"));
}

// 2 KB of which the buffer holds nothing: the argument before it, 8 bytes short of 2 KB, and the two lengths fill
// the stream's first receive, so all of the 2 KB come straight from the socket.
TEST_F(
  TcpStream,
  AnArgumentOf2KbWithNothingOfItBufferedArrivesWhole
)
{
  const std::string filler = RandomText(kBuffer - 2 * sizeof(std::uint32_t), 2);
  const std::string offer = RandomText(kBuffer, 3);
  Send({filler, offer, "Lobby"});
  ASSERT_TRUE(ArrivesWhole(filler));
  ASSERT_TRUE(ArrivesWhole(offer));
  EXPECT_TRUE(ArrivesWhole("Lobby")) << "the stream is in step after it";
}

// 4 KB, as a peer's ICE candidates can be in native mode: 2 KB or more are left after the buffer's part wherever
// it starts.
TEST_F(
  TcpStream,
  AnArgumentOf4KbArrivesWhole
)
{
  const std::string candidates = RandomText(2 * kBuffer, 4);
  Send({candidates, "Lobby"});
  ASSERT_TRUE(ArrivesWhole(candidates));
  EXPECT_TRUE(ArrivesWhole("Lobby")) << "the stream is in step after it";
}

// 64 KB, which the launcher writes while the game reads: as many receives straight from the socket as the loopback
// hands over, then the rest through the buffer.
TEST_F(
  TcpStream,
  AnArgumentOf64KbWrittenWhileTheGameReadsArrivesWhole
)
{
  const std::string many = RandomText(64 * 1024, 5);
  std::thread writer([&] {
    Send({many});
  });
  const ::testing::AssertionResult arrived = ArrivesWhole(many);
  if (!arrived) {
    game.reset(); // a writer still in send() fails once the game's end is closed
  }
  writer.join();
  ASSERT_TRUE(arrived);
  Send({"Lobby"});
  EXPECT_TRUE(ArrivesWhole("Lobby")) << "the stream is in step after it";
}

// A live replay's client takes a message at a time without blocking (CReplayClient::Start, CMessage::Read), adding
// each read's count to the message's position: a sim callback of 4 KB, then a beat, arrive whole and in step.
TEST_F(
  TcpStream,
  ALiveReplaysMessageOf4KbArrivesWholeWithoutBlocking
)
{
  moho::CMessage callback{moho::ECmdStreamOp::CMDST_LuaSimCallback};
  const std::string payload = RandomText(2 * kBuffer, 6);
  callback.Append(payload.data(), payload.size());
  moho::CMessage advance{moho::ECmdStreamOp::CMDST_Advance};
  const std::int32_t beats = 1;
  advance.Append(reinterpret_cast<const char*>(&beats), sizeof(beats));
  launcher->Write(callback.mBuff.start_, callback.mBuff.Size());
  launcher->Write(advance.mBuff.start_, advance.mBuff.Size());
  launcher->VirtFlush();

  const auto bytes = [](const moho::CMessage& message) {
    return std::string(message.mBuff.start_, message.mBuff.end_);
  };
  const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
  for (const moho::CMessage* const sent : {&callback, &advance}) {
    moho::CMessage received;
    bool whole = received.Read(game.get());
    while (!whole && std::chrono::steady_clock::now() < deadline) {
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
      whole = received.Read(game.get());
    }
    ASSERT_TRUE(whole) << received.mPos << " of " << sent->mBuff.Size() << " bytes counted after 5 s";
    EXPECT_TRUE(bytes(received) == bytes(*sent)) << "a whole message of other bytes than the ones sent";
  }
}

// A live replay's 6 KB sim callback that arrives in two parts: the read without blocking stops in the middle of the
// receive straight into the message, once the socket has nothing more, and the bytes it took there count. The rest
// and the beat after it then arrive whole and in step.
TEST_F(
  TcpStream,
  ALiveReplaysMessageInTwoPartsStaysInStep
)
{
  moho::CMessage callback{moho::ECmdStreamOp::CMDST_LuaSimCallback};
  const std::string payload = RandomText(3 * kBuffer, 7);
  callback.Append(payload.data(), payload.size());
  moho::CMessage advance{moho::ECmdStreamOp::CMDST_Advance};
  const std::int32_t beats = 1;
  advance.Append(reinterpret_cast<const char*>(&beats), sizeof(beats));
  const std::size_t firstPart = kBuffer + kBuffer / 4; // 2.5 KB: the buffer's 2 KB, then 512 bytes straight
  launcher->Write(callback.mBuff.start_, firstPart);
  launcher->VirtFlush();

  // The first part may come over the loopback in pieces: read until all of it is counted, or 5 s pass.
  moho::CMessage first;
  auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
  while (first.mPos < static_cast<int>(firstPart) && std::chrono::steady_clock::now() < deadline) {
    ASSERT_FALSE(first.Read(game.get())) << "a whole message from part of it";
    std::this_thread::sleep_for(std::chrono::milliseconds(1));
  }
  ASSERT_EQ(first.mPos, static_cast<int>(firstPart)) << "bytes counted from the first part after 5 s";

  launcher->Write(callback.mBuff.start_ + firstPart, callback.mBuff.Size() - firstPart);
  launcher->Write(advance.mBuff.start_, advance.mBuff.Size());
  launcher->VirtFlush();

  const auto bytes = [](const moho::CMessage& message) {
    return std::string(message.mBuff.start_, message.mBuff.end_);
  };
  const auto readWhole = [&](moho::CMessage& message) {
    deadline = std::chrono::steady_clock::now() + std::chrono::seconds(5);
    bool whole = message.Read(game.get());
    while (!whole && std::chrono::steady_clock::now() < deadline) {
      std::this_thread::sleep_for(std::chrono::milliseconds(1));
      whole = message.Read(game.get());
    }
    return whole;
  };

  ASSERT_TRUE(readWhole(first)) << first.mPos << " of " << callback.mBuff.Size() << " bytes counted after 5 s";
  EXPECT_TRUE(bytes(first) == bytes(callback)) << "a whole message of other bytes than the ones sent";

  moho::CMessage second;
  ASSERT_TRUE(readWhole(second)) << second.mPos << " of " << advance.mBuff.Size() << " bytes counted after 5 s";
  EXPECT_TRUE(bytes(second) == bytes(advance)) << "the beat after it is out of step";
}
