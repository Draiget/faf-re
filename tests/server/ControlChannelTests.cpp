// Plan WP17.2: the control API's channel (server/ControlChannel.h): handshake, frames, and a known-answer vector
// computed with Go's golang.org/x/crypto v0.58.0 (blake2b.New(32, key), chacha20poly1305.NewX), as the control
// service will compute it.
#include <gtest/gtest.h>

#include <string>
#include <string_view>
#include <vector>

#include "server/ControlChannel.h"
#include "server/ControlListener.h"

namespace
{
  using faf::server::CControlChannel;
  using faf::server::ControlKey;
  using faf::server::ControlNonce;
  using faf::server::ControlProof;
  using faf::server::EControlRole;

  ControlKey VectorKey()
  {
    ControlKey key{};
    for (std::size_t i = 0; i < key.size(); ++i) {
      key[i] = static_cast<std::uint8_t>(i);
    }
    return key;
  }

  ControlNonce Nonce(const std::uint8_t first)
  {
    ControlNonce nonce{};
    for (std::size_t i = 0; i < nonce.size(); ++i) {
      nonce[i] = static_cast<std::uint8_t>(first + i);
    }
    return nonce;
  }

  std::string Hex(const std::uint8_t* const data, const std::size_t size)
  {
    static constexpr char kDigits[] = "0123456789abcdef";
    std::string text;
    for (std::size_t i = 0; i < size; ++i) {
      text += kDigits[data[i] >> 4];
      text += kDigits[data[i] & 0xF];
    }
    return text;
  }

  std::span<const std::uint8_t> Bytes(const std::string_view text)
  {
    return {reinterpret_cast<const std::uint8_t*>(text.data()), text.size()};
  }

  /** Both ends after the handshake, the server's and the service's. */
  struct SPair
  {
    CControlChannel server{VectorKey(), EControlRole::Server, Nonce(0x10)};
    CControlChannel service{VectorKey(), EControlRole::Service, Nonce(0x40)};
    bool ok = false;

    SPair()
    {
      const ControlProof serverProof = server.Proof(service.OwnNonce());
      const ControlProof serviceProof = service.Proof(server.OwnNonce());
      ok = server.CheckPeerProof(serviceProof) && service.CheckPeerProof(serverProof);
    }
  };
} // namespace

TEST(ControlChannel, MatchesTheGoVector)
{
  SPair pair;
  ASSERT_TRUE(pair.ok);
  const ControlProof serverProof = CControlChannel(VectorKey(), EControlRole::Server, Nonce(0x10)).Proof(Nonce(0x40));
  const ControlProof serviceProof = CControlChannel(VectorKey(), EControlRole::Service, Nonce(0x40)).Proof(Nonce(0x10));
  EXPECT_EQ(Hex(serverProof.data(), serverProof.size()), "87a57dc7e495714a626877771e9e4280f7da5df3b42a0f63bdc731ec79663c8c");
  EXPECT_EQ(Hex(serviceProof.data(), serviceProof.size()), "f5402e1690ed49e47fb64c8cf3af73ec96de449ff0f2bf135ad3a7d6e787b45c");
  const std::vector<std::uint8_t> frame = pair.server.Seal(Bytes(R"({"op":"status"})"));
  EXPECT_EQ(Hex(frame.data(), frame.size()), "1f0000006b5e9bea6e449d70872477d977c6535a31b1534d510121194724dcb2035660");
}

TEST(ControlChannel, MessagesGoBothWaysInOrderWhateverTheReads)
{
  SPair pair;
  ASSERT_TRUE(pair.ok);
  std::vector<std::uint8_t> stream;
  for (const std::string_view text : {std::string_view("one"), std::string_view(""), std::string_view(R"({"op":"force_start"})")}) {
    const std::vector<std::uint8_t> frame = pair.service.Seal(Bytes(text));
    stream.insert(stream.end(), frame.begin(), frame.end());
  }
  // A byte at a time, as TCP may hand them over.
  for (const std::uint8_t byte : stream) {
    ASSERT_TRUE(pair.server.Feed(std::span<const std::uint8_t>(&byte, 1u)));
  }
  std::vector<std::uint8_t> message;
  ASSERT_TRUE(pair.server.Take(message));
  EXPECT_EQ(std::string(message.begin(), message.end()), "one");
  ASSERT_TRUE(pair.server.Take(message));
  EXPECT_TRUE(message.empty());
  ASSERT_TRUE(pair.server.Take(message));
  EXPECT_EQ(std::string(message.begin(), message.end()), R"({"op":"force_start"})");
  EXPECT_FALSE(pair.server.Take(message));

  const std::vector<std::uint8_t> reply = pair.server.Seal(Bytes("ok"));
  ASSERT_TRUE(pair.service.Feed(reply));
  ASSERT_TRUE(pair.service.Take(message));
  EXPECT_EQ(std::string(message.begin(), message.end()), "ok");
}

TEST(ControlChannel, AWrongKeyIsRefusedBothWays)
{
  ControlKey other = VectorKey();
  other[0] ^= 1u;
  CControlChannel server(VectorKey(), EControlRole::Server, Nonce(0x10));
  CControlChannel stranger(other, EControlRole::Service, Nonce(0x40));
  EXPECT_FALSE(server.CheckPeerProof(stranger.Proof(server.OwnNonce()))); // no peer nonce yet: refused
  const ControlProof serverProof = server.Proof(stranger.OwnNonce());
  EXPECT_FALSE(server.CheckPeerProof(stranger.Proof(server.OwnNonce())));
  EXPECT_FALSE(stranger.CheckPeerProof(serverProof));
  EXPECT_FALSE(server.Ready());
  EXPECT_TRUE(server.Seal(Bytes("x")).empty());
  // A proof of the wrong role (the server's own, sent back) doesn't pass either.
  CControlChannel again(VectorKey(), EControlRole::Server, Nonce(0x10));
  const ControlProof mine = again.Proof(Nonce(0x40));
  EXPECT_FALSE(again.CheckPeerProof(mine));
}

TEST(ControlChannel, ChangedReplayedOrHugeFramesEndTheConnection)
{
  {
    SPair pair;
    std::vector<std::uint8_t> frame = pair.service.Seal(Bytes("eject 1002"));
    frame[6] ^= 0x01u;
    EXPECT_FALSE(pair.server.Feed(frame));
  }
  {
    SPair pair;
    const std::vector<std::uint8_t> frame = pair.service.Seal(Bytes("pause"));
    ASSERT_TRUE(pair.server.Feed(frame));
    EXPECT_FALSE(pair.server.Feed(frame)); // the same frame again: its counter has gone
  }
  {
    SPair pair;
    const std::uint8_t huge[] = {0xFFu, 0xFFu, 0xFFu, 0x7Fu};
    EXPECT_FALSE(pair.server.Feed(huge));
    SPair second;
    const std::uint8_t tiny[] = {3u, 0u, 0u, 0u};
    EXPECT_FALSE(second.server.Feed(tiny)); // shorter than a tag
  }
  {
    SPair pair;
    const std::vector<std::uint8_t> big(faf::server::kMaxControlMessageBytes + 1u, std::uint8_t{'x'});
    EXPECT_TRUE(pair.server.Seal(big).empty());
  }
}

// Plan WP17.2: what the listener reads of a request (server/ControlListener.h).
TEST(ControlListener, ParsesFlatRequests)
{
  const auto eject = faf::server::ParseControlRequest(R"( {"id": 7, "op": "eject", "uid": 1002, "reason": "no \"show\"\n", "extra": true, "n": null} )");
  ASSERT_TRUE(eject.has_value());
  EXPECT_EQ(eject->id, 7);
  EXPECT_EQ(eject->op, "eject");
  EXPECT_EQ(eject->uid, 1002);
  EXPECT_EQ(eject->reason, "no \"show\"\n");
  const auto status = faf::server::ParseControlRequest(R"({"op":"status"})");
  ASSERT_TRUE(status.has_value());
  EXPECT_EQ(status->id, 0);
  EXPECT_EQ(faf::server::ParseControlRequest(R"({"op":"café"})")->op, "caf\xC3\xA9");
  // Not a request: no op, nested values, fractions, trailing text, truncation, other JSON.
  for (const std::string_view bad : {std::string_view(R"({"id":1})"), std::string_view(R"({"op":"x","args":{"a":1}})"),
                                     std::string_view(R"({"op":"x","list":[1]})"), std::string_view(R"({"op":"x","id":1.5})"),
                                     std::string_view(R"({"op":"x"} tail)"), std::string_view(R"({"op":"x")"), std::string_view("[1]"),
                                     std::string_view(""), std::string_view(R"({"op":"x",})"), std::string_view(R"({"op":"\q"})")}) {
    EXPECT_FALSE(faf::server::ParseControlRequest(bad).has_value()) << bad;
  }
  EXPECT_EQ(faf::server::JsonString("a\"b\\c\n\x01"), "\"a\\\"b\\\\c\\n\\u0001\"");
}

TEST(ControlChannel, ReadsTheKeyFile)
{
  ControlKey key{};
  EXPECT_TRUE(faf::server::ReadControlKey(" 000102030405060708090a0b0c0d0e0f101112131415161718191A1B1C1D1E1F\n", key));
  EXPECT_EQ(key, VectorKey());
  EXPECT_FALSE(faf::server::ReadControlKey("000102", key));
  EXPECT_FALSE(faf::server::ReadControlKey("zz0102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f", key));
  EXPECT_FALSE(faf::server::ReadControlKey("", key));
}
