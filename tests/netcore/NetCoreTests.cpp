// The network layer's small parts without a socket: moho/net/Common.h (the ping statistics, the names of player
// states and protocols, dotted addresses), the peer features announcement and rejoin bookkeeping
// (moho/net/PeerFeatures.h, issue #285) and the seat key that proves a rejoining player (moho/net/RejoinKey.h,
// issue #275). Expectations for recovered functions are read from the retail function at the address named.

#include "moho/net/CMessage.h"
#include "moho/net/CMessageStream.h"
#include "moho/net/Common.h"
#include "moho/net/EClientMsg.h"
#include "moho/net/PeerFeatures.h"
#include "moho/net/RejoinKey.h"
#include "moho/misc/StartupHelpers.h"

#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <stdexcept>
#include <string>

namespace
{
  std::string Str(const fa::string& value)
  {
    return value.c_str();
  }

  std::string StateName(const moho::ENetworkPlayerState state)
  {
    fa::string out;
    moho::ENetworkPlayerStateToStr(state, out);
    return out.c_str();
  }
} // namespace

// The ping ring (0x0048BEC0): 25 slots with one kept free, so it holds the newest 24 samples; Append returns 1 on
// the write that wraps the ring. Median and jitter (0x0048BF00, 0x0048BF60) sort the held samples and take the
// element at count / 2; jitter first takes each sample's distance from the center.
TEST(NetCore, PingRingKeepsTheNewest24AndTakesTheMiddleElement)
{
  moho::NetSpeeds speeds;
  int wraps = 0;
  for (int sample = 1; sample <= 30; ++sample) {
    const int wrapped = speeds.Append(static_cast<float>(sample));
    wraps += wrapped;
    if (sample == 25) {
      EXPECT_EQ(wrapped, 1) << "the 25th write is at the last slot";
    }
  }
  EXPECT_EQ(wraps, 1);
  // Held: 7..30, 24 samples; the element at 12 of them sorted is 19.
  EXPECT_EQ(speeds.Median(), 19.0f);
  // Distances from 19: 0, 1, 1, 2, 2, ... 11, 11, 12; the element at 12 is 6.
  EXPECT_EQ(speeds.Jitter(19.0f), 6.0f);

  moho::NetSpeeds even;
  for (const float sample : {40.0f, 10.0f, 30.0f, 20.0f}) {
    (void)even.Append(sample);
  }
  EXPECT_EQ(even.Median(), 30.0f); // sorted 10 20 30 40, element 2: the upper middle
  EXPECT_EQ(even.Jitter(25.0f), 15.0f); // 15 5 5 15 sorted 5 5 15 15, element 2
}

// The player state names (table at 0x00DFEB14); a value past them prints as a number (0x007C0560).
TEST(NetCore, PlayerStateNames)
{
  using moho::ENetworkPlayerState;
  EXPECT_EQ(StateName(ENetworkPlayerState::kUnknown), "Unknown");
  EXPECT_EQ(StateName(ENetworkPlayerState::kConnecting), "Connecting");
  EXPECT_EQ(StateName(ENetworkPlayerState::kConnected), "Connected");
  EXPECT_EQ(StateName(ENetworkPlayerState::kPending), "Pending");
  EXPECT_EQ(StateName(ENetworkPlayerState::kWaitingJoin), "WaitingJoin");
  EXPECT_EQ(StateName(ENetworkPlayerState::kEstablished), "Established");
  EXPECT_EQ(StateName(ENetworkPlayerState::kDisconnected), "Disconnected");
  EXPECT_EQ(StateName(static_cast<ENetworkPlayerState>(9)), "9");
}

// Protocol names both ways (0x0047EC90, 0x0047ED50): case-insensitive on the way in, domain_error for anything else.
TEST(NetCore, ProtocolNamesRoundTrip)
{
  using moho::ENetProtocolType;
  for (const ENetProtocolType protocol : {ENetProtocolType::kNone, ENetProtocolType::kTcp, ENetProtocolType::kUdp}) {
    EXPECT_EQ(moho::NET_ProtocolFromString(moho::NET_GetProtocolName(protocol).c_str()), protocol);
  }
  EXPECT_EQ(Str(moho::NET_GetProtocolName(ENetProtocolType::kUdp)), "UDP");
  EXPECT_EQ(moho::NET_ProtocolFromString("udp"), ENetProtocolType::kUdp);
  EXPECT_EQ(moho::NET_ProtocolFromString("Tcp"), ENetProtocolType::kTcp);
  EXPECT_THROW((void)moho::NET_ProtocolFromString("SCTP"), std::domain_error);
  EXPECT_THROW((void)moho::NET_GetProtocolName(static_cast<ENetProtocolType>(7)), std::domain_error);
}

// Dotted addresses (0x004801C0 "%d.%d.%d.%d", 0x00480200 folding each token in with acc << 8 | atoi).
TEST(NetCore, DottedAddressesRoundTrip)
{
  EXPECT_EQ(Str(moho::NET_GetDottedOctetFromUInt32(0xC0A80102u)), "192.168.1.2");
  EXPECT_EQ(Str(moho::NET_GetDottedOctetFromUInt32(0u)), "0.0.0.0");
  EXPECT_EQ(moho::NET_GetUInt32FromDottedOcted(fa::string("192.168.1.2")), 0xC0A80102u);
  EXPECT_EQ(moho::NET_GetUInt32FromDottedOcted(fa::string("10.0.0.255")), 0x0A0000FFu);
  for (const std::uint32_t address : {0x7F000001u, 0xFFFFFFFFu, 0x01020304u}) {
    EXPECT_EQ(moho::NET_GetUInt32FromDottedOcted(moho::NET_GetDottedOctetFromUInt32(address)), address);
  }
}

// The peer features announcement: kind 0, a format byte, the mask, then this build's name; anything shorter or of
// another kind is not one.
TEST(NetCore, PeerAnnouncementRoundTrips)
{
  const std::uint64_t mask = moho::PeerFeatureBit(moho::EPeerFeature::OrderStreamCheck) |
                             moho::PeerFeatureBit(moho::EPeerFeature::Rejoin) | (std::uint64_t{1} << 63);
  moho::CMessage message(moho::EClientMsg::CLIMSG_PeerFeatures);
  {
    moho::CMessageStream stream(message);
    moho::WritePeerAnnouncement(stream, mask);
  }
  const char* const payload = &message.mBuff[3];
  const auto size = static_cast<std::size_t>(message.GetMessageSize());
  ASSERT_GE(size, 10u);

  moho::SPeerAnnouncement read;
  ASSERT_TRUE(moho::ReadPeerAnnouncement(payload, size, read));
  EXPECT_EQ(read.mask, mask);
  EXPECT_EQ(read.build.size(), size - 11u); // the name and its NUL follow the 10 fixed bytes

  EXPECT_FALSE(moho::ReadPeerAnnouncement(payload, 9u, read));
  std::string other(payload, size);
  other[0] = static_cast<char>(moho::EPeerMessageKind::RejoinKey);
  EXPECT_FALSE(moho::ReadPeerAnnouncement(other.data(), other.size(), read));
  // A name without its NUL (a later format's fields would follow it) stops at the payload's end.
  ASSERT_TRUE(moho::ReadPeerAnnouncement(payload, size - 1u, read));
  EXPECT_EQ(read.build.size(), size - 11u);
}

TEST(NetCore, RejoinStageNames)
{
  using moho::ERejoinStage;
  EXPECT_STREQ(moho::RejoinStageName(ERejoinStage::None), "");
  EXPECT_STREQ(moho::RejoinStageName(ERejoinStage::Lost), "lost");
  EXPECT_STREQ(moho::RejoinStageName(ERejoinStage::Transfer), "transfer");
  EXPECT_STREQ(moho::RejoinStageName(ERejoinStage::Loading), "loading");
  EXPECT_STREQ(moho::RejoinStageName(ERejoinStage::CatchingUp), "catchingUp");
  EXPECT_STREQ(moho::RejoinStageName(ERejoinStage::Back), "back");
}

// What a client knows of its peers before any announcement: no features, the seats it ejected found by address,
// a rejoin's stage as noted, the first ready time kept, and no proof accepted from a seat whose key never came.
TEST(NetCore, PeerBookkeepingWithoutAnnouncements)
{
  moho::CPeerFeatures peers(3u);
  EXPECT_FALSE(peers.PeerSupports(1, moho::EPeerFeature::Rejoin));
  EXPECT_FALSE(peers.PeerSupports(-1, moho::EPeerFeature::Rejoin));
  EXPECT_FALSE(peers.PeerSupports(3, moho::EPeerFeature::Rejoin));

  EXPECT_EQ(peers.FindEjectedSeat(0x0A000002u, 6000u), -1);
  peers.NoteRejoinEjected(2, 0x0A000002u, 6000u);
  EXPECT_EQ(peers.FindEjectedSeat(0x0A000002u, 6000u), 2);
  EXPECT_EQ(peers.FindEjectedSeat(0x0A000002u, 6001u), -1);

  EXPECT_EQ(peers.RejoinStatus(1).stage, moho::ERejoinStage::None);
  peers.NoteRejoinLost(1);
  EXPECT_EQ(peers.RejoinStatus(1).stage, moho::ERejoinStage::Lost);
  peers.NoteRejoinStarted(1);
  EXPECT_EQ(peers.RejoinStatus(1).stage, moho::ERejoinStage::Transfer);
  EXPECT_LT(peers.RejoinSilenceSeconds(1), 5.0f);
  EXPECT_EQ(peers.RejoinStatus(7).stage, moho::ERejoinStage::None);

  peers.NoteReady(0, 1500);
  peers.NoteReady(0, 9000); // the first one stays
  EXPECT_EQ(peers.ReadyUs(0), 1500);
  EXPECT_EQ(peers.ReadyUs(1), 0);

  EXPECT_FALSE(peers.HasRejoinKey(1));
  const moho::SRejoinNonce nonce = peers.StartRejoinChallenge(1);
  (void)nonce;
  EXPECT_FALSE(peers.CheckRejoinProof(1, 0, moho::SRejoinSignature{}));
  EXPECT_FALSE(peers.RejoinProven(1));
  EXPECT_FALSE(peers.CheckRejoinProof(5, 0, moho::SRejoinSignature{}));
}

// The seat key (issue #275). Run with `/rejoinkeyfile <file>` (ctest passes one in the build folder), so the test
// never touches the key a real game keeps in the temp folder. A signature answers its own challenge, seat and peer
// only, and a key read back from the file signs as the one made.
TEST(NetCore, SeatKeySignsOnlyItsOwnChallenge)
{
  fa::vector<fa::string> args;
  if (!moho::CFG_GetArgOption("/rejoinkeyfile", 1, &args) || args.empty()) {
    GTEST_SKIP() << "run with /rejoinkeyfile <file>, as ctest does";
  }
  const std::filesystem::path file(args[0].c_str());
  std::error_code ignored;
  std::filesystem::remove(file, ignored);

  EXPECT_FALSE(moho::REJOIN_LoadKey()) << "no key file yet";
  ASSERT_TRUE(moho::REJOIN_CreateKey());
  ASSERT_TRUE(moho::REJOIN_HasKey());
  EXPECT_EQ(std::filesystem::file_size(file, ignored), 32u);
  const moho::SRejoinPublicKey key = moho::REJOIN_PublicKey();

  const moho::SRejoinNonce nonce = moho::REJOIN_MakeNonce();
  EXPECT_NE(nonce, moho::REJOIN_MakeNonce());
  const moho::SRejoinSignature signature = moho::REJOIN_SignChallenge(nonce, 2, 0);
  EXPECT_TRUE(moho::REJOIN_CheckProof(key, nonce, 2, 0, signature));
  EXPECT_FALSE(moho::REJOIN_CheckProof(key, nonce, 3, 0, signature)) << "another seat";
  EXPECT_FALSE(moho::REJOIN_CheckProof(key, nonce, 2, 1, signature)) << "another peer";
  moho::SRejoinNonce otherNonce = nonce;
  otherNonce[0] ^= 1u;
  EXPECT_FALSE(moho::REJOIN_CheckProof(key, otherNonce, 2, 0, signature)) << "another challenge";
  moho::SRejoinPublicKey otherKey = key;
  otherKey[5] ^= 0x40u;
  EXPECT_FALSE(moho::REJOIN_CheckProof(otherKey, nonce, 2, 0, signature)) << "another player's key";

  ASSERT_TRUE(moho::REJOIN_LoadKey());
  EXPECT_EQ(moho::REJOIN_PublicKey(), key);
  EXPECT_TRUE(moho::REJOIN_CheckProof(key, nonce, 2, 0, moho::REJOIN_SignChallenge(nonce, 2, 0)));

  std::filesystem::resize_file(file, 10u, ignored); // damaged
  EXPECT_FALSE(moho::REJOIN_LoadKey());
  EXPECT_FALSE(moho::REJOIN_HasKey());
  std::filesystem::remove(file, ignored);
}
