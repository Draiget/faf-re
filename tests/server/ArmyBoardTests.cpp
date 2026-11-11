#include <gtest/gtest.h>

#include <string>
#include <vector>

#include "moho/sim/SSTIArmyVariableData.h"
#include "moho/sim/SimDriver.h"
#include "server/ArmyBoard.h"

// Plan WP17.15: the dashboard's armies from a beat's packet (the commander and the sync's Score are proven on fw0 in a
// real game, tmp/server/fw0/srvarmies.sh, as they need blueprints and a Lua state).
TEST(
  ArmyBoard,
  EntityIdsCarryTheirArmy
)
{
  EXPECT_EQ(faf::server::ArmyOfEntity(0x00000005u), 0u);
  EXPECT_EQ(faf::server::ArmyOfEntity(0x00300012u), 3u);
  EXPECT_EQ(faf::server::ArmyOfEntity(0x10F00001u), 15u); // the family bits don't count
}

TEST(
  ArmyBoard,
  EconomyFromThePacketAndPlayersFromTheMatch
)
{
  moho::SSyncData packet;
  packet.mArmyUpdates.resize(2);
  packet.mArmyUpdates[0].mEconomyTotals.mStored.MASS = 650.0f;
  packet.mArmyUpdates[0].mEconomyTotals.mStored.ENERGY = 3900.5f;
  packet.mArmyUpdates[0].mEconomyTotals.mIncome.MASS = 0.4f; // per tick: 4 a second
  packet.mArmyUpdates[0].mEconomyTotals.mIncome.ENERGY = 2.0f;
  packet.mArmyUpdates[0].mEconomyTotals.mMaxStorage.MASS = 650u;
  packet.mArmyUpdates[0].mEconomyTotals.mMaxStorage.ENERGY = 4000u;
  packet.mArmyUpdates[0].mFaction = 0;
  packet.mArmyUpdates[1].mFaction = 3;
  packet.mArmyUpdates[1].mIsOutOfGame = 1u;

  faf::server::CArmyBoard board;
  board.ReadPacket(packet);
  EXPECT_EQ(board.Armies(), 2u);
  const std::vector<faf::server::CArmyBoard::SPlayer> players{
    {"Ann", 2, true, 1001, ""}, {"AI: rush", 3, false, 0, "defeat -10"}
  };
  const std::string json = board.Json(120, players);
  EXPECT_NE(json.find("\"beat\":120"), std::string::npos) << json;
  EXPECT_NE(
    json.find("{\"army\":1,\"name\":\"Ann\",\"team\":2,\"faction\":1,\"human\":true,\"uid\":1001"), std::string::npos
  ) << json;
  EXPECT_NE(json.find("\"mass\":{\"stored\":650,\"income\":4,\"storage\":650}"), std::string::npos) << json;
  EXPECT_NE(json.find("\"energy\":{\"stored\":3900.5,\"income\":20,\"storage\":4000}"), std::string::npos) << json;
  EXPECT_NE(json.find("\"units\":null,\"acu\":null,\"defeated\":false,\"result\":null"), std::string::npos) << json;
  EXPECT_NE(
    json.find("{\"army\":2,\"name\":\"AI: rush\",\"team\":3,\"faction\":4,\"human\":false,\"uid\":null"),
    std::string::npos
  ) << json;
  EXPECT_NE(json.find("\"defeated\":true,\"result\":\"defeat -10\"}"), std::string::npos) << json;
}

TEST(
  ArmyBoard,
  NoPacketYetGivesThePlayersOnly
)
{
  const faf::server::CArmyBoard board;
  const std::string json = board.Json(0, {{"Ann", 1, true, 1001, ""}});
  EXPECT_EQ(
    json,
    "\"beat\":0,\"armies\":[{\"army\":1,\"name\":\"Ann\",\"team\":1,\"faction\":null,\"human\":true,\"uid\":1001,"
    "\"type\":null,"
    "\"score\":null,\"mass\":null,\"energy\":null,\"units\":null,\"acu\":null,\"defeated\":false,\"result\":null}]"
  );
}
