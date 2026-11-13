// The server's view audit (remote/ViewAudit.h, `srv_ViewAudit`): what it counts as an incident in a view's Lua `Sync`,
// command-records lane and army lane, on hand-made lanes.

#include <cstdint>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

#include <gtest/gtest.h>

#include "remote/ViewAudit.h"

namespace
{
  using faf::remote::CViewAudit;
  using faf::remote::EViewAuditIncident;
  using faf::remote::SAuditEntity;
  using faf::remote::SViewAuditLuaFacts;

  /** `LuaObject::ToByteStream`'s encoding, by hand. */
  class CTable
  {
  public:
    CTable& Begin()
    {
      mBytes.push_back(4u);
      return *this;
    }
    CTable& End()
    {
      mBytes.push_back(5u);
      return *this;
    }
    CTable& String(
      const std::string_view text
    )
    {
      mBytes.push_back(1u);
      mBytes.insert(mBytes.end(), text.begin(), text.end());
      mBytes.push_back(0u);
      return *this;
    }
    CTable& Number(
      const float value
    )
    {
      mBytes.push_back(0u);
      std::uint8_t bytes[sizeof(value)];
      std::memcpy(bytes, &value, sizeof(value));
      mBytes.insert(mBytes.end(), bytes, bytes + sizeof(bytes));
      return *this;
    }
    CTable& Bool(
      const bool value
    )
    {
      mBytes.push_back(3u);
      mBytes.push_back(value ? 1u : 0u);
      return *this;
    }
    [[nodiscard]] const std::vector<std::uint8_t>& Bytes() const noexcept
    {
      return mBytes;
    }

  private:
    std::vector<std::uint8_t> mBytes;
  };

  // Army 0's units are 0x000xxxxx, army 1's 0x001xxxxx (`EntityId.h`), army 2's 0x002xxxxx.
  constexpr std::uint32_t kOwnUnit = 0x00000005u;
  constexpr std::uint32_t kAllyUnit = 0x00100007u;
  constexpr std::uint32_t kEnemyUnit = 0x00200009u;

  /** A view of army 0, allied with army 1, against army 2; `focusKeys` were written under its focus. */
  SViewAuditLuaFacts Facts(
    std::vector<std::string> focusKeys = {}
  )
  {
    SViewAuditLuaFacts facts;
    facts.entity = [](const std::uint32_t id) {
      SAuditEntity entity;
      entity.exists = id == kOwnUnit || id == kAllyUnit || id == kEnemyUnit;
      entity.owner = static_cast<std::int32_t>((id >> 20u) & 0xFFu);
      return entity;
    };
    facts.allied = [](const std::int32_t army) {
      return army == 0 || army == 1;
    };
    facts.labelSeen = [](std::uint32_t) {
      return true;
    };
    facts.wroteUnderFocus = [focusKeys](const std::string_view key) {
      for (const std::string& focusKey : focusKeys) {
        if (focusKey == key) {
          return true;
        }
      }
      return false;
    };
    return facts;
  }

  std::string Id(
    const std::uint32_t id
  )
  {
    return std::to_string(id);
  }
} // namespace

TEST(
  ViewAudit,
  EveryoneKeysAndOwnUnitsAreClean
)
{
  CViewAudit audit;
  CTable sync;
  sync.Begin()
    .String("GameHasAIs")
    .Bool(true)
    .String("UnitData")
    .Begin()
    .String(Id(kOwnUnit))
    .Begin()
    .String("name")
    .String("ACU")
    .End()
    .End()
    .String("UserUnitEnhancements")
    .Begin()
    .String(Id(kAllyUnit))
    .Begin()
    .String("Back")
    .String("Shield")
    .End()
    .End()
    .End();
  audit.CheckLuaPayload(10u, 0u, 0, sync.Bytes(), Facts());
  audit.CheckHeldIds([](std::size_t, std::uint32_t) {
    return false;
  });
  EXPECT_EQ(audit.Incidents(), 0u) << audit.Summary();
}

TEST(
  ViewAudit,
  KeysOutsideThePolicyOrForObserversAreIncidents
)
{
  CViewAudit audit;
  CTable sync;
  sync.Begin().String("NoSuchKeyInAnyPolicy").Bool(true).String("EnhanceMessage").Bool(true).End();
  audit.CheckLuaPayload(10u, 0u, 0, sync.Bytes(), Facts());
  EXPECT_EQ(audit.Incidents(EViewAuditIncident::UnroutedKey), 1u);
  EXPECT_EQ(audit.Incidents(EViewAuditIncident::ObserversKey), 1u);

  // Written under the view's own focus, an observers' key is that player's (the fan-out writes it per player).
  CViewAudit focused;
  focused.CheckLuaPayload(10u, 0u, 0, sync.Bytes(), Facts({"EnhanceMessage"}));
  EXPECT_EQ(focused.Incidents(EViewAuditIncident::ObserversKey), 0u);

  // The router's own count of writes it had no route for.
  CViewAudit unrouted;
  const std::vector<std::string> keys = {"NoSuchKeyInAnyPolicy"};
  unrouted.NoteUnroutedWrites(10u, 0u, keys);
  EXPECT_EQ(unrouted.Incidents(), 0u);
  unrouted.NoteUnroutedWrites(11u, 3u, keys);
  unrouted.NoteUnroutedWrites(12u, 3u, keys);
  EXPECT_EQ(unrouted.Incidents(EViewAuditIncident::UnroutedKey), 3u);
}

TEST(
  ViewAudit,
  MarkedIdsFollowTheirAudience
)
{
  CTable enemyUnitData;
  enemyUnitData.Begin().String("UnitData").Begin().String(Id(kEnemyUnit)).Bool(false).End().End();
  CViewAudit audit;
  audit.CheckLuaPayload(10u, 0u, 0, enemyUnitData.Bytes(), Facts());
  EXPECT_EQ(audit.Incidents(EViewAuditIncident::OutsideAudience), 1u);

  // An ally's unit data is the owner's alone too; its enhancements are the allies'.
  CTable allyUnitData;
  allyUnitData.Begin().String("UnitData").Begin().String(Id(kAllyUnit)).Bool(false).End().End();
  CViewAudit ally;
  ally.CheckLuaPayload(10u, 0u, 0, allyUnitData.Bytes(), Facts());
  EXPECT_EQ(ally.Incidents(EViewAuditIncident::OutsideAudience), 1u);

  CTable enemyEnhancements;
  enemyEnhancements.Begin().String("UserUnitEnhancements").Begin().String(Id(kEnemyUnit)).Bool(false).End().End();
  CViewAudit enhancements;
  enhancements.CheckLuaPayload(10u, 0u, 0, enemyEnhancements.Bytes(), Facts());
  EXPECT_EQ(enhancements.Incidents(EViewAuditIncident::OutsideAudience), 1u);

  // A field: floating text over another army's unit.
  CTable text;
  text.Begin()
    .String("FloatingEntityText")
    .Begin()
    .Number(1.0f)
    .Begin()
    .String("entity")
    .String(Id(kEnemyUnit))
    .String("text")
    .String("+100")
    .End()
    .End()
    .End();
  CViewAudit floating;
  floating.CheckLuaPayload(10u, 0u, 0, text.Bytes(), Facts());
  EXPECT_EQ(floating.Incidents(EViewAuditIncident::OutsideAudience), 1u);

  // A player watching everything may have them all.
  CViewAudit observer;
  observer.CheckLuaPayload(10u, 0u, -1, enemyUnitData.Bytes(), Facts());
  observer.CheckLuaPayload(10u, 0u, -1, text.Bytes(), Facts());
  EXPECT_EQ(observer.Incidents(), 0u) << observer.Summary();
}

TEST(
  ViewAudit,
  OtherIdsMustBeHeldByTheView
)
{
  // An id Lua wrote (a string) in a field the policy doesn't mark: checked against what the view's client holds.
  CTable sync;
  sync.Begin()
    .String("Ping")
    .Begin()
    .Number(1.0f)
    .Begin()
    .String("Owner")
    .Number(2.0f)
    .String("Target")
    .String(Id(kEnemyUnit))
    .String("Amount")
    .Number(3145737.0f) // a whole number above 2^20 that happens to name a unit: not written as an id
    .End()
    .End()
    .End();
  CViewAudit held;
  held.CheckLuaPayload(10u, 0u, 0, sync.Bytes(), Facts());
  EXPECT_EQ(held.Incidents(), 0u);
  held.CheckHeldIds([](std::size_t view, std::uint32_t id) {
    return view == 0u && id == kEnemyUnit;
  });
  EXPECT_EQ(held.Incidents(), 0u) << held.Summary();

  CViewAudit unheld;
  unheld.CheckLuaPayload(10u, 0u, 0, sync.Bytes(), Facts());
  unheld.CheckHeldIds([](std::size_t, std::uint32_t) {
    return false;
  });
  EXPECT_EQ(unheld.Incidents(EViewAuditIncident::NotHeld), 1u);
  unheld.CheckHeldIds([](std::size_t, std::uint32_t) {
    return false;
  });
  EXPECT_EQ(unheld.Incidents(EViewAuditIncident::NotHeld), 1u) << "each id is checked once";

  // What players type is never an id: a chat line, a marker ping's name ("2" is army 0's third unit).
  CTable chat;
  chat.Begin()
    .String("ChatMessages")
    .Begin()
    .Number(1.0f)
    .Begin()
    .String("text")
    .String(Id(kEnemyUnit))
    .End()
    .End()
    .String("Ping")
    .Begin()
    .Number(1.0f)
    .Begin()
    .String("Name")
    .String(Id(kEnemyUnit))
    .End()
    .End()
    .End();
  CViewAudit lines;
  lines.CheckLuaPayload(10u, 0u, 0, chat.Bytes(), Facts());
  lines.CheckHeldIds([](std::size_t, std::uint32_t) {
    return false;
  });
  EXPECT_EQ(lines.Incidents(), 0u);
}

TEST(
  ViewAudit,
  RenumberedIdsAndBrokenTables
)
{
  SViewAuditLuaFacts facts = Facts();
  facts.entity = [](const std::uint32_t id) {
    SAuditEntity entity;
    entity.exists = true;
    entity.owner = 2;
    entity.renumbered = id == kEnemyUnit;
    return entity;
  };
  CTable sync;
  sync.Begin().String("Ping").Begin().String("Target").String(Id(kEnemyUnit)).End().End();
  CViewAudit audit;
  audit.CheckLuaPayload(10u, 0u, 0, sync.Bytes(), facts);
  EXPECT_EQ(audit.Incidents(EViewAuditIncident::RenumberedRaw), 1u);

  std::vector<std::uint8_t> cut = sync.Bytes();
  cut.resize(cut.size() - 3u);
  CViewAudit broken;
  broken.CheckLuaPayload(10u, 0u, 0, cut, Facts());
  EXPECT_EQ(broken.Incidents(EViewAuditIncident::BadPayload), 1u);
}

TEST(
  ViewAudit,
  CommandRecordsNameHeldEntitiesOnly
)
{
  namespace wire = faf::remote::wire;
  wire::SCommandLane lane;
  wire::SCommandUpdate update;
  update.id = 0x0000002Au;
  update.fields = wire::kCommandUnits | wire::kCommandTarget1 | wire::kCommandTarget2;
  update.data.units = {kOwnUnit, kAllyUnit};
  update.data.target1.type = 1;
  update.data.target1.entity = kEnemyUnit;
  update.data.target2.entity = wire::kNoCommandEntity; // none: nothing to hold
  lane.updates.push_back(update);

  CViewAudit audit;
  audit.CheckCommandLane(10u, 0u, lane, [](const std::uint32_t id, std::string& why) {
    why = "not held";
    return id == kOwnUnit;
  });
  EXPECT_EQ(audit.Incidents(EViewAuditIncident::CommandUnit), 1u);
  EXPECT_EQ(audit.Incidents(EViewAuditIncident::CommandTarget), 1u);

  // A field the update doesn't carry is the client's own, not checked again.
  lane.updates[0].fields = wire::kCommandType;
  CViewAudit unchanged;
  unchanged.CheckCommandLane(10u, 0u, lane, [](std::uint32_t, std::string&) {
    return false;
  });
  EXPECT_EQ(unchanged.Incidents(), 0u);
}

TEST(
  ViewAudit,
  OtherArmiesFocusOnlyFieldsAreZero
)
{
  std::vector<faf::remote::wire::SArmyRecord> records(3);
  records[0].economy[0] = 500.0f; // the view's own
  records[0].useWholeMap = 1u;
  CViewAudit clean;
  clean.CheckArmyRecords(10u, 0u, records);
  EXPECT_EQ(clean.Incidents(), 0u);

  records[2].economy[3] = 4.0f;
  records[1].armyStart = {100.0f, 200.0f};
  CViewAudit audit;
  audit.CheckArmyRecords(10u, 0u, records);
  EXPECT_EQ(audit.Incidents(EViewAuditIncident::ArmyField), 2u);
}
