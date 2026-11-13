// The Lua Sync routing policy as a file (remote/SyncRouting.h, tools/sync-routing/policy_gen.py): the reader, and the
// committed policy of each validated FAF version against the compiled table.

#include <cstdio>
#include <string>

#include <gtest/gtest.h>

#include "remote/SyncRouting.h"

#ifndef FAF_SYNC_POLICY_DIR
#error "FAF_SYNC_POLICY_DIR names tools/sync-routing/policy"
#endif

namespace
{
  using faf::remote::ESyncRoute;
  using faf::remote::ParseSyncPolicy;
  using faf::remote::SSyncPolicy;

  std::string ReadFile(
    const std::string& path
  )
  {
    std::string text;
    std::FILE* const file = std::fopen(path.c_str(), "rb");
    if (file == nullptr) {
      return text;
    }
    char buffer[4096];
    for (std::size_t read = std::fread(buffer, 1u, sizeof(buffer), file); read != 0u;
         read = std::fread(buffer, 1u, sizeof(buffer), file)) {
      text.append(buffer, read);
    }
    std::fclose(file);
    return text;
  }
} // namespace

TEST(
  SyncPolicy,
  ReadsKeysRoutesAndVersion
)
{
  SSyncPolicy policy;
  std::string error;
  ASSERT_TRUE(ParseSyncPolicy(
    "# a comment\r\n# game-version: 3840\nUnitData\tEntityOwner\tgenerated\t7\n\nScore\tScore\tspecial\t0\tnote\n"
    "Ping\tObservers\n",
    policy,
    error
  )) << error;
  EXPECT_EQ(policy.gameVersion, 3840);
  ASSERT_EQ(policy.routes.size(), 3u);
  EXPECT_EQ(policy.routes[0].first, "Ping"); // sorted
  EXPECT_EQ(policy.routes[0].second, ESyncRoute::Observers);
  EXPECT_EQ(policy.routes[1].first, "Score");
  EXPECT_EQ(policy.routes[1].second, ESyncRoute::Score);
  EXPECT_EQ(policy.routes[2].second, ESyncRoute::EntityOwner);
}

TEST(
  SyncPolicy,
  RefusesBadFiles
)
{
  SSyncPolicy policy;
  std::string error;
  EXPECT_FALSE(ParseSyncPolicy("UnitData\tEntityOwner\n", policy, error)); // no version
  EXPECT_FALSE(ParseSyncPolicy("# game-version: 3840\nUnitData\tNoSuchRoute\n", policy, error));
  EXPECT_FALSE(ParseSyncPolicy("# game-version: 3840\nUnitData\n", policy, error));
  EXPECT_FALSE(ParseSyncPolicy("# game-version: 3840\nA\tEveryone\nA\tObservers\n", policy, error));
  EXPECT_FALSE(ParseSyncPolicy("# game-version: x\nA\tEveryone\n", policy, error));
}

TEST(
  SyncPolicy,
  RouteNamesRoundTrip
)
{
  for (const auto route :
       {ESyncRoute::Everyone,
        ESyncRoute::Reclaim,
        ESyncRoute::EntityOwner,
        ESyncRoute::EntityAllies,
        ESyncRoute::ReleasedIds,
        ESyncRoute::Score,
        ESyncRoute::ScoreAccum,
        ESyncRoute::NukeLaunch,
        ESyncRoute::Chat,
        ESyncRoute::Observers}) {
    ESyncRoute parsed = ESyncRoute::Everyone;
    ASSERT_TRUE(faf::remote::ParseSyncRouteName(faf::remote::SyncRouteName(route), parsed));
    EXPECT_EQ(parsed, route);
  }
}

// The committed policy file is what the compiled table says: a change to one without the other fails here.
TEST(
  SyncPolicy,
  CommittedPolicyIsTheCompiledTable
)
{
  for (const int version : faf::remote::kSyncPolicyGameVersions) {
    const std::string path = std::string(FAF_SYNC_POLICY_DIR) + "/" + std::to_string(version) + ".tsv";
    const std::string text = ReadFile(path);
    if (text.empty()) {
      continue; // a version validated before policy files: the compiled table alone
    }
    SSyncPolicy policy;
    std::string error;
    ASSERT_TRUE(ParseSyncPolicy(text, policy, error)) << path << ": " << error;
    EXPECT_EQ(policy.gameVersion, version);
    const auto compiled = faf::remote::CompiledSyncKeyRoutes();
    ASSERT_EQ(policy.routes.size(), compiled.size()) << path;
    for (std::size_t index = 0; index < compiled.size(); ++index) {
      EXPECT_EQ(policy.routes[index].first, compiled[index].key) << path;
      EXPECT_EQ(policy.routes[index].second, compiled[index].route) << path << " " << policy.routes[index].first;
    }
  }
}

// A policy file in use answers every lookup; the compiled table stays as it is.
TEST(
  SyncPolicy,
  LoadedPolicyAnswersLookups
)
{
  SSyncPolicy policy;
  std::string error;
  ASSERT_TRUE(ParseSyncPolicy("# game-version: 3999\nZeta\tEntityAllies\nAlpha\tEveryone\n", policy, error));
  const std::size_t compiledCount = faf::remote::CompiledSyncKeyRoutes().size();
  faf::remote::UseSyncPolicy(policy);
  bool known = false;
  EXPECT_EQ(faf::remote::RouteOfSyncKey("Zeta", known), ESyncRoute::EntityAllies);
  EXPECT_TRUE(known);
  EXPECT_EQ(faf::remote::RouteOfSyncKey("UnitData", known), ESyncRoute::Observers);
  EXPECT_FALSE(known);
  EXPECT_EQ(faf::remote::SyncKeyRoutes().size(), 2u);
  EXPECT_EQ(faf::remote::CompiledSyncKeyRoutes().size(), compiledCount);
  EXPECT_TRUE(faf::remote::ActiveSyncPolicyCovers(3999));
  EXPECT_FALSE(faf::remote::ActiveSyncPolicyCovers(3840));
  EXPECT_EQ(faf::remote::SyncPolicyGameVersionsText(), "3999");
  faf::remote::UseCompiledSyncPolicy();
  EXPECT_EQ(faf::remote::RouteOfSyncKey("UnitData", known), ESyncRoute::EntityOwner);
  EXPECT_TRUE(known);
}
