#include "moho/particles/ParticlePoolReclaim.h"

#include <gtest/gtest.h>

#include <cstddef>
#include <limits>
#include <utility>
#include <vector>

namespace
{
  struct Key
  {
    float sortScalar;
  };

  struct Bucket
  {
    int id;
    std::size_t pending = 0U;
  };

  using Buckets = std::vector<std::pair<Key, Bucket*>>;

  template<std::size_t Capacity>
  bool Reclaim(
    Buckets& buckets,
    const std::size_t start,
    const std::size_t available,
    const std::size_t pending,
    std::vector<int>& visited,
    const bool filterWater = false,
    const bool aboveWater = false,
    const float water = 0.0f
  )
  {
    return moho::detail::ReclaimRemainingBucketsUnderPressure<Capacity>(
      buckets.begin() + static_cast<Buckets::difference_type>(start), buckets.end(),
      available, pending, filterWater, aboveWater, water, 17.5f,
      [&](Bucket& bucket, const float frame) {
        EXPECT_FLOAT_EQ(frame, 17.5f);
        visited.push_back(bucket.id);
      }
    );
  }

  template<std::size_t Capacity>
  void CheckThresholds()
  {
    Bucket bucket{1};
    Buckets buckets{{{0.0f}, &bucket}};
    const std::size_t counts[]{0U, 1U, Capacity - 1U, Capacity, Capacity + 1U,
                               2U * Capacity - 1U, 2U * Capacity, 2U * Capacity + 1U};
    for (const auto count : counts) {
      SCOPED_TRACE(count);
      const auto needed = count / Capacity + (count % Capacity != 0U);
      std::vector<int> visited;
      EXPECT_FALSE(Reclaim<Capacity>(buckets, 0U, needed, count, visited));
      EXPECT_TRUE(visited.empty());
      if (needed != 0U) {
        EXPECT_TRUE(Reclaim<Capacity>(buckets, 0U, needed - 1U, count, visited));
        EXPECT_EQ(visited, (std::vector<int>{1}));
      }
    }
  }
} // namespace

TEST(ParticlePoolReclaim, ParticleCapacityThresholds)
{
  CheckThresholds<200U>();
}

TEST(ParticlePoolReclaim, TrailCapacityThresholds)
{
  CheckThresholds<100U>();
}

TEST(ParticlePoolReclaim, ZeroPendingDoesNotVisitAnyBucket)
{
  Bucket bucket{1};
  Buckets buckets{{{0.0f}, &bucket}};
  std::vector<int> visited;
  EXPECT_FALSE(Reclaim<200U>(buckets, 0U, 0U, 0U, visited));
  EXPECT_TRUE(visited.empty());
}

TEST(ParticlePoolReclaim, SufficientFreeBuffersDoNotVisitActiveBuckets)
{
  Bucket first{1}, second{2};
  Buckets buckets{{{0.0f}, &first}, {{1.0f}, &second}};
  std::vector<int> visited;
  EXPECT_FALSE(Reclaim<200U>(buckets, 0U, 2U, 201U, visited));
  EXPECT_TRUE(visited.empty());
}

TEST(ParticlePoolReclaim, RoundingDoesNotOverflowAtSizeMax)
{
  Bucket bucket{1};
  Buckets buckets{{{0.0f}, &bucket}};
  std::vector<int> visited;
  constexpr auto maximum = std::numeric_limits<std::size_t>::max();
  EXPECT_FALSE(Reclaim<1U>(buckets, 0U, maximum, maximum, visited));
  EXPECT_TRUE(visited.empty());
  EXPECT_TRUE(Reclaim<1U>(buckets, 0U, maximum - 1U, maximum, visited));
  EXPECT_EQ(visited, (std::vector<int>{1}));
  visited.clear();
  constexpr auto needed = maximum / 200U + (maximum % 200U != 0U);
  EXPECT_FALSE(Reclaim<200U>(buckets, 0U, needed, maximum, visited));
  EXPECT_TRUE(visited.empty());
  EXPECT_TRUE(Reclaim<200U>(buckets, 0U, needed - 1U, maximum, visited));
  EXPECT_EQ(visited, (std::vector<int>{1}));
}

TEST(ParticlePoolReclaim, StartsAtCurrentAndNeverRevisitsPrefix)
{
  Bucket prefix{1}, current{2}, later{3};
  Buckets buckets{{{0.0f}, &prefix}, {{1.0f}, &current}, {{2.0f}, &later}};
  std::vector<int> visited;
  EXPECT_TRUE(Reclaim<200U>(buckets, 1U, 0U, 1U, visited));
  EXPECT_EQ(visited, (std::vector<int>{2, 3}));
}

TEST(ParticlePoolReclaim, PassesIteratorByValue)
{
  Bucket first{1}, second{2};
  Buckets buckets{{{0.0f}, &first}, {{1.0f}, &second}};
  auto current = buckets.begin();
  std::size_t calls = 0U;
  EXPECT_TRUE(moho::detail::ReclaimRemainingBucketsUnderPressure<100U>(
    current, buckets.end(), 0U, 1U, false, false, 0.0f, 0.0f,
    [&](Bucket&, float) { ++calls; }
  ));
  EXPECT_EQ(current, buckets.begin());
  EXPECT_EQ(calls, 2U);
}

TEST(ParticlePoolReclaim, IncludesZeroPendingBucketsAndSkipsNulls)
{
  Bucket current{1, 1U}, reusable{2, 0U};
  Buckets buckets{{{0.0f}, &current}, {{1.0f}, nullptr}, {{2.0f}, &reusable}, {{3.0f}, nullptr}};
  std::vector<int> visited;
  EXPECT_TRUE(Reclaim<200U>(buckets, 0U, 0U, current.pending, visited));
  EXPECT_EQ(visited, (std::vector<int>{1, 2}));
}

TEST(ParticlePoolReclaim, AboveWaterIncludesEqualityAndSkipsLowerKeys)
{
  Bucket lower{1}, boundary{2}, higher{3};
  Buckets buckets{{{-1.0f}, &lower}, {{0.0f}, &boundary}, {{1.0f}, &higher}};
  std::vector<int> visited;
  EXPECT_TRUE(Reclaim<200U>(buckets, 0U, 0U, 1U, visited, true, true));
  EXPECT_EQ(visited, (std::vector<int>{2, 3}));
}

TEST(ParticlePoolReclaim, BelowWaterIncludesEqualityAndStopsAtHigherKey)
{
  Bucket lower{1}, boundary{2}, higher{3}, afterBreak{4};
  // The trailing lower key deliberately tests break rather than continue.
  // It is a synthetic sequence, not a claim about an ordered map's ordering.
  Buckets buckets{{{-1.0f}, &lower}, {{0.0f}, &boundary}, {{1.0f}, &higher}, {{-2.0f}, &afterBreak}};
  std::vector<int> visited;
  EXPECT_TRUE(Reclaim<100U>(buckets, 0U, 0U, 1U, visited, true, false));
  EXPECT_EQ(visited, (std::vector<int>{1, 2}));
}

TEST(ParticlePoolReclaim, DisabledWaterFilterVisitsWholeSuffix)
{
  Bucket lower{1}, higher{2};
  Buckets buckets{{{-10.0f}, &lower}, {{10.0f}, &higher}};
  std::vector<int> visited;
  EXPECT_TRUE(Reclaim<200U>(buckets, 0U, 0U, 1U, visited, false, true));
  EXPECT_EQ(visited, (std::vector<int>{1, 2}));
}

TEST(ParticlePoolReclaim, UnorderedWaterComparisonsMatchVisitPredicates)
{
  Bucket bucket{1};
  const auto nan = std::numeric_limits<float>::quiet_NaN();
  // A vector avoids imposing an invalid NaN comparator on an ordered map.
  Buckets buckets{{{nan}, &bucket}};
  std::vector<int> visited;
  EXPECT_TRUE(Reclaim<200U>(buckets, 0U, 0U, 1U, visited, true, true));
  EXPECT_TRUE(visited.empty());
  EXPECT_TRUE(Reclaim<200U>(buckets, 0U, 0U, 1U, visited, true, false));
  EXPECT_EQ(visited, (std::vector<int>{1}));
}

TEST(ParticlePoolReclaim, ReturnReportsAttemptedSweepNotFreedBufferCount)
{
  Buckets empty;
  std::vector<int> visited;
  EXPECT_FALSE(Reclaim<200U>(empty, 0U, 0U, 0U, visited));
  EXPECT_TRUE(Reclaim<200U>(empty, 0U, 0U, 1U, visited));
  EXPECT_TRUE(visited.empty());
}

TEST(ParticlePoolReclaim, CallerPatternConsumesAllowanceOnlyWhenSweepOccurs)
{
  Bucket empty{1, 0U}, fits{2, 200U}, pressure{3, 201U}, afterSweep{4, 1000U};
  Buckets buckets{{{0.0f}, &empty}, {{1.0f}, &fits}, {{2.0f}, &pressure}, {{3.0f}, &afterSweep}};
  // The flag belongs to the caller, not the helper. This exercises the calling
  // contract; it does not independently verify CWorldParticles integration.
  const auto invoke = [&] {
    bool reclaimed = false;
    std::size_t checks = 0U;
    std::vector<int> visited;
    for (auto current = buckets.begin(); current != buckets.end(); ++current) {
      if (!reclaimed && current->second->pending != 0U) {
        ++checks;
        reclaimed = moho::detail::ReclaimRemainingBucketsUnderPressure<200U>(
          current, buckets.end(), 1U, current->second->pending, false, false, 0.0f, 0.0f,
          [&](Bucket& bucket, float) { visited.push_back(bucket.id); }
        );
      }
    }
    EXPECT_TRUE(reclaimed);
    EXPECT_EQ(checks, 2U);
    EXPECT_EQ(visited, (std::vector<int>{3, 4}));
  };
  invoke();
  invoke(); // A new invocation has a fresh local allowance.
}
