// Actual production budget, vertex and container types. No replacement allocator.
#include <gtest/gtest.h>
#include <algorithm>
#include <cstddef>
#include <initializer_list>
#include <limits>
#include <thread>

#include "gpg/core/containers/FastVector.h"
#include "moho/terrain/SplatBudget.h"
#include "moho/terrain/splat/CWldSplat.h"

namespace
{
  using Vertex = moho::CWldSplat::SplatVertex;

  // Do not let a failing assertion contaminate another test's render-thread state.
  struct ScopedBackoff
  {
    moho::splat_detail::AllocationBackoff previous = moho::splat_detail::Backoff();
    ScopedBackoff() { moho::splat_detail::Backoff() = {}; }
    ~ScopedBackoff() { moho::splat_detail::Backoff() = previous; }
  };

  template <std::size_t N>
  void AppendQuad(gpg::core::FastVectorN<Vertex, N>& vertices, std::size_t id, float uv = 0.25f)
  {
    // WildMagic default constructors need not initialize their floats.
    Vertex vertex{};
    vertex.mPosition.x = static_cast<float>(id);
    vertex.mPosition.y = vertex.mPosition.z = 0.0f;
    vertex.mTexCoord.x = uv;
    vertex.mTexCoord.y = 0.75f;
    for (std::size_t corner = 0; corner < 4; ++corner) {
      vertex.mAlpha = static_cast<float>(id * 4 + corner);
      vertices.PushBack(vertex);
    }
  }

  template <std::size_t N>
  void CheckPrefix(const gpg::core::FastVectorN<Vertex, N>& vertices, float uv = 0.25f)
  {
    ASSERT_EQ(vertices.Size() % 4, 0u);
    for (std::size_t i = 0; i < vertices.Size(); ++i) {
      EXPECT_FLOAT_EQ(vertices[i].mPosition.x, static_cast<float>(i / 4));
      EXPECT_FLOAT_EQ(vertices[i].mAlpha, static_cast<float>(i));
      EXPECT_FLOAT_EQ(vertices[i].mTexCoord.x, uv);
    }
  }

  template <std::size_t N>
  void CheckBudgets()
  {
    const ScopedBackoff isolate;
    gpg::core::FastVectorN<Vertex, N> vertices;
    const auto* inlineData = vertices.Data();
    constexpr std::size_t inlineQuads = N / 4;
    const std::size_t caps[] = {inlineQuads - 1, N, N * 5 / 2, N * 5};
    ASSERT_EQ(sizeof(Vertex), 28u);
    for (const int tier : {0, 1, 2, 3, -1, 4, std::numeric_limits<int>::min(), std::numeric_limits<int>::max()}) {
      SCOPED_TRACE(::testing::Message() << "inline capacity=" << N << ", tier=" << tier);
      vertices.ResetStorageToInline();
      auto budget = moho::PrepareSplatOutput(vertices, tier);
      const auto cap = caps[tier >= 0 && tier <= 3 ? tier : 0];
      ASSERT_EQ(budget.limit, cap);
      ASSERT_EQ(budget.available, std::min(cap, inlineQuads));
      ASSERT_EQ(vertices.Data(), inlineData);
      ASSERT_EQ(vertices.Capacity(), N);
      ASSERT_TRUE(vertices.Empty());
      for (std::size_t quad = 0; quad < cap; ++quad) {
        if (quad >= budget.available) {
          ASSERT_TRUE(moho::TryGrowSplatOutput(vertices, budget));
          ASSERT_EQ(vertices.Size(), quad * 4);
          CheckPrefix(vertices);
        }
        AppendQuad(vertices, quad);
      }
      ASSERT_EQ(vertices.Size(), cap * 4);
      CheckPrefix(vertices);
      EXPECT_FALSE(moho::TryGrowSplatOutput(vertices, budget));
      EXPECT_LE(vertices.Capacity(), std::max(N, cap * 4));
      if (tier <= 0 || tier > 3) {
        EXPECT_EQ(vertices.Data(), inlineData);
        EXPECT_EQ(vertices.Capacity(), N);
      }
      const auto* allocated = vertices.Data();
      const auto capacity = vertices.Capacity();
      budget = moho::PrepareSplatOutput(vertices, tier);
      EXPECT_TRUE(vertices.Empty());
      EXPECT_EQ(vertices.Data(), allocated);
      EXPECT_EQ(vertices.Capacity(), capacity);
      if (tier == 3) {
        budget = moho::PrepareSplatOutput(vertices, 1);
        EXPECT_EQ(vertices.Data(), inlineData);
        EXPECT_EQ(vertices.Capacity(), N);
        EXPECT_EQ(budget.limit, caps[1]);
        EXPECT_TRUE(moho::TryGrowSplatOutput(vertices, budget));
      }
      budget = moho::PrepareSplatOutput(vertices, 0);
      EXPECT_TRUE(vertices.Empty());
      EXPECT_EQ(vertices.Data(), inlineData);
      EXPECT_EQ(vertices.Capacity(), N);
      EXPECT_EQ(budget.limit, caps[0]);
    }
  }

  // The collectors restart an atlas walk by clearing output, not by preparing a
  // new view or releasing its storage. Exercise that storage/budget contract at
  // every growth boundary; this is not a call to UpdateRenderContext itself.
  template <std::size_t N>
  void CheckAtlasRestartStorage()
  {
    const ScopedBackoff isolate;
    constexpr std::size_t inlineQuads = N / 4;
    for (const int tier : {0, 1, 2, 3}) {
      const auto limit = tier == 0 ? inlineQuads - 1 : inlineQuads * (tier == 1 ? 4 : tier == 2 ? 10 : 20);
      for (const std::size_t beforeRestart : {std::size_t(1), inlineQuads - 1, inlineQuads, inlineQuads + 1,
                                             inlineQuads * 2 + 1, inlineQuads * 4 + 1,
                                             inlineQuads * 8 + 1, inlineQuads * 16 + 1}) {
        if (beforeRestart > limit) {
          continue;
        }
        SCOPED_TRACE(::testing::Message() << "inline=" << N << ", tier=" << tier << ", prefix=" << beforeRestart);
        gpg::core::FastVectorN<Vertex, N> vertices;
        auto budget = moho::PrepareSplatOutput(vertices, tier);
        for (std::size_t quad = 0; quad < beforeRestart; ++quad) {
          if (quad >= budget.available) {
            ASSERT_TRUE(moho::TryGrowSplatOutput(vertices, budget));
          }
          AppendQuad(vertices, quad);
        }
        const auto* storage = vertices.Data();
        const auto capacity = vertices.Capacity();
        const auto available = budget.available;
        // As on REN_ResetSplatTextureBatcher, all previous UVs become stale.
        vertices.Clear();
        ASSERT_TRUE(vertices.Empty());
        ASSERT_EQ(vertices.Data(), storage);
        ASSERT_EQ(vertices.Capacity(), capacity);
        ASSERT_EQ(budget.available, available);
        ASSERT_EQ(budget.limit, limit);
        ASSERT_LE(budget.available * 4, vertices.Capacity());
        for (std::size_t quad = 0; quad < limit; ++quad) {
          if (quad >= budget.available) {
            ASSERT_TRUE(moho::TryGrowSplatOutput(vertices, budget));
          }
          ASSERT_LT(vertices.Size() + 3, vertices.Capacity());
          AppendQuad(vertices, quad, 0.5f);
        }
        CheckPrefix(vertices, 0.5f);
        ASSERT_EQ(vertices.Size(), limit * 4);
        EXPECT_FALSE(moho::TryGrowSplatOutput(vertices, budget));
      }
    }
  }

  template <std::size_t N>
  void CheckBackoffAfterRestart()
  {
    const ScopedBackoff isolate;
    gpg::core::FastVectorN<Vertex, N> vertices;
    auto budget = moho::PrepareSplatOutput(vertices, 3);
    ASSERT_TRUE(moho::TryGrowSplatOutput(vertices, budget));
    const auto retainedQuads = budget.available;
    const auto* retainedStorage = vertices.Data();
    for (std::size_t quad = 0; quad < retainedQuads; ++quad) {
      AppendQuad(vertices, quad);
    }
    // Seed the same state recorded by TryGrowSplatOutput's bad_alloc handler.
    // No process allocator is replaced or forced to fail in this native test.
    auto& backoff = moho::splat_detail::Backoff();
    const auto failedBytes = retainedQuads * 2 * 4 * sizeof(Vertex);
    backoff.Failed(failedBytes);
    vertices.Clear();
    for (std::size_t quad = 0; quad < retainedQuads; ++quad) {
      AppendQuad(vertices, quad, 0.5f);
    }
    for (unsigned retry = 0; retry < 32; ++retry) {
      ASSERT_FALSE(moho::TryGrowSplatOutput(vertices, budget));
      ASSERT_EQ(vertices.Data(), retainedStorage);
      ASSERT_EQ(vertices.Size(), retainedQuads * 4);
      ASSERT_EQ(budget.available, retainedQuads);
      ASSERT_EQ(backoff.skippedCalls, 31u - retry);
    }
    CheckPrefix(vertices, 0.5f);
    ASSERT_TRUE(moho::TryGrowSplatOutput(vertices, budget));
    EXPECT_EQ(budget.available, retainedQuads * 2);
    EXPECT_EQ(backoff.failedBytes, 0u);
    CheckPrefix(vertices, 0.5f);
  }

  template <std::size_t N>
  void CheckSparseOutputGrowth()
  {
    const ScopedBackoff isolate;
    gpg::core::FastVectorN<Vertex, N> vertices;
    auto budget = moho::PrepareSplatOutput(vertices, 1);
    // Atlas skips count toward the collectors' candidate cap without appending
    // vertices. At the first candidate growth boundary output can be sparse.
    AppendQuad(vertices, 0);
    ASSERT_TRUE(moho::TryGrowSplatOutput(vertices, budget));
    ASSERT_EQ(vertices.Size(), 4u);
    EXPECT_EQ(budget.available, N / 2);
    CheckPrefix(vertices);
    vertices.Clear();
    EXPECT_TRUE(vertices.Empty());
    EXPECT_EQ(budget.available, N / 2);
    EXPECT_EQ(vertices.Capacity(), N * 2);
  }
}

TEST(SplatBudget, HighAndMediumFidelityStorage) { CheckBudgets<10000>(); }
TEST(SplatBudget, LowFidelityStorage) { CheckBudgets<1000>(); }
TEST(SplatBudget, HighAndMediumAtlasRestartStorage) { CheckAtlasRestartStorage<10000>(); }
TEST(SplatBudget, LowAtlasRestartStorage) { CheckAtlasRestartStorage<1000>(); }
TEST(SplatBudget, HighAndMediumBackoffAfterRestart) { CheckBackoffAfterRestart<10000>(); }
TEST(SplatBudget, LowBackoffAfterRestart) { CheckBackoffAfterRestart<1000>(); }
TEST(SplatBudget, HighAndMediumSparseOutputGrowth) { CheckSparseOutputGrowth<10000>(); }
TEST(SplatBudget, LowSparseOutputGrowth) { CheckSparseOutputGrowth<1000>(); }

TEST(SplatBudget, AllocationBackoff)
{
  moho::splat_detail::AllocationBackoff state;
  EXPECT_TRUE(state.Allow(100));
  state.Failed(100);
  EXPECT_TRUE(state.Allow(50));
  state.Succeeded(50);
  EXPECT_EQ(state.failedBytes, 100u);
  EXPECT_EQ(state.skippedCalls, 32u);
  for (unsigned i = 0; i < 32; ++i) {
    EXPECT_FALSE(state.Allow(i % 2 ? 100 : 200));
  }
  EXPECT_TRUE(state.Allow(100));
  state.Succeeded(100);
  EXPECT_EQ(state.failedBytes, 0u);
  EXPECT_EQ(state.skippedCalls, 0u);
  state.Failed(100);
  EXPECT_TRUE(state.Allow(50));
  state.Failed(50);
  EXPECT_FALSE(state.Allow(50));
  EXPECT_FALSE(state.Allow(100));
}

TEST(SplatBudget, DefaultAndInvalidViewsLeaveBackoffUntouched)
{
  const ScopedBackoff isolate;
  auto& state = moho::splat_detail::Backoff();
  state.Failed(123456);
  for (const int tier : {0, -1, 4, std::numeric_limits<int>::min(), std::numeric_limits<int>::max()}) {
    gpg::core::FastVectorN<Vertex, 1000> vertices;
    const auto* inlineStorage = vertices.Data();
    auto budget = moho::PrepareSplatOutput(vertices, tier);
    EXPECT_FALSE(moho::TryGrowSplatOutput(vertices, budget));
    EXPECT_EQ(vertices.Data(), inlineStorage);
    EXPECT_EQ(state.failedBytes, 123456u);
    EXPECT_EQ(state.skippedCalls, 32u);
  }
}

TEST(SplatBudget, BudgetSnapshotSurvivesPreferenceChange)
{
  const ScopedBackoff isolate;
  gpg::core::FastVectorN<Vertex, 1000> vertices;
  int preference = 1;
  auto budget = moho::PrepareSplatOutput(vertices, preference);
  preference = 0;
  vertices.Clear();
  ASSERT_TRUE(moho::TryGrowSplatOutput(vertices, budget));
  EXPECT_EQ(budget.limit, 1000u);
  EXPECT_EQ(budget.available, 500u);
  const auto next = moho::PrepareSplatOutput(vertices, preference);
  EXPECT_EQ(next.limit, 249u);
  EXPECT_EQ(vertices.Capacity(), 1000u);
}

TEST(SplatBudget, SmallerFidelitySuccessPreservesLargerFailure)
{
  const ScopedBackoff isolate;
  gpg::core::FastVectorN<Vertex, 10000> high;
  gpg::core::FastVectorN<Vertex, 1000> low;
  auto highBudget = moho::PrepareSplatOutput(high, 1);
  auto lowBudget = moho::PrepareSplatOutput(low, 1);
  auto& state = moho::splat_detail::Backoff();
  const auto failedBytes = 20000 * sizeof(Vertex);
  state.Failed(failedBytes);
  ASSERT_TRUE(moho::TryGrowSplatOutput(low, lowBudget));
  EXPECT_EQ(state.failedBytes, failedBytes);
  EXPECT_EQ(state.skippedCalls, 32u);
  EXPECT_FALSE(moho::TryGrowSplatOutput(high, highBudget));
  EXPECT_EQ(state.skippedCalls, 31u);
  EXPECT_EQ(high.Capacity(), 10000u);
}

TEST(SplatBudget, BackoffIsRenderThreadLocal)
{
  const ScopedBackoff isolate;
  auto& state = moho::splat_detail::Backoff();
  state.Failed(56000);
  std::size_t initialFailedBytes = 1;
  unsigned initialSkippedCalls = 1;
  std::thread other([&] {
    auto& otherState = moho::splat_detail::Backoff();
    initialFailedBytes = otherState.failedBytes;
    initialSkippedCalls = otherState.skippedCalls;
    otherState.Failed(1);
  });
  other.join();
  EXPECT_EQ(initialFailedBytes, 0u);
  EXPECT_EQ(initialSkippedCalls, 0u);
  EXPECT_EQ(state.failedBytes, 56000u);
  EXPECT_EQ(state.skippedCalls, 32u);
}
