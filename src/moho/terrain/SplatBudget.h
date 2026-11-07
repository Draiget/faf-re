#pragma once

#include <algorithm>
#include <cstddef>
#include <new>

#include "gpg/core/containers/FastVector.h"
#include "moho/terrain/splat/CWldSplat.h"

namespace moho
{
  // Rendering-only preference. A collector snapshots it once per view.
  extern int ren_SplatBudgetTier;

  struct SplatOutputBudget
  {
    std::size_t limit;
    std::size_t available;
  };

  template <std::size_t InlineVertices>
  SplatOutputBudget PrepareSplatOutput(
    gpg::core::FastVectorN<CWldSplat::SplatVertex, InlineVertices>& vertices, int tier)
  {
    static_assert(InlineVertices == 1000 || InlineVertices == 10000);
    constexpr std::size_t inlineQuads = InlineVertices / 4;
    // Original code stops BEFORE appending the nominal 250th/2500th splat.
    // Invalid console/pref values must not increase the allocation budget.
    if (tier != 1 && tier != 2 && tier != 3) {
      vertices.ResetStorageToInline();
      return {inlineQuads - 1, inlineQuads - 1};
    }
    const std::size_t limit = inlineQuads * (tier == 1 ? 4 : tier == 2 ? 10 : 20);
    if (vertices.Capacity() / 4 > limit) {
      vertices.ResetStorageToInline();
    } else {
      vertices.Clear();
    }
    return {limit, std::min(limit, vertices.Capacity() / 4)};
  }

  namespace splat_detail
  {
    struct AllocationBackoff
    {
      std::size_t failedBytes = 0;
      unsigned skippedCalls = 0;

      bool Allow(std::size_t requestedBytes)
      {
        if (requestedBytes >= failedBytes && skippedCalls != 0) {
          --skippedCalls;
          return false;
        }
        return true;
      }
      void Failed(std::size_t requestedBytes)
      {
        failedBytes = requestedBytes;
        skippedCalls = 32;
      }
      void Succeeded(std::size_t requestedBytes)
      {
        // A smaller successful request must not erase a larger failure.
        if (requestedBytes >= failedBytes) {
          failedBytes = 0;
          skippedCalls = 0;
        }
      }
    };

    inline AllocationBackoff& Backoff()
    {
      // No terrain pointers or clocks. Shared by views/fidelities on this
      // render thread; accessed only when accepted output needs to grow.
      static thread_local AllocationBackoff state;
      return state;
    }
  } // namespace splat_detail

  template <std::size_t InlineVertices>
  bool TryGrowSplatOutput(
    gpg::core::FastVectorN<CWldSplat::SplatVertex, InlineVertices>& vertices, SplatOutputBudget& budget)
  {
    if (budget.available >= budget.limit) {
      return false;
    }
    const std::size_t target = std::min(budget.limit, vertices.Capacity() / 2);
    const std::size_t bytes = target * 4 * sizeof(CWldSplat::SplatVertex);
    auto& backoff = splat_detail::Backoff();
    if (!backoff.Allow(bytes)) {
      return false;
    }
    try {
      // Use FastVectorN, not its base: it owns inline storage. Live vertices
      // are copied by the existing container; failure preserves that prefix.
      vertices.Reserve(target * 4);
    } catch (const std::bad_alloc&) {
      backoff.Failed(bytes);
      return false; // Caller must break, at most one failure per view.
    }
    backoff.Succeeded(bytes);
    budget.available = std::min(budget.limit, vertices.Capacity() / 4);
    return true;
  }
} // namespace moho
