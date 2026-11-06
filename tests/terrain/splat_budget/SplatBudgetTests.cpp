// Actual production budget, vertex and container types. No replacement allocator.
#include <cstdio>
#include <cstdlib>
#include <initializer_list>
#include <limits>

#include "moho/terrain/SplatBudget.h"
#include "moho/terrain/splat/CWldSplat.h"
#include "gpg/core/containers/FastVector.h"

namespace
{
  void Check(bool ok, const char* why)
  {
    if (!ok) {
      std::fprintf(stderr, "FAIL: %s\n", why);
      std::exit(1);
    }
  }

  template <std::size_t N>
  void CheckBudgets()
  {
    using Vertex = moho::CWldSplat::SplatVertex;
    gpg::core::FastVectorN<Vertex, N> vertices;
    const auto* inlineData = vertices.Data();
    const std::size_t caps[] = {N / 4 - 1, N, N * 5 / 2, N * 5};
    Check(sizeof(Vertex) == 28, "real vertex size");
    for (const int tier : {0, 1, 2, 3, -1, 4, std::numeric_limits<int>::min(), std::numeric_limits<int>::max()}) {
      vertices.ResetStorageToInline();
      auto budget = moho::PrepareSplatOutput(vertices, tier);
      const auto cap = caps[tier >= 0 && tier <= 3 ? tier : 0];
      Check(budget.limit == cap, "tier/invalid limit");
      Check(budget.available == (cap < N / 4 ? cap : N / 4), "initial availability");
      Check(vertices.Data() == inlineData && vertices.Capacity() == N && vertices.Size() == 0, "prepare stays inline");
      for (std::size_t quad = 0; quad < cap; ++quad) {
        if (quad >= budget.available) {
          Check(moho::TryGrowSplatOutput(vertices, budget), "bounded successful growth");
          Check(vertices.Size() == quad * 4, "growth preserves live prefix length");
          for (std::size_t i = 0; i < vertices.Size(); ++i) {
            Check(vertices[i].mAlpha == static_cast<float>(i), "growth preserves every live vertex");
          }
        }
        Vertex vertex{};
        // WildMagic default constructors need not initialize their floats.
        vertex.mPosition.x = vertex.mPosition.y = vertex.mPosition.z = 0.0f;
        vertex.mTexCoord.x = vertex.mTexCoord.y = 0.0f;
        for (std::size_t corner = 0; corner < 4; ++corner) {
          vertex.mAlpha = static_cast<float>(quad * 4 + corner);
          vertices.PushBack(vertex);
        }
      }
      Check(vertices.Size() == cap * 4, "complete bounded quads");
      Check(!moho::TryGrowSplatOutput(vertices, budget), "full budget refuses more");
      Check(vertices.Capacity() <= (cap < N / 4 ? N : cap * 4), "capacity bounded");
      if (tier <= 0 || tier > 3) {
        Check(vertices.Data() == inlineData && vertices.Capacity() == N, "original/invalid never grows");
      }
      const auto* allocated = vertices.Data();
      const auto capacity = vertices.Capacity();
      budget = moho::PrepareSplatOutput(vertices, tier);
      Check(vertices.Size() == 0 && vertices.Data() == allocated && vertices.Capacity() == capacity, "same tier reuses storage");
      // Start one enlarged output, then lower the limit without changing vector identity.
      if (tier == 3) {
        budget = moho::PrepareSplatOutput(vertices, 1);
        Check(vertices.Data() == inlineData && vertices.Capacity() == N && budget.limit == caps[1], "downshift releases excessive storage");
        Check(moho::TryGrowSplatOutput(vertices, budget), "growth after downshift");
      }
      budget = moho::PrepareSplatOutput(vertices, 0);
      Check(vertices.Size() == 0 && vertices.Data() == inlineData && vertices.Capacity() == N, "original restores inline");
      Check(budget.limit == caps[0], "original restores legacy cutoff");
    }
  }

  void CheckBackoff()
  {
    moho::splat_detail::AllocationBackoff state;
    Check(state.Allow(100), "fresh backoff allows");
    state.Failed(100);
    Check(state.Allow(50), "smaller request bypasses");
    state.Succeeded(50);
    Check(state.failedBytes == 100 && state.skippedCalls == 32, "small success retains larger failure");
    for (unsigned i = 0; i < 32; ++i) {
      Check(!state.Allow(i % 2 ? 100 : 200), "equal/larger request backs off 32 calls");
    }
    Check(state.Allow(100), "retry after 32 skips");
    state.Succeeded(100);
    Check(state.failedBytes == 0 && state.skippedCalls == 0, "sufficient success clears backoff");
    state.Failed(100);
    Check(state.Allow(50), "smaller failure permitted once");
    state.Failed(50);
    Check(!state.Allow(50) && !state.Allow(100), "smaller failure also backs off");
  }
}

int main()
{
  CheckBackoff();
  CheckBudgets<10000>();
  CheckBudgets<1000>();
  std::puts("PASS: production splat budgets, inline/retained/downshift storage, live prefix and backoff state");
  return 0;
}
