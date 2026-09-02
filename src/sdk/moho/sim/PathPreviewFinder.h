#pragma once

namespace moho
{
  class PathPreviewFinder;

  /**
   * Address: 0x007657D0 (FUN_007657D0)
   *
   * What it does:
   * Destroys one heap-allocated `PathPreviewFinder` through its real
   * destructor chain: the implicit `PathPreviewFinder::~PathPreviewFinder()`
   * (no members of its own require teardown) chains to the already-recovered
   * `IPathTraveler::~IPathTraveler()`, which unlinks `mPathQueueNode` from
   * whatever path-queue ring it is currently threaded into, before the
   * storage is released. The real binary emits this identical body multiple
   * times (standalone at 0x007657D0; inlined directly into
   * `boost::detail::sp_counted_impl_p<Moho::PathPreviewFinder>::dispose` at
   * 0x00765720; and again, guarded by a leading null check, at 0x007657A0,
   * which sits at `??_7PathPreviewFinder@Moho@@6B@+0x8` and already backs
   * `IPathTraveler::~IPathTraveler()`'s own address citation) -- `final` on
   * `PathPreviewFinder` lets the compiler resolve the destructor
   * non-virtually at every one of those call sites.
   *
   * Declared here (rather than in Sim.h, which is large and pulls in
   * `moho/entity/Entity.h`, `lua/LuaObject.h`, and similar heavyweight
   * subsystem headers) so that other translation units -- in particular
   * `gpg/core/utils/BoostWrappers.cpp`'s `sp_counted_impl_p<PathPreviewFinder>`
   * control-block thunks -- can invoke the real destructor chain without
   * needing `PathPreviewFinder`'s full class layout. Defined in Sim.cpp,
   * where `PathPreviewFinder` is a complete type.
   */
  void DeletePathPreviewFinder(PathPreviewFinder* finder) noexcept;
} // namespace moho
