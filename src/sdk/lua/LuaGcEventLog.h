#pragma once

#include <cstddef>

struct global_State;

namespace lua
{
  /**
   * x64 port test mode (not in the binary; plan 4.1a, verification V12).
   *
   * With `FAF_LUAGC_LOG=1` every full collection of every Lua VM logs
   *
   *   [LUAGC] state=<n> allocs=<count> nblocks=<accounted> threshold=<value>
   *
   * where `n` is the order in which the VM's global_State was created and
   * `allocs` the number of `luaM_realloc` calls made on it so far. Lua starts
   * a collection when `nblocks` reaches `GCthreshold`, and `nblocks` counts
   * real allocation sizes, so comparing the sim VM's lines between an x86 and
   * an x64 run of the same replay shows whether collections run at the same
   * point of the allocation sequence on both builds. The per-VM counters live
   * in a side table keyed by the global_State, so no Lua layout changes.
   *
   * Without the variable every entry point is one cached flag test.
   */
  [[nodiscard]] bool GcEventLogEnabled() noexcept;

  /** f_luaopen: a new global_State takes the next creation index. */
  void GcEventLogRegisterState(const global_State* globalState) noexcept;

  /** close_state: the global_State is about to be freed. */
  void GcEventLogUnregisterState(const global_State* globalState) noexcept;

  /** luaM_realloc: one more allocator call on this global_State. */
  void GcEventLogCountRealloc(const global_State* globalState) noexcept;

  /** luaC_collectgarbage, before the collection runs. */
  void GcEventLogCollection(const global_State* globalState, std::size_t nblocks, std::size_t threshold) noexcept;
} // namespace lua
