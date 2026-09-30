#pragma once
#include <cstddef>
#include <cstdint>

#include "legacy/containers/String.h"
#include "moho/sim/SFootprint.h"

namespace moho
{
  /**
   * One entry of the rules' footprint table (`SRuleFootprintsBlueprint`): a
   * footprint shape plus the name blueprints refer to it by and its index in
   * the table, which is also the index of its `PathTables` cluster map.
   *
   * Address: 0x00514960 (FUN_00514960 -- the implicit copy constructor out of line: the four footprint
   * words, then `mName` default-initialised (`_Myres = 15`, `_Mysize = 0`, `_Bx[0] = 0`) and
   * `assign(src, 0, npos)` 0x004056B0, then `mIndex`; usercall this=ESI, source=EDI. Reached from
   * `list<SNamedFootprint>::_Buynode` 0x005144A0 and the element assignments 0x005145F0/0x00514820;
   * formerly `CopySNamedFootprintValue` in moho/path/SNamedFootprintTypeInfo.cpp (RULE ONE), removed
   * 2026-09-30.)
   */
  struct SNamedFootprint : public SFootprint
  {
    /**
     * An all-zero footprint with no name and index -1: the element
     * `RListType<SNamedFootprint>::SerLoad` reads into (0x00514165..0x005141A7:
     * four zero bytes, three zero floats, an empty string, `-1`) and the one
     * `cfunc_SpecFootprintsL` fills from each spec (0x0052861A).
     */
    SNamedFootprint()
      : SFootprint{}
    {}

    msvc8::string mName;     // +0x10
    std::int32_t mIndex = -1; // +0x2C
  };

  static_assert(offsetof(SNamedFootprint, mName) == 0x10, "SNamedFootprint::mName offset must be 0x10");
  static_assert(offsetof(SNamedFootprint, mIndex) == 0x2C, "SNamedFootprint::mIndex offset must be 0x2C");
  static_assert(sizeof(SNamedFootprint) == 0x30, "SNamedFootprint size must be 0x30");
} // namespace moho
