#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "moho/sim/CInfluenceMap.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E318D4
   *
   * Demangled: gpg::SerSaveLoadHelper<struct Moho::SThreat>
   *
   * Per-instantiation addresses (one compiler-emitted body per `T`; see the
   * template's class-level comment in Reflection.h for the general shape):
   *  - ctor / compiler dynamic-initializer (`register_SThreatSerializer`):
   *    0x00BDA780 (__xc_a-reachable; dead zero-xref COMDAT duplicate:
   *    0x00719340)
   *  - dtor: 0x00C00060 (no recovered mangled name; body confirmed via raw
   *    asm to just call `ResetLinks()`, same as every other instantiation's
   *    real destructor)
   *  - Init(): 0x00719370
   *  - Deserialize(): 0x00717AF0
   *  - Serialize(): 0x00717B00
   */
  using SThreatSerializer = gpg::SerSaveLoadHelper<SThreat>;
} // namespace moho
