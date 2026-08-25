#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "moho/sim/SPhysConstants.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E294BC
   *
   * Demangled: gpg::SerSaveLoadHelper<struct Moho::SPhysConstants>
   *
   * Per-instantiation addresses (one compiler-emitted body per `T`; see the
   * template's class-level comment in Reflection.h for the general shape):
   *  - ctor / compiler dynamic-initializer: 0x00BD6050 (__xc_a-reachable;
   *    dead zero-xref COMDAT duplicate: 0x00699EA0)
   *  - dtor: 0x00BFD460 (no recovered mangled name; body confirmed via raw
   *    asm to just call `ResetLinks()`, same as every other instantiation's
   *    real destructor)
   *  - Init(): 0x00699ED0
   *  - Deserialize(): 0x00699C10
   *  - Serialize(): 0x00699C50
   */
  using SPhysConstantsSerializer = gpg::SerSaveLoadHelper<SPhysConstants>;
} // namespace moho
