#pragma once

#include "gpg/core/reflection/Reflection.h"
#include "moho/containers/BVIntSet.h"

namespace moho
{
  /**
   * VFTABLE: 0x00DFFF54
   * COL: 0x00E5C3D0
   *
   * Demangled: gpg::SerSaveLoadHelper<class Moho::BVIntSet>
   *
   * Per-instantiation addresses (one compiler-emitted body per `T`; see the
   * template's class-level comment in Reflection.h for the general shape):
   *  - ctor / compiler dynamic-initializer (`register_BVIntSetSerializer`):
   *    0x00BC2D00 (dead zero-xref COMDAT duplicate: 0x004025F0)
   *  - dtor: 0x00BEDEE0 (`??1BVIntSetSerializer@Moho@@QAE@@Z`)
   *  - Init(): 0x00402620
   *  - Deserialize(): 0x004015A0
   *  - Serialize(): 0x004015B0
   */
  using BVIntSetSerializer = gpg::SerSaveLoadHelper<BVIntSet>;

  /**
   * Address: 0x00BC2D00 (FUN_00BC2D00, register_BVIntSetSerializer)
   *
   * What it does:
   * Forces this translation unit's global `BVIntSetSerializer` instance to
   * link into the reflection bootstrap sequence ahead of default-segment
   * consumers that query BVIntSet RTTI during static initialization. The
   * ctor/vtable-install/atexit-dtor-registration sequence this address
   * decompiles to is MSVC's own compiler-generated dynamic initializer for
   * that global, not hand-written source -- see `gpg::SerSaveLoadHelper<T>`
   * in Reflection.h, which documents the same shape already established for
   * `gpg::PrimitiveSerHelper<T,IntType>`.
   */
  void register_BVIntSetSerializer();
} // namespace moho
