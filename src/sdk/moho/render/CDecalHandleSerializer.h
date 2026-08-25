#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "moho/render/CDecalHandle.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E373E8
   * COL: 0x00E913E4
   *
   * Demangled: gpg::SerSaveLoadHelper<class Moho::CDecalHandle>
   *
   * Per-instantiation addresses (one compiler-emitted body per `T`; see the
   * template's class-level comment in Reflection.h for the general shape):
   *  - ctor / compiler dynamic-initializer (`register_CDecalHandleSerializer`):
   *    0x00BDD8E0 (__xc_a-reachable; dead zero-xref COMDAT duplicates:
   *    0x0077AB90, 0x00779FD0)
   *  - dtor: 0x00C02940 (`??1CDecalHandleSerializer@Moho@@QAE@@Z`)
   *  - Init(): 0x0077ABC0
   *  - Deserialize(): 0x00779FA0
   *  - Serialize(): 0x00779FB0
   *
   * NOTE: prior recovery had never identified the real ctor -- the
   * `CDecalHandleSerializerBootstrap` static-init struct in the old .cpp
   * only self-linked the helper node and left `mLoadCallback`/`mSaveCallback`
   * explicitly null, so the reflection callbacks were never actually
   * installed under that shape.
   */
  using CDecalHandleSerializer = gpg::SerSaveLoadHelper<CDecalHandle>;
} // namespace moho
