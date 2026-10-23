#pragma once

#include <cstdint>

namespace moho
{
  /**
   * Address: 0x0065DF10 (FUN_0065DF10)
   *
   * What it does:
   * Opaque emitter-kind enum consumed by EmitterType RTTI metadata.
   *
   * Notes:
   * Current FA evidence confirms enum width (`4`) and type name (`EmitterType`)
   * but does not expose lexical option labels in the RTTI init path.
   */
  enum EmitterType : std::int32_t;

  static_assert(sizeof(EmitterType) == 0x4, "EmitterType size must be 4 bytes");
} // namespace moho
