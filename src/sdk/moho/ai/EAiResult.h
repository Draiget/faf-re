#pragma once

#include <cstdint>

namespace moho
{
  /**
   * Address: 0x00608BD0 (FUN_00608BD0)
   *
   * What it does:
   * Opaque enum type consumed by EAiResult reflection metadata.
   *
   * Notes:
   * Current FA evidence confirms enum width (`4`) and type name (`EAiResult`),
   * but does not expose lexical option labels in the RTTI init path.
   */
  enum EAiResult : std::int32_t;
} // namespace moho
