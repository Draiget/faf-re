#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "moho/misc/WeakPtr.h"

namespace moho
{
  class Entity;

  /**
   * Address family:
   * - 0x006D38A0 (`SBlackListInfoTypeInfo::Init`, size = 0x0C)
   * - 0x006DD300 (`SBlackListInfo` save path uses +0x08 int lane)
   *
   * What it is:
   * One blacklist row containing an entity weak link and one integer payload.
   */
  struct SBlackListInfo
  {
    static gpg::RType* sType;
    [[nodiscard]] static gpg::RType* StaticGetClass();

    WeakPtr<Entity> mEntity; // +0x00
    std::int32_t mValue;     // +0x08
  };

  static_assert(sizeof(SBlackListInfo) == 0x0C, "SBlackListInfo size must be 0x0C");
  static_assert(offsetof(SBlackListInfo, mEntity) == 0x00, "SBlackListInfo::mEntity offset must be 0x00");
  static_assert(offsetof(SBlackListInfo, mValue) == 0x08, "SBlackListInfo::mValue offset must be 0x08");
} // namespace moho

