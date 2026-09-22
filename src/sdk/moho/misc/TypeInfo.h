#pragma once

#include <typeinfo>

namespace moho
{
  // These wrap `std::type_info`, the MSVC CRT's own `.?AVtype_info@@` (its
  // vector deleting dtor is 0x00A8244A, `??_Etype_info@@UAEPAXI@Z`), not a
  // Moho class.

  /**
   * Address: 0x00A8247D (`??8type_info@@QBE_NABV0@@Z`, `type_info::operator==`)
   *
   * Compares canonical runtime type descriptors for equality.
   */
  [[nodiscard]] bool RuntimeTypeEquals(const std::type_info& lhs, const std::type_info& rhs) noexcept;

  /**
   * Address: 0x00401250 (FUN_00401250)
   *
   * What it does:
   * Compares optional RTTI descriptor pointers with identity/null fast paths
   * before deferring to `type_info::operator==`.
   */
  [[nodiscard]] bool RuntimeTypePtrEquals(const std::type_info* lhs, const std::type_info* rhs) noexcept;

  /**
   * Address: 0x00A8242D (`?name@type_info@@QBEPBDPAU__type_info_node@@@Z`, `type_info::name`)
   *
   * Returns canonical runtime type name.
   */
  [[nodiscard]] const char* RuntimeTypeName(const std::type_info& typeInfo) noexcept;

  /**
   * Address: 0x00A824B4 (`?before@type_info@@QBEHABV1@@Z`, `type_info::before`)
   *
   * Strict weak ordering used by RTTI maps.
   */
  [[nodiscard]] bool RuntimeTypeBefore(const std::type_info& lhs, const std::type_info& rhs) noexcept;
} // namespace moho
