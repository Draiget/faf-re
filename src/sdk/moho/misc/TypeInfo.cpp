#include "TypeInfo.h"

namespace moho
{
  /**
   * Address: 0x00A8242D (`?name@type_info@@QBEPBDPAU__type_info_node@@@Z`, `type_info::name`)
   *
   * What it does:
   * Returns canonical runtime type name.
   */
  const char* RuntimeTypeName(const std::type_info& typeInfo) noexcept
  {
    return typeInfo.name();
  }

  /**
   * Address: 0x00A8247D (`??8type_info@@QBE_NABV0@@Z`, `type_info::operator==`)
   *
   * What it does:
   * Compares canonical runtime type descriptors for equality.
   */
  bool RuntimeTypeEquals(const std::type_info& lhs, const std::type_info& rhs) noexcept
  {
    return lhs == rhs;
  }

  /**
   * Address: 0x00401250 (FUN_00401250)
   *
   * What it does:
   * Compares optional runtime type pointers with identity/null short-circuiting.
   */
  bool RuntimeTypePtrEquals(const std::type_info* const lhs, const std::type_info* const rhs) noexcept
  {
    if (lhs == rhs) {
      return true;
    }
    if (!lhs || !rhs) {
      return false;
    }
    return *lhs == *rhs;
  }

  /**
   * Address: 0x00A824B4 (`?before@type_info@@QBEHABV1@@Z`, `type_info::before`)
   *
   * What it does:
   * Defines strict weak ordering between runtime type descriptors.
   */
  bool RuntimeTypeBefore(const std::type_info& lhs, const std::type_info& rhs) noexcept
  {
    return lhs.before(rhs);
  }
} // namespace moho
