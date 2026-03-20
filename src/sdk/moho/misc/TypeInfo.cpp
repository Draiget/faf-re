#include "TypeInfo.h"

namespace moho
{
  /**
   * Address: 0x00A8242D (`?name@type_info@@QBEPBDPAU__type_info_node@@@Z`, `type_info::name`)
   *
   * What it does:
   * Returns canonical runtime type name.
   */
  const char* RuntimeTypeName(const RuntimeTypeInfo& typeInfo) noexcept
  {
    return typeInfo.name();
  }

  /**
   * Address: 0x00A8247D (`??8type_info@@QBE_NABV0@@Z`, `type_info::operator==`)
   *
   * What it does:
   * Compares canonical runtime type descriptors for equality.
   */
  bool RuntimeTypeEquals(const RuntimeTypeInfo& lhs, const RuntimeTypeInfo& rhs) noexcept
  {
    return lhs == rhs;
  }

  /**
   * Address: 0x00A824B4 (`?before@type_info@@QBEHABV1@@Z`, `type_info::before`)
   *
   * What it does:
   * Defines strict weak ordering between runtime type descriptors.
   */
  bool RuntimeTypeBefore(const RuntimeTypeInfo& lhs, const RuntimeTypeInfo& rhs) noexcept
  {
    return lhs.before(rhs);
  }
} // namespace moho
