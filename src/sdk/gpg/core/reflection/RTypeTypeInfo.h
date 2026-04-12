#pragma once

#include <cstddef>
#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  class RTypeTypeInfo final : public gpg::RType
  {
  public:
    /** Address: 0x008E0580 */
    RTypeTypeInfo();
    /** Address: 0x008E0600 */
    ~RTypeTypeInfo() override;
    /** Address: 0x008E05F0 */
    [[nodiscard]] const char* GetName() const override;
    /** Address: 0x008E1560 */
    void Init() override;
  };

  static_assert(sizeof(RTypeTypeInfo) == 0x64, "RTypeTypeInfo size must be 0x64");

  /** Address: 0x00BE9980 */
  void register_RTypeTypeInfoStartup();
} // namespace gpg
