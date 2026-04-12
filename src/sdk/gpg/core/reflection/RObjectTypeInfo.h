#pragma once

#include <cstddef>
#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  class RObjectTypeInfo final : public gpg::RType
  {
  public:
    /** Address: 0x008E0660 */
    RObjectTypeInfo();
    /** Address: 0x008E06F0 */
    ~RObjectTypeInfo() override;
    /** Address: 0x008E06D0 */
    [[nodiscard]] const char* GetName() const override;
    /** Address: 0x008E06E0 */
    void Init() override;
  };

  static_assert(sizeof(RObjectTypeInfo) == 0x64, "RObjectTypeInfo size must be 0x64");

  /** Address: 0x00BE99A0 */
  void register_RObjectTypeInfoStartup();
} // namespace gpg
