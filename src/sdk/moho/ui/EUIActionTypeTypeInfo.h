#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * UI action category for command/build/select operations.
   * Recovered from binary AddEnums evidence at FUN_00822160.
   */
  enum class EUIActionType : std::int32_t
  {
    None = 0,
    Command = 1,
    Build = 2,
    BuildAnchored = 3,
    Select = 4,
    EditGraphDrag = 5,
    Cancel = 7,
  };

  class EUIActionTypeTypeInfo final : public gpg::REnumType
  {
  public:
    /** Address: 0x008220A0 (FUN_008220A0, sub_8220A0) */
    EUIActionTypeTypeInfo();
    /** Address: 0x00822130 (deleting thunk) */
    ~EUIActionTypeTypeInfo() override;
    /** Address: 0x00822120 */
    [[nodiscard]] const char* GetName() const override;
    /** Address: 0x00822100 */
    void Init() override;

  private:
    /** Address: 0x00822160 (FUN_00822160, AddEnums) */
    static void AddEnums(gpg::REnumType* enumType);
  };

  static_assert(sizeof(EUIActionTypeTypeInfo) == 0x78, "EUIActionTypeTypeInfo size must be 0x78");

  void register_EUIActionTypeTypeInfoStartup();
} // namespace moho
