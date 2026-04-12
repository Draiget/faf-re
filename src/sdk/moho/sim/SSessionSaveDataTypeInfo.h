#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class SSessionSaveDataTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x00897300 (Moho::SSessionSaveDataTypeInfo::SSessionSaveDataTypeInfo)
     */
    SSessionSaveDataTypeInfo();

    /**
     * Address: 0x008973B0 (scalar deleting thunk)
     */
    ~SSessionSaveDataTypeInfo() override;

    /**
     * Address: 0x008973A0 (Moho::SSessionSaveDataTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00897360 (Moho::SSessionSaveDataTypeInfo::Init)
     */
    void Init() override;
  };

  static_assert(sizeof(SSessionSaveDataTypeInfo) == 0x64, "SSessionSaveDataTypeInfo size must be 0x64");

  /**
   * Address: 0x00BE7770 (register_SSessionSaveDataTypeInfo)
   */
  void register_SSessionSaveDataTypeInfoStartup();
} // namespace moho
