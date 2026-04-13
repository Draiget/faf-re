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

    /**
     * Address: 0x0089A2E0 (FUN_0089A2E0, Moho::SSessionSaveDataTypeInfo::NewRef)
     */
    static gpg::RRef NewRef();

    /**
     * Address: 0x0089A3C0 (FUN_0089A3C0, Moho::SSessionSaveDataTypeInfo::CtrRef)
     */
    static gpg::RRef CtrRef(void* objectStorage);

    /**
     * Address: 0x0089A380 (FUN_0089A380, Moho::SSessionSaveDataTypeInfo::Delete)
     */
    static void Delete(void* objectStorage);

    /**
     * Address: 0x0089A450 (FUN_0089A450, Moho::SSessionSaveDataTypeInfo::Destruct)
     */
    static void Destruct(void* objectStorage);
  };

  static_assert(sizeof(SSessionSaveDataTypeInfo) == 0x64, "SSessionSaveDataTypeInfo size must be 0x64");

  /**
   * Address: 0x00BE7770 (register_SSessionSaveDataTypeInfo)
   */
  void register_SSessionSaveDataTypeInfoStartup();
} // namespace moho
