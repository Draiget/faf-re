#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  struct SAudioRequest;

  class SAudioRequestTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x004E0F00 (FUN_004E0F00, Moho::SAudioRequestTypeInfo::SAudioRequestTypeInfo)
     *
     * What it does:
     * Constructs and preregisters `SAudioRequest` reflection type metadata.
     */
    SAudioRequestTypeInfo();

    /**
     * Address: 0x004E0F90 (FUN_004E0F90, Moho::SAudioRequestTypeInfo::dtr)
     */
    ~SAudioRequestTypeInfo() override;

    /**
     * Address: 0x004E0F80 (FUN_004E0F80, Moho::SAudioRequestTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x004E0F60 (FUN_004E0F60, Moho::SAudioRequestTypeInfo::Init)
     */
    void Init() override;
  };

  /**
   * Address: 0x00BF1020 (FUN_00BF1020, cleanup_SAudioRequestTypeInfo)
   */
  void cleanup_SAudioRequestTypeInfo();

  /**
   * Address: 0x00BC6A30 (FUN_00BC6A30, register_SAudioRequestTypeInfo)
   */
  int register_SAudioRequestTypeInfo();

  static_assert(sizeof(SAudioRequestTypeInfo) == 0x64, "SAudioRequestTypeInfo size must be 0x64");
} // namespace moho

