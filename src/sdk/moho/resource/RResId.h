#pragma once

#include <cstddef>

#include "gpg/core/containers/String.h"
#include "gpg/core/reflection/Reflection.h"
#include "legacy/containers/String.h"

namespace moho
{
  /**
   * Address: 0x004A94F0 (FUN_004A94F0)
   *
   * What it does:
   * Reflection type init sets `sizeof(RResId) = 0x1C`.
   */
  struct RResId
  {
    static gpg::RType* sType;

    [[nodiscard]] static gpg::RType* StaticGetClass();

    msvc8::string name;
  };

  /**
   * Address: 0x004A9350 (FUN_004A9350, Moho::RES_CompletePath)
   *
   * What it does:
   * Completes a resource path using the source-file directory and collapses
   * separator / `.` / `..` path segments into canonical form.
   */
  [[nodiscard]] msvc8::string RES_CompletePath(gpg::StrArg resourceName, gpg::StrArg sourceName);

  /**
   * VFTABLE: 0x00E07368
   *
   * What it does:
   * Reflection descriptor for `RResId` with filename lexical semantics.
   */
  class RResIdType final : public gpg::RType
  {
  public:
    /**
     * Address: 0x004A9490 (FUN_004A9490, Moho::RResIdType::RResIdType)
     */
    RResIdType();

    /**
     * Address: 0x004A9520 (FUN_004A9520, scalar deleting destructor lane)
     * Address: 0x004A9620 (FUN_004A9620, duplicate deleting destructor lane)
     */
    ~RResIdType() override;

    /**
     * Address: 0x004A9510 (FUN_004A9510)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x004A9450 (FUN_004A9450, Moho::RResIdType::GetLexical)
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;

    /**
     * Address: 0x004A9430 (FUN_004A9430, Moho::RResIdType::SetLexical)
     */
    bool SetLexical(const gpg::RRef& ref, const char* lexical) const override;

    /**
     * Address: 0x004A94F0 (FUN_004A94F0)
     */
    void Init() override;
  };

  static_assert(offsetof(RResId, name) == 0x00, "RResId::name offset must be 0x00");
  static_assert(sizeof(RResId) == 0x1C, "RResId size must be 0x1C");
  static_assert(sizeof(RResIdType) == 0x64, "RResIdType size must be 0x64");
} // namespace moho
