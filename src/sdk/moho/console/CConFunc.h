#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/console/CConCommand.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E01708
   * COL:     0x00E5E2C8
   */
  class CConFunc final : public CConCommand
  {
  public:
    using Callback = void(__cdecl*)(void* commandArgs);

    CConFunc() noexcept;

    /**
     * Address: <synthetic initializer built from CConCommand registration shape>
     *
     * const char* description, const char* name, Callback callback
     *
     * What it does:
     * Initializes command metadata and callback payload, then registers by name.
     */
    void InitializeRecovered(const char* description, const char* name, Callback callback) noexcept;

    /**
     * Address: 0x1001DC00 (MohoEngine.dll, FUN_1001DC00)
     * Address: 0x0041E5F0 (ForgedAlliance.exe, FUN_0041E5F0)
     *
     * What it does:
     * Forwards command args to callback stored at payload offset +0x0C.
     */
    void Handle(void* commandArgs) override;

    [[nodiscard]] Callback GetCallback() const noexcept;
  };

  static_assert(sizeof(CConFunc) == 0x10, "CConFunc size must be 0x10");
} // namespace moho
