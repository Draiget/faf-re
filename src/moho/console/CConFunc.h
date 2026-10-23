#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/console/CConCommand.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E01708
   * COL:     0x00E5E2C8
   *
   * A console command bound to one handler function. Each instance is a
   * namespace-scope global: its constructor registers it and its destructor
   * (run through `atexit`) unregisters it.
   */
  class CConFunc final : public CConCommand
  {
  public:
    using Callback = void(__cdecl*)(const msvc8::vector<msvc8::string>& args);

    /**
     * Address: 0x0041E5C0 (FUN_0041E5C0, ??0CConFunc@Moho@@QAE@PBD0@Z)
     *
     * const char* name, const char* description, Callback callback
     *
     * What it does:
     * Runs base command initialization/registration and stores the handler.
     */
    CConFunc(const char* name, const char* description, Callback callback) noexcept;

    /**
     * Address: 0x1001DC00 (MohoEngine.dll, FUN_1001DC00)
     * Address: 0x0041E5F0 (ForgedAlliance.exe, FUN_0041E5F0)
     *
     * What it does:
     * Forwards command args to the stored handler.
     */
    void Handle(const msvc8::vector<msvc8::string>& args) override;

    Callback mFunc; // 0x0C
  };

  static_assert(sizeof(CConFunc) == 0x10, "CConFunc size must be 0x10");
  static_assert(offsetof(CConFunc, mFunc) == 0x0C, "CConFunc::mFunc offset must be 0x0C");
} // namespace moho
