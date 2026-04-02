#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/String.h"
#include "moho/console/CConCommand.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E01710
   * COL:     0x00E5E278
   */
  class CConAlias final : public CConCommand
  {
  public:
    CConAlias() noexcept;

    /**
     * Address: 0x0041E600 (FUN_0041E600)
     *
     * const char* description, const char* name, const char* aliasCommandText
     *
     * What it does:
     * Initializes alias metadata, registers by command name, and stores expansion text.
     */
    void InitializeRecovered(const char* description, const char* name, const char* aliasCommandText);

    /**
     * Address: 0x00BFE370/FUN_00BFE370-family cleanup lanes
     *
     * What it does:
     * Resets alias command-text storage and tears down command registration for
     * startup-owned cleanup thunks.
     */
    void ShutdownRecovered();

    /**
     * Address: 0x0041E6A0 (FUN_0041E6A0)
     *
     * What it does:
     * Executes the alias text and appends escaped runtime command arguments.
     */
    void Handle(void* commandArgs) override;

    [[nodiscard]] const msvc8::string& AliasCommandText() const noexcept;

  private:
    [[nodiscard]] void* AliasCommandStorageAddress() noexcept;
    [[nodiscard]] const void* AliasCommandStorageAddress() const noexcept;
    [[nodiscard]] msvc8::string& AliasCommandStorage() noexcept;
    [[nodiscard]] const msvc8::string& AliasCommandStorage() const noexcept;

    std::uint8_t mAliasStorageTail[0x18]{};
  };

  static_assert(sizeof(CConAlias) == 0x28, "CConAlias size must be 0x28");
} // namespace moho
