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
   *
   * A console command that expands to another command line. Each instance is
   * a namespace-scope global: its constructor registers it and its destructor
   * (run through `atexit`) frees the text and unregisters it. Every
   * `TSimConVar`/`CSimConFunc` has one, `"<name>"` -> `"DoSimCommand <name>"`,
   * so the user console forwards to the sim.
   */
  class CConAlias final : public CConCommand
  {
  public:
    /**
     * Address: 0x0041E600 (FUN_0041E600)
     *
     * const char* name, const char* description, const char* aliasText
     *
     * What it does:
     * Runs base command initialization/registration, then copies the
     * expansion text.
     */
    CConAlias(const char* name, const char* description, const char* aliasText);

    /**
     * Address: 0x0041E6A0 (FUN_0041E6A0)
     *
     * What it does:
     * Executes the alias text and appends escaped runtime command arguments.
     */
    void Handle(const msvc8::vector<msvc8::string>& args) override;

    msvc8::string mAliasText; // 0x0C
  };

  static_assert(sizeof(CConAlias) == 0x28, "CConAlias size must be 0x28");
  static_assert(offsetof(CConAlias, mAliasText) == 0x0C, "CConAlias::mAliasText offset must be 0x0C");
} // namespace moho
