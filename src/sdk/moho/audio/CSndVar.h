#pragma once

#include <cstddef>
#include <cstdint>

#include "legacy/containers/String.h"

namespace gpg
{
  class RType;
}

namespace moho
{
  /**
   * Resolvable sound variable descriptor.
   *
   * Binary shape recovered from FUN_004E02B0/FUN_004E0330:
   * - +0x00: resolved runtime variable id (0xFFFF = unresolved/invalid)
   * - +0x02: resolve-attempt flag (set by DoResolve)
   * - +0x04: variable name (MSVC8 string)
   */
  class CSndVar
  {
  public:
    inline static gpg::RType* sType = nullptr;

    /**
     * Address: 0x004E02B0 (FUN_004E02B0)
     *
     * gpg::StrArg name
     *
     * What it does:
     * Initializes variable id/flags and stores the variable name token.
     */
    explicit CSndVar(const char* name);

    /**
     * Address: 0x004E0330 (FUN_004E0330)
     *
     * What it does:
     * Releases name storage and resets the instance to unresolved state.
     */
    ~CSndVar();

    /**
     * Address: 0x004E0390 (FUN_004E0390)
     *
     * What it does:
     * Lazily resolves the named global sound variable id and caches the result.
     */
    bool DoResolve() const;

  public:
    mutable std::uint16_t mState;   // +0x00
    mutable std::uint8_t mResolved; // +0x02
    std::uint8_t mReserved03;       // +0x03
    msvc8::string mName;            // +0x04
  };

  /**
   * Address: 0x004DF390 (FUN_004DF390, func_NewCSndVar)
   *
   * What it does:
   * Returns one interned `CSndVar` for the supplied variable name, creating a
   * new descriptor on first use.
   */
  CSndVar* SND_FindOrCreateVariable(const msvc8::string& variableName);

  static_assert(offsetof(CSndVar, mState) == 0x00, "CSndVar::mState offset must be 0x00");
  static_assert(offsetof(CSndVar, mResolved) == 0x02, "CSndVar::mResolved offset must be 0x02");
  static_assert(offsetof(CSndVar, mName) == 0x04, "CSndVar::mName offset must be 0x04");
  static_assert(sizeof(CSndVar) == 0x20, "CSndVar size must be 0x20");
} // namespace moho
