#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "legacy/containers/String.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E198EC
   * COL:		0x00E6EAC0
   */
  class CSimConVarInstanceBase
  {
  public:
    /**
     * Address: 0x00579740 (FUN_00579740, sub_579740)
     *
     * IDA signature:
     * _DWORD *__thiscall sub_579740(_DWORD *this, char a2);
     *
     * What it does:
     * Scalar-deleting destructor for base convar-instance objects.
     */
    virtual ~CSimConVarInstanceBase();

    /**
     * Address: 0x00A82547 (_purecall in base)
     *
     * What it does:
     * Handles console command args for this typed convar instance.
     */
    virtual int HandleConsoleCommand(void* commandArgs) = 0;

    /**
     * Address: 0x00A82547 (_purecall in base)
     *
     * What it does:
     * Returns pointer to underlying typed value storage used by Sim convar readers.
     */
    virtual void* GetValueStorage() = 0;

    /**
     * Address: 0x00A82547 (_purecall in base)
     *
     * What it does:
     * Exports the typed value as a reflection `gpg::RRef`.
     */
    virtual gpg::RRef* GetValueRef(gpg::RRef* outRef) = 0;

  public:
    const char* mName; // 0x04
  };

  static_assert(sizeof(CSimConVarInstanceBase) == 0x08, "CSimConVarInstanceBase size must be 0x08");
  static_assert(offsetof(CSimConVarInstanceBase, mName) == 0x04, "CSimConVarInstanceBase::mName offset must be 0x04");

  template <typename T>
  class TSimConVarInstance : public CSimConVarInstanceBase
  {
  public:
    T mValue; // +0x08
  };

  static_assert(
    offsetof(TSimConVarInstance<bool>, mValue) == 0x08, "TSimConVarInstance<bool>::mValue offset must be 0x08"
  );
  static_assert(offsetof(TSimConVarInstance<int>, mValue) == 0x08, "TSimConVarInstance<int>::mValue offset must be 0x08");
  static_assert(
    offsetof(TSimConVarInstance<float>, mValue) == 0x08, "TSimConVarInstance<float>::mValue offset must be 0x08"
  );
  static_assert(
    offsetof(TSimConVarInstance<std::uint8_t>, mValue) == 0x08,
    "TSimConVarInstance<uint8_t>::mValue offset must be 0x08"
  );
  static_assert(
    offsetof(TSimConVarInstance<msvc8::string>, mValue) == 0x08,
    "TSimConVarInstance<string>::mValue offset must be 0x08"
  );
  static_assert(sizeof(TSimConVarInstance<bool>) == 0x0C, "TSimConVarInstance<bool> size must be 0x0C");
  static_assert(sizeof(TSimConVarInstance<int>) == 0x0C, "TSimConVarInstance<int> size must be 0x0C");
  static_assert(sizeof(TSimConVarInstance<float>) == 0x0C, "TSimConVarInstance<float> size must be 0x0C");
  static_assert(sizeof(TSimConVarInstance<std::uint8_t>) == 0x0C, "TSimConVarInstance<uint8_t> size must be 0x0C");
  static_assert(sizeof(TSimConVarInstance<msvc8::string>) == 0x24, "TSimConVarInstance<string> size must be 0x24");
} // namespace moho
