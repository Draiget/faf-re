#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

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
} // namespace moho
