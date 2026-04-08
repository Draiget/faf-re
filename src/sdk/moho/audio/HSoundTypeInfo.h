#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E0B980
   * COL: 0x00E64FF8
   */
  class HSoundTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x004E1360 (FUN_004E1360, Moho::HSoundTypeInfo::HSoundTypeInfo)
     *
     * What it does:
     * Constructs and preregisters `HSound` reflection type metadata.
     */
    HSoundTypeInfo();

    /**
     * Address: 0x004E1400 (FUN_004E1400, Moho::HSoundTypeInfo::dtr)
     * Slot: 2
     */
    ~HSoundTypeInfo() override;

    /**
     * Address: 0x004E13F0 (FUN_004E13F0, Moho::HSoundTypeInfo::GetName)
     * Slot: 3
     *
     * What it does:
     * Returns reflection type-name literal for `HSound`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x004E13C0 (FUN_004E13C0, Moho::HSoundTypeInfo::Init)
     * Slot: 9
     *
     * What it does:
     * Initializes reflection metadata for `HSound` (`sizeof = 0x58`)
     * and registers `CScriptEvent` as base metadata.
     */
    void Init() override;

  private:
    /**
     * Address: 0x004E4E80 (FUN_004E4E80, Moho::HSoundTypeInfo::AddBase_CScriptEvent)
     *
     * What it does:
     * Registers `CScriptEvent` as reflection base at subobject offset `0`.
     */
    static void AddBase_CScriptEvent(gpg::RType* typeInfo);
  };

  /**
   * Address: 0x00BF10B0 (FUN_00BF10B0, cleanup_HSoundTypeInfo)
   *
   * What it does:
   * Releases process-exit `HSoundTypeInfo` field/base vector storage.
   */
  void cleanup_HSoundTypeInfo();

  /**
   * Address: 0x00BC6AB0 (FUN_00BC6AB0, register_HSoundTypeInfo)
   *
   * What it does:
   * Forces `HSoundTypeInfo` startup construction and installs `atexit` cleanup.
   */
  int register_HSoundTypeInfo();

  static_assert(sizeof(HSoundTypeInfo) == 0x64, "HSoundTypeInfo size must be 0x64");
} // namespace moho
