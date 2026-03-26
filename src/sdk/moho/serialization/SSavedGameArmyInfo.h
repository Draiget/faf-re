#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "legacy/containers/String.h"

namespace moho
{
  /**
   * Address evidence:
   * - typeinfo size init at 0x0087FF60 (FUN_0087FF60, size 0x1C)
   * - vector stride at 0x00882260 / 0x008822C0 / 0x008827F0 (element size 0x1C)
   *
   * What it is:
   * One saved-army label row serialized into saved-game header payload.
   */
  struct SSavedGameArmyInfo
  {
    static gpg::RType* sType;

    [[nodiscard]] static gpg::RType* StaticGetClass();

    msvc8::string mPlayerName; // +0x00
  };

  static_assert(offsetof(SSavedGameArmyInfo, mPlayerName) == 0x00, "SSavedGameArmyInfo::mPlayerName offset must be 0x00");
  static_assert(sizeof(SSavedGameArmyInfo) == 0x1C, "SSavedGameArmyInfo size must be 0x1C");

  /**
   * VFTABLE: 0x00E8C7D0 (FA)
   */
  class SSavedGameArmyInfoTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x0087FF80 (FUN_0087FF80)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0087FF60 (FUN_0087FF60)
     */
    void Init() override;
  };

  static_assert(sizeof(SSavedGameArmyInfoTypeInfo) == 0x64, "SSavedGameArmyInfoTypeInfo size must be 0x64");

  class SSavedGameArmyInfoSerializer
  {
  public:
    /**
     * Address: 0x00882090 (FUN_00882090)
     *
     * What it does:
     * Registers load/save callbacks for SSavedGameArmyInfo.
     */
    virtual void RegisterSerializeFunctions();

  public:
    void* mNext;
    void* mPrev;
    gpg::RType::load_func_t mSerLoadFunc;
    gpg::RType::save_func_t mSerSaveFunc;
  };

  static_assert(sizeof(SSavedGameArmyInfoSerializer) == 0x14, "SSavedGameArmyInfoSerializer size must be 0x14");
} // namespace moho
