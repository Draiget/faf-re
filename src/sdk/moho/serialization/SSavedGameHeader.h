#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/BoostWrappers.h"
#include "legacy/containers/String.h"
#include "legacy/containers/Vector.h"
#include "moho/serialization/SSavedGameArmyInfo.h"

namespace moho
{
  class LaunchInfoBase;

  /**
   * Address evidence:
   * - typeinfo size/version at 0x00880170 (FUN_00880170, size 0x58, version 3)
   * - save/load callbacks at 0x00883280 / 0x008831C0
   * - ctor/dtor helper chain at 0x00880580 / 0x008805E0
   *
   * What it is:
   * Saved-game header payload persisted ahead of body archive data.
   */
  struct SSavedGameHeader
  {
    static gpg::RType* sType;

    [[nodiscard]] static gpg::RType* StaticGetClass();

    /**
     * Address: 0x00880580 (FUN_00880580)
     *
     * What it does:
     * Initializes header defaults (`mVersion = 0x14`) and clears payload fields.
     */
    SSavedGameHeader();

    SSavedGameHeader(const SSavedGameHeader& other);
    SSavedGameHeader& operator=(const SSavedGameHeader& other);

    /**
     * Address: 0x008805E0 (FUN_008805E0)
     *
     * What it does:
     * Releases launch-info shared handle and clears owned fields.
     */
    ~SSavedGameHeader();

    std::int32_t mVersion;                                // +0x00
    msvc8::string mMapName;                               // +0x04
    std::int32_t mFocusArmy;                              // +0x20
    msvc8::vector<SSavedGameArmyInfo> mArmyInfo;          // +0x24
    msvc8::string mScenarioInfoText;                      // +0x34
    boost::SharedPtrRaw<LaunchInfoBase> mLaunchInfo;      // +0x50
  };

  static_assert(offsetof(SSavedGameHeader, mVersion) == 0x00, "SSavedGameHeader::mVersion offset must be 0x00");
  static_assert(offsetof(SSavedGameHeader, mMapName) == 0x04, "SSavedGameHeader::mMapName offset must be 0x04");
  static_assert(offsetof(SSavedGameHeader, mFocusArmy) == 0x20, "SSavedGameHeader::mFocusArmy offset must be 0x20");
  static_assert(offsetof(SSavedGameHeader, mArmyInfo) == 0x24, "SSavedGameHeader::mArmyInfo offset must be 0x24");
  static_assert(
    offsetof(SSavedGameHeader, mScenarioInfoText) == 0x34, "SSavedGameHeader::mScenarioInfoText offset must be 0x34"
  );
  static_assert(offsetof(SSavedGameHeader, mLaunchInfo) == 0x50, "SSavedGameHeader::mLaunchInfo offset must be 0x50");
  static_assert(sizeof(SSavedGameHeader) == 0x58, "SSavedGameHeader size must be 0x58");

  class SSavedGameHeaderTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x008801A0 (FUN_008801A0)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00880170 (FUN_00880170)
     */
    void Init() override;
  };

  static_assert(sizeof(SSavedGameHeaderTypeInfo) == 0x64, "SSavedGameHeaderTypeInfo size must be 0x64");

  class SSavedGameHeaderSerializer
  {
  public:
    /**
     * Address: 0x00882330 (FUN_00882330)
     *
     * What it does:
     * Registers save/load callbacks for SSavedGameHeader.
     */
    virtual void RegisterSerializeFunctions();

  public:
    void* mNext;
    void* mPrev;
    gpg::RType::load_func_t mSerLoadFunc;
    gpg::RType::save_func_t mSerSaveFunc;
  };

  static_assert(sizeof(SSavedGameHeaderSerializer) == 0x14, "SSavedGameHeaderSerializer size must be 0x14");
} // namespace moho
