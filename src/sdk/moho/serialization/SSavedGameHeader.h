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

  class SSavedGameHeaderSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BE7040 (FUN_00BE7040, register_SSavedGameHeaderSerializer,
     * dynamic initializer for the global `SSavedGameHeaderSerializer`
     * singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields.
     */
    SSavedGameHeaderSerializer();

    /**
     * Address: 0x00C07D50 (FUN_00C07D50, ??1SSavedGameHeaderSerializer@Moho@@QAE@@Z)
     */
    ~SSavedGameHeaderSerializer();

    /**
     * Address: 0x00880260 (FUN_00880260, Moho::SSavedGameHeaderSerializer::Deserialize)
     *
     * What it does:
     * Thin forwarder into the real load body at 0x008831C0 (a single-caller
     * internal function the compiler passes `archive`/`objectPtr` through
     * `esi`/`edi` for, confirmed from raw asm -- not a normal 4-arg cdecl
     * call at the machine-code level, but behaviourally identical).
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00880280 (FUN_00880280, Moho::SSavedGameHeaderSerializer::Serialize)
     *
     * What it does:
     * Thin forwarder into the real save body at 0x00883280 (same
     * single-caller register-passing shape as Deserialize/0x008831C0).
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00882330 (FUN_00882330, Moho::SSavedGameHeaderSerializer::Init)
     *
     * This body is ICF-folded/shared with vtable slot 0 of the
     * never-constructed `gpg::SerSaveLoadHelper<SSavedGameHeader>` template
     * instantiation (`??_7?$SerSaveLoadHelper@USSavedGameHeader@Moho@@@gpg@@6B@`,
     * confirmed to have zero vtable-writer ctors anywhere in the binary).
     * `SSavedGameHeaderSerializer` is not derived through that template:
     * `SSavedGameHeader` has no `MemberDeserialize`/`MemberSerialize` pair for
     * the template to forward into in the first place.
     *
     * What it does:
     * Registers save/load callbacks for SSavedGameHeader.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mSerLoadFunc; // +0x0C
    gpg::RType::save_func_t mSerSaveFunc; // +0x10
  };

  static_assert(
    offsetof(SSavedGameHeaderSerializer, mSerLoadFunc) == 0x0C,
    "SSavedGameHeaderSerializer::mSerLoadFunc offset must be 0x0C"
  );
  static_assert(
    offsetof(SSavedGameHeaderSerializer, mSerSaveFunc) == 0x10,
    "SSavedGameHeaderSerializer::mSerSaveFunc offset must be 0x10"
  );
  static_assert(sizeof(SSavedGameHeaderSerializer) == 0x14, "SSavedGameHeaderSerializer size must be 0x14");
} // namespace moho
