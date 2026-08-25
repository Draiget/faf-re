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

  class SSavedGameArmyInfoSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BE6FE0 (FUN_00BE6FE0, register_SSavedGameArmyInfoSerializer,
     * dynamic initializer for the global `SSavedGameArmyInfoSerializer`
     * singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields.
     */
    SSavedGameArmyInfoSerializer();

    /**
     * Address: 0x00C07CC0 (FUN_00C07CC0)
     *
     * IDA never produced a mangled name for this one (unlike its siblings'
     * `??1...Serializer@Moho@@QAE@@Z` destructors) -- confirmed real by its
     * single code xref, the real ctor's `atexit` push at 0x00BE6FEA, and a
     * body that operates directly on the `SSavedGameArmyInfoSerializer`
     * global (not a parameterized/shared thunk).
     */
    ~SSavedGameArmyInfoSerializer();

    /**
     * Address: 0x00880040 (FUN_00880040, Moho::SSavedGameArmyInfoSerializer::Deserialize)
     *
     * What it does:
     * Loads one `SSavedGameArmyInfo::mPlayerName` lane via
     * `gpg::ReadArchive::ReadString` (vtable slot 2).
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00880060 (FUN_00880060, Moho::SSavedGameArmyInfoSerializer::Serialize)
     *
     * What it does:
     * Saves one `SSavedGameArmyInfo::mPlayerName` lane via
     * `gpg::WriteArchive::WriteString` (vtable slot 2).
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00882090 (FUN_00882090, Moho::SSavedGameArmyInfoSerializer::Init)
     *
     * This body is ICF-folded/shared with vtable slot 0 of the
     * never-constructed `gpg::SerSaveLoadHelper<SSavedGameArmyInfo>` template
     * instantiation (`??_7?$SerSaveLoadHelper@USSavedGameArmyInfo@Moho@@@gpg@@6B@`,
     * confirmed to have zero vtable-writer ctors anywhere in the binary).
     * `SSavedGameArmyInfoSerializer` is not derived through that template:
     * `SSavedGameArmyInfo` has no `MemberDeserialize`/`MemberSerialize` pair
     * for the template to forward into in the first place.
     *
     * What it does:
     * Binds SSavedGameArmyInfo serializer callbacks into RTTI.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mSerLoadFunc; // +0x0C
    gpg::RType::save_func_t mSerSaveFunc; // +0x10
  };

  static_assert(
    offsetof(SSavedGameArmyInfoSerializer, mSerLoadFunc) == 0x0C,
    "SSavedGameArmyInfoSerializer::mSerLoadFunc offset must be 0x0C"
  );
  static_assert(
    offsetof(SSavedGameArmyInfoSerializer, mSerSaveFunc) == 0x10,
    "SSavedGameArmyInfoSerializer::mSerSaveFunc offset must be 0x10"
  );
  static_assert(sizeof(SSavedGameArmyInfoSerializer) == 0x14, "SSavedGameArmyInfoSerializer size must be 0x14");
} // namespace moho
