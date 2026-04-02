#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "moho/unit/core/UnitWeapon.h"

namespace gpg
{
  class SerConstructResult;
}

namespace moho
{
  class UnitWeaponConstruct
  {
  public:
    /**
     * Address: 0x006DB960 (FUN_006DB960, sub_6DB960)
     *
     * What it does:
     * Binds UnitWeapon construct/delete callbacks into reflected RTTI.
     */
    virtual void RegisterConstructFunction();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };

  static_assert(offsetof(UnitWeaponConstruct, mHelperNext) == 0x04, "UnitWeaponConstruct::mHelperNext offset must be 0x04");
  static_assert(offsetof(UnitWeaponConstruct, mHelperPrev) == 0x08, "UnitWeaponConstruct::mHelperPrev offset must be 0x08");
  static_assert(
    offsetof(UnitWeaponConstruct, mConstructCallback) == 0x0C,
    "UnitWeaponConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(UnitWeaponConstruct, mDeleteCallback) == 0x10, "UnitWeaponConstruct::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(UnitWeaponConstruct) == 0x14, "UnitWeaponConstruct size must be 0x14");

  class UnitWeaponSerializer
  {
  public:
    /**
     * Address: 0x006D7B10 (FUN_006D7B10, Moho::UnitWeaponSerializer::Deserialize)
     *
     * What it does:
     * Dispatches archive loading into `UnitWeapon::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006D7B20 (FUN_006D7B20, Moho::UnitWeaponSerializer::Serialize)
     *
     * What it does:
     * Dispatches archive saving into `UnitWeapon::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006DB9E0 (FUN_006DB9E0, sub_6DB9E0)
     *
     * What it does:
     * Binds UnitWeapon load/save callbacks into reflected RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(offsetof(UnitWeaponSerializer, mHelperNext) == 0x04, "UnitWeaponSerializer::mHelperNext offset must be 0x04");
  static_assert(offsetof(UnitWeaponSerializer, mHelperPrev) == 0x08, "UnitWeaponSerializer::mHelperPrev offset must be 0x08");
  static_assert(
    offsetof(UnitWeaponSerializer, mDeserialize) == 0x0C, "UnitWeaponSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(offsetof(UnitWeaponSerializer, mSerialize) == 0x10, "UnitWeaponSerializer::mSerialize offset must be 0x10");
  static_assert(sizeof(UnitWeaponSerializer) == 0x14, "UnitWeaponSerializer size must be 0x14");

  /**
   * Address: 0x006D7A80 (FUN_006D7A80, sub_6D7A80)
   *
   * What it does:
   * Allocates one `UnitWeapon` and sets it as unowned construct result.
   */
  void construct_UnitWeapon_00Variant2(gpg::SerConstructResult* result);

  /**
   * Address: 0x006D7A70 (FUN_006D7A70, sub_6D7A70)
   *
   * What it does:
   * Construct callback thunk forwarding to `construct_UnitWeapon_00Variant2`.
   */
  void construct_UnitWeapon_00Variant1(gpg::ReadArchive* archive, int objectPtr, int version, gpg::SerConstructResult* result);

  /**
   * Address: 0x006DD740 (FUN_006DD740, sub_6DD740)
   *
   * What it does:
   * Deletes constructed `UnitWeapon` through deleting-dtor path.
   */
  void delete_UnitWeapon_00(void* objectPtr);

  /**
   * Address: 0x00BFE7A0 (FUN_00BFE7A0, sub_BFE7A0)
   *
   * What it does:
   * Unlinks `UnitWeaponConstruct` helper-node links and rewires self-links.
   */
  gpg::SerHelperBase* cleanup_UnitWeaponConstruct();

  /**
   * Address: 0x006D7A10 (FUN_006D7A10, sub_6D7A10)
   *
   * What it does:
   * Duplicate cleanup lane for `UnitWeaponConstruct` helper links.
   */
  gpg::SerHelperBase* cleanup_UnitWeaponConstruct_00Variant1();

  /**
   * Address: 0x006D7A40 (FUN_006D7A40, sub_6D7A40)
   *
   * What it does:
   * Duplicate cleanup lane for `UnitWeaponConstruct` helper links.
   */
  gpg::SerHelperBase* cleanup_UnitWeaponConstruct_00Variant2();

  /**
   * Address: 0x00BFE7D0 (FUN_00BFE7D0, Moho::UnitWeaponSerializer::~UnitWeaponSerializer)
   *
   * What it does:
   * Unlinks `UnitWeaponSerializer` helper-node links and rewires self-links.
   */
  gpg::SerHelperBase* cleanup_UnitWeaponSerializer();

  /**
   * Address: 0x006D7B70 (FUN_006D7B70, sub_6D7B70)
   *
   * What it does:
   * Duplicate cleanup lane for `UnitWeaponSerializer` helper links.
   */
  gpg::SerHelperBase* cleanup_UnitWeaponSerializer_00Variant1();

  /**
   * Address: 0x006D7BA0 (FUN_006D7BA0, sub_6D7BA0)
   *
   * What it does:
   * Duplicate cleanup lane for `UnitWeaponSerializer` helper links.
   */
  gpg::SerHelperBase* cleanup_UnitWeaponSerializer_00Variant2();

  /**
   * Address: 0x00BD88F0 (FUN_00BD88F0, sub_BD88F0)
   *
   * What it does:
   * Initializes and registers `UnitWeaponConstruct` helper callbacks.
   */
  int register_UnitWeaponConstruct();

  /**
   * Address: 0x00BD8930 (FUN_00BD8930, register_UnitWeaponSerializer)
   *
   * What it does:
   * Initializes and registers `UnitWeaponSerializer` helper callbacks.
   */
  void register_UnitWeaponSerializer();
} // namespace moho
