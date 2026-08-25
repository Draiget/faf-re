#include "moho/unit/core/UnitWeaponSerHelpers.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

namespace gpg
{
  class SerConstructResult
  {
  public:
    void SetUnowned(const RRef& ref, unsigned int flags);
  };
} // namespace gpg

namespace
{
  /**
   * Address: 0x00BD88F0 (FUN_00BD88F0, dynamic initializer for the global
   * `UnitWeaponConstruct` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * construct/delete callback fields (vtable slot 0 `Init()` dispatched
   * later by `gpg::SerHelperBase::InitNewHelpers`). Confirmed via raw asm:
   * base-ctor call -> field-set -> vtable-install -> atexit, with no eager
   * `RegisterConstructFunction()` dispatch (the prior recovery fabricated
   * that eager call from `register_UnitWeaponConstruct`).
   */
  moho::UnitWeaponConstruct gUnitWeaponConstruct{};

  /**
   * Address: 0x00BD8930 (FUN_00BD8930, dynamic initializer for the global
   * `UnitWeaponSerializer` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields. Independent `__xc_a` static initializer,
   * separate from `UnitWeaponConstruct`'s own initializer above.
   */
  moho::UnitWeaponSerializer gUnitWeaponSerializer{};
} // namespace

namespace moho
{
  /**
   * Address: 0x006D7A80 (FUN_006D7A80, sub_6D7A80)
   */
  void construct_UnitWeapon_00Variant2(gpg::SerConstructResult* const result)
  {
    if (!result) {
      return;
    }

    UnitWeapon* const weapon = new (std::nothrow) UnitWeapon();
    gpg::RRef weaponRef{};
    weaponRef.mObj = weapon;
    weaponRef.mType = UnitWeapon::StaticGetClass();
    result->SetUnowned(weaponRef, 0u);
  }

  /**
   * Address: 0x006D7A70 (FUN_006D7A70, sub_6D7A70)
   */
  void construct_UnitWeapon_00Variant1(
    gpg::ReadArchive* const,
    const int,
    const int,
    gpg::SerConstructResult* const result
  )
  {
    construct_UnitWeapon_00Variant2(result);
  }

  /**
   * Address: 0x006DD740 (FUN_006DD740, sub_6DD740)
   */
  void delete_UnitWeapon_00(void* const objectPtr)
  {
    auto* const weapon = static_cast<UnitWeapon*>(objectPtr);
    if (!weapon) {
      return;
    }

    delete weapon;
  }

  /**
   * Address: 0x00BD88F0 (FUN_00BD88F0, register_UnitWeaponConstruct)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * construct/delete callback fields.
   */
  UnitWeaponConstruct::UnitWeaponConstruct()
    : mConstructCallback(reinterpret_cast<gpg::RType::construct_func_t>(&construct_UnitWeapon_00Variant1))
    , mDeleteCallback(&delete_UnitWeapon_00)
  {}

  /**
   * Address: 0x00BFE7A0 (FUN_00BFE7A0, sub_BFE7A0)
   */
  UnitWeaponConstruct::~UnitWeaponConstruct()
  {
    ResetLinks();
  }

  /**
   * Address: 0x006DB960 (FUN_006DB960, sub_6DB960)
   */
  void UnitWeaponConstruct::Init()
  {
    gpg::RType* type = UnitWeapon::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(UnitWeapon));
      UnitWeapon::sType = type;
    }

    GPG_ASSERT(type->serConstructFunc_ == nullptr);
    type->serConstructFunc_ = mConstructCallback;
    type->deleteFunc_ = mDeleteCallback;
  }

  /**
   * Address: 0x006D7B10 (FUN_006D7B10, Moho::UnitWeaponSerializer::Deserialize)
   *
   * What it does:
   * Dispatches archive loading into `UnitWeapon::MemberDeserialize`. Real
   * body is an unconditional call with no null guard.
   */
  void UnitWeaponSerializer::Deserialize(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    reinterpret_cast<UnitWeapon*>(objectPtr)->MemberDeserialize(*archive);
  }

  /**
   * Address: 0x006D7B20 (FUN_006D7B20, Moho::UnitWeaponSerializer::Serialize)
   *
   * What it does:
   * Dispatches archive saving into `UnitWeapon::MemberSerialize`. Real body
   * is an unconditional call with no null guard and no `ownerRef` branch --
   * the prior recovery fabricated an `ownerRef`-conditional dispatch
   * through a dead one-instruction jump-thunk pair
   * (`j_Moho::UnitWeapon::MemberSerialize`/`_0` at 0x006DD780/0x006DE7B0,
   * both zero-xref, both jumping straight to the same
   * `UnitWeapon::MemberSerialize` this call already reaches directly).
   */
  void UnitWeaponSerializer::Serialize(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    reinterpret_cast<UnitWeapon*>(objectPtr)->MemberSerialize(*archive);
  }

  /**
   * Address: 0x00BFE7D0 (FUN_00BFE7D0, Moho::UnitWeaponSerializer::~UnitWeaponSerializer)
   */
  UnitWeaponSerializer::~UnitWeaponSerializer()
  {
    ResetLinks();
  }

  /**
   * Address: 0x00BD8930 (FUN_00BD8930, register_UnitWeaponSerializer)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields.
   */
  UnitWeaponSerializer::UnitWeaponSerializer()
    : mDeserialize(reinterpret_cast<gpg::RType::load_func_t>(&UnitWeaponSerializer::Deserialize))
    , mSerialize(reinterpret_cast<gpg::RType::save_func_t>(&UnitWeaponSerializer::Serialize))
  {}

  /**
   * Address: 0x006DB9E0 (FUN_006DB9E0, sub_6DB9E0)
   */
  void UnitWeaponSerializer::Init()
  {
    gpg::RType* type = UnitWeapon::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(UnitWeapon));
      UnitWeapon::sType = type;
    }

    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }
} // namespace moho
