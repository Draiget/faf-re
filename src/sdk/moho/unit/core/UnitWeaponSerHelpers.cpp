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

#pragma init_seg(lib)

namespace
{
  moho::UnitWeaponConstruct gUnitWeaponConstruct{};
  moho::UnitWeaponSerializer gUnitWeaponSerializer{};

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* HelperSelfNode(THelper& helper) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&helper.mHelperNext);
  }

  template <typename THelper>
  void InitializeHelperNode(THelper& helper) noexcept
  {
    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperNext = self;
    helper.mHelperPrev = self;
  }

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* UnlinkHelperNode(THelper& helper) noexcept
  {
    if (helper.mHelperNext != nullptr && helper.mHelperPrev != nullptr) {
      helper.mHelperNext->mPrev = helper.mHelperPrev;
      helper.mHelperPrev->mNext = helper.mHelperNext;
    }

    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperPrev = self;
    helper.mHelperNext = self;
    return self;
  }

  void cleanup_UnitWeaponConstruct_AtExit()
  {
    (void)moho::cleanup_UnitWeaponConstruct();
  }

  void cleanup_UnitWeaponSerializer_AtExit()
  {
    (void)moho::cleanup_UnitWeaponSerializer();
  }

  struct UnitWeaponSerHelpersBootstrap
  {
    UnitWeaponSerHelpersBootstrap()
    {
      (void)moho::register_UnitWeaponConstruct();
      moho::register_UnitWeaponSerializer();
    }
  };

  UnitWeaponSerHelpersBootstrap gUnitWeaponSerHelpersBootstrap;
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
   * Address: 0x006DB960 (FUN_006DB960, sub_6DB960)
   */
  void UnitWeaponConstruct::RegisterConstructFunction()
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
   */
  void UnitWeaponSerializer::Deserialize(
    gpg::ReadArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    auto* const weapon = reinterpret_cast<UnitWeapon*>(objectPtr);
    if (!archive || !weapon) {
      return;
    }

    weapon->MemberDeserialize(*archive);
  }

  /**
   * Address: 0x006D7B20 (FUN_006D7B20, Moho::UnitWeaponSerializer::Serialize)
   */
  void UnitWeaponSerializer::Serialize(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::RRef*
  )
  {
    auto* const weapon = reinterpret_cast<UnitWeapon*>(objectPtr);
    if (!archive || !weapon) {
      return;
    }

    weapon->MemberSerialize(*archive);
  }

  /**
   * Address: 0x006DB9E0 (FUN_006DB9E0, sub_6DB9E0)
   */
  void UnitWeaponSerializer::RegisterSerializeFunctions()
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

  /**
   * Address: 0x00BFE7A0 (FUN_00BFE7A0, sub_BFE7A0)
   */
  gpg::SerHelperBase* cleanup_UnitWeaponConstruct()
  {
    return UnlinkHelperNode(gUnitWeaponConstruct);
  }

  /**
   * Address: 0x006D7A10 (FUN_006D7A10, sub_6D7A10)
   */
  gpg::SerHelperBase* cleanup_UnitWeaponConstruct_00Variant1()
  {
    return cleanup_UnitWeaponConstruct();
  }

  /**
   * Address: 0x006D7A40 (FUN_006D7A40, sub_6D7A40)
   */
  gpg::SerHelperBase* cleanup_UnitWeaponConstruct_00Variant2()
  {
    return cleanup_UnitWeaponConstruct();
  }

  /**
   * Address: 0x00BFE7D0 (FUN_00BFE7D0, Moho::UnitWeaponSerializer::~UnitWeaponSerializer)
   */
  gpg::SerHelperBase* cleanup_UnitWeaponSerializer()
  {
    return UnlinkHelperNode(gUnitWeaponSerializer);
  }

  /**
   * Address: 0x006D7B70 (FUN_006D7B70, sub_6D7B70)
   */
  gpg::SerHelperBase* cleanup_UnitWeaponSerializer_00Variant1()
  {
    return cleanup_UnitWeaponSerializer();
  }

  /**
   * Address: 0x006D7BA0 (FUN_006D7BA0, sub_6D7BA0)
   */
  gpg::SerHelperBase* cleanup_UnitWeaponSerializer_00Variant2()
  {
    return cleanup_UnitWeaponSerializer();
  }

  /**
   * Address: 0x00BD88F0 (FUN_00BD88F0, sub_BD88F0)
   */
  int register_UnitWeaponConstruct()
  {
    InitializeHelperNode(gUnitWeaponConstruct);
    gUnitWeaponConstruct.mConstructCallback =
      reinterpret_cast<gpg::RType::construct_func_t>(&construct_UnitWeapon_00Variant1);
    gUnitWeaponConstruct.mDeleteCallback = &delete_UnitWeapon_00;
    gUnitWeaponConstruct.RegisterConstructFunction();
    return std::atexit(&cleanup_UnitWeaponConstruct_AtExit);
  }

  /**
   * Address: 0x00BD8930 (FUN_00BD8930, register_UnitWeaponSerializer)
   */
  void register_UnitWeaponSerializer()
  {
    InitializeHelperNode(gUnitWeaponSerializer);
    gUnitWeaponSerializer.mDeserialize = reinterpret_cast<gpg::RType::load_func_t>(&UnitWeaponSerializer::Deserialize);
    gUnitWeaponSerializer.mSerialize = reinterpret_cast<gpg::RType::save_func_t>(&UnitWeaponSerializer::Serialize);
    gUnitWeaponSerializer.RegisterSerializeFunctions();
    (void)std::atexit(&cleanup_UnitWeaponSerializer_AtExit);
  }
} // namespace moho
