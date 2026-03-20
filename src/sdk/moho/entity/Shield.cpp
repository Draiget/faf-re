#include "Shield.h"

#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/sim/Sim.h"

namespace
{
  gpg::RType* CachedShieldType()
  {
    static gpg::RType* sShieldType = nullptr;
    if (!sShieldType) {
      sShieldType = gpg::LookupRType(typeid(moho::Shield));
    }
    return sShieldType;
  }

  gpg::RType* CachedEntityType()
  {
    static gpg::RType* sEntityType = nullptr;
    if (!sEntityType) {
      sEntityType = gpg::LookupRType(typeid(moho::Entity));
    }
    return sEntityType;
  }

  /**
   * Address: 0x00776F60 (FUN_00776F60, sub_776F60)
   *
   * What it does:
   * Adds `Entity` as a reflected base of `Shield`.
   */
  void AddEntityBaseToShieldTypeInfo(gpg::RType* const typeInfo)
  {
    gpg::RType* const entityType = CachedEntityType();
    gpg::RField baseField{};
    baseField.mName = entityType->GetName();
    baseField.mType = entityType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  void UnlinkShieldFromSimList(moho::Shield* const shield)
  {
    if (!shield || !shield->SimulationRef) {
      return;
    }

    auto& shields = shield->SimulationRef->mShields;
    for (auto it = shields.begin(); it != shields.end();) {
      if (*it == shield) {
        it = shields.erase(it);
        continue;
      }

      ++it;
    }
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x007762F0 (FUN_007762F0)
   *
   * What it does:
   * Returns cached reflection descriptor for Shield.
   */
  gpg::RType* Shield::GetClass() const
  {
    return CachedShieldType();
  }

  /**
   * Address: 0x00776310 (FUN_00776310)
   *
   * What it does:
   * Packs {this, GetClass()} as a reflection reference handle.
   */
  gpg::RRef Shield::GetDerivedObjectRef()
  {
    gpg::RRef ref{};
    ref.mObj = this;
    ref.mType = GetClass();
    return ref;
  }

  /**
   * Address: 0x00776570 (FUN_00776570)
   *
   * What it does:
   * Unlinks this shield from Sim shield-list, then runs base entity teardown.
   */
  Shield::~Shield()
  {
    UnlinkShieldFromSimList(this);
  }

  /**
   * Address: 0x00776330 (FUN_00776330)
   *
   * What it does:
   * Runtime type probe override for shield entities.
   */
  Shield* Shield::IsShield()
  {
    return this;
  }

  /**
   * Address: 0x00776D20 (FUN_00776D20, sub_776D20)
   *
   * What it does:
   * Binds save-construct-args callback into Shield RTTI (`serSaveConstructArgsFunc_`).
   */
  void ShieldSaveConstruct::RegisterSaveConstructArgsFunction()
  {
    gpg::RType* const type = CachedShieldType();
    GPG_ASSERT(type->serSaveConstructArgsFunc_ == nullptr);
    type->serSaveConstructArgsFunc_ = mSerSaveConstructArgsFunc;
  }

  /**
   * Address: 0x00776DA0 (FUN_00776DA0, sub_776DA0)
   *
   * What it does:
   * Binds construct/delete callbacks into Shield RTTI (`serConstructFunc_`, `deleteFunc_`).
   */
  void ShieldConstruct::RegisterConstructFunction()
  {
    gpg::RType* const type = CachedShieldType();
    GPG_ASSERT(type->serConstructFunc_ == nullptr);
    type->serConstructFunc_ = mSerConstructFunc;
    type->deleteFunc_ = mDeleteFunc;
  }

  /**
   * Address: 0x00776E20 (FUN_00776E20, sub_776E20)
   *
   * What it does:
   * Binds load/save serializer callbacks into Shield RTTI (`serLoadFunc_`, `serSaveFunc_`).
   */
  void ShieldSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CachedShieldType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mSerLoadFunc;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerSaveFunc;
  }

  /**
   * Address: 0x007763E0 (FUN_007763E0, sub_7763E0)
   */
  ShieldTypeInfo::~ShieldTypeInfo() = default;

  /**
   * Address: 0x007763D0 (FUN_007763D0)
   */
  const char* ShieldTypeInfo::GetName() const
  {
    return "Shield";
  }

  /**
   * Address: 0x007763A0 (FUN_007763A0)
   *
   * What it does:
   * Sets Shield size and registers Entity base-field metadata.
   */
  void ShieldTypeInfo::Init()
  {
    size_ = sizeof(Shield);
    AddEntityBaseToShieldTypeInfo(this);
    gpg::RType::Init();
    Finish();
  }
} // namespace moho
