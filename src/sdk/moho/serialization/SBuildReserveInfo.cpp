#include "moho/serialization/SBuildReserveInfo.h"

#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/unit/CUnitCommandWeakPtrReflection.h"
#include "moho/unit/core/UnitWeakPtrReflection.h"

namespace
{
  gpg::RType* gWeakPtrUnitType = nullptr;
  gpg::RType* gWeakPtrCUnitCommandType = nullptr;

  [[nodiscard]] gpg::RType* ResolveWeakPtrUnitType()
  {
    if (!gWeakPtrUnitType) {
      gWeakPtrUnitType = gpg::LookupRType(typeid(moho::WeakPtr<moho::Unit>));
      if (!gWeakPtrUnitType) {
        gWeakPtrUnitType = moho::register_WeakPtr_Unit_Type_00();
      }
    }

    GPG_ASSERT(gWeakPtrUnitType != nullptr);
    return gWeakPtrUnitType;
  }

  [[nodiscard]] gpg::RType* ResolveWeakPtrCUnitCommandType()
  {
    if (!gWeakPtrCUnitCommandType) {
      gWeakPtrCUnitCommandType = gpg::LookupRType(typeid(moho::WeakPtr<moho::CUnitCommand>));
      if (!gWeakPtrCUnitCommandType) {
        gWeakPtrCUnitCommandType = moho::register_WeakPtr_CUnitCommand_Type_00();
      }
    }

    GPG_ASSERT(gWeakPtrCUnitCommandType != nullptr);
    return gWeakPtrCUnitCommandType;
  }
} // namespace

namespace moho
{
  gpg::RType* SBuildReserveInfo::sType = nullptr;

  gpg::RType* SBuildReserveInfo::StaticGetClass()
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(SBuildReserveInfo));
    }
    return sType;
  }

  /**
   * Address: 0x00581730 (FUN_00581730, Moho::SBuildReserveInfo::MemberDeserialize)
   */
  void SBuildReserveInfo::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (!archive) {
      return;
    }

    gpg::RRef unitOwnerRef{};
    archive->Read(ResolveWeakPtrUnitType(), &mUnit, unitOwnerRef);

    gpg::RRef commandOwnerRef{};
    archive->Read(ResolveWeakPtrCUnitCommandType(), &mCom, commandOwnerRef);
  }

  /**
   * Address: 0x005817B0 (FUN_005817B0, Moho::SBuildReserveInfo::MemberSerialize)
   */
  void SBuildReserveInfo::MemberSerialize(gpg::WriteArchive* const archive)
  {
    if (!archive) {
      return;
    }

    gpg::RRef unitOwnerRef{};
    archive->Write(ResolveWeakPtrUnitType(), &mUnit, unitOwnerRef);

    gpg::RRef commandOwnerRef{};
    archive->Write(ResolveWeakPtrCUnitCommandType(), &mCom, commandOwnerRef);
  }
} // namespace moho

