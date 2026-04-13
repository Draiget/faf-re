#include "SimArmy.h"

#include <cstddef>
#include <new>
#include <typeinfo>

#include "gpg/core/reflection/Reflection.h"
#include "moho/sim/SSTIArmyConstantData.h"

namespace moho
{
  namespace
  {
    struct IArmyConstructionView
    {
      SSTIArmyConstantData mConstDat; // +0x00
      SSTIArmyVariableData mVarDat;   // +0x80
    };

    static_assert(offsetof(IArmyConstructionView, mConstDat) == 0x00, "IArmyConstructionView::mConstDat offset must be 0x00");
    static_assert(offsetof(IArmyConstructionView, mVarDat) == 0x80, "IArmyConstructionView::mVarDat offset must be 0x80");
  } // namespace

  gpg::RType* IArmy::sType = nullptr;
  gpg::RType* SimArmy::sType = nullptr;
  gpg::RType* SimArmy::sPointerType = nullptr;

  gpg::RType* IArmy::StaticGetClass()
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(IArmy));
    }
    return sType;
  }

  /**
   * Address: 0x006FD520 (FUN_006FD520, Moho::IArmy::IArmy)
   *
   * What it does:
   * Constructs IArmy's serialized base payload lanes in-place.
   */
  IArmy::IArmy()
  {
    auto* const view = reinterpret_cast<IArmyConstructionView*>(this);
    ::new (&view->mConstDat) SSTIArmyConstantData();
    ::new (&view->mVarDat) SSTIArmyVariableData();
  }

  gpg::RType* SimArmy::StaticGetClass()
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(SimArmy));
    }
    return sType;
  }

  /**
   * Address: 0x0074E550 (FUN_0074E550, Moho::SimArmy::GetPointerType)
   *
   * What it does:
   * Lazily resolves and caches reflected RTTI for `SimArmy*`.
   */
  gpg::RType* SimArmy::GetPointerType()
  {
    (void)StaticGetClass();

    gpg::RType* cached = sPointerType;
    if (!cached) {
      cached = gpg::LookupRType(typeid(SimArmy*));
      sPointerType = cached;
    }

    return cached;
  }

  /**
   * Address: 0x00703EA0 (FUN_00703EA0, Moho::SimArmy::MemberDeserialize)
   */
  void SimArmy::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    IArmy* const base = this ? static_cast<IArmy*>(this) : nullptr;
    gpg::RType* type = IArmy::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(IArmy));
      IArmy::sType = type;
    }

    gpg::RRef owner{};
    archive->Read(type, base, owner);
  }

  /**
   * Address: 0x00703EF0 (FUN_00703EF0, Moho::SimArmy::MemberSerialize)
   */
  void SimArmy::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    const IArmy* const base = this ? static_cast<const IArmy*>(this) : nullptr;
    gpg::RType* type = IArmy::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(IArmy));
      IArmy::sType = type;
    }

    gpg::RRef owner{};
    archive->Write(type, base, owner);
  }

  IArmy::~IArmy() = default;

  /**
   * Address: 0x006FDAD0 (FUN_006FDAD0, Moho::SimArmy::~SimArmy)
   */
  SimArmy::~SimArmy() = default;
} // namespace moho
