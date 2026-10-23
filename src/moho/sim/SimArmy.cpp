#include "SimArmy.h"

#include <cstddef>
#include <new>
#include <typeinfo>

#include "gpg/core/reflection/Reflection.h"
#include "moho/sim/SSTIArmyConstantData.h"

namespace moho
{
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
   * Constructs the two replicated payload members, constant data then
   * variable data.
   */
  IArmy::IArmy()
    : mConstDat()
    , mVarDat()
  {}

  gpg::RType* SimArmy::StaticGetClass()
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(SimArmy));
    }
    return sType;
  }

  /**
   * Address: 0x006FDAB0 (FUN_006FDAB0, Moho::SimArmy::SimArmy)
   *
   * What it does:
   * Constructs the +0x08 `IArmy` base subobject and installs the
   * `SimArmy` vtable on the complete object.
   */
  SimArmy::SimArmy() = default;

  /**
   * Address: 0x0074E550 (FUN_0074E550, Moho::SimArmy::GetPointerType)
   *
   * What it does:
   * Lazily resolves and caches the reflected pointer type for `SimArmy*` by
   * driving the startup registrar `preregister_SimArmyPointerTypeStartup`
   * (FUN_0074FE70), falling back to a plain `LookupRType` when the descriptor
   * is not yet registered.
   */
  gpg::RType* SimArmy::GetPointerType()
  {
    (void)StaticGetClass();

    gpg::RType* cached = sPointerType;
    if (!cached) {
      cached = gpg::preregister_SimArmyPointerTypeStartup();
      if (!cached) {
        cached = gpg::LookupRType(typeid(SimArmy*));
      }
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

  /**
   * Address: 0x006FD570 (FUN_006FD570, Moho::IArmy::~IArmy)
   */
  IArmy::~IArmy() = default;

  /**
   * Address: 0x006FDAD0 (FUN_006FDAD0, Moho::SimArmy::~SimArmy)
   */
  SimArmy::~SimArmy() = default;
} // namespace moho

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<SimArmy>`, vtable 0x00E2FAC4.
   *
   * Address: 0x00BD9BC0 (FUN_00BD9BC0 -- constructs the global and registers its destructor.)
   * Address: 0x00BFF380 (FUN_00BFF380 -- the global's destructor.)
   * Address: 0x00701610 (FUN_00701610 -- `Init`.)
   * Address: 0x006FDB60 (FUN_006FDB60 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x006FDB70 (FUN_006FDB70 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct SimArmySerializer : gpg::SerSaveLoadHelper<SimArmy>
  {};
} // namespace moho

namespace
{
  // Address: 0x010B8A48 -- process-global `SimArmySerializer` singleton.
  moho::SimArmySerializer gSimArmySerializer;
} // namespace
