#include "moho/unit/core/UserUnitTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/script/CScriptObject.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/UserUnit.h"

// UserUnit registration runs from the earliest C++ initializer segment (binary
// __xc_a) so the descriptor is preregistered before default-segment bootstrap
// objects query UserUnit RTTI during static initialization.
#pragma init_seg(lib)

namespace
{
  // Reflected base sub-object offsets inside the retail `UserUnit` complete
  // object. `UserUnit` is modeled flat in this tree, so the multiple-inheritance
  // sub-object displacements the descriptor publishes are carried here as the
  // binary's own layout constants (FUN_008C6030 / FUN_008C6090).
  constexpr int kUserUnitCScriptObjectBaseOffset = 0x150;
  constexpr int kUserUnitIUnitBaseOffset = 0x148;

  alignas(moho::UserUnitTypeInfo) unsigned char gUserUnitTypeInfoStorage[sizeof(moho::UserUnitTypeInfo)];
  bool gUserUnitTypeInfoConstructed = false;

  [[nodiscard]] moho::UserUnitTypeInfo* AcquireUserUnitTypeInfo()
  {
    if (!gUserUnitTypeInfoConstructed) {
      new (gUserUnitTypeInfoStorage) moho::UserUnitTypeInfo();
      gUserUnitTypeInfoConstructed = true;
    }

    return reinterpret_cast<moho::UserUnitTypeInfo*>(gUserUnitTypeInfoStorage);
  }

  /**
   * Address: 0x00C08780 (FUN_00C08780)
   *
   * What it does:
   * Runs startup-registered teardown for the global `UserUnit` descriptor,
   * releasing its reflected field/base lanes.
   */
  void cleanup_UserUnitTypeInfo()
  {
    if (!gUserUnitTypeInfoConstructed) {
      return;
    }

    AcquireUserUnitTypeInfo()->~UserUnitTypeInfo();
    gUserUnitTypeInfoConstructed = false;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x008BF2D0 (FUN_008BF2D0, construct-and-preregister worker)
   *
   * What it does:
   * Preregisters `UserUnit` RTTI so lookup resolves to this type helper.
   */
  UserUnitTypeInfo::UserUnitTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(UserUnit), this);
  }

  /**
   * Address: 0x008BF370 (FUN_008BF370, scalar deleting thunk)
   */
  UserUnitTypeInfo::~UserUnitTypeInfo() = default;

  /**
   * Address: 0x008BF360 (FUN_008BF360)
   *
   * What it does:
   * Returns the reflection type name literal for UserUnit.
   */
  const char* UserUnitTypeInfo::GetName() const
  {
    return "UserUnit";
  }

  /**
   * Address: 0x008C6030 (FUN_008C6030, Moho::UserUnitTypeInfo::AddBase_CScriptObject)
   *
   * What it does:
   * Resolves (and caches) the `CScriptObject` reflection type, then appends it
   * as a reflected base at the `CScriptObject` sub-object offset.
   */
  void UserUnitTypeInfo::AddBaseCScriptObject()
  {
    if (CScriptObject::sType == nullptr) {
      CScriptObject::sType = gpg::LookupRType(typeid(CScriptObject));
    }

    gpg::RType* const baseType = CScriptObject::sType;
    const gpg::RField base(baseType->GetName(), baseType, kUserUnitCScriptObjectBaseOffset, 0, nullptr);
    AddBase(base);
  }

  /**
   * Address: 0x008C6090 (FUN_008C6090, Moho::UserUnitTypeInfo::AddBase_IUnit)
   *
   * What it does:
   * Resolves (and caches) the `IUnit` reflection type, then appends it as a
   * reflected base at the `IUnit` sub-object offset.
   */
  void UserUnitTypeInfo::AddBaseIUnit()
  {
    if (IUnit::sType == nullptr) {
      IUnit::sType = gpg::LookupRType(typeid(IUnit));
    }

    gpg::RType* const baseType = IUnit::sType;
    const gpg::RField base(baseType->GetName(), baseType, kUserUnitIUnitBaseOffset, 0, nullptr);
    AddBase(base);
  }

  /**
   * Address: 0x008BF330 (FUN_008BF330)
   *
   * What it does:
   * Writes `size_` for UserUnit, registers the `CScriptObject` reflected base,
   * runs base-init, registers the `IUnit` reflected base, then finalizes the
   * descriptor. The base registrations straddle `RType::Init()` exactly as the
   * retail body does.
   */
  void UserUnitTypeInfo::Init()
  {
    size_ = sizeof(UserUnit);
    AddBaseCScriptObject();
    gpg::RType::Init();
    AddBaseIUnit();
    Finish();
  }

  /**
   * Address: 0x00BE8720 (FUN_00BE8720, register_UserUnitTypeInfo)
   *
   * What it does:
   * Registers the `UserUnit` type-info object and installs process-exit cleanup.
   */
  int register_UserUnitTypeInfo()
  {
    (void)AcquireUserUnitTypeInfo();
    return std::atexit(&cleanup_UserUnitTypeInfo);
  }
} // namespace moho

namespace
{
  struct UserUnitTypeInfoRegistration
  {
    UserUnitTypeInfoRegistration()
    {
      (void)moho::register_UserUnitTypeInfo();
    }
  };

  [[maybe_unused]] UserUnitTypeInfoRegistration gUserUnitTypeInfoRegistration;
} // namespace
