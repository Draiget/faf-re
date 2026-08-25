#include "moho/command/EUnitCommandTypeTypeInfo.h"

#include <cstdlib>
#include <typeinfo>

#include "gpg/core/reflection/StaticInitPhase.h"
#include "gpg/core/reflection/StaticTypeInfoStorage.h"

namespace
{
  gpg::StaticTypeInfoStorage<moho::EUnitCommandTypeTypeInfo> gEUnitCommandTypeTypeInfoStorage{};

  /**
   * Address: 0x00BF4950 (FUN_00BF4950, cleanup_EUnitCommandTypeTypeInfo)
   *
   * What it does:
   * Process-exit teardown for the `EUnitCommandTypeTypeInfo` descriptor.
   * The real ctor's atexit push at 0x00BC9C20 targets a plain destructor
   * call, not a mangled symbol.
   */
  void cleanup_EUnitCommandTypeTypeInfo()
  {
    gEUnitCommandTypeTypeInfoStorage.Destroy();
  }

  // Address: 0x010AC568 -- process-global `EUnitCommandTypeTypeInfo` singleton
  // storage (constructed in place by `register_EUnitCommandTypeTypeInfo`).

  /**
   * Address: 0x00553540 (FUN_00553540, Deserialize_EUnitCommandType_Primitive)
   * Address: 0x00553560 (FUN_00553560, Serialize_EUnitCommandType_Primitive)
   * Address: 0x00BC9C40 (FUN_00BC9C40, dynamic initializer for the global
   * `PrimitiveSerHelper<EUnitCommandType,int>` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields (vtable slot 0 `Init()` dispatched later by
   * `gpg::SerHelperBase::InitNewHelpers`). This is an independent `__xc_a`
   * static initializer, separate from `EUnitCommandTypeTypeInfo`'s own
   * initializer above -- the prior recovery wrongly coupled both into one
   * shared bootstrap struct.
   */
  moho::EUnitCommandTypePrimitiveSerializer gEUnitCommandTypePrimitiveSerializer;
} // namespace

namespace moho
{
  /**
   * Address: 0x005520B0 (FUN_005520B0, Moho::EUnitCommandTypeTypeInfo::EUnitCommandTypeTypeInfo)
   *
   * What it does:
   * Preregisters the enum type descriptor for `EUnitCommandType` with the reflection registry.
   */
  EUnitCommandTypeTypeInfo::EUnitCommandTypeTypeInfo()
    : gpg::REnumType()
  {
    gpg::PreRegisterRType(typeid(EUnitCommandType), this);
  }

  /**
   * Address: 0x00552140 (FUN_00552140, Moho::EUnitCommandTypeTypeInfo::dtr)
   */
  EUnitCommandTypeTypeInfo::~EUnitCommandTypeTypeInfo() = default;

  /**
   * Address: 0x00552130 (FUN_00552130, Moho::EUnitCommandTypeTypeInfo::GetName)
   */
  const char* EUnitCommandTypeTypeInfo::GetName() const
  {
    return "EUnitCommandType";
  }

  /**
   * Address: 0x00552110 (FUN_00552110, Moho::EUnitCommandTypeTypeInfo::Init)
   */
  void EUnitCommandTypeTypeInfo::Init()
  {
    size_ = sizeof(EUnitCommandType);
    gpg::RType::Init();
    AddEnums();
    Finish();
  }

  /**
   * Address: 0x00552170 (FUN_00552170, Moho::EUnitCommandTypeTypeInfo::AddEnums)
   */
  void EUnitCommandTypeTypeInfo::AddEnums()
  {
    mPrefix = "UNITCOMMAND_";
    AddEnum(StripPrefix("UNITCOMMAND_None"), 0);
    AddEnum(StripPrefix("UNITCOMMAND_Stop"), 1);
    AddEnum(StripPrefix("UNITCOMMAND_Move"), 2);
    AddEnum(StripPrefix("UNITCOMMAND_Dive"), 3);
    AddEnum(StripPrefix("UNITCOMMAND_FormMove"), 4);
    AddEnum(StripPrefix("UNITCOMMAND_BuildSiloTactical"), 5);
    AddEnum(StripPrefix("UNITCOMMAND_BuildSiloNuke"), 6);
    AddEnum(StripPrefix("UNITCOMMAND_BuildFactory"), 7);
    AddEnum(StripPrefix("UNITCOMMAND_BuildMobile"), 8);
    AddEnum(StripPrefix("UNITCOMMAND_BuildAssist"), 9);
    AddEnum(StripPrefix("UNITCOMMAND_Attack"), 10);
    AddEnum(StripPrefix("UNITCOMMAND_FormAttack"), 11);
    AddEnum(StripPrefix("UNITCOMMAND_Nuke"), 12);
    AddEnum(StripPrefix("UNITCOMMAND_Tactical"), 13);
    AddEnum(StripPrefix("UNITCOMMAND_Teleport"), 14);
    AddEnum(StripPrefix("UNITCOMMAND_Guard"), 15);
    AddEnum(StripPrefix("UNITCOMMAND_Patrol"), 16);
    AddEnum(StripPrefix("UNITCOMMAND_Ferry"), 17);
    AddEnum(StripPrefix("UNITCOMMAND_FormPatrol"), 18);
    AddEnum(StripPrefix("UNITCOMMAND_Reclaim"), 19);
    AddEnum(StripPrefix("UNITCOMMAND_Repair"), 20);
    AddEnum(StripPrefix("UNITCOMMAND_Capture"), 21);
    AddEnum(StripPrefix("UNITCOMMAND_TransportLoadUnits"), 22);
    AddEnum(StripPrefix("UNITCOMMAND_TransportReverseLoadUnits"), 23);
    AddEnum(StripPrefix("UNITCOMMAND_TransportUnloadUnits"), 24);
    AddEnum(StripPrefix("UNITCOMMAND_TransportUnloadSpecificUnits"), 25);
    AddEnum(StripPrefix("UNITCOMMAND_DetachFromTransport"), 26);
    AddEnum(StripPrefix("UNITCOMMAND_Upgrade"), 27);
    AddEnum(StripPrefix("UNITCOMMAND_Script"), 28);
    AddEnum(StripPrefix("UNITCOMMAND_AssistCommander"), 29);
    AddEnum(StripPrefix("UNITCOMMAND_KillSelf"), 30);
    AddEnum(StripPrefix("UNITCOMMAND_DestroySelf"), 31);
    AddEnum(StripPrefix("UNITCOMMAND_Sacrifice"), 32);
    AddEnum(StripPrefix("UNITCOMMAND_Pause"), 33);
    AddEnum(StripPrefix("UNITCOMMAND_OverCharge"), 34);
    AddEnum(StripPrefix("UNITCOMMAND_AggressiveMove"), 35);
    AddEnum(StripPrefix("UNITCOMMAND_FormAggressiveMove"), 36);
    AddEnum(StripPrefix("UNITCOMMAND_AssistMove"), 37);
    AddEnum(StripPrefix("UNITCOMMAND_SpecialAction"), 38);
    AddEnum(StripPrefix("UNITCOMMAND_Dock"), 39);
  }

  /**
   * Address: 0x00BC9C20 (FUN_00BC9C20, sub_BC9C20)
   *
   * What it does:
   * Constructs the static `EUnitCommandTypeTypeInfo` descriptor in place and
   * installs its atexit teardown.
   */
  int register_EUnitCommandTypeTypeInfo()
  {
    (void)gEUnitCommandTypeTypeInfoStorage.Ensure();
    return std::atexit(&cleanup_EUnitCommandTypeTypeInfo);
  }
} // namespace moho

// Phase-1 pre-registration: run this descriptor registration ahead of every
// consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_EUnitCommandTypeTypeInfo_14a04b, moho::register_EUnitCommandTypeTypeInfo)
