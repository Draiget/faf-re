#include "moho/ai/EFormationdStatusTypeInfo.h"

#include <cstdlib>
#include <cstdint>
#include <new>
#include <typeinfo>

#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  /**
   * Address: 0x00BF57F0 (FUN_00BF57F0, atexit destructor of the EFormationdStatusTypeInfo object)
   */
  [[nodiscard]] moho::EFormationdStatusTypeInfo& AcquireEFormationdStatusTypeInfo()
  {
    static moho::EFormationdStatusTypeInfo sInstance;
    return sInstance;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00BCAA80 (FUN_00BCAA80, sub_BCAA80)
   *
   * IDA signature:
   * int sub_BCAA80();
   *
   * What it does:
   * Constructs the process-wide `EFormationdStatusTypeInfo` singleton, whose
   * constructor pre-registers `typeid(EFormationdStatus)`. CRT dynamic
   * initializer #1447 in the shipped binary:
   *
   *     sub_566090();                 // the descriptor's constructor
   *     return atexit(sub_BF57F0);    // the compiler's destructor registration
   *
   * Nothing constructed the descriptor before this was recovered, so
   * `LookupRType(typeid(EFormationdStatus))` threw during REF_RegisterAllTypes.
   */
  void register_EFormationdStatusTypeInfo()
  {
    (void)AcquireEFormationdStatusTypeInfo();
  }

  /**
   * Address: 0x00566090 (FUN_00566090, Moho::EFormationdStatusTypeInfo::EFormationdStatusTypeInfo)
   *
   * What it does:
   * Preregisters the enum type descriptor for `EFormationdStatus` with the reflection registry.
   */
  EFormationdStatusTypeInfo::EFormationdStatusTypeInfo()
    : gpg::REnumType()
  {
    gpg::PreRegisterRType(typeid(EFormationdStatus), this);
  }

  /**
   * Address: 0x00566150 (FUN_00566150, Moho::EFormationdStatusTypeInfo::dtr)
   */
  EFormationdStatusTypeInfo::~EFormationdStatusTypeInfo() = default;

  /**
   * Address: 0x00566140 (FUN_00566140, Moho::EFormationdStatusTypeInfo::GetName)
   */
  const char* EFormationdStatusTypeInfo::GetName() const
  {
    return "EFormationdStatus";
  }

  /**
   * Address: 0x005660F0 (FUN_005660F0, Moho::EFormationdStatusTypeInfo::Init)
   */
  void EFormationdStatusTypeInfo::Init()
  {
    size_ = sizeof(EFormationdStatus);
    gpg::RType::Init();
    AddEnums();
    Finish();
  }

  /**
   * Address: 0x00566180 (FUN_00566180, Moho::EFormationdStatusTypeInfo::AddEnums)
   */
  void EFormationdStatusTypeInfo::AddEnums()
  {
    mPrefix = "FORMATIONSTATUS_";

    AddEnum(StripPrefix("FORMATIONSTATUS_FormationUpdated"), static_cast<std::int32_t>(FORMATIONSTATUS_FormationUpdated));
    AddEnum(StripPrefix("FORMATIONSTATUS_FormationAtGoal"), static_cast<std::int32_t>(FORMATIONSTATUS_FormationAtGoal));
  }
} // namespace moho

// Phase-1 pre-registration: run this descriptor registration ahead of every
// consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_EFormationdStatusTypeInfo, moho::register_EFormationdStatusTypeInfo)
