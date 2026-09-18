#include "moho/sim/RRuleGameRulesTypeInfo.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "moho/sim/RRuleGameRules.h"
#include "gpg/core/reflection/StaticInitPhase.h"

namespace
{
  using TypeInfo = moho::RRuleGameRulesTypeInfo;

  alignas(TypeInfo) unsigned char gRRuleGameRulesTypeInfoStorage[sizeof(TypeInfo)];
  bool gRRuleGameRulesTypeInfoConstructed = false;

  [[nodiscard]] TypeInfo& AcquireRRuleGameRulesTypeInfo()
  {
    if (!gRRuleGameRulesTypeInfoConstructed) {
      new (gRRuleGameRulesTypeInfoStorage) TypeInfo();
      gRRuleGameRulesTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gRRuleGameRulesTypeInfoStorage);
  }

  void cleanup_RRuleGameRulesTypeInfo()
  {
    if (!gRRuleGameRulesTypeInfoConstructed) {
      return;
    }

    AcquireRRuleGameRulesTypeInfo().~TypeInfo();
    gRRuleGameRulesTypeInfoConstructed = false;
  }

  struct RRuleGameRulesTypeInfoBootstrap
  {
    RRuleGameRulesTypeInfoBootstrap()
    {
      (void)moho::register_RRuleGameRulesTypeInfoStartup();
    }
  };

  RRuleGameRulesTypeInfoBootstrap gRRuleGameRulesTypeInfoBootstrap;
} // namespace

namespace moho
{
  gpg::RType* RRuleGameRules::sType = nullptr;
  gpg::RType* RRuleGameRules::sType2 = nullptr;

  gpg::RType* RRuleGameRules::StaticGetClass()
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(RRuleGameRules));
    }
    return sType;
  }

  // Address: 0x0052B490 (FUN_0052B490, sub_52B490) -- not a function, and
  // deliberately not recovered here. The four bytes are `8B 40 5C C3`,
  // `mov eax,[eax+0x5Ch]; ret`: the object arrives in EAX, which is no x86
  // calling convention, so this is a basic block lifted out of the middle of
  // some larger routine by the capstone scan that replaced the lost IDA
  // database, not a callable body. It has zero evidence of its own - no code
  // caller, no data or vtable xref, unreachable per the enriched index.
  //
  // The same four bytes appear again at FUN_005281C0, with the same SHA. That
  // is the confirmation rather than a coincidence: /OPT:ICF would have folded
  // two byte-identical COMDATs onto one address, so two addresses means
  // neither is a COMDAT. Both were previously recovered as a named getter
  // (`ReadAuxiliaryRuntimeWord`, over an invented `AuxiliaryWordRuntimeView`);
  // that body has been deleted and both tokens marked skip.
  //
  // The real "read dtrFunc_ back and invoke it" mechanism is recovered and
  // wired in LuaObject.cpp as `type->dtrFunc_(...)`, which compiles to a call
  // through the slot rather than a bare load-and-return.

  /**
   * Address: 0x0052B4A0 (FUN_0052B4A0, Moho::RRuleGameRulesTypeInfo::RRuleGameRulesTypeInfo)
   */
  RRuleGameRulesTypeInfo::RRuleGameRulesTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(RRuleGameRules), this);
  }

  /**
   * Address: 0x0052B530 (FUN_0052B530)
   */
  RRuleGameRulesTypeInfo::~RRuleGameRulesTypeInfo() = default;

  /**
   * Address: 0x0052B520 (FUN_0052B520, Moho::RRuleGameRulesTypeInfo::GetName)
   */
  const char* RRuleGameRulesTypeInfo::GetName() const
  {
    return "RRuleGameRules";
  }

  /**
   * Address: 0x0052B500 (FUN_0052B500, Moho::RRuleGameRulesTypeInfo::Init)
   */
  void RRuleGameRulesTypeInfo::Init()
  {
    size_ = sizeof(RRuleGameRules);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00BC8ED0 (FUN_00BC8ED0, register_RRuleGameRulesTypeInfoStartup)
   */
  int register_RRuleGameRulesTypeInfoStartup()
  {
    (void)AcquireRRuleGameRulesTypeInfo();
    return std::atexit(&cleanup_RRuleGameRulesTypeInfo);
  }
} // namespace moho


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_RRuleGameRulesTypeInfoStartup_ea72de, moho::register_RRuleGameRulesTypeInfoStartup)
