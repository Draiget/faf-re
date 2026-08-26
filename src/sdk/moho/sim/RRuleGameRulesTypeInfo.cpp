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

  // Address: 0x0052B490 (FUN_0052B490, sub_52B490) -- tiny 2-instruction
  // `mov eax,[ecx+0x5Ch]; retn` accessor. Byte-identical to (ICF twin of)
  // FUN_005281C0 (`gpg::RType::dtr_func_t`'s own offset, +0x5C, happens to
  // match this canonical twin's unrelated field): the canonical body is
  // already recovered as `ReadAuxiliaryRuntimeWord` in
  // `src/sdk/lua/LuaObject.cpp` (`AuxiliaryWordRuntimeView::mAuxiliaryWord`,
  // a Lua userdata runtime lane, not `gpg::RType::dtrFunc_`). This address
  // has zero callsite evidence of its own anywhere in the binary (no code
  // caller, no data/vtable xref, unreachable per the enriched callgraph
  // index) -- the real "read dtrFunc_ back and invoke it" mechanism is
  // already recovered and wired at `LuaObject.cpp:16870`
  // (`type->dtrFunc_(...)`), which compiles to a different instruction
  // shape (a call through the slot, not a bare load-and-return). No
  // registration or dispatch site anywhere in `src/sdk/**` needs a
  // dedicated named getter for `dtrFunc_` -- so this address intentionally
  // has no dedicated recovered function here.

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
