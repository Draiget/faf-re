#include "moho/sim/CSimConVarBase.h"

#include <cstdint>

#include "moho/sim/Sim.h"

using namespace moho;

namespace
{
  std::uint32_t gSimConVarIndexCounter = 0u;
}

CSimConVarBase::CSimConVarBase(const bool requiresCheat, const char* const name)
  : CSimConCommand(requiresCheat, name)
  , mIndex(0u)
{
}

/**
 * Address: 0x00734820 (FUN_00734820, sub_734820)
 *
 * IDA signature:
 * int __thiscall sub_734820(Moho::CSimConVarBase *this, Moho::Sim *arg0, int a3, int a4, int a5, int a6);
 *
 * What it does:
 * Resolves this convar's per-Sim instance and forwards command args to the
 * instance handler virtual (slot +0x04).
 */
int CSimConVarBase::Run(
  Sim* const sim,
  ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f*,
  CArmyImpl*,
  SEntitySetTemplateUnit*
)
{
  CSimConVarInstanceBase* const simVar = sim->GetSimVar(this);
  return simVar->HandleConsoleCommand(commandArgs);
}

/**
 * Address: 0x00579790 (FUN_00579790, sub_579790)
 *
 * What it does:
 * Identity helper virtual; returns `this`.
 */
CSimConVarBase* CSimConVarBase::Identity()
{
  return this;
}

/**
 * Address: 0x0057DED0 (FUN_0057DED0, Moho::TSimConVar_bool::NewInstance)
 *
 * What it does:
 * Allocates one bool sim-convar instance, copies convar name/default value,
 * and returns it as `CSimConVarInstanceBase`.
 */
template <>
CSimConVarInstanceBase* moho::TSimConVar<bool>::CreateInstance()
{
  auto* const instance = new TSimConVarInstance<bool>();
  if (!instance) {
    return nullptr;
  }

  instance->mName = mName;
  instance->mValue = mDefaultValue;
  return instance;
}

/**
 * Address: 0x005D3CE0 (FUN_005D3CE0, Moho::TSimConVar_float::NewInstance)
 *
 * What it does:
 * Allocates one float sim-convar instance, copies convar name/default value,
 * and returns it as `CSimConVarInstanceBase`.
 */
template <>
CSimConVarInstanceBase* moho::TSimConVar<float>::CreateInstance()
{
  auto* const instance = new TSimConVarInstance<float>();
  if (!instance) {
    return nullptr;
  }

  instance->mName = mName;
  instance->mValue = mDefaultValue;
  return instance;
}

std::uint32_t CSimConVarBase::AllocateSimConVarIndex() noexcept
{
  return gSimConVarIndexCounter++;
}
