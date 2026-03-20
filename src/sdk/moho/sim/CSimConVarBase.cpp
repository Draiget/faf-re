#include "moho/sim/CSimConVarBase.h"

#include "moho/sim/Sim.h"

using namespace moho;

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
int CSimConVarBase::DispatchToSimVar(Sim* sim, int, void* commandArgs, int, int)
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
