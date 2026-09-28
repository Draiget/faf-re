#pragma once

#include <cstdint>

#include "legacy/containers/String.h"
#include "moho/sim/CSimConVarBase.h"

namespace moho
{
  // Sim console variables read outside the console. Each is a global
  // defined in SimDebugCommandRegistrations.cpp next to its `DoSimCommand`
  // alias; readers hand its address to `Sim::GetSimVar`.
  extern TSimConVar<bool> gSimConVar_NoDamage;
  extern TSimConVar<bool> gSimConVar_AI_RunOpponentAI;
  extern TSimConVar<bool> gSimConVar_AI_DebugCollision;
  extern TSimConVar<bool> gSimConVar_ai_InstaBuild;
  extern TSimConVar<float> gSimConVar_ai_SteeringAirTolerance;
  extern TSimConVar<float> gSimConVar_NeedRefuelThresholdRatio;
  extern TSimConVar<float> gSimConVar_NeedRepairThresholdRatio;
  extern TSimConVar<bool> gSimConVar_path_BackgroundUpdate;
  extern TSimConVar<int> gSimConVar_path_BackgroundBudget;
  extern TSimConVar<int> gSimConVar_path_TimeoutPreview;
  extern TSimConVar<int> gSimConVar_sim_ChecksumPeriod;
  extern TSimConVar<std::uint8_t> gSimConVar_sim_TestVarUByte;
  extern TSimConVar<msvc8::string> gSimConVar_sim_TestVarStr;
} // namespace moho
