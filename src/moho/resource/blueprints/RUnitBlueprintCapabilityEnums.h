#pragma once

#include <cstdint>

namespace moho
{
  enum ERuleBPUnitCommandCaps : std::int32_t
  {
    RULEUCC_None = 0,
    RULEUCC_Move = 1,
    RULEUCC_Stop = 2,
    RULEUCC_Attack = 4,
    RULEUCC_Guard = 8,
    RULEUCC_Patrol = 16,
    RULEUCC_RetaliateToggle = 32,
    RULEUCC_Repair = 64,
    RULEUCC_Capture = 128,
    RULEUCC_Transport = 256,
    RULEUCC_CallTransport = 512,
    RULEUCC_Nuke = 1024,
    RULEUCC_Tactical = 2048,
    RULEUCC_Teleport = 4096,
    RULEUCC_Ferry = 0x2000,
    RULEUCC_SiloBuildTactical = 0x4000,
    RULEUCC_SiloBuildNuke = 0x8000,
    RULEUCC_Sacrifice = 0x10000,
    RULEUCC_Pause = 0x20000,
    RULEUCC_Overcharge = 0x40000,
    RULEUCC_Dive = 0x80000,
    RULEUCC_Reclaim = 0x100000,
    RULEUCC_SpecialAction = 0x200000,
    RULEUCC_Dock = 0x400000,
    RULEUCC_Script = 0x800000,
    RULEUCC_Invalid = 0x1000000,
  };

  enum ERuleBPUnitToggleCaps : std::int32_t
  {
    RULEUTC_ShieldToggle = 1,
    RULEUTC_WeaponToggle = 2,
    RULEUTC_JammingToggle = 4,
    RULEUTC_IntelToggle = 8,
    RULEUTC_ProductionToggle = 16,
    RULEUTC_StealthToggle = 32,
    RULEUTC_GenericToggle = 64,
    RULEUTC_SpecialToggle = 128,
    RULEUTC_CloakToggle = 256,
  };

  static_assert(sizeof(ERuleBPUnitCommandCaps) == 0x4, "ERuleBPUnitCommandCaps size must be 0x4");
  static_assert(sizeof(ERuleBPUnitToggleCaps) == 0x4, "ERuleBPUnitToggleCaps size must be 0x4");
  static_assert(RULEUCC_None == 0, "RULEUCC_None value must be 0");
  static_assert(RULEUCC_Move == 1, "RULEUCC_Move value must be 1");
  static_assert(RULEUCC_CallTransport == 0x200, "RULEUCC_CallTransport value must be 0x200");
  static_assert(RULEUCC_Invalid == 0x1000000, "RULEUCC_Invalid value must be 0x1000000");
  static_assert(RULEUTC_ShieldToggle == 1, "RULEUTC_ShieldToggle value must be 1");
  static_assert(RULEUTC_WeaponToggle == 2, "RULEUTC_WeaponToggle value must be 2");
  static_assert(RULEUTC_SpecialToggle == 128, "RULEUTC_SpecialToggle value must be 128");
  static_assert(RULEUTC_CloakToggle == 256, "RULEUTC_CloakToggle value must be 256");
} // namespace moho
