#pragma once
#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/FastVector.h"
#include "lua/LuaObject.h"
#include "moho/sim/SOCellPos.h"
#include "SSTITarget.h"
#include "wm3/Quaternion.h"

namespace moho
{
  class CUnitCommand;
  class CUnitCommandQueue;
  class RUnitBlueprint;

  enum class EUnitCommandType : int32_t
  {
    UNITCOMMAND_None = 0x0,
    UNITCOMMAND_Stop = 0x1,
    UNITCOMMAND_Move = 0x2,
    UNITCOMMAND_Dive = 0x3,
    UNITCOMMAND_FormMove = 0x4,
    UNITCOMMAND_BuildSiloTactical = 0x5,
    UNITCOMMAND_BuildSiloNuke = 0x6,
    UNITCOMMAND_BuildFactory = 0x7,
    UNITCOMMAND_BuildMobile = 0x8,
    UNITCOMMAND_BuildAssist = 0x9,
    UNITCOMMAND_Attack = 0xA,
    UNITCOMMAND_FormAttack = 0xB,
    UNITCOMMAND_Nuke = 0xC,
    UNITCOMMAND_Tactical = 0xD,
    UNITCOMMAND_Teleport = 0xE,
    UNITCOMMAND_Guard = 0xF,
    UNITCOMMAND_Patrol = 0x10,
    UNITCOMMAND_Ferry = 0x11,
    UNITCOMMAND_FormPatrol = 0x12,
    UNITCOMMAND_Reclaim = 0x13,
    UNITCOMMAND_Repair = 0x14,
    UNITCOMMAND_Capture = 0x15,
    UNITCOMMAND_TransportLoadUnits = 0x16,
    UNITCOMMAND_TransportReverseLoadUnits = 0x17,
    UNITCOMMAND_TransportUnloadUnits = 0x18,
    UNITCOMMAND_TransportUnloadSpecificUnits = 0x19,
    UNITCOMMAND_DetachFromTransport = 0x1A,
    UNITCOMMAND_Upgrade = 0x1B,
    UNITCOMMAND_Script = 0x1C,
    UNITCOMMAND_AssistCommander = 0x1D,
    UNITCOMMAND_KillSelf = 0x1E,
    UNITCOMMAND_DestroySelf = 0x1F,
    UNITCOMMAND_Sacrifice = 0x20,
    UNITCOMMAND_Pause = 0x21,
    UNITCOMMAND_OverCharge = 0x22,
    UNITCOMMAND_AggressiveMove = 0x23,
    UNITCOMMAND_FormAggressiveMove = 0x24,
    UNITCOMMAND_AssistMove = 0x25,
    UNITCOMMAND_SpecialAction = 0x26,
    UNITCOMMAND_Dock = 0x27,
  };

  /**
   * Network command-issue payload used by CMarshaller command streams.
   *
   * Recovered wire offsets come from:
   * - FA `CMarshaller::WriteCommandData` (0x006E76C0)
   * - MohoEngine `CMarshaller::WriteCommandData` (0x102C29D0)
   */
  struct SSTICommandIssueData
  {
    int32_t nextCommandId;                   // +0x00
    int32_t unk04;                           // +0x04
    int32_t mIndex;                          // +0x08
    EUnitCommandType mCommandType;           // +0x0C (serialized as 1 byte in marshaller stream)
    SSTITarget mTarget;                      // +0x10
    SSTITarget mTarget2;                     // +0x24
    int32_t unk38;                           // +0x38
    Wm3::Quatf mOri;                         // +0x3C
    float unk4C;                             // +0x4C
    RUnitBlueprint* mBlueprint;              // +0x50
    int32_t unk54;                           // +0x54
    gpg::core::FastVector<SOCellPos> mCells; // +0x58
    int32_t unk64;                           // +0x64
    int32_t unk68;                           // +0x68
    int32_t unk6C;                           // +0x6C
    int32_t unk70;                           // +0x70
    int32_t unk74;                           // +0x74
    LuaPlus::LuaObject mObject;              // +0x78
    lua_State* mLuaState;                    // +0x8C
    CUnitCommand* mUnitCommand;              // +0x90
    CUnitCommandQueue* mCommandQueue;        // +0x94
  };

  static_assert(
    offsetof(SSTICommandIssueData, nextCommandId) == 0x00, "SSTICommandIssueData::nextCommandId offset must be 0x00"
  );
  static_assert(offsetof(SSTICommandIssueData, mIndex) == 0x08, "SSTICommandIssueData::mIndex offset must be 0x08");
  static_assert(
    offsetof(SSTICommandIssueData, mCommandType) == 0x0C, "SSTICommandIssueData::mCommandType offset must be 0x0C"
  );
  static_assert(offsetof(SSTICommandIssueData, mTarget) == 0x10, "SSTICommandIssueData::mTarget offset must be 0x10");
  static_assert(offsetof(SSTICommandIssueData, mTarget2) == 0x24, "SSTICommandIssueData::mTarget2 offset must be 0x24");
  static_assert(offsetof(SSTICommandIssueData, mOri) == 0x3C, "SSTICommandIssueData::mOri offset must be 0x3C");
  static_assert(
    offsetof(SSTICommandIssueData, mBlueprint) == 0x50, "SSTICommandIssueData::mBlueprint offset must be 0x50"
  );
  static_assert(offsetof(SSTICommandIssueData, mCells) == 0x58, "SSTICommandIssueData::mCells offset must be 0x58");
  static_assert(offsetof(SSTICommandIssueData, mObject) == 0x78, "SSTICommandIssueData::mObject offset must be 0x78");
  static_assert(
    offsetof(SSTICommandIssueData, mLuaState) == 0x8C, "SSTICommandIssueData::mLuaState offset must be 0x8C"
  );
  static_assert(
    offsetof(SSTICommandIssueData, mUnitCommand) == 0x90, "SSTICommandIssueData::mUnitCommand offset must be 0x90"
  );
  static_assert(
    offsetof(SSTICommandIssueData, mCommandQueue) == 0x94, "SSTICommandIssueData::mCommandQueue offset must be 0x94"
  );
  static_assert(sizeof(SSTICommandIssueData) == 0x98, "SSTICommandIssueData size must be 0x98");
} // namespace moho
