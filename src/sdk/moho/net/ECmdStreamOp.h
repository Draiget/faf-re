#pragma once

#include <cstdint>

namespace moho
{
  /**
   * Simulation command stream opcodes.
   *
   * Scope:
   * - This enum intentionally covers only the simulation command domain (0..23).
   * - Client/replay control opcodes (50..57) live in EClientMsg.
   * - Lobby and connection lifecycle opcodes (100+ / 200+) live in ELobbyMsg.
   *
   * Binary evidence:
   * - FA 0x006E5A90..0x006E7600 (marshaller writers)
   * - FA 0x0073C660..0x0073D1B0 (CSimDriver ISTIDriver slots)
   */
  enum class ECmdStreamOp : uint8_t
  {
    /**
     * Data payload:
     * - uint32_t - number of beats to advance in simulation
     */
    CMDST_Advance = 0,

    /**
     * Data payload:
     * - uint8_t - command source id
     */
    CMDST_SetCommandSource = 1,

    /**
     * Data payload:
     * - (nothing)
     */
    CMDST_CommandSourceTerminated = 2,

    /**
     * Data payload:
     * - MD5Digest - checksum
     * - uint32_t - beat number
     */
    CMDST_VerifyChecksum = 3,

    /**
     * Data payload:
     * - (nothing)
     */
    CMDST_RequestPause = 4,

    /**
     * Data payload:
     * - (nothing)
     */
    CMDST_Resume = 5,

    /**
     * Data payload:
     * - (nothing)
     */
    CMDST_SingleStep = 6,

    /**
     * Data payload:
     * - uint8_t - army index
     * - string - blueprint id
     * - float - x
     * - float - z
     * - float - heading
     */
    CMDST_CreateUnit = 7,

    /**
     * Data payload:
     * - string - blueprint id
     * - Vec3f - location
     */
    CMDST_CreateProp = 8,

    /**
     * Data payload:
     * - int32_t - entity id
     */
    CMDST_DestroyEntity = 9,

    /**
     * Data payload:
     * - int32_t - entity id
     * - VTransform - new entity transform
     */
    CMDST_WarpEntity = 10,

    /**
     * Data payload:
     * - int32_t - entity id
     * - string - key
     * - string - value
     */
    CMDST_ProcessInfoPair = 11,

    /**
     * Data payload:
     * - uint32_t - number of units
     * - set<int32_t> - unit ids
     * - CmdData - command data
     * - uint8_t - clear queue flag
     */
    CMDST_IssueCommand = 12,

    /**
     * Data payload:
     * - uint32_t - number of factories
     * - set<int32_t> - factory ids
     * - CmdData - command data
     * - uint8_t - clear queue flag
     */
    CMDST_IssueFactoryCommand = 13,

    /**
     * Data payload:
     * - CmdId - command id
     * - int32_t - count delta
     */
    CMDST_IncreaseCommandCount = 14,

    /**
     * Data payload:
     * - CmdId - command id
     * - int32_t - count delta
     */
    CMDST_DecreaseCommandCount = 15,

    /**
     * Data payload:
     * - CmdId - command id
     * - STITarget - target
     */
    CMDST_SetCommandTarget = 16,

    /**
     * Data payload:
     * - CmdId - command id
     * - EUnitCommandType - type
     */
    CMDST_SetCommandType = 17,

    /**
     * Data payload:
     * - CmdId - command id
     * - ListOfCells - list of cells
     * - Vec3f - pos
     */
    CMDST_SetCommandCells = 18,

    /**
     * Data payload:
     * - CmdId - command id
     * - int32_t - unit id
     */
    CMDST_RemoveCommandFromQueue = 19,

    /**
     * Data payload:
     * - string - debug command string
     * - Vec3f - mouse pos
     * - uint8_t - focus army index
     * - set<int32_t> - selected entity ids
     */
    CMDST_DebugCommand = 20,

    /**
     * Data payload:
     * - string - lua string to execute in sim
     */
    CMDST_ExecuteLuaInSim = 21,

    /**
     * Data payload:
     * - string - callback function name
     * - LuaObject - callback args
     */
    CMDST_LuaSimCallback = 22,

    /**
     * Data payload:
     * - (nothing)
     */
    CMDST_EndGame = 23,
  };
} // namespace moho
