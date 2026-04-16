// Reconstructed from FA binary evidence (vtable + callsites + decomp).
#pragma once

#include <cstdint>

#include "gpg/core/containers/FastVector.h"
#include "gpg/core/containers/String.h"
#include "moho/containers/SCoordsVec2.h"

namespace LuaPlus
{
  class LuaState;
}

namespace moho
{
  class CAiFormationInstance;
  class Unit;

  /**
   * Formation script bucket type used by `/lua/formations.lua`.
   * Evidence: `FUN_00575A30`, `FUN_00575BD0`, `FUN_00575DB0`.
   */
  enum class EFormationType : std::int32_t
  {
    Surface = 0,
    Air = 1,
    Mixed = 2,
  };

  /**
   * 32-bit intrusive weak-unit slot word used by the formation creation path.
   *
   * Evidence:
   * - `FUN_0059C120` walks source entries as 4-byte words and re-links through
   *   owner-chain slot heads before passing a temporary linked view to
   *   `CFormationInstance` ctor (`FUN_005694B0`).
   */
  struct SFormationUnitWeakRef
  {
    std::uint32_t ownerLinkSlotWord;

    [[nodiscard]] static SFormationUnitWeakRef FromUnit(Unit* unit) noexcept;
    [[nodiscard]] std::uint32_t* DecodeOwnerChainHead() const noexcept;
  };
  using SFormationUnitWeakRefSet = gpg::fastvector_n<SFormationUnitWeakRef, 10>;
  static_assert(sizeof(SFormationUnitWeakRef) == 0x04, "SFormationUnitWeakRef size must be 0x04");
  static_assert(sizeof(SFormationUnitWeakRefSet) == 0x38, "SFormationUnitWeakRefSet size must be 0x38");

  /**
   * Address: 0x00575A30 (FUN_00575A30, ?FORMATION_GetNumScripts@Moho@@YAIPAVLuaState@LuaPlus@@W4EFormationType@1@@Z)
   *
   * What it does:
   * Loads `/lua/formations.lua`, resolves a formation bucket table, and returns
   * the number of scripts in that bucket.
   */
  unsigned int FORMATION_GetNumScripts(LuaPlus::LuaState* state, EFormationType formationType);

  /**
   * Address: 0x00575BD0 (FUN_00575BD0, ?FORMATION_GetScriptName@Moho@@YAPBDPAVLuaState@LuaPlus@@HW4EFormationType@1@@Z)
   *
   * What it does:
   * Loads `/lua/formations.lua`, resolves a formation bucket table, and returns
   * one script-name string for the requested index.
   */
  const char* FORMATION_GetScriptName(LuaPlus::LuaState* state, int scriptIndex, EFormationType formationType);

  /**
   * Address: 0x00575DB0 (FUN_00575DB0, ?FORMATION_GetScriptIndex@Moho@@YAHPAVLuaState@LuaPlus@@VStrArg@gpg@@W4EFormationType@1@@Z)
   *
   * What it does:
   * Loads `/lua/formations.lua`, resolves a formation bucket table, and returns
   * the zero-based index for one script name (`-1` when missing).
   */
  int FORMATION_GetScriptIndex(LuaPlus::LuaState* state, gpg::StrArg scriptName, EFormationType formationType);

  /**
   * Address: 0x00576350 (FUN_00576350, ?FORMATION_PickBestFormation@Moho@@YAHPAVLuaState@LuaPlus@@W4EFormationType@1@M@Z)
   *
   * What it does:
   * Calls `/lua/formations.lua` helper `PickBestFinalFormationIndex` and returns
   * the selected formation index.
   */
  int FORMATION_PickBestFormation(LuaPlus::LuaState* state, EFormationType formationType, float radius);

  /**
   * VFTABLE: 0x00E1B45C
   * COL:  0x00E70BD8
   */
  class IAiFormationDB
  {
  public:
    /**
     * Address: 0x0059C360 (FUN_0059C360)
     *
     * What it does:
     * Initializes one IAiFormationDB interface subobject vtable lane.
     */
    IAiFormationDB();

    /**
     * Address: 0x0059A3D0 (FUN_0059A3D0)
     *
     * What it does:
     * Base deleting-destructor thunk for formation DB interface.
     */
    virtual ~IAiFormationDB();

    /**
     * Address: 0x0059C0C0 (FUN_0059C0C0)
     * Mangled: ?GetScriptName@CAiFormationDBImpl@Moho@@UAEPBDHW4EFormationType@2@@Z
     *
     * What it does:
     * Returns the script-name string for a formation script index/type.
     */
    virtual const char* GetScriptName(int scriptIndex, EFormationType formationType) = 0;

    /**
     * Address: 0x0059C0F0 (FUN_0059C0F0)
     * Mangled: ?GetScriptIndex@CAiFormationDBImpl@Moho@@UAEHPBDW4EFormationType@2@@Z
     *
     * What it does:
     * Resolves a formation script name into its zero-based index.
     */
    virtual int GetScriptIndex(gpg::StrArg scriptName, EFormationType formationType) = 0;

    /**
     * Address: 0x0059C060 (FUN_0059C060)
     * Mangled: ?RemoveFormation@CAiFormationDBImpl@Moho@@UAEXPAVCAiFormationInstance@2@@Z
     *
     * What it does:
     * Removes one formation-instance pointer from the DB storage.
     */
    virtual void RemoveFormation(CAiFormationInstance* formation) = 0;

    /**
     * Address: 0x0059C030 (FUN_0059C030)
     * Mangled: ?Update@CAiFormationDBImpl@Moho@@UAEXXZ
     *
     * What it does:
     * Advances all live formation instances for the current sim tick.
     */
    virtual void Update() = 0;

    /**
     * Address: 0x0059C120 (FUN_0059C120)
     *
     * What it does:
     * Builds a temporary linked weak-unit view, constructs a new formation
     * instance, then appends it to this DB.
     */
    virtual CAiFormationInstance* NewFormation(
      const SFormationUnitWeakRefSet* unitWeakSet,
      const char* scriptName,
      const SCoordsVec2* formationCenter,
      float orientX,
      float orientY,
      float orientZ,
      float orientW,
      int commandType
    ) = 0;
  };

  static_assert(sizeof(IAiFormationDB) == 0x04, "IAiFormationDB size must be 0x04");
} // namespace moho
