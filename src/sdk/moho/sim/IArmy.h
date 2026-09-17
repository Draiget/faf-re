#pragma once

#include <cstddef>
#include <cstdint>

#include "../../gpg/core/utils/BoostWrappers.h"
#include "../../legacy/containers/String.h"
#include "../../legacy/containers/Vector.h"
#include "ArmyUnitSet.h"
#include "ESquadClass.h"
#include "SSTIArmyConstantData.h"
#include "SSTIArmyVariableData.h"
#include "Wm3Vector2.h"
#include "Wm3Vector3.h"

namespace gpg
{
  class RType;
}

namespace moho
{
  class Sim;
  class CInfluenceMap;
  class CAiBrain;
  class CAiReconDBImpl;
  class CSimArmyEconomyInfo;
  class CArmyStats;
  class CPlatoon;
  class CArmyImpl;
  class UserArmy;
  class Unit;
  enum EAlliance : std::int32_t;
  struct ArmyPool;

  /**
   * The army's replicated state: one `SSTIArmyConstantData` and one
   * `SSTIArmyVariableData`, and nothing else.
   *
   * This class is NOT polymorphic. Three independent pieces of binary evidence
   * say so, and the tree had it wrong until 2026-09-17:
   *
   * - Its typeinfo size is 0x1E0 (FUN_00550B20), which is exactly
   *   0x80 + 0x160 -- there is no room for a vfptr.
   * - Every accessor reads its payload at `this + 0`. `IsCivilian`
   *   (0x00707CA0) is `mov al, [eax+0x3C]`, `SetShowScoreFlag` (0x00707C90) is
   *   `mov [eax+0x188], cl`, `IsEnemy` (0x005D5540) reads the enemy set at
   *   `[edx+0x100]`.
   * - `CArmyImpl`'s RTTI base-class array places it at mdisp=8, and every call
   *   site adjusts for that: `CAiAttackerImpl::FindBestEnemy` loads the army
   *   and does `add edx, 8` before `call 0x5D5540` (0x005D7C24).
   *
   * `SimArmy` introduces the vtable. Because `SEconTotals` holds two u64
   * storage lanes this class is 8-byte aligned, so MSVC puts the base after
   * `SimArmy`'s vfptr and four bytes of padding -- at +0x08, matching the BCA.
   *
   * Declaring the army interface's pure virtuals here instead made this class
   * polymorphic, put it at +0x00, and moved every accessor's `this` eight bytes
   * short of the payload. `IsEnemy` then read the tail of `mAllies`, returned
   * false for every real enemy, and `FindBestEnemy` discarded every target --
   * no unit ever auto-acquired, explicit attack orders were dropped on arrival,
   * and structures were never targeted.
   */
  class IArmy
  {
  public:
    static gpg::RType* sType;
    [[nodiscard]] static gpg::RType* StaticGetClass();

    /**
     * Address: 0x006FD520 (FUN_006FD520, Moho::IArmy::IArmy)
     *
     * What it does:
     * Constructs the two replicated payload members in declaration order:
     * `SSTIArmyConstantData` (FUN_006FD330) then `SSTIArmyVariableData`
     * (FUN_006FD390).
     */
    IArmy();

    /**
     * Address: 0x006FD570 (FUN_006FD570, Moho::IArmy::~IArmy)
     *
     * What it does:
     * Destroys `mVarDat` then `mConstDat`. Non-virtual: reached only through
     * `SimArmy`'s destructor (via 0x006FDB00).
     */
    ~IArmy();

    /**
     * Address: 0x005517A0 (FUN_005517A0, Moho::IArmy::MemberDeserialize)
     *
     * What it does:
     * Deserializes the fixed `SSTIArmyConstantData` (+0x00) and
     * `SSTIArmyVariableData` (+0x80) lanes of the IArmy payload.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x00551820 (FUN_00551820, Moho::IArmy::MemberSerialize)
     *
     * What it does:
     * Serializes the fixed `SSTIArmyConstantData` (+0x00) and
     * `SSTIArmyVariableData` (+0x80) lanes of the IArmy payload.
     */
    void MemberSerialize(gpg::WriteArchive* archive);

    /**
     * Address: 0x00579430 (FUN_00579430, Moho::IArmy::GetAllianceWith)
     *
     * What it does:
     * Resolves alliance relation against `other` using the neutral/ally/enemy
     * relation bitsets, defaulting to neutral.
     */
    [[nodiscard]] EAlliance GetAllianceWith(const IArmy* other) const;

    /**
     * Address: 0x005D5540 (FUN_005D5540, Moho::IArmy::IsEnemy)
     *
     * What it does:
     * Returns whether `armyIndex` is present in the enemy relation bitset.
     */
    [[nodiscard]] bool IsEnemy(std::uint32_t armyIndex) const;

    /**
     * Address: 0x00707C40 (FUN_00707C40)
     *
     * What it does:
     * Writes one player-color BGRA value into the variable-data payload.
     */
    void SetPlayerColorBgra(std::uint32_t playerColorBgra);

    /**
     * Address: 0x00707C50 (FUN_00707C50)
     *
     * What it does:
     * Writes one army-color BGRA value into the variable-data payload.
     */
    void SetArmyColorBgra(std::uint32_t armyColorBgra);

    /**
     * Address: 0x00707C60 (FUN_00707C60)
     *
     * What it does:
     * Writes one faction index into the variable-data payload.
     */
    void SetFactionIndex(std::int32_t factionIndex);

    /**
     * Address: 0x00707C90 (FUN_00707C90)
     *
     * What it does:
     * Sets the variable-data show-score flag.
     */
    void SetShowScoreFlag(bool enabled);

    /**
     * Address: 0x00707CA0 (FUN_00707CA0)
     *
     * What it does:
     * Returns the constant-data civilian flag.
     */
    [[nodiscard]] bool IsCivilian() const;

    /**
     * Address: 0x00707CB0 (FUN_00707CB0)
     *
     * What it does:
     * Returns the variable-data out-of-game flag.
     */
    [[nodiscard]] bool IsOutOfGame() const;

    /**
     * Address: 0x00707CD0 (FUN_00707CD0)
     *
     * What it does:
     * Returns handicap scalar when handicap is enabled, otherwise `0.0f`.
     */
    [[nodiscard]] float GetHandicap() const;

  public:
    SSTIArmyConstantData mConstDat; // +0x000
    SSTIArmyVariableData mVarDat;   // +0x080
  };

  static_assert(offsetof(IArmy, mConstDat) == 0x000, "IArmy::mConstDat offset must be 0x000");
  static_assert(offsetof(IArmy, mVarDat) == 0x080, "IArmy::mVarDat offset must be 0x080");
  static_assert(sizeof(IArmy) == 0x1E0, "IArmy size must be 0x1E0");
  static_assert(alignof(IArmy) == 8, "IArmy must be 8-byte aligned so SimArmy places it at +0x08");

} // namespace moho
