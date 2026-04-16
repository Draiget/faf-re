#include "moho/command/SSTICommandIssueData.h"

#include "lua/LuaObject.h"
#include "moho/ai/EAiTargetType.h"
#include "moho/command/SSTITarget.h"
#include "moho/sim/SOCellPos.h"
#include "Wm3Quaternion.h"
#include "Wm3Vector3.h"

namespace
{
  /**
   * Address: 0x00552C90 (FUN_00552C90, gpg::fastvector_SOCellPos::cpy)
   *
   * What it does:
   * Rebinds one `FastVectorN<SOCellPos, 2>` destination lane to inline storage,
   * then copies source payload/storage into the destination using the legacy
   * runtime-view copy helper path.
   */
  [[nodiscard]] gpg::fastvector_n<moho::SOCellPos, 2>& CopySOCellPosFastVectorN2(
    gpg::fastvector_n<moho::SOCellPos, 2>& destination,
    const gpg::fastvector_n<moho::SOCellPos, 2>& source
  )
  {
    (void)gpg::FastVectorN2RebindAndCopy(&destination, &source);
    return destination;
  }

  /**
   * Address: 0x00579370 (FUN_00579370)
   *
   * What it does:
   * Initializes one ground-position target lane from world coordinates, setting
   * target kind to `AITARGET_Ground` and entity-id sentinel to `0xF0000000`.
   */
  [[maybe_unused]] [[nodiscard]] moho::SSTITarget* InitializeGroundTargetFromWorldPos(
    moho::SSTITarget* const outTarget,
    const Wm3::Vec3f* const worldPos
  ) noexcept
  {
    outTarget->mType = moho::EAiTargetType::AITARGET_Ground;
    outTarget->mEntityId = 0xF0000000u;
    outTarget->mPos = *worldPos;
    return outTarget;
  }

  /**
   * Address: 0x00579390 (FUN_00579390)
   *
   * What it does:
   * Stores one source target lane into `SSTICommandIssueData::mTarget2`.
   */
  [[maybe_unused]] [[nodiscard]] moho::SSTICommandIssueData* AssignSecondaryTargetLane(
    moho::SSTICommandIssueData* const outIssueData,
    const moho::SSTITarget* const sourceTarget
  ) noexcept
  {
    outIssueData->mTarget2 = *sourceTarget;
    return outIssueData;
  }

  /**
   * Address: 0x005793D0 (FUN_005793D0)
   *
   * What it does:
   * Stores one blueprint pointer lane into `SSTICommandIssueData::mBlueprint`.
   */
  [[maybe_unused]] [[nodiscard]] moho::SSTICommandIssueData* AssignBlueprintLane(
    moho::SSTICommandIssueData* const outIssueData,
    moho::RUnitBlueprint* const blueprint
  ) noexcept
  {
    outIssueData->mBlueprint = blueprint;
    return outIssueData;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00552550 (FUN_00552550, ??0SSTICommandIssueData@Moho@@QAE@W4EUnitCommandType@1@@Z)
   *
   * IDA signature:
   * Moho::SSTICommandIssueData *__thiscall Moho::SSTICommandIssueData::SSTICommandIssueData(
   *   Moho::EUnitCommandType val, Moho::SSTICommandIssueData *this);
   *
   * What it does:
   * Default-initializes the command-issue payload for a given command
   * type. The three id/index lanes (`nextCommandId`, `unk04`, `mIndex`)
   * are all seeded to `-1`; both `SSTITarget` lanes are cleared to
   * `AITARGET_None` with a sentinel entity id of `0xF0000000` and a
   * zero world position; the tail orientation quaternion is set to the
   * identity `(w=1, x=0, y=0, z=0)` and the trailing `unk4C` float is
   * primed to `1.0f`; the blueprint pointer is nulled; the inline cell
   * vector is parked in its two-element inline buffer; `unk70` and
   * `unk74` are both written to `1`; and the embedded
   * `LuaPlus::LuaObject` is default-constructed.
   */
  SSTICommandIssueData::SSTICommandIssueData(const EUnitCommandType commandType)
    : nextCommandId(-1)
    , unk04(-1)
    , mIndex(-1)
    , mCommandType(commandType)
    , mTarget{EAiTargetType::AITARGET_None, 0xF0000000u, Wm3::Vec3f{0.0f, 0.0f, 0.0f}}
    , mTarget2{EAiTargetType::AITARGET_None, 0xF0000000u, Wm3::Vec3f{0.0f, 0.0f, 0.0f}}
    , unk38(-1)
    , mOri(1.0f, 0.0f, 0.0f, 0.0f)
    , unk4C(1.0f)
    , mBlueprint(nullptr)
    , unk54(0)
    , mCells{}
    , unk70(1)
    , unk74(1)
    , mObject{}
    , mLuaState(nullptr)
    , mUnitCommand(nullptr)
    , mCommandQueue(nullptr)
  {
  }

  /**
   * Address: 0x006E5400 (FUN_006E5400, ??0SSTICommandIssueData@Moho@@QAEABU01@@Z)
   *
   * IDA signature:
   * Moho::SSTICommandIssueData *__thiscall Moho::SSTICommandIssueData::SSTICommandIssueData(
   *   Moho::SSTICommandIssueData *src, Moho::SSTICommandIssueData *this);
   *
   * What it does:
   * Copy-constructs every command-issue payload lane, including fastvector
   * cell storage and embedded Lua object state.
   */
  SSTICommandIssueData::SSTICommandIssueData(const SSTICommandIssueData& other)
    : nextCommandId(other.nextCommandId)
    , unk04(other.unk04)
    , mIndex(other.mIndex)
    , mCommandType(other.mCommandType)
    , mTarget(other.mTarget)
    , mTarget2(other.mTarget2)
    , unk38(other.unk38)
    , mOri(other.mOri)
    , unk4C(other.unk4C)
    , mBlueprint(other.mBlueprint)
    , unk54(other.unk54)
    , mCells{}
    , unk70(other.unk70)
    , unk74(other.unk74)
    , mObject(other.mObject)
    , mLuaState(other.mLuaState)
    , mUnitCommand(other.mUnitCommand)
    , mCommandQueue(other.mCommandQueue)
  {
    (void)CopySOCellPosFastVectorN2(mCells, other.mCells);
  }

  /**
   * Address: 0x0057ABB0 (FUN_0057ABB0, ??1SSTICommandIssueData@Moho@@QAE@XZ)
   *
   * IDA signature:
   * void __stdcall Moho::SSTICommandIssueData::~SSTICommandIssueData(
   *   Moho::SSTICommandIssueData *this);
   *
   * What it does:
   * Runs the implicit compiler-generated reverse-order member
   * destruction sequence: `LuaPlus::LuaObject::~LuaObject` on
   * `mObject`, followed by `gpg::core::FastVectorN<SOCellPos, 2>::
   * ~FastVectorN` on `mCells`, which releases any active heap buffer
   * and rebinds storage back to the inline lane. All other members
   * are trivially destructible.
   */
  SSTICommandIssueData::~SSTICommandIssueData() = default;
} // namespace moho
