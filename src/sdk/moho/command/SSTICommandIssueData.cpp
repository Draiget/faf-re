#include "moho/command/SSTICommandIssueData.h"

#include "lua/LuaObject.h"
#include "moho/ai/EAiTargetType.h"
#include "moho/command/SSTITarget.h"
#include "moho/sim/SOCellPos.h"
#include "Wm3Quaternion.h"
#include "Wm3Vector3.h"

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
    , mTarget{AITARGET_None, 0xF0000000u, Wm3::Vec3f{0.0f, 0.0f, 0.0f}}
    , mTarget2{AITARGET_None, 0xF0000000u, Wm3::Vec3f{0.0f, 0.0f, 0.0f}}
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
