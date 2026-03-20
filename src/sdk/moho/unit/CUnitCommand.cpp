#include "CUnitCommand.h"
#include "moho/command/SSTICommandIssueData.h"

using namespace moho;

namespace
{
  constexpr std::uintptr_t kCUnitCommandDestroyInternalEa = 0x006E8500u;
  constexpr std::uintptr_t kCUnitCommandRefreshInternalEa = 0x006E8DC0u;
  constexpr std::uintptr_t kCUnitCommandLinkInternalEa = 0x006E9000u;
  constexpr std::uintptr_t kCUnitCommandRefreshBlipStateEa = 0x005BF810u;
} // namespace

// 0x006F1650
void CUnitCommand::IncreaseCount(const int amount)
{
  if (amount <= 0 || mVarDat.mCmdType != EUnitCommandType::UNITCOMMAND_BuildFactory) {
    return;
  }

  const int newCount = mVarDat.mCount + amount;

  mVarDat.mCount = newCount;
  if (newCount > mVarDat.mMaxCount) {
    mVarDat.mMaxCount = newCount;
  }

  mNeedsUpdate = true;
}

// 0x006F16A0
void CUnitCommand::DecreaseCount(const int amount)
{
  if (amount <= 0 || mVarDat.mCmdType != EUnitCommandType::UNITCOMMAND_BuildFactory) {
    return;
  }

  int newCount = mVarDat.mCount - amount;
  if (newCount < 0) {
    newCount = 0;
  }

  mVarDat.mCount = newCount;
  mNeedsUpdate = true;
}

// 0x006E8820
void CUnitCommand::SetTarget(const CAiTarget& target)
{
  mTarget = target;
  mVarDat.mTarget1.mType = target.targetType;
  mVarDat.mTarget1.mEntityId = 0;
  mVarDat.mTarget1.mPos = target.position;
  mNeedsUpdate = true;
}

// 0x005BF810 (FUN_005BF810)
void CUnitCommand::RefreshBlipState()
{
  using Fn = void(__thiscall*)(CUnitCommand*);
  auto fn = reinterpret_cast<Fn>(kCUnitCommandRefreshBlipStateEa);
  fn(this);
}

// 0x006E8500 (FUN_006E8500)
void CUnitCommand::DestroyInternal()
{
  using Fn = void(__stdcall*)(CUnitCommand*);
  auto fn = reinterpret_cast<Fn>(kCUnitCommandDestroyInternalEa);
  fn(this);
}

// 0x006E8DC0 (FUN_006E8DC0)
void CUnitCommand::RefreshPublishedCommandEvent(const bool forceRefresh, const int callbackContext)
{
  using Fn = void(__thiscall*)(CUnitCommand*, bool, int);
  auto fn = reinterpret_cast<Fn>(kCUnitCommandRefreshInternalEa);
  fn(this, forceRefresh, callbackContext);
}

// 0x006E9000 (FUN_006E9000)
void CUnitCommand::LinkCoordinatingOrder(CUnitCommand* const other)
{
  if (!other) {
    return;
  }

  using Fn = void(__fastcall*)(CUnitCommand*, CUnitCommand*);
  auto fn = reinterpret_cast<Fn>(kCUnitCommandLinkInternalEa);
  fn(this, other);
}
