#include "moho/ai/CAiBrain.h"

#include <new>
#include <typeinfo>

#include "gpg/core/utils/Logging.h"
#include "lua/LuaObject.h"
#include "moho/ai/CAiPersonality.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/Sim.h"
#include "moho/task/CTaskThread.h"

using namespace moho;

namespace
{
  constexpr const char* kAiBrainModulePath = "/lua/aibrain.lua";
  constexpr const char* kAiBrainClassName = "AIBrain";

  [[nodiscard]] LuaPlus::LuaObject LoadAiBrainFactoryObject(LuaPlus::LuaState* const state)
  {
    LuaPlus::LuaObject moduleObj = SCR_ImportLuaModule(state, kAiBrainModulePath);
    if (moduleObj) {
      LuaPlus::LuaObject classObj = SCR_GetLuaTableField(state, moduleObj, kAiBrainClassName);
      if (!classObj.IsNil()) {
        return classObj;
      }
    }

    gpg::Logf("Can't find AIBrain, using CAiBrain directly");
    return CScrLuaMetatableFactory<CScriptObject*>::Instance().Get(state);
  }

  [[nodiscard]] SBuildStructurePositionNode* AllocateBuildStructureNode()
  {
    auto* const node = static_cast<SBuildStructurePositionNode*>(::operator new(sizeof(SBuildStructurePositionNode)));
    node->left = nullptr;
    node->parent = nullptr;
    node->right = nullptr;
    node->mGridPosition = {};
    node->mBuildInfo.mPlacementLink.mOwnerSlot = nullptr;
    node->mBuildInfo.mPlacementLink.mNext = nullptr;
    node->mBuildInfo.mResourceLink.mOwnerSlot = nullptr;
    node->mBuildInfo.mResourceLink.mNext = nullptr;
    node->mColor = 1;
    node->mIsNil = 0;
    node->mPad26[0] = 0;
    node->mPad26[1] = 0;
    return node;
  }

  void InitializeBuildStructureMap(SBuildStructurePositionMap& map)
  {
    map.mMeta00 = 0;
    map.mHead = AllocateBuildStructureNode();
    map.mHead->mIsNil = 1;
    map.mHead->parent = map.mHead;
    map.mHead->left = map.mHead;
    map.mHead->right = map.mHead;
    map.mSize = 0;
  }

  void UnlinkBuildResourceInfoLink(SBuildResourceInfoLink& link)
  {
    SBuildResourceInfoLink** cursor = link.mOwnerSlot;
    if (!cursor) {
      return;
    }

    while (*cursor != &link) {
      if (!*cursor) {
        return;
      }
      cursor = &(*cursor)->mNext;
    }

    *cursor = link.mNext;
    link.mOwnerSlot = nullptr;
    link.mNext = nullptr;
  }

  void DestroyBuildStructureTree(SBuildStructurePositionNode* node)
  {
    while (node && node->mIsNil == 0u) {
      DestroyBuildStructureTree(node->right);
      SBuildStructurePositionNode* const left = node->left;

      // Matches sub_5812C0 unlink order (+0x1C link first, then +0x14 link).
      UnlinkBuildResourceInfoLink(node->mBuildInfo.mResourceLink);
      UnlinkBuildResourceInfoLink(node->mBuildInfo.mPlacementLink);
      ::operator delete(node);

      node = left;
    }
  }

  void DestroyBuildStructureMap(SBuildStructurePositionMap& map)
  {
    if (!map.mHead) {
      return;
    }

    DestroyBuildStructureTree(map.mHead->parent);
    ::operator delete(map.mHead);
    map.mHead = nullptr;
    map.mSize = 0;
  }

  [[nodiscard]] CTaskStage* AllocateTaskStage()
  {
    auto* const stage = static_cast<CTaskStage*>(::operator new(sizeof(CTaskStage)));
    stage->mThreads.mPrev = &stage->mThreads;
    stage->mThreads.mNext = &stage->mThreads;
    stage->mStagedThreads.mPrev = &stage->mStagedThreads;
    stage->mStagedThreads.mNext = &stage->mStagedThreads;
    stage->mActive = true;
    stage->mAlignmentPad11[0] = 0;
    stage->mAlignmentPad11[1] = 0;
    stage->mAlignmentPad11[2] = 0;
    return stage;
  }

  void DestroyTaskStageAndDelete(CTaskStage*& stage)
  {
    if (!stage) {
      return;
    }

    stage->Teardown();
    stage->mStagedThreads.ListUnlink();
    stage->mThreads.ListUnlink();
    ::operator delete(stage);
    stage = nullptr;
  }
} // namespace

gpg::RType* CAiBrain::sType = nullptr;

/**
 * Address: 0x00579E40 (FUN_00579E40, default ctor)
 */
CAiBrain::CAiBrain()
  : mArmy(nullptr)
  , mCurrentEnemy(nullptr)
  , mPersonality(nullptr)
  , mCurrentPlan()
  , mAttackVectors()
  , mBuildCategoryRange()
  , mBuildStructureMap{}
  , mSim(nullptr)
  , mAiThreadStage(nullptr)
  , mAttackerThreadStage(nullptr)
  , mReservedThreadStage(nullptr)
  , mTailWord(0)
{
  mCurrentPlan.assign("", 0);
  InitializeBuildStructureMap(mBuildStructureMap);
}

/**
 * Address: 0x00579F80 (FUN_00579F80, army ctor)
 */
CAiBrain::CAiBrain(CArmyImpl* const army)
  : CAiBrain()
{
  mArmy = army;
  mCurrentEnemy = nullptr;
  mSim = army ? army->GetSim() : nullptr;

  if (mSim && mSim->mLuaState) {
    LuaPlus::LuaObject arg1;
    LuaPlus::LuaObject arg2;
    LuaPlus::LuaObject arg3;
    LuaPlus::LuaObject factory = LoadAiBrainFactoryObject(mSim->mLuaState);
    CreateLuaObject(factory, arg1, arg2, arg3);
  }

  mPersonality = new (std::nothrow) CAiPersonality(mSim);

  mAiThreadStage = AllocateTaskStage();
  mAttackerThreadStage = AllocateTaskStage();
  mReservedThreadStage = AllocateTaskStage();

  if (mPersonality) {
    mPersonality->ReadData();
  }
}

/**
 * Address: 0x00579590 (FUN_00579590, ?GetClass@CAiBrain@Moho@@UBEPAVRType@gpg@@XZ)
 */
gpg::RType* CAiBrain::GetClass() const
{
  gpg::RType* type = sType;
  if (!type) {
    type = gpg::LookupRType(typeid(CAiBrain));
    sType = type;
  }
  return type;
}

/**
 * Address: 0x005795B0 (FUN_005795B0, ?GetDerivedObjectRef@CAiBrain@Moho@@UAE?AVRRef@gpg@@XZ)
 */
gpg::RRef CAiBrain::GetDerivedObjectRef()
{
  gpg::RRef ref{};
  ref.mObj = this;
  ref.mType = GetClass();
  return ref;
}

/**
 * Address: 0x00579F30 (FUN_00579F30, scalar deleting thunk)
 * Address: 0x0057A1E0 (FUN_0057A1E0, core destructor)
 */
CAiBrain::~CAiBrain()
{
  DestroyTaskStageAndDelete(mReservedThreadStage);
  DestroyTaskStageAndDelete(mAttackerThreadStage);
  DestroyTaskStageAndDelete(mAiThreadStage);

  DestroyBuildStructureMap(mBuildStructureMap);

  // mCurrentPlan has no automatic heap cleanup in this legacy wrapper.
  mCurrentPlan.tidy(true, 0U);

  delete mPersonality;
  mPersonality = nullptr;
}
