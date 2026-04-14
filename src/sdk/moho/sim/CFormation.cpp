#include "moho/sim/CFormation.h"

#include <cstring>
#include <new>

#include "moho/ai/IFormationInstance.h"

namespace
{
  [[nodiscard]] moho::CFormation::Node* AllocateFormationNode()
  {
    auto* const node = static_cast<moho::CFormation::Node*>(::operator new(sizeof(moho::CFormation::Node), std::nothrow));
    if (node == nullptr) {
      return nullptr;
    }

    node->mLeft = nullptr;
    node->mParent = nullptr;
    node->mRight = nullptr;
    node->mValue = nullptr;
    node->mListPrev = nullptr;
    node->mListNext = nullptr;
    node->mColor = 1u;
    node->mIsSentinel = 0u;
    node->mPad1A[0] = 0u;
    node->mPad1A[1] = 0u;
    return node;
  }

  void ClearFormationNodes(moho::CFormation::Node* node)
  {
    if (node == nullptr || node->mIsSentinel != 0u) {
      return;
    }

    ClearFormationNodes(node->mRight);
    ClearFormationNodes(node->mLeft);
    ::operator delete(node);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00838070 (FUN_00838070, ??0CFormation@Moho@@QAE@@Z)
   */
  CFormation::CFormation()
    : mTreeAllocProxy(nullptr)
    , mNodeHead(nullptr)
    , mNodeCount(0)
    , mCurInstance(nullptr)
    , mReady(false)
    , mPad11{0u, 0u, 0u}
    , mType(0)
    , mStart()
    , mFinish()
    , mMousePos()
    , mBestFormation(-1)
    , mTravelFormation(-1)
    , mNumFormationScripts(0)
    , mDirectionX(0.0f)
    , mDirectionY(0.0f)
    , mDirectionZ(0.0f)
    , mDirectionW(1.0f)
    , mDirectionScale(1.0f)
    , mTimeLeft(0.5f)
    , mLastUpdate(0.0f)
  {
    Node* const head = AllocateFormationNode();
    mNodeHead = head;
    if (head != nullptr) {
      head->mIsSentinel = 1u;
      head->mParent = head;
      head->mLeft = head;
      head->mRight = head;
    }

    Reset();
  }

  /**
   * Address: 0x008380E0 (FUN_008380E0, Moho::CFormation::Reset)
   */
  void CFormation::Reset()
  {
    if (mNodeHead != nullptr) {
      ClearFormationNodes(mNodeHead->mParent);
      mNodeHead->mParent = mNodeHead;
      mNodeHead->mLeft = mNodeHead;
      mNodeHead->mRight = mNodeHead;
    }
    mNodeCount = 0u;

    IFormationInstance* const curInstance = mCurInstance;
    mCurInstance = nullptr;
    if (curInstance != nullptr) {
      curInstance->operator_delete(1);
    }

    mReady = false;
    mType = 2;

    std::memset(&mStart, 0, sizeof(mStart));
    std::memset(&mFinish, 0, sizeof(mFinish));
    std::memset(&mMousePos, 0, sizeof(mMousePos));

    mNumFormationScripts = 0;
    mDirectionX = 0.0f;
    mDirectionY = 0.0f;
    mDirectionZ = 0.0f;
    mDirectionW = 1.0f;
    mDirectionScale = 1.0f;
    mTimeLeft = 0.5f;
    mLastUpdate = 0.0f;
  }
} // namespace moho
