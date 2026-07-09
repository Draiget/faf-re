#pragma once

#include <cstddef>
#include <cstdint>

#include "Wm3Quaternion.h"
#include "Wm3Vector3.h"

namespace moho
{
  class IFormationInstance;

  class CFormation
  {
  public:
    struct Node
    {
      Node* mLeft;                // +0x00
      Node* mParent;              // +0x04
      Node* mRight;               // +0x08
      void* mValue;               // +0x0C
      Node* mListPrev;            // +0x10
      Node* mListNext;            // +0x14
      std::uint8_t mColor;        // +0x18
      std::uint8_t mIsSentinel;   // +0x19
      std::uint8_t mPad1A[0x02];  // +0x1A
    };

    /**
     * Address: 0x00838070 (FUN_00838070, ??0CFormation@Moho@@QAE@@Z)
     *
     * What it does:
     * Allocates one formation-node tree head, initializes formation runtime
     * lanes, and resets per-command formation state.
     */
    CFormation();

    /**
     * Address: 0x0089B370 (FUN_0089B370, ??1CFormation@Moho@@QAE@XZ)
     *
     * What it does:
     * Releases current formation-instance ownership, tears down the intrusive
     * formation-node tree head/lane, and clears node-count state.
     */
    ~CFormation();

    /**
     * Address: 0x008380E0 (FUN_008380E0, Moho::CFormation::Reset)
     *
     * What it does:
     * Clears formation-node entries, drops the current formation-instance lane,
     * and restores default orientation/timer state for command processing.
     */
    void Reset();

    /**
     * Address: 0x00838860 (FUN_00838860, Moho::CFormation::UpdateOrientation)
     *
     * IDA signature:
     * void __fastcall Moho::CFormation::UpdateOrientation(
     *     Wm3::Vector3f *mouseWorldPos, Moho::CFormation *formation);
     *
     * What it does:
     * Per-frame command-formation orientation update. Once the formation timer
     * expires and the mouse has moved far enough, recomputes the formation
     * direction quaternion from (mouse - finish) and pushes it into the live
     * formation instance via SetOrientation, unless the UI is in NIS mode (then
     * it resets the formation). Modeled static because the binary passes the
     * formation in edx, not as a thiscall receiver.
     */
    static void UpdateOrientation(const Wm3::Vector3f& mouseWorldPos, CFormation* formation);

  public:
    void* mTreeAllocProxy;             // +0x00
    Node* mNodeHead;                   // +0x04
    std::uint32_t mNodeCount;          // +0x08
    IFormationInstance* mCurInstance;  // +0x0C
    bool mReady;                       // +0x10
    std::uint8_t mPad11[0x03];         // +0x11
    std::int32_t mType;                // +0x14
    Wm3::Vector3f mStart;              // +0x18
    Wm3::Vector3f mFinish;             // +0x24
    Wm3::Vector3f mMousePos;           // +0x30
    std::int32_t mBestFormation;       // +0x3C
    std::int32_t mTravelFormation;     // +0x40
    std::int32_t mNumFormationScripts; // +0x44
    Wm3::Quaternionf mDirection;       // +0x48 (Wm3 layout: w@+0x48, x@+0x4C, y@+0x50, z@+0x54)
    float mDirectionScale;             // +0x58
    float mTimeLeft;                   // +0x5C
    float mLastUpdate;                 // +0x60
  };

  static_assert(sizeof(CFormation::Node) == 0x1C, "CFormation::Node size must be 0x1C");
  static_assert(offsetof(CFormation::Node, mLeft) == 0x00, "CFormation::Node::mLeft offset must be 0x00");
  static_assert(offsetof(CFormation::Node, mParent) == 0x04, "CFormation::Node::mParent offset must be 0x04");
  static_assert(offsetof(CFormation::Node, mRight) == 0x08, "CFormation::Node::mRight offset must be 0x08");
  static_assert(offsetof(CFormation::Node, mValue) == 0x0C, "CFormation::Node::mValue offset must be 0x0C");
  static_assert(offsetof(CFormation::Node, mColor) == 0x18, "CFormation::Node::mColor offset must be 0x18");
  static_assert(offsetof(CFormation::Node, mIsSentinel) == 0x19, "CFormation::Node::mIsSentinel offset must be 0x19");

  static_assert(sizeof(CFormation) == 0x64, "CFormation size must be 0x64");
  static_assert(offsetof(CFormation, mNodeHead) == 0x04, "CFormation::mNodeHead offset must be 0x04");
  static_assert(offsetof(CFormation, mNodeCount) == 0x08, "CFormation::mNodeCount offset must be 0x08");
  static_assert(offsetof(CFormation, mCurInstance) == 0x0C, "CFormation::mCurInstance offset must be 0x0C");
  static_assert(offsetof(CFormation, mType) == 0x14, "CFormation::mType offset must be 0x14");
  static_assert(offsetof(CFormation, mBestFormation) == 0x3C, "CFormation::mBestFormation offset must be 0x3C");
  static_assert(offsetof(CFormation, mTravelFormation) == 0x40, "CFormation::mTravelFormation offset must be 0x40");
  static_assert(offsetof(CFormation, mNumFormationScripts) == 0x44, "CFormation::mNumFormationScripts offset must be 0x44");
  static_assert(offsetof(CFormation, mDirection) == 0x48, "CFormation::mDirection offset must be 0x48");
  static_assert(sizeof(Wm3::Quaternionf) == 0x10, "Wm3::Quaternionf size must be 0x10");
  static_assert(offsetof(CFormation, mTimeLeft) == 0x5C, "CFormation::mTimeLeft offset must be 0x5C");
  static_assert(offsetof(CFormation, mLastUpdate) == 0x60, "CFormation::mLastUpdate offset must be 0x60");
} // namespace moho
