#pragma once
#include <cstdint>

#include "boost/weak_ptr.h"
#include "Broadcaster.h"
#include "gpg/core/containers/FastVector.h"
#include "moho/ai/CAiTarget.h"
#include "moho/command/CmdDefs.h"
#include "moho/command/SSTICommandConstantData.h"
#include "moho/command/SSTICommandVariableData.h"
#include "moho/script/CScriptObject.h"

namespace moho
{
  class CAiFormationInstance;
  class Sim;
  class Unit;

  struct SCommandUnitSet
  {
    // Command unit-set uses 0x8 as an erased/tombstone entry marker.
    static constexpr std::uintptr_t kErasedEntryTag = 8u;

    static bool IsUsableEntry(const CScriptObject* scriptObject)
    {
      return scriptObject != nullptr && reinterpret_cast<std::uintptr_t>(scriptObject) != kErasedEntryTag;
    }

    gpg::core::FastVector<CScriptObject*> mVec;
  };

  class CUnitCommand : public Broadcaster
  {
  public:
    /**
     * Address: 0x006F1650
     * @param amount
     */
    void IncreaseCount(int amount);

    /**
     * Address: 0x006F16A0
     * @param amount
     */
    void DecreaseCount(int amount);

    /**
     * Address: 0x006E8820
     */
    void SetTarget(const CAiTarget& target);

    /**
     * Address: 0x005BF810 (FUN_005BF810)
     *
     * What it does:
     * Refreshes cached command blip/transform state for the current frame.
     */
    void RefreshBlipState();

  private:
    /**
     * Address: 0x006E8500 (FUN_006E8500)
     *
     * Internal teardown used by the deleting destructor.
     */
    void DestroyInternal();

    /**
     * Address: 0x006E8DC0 (FUN_006E8DC0)
     *
     * Rebuilds cached unit/event payload state when pending updates exist.
     */
    void RefreshPublishedCommandEvent(bool forceRefresh, int callbackContext);

    /**
     * Address: 0x006E9000 (FUN_006E9000)
     *
     * Links compatible commands into the coordinating-order ring.
     */
    void LinkCoordinatingOrder(CUnitCommand* other);

  public:
    // Placeholder for unresolved leading subobject/layout slice.
    void* unk0;
    Sim* mSim;
    SSTICommandConstantData mConstDat;
    SSTICommandVariableData mVarDat;
    // Likely list/sentinel related storage near +0xF0/+0xF4.
    void* unk1;
    SCommandUnitSet mUnitSet;
    CAiFormationInstance* mFormationInstance;
    CAiTarget mTarget;
    // Monotonic per-command serial assigned from Sim counter (not mConstDat.cmd).
    CmdId mInstanceSerial;
    bool mHasPublishedCommandEvent;
    bool mNeedsUpdate;
    bool mUnknownFlag142;
    bool mUnknownFlag143;
    // TODO(binary-layout): element type is still under investigation.
    msvc8::vector<boost::shared_ptr<CUnitCommand>> mCoordinatingOrders;
    bool mUnknownFlag154;
    boost::weak_ptr<Unit> mUnit;
    LuaPlus::LuaObject mArgs;
    int32_t mUnknownTailInt;
  };
} // namespace moho
