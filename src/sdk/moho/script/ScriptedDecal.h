#pragma once

#include <cstddef>
#include <cstdint>

#include "boost/shared_ptr.h"

#include "gpg/core/reflection/Reflection.h"
#include "moho/script/CScriptObject.h"
#include "moho/unit/Broadcaster.h"
#include "wm3/Vector3.h"

namespace moho
{
  /**
   * Runtime service used by ScriptedDecal for registration/unregistration.
   *
   * `RemoveRuntimeDecal` corresponds to vtable slot offset +0x24 in recovered
   * ScriptedDecal teardown path (FUN_0087EC20).
   */
  class IDecalRuntimeService
  {
  public:
    virtual void Slot00() = 0;
    virtual void Slot01() = 0;
    virtual void Slot02() = 0;
    virtual void Slot03() = 0;
    virtual void Slot04() = 0;
    virtual void Slot05() = 0;
    virtual void Slot06() = 0;
    virtual void Slot07() = 0;
    virtual void Slot08() = 0;
    virtual void RemoveRuntimeDecal(void* runtimeEntry) = 0;
  };

  /**
   * VFTABLE: 0x00E499BC
   * COL: 0x00E9C420
   */
  class ScriptedDecal : public CScriptObject
  {
  public:
    /**
     * Address: 0x0087F070 (FUN_0087F070, scalar deleting thunk)
     * Address: 0x0087EC20 (FUN_0087EC20, non-deleting body)
     *
     * VFTable SLOT: 2
     */
    ~ScriptedDecal() override;

    /**
     * Address: 0x0087F030 (FUN_0087F030, ?GetClass@ScriptedDecal@Moho@@UBEPAVRType@gpg@@XZ)
     *
     * VFTable SLOT: 0
     */
    [[nodiscard]]
    gpg::RType* GetClass() const override;

    /**
     * Address: 0x0087F050 (FUN_0087F050, ?GetDerivedObjectRef@ScriptedDecal@Moho@@UAE?AVRRef@gpg@@XZ)
     *
     * VFTable SLOT: 1
     */
    gpg::RRef GetDerivedObjectRef() override;

  public:
    static gpg::RType* sType;

    Broadcaster mRuntimeLink;                  // +0x34
    boost::shared_ptr<void> mDynamicTexture;   // +0x3C
    IDecalRuntimeService* mDecalService;       // +0x44
    void* mWorldCamera;                        // +0x48
    float mScaleX;                             // +0x4C
    float mScaleY;                             // +0x50
    float mScaleZ;                             // +0x54
    Wm3::Vector3f mWorldPosition;              // +0x58
  };

  static_assert(sizeof(ScriptedDecal) == 0x64, "ScriptedDecal size must be 0x64");
  static_assert(offsetof(ScriptedDecal, mRuntimeLink) == 0x34, "ScriptedDecal::mRuntimeLink offset must be 0x34");
  static_assert(
    offsetof(ScriptedDecal, mDynamicTexture) == 0x3C, "ScriptedDecal::mDynamicTexture offset must be 0x3C"
  );
  static_assert(offsetof(ScriptedDecal, mDecalService) == 0x44, "ScriptedDecal::mDecalService offset must be 0x44");
  static_assert(offsetof(ScriptedDecal, mWorldCamera) == 0x48, "ScriptedDecal::mWorldCamera offset must be 0x48");
  static_assert(offsetof(ScriptedDecal, mScaleX) == 0x4C, "ScriptedDecal::mScaleX offset must be 0x4C");
  static_assert(offsetof(ScriptedDecal, mScaleY) == 0x50, "ScriptedDecal::mScaleY offset must be 0x50");
  static_assert(offsetof(ScriptedDecal, mScaleZ) == 0x54, "ScriptedDecal::mScaleZ offset must be 0x54");
  static_assert(offsetof(ScriptedDecal, mWorldPosition) == 0x58, "ScriptedDecal::mWorldPosition offset must be 0x58");
} // namespace moho
