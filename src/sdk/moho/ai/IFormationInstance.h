#pragma once

#include <cstdint>

#include "Wm3Quaternion.h"
#include "Wm3Vector3.h"

#include "moho/misc/CountedObject.h"
#include "moho/unit/Broadcaster.h"

namespace gpg
{
  class RType;
  class ReadArchive;
  class WriteArchive;
}

namespace moho
{
  enum class EUnitCommandType : std::int32_t;
  struct SCoordsVec2;
  struct SOCellPos;
  struct SOffsetInfo;
  class Unit;

  /**
   * The interface every formation object is reached through.
   *
   * VFTABLE: 0x00E18D74
   *
   * Bases, from the RTTI hierarchy descriptor of
   * `.?AVIFormationInstance@Moho@@` (HierarchyAttribs 0x1 -- multiple
   * inheritance):
   *
   *   base: Moho::CountedObject                                   mdisp=0
   *   base: Moho::Broadcaster<EFormationdStatus>                  mdisp=8
   *
   * The constructor at 0x00569450 is the whole proof in six instructions:
   *
   *   lea ecx, [eax + 8]          ; &(the broadcaster base)
   *   mov dword [eax + 4], 0      ; CountedObject::mRefCount
   *   mov dword [ecx + 4], ecx    ; the node self-links -- TDatListItem()
   *   mov dword [ecx], ecx
   *   mov dword [eax], 0xE18D74   ; this class's own vftable, published last
   *
   * -- i.e. `CountedObject()` inlined (its vftable store elided because the
   * derived one overwrites it), then the broadcaster node's own constructor,
   * then the vptr. The destructor (0x00565C70) runs the same layout
   * backwards: vptr, the node's unlink at +0x08, then `mov [ecx], 0xE01810`,
   * which is `~CountedObject` inlined. `~CFormationInstance` (0x00569880)
   * ends with that identical eight-instruction tail, which is what pins the
   * unlink to this class rather than to its owner.
   *
   * Both of those lanes used to be reached through a two-field
   * `IFormationInstanceSerializationRuntimeView` laid over the object with a
   * stand-in vtable word, because this class was modelled as a bare 4-byte
   * vtable carrier that declared the reference count as its own
   * `mSharedCount` member and left the broadcaster on `CFormationInstance` as
   * `mStatusListeners`.
   */
  class IFormationInstance : public CountedObject, public BroadcasterEventTag<EFormationdStatus>
  {
  public:
    inline static gpg::RType* sType = nullptr;
    inline static gpg::RType* sPointerType = nullptr;

    /**
     * Address: 0x00569450 (FUN_00569450, Moho::IFormationInstance::IFormationInstance)
     *
     * What it does:
     * Nothing of its own -- the cleared reference count and the self-linked
     * listener ring are the two base constructors, and the vftable store is
     * the compiler's.
     */
    IFormationInstance();

    /**
     * Address: 0x00565C70 (FUN_00565C70, Moho::IFormationInstance::~IFormationInstance)
     * Address: 0x00565CA0 (FUN_00565CA0, `??_GIFormationInstance@Moho@@UAEPAXI@Z`,
     *   the scalar deleting destructor MSVC parks in slot 0: the body below
     *   followed by the conditional `::operator delete`)
     *
     * VFTable SLOT: 0 (overriding `CountedObject`'s own slot-0 destructor,
     * 0x004228E0)
     *
     * What it does:
     * Unlinks the broadcaster base from whatever listener ring it is in.
     */
    ~IFormationInstance() override;

    /**
     * Address: 0x0059D010 (FUN_0059D010, Moho::IFormationInstance::GetPointerType)
     *
     * What it does:
     * Lazily resolves and caches the reflection descriptor for
     * `IFormationInstance*`.
     */
    [[nodiscard]] static gpg::RType* GetPointerType();

    /**
     * Address: 0x00570D80 (FUN_00570D80, Moho::IFormationInstance::MemberDeserialize)
     *
     * What it does:
     * Loads reflected formation-status broadcaster payload for this instance.
     */
    static void MemberDeserialize(IFormationInstance* object, gpg::ReadArchive* archive);

    /**
     * Address: 0x00570DD0 (FUN_00570DD0, Moho::IFormationInstance::MemberSerialize)
     *
     * What it does:
     * Saves reflected formation-status broadcaster payload for this instance.
     */
    static void MemberSerialize(const IFormationInstance* object, gpg::WriteArchive* archive);

    /**
     * Slots 1-24 of `??_7IFormationInstance@Moho@@6B@` (0x00E18D74) are all
     * `_purecall`; only the deleting destructor at slot 0 (0x00565CA0) has a
     * body. `CFormationInstance` (0x00E18E0C) fills every one of them and adds
     * slot 25 (`FindSlotFor`); `CAiFormationInstance` (0x00E1B47C) overrides
     * six and adds slot 26 (`PosIsFree`). The order below is the binary slot
     * order and must not change.
     *
     * Slot names come from the FAF IDB where it carries one (`SetCoords`,
     * `UnitCount`, `GetLayer`, `Contains`, `CommandIsForm`, `SetOrientation`,
     * `GetOrientation`, `GetCommandType`, `PosIsFree`) and otherwise from the
     * `SUnitOffsetInfo`/`SOffsetInfo` field each override provably reads:
     * `GetOffsetInfo` returns the unit's `SOffsetInfo`, `GetOffsetPosition`
     * is `mCoords + SUnitOffsetInfo::mOffset`, `GetTargetPosition` is
     * `SUnitOffsetInfo::mTargetPos`, `GetDistFromLeader` is
     * `SUnitOffsetInfo::mDistFromLeader`, `GetPriority` is derived from
     * `SUnitOffsetInfo::mWeight`, `GetLeader` is `SOffsetInfo::GetLeader`,
     * `GetForwardVector` is `mForwardVector`, `IsInFormation` is
     * `SOffsetInfo::mInFormation` and `SetScale` writes `mScale`.
     */
    virtual SCoordsVec2* GetCoords(SCoordsVec2* outCoords) const = 0;                                    // slot 1
    virtual void SetCoords(const SCoordsVec2& coords) = 0;                                                // slot 2
    virtual int UnitCount() const = 0;                                                                    // slot 3
    virtual std::int32_t GetLayer(Unit* unit) const = 0;                                                  // slot 4
    virtual SOffsetInfo* GetOffsetInfo(Unit* unit) = 0;                                                   // slot 5
    virtual SCoordsVec2* GetFormationPosition(SCoordsVec2* dest, Unit* unit, SOffsetInfo* info) = 0;      // slot 6
    virtual SOCellPos* GetAdjustedFormationPosition(SOCellPos* dest, Unit* unit, SOffsetInfo* info) = 0;  // slot 7
    virtual SCoordsVec2* GetOffsetPosition(SCoordsVec2* dest, Unit* unit, SOffsetInfo* info) = 0;         // slot 8
    virtual Wm3::Vec3f* GetTargetPosition(Wm3::Vec3f* out, Unit* unit, SOffsetInfo* info) = 0;            // slot 9
    virtual float GetDistFromLeader(Unit* unit, SOffsetInfo* info) = 0;                                   // slot 10
    virtual std::int32_t GetPriority(Unit* unit, SOffsetInfo* info) = 0;                                  // slot 11
    virtual float CalcFormationSpeed(Unit* unit, float* speedScaleOut, SOffsetInfo* info) = 0;            // slot 12
    virtual Unit* GetLeader(Unit* unit, SOffsetInfo* info) = 0;                                           // slot 13
    virtual void AddUnit(Unit* unit) = 0;                                                                 // slot 14
    virtual void RemoveUnit(Unit* unit) = 0;                                                              // slot 15
    virtual bool Contains(Unit* unit, bool checkAll) const = 0;                                           // slot 16
    virtual void Update() = 0;                                                                            // slot 17
    virtual Wm3::Vec3f* GetForwardVector(Wm3::Vec3f* out, Unit* unit) const = 0;                          // slot 18
    virtual bool CommandIsForm() const = 0;                                                               // slot 19
    virtual bool IsInFormation(Unit* unit) const = 0;                                                     // slot 20
    virtual void SetScale(float scale) = 0;                                                               // slot 21
    virtual void SetOrientation(const Wm3::Quatf& orientation) = 0;                                       // slot 22
    virtual Wm3::Quatf* GetOrientation(Wm3::Quatf* outOrientation) const = 0;                             // slot 23
    virtual EUnitCommandType GetCommandType() const = 0;                                                  // slot 24
  };

  /**
   * `CountedObject` (0x08, its own size assert) then the broadcaster node
   * (0x08, likewise) -- which is the mdisp 0 / mdisp 8 pair the RTTI names,
   * and also what `CAiFormationInstance`'s `offsetof(.., mState) == 0x10`
   * pins from the far side. `offsetof` cannot name either base subobject, so
   * the three size asserts together are the layout guard.
   */
  static_assert(sizeof(IFormationInstance) == 0x10, "IFormationInstance size must be 0x10");
} // namespace moho
