// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once

#include "moho/entity/Entity.h"
#include "moho/unit/core/Unit.h"

namespace moho {  class IFormationInstance; class RUnitBlueprint; class SCoordsVec2; class SOCellPos; } // forward decl

namespace moho {
  /**
   * VFTABLE: 0x00E1F3CC
   * COL:  0x00E7664C
   */
  class CAiTransportImpl
  {
  public:
    /**
     * Address: 0x005E8280
     * Slot: 0
     * Demangled: sub_5E8280
     */
    virtual void sub_5E8280() = 0;

    /**
     * Address: 0x005E60F0
     * Slot: 1
     * Demangled: public: virtual bool __thiscall moho::CAiTransportImpl::TransportIsAirStagingPlatform(void)const
     */
    virtual bool TransportIsAirStagingPlatform() const = 0;

    /**
     * Address: 0x005E6100
     * Slot: 2
     * Demangled: public: virtual bool __thiscall moho::CAiTransportImpl::TransportIsTeleporter(void)const
     */
    virtual bool TransportIsTeleporter() const = 0;

    /**
     * Address: 0x005E6110
     * Slot: 3
     * Demangled: public: virtual class moho::EntitySetTemplate<class moho::Unit> __thiscall moho::CAiTransportImpl::TransportGetLoadedUnits(bool)const
     */
    virtual EntitySetTemplate<Unit> TransportGetLoadedUnits(bool) const = 0;

    /**
     * Address: 0x005E6260
     * Slot: 4
     * Demangled: public: virtual void __thiscall moho::CAiTransportImpl::TransportAddPickupUnits(class moho::EntitySetTemplate<class moho::Unit> const near &,struct moho::SCoordsVec2)
     */
    virtual void TransportAddPickupUnits(EntitySetTemplate<Unit> const &, SCoordsVec2) = 0;

    /**
     * Address: 0x005E64A0
     * Slot: 5
     * Demangled: public: virtual void __thiscall moho::CAiTransportImpl::TransportRemovePickupUnit(class moho::Unit near *,bool)
     */
    virtual void TransportRemovePickupUnit(Unit *, bool) = 0;

    /**
     * Address: 0x005E64D0
     * Slot: 6
     * Demangled: public: virtual void __thiscall moho::CAiTransportImpl::TransportRemoveUnitReservation(class moho::Unit near *)
     */
    virtual void TransportRemoveUnitReservation(Unit *) = 0;

    /**
     * Address: 0x005E65A0
     * Slot: 7
     * Demangled: public: virtual unsigned int __thiscall moho::CAiTransportImpl::TransportGetPickupUnitCount(void)const
     */
    virtual unsigned int TransportGetPickupUnitCount() const = 0;

    /**
     * Address: 0x005E65F0
     * Slot: 8
     * Demangled: public: virtual class moho::EntitySetTemplate<class moho::Unit> __thiscall moho::CAiTransportImpl::TransportGetPickupUnits(void)
     */
    virtual EntitySetTemplate<Unit> TransportGetPickupUnits() = 0;

    /**
     * Address: 0x005E6870
     * Slot: 9
     * Demangled: public: virtual bool __thiscall moho::CAiTransportImpl::TransportCanCarryUnit(class moho::Unit near *)const
     */
    virtual bool TransportCanCarryUnit(Unit *) const = 0;

    /**
     * Address: 0x005E6C70
     * Slot: 10
     * Demangled: public: virtual bool __thiscall moho::CAiTransportImpl::TransportHasSpaceFor(class moho::RUnitBlueprint const near *)
     */
    virtual bool TransportHasSpaceFor(RUnitBlueprint const *) = 0;

    /**
     * Address: 0x005E6E30
     * Slot: 11
     * Demangled: public: virtual bool __thiscall moho::CAiTransportImpl::TransportAssignSlot(class moho::Unit near *,int)
     */
    virtual bool TransportAssignSlot(Unit *, int) = 0;

    /**
     * Address: 0x005E7100
     * Slot: 12
     * Demangled: public: virtual bool __thiscall moho::CAiTransportImpl::TransportAttachUnit(class moho::Unit near *)
     */
    virtual bool TransportAttachUnit(Unit *) = 0;

    /**
     * Address: 0x005E7170
     * Slot: 13
     * Demangled: public: virtual bool __thiscall moho::CAiTransportImpl::TransportDetachUnit(class moho::Unit near *)
     */
    virtual bool TransportDetachUnit(Unit *) = 0;

    /**
     * Address: 0x005E73E0
     * Slot: 14
     * Demangled: public: virtual class moho::EntitySetTemplate<class moho::Unit> __thiscall moho::CAiTransportImpl::TransportDetachAllUnits(bool)
     */
    virtual EntitySetTemplate<Unit> TransportDetachAllUnits(bool) = 0;

    /**
     * Address: 0x005E6690
     * Slot: 15
     * Demangled: public: virtual bool __thiscall moho::CAiTransportImpl::TransportIsUnitAssignedForPickup(class moho::Unit near *)const
     */
    virtual bool TransportIsUnitAssignedForPickup(Unit *) const = 0;

    /**
     * Address: 0x005E66B0
     * Slot: 16
     * Demangled: public: virtual struct moho::SOCellPos __thiscall moho::CAiTransportImpl::TransportGetPickupUnitPos(class moho::Unit near *)const
     */
    virtual SOCellPos TransportGetPickupUnitPos(Unit *) const = 0;

    /**
     * Address: 0x005E77B0
     * Slot: 17
     * Demangled: public: virtual void __thiscall moho::CAiTransportImpl::TransportAtPickupPosition(void)
     */
    virtual void TransportAtPickupPosition() = 0;

    /**
     * Address: 0x005E77C0
     * Slot: 18
     * Demangled: public: virtual bool __thiscall moho::CAiTransportImpl::TransportIsReadyForUnit(class moho::Unit near *)const
     */
    virtual bool TransportIsReadyForUnit(Unit *) const = 0;

    /**
     * Address: 0x005E7930
     * Slot: 19
     * Demangled: public: virtual int __thiscall moho::CAiTransportImpl::TransportGetAttachBone(class moho::Unit near *)const
     */
    virtual int TransportGetAttachBone(Unit *) const = 0;

    /**
     * Address: 0x005E77F0
     * Slot: 20
     * Demangled: public: virtual struct moho::SOCellPos __thiscall moho::CAiTransportImpl::TransportGetAttachPosition(class moho::Unit near *)const
     */
    virtual SOCellPos TransportGetAttachPosition(Unit *) const = 0;

    /**
     * Address: 0x005E7950
     * Slot: 21
     * Demangled: public: virtual class Wm3::Vec3f __thiscall moho::CAiTransportImpl::TransportGetAttachBonePosition(class moho::Unit near *)const
     */
    virtual Wm3::Vec3f TransportGetAttachBonePosition(Unit *) const = 0;

    /**
     * Address: 0x005E7A60
     * Slot: 22
     * Demangled: public: virtual class moho::VTransform __thiscall moho::CAiTransportImpl::TransportGetAttachBoneTransform(class moho::Unit near *)const
     */
    virtual VTransform TransportGetAttachBoneTransform(Unit *) const = 0;

    /**
     * Address: 0x005E7AD0
     * Slot: 23
     * Demangled: public: virtual class Wm3::Vec3f __thiscall moho::CAiTransportImpl::TransportGetAttachFacing(class moho::Unit near *)const
     */
    virtual Wm3::Vec3f TransportGetAttachFacing(Unit *) const = 0;

    /**
     * Address: 0x005E7BB0
     * Slot: 24
     * Demangled: public: virtual class Wm3::Vec3f __thiscall moho::CAiTransportImpl::TransportGetPickupFacing(void)const
     */
    virtual Wm3::Vec3f TransportGetPickupFacing() const = 0;

    /**
     * Address: 0x005E7BE0
     * Slot: 25
     * Demangled: public: virtual void __thiscall moho::CAiTransportImpl::TransportAddToStorage(class moho::Unit near *)
     */
    virtual void TransportAddToStorage(Unit *) = 0;

    /**
     * Address: 0x005E7CF0
     * Slot: 26
     * Demangled: public: virtual void __thiscall moho::CAiTransportImpl::TransportRemoveFromStorage(class moho::Unit near *,class moho::VTransform near &)
     */
    virtual void TransportRemoveFromStorage(Unit *, VTransform &) = 0;

    /**
     * Address: 0x005E7E60
     * Slot: 27
     * Demangled: public: virtual class moho::EntitySetTemplate<class moho::Unit> __thiscall moho::CAiTransportImpl::TransportGetStoredUnits(void)const
     */
    virtual EntitySetTemplate<Unit> TransportGetStoredUnits() const = 0;

    /**
     * Address: 0x005E8050
     * Slot: 28
     * Demangled: public: virtual bool __thiscall moho::CAiTransportImpl::TransportIsStoredUnit(class moho::Unit near *)const
     */
    virtual bool TransportIsStoredUnit(Unit *) const = 0;

    /**
     * Address: 0x005E7E80
     * Slot: 29
     * Demangled: public: virtual bool __thiscall moho::CAiTransportImpl::TransportHasAvailableStorage(void)const
     */
    virtual bool TransportHasAvailableStorage() const = 0;

    /**
     * Address: 0x005E7EC0
     * Slot: 30
     * Demangled: public: virtual int __thiscall moho::CAiTransportImpl::TransportReserveStorage(class moho::Unit near *,class Wm3::Vec3f near &,class Wm3::Vec3f near &,float near &)
     */
    virtual int TransportReserveStorage(Unit *, Wm3::Vec3f &, Wm3::Vec3f &, float &) = 0;

    /**
     * Address: 0x005E8020
     * Slot: 31
     * Demangled: public: virtual void __thiscall moho::CAiTransportImpl::TransportClearReservation(class moho::Unit near *)
     */
    virtual void TransportClearReservation(Unit *) = 0;

    /**
     * Address: 0x005E8040
     * Slot: 32
     * Demangled: public: virtual void __thiscall moho::CAiTransportImpl::TransportResetReservation(void)
     */
    virtual void TransportResetReservation() = 0;

    /**
     * Address: 0x005E6530
     * Slot: 33
     * Demangled: public: virtual void __thiscall moho::CAiTransportImpl::TransportUnreserveUnattachedSpots(void)
     */
    virtual void TransportUnreserveUnattachedSpots() = 0;

    /**
     * Address: 0x005E5F10
     * Slot: 34
     * Demangled: public: virtual void __thiscall moho::CAiTransportImpl::TransportRemoveFromWaitingList(class moho::Unit near *)
     */
    virtual void TransportRemoveFromWaitingList(Unit *) = 0;

    /**
     * Address: 0x005E5EF0
     * Slot: 35
     * Demangled: public: virtual class moho::EntitySetTemplate<class moho::Unit> __thiscall moho::CAiTransportImpl::TransportGetUnitsWaitingForPickup(void)const
     */
    virtual EntitySetTemplate<Unit> TransportGetUnitsWaitingForPickup() const = 0;

    /**
     * Address: 0x005E5F30
     * Slot: 36
     * Demangled: public: virtual class moho::IFormationInstance near * __thiscall moho::CAiTransportImpl::TransportGetWaitingFormation(void)const
     */
    virtual IFormationInstance * TransportGetWaitingFormation() const = 0;

    /**
     * Address: 0x005E5F40
     * Slot: 37
     * Demangled: public: virtual void __thiscall moho::CAiTransportImpl::TransportGenerateWaitingFormationForUnits(class moho::EntitySetTemplate<class moho::Unit> const near &)
     */
    virtual void TransportGenerateWaitingFormationForUnits(EntitySetTemplate<Unit> const &) = 0;

    /**
     * Address: 0x005E60A0
     * Slot: 38
     * Demangled: public: virtual void __thiscall moho::CAiTransportImpl::TransportClearWaitingFormation(void)
     */
    virtual void TransportClearWaitingFormation() = 0;

    /**
     * Address: 0x005E8080
     * Slot: 39
     * Demangled: public: virtual void __thiscall moho::CAiTransportImpl::TranspotSetTeleportDest(class moho::Unit near *)
     */
    virtual void TranspotSetTeleportDest(Unit *) = 0;

    /**
     * Address: 0x005E8120
     * Slot: 40
     * Demangled: public: virtual class Wm3::Vec3f __thiscall moho::CAiTransportImpl::TransportGetTeleportDest(void)const
     */
    virtual Wm3::Vec3f TransportGetTeleportDest() const = 0;

    /**
     * Address: 0x005E81C0
     * Slot: 41
     * Demangled: public: virtual class moho::Unit near * __thiscall moho::CAiTransportImpl::TransportGetTeleportBeacon(void)const
     */
    virtual Unit * TransportGetTeleportBeacon() const = 0;

    /**
     * Address: 0x005E81D0
     * Slot: 42
     * Demangled: public: virtual bool __thiscall moho::CAiTransportImpl::TransportIsTeleportBeaconReady(void)const
     */
    virtual bool TransportIsTeleportBeaconReady() const = 0;
  };
} // namespace moho
