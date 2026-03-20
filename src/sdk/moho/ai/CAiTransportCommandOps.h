#pragma once

#include "moho/entity/Entity.h"
#include "moho/unit/core/Unit.h"

namespace moho
{
  class IFormationInstance;
  class CUnitCommand;
  class RUnitBlueprint;
  class SCoordsVec2;
  class SOCellPos;

  /**
   * Transport command-ops vtable view used by command queue cleanup paths.
   *
   * Evidence:
   * - RTTI `CAiTransportImpl@Moho` reports a single 43-slot primary vtable.
   * - Callsite `FUN_00749970` dispatches through this vtable at +0x2C/+0x34.
   */
  class CAiTransportCommandOps
  {
  public:
    virtual ~CAiTransportCommandOps() = default;

    virtual bool TransportIsAirStagingPlatform() const = 0;                                     // +0x04
    virtual bool TransportIsTeleporter() const = 0;                                             // +0x08
    virtual EntitySetTemplate<Unit> TransportGetLoadedUnits(bool) const = 0;                    // +0x0C
    virtual void TransportAddPickupUnits(EntitySetTemplate<Unit> const&, SCoordsVec2) = 0;      // +0x10
    virtual void TransportRemovePickupUnit(Unit*, bool) = 0;                                    // +0x14
    virtual void TransportRemoveUnitReservation(Unit*) = 0;                                     // +0x18
    virtual unsigned int TransportGetPickupUnitCount() const = 0;                               // +0x1C
    virtual EntitySetTemplate<Unit> TransportGetPickupUnits() = 0;                              // +0x20
    virtual bool TransportCanCarryUnit(Unit*) const = 0;                                        // +0x24
    virtual bool TransportHasSpaceFor(RUnitBlueprint const*) = 0;                               // +0x28
    virtual bool TransportAssignSlot(CUnitCommand*) = 0;                                        // +0x2C
    virtual bool TransportAttachUnit(Unit*) = 0;                                                // +0x30
    virtual bool TransportDetachUnit(CUnitCommand*) = 0;                                        // +0x34
    virtual EntitySetTemplate<Unit> TransportDetachAllUnits(bool) = 0;                          // +0x38
    virtual bool TransportIsUnitAssignedForPickup(Unit*) const = 0;                             // +0x3C
    virtual SOCellPos TransportGetPickupUnitPos(Unit*) const = 0;                               // +0x40
    virtual void TransportAtPickupPosition() = 0;                                               // +0x44
    virtual bool TransportIsReadyForUnit(Unit*) const = 0;                                      // +0x48
    virtual int TransportGetAttachBone(Unit*) const = 0;                                        // +0x4C
    virtual SOCellPos TransportGetAttachPosition(Unit*) const = 0;                              // +0x50
    virtual Wm3::Vec3f TransportGetAttachBonePosition(Unit*) const = 0;                         // +0x54
    virtual VTransform TransportGetAttachBoneTransform(Unit*) const = 0;                        // +0x58
    virtual Wm3::Vec3f TransportGetAttachFacing(Unit*) const = 0;                               // +0x5C
    virtual Wm3::Vec3f TransportGetPickupFacing() const = 0;                                    // +0x60
    virtual void TransportAddToStorage(Unit*) = 0;                                              // +0x64
    virtual void TransportRemoveFromStorage(Unit*, VTransform&) = 0;                            // +0x68
    virtual EntitySetTemplate<Unit> TransportGetStoredUnits() const = 0;                        // +0x6C
    virtual bool TransportIsStoredUnit(Unit*) const = 0;                                        // +0x70
    virtual bool TransportHasAvailableStorage() const = 0;                                      // +0x74
    virtual int TransportReserveStorage(Unit*, Wm3::Vec3f&, Wm3::Vec3f&, float&) = 0;           // +0x78
    virtual void TransportClearReservation(Unit*) = 0;                                          // +0x7C
    virtual void TransportResetReservation() = 0;                                               // +0x80
    virtual void TransportUnreserveUnattachedSpots() = 0;                                       // +0x84
    virtual void TransportRemoveFromWaitingList(Unit*) = 0;                                     // +0x88
    virtual EntitySetTemplate<Unit> TransportGetUnitsWaitingForPickup() const = 0;              // +0x8C
    virtual IFormationInstance* TransportGetWaitingFormation() const = 0;                       // +0x90
    virtual void TransportGenerateWaitingFormationForUnits(EntitySetTemplate<Unit> const&) = 0; // +0x94
    virtual void TransportClearWaitingFormation() = 0;                                          // +0x98
    virtual void TranspotSetTeleportDest(Unit*) = 0;                                            // +0x9C
    virtual Wm3::Vec3f TransportGetTeleportDest() const = 0;                                    // +0xA0
    virtual Unit* TransportGetTeleportBeacon() const = 0;                                       // +0xA4
    virtual bool TransportIsTeleportBeaconReady() const = 0;                                    // +0xA8

    [[nodiscard]] Unit* TransportGetTeleportBeaconForSync() const
    {
      return TransportGetTeleportBeacon();
    }
  };
} // namespace moho
