#pragma once

#include <cstddef>
#include <cstdint>

#include "moho/ai/IFormationInstance.h"
#include "moho/entity/Entity.h"
#include "moho/unit/Broadcaster.h"
#include "moho/unit/core/Unit.h"
#include "Wm3Vector3.h"

namespace gpg
{
  class RType;
}

namespace moho
{
  struct RUnitBlueprint;
  struct SCoordsVec2;
  struct SOCellPos;

  /**
   * Address: 0x005E3DD0 (FUN_005E3DD0)
   *
   * What it does:
   * Transport-event enum consumed by IAiTransport broadcaster listeners.
   */
  enum EAiTransportEvent : std::int32_t
  {
    AITRANSPORTEVENT_LoadFailed = 0,
    AITRANSPORTEVENT_Load = 0,
    AITRANSPORTEVENT_Unload = 1,
  };

  class IAiTransportEventListener
  {
  public:
    virtual void OnTransportEvent(EAiTransportEvent event) = 0;

    [[nodiscard]] static IAiTransportEventListener* FromListenerLink(Broadcaster* link) noexcept;
    [[nodiscard]] static const IAiTransportEventListener* FromListenerLink(const Broadcaster* link) noexcept;

    Broadcaster mListenerLink; // +0x04
  };

  static_assert(sizeof(IAiTransportEventListener) == 0x0C, "IAiTransportEventListener size must be 0x0C");
  static_assert(
    offsetof(IAiTransportEventListener, mListenerLink) == 0x04,
    "IAiTransportEventListener::mListenerLink offset must be 0x04"
  );

  /**
   * VFTABLE: 0x00E1F0AC
   * COL:  0x00E76D64
   *
   * RTTI evidence:
   * - IAiTransport contains a broadcaster subobject at +0x04
   *   (`Broadcaster<EAiTransportEvent>` in emitted RTTI).
   */
  class IAiTransport : public Broadcaster
  {
  public:
    /**
     * Address: 0x005E3C70 (FUN_005E3C70, scalar deleting thunk)
     *
     * What it does:
     * Unlinks IAiTransport from its broadcaster chain and resets self-links.
     *
     * VFTable SLOT: 0
     */
    virtual ~IAiTransport();

    /**
     * Address: 0x005E60F0 (FUN_005E60F0, CAiTransportImpl::TransportIsAirStagingPlatform)
     *
     * VFTable SLOT: 1
     */
    virtual bool TransportIsAirStagingPlatform() const = 0;

    /**
     * Address: 0x005E6100 (FUN_005E6100, CAiTransportImpl::TransportIsTeleporter)
     *
     * VFTable SLOT: 2
     */
    virtual bool TransportIsTeleporter() const = 0;

    /**
     * Address: 0x005E6110 (FUN_005E6110, CAiTransportImpl::TransportGetLoadedUnits)
     *
     * VFTable SLOT: 3
     */
    virtual EntitySetTemplate<Unit> TransportGetLoadedUnits(bool includeFutureLoad) const = 0;

    /**
     * Address: 0x005E6260 (FUN_005E6260, CAiTransportImpl::TransportAddPickupUnits)
     *
     * VFTable SLOT: 4
     */
    virtual void TransportAddPickupUnits(const EntitySetTemplate<Unit>& units, SCoordsVec2 fallbackPos) = 0;

    /**
     * Address: 0x005E64A0 (FUN_005E64A0, CAiTransportImpl::TransportRemovePickupUnit)
     *
     * VFTable SLOT: 5
     */
    virtual void TransportRemovePickupUnit(Unit* unit, bool clearReservation) = 0;

    /**
     * Address: 0x005E64D0 (FUN_005E64D0, CAiTransportImpl::TransportRemoveUnitReservation)
     *
     * VFTable SLOT: 6
     */
    virtual void TransportRemoveUnitReservation(Unit* unit) = 0;

    /**
     * Address: 0x005E65A0 (FUN_005E65A0, CAiTransportImpl::TransportGetPickupUnitCount)
     *
     * VFTable SLOT: 7
     */
    virtual unsigned int TransportGetPickupUnitCount() const = 0;

    /**
     * Address: 0x005E65F0 (FUN_005E65F0, CAiTransportImpl::TransportGetPickupUnits)
     *
     * VFTable SLOT: 8
     */
    virtual EntitySetTemplate<Unit> TransportGetPickupUnits() = 0;

    /**
     * Address: 0x005E6870 (FUN_005E6870, CAiTransportImpl::TransportCanCarryUnit)
     *
     * VFTable SLOT: 9
     */
    virtual bool TransportCanCarryUnit(Unit* unit) const = 0;

    /**
     * Address: 0x005E6C70 (FUN_005E6C70, CAiTransportImpl::TransportHasSpaceFor)
     *
     * VFTable SLOT: 10
     */
    virtual bool TransportHasSpaceFor(const RUnitBlueprint* unitBlueprint) = 0;

    /**
     * Address: 0x005E6E30 (FUN_005E6E30, CAiTransportImpl::TransportAssignSlot)
     *
     * What it does:
     * Reserves attach-bone slots for `unit` using `hookIndex`.
     *
     * VFTable SLOT: 11
     */
    virtual bool TransportAssignSlot(Unit* unit, int hookIndex) = 0;

    /**
     * Address: 0x005E7100 (FUN_005E7100, CAiTransportImpl::TransportAttachUnit)
     *
     * VFTable SLOT: 12
     */
    virtual bool TransportAttachUnit(Unit* unit) = 0;

    /**
     * Address: 0x005E7170 (FUN_005E7170, CAiTransportImpl::TransportDetachUnit)
     *
     * What it does:
     * Detaches a transported `unit` from reserved transport bones.
     *
     * VFTable SLOT: 13
     */
    virtual bool TransportDetachUnit(Unit* unit) = 0;

    /**
     * Address: 0x005E73E0 (FUN_005E73E0, CAiTransportImpl::TransportDetachAllUnits)
     *
     * VFTable SLOT: 14
     */
    virtual EntitySetTemplate<Unit> TransportDetachAllUnits(bool clearReservations) = 0;

    /**
     * Address: 0x005E6690 (FUN_005E6690, CAiTransportImpl::TransportIsUnitAssignedForPickup)
     *
     * VFTable SLOT: 15
     */
    virtual bool TransportIsUnitAssignedForPickup(Unit* unit) const = 0;

    /**
     * Address: 0x005E66B0 (FUN_005E66B0, CAiTransportImpl::TransportGetPickupUnitPos)
     *
     * VFTable SLOT: 16
     */
    virtual SOCellPos TransportGetPickupUnitPos(Unit* unit) const = 0;

    /**
     * Address: 0x005E77B0 (FUN_005E77B0, CAiTransportImpl::TransportAtPickupPosition)
     *
     * VFTable SLOT: 17
     */
    virtual void TransportAtPickupPosition() = 0;

    /**
     * Address: 0x005E77C0 (FUN_005E77C0, CAiTransportImpl::TransportIsReadyForUnit)
     *
     * VFTable SLOT: 18
     */
    virtual bool TransportIsReadyForUnit(Unit* unit) const = 0;

    /**
     * Address: 0x005E7930 (FUN_005E7930, CAiTransportImpl::TransportGetAttachBone)
     *
     * VFTable SLOT: 19
     */
    virtual int TransportGetAttachBone(Unit* unit) const = 0;

    /**
     * Address: 0x005E77F0 (FUN_005E77F0, CAiTransportImpl::TransportGetAttachPosition)
     *
     * VFTable SLOT: 20
     */
    virtual SOCellPos TransportGetAttachPosition(Unit* unit) const = 0;

    /**
     * Address: 0x005E7950 (FUN_005E7950, CAiTransportImpl::TransportGetAttachBonePosition)
     *
     * VFTable SLOT: 21
     */
    virtual Wm3::Vec3f TransportGetAttachBonePosition(Unit* unit) const = 0;

    /**
     * Address: 0x005E7A60 (FUN_005E7A60, CAiTransportImpl::TransportGetAttachBoneTransform)
     *
     * VFTable SLOT: 22
     */
    virtual VTransform TransportGetAttachBoneTransform(Unit* unit) const = 0;

    /**
     * Address: 0x005E7AD0 (FUN_005E7AD0, CAiTransportImpl::TransportGetAttachFacing)
     *
     * VFTable SLOT: 23
     */
    virtual Wm3::Vec3f TransportGetAttachFacing(Unit* unit) const = 0;

    /**
     * Address: 0x005E7BB0 (FUN_005E7BB0, CAiTransportImpl::TransportGetPickupFacing)
     *
     * VFTable SLOT: 24
     */
    virtual Wm3::Vec3f TransportGetPickupFacing() const = 0;

    /**
     * Address: 0x005E7BE0 (FUN_005E7BE0, CAiTransportImpl::TransportAddToStorage)
     *
     * VFTable SLOT: 25
     */
    virtual void TransportAddToStorage(Unit* unit) = 0;

    /**
     * Address: 0x005E7CF0 (FUN_005E7CF0, CAiTransportImpl::TransportRemoveFromStorage)
     *
     * VFTable SLOT: 26
     */
    virtual void TransportRemoveFromStorage(Unit* unit, VTransform& outTransform) = 0;

    /**
     * Address: 0x005E7E60 (FUN_005E7E60, CAiTransportImpl::TransportGetStoredUnits)
     *
     * VFTable SLOT: 27
     */
    virtual EntitySetTemplate<Unit> TransportGetStoredUnits() const = 0;

    /**
     * Address: 0x005E8050 (FUN_005E8050, CAiTransportImpl::TransportIsStoredUnit)
     *
     * VFTable SLOT: 28
     */
    virtual bool TransportIsStoredUnit(Unit* unit) const = 0;

    /**
     * Address: 0x005E7E80 (FUN_005E7E80, CAiTransportImpl::TransportHasAvailableStorage)
     *
     * VFTable SLOT: 29
     */
    virtual bool TransportHasAvailableStorage() const = 0;

    /**
     * Address: 0x005E7EC0 (FUN_005E7EC0, CAiTransportImpl::TransportReserveStorage)
     *
     * VFTable SLOT: 30
     */
    virtual int TransportReserveStorage(Unit* unit, Wm3::Vec3f& outPos, Wm3::Vec3f& outFacing, float& outDropDist) = 0;

    /**
     * Address: 0x005E8020 (FUN_005E8020, CAiTransportImpl::TransportClearReservation)
     *
     * VFTable SLOT: 31
     */
    virtual void TransportClearReservation(Unit* unit) = 0;

    /**
     * Address: 0x005E8040 (FUN_005E8040, CAiTransportImpl::TransportResetReservation)
     *
     * VFTable SLOT: 32
     */
    virtual void TransportResetReservation() = 0;

    /**
     * Address: 0x005E6530 (FUN_005E6530, CAiTransportImpl::TransportUnreserveUnattachedSpots)
     *
     * VFTable SLOT: 33
     */
    virtual void TransportUnreserveUnattachedSpots() = 0;

    /**
     * Address: 0x005E5F10 (FUN_005E5F10, CAiTransportImpl::TransportRemoveFromWaitingList)
     *
     * VFTable SLOT: 34
     */
    virtual void TransportRemoveFromWaitingList(Unit* unit) = 0;

    /**
     * Address: 0x005E5EF0 (FUN_005E5EF0, CAiTransportImpl::TransportGetUnitsWaitingForPickup)
     *
     * VFTable SLOT: 35
     */
    virtual EntitySetTemplate<Unit> TransportGetUnitsWaitingForPickup() const = 0;

    /**
     * Address: 0x005E5F30 (FUN_005E5F30, CAiTransportImpl::TransportGetWaitingFormation)
     *
     * VFTable SLOT: 36
     */
    virtual IFormationInstance* TransportGetWaitingFormation() const = 0;

    /**
     * Address: 0x005E5F40 (FUN_005E5F40, CAiTransportImpl::TransportGenerateWaitingFormationForUnits)
     *
     * VFTable SLOT: 37
     */
    virtual void TransportGenerateWaitingFormationForUnits(const EntitySetTemplate<Unit>& units) = 0;

    /**
     * Address: 0x005E60A0 (FUN_005E60A0, CAiTransportImpl::TransportClearWaitingFormation)
     *
     * VFTable SLOT: 38
     */
    virtual void TransportClearWaitingFormation() = 0;

    /**
     * Address: 0x005E8080 (FUN_005E8080, CAiTransportImpl::TranspotSetTeleportDest)
     *
     * VFTable SLOT: 39
     */
    virtual void TranspotSetTeleportDest(Unit* beaconUnit) = 0;

    /**
     * Address: 0x005E8120 (FUN_005E8120, CAiTransportImpl::TransportGetTeleportDest)
     *
     * VFTable SLOT: 40
     */
    virtual Wm3::Vec3f TransportGetTeleportDest() const = 0;

    /**
     * Address: 0x005E81C0 (FUN_005E81C0, CAiTransportImpl::TransportGetTeleportBeacon)
     *
     * VFTable SLOT: 41
     */
    virtual Unit* TransportGetTeleportBeacon() const = 0;

    /**
     * Address: 0x005E81D0 (FUN_005E81D0, CAiTransportImpl::TransportIsTeleportBeaconReady)
     *
     * VFTable SLOT: 42
     */
    virtual bool TransportIsTeleportBeaconReady() const = 0;

  public:
    /**
     * What it does:
     * Sync-only helper aliasing the runtime teleport-beacon getter.
     */
    [[nodiscard]]
    Unit* TransportGetTeleportBeaconForSync() const;

  public:
    static gpg::RType* sType;
  };

  /**
   * Address: 0x005E87E0 (FUN_005E87E0, ?AI_CreateTransport@Moho@@YAPAVIAiTransport@1@PAVUnit@1@@Z)
   *
   * What it does:
   * Allocates one `CAiTransportImpl` bound to `unit` and returns it through
   * the `IAiTransport` interface lane.
   */
  [[nodiscard]] IAiTransport* AI_CreateTransport(Unit* unit);

  /**
   * Address: 0x00BCEFA0 (FUN_00BCEFA0, register_RBroadcasterRType_EAiTransportEvent)
   *
   * What it does:
   * Registers the broadcaster reflection lane for `EAiTransportEvent` and
   * installs process-exit cleanup.
   */
  int register_RBroadcasterRType_EAiTransportEvent();

  /**
   * Address: 0x00BCEFC0 (FUN_00BCEFC0, register_RListenerRType_EAiTransportEvent)
   *
   * What it does:
   * Registers the listener reflection lane for `EAiTransportEvent` and
   * installs process-exit cleanup.
   */
  int register_RListenerRType_EAiTransportEvent();

  /**
   * Address: 0x00BCEFE0 (FUN_00BCEFE0, register_RVectorType_int)
   *
   * What it does:
   * Registers `msvc8::vector<int>` reflection metadata and installs cleanup.
   */
  int register_RVectorType_int();

  /**
   * Address: 0x00BCF000 (FUN_00BCF000, register_RVectorType_SAiReservedTransportBone)
   *
   * What it does:
   * Registers `msvc8::vector<SAiReservedTransportBone>` reflection metadata and
   * installs cleanup.
   */
  int register_RVectorType_SAiReservedTransportBone();

  /**
   * Address: 0x00BCF020 (FUN_00BCF020, register_RVectorType_SAttachPoint)
   *
   * What it does:
   * Registers `msvc8::vector<SAttachPoint>` reflection metadata and installs
   * cleanup.
   */
  int register_RVectorType_SAttachPoint();

  static_assert(sizeof(IAiTransport) == 0x0C, "IAiTransport size must be 0x0C");
} // namespace moho
