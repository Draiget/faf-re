#pragma once

#include "gpg/core/reflection/Reflection.h"
#include "moho/entity/ECollisionBeamEvent.h"

namespace moho
{
  // Address-backed collision-beam debug toggle convar payload.
  extern bool dbg_CollisionBeam;

  // Address-backed collision-beam startup trigonometric cache values.
  extern float gCollisionBeamConeCosine;
  extern float gCollisionBeamConeAxisScaleX;
  extern float gCollisionBeamConeSine;
  extern float gCollisionBeamConeAxisScaleY;

  class ECollisionBeamEventTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x00672CC0 (FUN_00672CC0, Moho::ECollisionBeamEventTypeInfo::ECollisionBeamEventTypeInfo)
     */
    ECollisionBeamEventTypeInfo();

    /**
     * Address: 0x00BFC2D0 (FUN_00BFC2D0, Moho::ECollisionBeamEventTypeInfo::dtr)
     */
    ~ECollisionBeamEventTypeInfo() override;

    /**
     * Address: 0x00672D40 (FUN_00672D40, Moho::ECollisionBeamEventTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00672D20 (FUN_00672D20, Moho::ECollisionBeamEventTypeInfo::Init)
     */
    void Init() override;

    /**
     * Address lane: ECollisionBeamEventTypeInfo::Init helper call.
     *
     * What it does:
     * Registers enumerator literals for the reflected enum when available.
     */
    static void AddEnums(gpg::REnumType* typeInfo);
  };

  static_assert(sizeof(ECollisionBeamEventTypeInfo) == 0x78, "ECollisionBeamEventTypeInfo size must be 0x78");

  /**
   * Address: 0x00BD4BA0 (FUN_00BD4BA0, register_TConVar_dbg_CollisionBeam)
   *
   * What it does:
   * Registers startup `dbg_CollisionBeam` `TConVar<bool>` and installs exit cleanup.
   */
  void register_TConVar_dbg_CollisionBeam();

  /**
   * Address: 0x00BD4B40 (FUN_00BD4B40, initialize_CollisionBeamTrigConstants)
   *
   * What it does:
   * Precomputes sin/cos constants for the collision-beam startup cone angle.
   */
  void initialize_CollisionBeamTrigConstants();

  /**
   * Address: 0x00BD4C20 (FUN_00BD4C20, register_ECollisionBeamEventTypeInfo)
   *
   * What it does:
   * Constructs/preregisters `ECollisionBeamEventTypeInfo` and installs exit cleanup.
   */
  void register_ECollisionBeamEventTypeInfo();

  /**
   * Address: 0x00BFC2D0 (FUN_00BFC2D0, cleanup_ECollisionBeamEventTypeInfo)
   *
   * What it does:
   * Tears down startup `ECollisionBeamEventTypeInfo` storage.
   */
  void cleanup_ECollisionBeamEventTypeInfo();

  /**
   * Address: 0x00BD4D90 (FUN_00BD4D90, register_ManyToOneBroadcaster_ECollisionBeamEvent_TypeInfo)
   *
   * What it does:
   * Constructs/preregisters startup type-info for
   * `ManyToOneBroadcaster<ECollisionBeamEvent>` and installs exit cleanup.
   */
  int register_ManyToOneBroadcaster_ECollisionBeamEvent_TypeInfo();

  /**
   * Address: 0x00BFC5B0 (FUN_00BFC5B0, cleanup_ManyToOneBroadcaster_ECollisionBeamEvent_TypeInfo)
   *
   * What it does:
   * Tears down startup type-info storage for
   * `ManyToOneBroadcaster<ECollisionBeamEvent>`.
   */
  void cleanup_ManyToOneBroadcaster_ECollisionBeamEvent_TypeInfo();

  /**
   * Address: 0x00BD4DB0 (FUN_00BD4DB0, register_ManyToOneListener_ECollisionBeamEvent_TypeInfo)
   *
   * What it does:
   * Constructs/preregisters startup type-info for
   * `ManyToOneListener<ECollisionBeamEvent>` and installs exit cleanup.
   */
  int register_ManyToOneListener_ECollisionBeamEvent_TypeInfo();

  /**
   * Address: 0x00BFC550 (FUN_00BFC550, cleanup_ManyToOneListener_ECollisionBeamEvent_TypeInfo)
   *
   * What it does:
   * Tears down startup type-info storage for
   * `ManyToOneListener<ECollisionBeamEvent>`.
   */
  void cleanup_ManyToOneListener_ECollisionBeamEvent_TypeInfo();
} // namespace moho
