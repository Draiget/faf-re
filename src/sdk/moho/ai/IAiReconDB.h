#pragma once

#include <cstdint>

#include "gpg/core/containers/FastVector.h"
#include "gpg/core/containers/Rect2.h"
#include "gpg/core/utils/BoostWrappers.h"
#include "legacy/containers/Vector.h"
#include "Wm3Box3.h"
#include "Wm3Vector3.h"

namespace gpg
{
  class RType;
}

namespace moho
{
  class CIntelGrid;
  class Entity;
  class ReconBlip;
  class Unit;
  template <class T>
  class EntitySetTemplate;

  /**
   * Address family:
   * - 0x005C64550 (`CAiReconDBImpl::GetReconFlags` lexical helper chain)
   *
   * What it does:
   * Bitmask describing current reconnaissance knowledge for one contact.
   */
  enum EReconFlags : std::int32_t
  {
    RECON_None = 0x00,
    RECON_Radar = 0x01,
    RECON_Sonar = 0x02,
    RECON_Omni = 0x04,
    RECON_LOSNow = 0x08,
    RECON_LOSEver = 0x10,
    RECON_KnownFake = 0x20,
    RECON_MaybeDead = 0x40,

    RECON_RadarSonar = RECON_Radar | RECON_Sonar,
    RECON_AnyPing = RECON_Radar | RECON_Sonar | RECON_Omni,
    RECON_Exposed = RECON_Omni | RECON_LOSNow | RECON_LOSEver,
    RECON_AnySense = RECON_Radar | RECON_Sonar | RECON_Omni | RECON_LOSNow,
  };

  /**
   * VFTABLE: 0x00E1D7C4
   * COL:  0x00E74750
   */
  class IAiReconDB
  {
  public:
    /**
     * Address: 0x005BE010 (??1IAiReconDB@Moho@@UAE@XZ)
     *
     * VFTable SLOT: 0
     */
    virtual ~IAiReconDB();

    /**
     * Address: 0x005C0C40 (FUN_005C0C40)
     *
     * VFTable SLOT: 1
     */
    virtual void ReconTick(int dTicks) = 0;

    /**
     * Address: 0x005C14E0 (FUN_005C14E0)
     *
     * VFTable SLOT: 2
     */
    virtual void ReconRefresh() = 0;

    /**
     * Address: 0x005C18A0 (FUN_005C18A0)
     *
     * VFTable SLOT: 3
     */
    [[nodiscard]]
    virtual EReconFlags ReconCanDetect(const moho::Rect2<int>& rect, float y, int oldFlags) const = 0;

    /**
     * Address: 0x005C1850 (FUN_005C1850)
     *
     * VFTable SLOT: 4
     */
    [[nodiscard]]
    virtual EReconFlags ReconCanDetect(const Wm3::Vec3f& pos, int oldFlags) const = 0;

    /**
     * Address: 0x005C1720 (FUN_005C1720)
     *
     * VFTable SLOT: 5
     */
    virtual void ReconGetBlips(const Wm3::Box3f& box, gpg::core::FastVector<Entity*>* outBlips) const = 0;

    /**
     * Address: 0x005C1640 (FUN_005C1640)
     *
     * VFTable SLOT: 6
     */
    virtual void ReconGetBlips(const Wm3::Vec3f& center, float radius, gpg::core::FastVector<Entity*>* outBlips) const = 0;

    /**
     * Address: 0x005C1590 (FUN_005C1590)
     *
     * VFTable SLOT: 7
     */
    [[nodiscard]]
    virtual const msvc8::vector<ReconBlip*>& ReconGetBlips() const = 0;

    /**
     * Address: 0x005C1A10 (FUN_005C1A10)
     *
     * VFTable SLOT: 8
     */
    [[nodiscard]]
    virtual boost::SharedPtrRaw<CIntelGrid> ReconGetVisionGrid() const = 0;

    /**
     * Address: 0x005C1A40 (FUN_005C1A40)
     *
     * VFTable SLOT: 9
     */
    [[nodiscard]]
    virtual boost::SharedPtrRaw<CIntelGrid> ReconGetWaterGrid() const = 0;

    /**
     * Address: 0x005C1A70 (FUN_005C1A70)
     *
     * VFTable SLOT: 10
     */
    [[nodiscard]]
    virtual boost::SharedPtrRaw<CIntelGrid> ReconGetRadarGrid() const = 0;

    /**
     * Address: 0x005C1AA0 (FUN_005C1AA0)
     *
     * VFTable SLOT: 11
     */
    [[nodiscard]]
    virtual boost::SharedPtrRaw<CIntelGrid> ReconGetSonarGrid() const = 0;

    /**
     * Address: 0x005C1AD0 (FUN_005C1AD0)
     *
     * VFTable SLOT: 12
     */
    [[nodiscard]]
    virtual boost::SharedPtrRaw<CIntelGrid> ReconGetOmniGrid() const = 0;

    /**
     * Address: 0x005C1B00 (FUN_005C1B00)
     *
     * VFTable SLOT: 13
     */
    [[nodiscard]]
    virtual boost::SharedPtrRaw<CIntelGrid> ReconGetRCIGrid() const = 0;

    /**
     * Address: 0x005C1B30 (FUN_005C1B30)
     *
     * VFTable SLOT: 14
     */
    [[nodiscard]]
    virtual boost::SharedPtrRaw<CIntelGrid> ReconGetSCIGrid() const = 0;

    /**
     * Address: 0x005C1B60 (FUN_005C1B60)
     *
     * VFTable SLOT: 15
     */
    [[nodiscard]]
    virtual boost::SharedPtrRaw<CIntelGrid> ReconGetVCIGrid() const = 0;

    /**
     * Address: 0x005C08F0 (FUN_005C08F0)
     *
     * VFTable SLOT: 16
     */
    virtual void ReconSetFogOfWar(bool enabled) = 0;

    /**
     * Address: 0x005C0910 (FUN_005C0910)
     *
     * VFTable SLOT: 17
     */
    [[nodiscard]]
    virtual bool ReconGetFogOfWar() const = 0;

    /**
     * Address: 0x005C29C0 (FUN_005C29C0, nullsub_1553)
     *
     * VFTable SLOT: 18
     */
    virtual void UpdateSimChecksum();

    /**
     * Address: 0x005C15A0 (FUN_005C15A0)
     *
     * VFTable SLOT: 19
     */
    [[nodiscard]]
    virtual ReconBlip* ReconGetBlip(Unit* unit) const = 0;

    /**
     * Address: 0x005C20C0 (FUN_005C20C0)
     *
     * VFTable SLOT: 20
     */
    [[nodiscard]]
    virtual EntitySetTemplate<Entity> ReconGetJamingBlips(Unit* unit) = 0;

    /**
     * Address: 0x005C05A0 (FUN_005C05A0)
     *
     * VFTable SLOT: 21
     */
    virtual void ReconFlushBlipsInRect(const moho::Rect2<int>& rect) = 0;

  public:
    static gpg::RType* sType;
  };

  static_assert(sizeof(IAiReconDB) == 0x04, "IAiReconDB size must be 0x04");
} // namespace moho
