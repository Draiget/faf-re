#pragma once

#include <cstddef>
#include <cstdint>
#include <vector>

#include "gpg/core/containers/FastVector.h"
#include "gpg/core/containers/Rect2.h"
#include "gpg/core/utils/BoostWrappers.h"
#include "legacy/containers/Vector.h"
#include "moho/ai/IAiReconDB.h"
#include "moho/entity/EntityCategoryLookupResolver.h"
#include "moho/entity/Entity.h"
#include "moho/misc/WeakPtr.h"
#include "moho/sim/STIMap.h"
#include "Wm3Box3.h"
#include "Wm3Vector3.h"

namespace moho
{
  class CArmyImpl;
  class CInfluenceMap;
  class Sim;

  /**
   * Raw map header used by CAiReconDBImpl for blip lookup tree ownership.
   *
   * Evidence:
   * - ctor: 0x005BFF90 writes head at +0x08 and size at +0x0C
   * - dtor: 0x005C23F0 tears down tree via helper + operator delete(head)
   */
  struct SReconBlipMapStorage
  {
    void* mAllocProxy; // +0x00
    void* mHead;       // +0x04
    std::uint32_t mSize; // +0x08
  };

  static_assert(sizeof(SReconBlipMapStorage) == 0x0C, "SReconBlipMapStorage size must be 0x0C");

  /**
   * Key payload used by `CAiReconDBImpl::mBlipMap` multimap.
   *
   * Address family:
   * - 0x005C4450 (`SReconKey` serializer registration)
   * - 0x005C4950/0x005C49B0 (entity-id range lower/upper bound)
   * - 0x005C5AF0 (insert path)
   *
   * What it does:
   * Stores source-unit weak-link state plus source entity id used as
   * map-order key for per-source blip range traversal.
   */
  struct SReconKey
  {
    WeakPtr<Unit> sourceUnit; // +0x00
    std::uint32_t sourceEntityId; // +0x08

    /**
     * Address: 0x005C90F0 (FUN_005C90F0, Moho::SReconKey::MemberDeserialize)
     *
     * What it does:
     * Deserializes source-unit weak pointer plus source entity-id payload.
     */
    void MemberDeserialize(gpg::ReadArchive* archive);

    /**
     * Address: 0x005C9170 (FUN_005C9170, Moho::SReconKey::MemberSerialize)
     *
     * What it does:
     * Serializes source-unit weak pointer plus source entity-id payload.
     */
    void MemberSerialize(gpg::WriteArchive* archive) const;

    static gpg::RType* sType;
  };
  static_assert(sizeof(SReconKey) == 0x0C, "SReconKey size must be 0x0C");
  static_assert(offsetof(SReconKey, sourceUnit) == 0x00, "SReconKey::sourceUnit offset must be 0x00");
  static_assert(offsetof(SReconKey, sourceEntityId) == 0x08, "SReconKey::sourceEntityId offset must be 0x08");

  /**
   * VFTABLE: 0x00E1D8D4
   * COL:  0x00E74388
   */
  class CAiReconDBImpl : public IAiReconDB
  {
  public:
    /**
     * Address: 0x005C0290 (FUN_005C0290, ??0CAiReconDBImpl@Moho@@QAE@XZ)
     *
     * What it does:
     * Initializes recon map/list/grid lanes with no owning army and fog-of-war
     * disabled.
     */
    CAiReconDBImpl();

    /**
     * Address: 0x005BFF90 (FUN_005BFF90, ??0CAiReconDBImpl@Moho@@QAE@PAVSimArmy@1@_N1@Z)
     *
     * What it does:
     * Initializes recon maps/grids from the owning army and optionally enables
     * fog-of-war vision/water grids.
     */
    CAiReconDBImpl(CArmyImpl* army, bool fogOfWar);

    /**
     * Address: 0x005C2300 (FUN_005C2300, scalar deleting thunk)
     * Address: 0x005C23F0 (FUN_005C23F0, full destructor body)
     *
     * VFTable SLOT: 0
     */
    ~CAiReconDBImpl() override;

    /**
     * Address: 0x005C0C40
     * VFTable SLOT: 1
     */
    void ReconTick(int dTicks) override;

    /**
     * Address: 0x005C14E0 (FUN_005C14E0)
     *
     * Moho::CAiReconDBImpl::ReconRefresh()
     *
     * IDA signature:
     * _DWORD *__thiscall Moho::CAiReconDBImpl::ReconRefresh(Moho::CAiReconDBImpl *this)
     *
     * What it does:
     * Traverses `mBlipMap` and refreshes each blip's per-army cached
     * payload from its source unit when that source still exists and is not
     * queued for destruction.
     *
     * VFTable SLOT: 2
     */
    void ReconRefresh() override;

    /**
     * Address: 0x005C18A0 (FUN_005C18A0, Moho::CAiReconDBImpl::ReconCanDetect)
     *
     * gpg::Rect2<int> const &, float, int
     *
     * What it does:
     * Computes recon flags for an area and merges allied-army recon state
     * before applying counter-intel suppression.
     *
     * VFTable SLOT: 3
     */
    [[nodiscard]]
    EReconFlags ReconCanDetect(const moho::Rect2<int>& rect, float y, int oldFlags) const override;

    /**
     * Address: 0x005C1850 (FUN_005C1850, Moho::CAiReconDBImpl::ReconCanDetect)
     *
     * Wm3::Vector3<float> const &, int
     *
     * What it does:
     * Classifies point medium (surface/underwater) and resolves detection
     * through the shared recon-flag aggregation path.
     *
     * VFTable SLOT: 4
     */
    [[nodiscard]]
    EReconFlags ReconCanDetect(const Wm3::Vec3f& pos, int oldFlags) const override;

    /**
     * Address: 0x005C18F0 (FUN_005C18F0, Moho::CAiReconDBImpl::ReconCanDetect)
     *
     * Entity *, Wm3::Vector3<float> const &, EReconFlags
     *
     * What it does:
     * Runs map/alliance/layer gating for an entity probe and resolves final
     * recon flags through the point recon helper chain.
     */
    [[nodiscard]] EReconFlags ReconCanDetect(Entity* ent, const Wm3::Vec3f& pos, EReconFlags oldFlags) const;

    /**
     * Address: 0x005C1720
     * VFTable SLOT: 5
     */
    void ReconGetBlips(const Wm3::Box3<float>& box, gpg::core::FastVector<Entity*>* outBlips) const override;

    /**
     * Address: 0x005C1640
     * VFTable SLOT: 6
     */
    void ReconGetBlips(const Wm3::Vec3f& center, float radius, gpg::core::FastVector<Entity*>* outBlips) const override;

    /**
     * Address: 0x005C1590
     * VFTable SLOT: 7
     */
    [[nodiscard]]
    const msvc8::vector<ReconBlip*>& ReconGetBlips() const override;

    /**
     * Address: 0x005C1A10
     * VFTable SLOT: 8
     */
    [[nodiscard]]
    boost::SharedPtrRaw<CIntelGrid> ReconGetVisionGrid() const override;

    /**
     * Address: 0x005C1A40
     * VFTable SLOT: 9
     */
    [[nodiscard]]
    boost::SharedPtrRaw<CIntelGrid> ReconGetWaterGrid() const override;

    /**
     * Address: 0x005C1A70
     * VFTable SLOT: 10
     */
    [[nodiscard]]
    boost::SharedPtrRaw<CIntelGrid> ReconGetRadarGrid() const override;

    /**
     * Address: 0x005C1AA0
     * VFTable SLOT: 11
     */
    [[nodiscard]]
    boost::SharedPtrRaw<CIntelGrid> ReconGetSonarGrid() const override;

    /**
     * Address: 0x005C1AD0
     * VFTable SLOT: 12
     */
    [[nodiscard]]
    boost::SharedPtrRaw<CIntelGrid> ReconGetOmniGrid() const override;

    /**
     * Address: 0x005C1B00
     * VFTable SLOT: 13
     */
    [[nodiscard]]
    boost::SharedPtrRaw<CIntelGrid> ReconGetRCIGrid() const override;

    /**
     * Address: 0x005C1B30
     * VFTable SLOT: 14
     */
    [[nodiscard]]
    boost::SharedPtrRaw<CIntelGrid> ReconGetSCIGrid() const override;

    /**
     * Address: 0x005C1B60
     * VFTable SLOT: 15
     */
    [[nodiscard]]
    boost::SharedPtrRaw<CIntelGrid> ReconGetVCIGrid() const override;

    /**
     * Address: 0x005C08F0
     * VFTable SLOT: 16
     */
    void ReconSetFogOfWar(bool enabled) override;

    /**
     * Address: 0x005C0910
     * VFTable SLOT: 17
     */
    [[nodiscard]]
    bool ReconGetFogOfWar() const override;

    /**
     * Address: 0x005C29C0 (nullsub_1553)
     *
     * What it does:
     * No-op checksum hook in this implementation.
     * VFTable SLOT: 18
     */
    void UpdateSimChecksum() override;

    /**
     * Address: 0x005C15A0
     * VFTable SLOT: 19
     */
    [[nodiscard]]
    ReconBlip* ReconGetBlip(Unit* unit) const override;

    /**
     * Address: 0x005C20C0
     * VFTable SLOT: 20
     */
    [[nodiscard]]
    EntitySetTemplate<Entity> ReconGetJamingBlips(Unit* unit) override;

    /**
     * Address: 0x005C05A0
     * VFTable SLOT: 21
     */
    void ReconFlushBlipsInRect(const moho::Rect2<int>& rect) override;

    /**
     * Address: 0x005C0370 (FUN_005C0370, Moho::CAiReconDBImpl::Flush)
     *
     * What it does:
     * Clears per-army recon flags for orphan + mapped blips, emits intel-loss
     * events, destroys unused blips, and resets map/list state.
     */
    void Flush();

    /**
     * Address: 0x005C36A0 (FUN_005C36A0, ??2CAiReconDBImpl@Moho@@QAE@@Z)
     *
     * What it does:
     * Allocates and constructs a CAiReconDBImpl instance.
     */
    [[nodiscard]]
    static CAiReconDBImpl* Create(CArmyImpl* army, bool fogOfWar);

  private:
  public:
    struct SNewBlip
    {
      Unit* sourceUnit;
      std::uint8_t fake;
      std::uint8_t pad_09_0B[0x03];
      EReconFlags detectedFlags;
    };
    static_assert(sizeof(SNewBlip) == 0x0C, "CAiReconDBImpl::SNewBlip size must be 0x0C");

  public:
    /**
     * Address: 0x005C07E0 (FUN_005C07E0, Moho::CAiReconDBImpl::CheckEvent)
     *
     * ReconBlip *, int, EReconFlags
     *
     * What it does:
     * Dispatches one `OnIntelChange` callback to army script for a single
     * recon-sense lane transition.
     */
    void CheckEvent(ReconBlip* blip, int newFlags, EReconFlags changedFlag);

    /**
     * Address: 0x005C0890 (FUN_005C0890, Moho::CAiReconDBImpl::CheckIntelEvents)
     *
     * ReconBlip *, int, int
     *
     * What it does:
     * Diffs old/new recon masks and emits lane-specific intel-change events.
     */
    void CheckIntelEvents(ReconBlip* blip, int oldFlags, int newFlags);

    /**
     * Address: 0x005C0A70 (FUN_005C0A70, Moho::CAiReconDBImpl::GenerateNewBlips)
     *
     * std::vector<SNewBlip> const &
     *
     * What it does:
     * Materializes pending blip requests, updates per-army state, and inserts
     * resulting blips into the typed blip map.
     */
    void GenerateNewBlips(const std::vector<SNewBlip>& pending);

    /**
     * Address: 0x005C1810 (FUN_005C1810, Moho::CAiReconDBImpl::IntelConfirmDead)
     *
     * ReconBlip *
     *
     * What it does:
     * Returns true when a blip should be treated as confirmed-dead for this
     * army (ally visibility or direct LOS probe).
     */
    [[nodiscard]] bool IntelConfirmDead(ReconBlip* blip);

    /**
     * Address: 0x005C0930 (FUN_005C0930)
     *
     * SNewBlip const &
     *
     * IDA signature:
     * Moho::ReconBlip *__thiscall Moho::CAiReconDBImpl::FindOrCreateBlip(
     *   Moho::CAiReconDBImpl::SNewBlip const *);
     *
     * What it does:
     * Reuses a matching source-unit blip when possible, otherwise allocates and
     * constructs a new `ReconBlip`.
     */
    [[nodiscard]] ReconBlip* FindOrCreateBlip(const SNewBlip& candidate);

    /**
     * Address: 0x005C1B90 (FUN_005C1B90)
     *
     * ReconBlip *,Unit *
     *
     * What it does:
     * Refreshes per-army recon snapshot payload for `blip`.
     */
    void RefreshBlip(ReconBlip* blip, Unit* sourceUnit);

    /**
     * Address: 0x005C1CF0 (FUN_005C1CF0)
     *
     * ReconBlip *,Unit *,unsigned int
     *
     * What it does:
     * Updates one blip's per-army recon flags and side effects for this army.
     */
    void UpdateBlip(ReconBlip* blip, Unit* sourceUnit, std::uint32_t newFlags);

    /**
     * Address: 0x005C1F80 (FUN_005C1F80)
     *
     * Unit *, EReconFlags, std::vector<SNewBlip> &
     *
     * What it does:
     * Updates all map-owned blips for one source unit, prunes excess fake
     * jammer blips, and appends pending fake-blip creation requests when needed.
     */
    void UpdateBlips(Unit* sourceUnit, EReconFlags detectedFlags, std::vector<SNewBlip>& pending);

    /**
     * Address: 0x005C21F0 (FUN_005C21F0)
     *
     * ReconBlip *
     *
     * What it does:
     * Clears this army's recon state on `blip` and destroys it if no longer used.
     */
    void DeleteBlip(ReconBlip* blip);

    /**
     * Address: 0x005C2230 (FUN_005C2230)
     *
     * Unit *
     *
     * What it does:
     * Clears this army's recon state for all map-owned blips from `sourceUnit`
     * and erases those blips from the typed recon map range.
     */
    void DeleteBlips(Unit* sourceUnit);

    /**
     * Address: 0x005C9720 (FUN_005C9720, sub_5C9720)
     *
     * gpg::Rect2<int> const &, EReconFlags, bool
     *
     * What it does:
     * Merges rectangle recon senses from this army + allies and applies
     * rectangle counter-intel filtering.
     */
    [[nodiscard]]
    EReconFlags GetReconFlagsForRect(const moho::Rect2<int>& rect, EReconFlags oldFlags, bool isUnderwater) const;

    /**
     * Address: 0x005C9600 (FUN_005C9600, Moho::CAiReconDBImpl::GetReconFlags)
     *
     * Entity *, Wm3::Vector3<float> const &, EReconFlags, bool
     *
     * What it does:
     * Merges point recon senses from this army and allied recon DBs, then
     * applies point counter-intel filtering.
     */
    [[nodiscard]]
    EReconFlags GetReconFlags(Entity* entity, const Wm3::Vec3f& pos, EReconFlags oldFlags, bool belowWater) const;

    /**
     * Address: 0x005CB360 (FUN_005CB360, Moho::CAiReconDBImpl::GetNewReconFor)
     *
     * Entity *, Wm3::Vector3<float> const &, EReconFlags, bool
     *
     * What it does:
     * Computes one-army point recon senses (LOS/radar/sonar/omni) before
     * counter-intel suppression.
     */
    [[nodiscard]]
    EReconFlags GetNewReconFor(Entity* entity, const Wm3::Vec3f& pos, EReconFlags oldFlags, bool belowWater) const;

    /**
     * Address: 0x005CB460 (FUN_005CB460, Moho::CAiReconDBImpl::ApplyReconCounters)
     *
     * Entity *, Wm3::Vector3<float> const &, EReconFlags
     *
     * What it does:
     * Applies point counter-intel and stealth/counter-stealth suppression to
     * raw recon flags.
     */
    [[nodiscard]]
    EReconFlags ApplyReconCounters(Entity* entity, const Wm3::Vec3f& pos, EReconFlags flags) const;

    /**
     * Address: 0x005CB520 (FUN_005CB520, Moho::CAiReconDBImpl::GetDetection)
     *
     * gpg::Rect2<int> const &, EReconFlags, bool
     *
     * What it does:
     * Evaluates direct detection senses (LOS/radar/sonar/omni) over one
     * rectangle for this army's recon grids.
     */
    [[nodiscard]] EReconFlags GetDetection(const moho::Rect2<int>& rect, EReconFlags oldFlags, bool isUnderwater) const;

    /**
     * Address: 0x005CB600 (FUN_005CB600, Moho::CAiReconDBImpl::DoCounterDetection)
     *
     * gpg::Rect2<int> const &, EReconFlags
     *
     * What it does:
     * Applies radar/sonar/LOS suppression against counter-intel coverage.
     */
    [[nodiscard]] EReconFlags DoCounterDetection(const moho::Rect2<int>& rect, EReconFlags flags) const;

    [[nodiscard]] static boost::SharedPtrRaw<CIntelGrid> MakeGrid(STIMap* map, std::uint32_t gridSize);

  public:
    static gpg::RType* sType;

    SReconBlipMapStorage mBlipMap;      // +0x04
    msvc8::vector<ReconBlip*> mBblips;  // +0x10
    msvc8::vector<ReconBlip*> mTempBlips; // +0x20
    CArmyImpl* mArmy;                   // +0x30
    STIMap* mMapData;                   // +0x34
    Sim* mSim;                          // +0x38
    CInfluenceMap* mIMap;               // +0x3C
    boost::SharedPtrRaw<CIntelGrid> mVisionGrid; // +0x40
    boost::SharedPtrRaw<CIntelGrid> mWaterGrid;  // +0x48
    boost::SharedPtrRaw<CIntelGrid> mRadarGrid;  // +0x50
    boost::SharedPtrRaw<CIntelGrid> mSonarGrid;  // +0x58
    boost::SharedPtrRaw<CIntelGrid> mOmniGrid;   // +0x60
    boost::SharedPtrRaw<CIntelGrid> mRCIGrid;    // +0x68
    boost::SharedPtrRaw<CIntelGrid> mSCIGrid;    // +0x70
    boost::SharedPtrRaw<CIntelGrid> mVCIGrid;    // +0x78
    CategoryWordRangeView mVisibleToReconCategory; // +0x80
    std::uint8_t mFogOfWar;              // +0xA8
    std::uint8_t mPadA9[0x07];           // +0xA9
  };

  static_assert(sizeof(CAiReconDBImpl) == 0xB0, "CAiReconDBImpl size must be 0xB0");
  static_assert(offsetof(CAiReconDBImpl, mBlipMap) == 0x04, "CAiReconDBImpl::mBlipMap offset must be 0x04");
  static_assert(offsetof(CAiReconDBImpl, mBblips) == 0x10, "CAiReconDBImpl::mBblips offset must be 0x10");
  static_assert(offsetof(CAiReconDBImpl, mTempBlips) == 0x20, "CAiReconDBImpl::mTempBlips offset must be 0x20");
  static_assert(offsetof(CAiReconDBImpl, mArmy) == 0x30, "CAiReconDBImpl::mArmy offset must be 0x30");
  static_assert(offsetof(CAiReconDBImpl, mMapData) == 0x34, "CAiReconDBImpl::mMapData offset must be 0x34");
  static_assert(offsetof(CAiReconDBImpl, mSim) == 0x38, "CAiReconDBImpl::mSim offset must be 0x38");
  static_assert(offsetof(CAiReconDBImpl, mIMap) == 0x3C, "CAiReconDBImpl::mIMap offset must be 0x3C");
  static_assert(offsetof(CAiReconDBImpl, mVisionGrid) == 0x40, "CAiReconDBImpl::mVisionGrid offset must be 0x40");
  static_assert(offsetof(CAiReconDBImpl, mWaterGrid) == 0x48, "CAiReconDBImpl::mWaterGrid offset must be 0x48");
  static_assert(offsetof(CAiReconDBImpl, mRadarGrid) == 0x50, "CAiReconDBImpl::mRadarGrid offset must be 0x50");
  static_assert(offsetof(CAiReconDBImpl, mSonarGrid) == 0x58, "CAiReconDBImpl::mSonarGrid offset must be 0x58");
  static_assert(offsetof(CAiReconDBImpl, mOmniGrid) == 0x60, "CAiReconDBImpl::mOmniGrid offset must be 0x60");
  static_assert(offsetof(CAiReconDBImpl, mRCIGrid) == 0x68, "CAiReconDBImpl::mRCIGrid offset must be 0x68");
  static_assert(offsetof(CAiReconDBImpl, mSCIGrid) == 0x70, "CAiReconDBImpl::mSCIGrid offset must be 0x70");
  static_assert(offsetof(CAiReconDBImpl, mVCIGrid) == 0x78, "CAiReconDBImpl::mVCIGrid offset must be 0x78");
  static_assert(
    offsetof(CAiReconDBImpl, mVisibleToReconCategory) == 0x80,
    "CAiReconDBImpl::mVisibleToReconCategory offset must be 0x80"
  );
  static_assert(offsetof(CAiReconDBImpl, mFogOfWar) == 0xA8, "CAiReconDBImpl::mFogOfWar offset must be 0xA8");
} // namespace moho
