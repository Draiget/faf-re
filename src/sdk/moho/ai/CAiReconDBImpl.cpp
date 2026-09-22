#include "moho/ai/CAiReconDBImpl.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <limits>
#include <new>
#include <stdexcept>
#include <string>
#include <utility>
#include <vector>

#include "moho/ai/CAiBrain.h"
#include "moho/animation/CAniActor.h"
#include "moho/entity/EntityDb.h"
#include "moho/entity/EntityCollisionUpdater.h"
#include "moho/entity/intel/CIntel.h"
#include "moho/particles/SWorldBeam.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/CIntelGrid.h"
#include "moho/sim/CInfluenceMap.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/ReconBlip.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/SFootprint.h"
#include "moho/sim/Sim.h"
#include "moho/unit/core/Unit.h"

using namespace moho;

namespace
{



  void LinkKeyToSourceChain(SReconKey& key) noexcept
  {
    key.sourceUnit.LinkIntoOwnerChainHeadUnlinked();
  }

  /**
   * Address: 0x005C2360 (FUN_005C2360)
   *
   * What it does:
   * Unlinks one weak-link node from its owner chain.
   */
  void UnlinkKeyFromSourceChain(SReconKey& key) noexcept
  {
    key.sourceUnit.UnlinkFromOwnerChain();
  }

  [[nodiscard]] std::uint32_t GetSourceEntityId(const Unit* const source) noexcept
  {
    return source ? static_cast<std::uint32_t>(source->id_) : 0u;
  }

  [[nodiscard]] SReconKey MakeReconProbeKey(const std::uint32_t sourceEntityId) noexcept
  {
    SReconKey probe{};
    probe.sourceEntityId = sourceEntityId;
    return probe;
  }

  [[nodiscard]] SReconKey MakeReconMapKey(Unit* const sourceUnit) noexcept
  {
    SReconKey key{};
    key.sourceUnit.BindObjectUnlinked(sourceUnit);
    key.sourceEntityId = GetSourceEntityId(sourceUnit);
    return key;
  }

  [[nodiscard]] std::pair<ReconBlipMap::iterator, ReconBlipMap::iterator>
  FindReconBlipRange(CAiReconDBImpl* const owner, Unit* const sourceUnit)
  {
    return owner->mBlipMap.equal_range(MakeReconProbeKey(GetSourceEntityId(sourceUnit)));
  }

  [[nodiscard]] bool IsInsideRectXZ(const moho::Rect2<int>& rect, const Wm3::Vec3f& pos) noexcept
  {
    return pos.x >= static_cast<float>(rect.x0) && pos.x <= static_cast<float>(rect.x1) &&
      pos.z >= static_cast<float>(rect.z0) && pos.z <= static_cast<float>(rect.z1);
  }

  [[nodiscard]] bool IsInsideRadiusXZ(const Wm3::Vec3f& center, const float radius, const Wm3::Vec3f& pos) noexcept
  {
    const float dx = pos.x - center.x;
    const float dz = pos.z - center.z;
    return (dx * dx) + (dz * dz) <= (radius * radius);
  }

  /**
   * Point visibility against one intel grid.
   *
   * Both point-recon lanes reach the grid through
   * `?IsVisible@CIntelGrid@Moho@@QBE_NABV?$Vector3@M@Wm3@@@Z` (0x005BE1C0) --
   * the `Vec3f` overload -- at every one of their seven call sites:
   * `GetNewReconFor` at 0x005CB3B6, 0x005CB40B, 0x005CB42C and 0x005CB446, and
   * `ApplyReconCounters` at 0x005CB4A2, 0x005CB4B7 and 0x005CB4D6. That
   * overload divides the world position by `mGridSize` and tests exactly one
   * grid cell.
   */
  [[nodiscard]] bool IsGridVisibleAtPoint(const CIntelGrid* const grid, const Wm3::Vec3f& pos)
  {
    return grid && grid->IsVisible(pos);
  }

  [[nodiscard]] bool IsWithinPlayableMapRadius(
    const STIMap* const map,
    const Wm3::Vec3f& pos,
    const float radius,
    const bool ignorePlayableRect
  ) noexcept
  {
    if (!map) {
      return true;
    }

    float minX = 0.0f;
    float minZ = 0.0f;
    float maxX = std::numeric_limits<float>::infinity();
    float maxZ = std::numeric_limits<float>::infinity();

    const CHeightField* const heightField = map->mHeightField.get();
    if (heightField) {
      maxX = static_cast<float>(heightField->width);
      maxZ = static_cast<float>(heightField->height);
    }

    if (!ignorePlayableRect) {
      minX = std::max(minX, static_cast<float>(map->mPlayableRect.x0));
      minZ = std::max(minZ, static_cast<float>(map->mPlayableRect.z0));
      maxX = std::min(maxX, static_cast<float>(map->mPlayableRect.x1));
      maxZ = std::min(maxZ, static_cast<float>(map->mPlayableRect.z1));
    }

    if (maxX < minX || maxZ < minZ) {
      return false;
    }

    return pos.x >= minX + radius && pos.x <= maxX - radius && pos.z >= minZ + radius && pos.z <= maxZ - radius;
  }

  [[nodiscard]] EReconFlags SetFlag(const EReconFlags value, const EReconFlags bit) noexcept
  {
    return static_cast<EReconFlags>(static_cast<std::int32_t>(value) | static_cast<std::int32_t>(bit));
  }

  [[nodiscard]] EReconFlags MergeFlags(const EReconFlags lhs, const EReconFlags rhs) noexcept
  {
    return static_cast<EReconFlags>(static_cast<std::int32_t>(lhs) | static_cast<std::int32_t>(rhs));
  }

  [[nodiscard]] EReconFlags ClearFlag(const EReconFlags value, const EReconFlags bit) noexcept
  {
    return static_cast<EReconFlags>(static_cast<std::int32_t>(value) & ~static_cast<std::int32_t>(bit));
  }

  [[nodiscard]] bool HasFlag(const EReconFlags value, const EReconFlags bit) noexcept
  {
    return (static_cast<std::int32_t>(value) & static_cast<std::int32_t>(bit)) != 0;
  }

  [[nodiscard]] bool UsesWaterSenseLane(const ELayer layer) noexcept
  {
    constexpr std::int32_t kWaterSenseMask = static_cast<std::int32_t>(LAYER_Sub) | static_cast<std::int32_t>(LAYER_Water);
    return (static_cast<std::int32_t>(layer) & kWaterSenseMask) != 0;
  }

  [[nodiscard]] const char* ReconSenseLexical(const EReconFlags sense) noexcept
  {
    switch (sense) {
      case RECON_LOSNow:
        return "LOSNow";
      case RECON_Radar:
        return "Radar";
      case RECON_Sonar:
        return "Sonar";
      case RECON_Omni:
        return "Omni";
      default:
        return "Unknown";
    }
  }

  [[nodiscard]] bool IsAlliedOrSameArmy(const CArmyImpl* const viewer, const CArmyImpl* const owner) noexcept
  {
    if (!viewer || !owner) {
      return false;
    }

    if (viewer == owner) {
      return true;
    }

    if (owner->mConstDat.mArmyIndex < 0) {
      return false;
    }

    return viewer->mVarDat.mAllies.Contains(static_cast<std::uint32_t>(owner->mConstDat.mArmyIndex));
  }

  [[nodiscard]] Unit* DecodeBlipSourceUnit(ReconBlip* const blip) noexcept
  {
    return blip ? blip->GetSourceUnit() : nullptr;
  }

  [[nodiscard]] bool IsFakeBlip(ReconBlip* const blip) noexcept
  {
    return blip && blip->IsFake();
  }

  [[nodiscard]] SPerArmyReconInfo* GetPerArmyReconSlot(
    ReconBlip* const blip, const std::int32_t armyIndex
  ) noexcept
  {
    return blip ? blip->GetPerArmyReconInfo(armyIndex) : nullptr;
  }

  [[nodiscard]] std::int32_t GetActiveJammerBlipCount(const Unit* const unit) noexcept
  {
    if (!unit) {
      return 0;
    }

    const CIntel* const intel = unit->GetIntelManager();
    if (!intel || !intel->HasActiveJamming()) {
      return 0;
    }

    const RUnitBlueprint* const blueprint = unit->GetBlueprint();
    if (!blueprint) {
      return 0;
    }

    return static_cast<std::int32_t>(blueprint->Intel.JammerBlips);
  }

  /**
   * "Does the blip's own army count the viewer as an ally?"
   *
   * The direction matters and it is the opposite of `IsAlliedOrSameArmy`.
   * `ReconTick` loads the VIEWER's army index and tests it against the BLIP
   * army's ally set (0x005C0CC0 `mov ecx,[esi+30h]` / `mov eax,[ecx+8]` ->
   * viewer army index; 0x005C0CCB `mov ecx,[edi+14Ch]` -> blip->ArmyRef; then
   * the set is read out of THAT army at `[ecx+0E8h]` / `[ecx+0F0h]` /
   * `[ecx+0F4h]`). `ReconCanDetect` at 0x005C193C asks the question the other
   * way round, which is why both forms exist in this file -- with asymmetric
   * alliances they are genuinely different answers.
   *
   * An unfocused viewer (index -1) short-circuits to false at 0x005C0CC6
   * `cmp eax,-1`, leaving the decision to the LOS probe beside this call.
   */
  [[nodiscard]] bool BlipArmyTreatsViewerAsAlly(CAiReconDBImpl* const owner, ReconBlip* const blip) noexcept
  {
    if (!owner || !blip || !owner->mArmy) {
      return false;
    }

    const std::int32_t viewerArmyId = owner->mArmy->mConstDat.mArmyIndex;
    if (viewerArmyId == -1) {
      return false;
    }

    CArmyImpl* const blipArmy = reinterpret_cast<Entity*>(blip)->ArmyRef;
    if (!blipArmy) {
      return false;
    }

    return blipArmy->mVarDat.mAllies.Contains(static_cast<std::uint32_t>(viewerArmyId));
  }

  [[nodiscard]] Wm3::Vec3f BlipProbePosition(ReconBlip* const blip) noexcept
  {
    if (!blip) {
      return {};
    }

    return reinterpret_cast<Entity*>(blip)->PendingPosition;
  }

  /**
   * Address: 0x005C9830 (FUN_005C9830)
   *
   * What it does:
   * Forwards one entity-backed blip lane into `CInfluenceMap::UpdateBlipPosition`
   * using `Entity::id_`, current `Entity::Position`, and current blueprint.
   */
  [[maybe_unused]] void UpdateInfluenceMapFromEntityState(
    Entity* const blipEntity,
    CInfluenceMap* const influenceMap
  )
  {
    const auto blipId = static_cast<std::uint32_t>(blipEntity->id_);
    const RUnitBlueprint* const blueprint = static_cast<const RUnitBlueprint*>(blipEntity->BluePrint);
    influenceMap->UpdateBlipPosition(blipId, blipEntity->mVarDat.mCurTransform.pos_, blueprint);
  }

  [[nodiscard]] bool DoesBlipSourceCollideBox(ReconBlip* const blip, const Wm3::Box3f& box) noexcept
  {
    Unit* const sourceUnit = DecodeBlipSourceUnit(blip);
    if (!sourceUnit) {
      return false;
    }

    EntityCollisionUpdater* const collision = sourceUnit->CollisionExtents;
    if (!collision) {
      return false;
    }

    CollisionPairResult overlap{};
    return collision->CollideBox(&box, &overlap);
  }

  void SeedReconMapFromBlipList(CAiReconDBImpl* const owner)
  {
    if (!owner || !owner->mBlipMap.empty()) {
      return;
    }

    for (ReconBlip* const blip : owner->mBblips) {
      if (!blip) {
        continue;
      }
      (void)owner->mBlipMap.insert({MakeReconMapKey(DecodeBlipSourceUnit(blip)), blip});
    }
  }

  void RebuildBlipListFromMapAndOrphans(CAiReconDBImpl* const owner)
  {
    if (!owner) {
      return;
    }

    const std::size_t targetCount = owner->mBlipMap.size() + owner->mTempBlips.size();
    owner->mBblips.resize(targetCount, nullptr);

    std::size_t writeIndex = 0u;
    for (const auto& entry : owner->mBlipMap) {
      if (entry.second) {
        owner->mBblips.begin()[writeIndex] = entry.second;
        ++writeIndex;
      }
    }

    for (ReconBlip* const orphan : owner->mTempBlips) {
      if (orphan) {
        owner->mBblips.begin()[writeIndex] = orphan;
        ++writeIndex;
      }
    }

    owner->mBblips.resize(writeIndex, nullptr);
  }

  void AppendUniqueBlip(msvc8::vector<ReconBlip*>& values, ReconBlip* const blip)
  {
    if (!blip) {
      return;
    }
    if (std::find(values.begin(), values.end(), blip) != values.end()) {
      return;
    }
    values.push_back(blip);
  }

  void ClearPerArmyRecon(
    CAiReconDBImpl* const owner, ReconBlip* const blip, const bool emitIntelEvents
  )
  {
    if (!owner || !owner->mArmy || !blip) {
      return;
    }

    const std::int32_t armyIndex = owner->mArmy->mConstDat.mArmyIndex;
    SPerArmyReconInfo* const recon = GetPerArmyReconSlot(blip, armyIndex);
    if (!recon) {
      return;
    }

    const int oldFlags = static_cast<int>(recon->mReconFlags);
    if (emitIntelEvents && oldFlags != 0) {
      owner->CheckIntelEvents(blip, oldFlags, 0);
    }
    recon->mNeedsFlush = 0u;
    recon->mReconFlags = 0u;
  }

  /**
   * Address: 0x005C4CA0 (FUN_005C4CA0)
   *
   * What it does:
   * Appends one pending-new-blip request into the temporary generation vector.
   *
   * DB-integrity fix: `pending` was previously typed `std::vector<SNewBlip>`,
   * which does not match this binary -- `SNewBlip` is a 12-byte trivially-
   * copyable POD (`Unit* sourceUnit; uint8_t fake; EReconFlags
   * detectedFlags;`) and `push_back`'s growth-fill emission at this call
   * site (`FUN_005CBC70`, a 3-dword-stride uninit_fill_n loop) matches
   * `msvc8::vector<T>::push_back`'s shape exactly, not the real STL's.
   * Retyped to `msvc8::vector<SNewBlip>` across this helper, `GenerateNewBlips`,
   * and `UpdateBlips` (see their own citations) to match the binary; this
   * caller now correctly reaches `legacy/containers/Vector.h`'s shared
   * `push_back` template member.
   */
  void AppendPendingNewBlip(
    msvc8::vector<CAiReconDBImpl::SNewBlip>& pending,
    Unit* const sourceUnit,
    const std::uint8_t fake,
    const EReconFlags detectedFlags
  )
  {
    pending.push_back(CAiReconDBImpl::SNewBlip{
      .sourceUnit = sourceUnit,
      .fake = fake,
      .detectedFlags = detectedFlags,
    });
  }

  [[nodiscard]] EReconFlags ReconCanDetectEntity(
    const CAiReconDBImpl* const owner, Entity* const entity, const Wm3::Vec3f& pos, const EReconFlags oldFlags
  )
  {
    return owner ? owner->ReconCanDetect(entity, pos, oldFlags) : RECON_None;
  }

  void TickAllReconGrids(CAiReconDBImpl* const owner, const int dTicks)
  {
    if (!owner) {
      return;
    }

    if (owner->mVisionGrid.px) {
      owner->mVisionGrid.px->Tick(dTicks);
    }
    if (owner->mWaterGrid.px) {
      owner->mWaterGrid.px->Tick(dTicks);
    }
    if (owner->mRadarGrid.px) {
      owner->mRadarGrid.px->Tick(dTicks);
    }
    if (owner->mSonarGrid.px) {
      owner->mSonarGrid.px->Tick(dTicks);
    }
    if (owner->mOmniGrid.px) {
      owner->mOmniGrid.px->Tick(dTicks);
    }
    if (owner->mRCIGrid.px) {
      owner->mRCIGrid.px->Tick(dTicks);
    }
    if (owner->mSCIGrid.px) {
      owner->mSCIGrid.px->Tick(dTicks);
    }
    if (owner->mVCIGrid.px) {
      owner->mVCIGrid.px->Tick(dTicks);
    }
  }
} // namespace

gpg::RType* SReconKey::sType = nullptr;
gpg::RType* CAiReconDBImpl::sType = nullptr;

/**
 * Address: 0x005C0290 (FUN_005C0290, ??0CAiReconDBImpl@Moho@@QAE@XZ)
 *
 * What it does:
 * Builds an empty recon DB instance with no owning army and all recon grids
 * released.
 */
CAiReconDBImpl::CAiReconDBImpl()
  : CAiReconDBImpl(nullptr, false)
{
}

/**
 * Address: 0x005BFF90 (FUN_005BFF90, ??0CAiReconDBImpl@Moho@@QAE@PAVSimArmy@1@_N1@Z)
 *
 * Address: 0x005C91F0 (FUN_005C91F0, ??4shared_ptr_CIntelGrid@boost@@QAE@@Z) --
 * boost::shared_ptr<CIntelGrid>::operator=, the emission invoked via
 * boost::ResetSharedPtrRawOwning at all 8 grid-assignment call sites below
 * (e.g. 0x005C00D7).
 */
CAiReconDBImpl::CAiReconDBImpl(CArmyImpl* const army, const bool fogOfWar) :
    mBlipMap{},
    mBblips{},
    mTempBlips{},
    mArmy(army),
    mMapData(nullptr),
    mSim(nullptr),
    mIMap(nullptr),
    mVisionGrid{},
    mWaterGrid{},
    mRadarGrid{},
    mSonarGrid{},
    mOmniGrid{},
    mRCIGrid{},
    mSCIGrid{},
    mVCIGrid{},
    mVisibleToReconCategory{},
    mFogOfWar(static_cast<std::uint8_t>(fogOfWar ? 1u : 0u)),
    mPadA9{0, 0, 0, 0, 0, 0, 0}
{


  if (!mArmy) {
    return;
  }

  mSim = mArmy->GetSim();
  mMapData = mSim ? mSim->mMapData : nullptr;
  mIMap = mArmy->GetIGrid();

  {
    const EntityCategorySet* const category =
      (mSim && mSim->mRules) ? mSim->mRules->GetEntityCategory("VISIBLETORECON") : nullptr;
    if (category) {
      mVisibleToReconCategory = *category;
    }

    // TEMPORARY PROBE -- delete once resolved.
    //
    // ReconTick gates EVERY candidate on this set
    // (`mVisibleToReconCategory.ContainsBit(bp->mCategoryBitIndex)`), and the
    // set is captured here, once, at army construction. If "VISIBLETORECON" is
    // not registered yet at this point -- categories come from Lua -- the set
    // stays empty for the army's whole life, no blip is ever created, and every
    // downstream symptom follows at once: nothing is ever seen (fog), nothing
    // auto-acquires, attack-ground finds no target, and clicking an enemy
    // issues nothing. ContainsBit itself is verified against the binary's
    // `(ord>>5) - ordinalStart` / `ord & 0x1F` test, so an empty set is the
    // only way this gate can reject everything.
    gpg::Warnf(
      "[RECONCAT] army=%d sim=%p rules=%p resolved=%d words=%u fog=%u",
      static_cast<int>(mArmy->mConstDat.mArmyIndex),
      static_cast<void*>(mSim),
      static_cast<void*>(mSim ? mSim->mRules : nullptr),
      (category != nullptr) ? 1 : 0,
      static_cast<unsigned>(mVisibleToReconCategory.WordCount()),
      static_cast<unsigned>(mFogOfWar)
    );
  }

  boost::ResetSharedPtrRawOwning(mRadarGrid, MakeGrid(mMapData, 4));
  boost::ResetSharedPtrRawOwning(mSonarGrid, MakeGrid(mMapData, 4));
  boost::ResetSharedPtrRawOwning(mOmniGrid, MakeGrid(mMapData, 4));
  boost::ResetSharedPtrRawOwning(mRCIGrid, MakeGrid(mMapData, 4));
  boost::ResetSharedPtrRawOwning(mSCIGrid, MakeGrid(mMapData, 4));
  boost::ResetSharedPtrRawOwning(mVCIGrid, MakeGrid(mMapData, 4));

  if (fogOfWar) {
    boost::ResetSharedPtrRawOwning(mVisionGrid, MakeGrid(mMapData, 2));
    boost::ResetSharedPtrRawOwning(mWaterGrid, MakeGrid(mMapData, 4));
  }
}

/**
 * Address: 0x005C2300 (FUN_005C2300, scalar deleting thunk)
 * Address: 0x005C23F0 (FUN_005C23F0, full destructor body)
 */
CAiReconDBImpl::~CAiReconDBImpl()
{


  mBblips.clear();
  mTempBlips.clear();

  mVCIGrid.release();
  mSCIGrid.release();
  mRCIGrid.release();
  mOmniGrid.release();
  mSonarGrid.release();
  mRadarGrid.release();
  mWaterGrid.release();
  mVisionGrid.release();

  mFogOfWar = 0;
  mArmy = nullptr;
  mMapData = nullptr;
  mSim = nullptr;
  mIMap = nullptr;
}

/**
 * Address: 0x005C0370 (FUN_005C0370, Moho::CAiReconDBImpl::Flush)
 *
 * What it does:
 * Clears per-army recon state for orphan and mapped blips, emits intel-loss
 * notifications, destroys no-longer-used blips, then resets map/list storage.
 */
void CAiReconDBImpl::Flush()
{
  for (ReconBlip* const blip : mTempBlips) {
    if (!blip) {
      continue;
    }
    ClearPerArmyRecon(this, blip, true);
    blip->DestroyIfUnused();
  }
  mTempBlips.clear();

  for (auto it = mBlipMap.begin(); it != mBlipMap.end(); ++it) {
    ReconBlip* const blip = it->second;
    if (!blip) {
      continue;
    }
    ClearPerArmyRecon(this, blip, true);
    blip->DestroyIfUnused();
  }

  mBlipMap.clear();
  mBblips.clear();
}

/**
 * Address: 0x005C0C40 (FUN_005C0C40)
 */
void CAiReconDBImpl::ReconTick(const int dTicks)
{
  if (!mArmy || !mSim) {
    TickAllReconGrids(this, dTicks);
    return;
  }

  // 0x005C0C40 opens on the Logf and goes straight into the orphan loop at
  // 0x005C0CA5. There is no map re-seed here; seeding belongs to the two entry
  // points that can be reached with an empty map, not to the per-tick path.
  mSim->Logf("ReconTick for army %d: %s [%s]\n", mArmy->mConstDat.mArmyIndex, mArmy->mConstDat.mPlayerName.raw_data_unsafe(), mArmy->mConstDat.mArmyName.raw_data_unsafe());

  for (auto it = mTempBlips.begin(); it != mTempBlips.end();) {
    ReconBlip* const blip = *it;
    const bool shouldDelete = BlipArmyTreatsViewerAsAlly(this, blip) ||
      (ReconCanDetectEntity(this, reinterpret_cast<Entity*>(blip), BlipProbePosition(blip), RECON_LOSNow) != RECON_None);
    if (shouldDelete) {
      // 0x005C0D39-0x005C0D74: the orphan teardown logs the confirmation and
      // feeds the sim checksum -- tag 2, then the blip id, four bytes each, the
      // same shape UpdateBlip uses with tag 4. Both writes were missing, so
      // every orphan retirement left this client's checksum one pair of words
      // behind a client that ran the real code: a desync, not a cosmetic gap.
      const std::uint32_t blipId = static_cast<std::uint32_t>(blip->id_);
      mSim->Logf("  orphan 0x%08x confirmed dead\n", blipId);
      std::uint32_t checksumTag = 2u;
      mSim->mContext.Update(&checksumTag, sizeof(checksumTag));
      checksumTag = blipId;
      mSim->mContext.Update(&checksumTag, sizeof(checksumTag));

      it = mTempBlips.erase(it);

      // 0x005C0D9F. The blip also owns an influence-map entry; leaving it
      // behind keeps a dead blip contributing threat to the AI's grid forever.
      if (mIMap) {
        mIMap->RemoveEntry(blipId);
      }

      ClearPerArmyRecon(this, blip, true);
      // 0x005C0E15. Clearing the per-army record is only half the teardown --
      // the blip is an Entity, and this army was holding it alive. Without the
      // release it stays in `sourceUnit->mReconBlips`, where `FindOrCreateBlip`
      // (0x005C0930) finds it again on a later tick, sets `mNeedsFlush` back to
      // 1 and republishes it. `ReconBlip::UpdateVisibility` (0x005BEE40) gates
      // sim visibility on exactly that byte, so a blip nothing destroys is a
      // ghost that keeps coming back.
      blip->DestroyIfUnused();
    } else {
      ++it;
    }
  }

  for (auto it = mBlipMap.begin(); it != mBlipMap.end();) {
    const auto node = it++;

    ReconBlip* const blip = node->second;
    if (!blip) {
      (void)mBlipMap.erase(node);
      continue;
    }

    // 0x005C0E54-0x005C0E7C decodes the source from the MAP KEY's weak pointer
    // and nothing else: a null pointer goes straight to the dead-source arm.
    // Falling back to `blip->GetSourceUnit()` here used to resurrect a source
    // the weak pointer had already given up on, so the entry never left the map
    // and its recon record never cleared -- a blip stranded visible forever.
    Unit* const sourceUnit = node->first.sourceUnit.GetObjectPtr();

    if (!sourceUnit || sourceUnit->DestroyQueued()) {
      // 0x005C0E9B `cmp byte ptr [edi+278h], 0` -- `mDeleteWhenStale`, which the
      // constructor sets to `sourceUnit->IsMobile()` (ReconBlip.cpp:1071). So a
      // MOBILE source drops its blip outright, and a STRUCTURE keeps it as a
      // RECON_MaybeDead ghost until the viewer can prove the spot is empty.
      //
      // This tested `IsFakeBlip` (+0x294, `mUnitConstDat.mFake`) instead, which
      // is a different field with an unrelated meaning: dead structures lost the
      // ghost they are supposed to leave behind, and dead jammers left permanent
      // decoy ghosts that nothing would ever clear.
      if (blip->mDeleteWhenStale != 0u) {
        ClearPerArmyRecon(this, blip, true);
        blip->DestroyIfUnused();  // 0x005C0F14
      } else {
        const bool shouldDeleteFake = BlipArmyTreatsViewerAsAlly(this, blip) ||
          (ReconCanDetectEntity(this, reinterpret_cast<Entity*>(blip), BlipProbePosition(blip), RECON_LOSNow) != RECON_None);
        if (shouldDeleteFake) {
          // 0x005C0F8A. Same influence-map release as the orphan arm. The
          // stale-mobile arm below deliberately has none -- the binary does not
          // call it there either.
          if (mIMap) {
            mIMap->RemoveEntry(static_cast<std::uint32_t>(blip->id_));
          }
          ClearPerArmyRecon(this, blip, true);
          blip->DestroyIfUnused();  // 0x005C0FBA
        } else {
          SPerArmyReconInfo* const recon = GetPerArmyReconSlot(blip, mArmy->mConstDat.mArmyIndex);
          if (recon) {
            recon->mReconFlags |= static_cast<std::uint32_t>(RECON_MaybeDead);
          }
          AppendUniqueBlip(mTempBlips, blip);
        }
      }

      (void)mBlipMap.erase(node);
      continue;
    }
  }

  // TEMPORARY PROBE -- delete once resolved.
  //
  // Direct measurement of the gate every blip candidate must pass. The
  // constructor probe never fires, which says this army's recon DB was built
  // through the reflection default ctor + deserialize path rather than
  // CAiReconDBImpl::Create, so the "VISIBLETORECON" set may never have been
  // populated from the rules at all. words=0 here means ContainsBit rejects
  // every unit, no blip is ever created, and the fog/auto-attack/attack-ground/
  // enemy-click symptoms all follow from this one line.
  {
    // Periodic, not first-N: at game start the armies have not met yet, so an
    // early blipMap=0 proves nothing. Sample every 300 ticks instead.
    if ((mSim->mCurTick % 301u) == 0u) {
      std::size_t entities = 0;
      if (mSim->mEntityDB) {
        for (const auto& [entityId, e] : mSim->mEntityDB->mAllUnits) {
          if (e) {
            ++entities;
          }
        }
      }
      gpg::Warnf(
        "[RECONGATE] army=%d words=%u fog=%u entities=%u blipMap=%u bblips=%u",
        static_cast<int>(mArmy ? mArmy->mConstDat.mArmyIndex : -1),
        static_cast<unsigned>(mVisibleToReconCategory.WordCount()),
        static_cast<unsigned>(mFogOfWar),
        static_cast<unsigned>(entities),
        static_cast<unsigned>(mBlipMap.size()),
        static_cast<unsigned>(mBblips.end() - mBblips.begin())
      );
    }
  }

  // TEMPORARY PROBE counters -- delete once resolved. The cumulative ones are
  // what matter: sampling one tick in 301 cannot tell "never detects" from
  // "the sampled tick happened to miss it".
  std::size_t gTotal = 0, gUnit = 0, gBp = 0, gNotOwn = 0, gCat = 0, gDetect = 0;
  static unsigned sEverDetect = 0, sEverPending = 0, sEverCreated = 0, sTicks = 0;
  ++sTicks;

  msvc8::vector<SNewBlip> pendingNewBlips{};
  if (mSim->mEntityDB) {
    for (const auto& [entityId, entity] : mSim->mEntityDB->mAllUnits) {
      ++gTotal;
      Unit* const unit = entity ? entity->IsUnit() : nullptr;
      if (!unit || unit->DestroyQueued()) {
        continue;
      }
      ++gUnit;
      if (!unit->BluePrint) {
        continue;
      }
      ++gBp;
      // 0x005C107B `cmp eax,[esi+30h]` / `je` -- a POINTER-identity test against
      // this recon DB's own army, not an alliance test. Allied units do get
      // blips: that is how you see an ally's army at all, and `ReconCanDetect`
      // (0x005C18F0) hands allied entities their incoming flags back unchanged
      // rather than re-deriving them from the grids. Skipping every ally here
      // made an ally's units invisible.
      if (unit->ArmyRef == mArmy) {
        continue;
      }
      ++gNotOwn;
      if (!mVisibleToReconCategory.ContainsBit(unit->BluePrint->mCategoryBitIndex)) {
        continue;
      }
      ++gCat;

      const EReconFlags detectFlags = ReconCanDetectEntity(this, unit, unit->GetPositionWm3(), RECON_AnySense);
      if (detectFlags != RECON_None) {
        ++gDetect;
        ++sEverDetect;
      }
      auto [rangeBegin, rangeEnd] = FindReconBlipRange(this, unit);
      if (detectFlags != RECON_None) {
        if (rangeBegin == rangeEnd) {
          AppendPendingNewBlip(pendingNewBlips, unit, 0u, detectFlags);
        } else {
          UpdateBlips(unit, detectFlags, pendingNewBlips);
        }
        continue;
      }

      if (rangeBegin != rangeEnd) {
        bool keepStaticLosBlip = false;
        SPerArmyReconInfo* const recon = GetPerArmyReconSlot(rangeBegin->second, mArmy->mConstDat.mArmyIndex);
        if (recon && (recon->mReconFlags & static_cast<std::uint32_t>(RECON_LOSEver)) != 0u && !unit->IsMobile()) {
          keepStaticLosBlip = true;
        }

        if (keepStaticLosBlip) {
          UpdateBlips(unit, RECON_None, pendingNewBlips);
        } else {
          DeleteBlips(unit);
        }
      }
    }
  }

  sEverPending += static_cast<unsigned>(pendingNewBlips.size());
  GenerateNewBlips(pendingNewBlips);
  sEverCreated = static_cast<unsigned>(mBlipMap.size()) > sEverCreated
    ? static_cast<unsigned>(mBlipMap.size()) : sEverCreated;
  RebuildBlipListFromMapAndOrphans(this);
  TickAllReconGrids(this, dTicks);

  // TEMPORARY PROBE -- delete once resolved. Per-gate survivor counts for the
  // publish loop above, sampled periodically so it reports after the armies
  // have actually met rather than only on the opening ticks.
  if ((mSim->mCurTick % 301u) == 0u) {
    gpg::Warnf(
      "[RECONFUNNEL] army=%d db=%p visionGrid=%p fog=%u ticks=%u unit=%u cat=%u detect=%u | EVER detect=%u pending=%u maxBlipMap=%u",
      static_cast<int>(mArmy ? mArmy->mConstDat.mArmyIndex : -1),
      static_cast<const void*>(this),
      static_cast<const void*>(mVisionGrid.px),
      static_cast<unsigned>(mFogOfWar),
      sTicks,
      static_cast<unsigned>(gUnit),
      static_cast<unsigned>(gCat),
      static_cast<unsigned>(gDetect),
      sEverDetect, sEverPending, sEverCreated
    );
  }
}

/**
 * Address: 0x005C14E0 (FUN_005C14E0)
 *
 * Moho::CAiReconDBImpl::ReconRefresh()
 *
 * IDA signature:
 * _DWORD *__thiscall Moho::CAiReconDBImpl::ReconRefresh(Moho::CAiReconDBImpl *this)
 *
 * What it does:
 * Iterates current recon blips and refreshes per-army cached recon fields
 * from each live source unit.
 */
void CAiReconDBImpl::ReconRefresh()
{
  for (auto it = mBlipMap.begin(); it != mBlipMap.end();) {
    const auto node = it++;

    ReconBlip* const blip = node->second;
    if (!blip) {
      continue;
    }

    Unit* const sourceUnit = DecodeBlipSourceUnit(blip);
    if (!sourceUnit || sourceUnit->DestroyQueued()) {
      continue;
    }

    RefreshBlip(blip, sourceUnit);
  }
}

/**
 * Address: 0x005C07E0 (FUN_005C07E0, Moho::CAiReconDBImpl::CheckEvent)
 *
 * ReconBlip *, int, EReconFlags
 *
 * IDA signature:
 * void Moho::CAiReconDBImpl::CheckEvent(
 *   Moho::CAiReconDBImpl *this,
 *   Moho::ReconBlip *blip,
 *   Moho::EReconFlags newFlags,
 *   Moho::EReconFlags changedFlag);
 *
 * What it does:
 * Emits one `OnIntelChange` script event for a single changed recon lane.
 */
void CAiReconDBImpl::CheckEvent(ReconBlip* const blip, const int newFlags, const EReconFlags changedFlag)
{
  if (!mArmy || !blip) {
    return;
  }

  CAiBrain* const brain = mArmy->GetArmyBrain();
  if (!brain) {
    return;
  }

  const bool gained = (newFlags & static_cast<int>(changedFlag)) != 0;
  brain->RunScriptOnIntelChange(blip, ReconSenseLexical(changedFlag), gained);
}

/**
 * Address: 0x005C0890 (FUN_005C0890, Moho::CAiReconDBImpl::CheckIntelEvents)
 *
 * ReconBlip *, int, int
 *
 * IDA signature:
 * void __userpurge Moho::CAiReconDBImpl::CheckIntelEvents(
 *   Moho::CAiReconDBImpl *this,
 *   Moho::ReconBlip *blip,
 *   Moho::EReconFlags newFlags,
 *   Moho::EReconFlags oldFlags);
 *
 * What it does:
 * Diffs old/new recon masks and emits lane-specific intel-change callbacks.
 */
void CAiReconDBImpl::CheckIntelEvents(ReconBlip* const blip, const int oldFlags, const int newFlags)
{
  if (oldFlags == newFlags) {
    return;
  }

  const int diff = oldFlags ^ newFlags;
  if ((diff & static_cast<int>(RECON_LOSNow)) != 0) {
    CheckEvent(blip, newFlags, RECON_LOSNow);
  }
  if ((diff & static_cast<int>(RECON_Radar)) != 0) {
    CheckEvent(blip, newFlags, RECON_Radar);
  }
  if ((diff & static_cast<int>(RECON_Sonar)) != 0) {
    CheckEvent(blip, newFlags, RECON_Sonar);
  }
  if ((diff & static_cast<int>(RECON_Omni)) != 0) {
    CheckEvent(blip, newFlags, RECON_Omni);
  }
}

/**
 * Address: 0x005C0A70 (FUN_005C0A70, Moho::CAiReconDBImpl::GenerateNewBlips)
 *
 * msvc8::vector<SNewBlip> const &
 *
 * What it does:
 * Materializes pending blips, updates per-army blip state, and inserts them
 * into the recon blip map.
 */
void CAiReconDBImpl::GenerateNewBlips(const msvc8::vector<SNewBlip>& pending)
{
  for (const SNewBlip& candidate : pending) {
    ReconBlip* const blip = FindOrCreateBlip(candidate);
    if (!blip) {
      continue;
    }

    UpdateBlip(blip, candidate.sourceUnit, static_cast<std::uint32_t>(candidate.detectedFlags));
    (void)mBlipMap.insert({MakeReconMapKey(candidate.sourceUnit), blip});
  }
}

/**
 * Address: 0x005C0930 (FUN_005C0930)
 */
ReconBlip* CAiReconDBImpl::FindOrCreateBlip(const SNewBlip& candidate)
{
  Unit* const sourceUnit = candidate.sourceUnit;
  if (!mArmy || !sourceUnit) {
    return nullptr;
  }

  const std::int32_t armyIndex = mArmy->mConstDat.mArmyIndex;
  if (armyIndex < 0) {
    return nullptr;
  }

  const bool wantFake = candidate.fake != 0u;
  for (ReconBlip* const existing : sourceUnit->mReconBlips) {
    if (!existing) {
      continue;
    }

    SPerArmyReconInfo* const perArmy = existing->GetPerArmyReconInfo(armyIndex);
    if (!perArmy || perArmy->mNeedsFlush != 0u) {
      continue;
    }

    if (existing->IsFake() == wantFake) {
      perArmy->mNeedsFlush = 1u;
      return existing;
    }
  }

  ReconBlip* const created = new (std::nothrow) ReconBlip(sourceUnit, mSim, wantFake);
  if (!created) {
    return nullptr;
  }

  sourceUnit->mReconBlips.push_back(created);
  if (SPerArmyReconInfo* const perArmy = created->GetPerArmyReconInfo(armyIndex)) {
    perArmy->mNeedsFlush = 1u;
  }
  return created;
}

/**
 * Address: 0x005C1B90 (FUN_005C1B90)
 */
void CAiReconDBImpl::RefreshBlip(ReconBlip* const blip, Unit* const sourceUnit)
{
  if (!mArmy || !blip || !sourceUnit || blip->IsFake()) {
    return;
  }

  const std::int32_t armyIndex = mArmy->mConstDat.mArmyIndex;
  if (armyIndex < 0) {
    return;
  }

  SPerArmyReconInfo* const perArmy = blip->GetPerArmyReconInfo(armyIndex);
  if (!perArmy) {
    return;
  }

  if ((perArmy->mReconFlags & static_cast<std::uint32_t>(RECON_LOSNow)) != 0u) {
    // 0x005C1BD5 `mov eax, [ebx+88h]` / `mov [edi+8], eax`: the source unit's
    // mesh-blueprint lane (Entity +0x80 == SSTIEntityVariableData +0x08) into
    // `SPerArmyReconInfo::mStiMesh` -- the same union slot this field names.
    perArmy->mMeshTypeClassId = sourceUnit->mVarDat.mMeshBlueprint;

    // 0x005C1BE5 `Entity::GetMesh()` returns a retained
    // `shared_ptr<RScmResource>`; the snapshot takes its own owner on the
    // control block (0x005C1BF2..0x005C1C1B) and the temporary is released at
    // 0x005C1C2A.
    //
    // This capture was missing. `ReconBlip::SyncInterface` ships
    // `mMesh.px`/`mMesh.pi` to the client through `PatchEntityUpdateReconMesh`,
    // and `UserEntity::UpdateEntityData` only builds a mesh instance when the
    // incoming `mScmResource` is non-null -- so every recon blip arrived with no
    // scm resource and the client drew the unit's footprint and attached
    // effects but never its mesh.
    boost::SharedPtrRaw<RScmResource> unitMesh = sourceUnit->Entity::GetMesh();
    perArmy->mMesh.reset_from(unitMesh);
    unitMesh.release();

    // 0x005C1C2F: an animated source unit reseats both pose lanes from its
    // actor; one without an actor drops them instead (0x005C1C95/0x005C1CA0).
    if (CAniActor* const actor = sourceUnit->AniActor; actor != nullptr) {
      perArmy->mPriorPose.reset_from_owner(actor->GetPriorPoseShared());
      perArmy->mPose.reset_from_owner(actor->GetPoseShared());
    } else {
      perArmy->mPriorPose.release();
      perArmy->mPose.release();
    }

    perArmy->mHealth = sourceUnit->mVarDat.mHealth;
    perArmy->mMaxHealth = sourceUnit->mVarDat.mMaxHealth;
    perArmy->mFractionComplete = sourceUnit->mVarDat.mFractionComplete;
  }

  if ((perArmy->mReconFlags & static_cast<std::uint32_t>(RECON_AnySense)) != 0u) {
    perArmy->mMaybeDead = static_cast<std::uint8_t>(sourceUnit->IsDead() ? 1u : 0u);
  }
}

/**
 * Address: 0x005C1CF0 (FUN_005C1CF0)
 */
void CAiReconDBImpl::UpdateBlip(ReconBlip* const blip, Unit* const sourceUnit, std::uint32_t newFlags)
{
  if (!mArmy || !blip) {
    return;
  }

  const std::int32_t armyIndex = mArmy->mConstDat.mArmyIndex;
  SPerArmyReconInfo* const perArmy = blip->GetPerArmyReconInfo(armyIndex);
  if (!perArmy) {
    return;
  }

  Sim* const sim = mArmy->GetSim();
  const std::uint32_t blipId = static_cast<std::uint32_t>(blip->id_);

  if (sim) {
    sim->Logf("  UpdateBlip(blip=0x%08x):\n", blipId);
    std::uint32_t checksumTag = 4u;
    sim->mContext.Update(&checksumTag, sizeof(checksumTag));
    checksumTag = blipId;
    sim->mContext.Update(&checksumTag, sizeof(checksumTag));
  }

  const std::uint32_t oldFlags = perArmy->mReconFlags;
  if (blip->IsFake()) {
    Entity* const sourceEntity = sourceUnit ? static_cast<Entity*>(sourceUnit) : nullptr;
    newFlags = static_cast<std::uint32_t>(ReconCanDetectEntity(this, sourceEntity, blip->mVarDat.mCurTransform.pos_, RECON_AnySense));
  }

  newFlags |= (oldFlags & 0x30u);

  if (sim) {
    sim->Logf("    newflags=0x%08x\n", newFlags);
    sim->mContext.Update(&newFlags, sizeof(newFlags));
  }

  if ((newFlags & static_cast<std::uint32_t>(RECON_LOSNow)) != 0u && sourceUnit) {
    const std::string customName = sourceUnit->GetCustomName();
    blip->mUnitVarDat.mCustomName.assign(customName.c_str(), customName.size());
    newFlags |= static_cast<std::uint32_t>(RECON_LOSEver);
    if (blip->IsFake()) {
      newFlags |= static_cast<std::uint32_t>(RECON_KnownFake);
    }
  }

  if (blip->IsFake()) {
    bool markKnownFake = false;
    if ((newFlags & static_cast<std::uint32_t>(RECON_Omni)) != 0u) {
      markKnownFake = true;
    } else if (!sourceUnit) {
      markKnownFake = true;
    } else if (IsAlliedOrSameArmy(mArmy, sourceUnit->ArmyRef)) {
      markKnownFake = true;
    } else {
      const SFootprint& footprint = sourceUnit->GetFootprint();
      const float maxFootprint = static_cast<float>(std::max(footprint.mSizeX, footprint.mSizeZ));
      STIMap* const map = sourceUnit->SimulationRef ? sourceUnit->SimulationRef->mMapData : nullptr;
      const bool useWholeMap = mArmy->UseWholeMap();
      if (!IsWithinPlayableMapRadius(map, blip->mVarDat.mCurTransform.pos_, maxFootprint, useWholeMap)) {
        markKnownFake = true;
      }
    }

    if (markKnownFake) {
      newFlags |= static_cast<std::uint32_t>(RECON_KnownFake);
    }
  }

  perArmy->mReconFlags = newFlags;
  RefreshBlip(blip, sourceUnit);

  const std::uint32_t refreshedFlags = perArmy->mReconFlags;
  if (sim) {
    sim->Logf("    mReconFlags=0x%08x [second]\n", refreshedFlags);
    sim->mContext.Update(&refreshedFlags, sizeof(refreshedFlags));
  }

  if (mIMap) {
    mIMap->UpdateBlipPosition(
      static_cast<std::uint32_t>(blip->id_), blip->mVarDat.mCurTransform.pos_, static_cast<const RUnitBlueprint*>(blip->GetBlueprint())
    );
  }
  CheckIntelEvents(blip, static_cast<int>(oldFlags), static_cast<int>(refreshedFlags));
}

/**
 * Address: 0x005C1F80 (FUN_005C1F80, Moho::CAiReconDBImpl::UpdateBlips)
 *
 * Unit *, EReconFlags, msvc8::vector<SNewBlip> &
 *
 * IDA signature:
 * void __thiscall Moho::CAiReconDBImpl::UpdateBlips(
 *   Moho::CAiReconDBImpl *this,
 *   ... range-pair ...,
 *   Moho::Unit *unit,
 *   unsigned int detectFlags,
 *   std::vector<Moho::CAiReconDBImpl::SNewBlip> *);
 *
 * What it does:
 * Updates all map-owned blips for one source unit, prunes excess fake jammer
 * blips, and enqueues pending fake blips when jammer count increased.
 *
 * DB-integrity fix: `pending` was previously typed `std::vector<SNewBlip>`
 * (matching IDA's own generic type guess above); the real binary shape is
 * `msvc8::vector<SNewBlip>` -- see `AppendPendingNewBlip`'s citation for the
 * evidence (`FUN_005CBC70`'s push_back growth-fill emission).
 */
void CAiReconDBImpl::UpdateBlips(
  Unit* const sourceUnit, const EReconFlags detectedFlags, msvc8::vector<CAiReconDBImpl::SNewBlip>& pending
)
{
  if (!sourceUnit) {
    return;
  }

  auto [it, end] = FindReconBlipRange(this, sourceUnit);
  if (it == end) {
    return;
  }

  const std::int32_t requiredFakeBlips = std::max(0, GetActiveJammerBlipCount(sourceUnit));
  std::int32_t refreshedFakeBlips = 0;

  while (it != end) {
    const auto node = it++;

    ReconBlip* const blip = node->second;
    if (!blip) {
      (void)mBlipMap.erase(node);
      continue;
    }

    if (IsFakeBlip(blip)) {
      if (refreshedFakeBlips >= requiredFakeBlips) {
        DeleteBlip(blip);
        (void)mBlipMap.erase(node);
        continue;
      }

      UpdateBlip(blip, sourceUnit, static_cast<std::uint32_t>(detectedFlags));
      ++refreshedFakeBlips;
      continue;
    }

    UpdateBlip(blip, sourceUnit, static_cast<std::uint32_t>(detectedFlags));
  }

  while (refreshedFakeBlips < requiredFakeBlips) {
    AppendPendingNewBlip(pending, sourceUnit, 1u, detectedFlags);
    ++refreshedFakeBlips;
  }
}

/**
 * Address: 0x005C21F0 (FUN_005C21F0)
 */
void CAiReconDBImpl::DeleteBlip(ReconBlip* const blip)
{
  if (!mArmy || !blip) {
    return;
  }

  const std::int32_t armyIndex = mArmy->mConstDat.mArmyIndex;
  SPerArmyReconInfo* const perArmy = blip->GetPerArmyReconInfo(armyIndex);
  if (!perArmy) {
    return;
  }

  const int oldFlags = static_cast<int>(perArmy->mReconFlags);
  CheckIntelEvents(blip, oldFlags, 0);
  perArmy->mNeedsFlush = 0u;
  perArmy->mReconFlags = 0u;
  blip->DestroyIfUnused();
}

/**
 * Address: 0x005C2230 (FUN_005C2230, Moho::CAiReconDBImpl::DeleteBlips)
 *
 * Unit *
 *
 * IDA signature:
 * void __thiscall Moho::CAiReconDBImpl::DeleteBlips(
 *   Moho::CAiReconDBImpl *this,
 *   ... range-pair ...);
 *
 * What it does:
 * Clears this army's recon state for all map blips from one source unit and
 * removes that source's range from the typed recon map.
 */
void CAiReconDBImpl::DeleteBlips(Unit* const sourceUnit)
{
  if (!sourceUnit) {
    return;
  }

  auto [it, end] = FindReconBlipRange(this, sourceUnit);
  while (it != end) {
    const auto node = it++;

    ReconBlip* const blip = node->second;
    if (blip) {
      DeleteBlip(blip);
    }
    (void)mBlipMap.erase(node);
  }
}

/**
 * Address: 0x005CB360 (FUN_005CB360, Moho::CAiReconDBImpl::GetNewReconFor)
 *
 * Entity *, Wm3::Vector3<float> const &, EReconFlags, bool
 *
 * IDA signature:
 * Moho::EReconFlags __userpurge Moho::CAiReconDBImpl::GetNewReconFor@<eax>(
 *   Wm3::Vector3f *pos@<eax>,
 *   Moho::Entity *entity@<ecx>,
 *   Moho::CAiReconDBImpl *this,
 *   Moho::EReconFlags oldFlags,
 *   bool belowWater);
 *
 * What it does:
 * Computes one-army point recon senses (LOS/radar/sonar/omni) before
 * counter-intel suppression.
 */
EReconFlags CAiReconDBImpl::GetNewReconFor(
  Entity* const entity, const Wm3::Vec3f& pos, const EReconFlags oldFlags, const bool belowWater
) const
{
  Unit* const unit = entity ? entity->IsUnit() : nullptr;
  ReconBlip* const blip = (entity && !unit) ? entity->IsReconBlip() : nullptr;

  EReconFlags detected = RECON_None;
  if (mFogOfWar == 0 || mVisionGrid.px == nullptr) {
    detected = RECON_LOSNow;
  } else if (HasFlag(oldFlags, RECON_LOSNow)) {
    const CIntelGrid* const losGrid = belowWater ? mWaterGrid.px : mVisionGrid.px;
    if (IsGridVisibleAtPoint(losGrid, pos)) {
      detected = RECON_LOSNow;
    }
  }

  bool sonarEligible = belowWater;
  if (unit) {
    sonarEligible = sonarEligible || UsesWaterSenseLane(unit->mVarDat.mLayerMask);
  } else if (blip) {
    sonarEligible = sonarEligible || UsesWaterSenseLane(blip->mVarDat.mLayerMask);
  }

  if (sonarEligible && HasFlag(oldFlags, RECON_Sonar) && IsGridVisibleAtPoint(mSonarGrid.px, pos)) {
    detected = MergeFlags(detected, RECON_Sonar);
  }

  if (!belowWater && HasFlag(oldFlags, RECON_Radar) && IsGridVisibleAtPoint(mRadarGrid.px, pos)) {
    detected = MergeFlags(detected, RECON_Radar);
  }

  if (HasFlag(oldFlags, RECON_Omni) && IsGridVisibleAtPoint(mOmniGrid.px, pos)) {
    detected = MergeFlags(detected, RECON_Omni);
  }

  return detected;
}

/**
 * Address: 0x005CB460 (FUN_005CB460, Moho::CAiReconDBImpl::ApplyReconCounters)
 *
 * Entity *, Wm3::Vector3<float> const &, EReconFlags
 *
 * IDA signature:
 * unsigned int __userpurge Moho::CAiReconDBImpl::ApplyReconCounters@<eax>(
 *   Wm3::Vector3f *pos@<eax>,
 *   Moho::Entity *entity@<ecx>,
 *   Moho::CAiReconDBImpl *this,
 *   Moho::EReconFlags flags);
 *
 * What it does:
 * Applies point counter-intel and stealth/counter-stealth suppression to
 * raw recon flags.
 */
EReconFlags CAiReconDBImpl::ApplyReconCounters(Entity* const entity, const Wm3::Vec3f& pos, EReconFlags flags) const
{
  Unit* const unit = entity ? entity->IsUnit() : nullptr;

  if (HasFlag(flags, RECON_Omni)) {
    return flags;
  }

  const CIntel* const intel = unit ? unit->GetIntelManager() : nullptr;
  const bool activeCloak = intel && intel->mCloak.present != 0u && intel->mCloak.enabled != 0u;

  if (IsGridVisibleAtPoint(mRCIGrid.px, pos)) {
    flags = ClearFlag(flags, RECON_Radar);
  }
  if (IsGridVisibleAtPoint(mSCIGrid.px, pos)) {
    flags = ClearFlag(flags, RECON_Sonar);
  }

  if (activeCloak || IsGridVisibleAtPoint(mVCIGrid.px, pos)) {
    flags = ClearFlag(flags, RECON_LOSNow);
  }

  if (intel && !HasFlag(flags, RECON_LOSNow)) {
    if (intel->mRadarStealth.present != 0u && intel->mRadarStealth.enabled != 0u) {
      flags = ClearFlag(flags, RECON_Radar);
    }
    if (intel->mSonarStealth.present != 0u && intel->mSonarStealth.enabled != 0u) {
      flags = ClearFlag(flags, RECON_Sonar);
    }
  }

  return flags;
}

/**
 * Address: 0x005C9600 (FUN_005C9600, Moho::CAiReconDBImpl::GetReconFlags)
 *
 * Entity *, Wm3::Vector3<float> const &, EReconFlags, bool
 *
 * IDA signature:
 * Moho::EReconFlags __userpurge Moho::CAiReconDBImpl::GetReconFlags@<eax>(
 *   Moho::CAiReconDBImpl *this@<ebx>,
 *   Moho::Entity *entity,
 *   Wm3::Vector3f *pos,
 *   Moho::EReconFlags oldFlags,
 *   bool belowWater);
 *
 * What it does:
 * Merges point recon senses from this army and allied recon DBs, then
 * applies point counter-intel filtering.
 */
EReconFlags CAiReconDBImpl::GetReconFlags(
  Entity* const entity, const Wm3::Vec3f& pos, const EReconFlags oldFlags, const bool belowWater
) const
{
  EReconFlags combined = GetNewReconFor(entity, pos, oldFlags, belowWater);

  if (mSim && mArmy && mArmy->mConstDat.mArmyIndex >= 0) {
    const std::uint32_t viewerArmyId = static_cast<std::uint32_t>(mArmy->mConstDat.mArmyIndex);
    const std::size_t armyCount = mSim->mArmiesList.size();
    for (std::size_t i = 0; i < armyCount; ++i) {
      CArmyImpl* const allyArmy = mSim->mArmiesList[i];
      if (!allyArmy || !allyArmy->mVarDat.mAllies.Contains(viewerArmyId)) {
        continue;
      }

      CAiReconDBImpl* const allyReconDb = allyArmy->GetReconDB();
      if (!allyReconDb) {
        continue;
      }

      combined = MergeFlags(combined, allyReconDb->GetNewReconFor(entity, pos, oldFlags, belowWater));
    }
  }

  if (combined == RECON_None) {
    return RECON_None;
  }

  return ApplyReconCounters(entity, pos, combined);
}

/**
 * Address: 0x005C9720 (FUN_005C9720, sub_5C9720)
 *
 * gpg::Rect2<int> const &, EReconFlags, bool
 *
 * IDA signature:
 * Moho::EReconFlags __stdcall sub_5C9720(
 *   Moho::CAiReconDBImpl *this,
 *   gpg::Rect2i *rect,
 *   Moho::EReconFlags oldFlags,
 *   bool underwater);
 *
 * What it does:
 * Merges rectangle recon detection across this army and allied recon DBs, then
 * applies rectangle counter-intel filtering.
 */
EReconFlags CAiReconDBImpl::GetReconFlagsForRect(
  const moho::Rect2<int>& rect, const EReconFlags oldFlags, const bool isUnderwater
) const
{
  EReconFlags combined = GetDetection(rect, oldFlags, isUnderwater);

  if (mSim && mArmy && mArmy->mConstDat.mArmyIndex >= 0) {
    const std::uint32_t viewerArmyId = static_cast<std::uint32_t>(mArmy->mConstDat.mArmyIndex);
    const std::size_t armyCount = mSim->mArmiesList.size();
    for (std::size_t i = 0; i < armyCount; ++i) {
      CArmyImpl* const allyArmy = mSim->mArmiesList[i];
      if (!allyArmy || !allyArmy->mVarDat.mAllies.Contains(viewerArmyId)) {
        continue;
      }

      CAiReconDBImpl* const allyReconDb = allyArmy->GetReconDB();
      if (!allyReconDb) {
        continue;
      }

      combined = MergeFlags(combined, allyReconDb->GetDetection(rect, oldFlags, isUnderwater));
    }
  }

  if (combined == RECON_None) {
    return RECON_None;
  }

  return DoCounterDetection(rect, combined);
}

/**
 * Address: 0x005CB520 (FUN_005CB520, Moho::CAiReconDBImpl::GetDetection)
 *
 * gpg::Rect2<int> const &, EReconFlags, bool
 *
 * IDA signature:
 * int __userpurge Moho::CAiReconDBImpl::GetDetection@<eax>(
 *   Moho::CAiReconDBImpl *this@<edx>,
 *   gpg::Rect2i *rect@<ecx>,
 *   Moho::EReconFlags_8 oldFlags,
 *   bool isUnderwater@<al>);
 *
 * What it does:
 * Computes direct recon senses (LOS/radar/sonar/omni) for this army over one
 * world-space rectangle.
 */
EReconFlags CAiReconDBImpl::GetDetection(
  const moho::Rect2<int>& rect, const EReconFlags oldFlags, const bool isUnderwater
) const
{
  EReconFlags detected = RECON_None;

  if (mFogOfWar == 0 || mVisionGrid.px == nullptr) {
    detected = RECON_LOSNow;
  } else if (HasFlag(oldFlags, RECON_LOSNow)) {
    if (isUnderwater) {
      if (mWaterGrid.px && mWaterGrid.px->IsVisible(rect)) {
        detected = RECON_LOSNow;
      }
    } else if (mVisionGrid.px->IsVisible(rect)) {
      detected = RECON_LOSNow;
    }
  }

  const EReconFlags pingSense = isUnderwater ? RECON_Sonar : RECON_Radar;
  const CIntelGrid* const pingGrid = isUnderwater ? mSonarGrid.px : mRadarGrid.px;
  if (HasFlag(oldFlags, pingSense) && pingGrid && pingGrid->IsVisible(rect)) {
    detected = MergeFlags(detected, pingSense);
  }

  if (HasFlag(oldFlags, RECON_Omni) && mOmniGrid.px && mOmniGrid.px->IsVisible(rect)) {
    detected = MergeFlags(detected, RECON_Omni);
  }

  return detected;
}

/**
 * Address: 0x005CB600 (FUN_005CB600, Moho::CAiReconDBImpl::DoCounterDetection)
 *
 * gpg::Rect2<int> const &, EReconFlags
 *
 * IDA signature:
 * Moho::EReconFlags __userpurge Moho::CAiReconDBImpl::DoCounterDetection@<eax>(
 *   Moho::CAiReconDBImpl *this,
 *   gpg::Rect2i *rect@<ebx>,
 *   Moho::EReconFlags flags);
 *
 * What it does:
 * Clears recon senses suppressed by active counter-intel grids.
 */
EReconFlags CAiReconDBImpl::DoCounterDetection(const moho::Rect2<int>& rect, EReconFlags flags) const
{
  if (HasFlag(flags, RECON_Omni)) {
    return flags;
  }

  if (mRCIGrid.px && mRCIGrid.px->IsVisible(rect)) {
    flags = ClearFlag(flags, RECON_Radar);
  }
  if (mSCIGrid.px && mSCIGrid.px->IsVisible(rect)) {
    flags = ClearFlag(flags, RECON_Sonar);
  }
  if (mVCIGrid.px && mVCIGrid.px->IsVisible(rect)) {
    flags = ClearFlag(flags, RECON_LOSNow);
  }
  return flags;
}

/**
 * Address: 0x005C18A0 (FUN_005C18A0, Moho::CAiReconDBImpl::ReconCanDetect)
 */
EReconFlags CAiReconDBImpl::ReconCanDetect(const moho::Rect2<int>& rect, const float y, const int oldFlags) const
{
  const EReconFlags senseMask = static_cast<EReconFlags>(oldFlags);
  const float waterElevation = (mMapData && mMapData->mWaterEnabled != 0u) ? mMapData->mWaterElevation : -10000.0f;
  const bool isUnderwater = waterElevation > y;
  return GetReconFlagsForRect(rect, senseMask, isUnderwater);
}

/**
 * Address: 0x005C19C0 (FUN_005C19C0)
 *
 * What it does:
 * Register-shape adapter that computes underwater state from map water lanes
 * and forwards one rect probe to `CAiReconDBImpl::GetReconFlagsForRect`.
 */
[[maybe_unused]] EReconFlags ReconCanDetectRectWithWaterAdapter(
  const CAiReconDBImpl* const reconDb,
  const EReconFlags oldFlags,
  const moho::Rect2<int>& rect,
  const float y
)
{
  if (reconDb == nullptr) {
    return oldFlags;
  }

  const float waterElevation =
    (reconDb->mMapData && reconDb->mMapData->mWaterEnabled != 0u) ? reconDb->mMapData->mWaterElevation : -10000.0f;
  return reconDb->GetReconFlagsForRect(rect, oldFlags, waterElevation > y);
}

/**
 * Address: 0x005C18F0 (FUN_005C18F0, Moho::CAiReconDBImpl::ReconCanDetect)
 *
 * Entity *, Wm3::Vector3<float> const &, EReconFlags
 *
 * IDA signature:
 * unsigned int __userpurge Moho::CAiReconDBImpl::ReconCanDetect@<eax>(
 *   Moho::Entity *ent@<edi>,
 *   Moho::CAiReconDBImpl *this@<esi>,
 *   Wm3::Vector3f *pos,
 *   Moho::EReconFlags oldFlags);
 *
 * What it does:
 * Applies map/alliance/layer gates for one entity probe, then resolves
 * point recon flags through `GetReconFlags`.
 */
EReconFlags CAiReconDBImpl::ReconCanDetect(
  Entity* const ent, const Wm3::Vec3f& pos, const EReconFlags oldFlags
) const
{
  if (!ent) {
    const float waterElevation = (mMapData && mMapData->mWaterEnabled != 0u) ? mMapData->mWaterElevation : -10000.0f;
    const bool belowWater = waterElevation > pos.y;
    return GetReconFlags(nullptr, pos, oldFlags, belowWater);
  }

  // TEMPORARY PROBE -- delete once resolved. RECONFUNNEL proved every enemy
  // candidate dies here (cat=14 -> detect=0), so this splits the two ways that
  // happens: the playable-radius gate, or GetReconFlags finding nothing in the
  // vision/radar/sonar/omni grids.
  static unsigned sCalls = 0, sOutside = 0, sAllied = 0, sGridNone = 0, sGridHit = 0;
  ++sCalls;

  if (mMapData && mArmy) {
    const bool useWholeMap = mArmy->UseWholeMap();
    if (!IsWithinPlayableMapRadius(mMapData, pos, 0.0f, useWholeMap)) {
      ++sOutside;
      if ((sCalls % 4000u) == 0u) {
        gpg::Warnf(
          "[RECONDETECT] calls=%u outsideRect=%u allied=%u gridNone=%u gridHit=%u "
          "pos=(%.1f,%.1f,%.1f) rect=(%d,%d,%d,%d) wholeMap=%d",
          sCalls, sOutside, sAllied, sGridNone, sGridHit, pos.x, pos.y, pos.z,
          mMapData->mPlayableRect.x0, mMapData->mPlayableRect.z0,
          mMapData->mPlayableRect.x1, mMapData->mPlayableRect.z1,
          useWholeMap ? 1 : 0
        );
      }
      return RECON_None;
    }
  }

  if (IsAlliedOrSameArmy(mArmy, ent->ArmyRef)) {
    ++sAllied;
    return oldFlags;
  }

  const bool belowWater = ent->mVarDat.mLayerMask == LAYER_Seabed || ent->mVarDat.mLayerMask == LAYER_Sub;
  const EReconFlags resolved = GetReconFlags(ent, pos, oldFlags, belowWater);
  if (resolved == RECON_None) {
    ++sGridNone;
  } else {
    ++sGridHit;
  }
  if ((sCalls % 4000u) == 0u) {
    gpg::Warnf(
      "[RECONDETECT] calls=%u outsideRect=%u allied=%u gridNone=%u gridHit=%u "
      "pos=(%.1f,%.1f,%.1f) rect=(%d,%d,%d,%d)",
      sCalls, sOutside, sAllied, sGridNone, sGridHit, pos.x, pos.y, pos.z,
      mMapData ? mMapData->mPlayableRect.x0 : -1, mMapData ? mMapData->mPlayableRect.z0 : -1,
      mMapData ? mMapData->mPlayableRect.x1 : -1, mMapData ? mMapData->mPlayableRect.z1 : -1
    );
  }
  return resolved;
}

/**
 * Address: 0x00655610 (FUN_00655610, Moho::CAiReconDBImpl::BeamIsVisible)
 *
 * What it does:
 * Probes LOS at the far beam endpoint selected by `mFromStart`.
 */
bool CAiReconDBImpl::BeamIsVisible(const SWorldBeam& beam) const
{
  if (beam.mFromStart) {
    return ReconCanDetect(beam.mCurEnd.pos_, RECON_LOSNow) != RECON_None;
  }

  Wm3::Vec3f beamEndProbe{
    beam.mCurStart.pos_.x + beam.mEnd.x,
    beam.mCurStart.pos_.y + beam.mEnd.y,
    beam.mCurStart.pos_.z + beam.mEnd.z,
  };
  return ReconCanDetect(beamEndProbe, RECON_LOSNow) != RECON_None;
}

/**
 * Address: 0x005C1810 (FUN_005C1810, Moho::CAiReconDBImpl::IntelConfirmDead)
 *
 * ReconBlip *
 *
 * IDA signature:
 * bool __usercall Moho::CAiReconDBImpl::IntelConfirmDead@<al>(
 *   Moho::ReconBlip *blip@<eax>, Moho::CAiReconDBImpl *this@<ecx>);
 *
 * What it does:
 * Confirms dead-state visibility when the blip is allied or currently
 * detectable via LOS at its probe position.
 */
bool CAiReconDBImpl::IntelConfirmDead(ReconBlip* const blip)
{
  if (!blip) {
    return false;
  }

  auto* const entity = reinterpret_cast<Entity*>(blip);
  if (IsAlliedOrSameArmy(mArmy, entity->ArmyRef)) {
    return true;
  }

  return ReconCanDetect(entity, entity->GetPositionWm3(), RECON_LOSNow) != RECON_None;
}

/**
 * Address: 0x005C1850 (FUN_005C1850, Moho::CAiReconDBImpl::ReconCanDetect)
 *
 * Wm3::Vector3<float> const &, int
 *
 * IDA signature:
 * Moho::EReconFlags __thiscall Moho::CAiReconDBImpl::ReconCanDetect(
 *   Moho::CAiReconDBImpl *this,
 *   Wm3::Vector3f *pos,
 *   Moho::EReconFlags oldFlags)
 */
EReconFlags CAiReconDBImpl::ReconCanDetect(const Wm3::Vec3f& pos, const int oldFlags) const
{
  const float waterElevation = (mMapData && mMapData->mWaterEnabled != 0u) ? mMapData->mWaterElevation : -10000.0f;
  const bool belowWater = waterElevation > pos.y;
  return GetReconFlags(nullptr, pos, static_cast<EReconFlags>(oldFlags), belowWater);
}

/**
 * Address: 0x005C1720 (FUN_005C1720)
 *
 * What it does:
 * Appends blips whose source-unit collision primitive overlaps `box`.
 */
void CAiReconDBImpl::ReconGetBlips(const Wm3::Box3<float>& box, gpg::core::FastVector<Entity*>* const outBlips) const
{
  for (ReconBlip* const blip : mBblips) {
    if (!blip) {
      continue;
    }
    if (DoesBlipSourceCollideBox(blip, box)) {
      outBlips->PushBack(reinterpret_cast<Entity*>(blip));
    }
  }
}

/**
 * Address: 0x005C1640 (FUN_005C1640)
 *
 * What it does:
 * Appends blips whose world position is inside a sphere centered at `center`
 * with radius `radius` (3D distance check, no output clear).
 */
void CAiReconDBImpl::ReconGetBlips(
  const Wm3::Vec3f& center, const float radius, gpg::core::FastVector<Entity*>* const outBlips
) const
{
  const float radiusSquared = radius * radius;
  for (ReconBlip* const blip : mBblips) {
    if (!blip) {
      continue;
    }
    auto* const entity = reinterpret_cast<Entity*>(blip);
    const Wm3::Vec3f& pos = entity->GetPositionWm3();
    const float dx = pos.x - center.x;
    const float dy = pos.y - center.y;
    const float dz = pos.z - center.z;
    if ((dx * dx) + (dy * dy) + (dz * dz) <= radiusSquared) {
      outBlips->PushBack(entity);
    }
  }
}

/**
 * Address: 0x005C1590 (FUN_005C1590)
 *
 * What it does:
 * Returns the per-army current blip list container by reference.
 */
const msvc8::vector<ReconBlip*>& CAiReconDBImpl::ReconGetBlips() const
{
  return mBblips;
}

/**
 * Address: 0x005C1A10 (FUN_005C1A10)
 */
boost::SharedPtrRaw<CIntelGrid> CAiReconDBImpl::ReconGetVisionGrid() const
{
  return mVisionGrid.clone_retained();
}

/**
 * Address: 0x005C1A40 (FUN_005C1A40)
 */
boost::SharedPtrRaw<CIntelGrid> CAiReconDBImpl::ReconGetWaterGrid() const
{
  return mWaterGrid.clone_retained();
}

/**
 * Address: 0x005C1A70 (FUN_005C1A70)
 */
boost::SharedPtrRaw<CIntelGrid> CAiReconDBImpl::ReconGetRadarGrid() const
{
  return mRadarGrid.clone_retained();
}

/**
 * Address: 0x005C1AA0 (FUN_005C1AA0)
 */
boost::SharedPtrRaw<CIntelGrid> CAiReconDBImpl::ReconGetSonarGrid() const
{
  return mSonarGrid.clone_retained();
}

/**
 * Address: 0x005C1AD0 (FUN_005C1AD0)
 */
boost::SharedPtrRaw<CIntelGrid> CAiReconDBImpl::ReconGetOmniGrid() const
{
  return mOmniGrid.clone_retained();
}

/**
 * Address: 0x005C1B00 (FUN_005C1B00)
 */
boost::SharedPtrRaw<CIntelGrid> CAiReconDBImpl::ReconGetRCIGrid() const
{
  return mRCIGrid.clone_retained();
}

/**
 * Address: 0x005C1B30 (FUN_005C1B30)
 */
boost::SharedPtrRaw<CIntelGrid> CAiReconDBImpl::ReconGetSCIGrid() const
{
  return mSCIGrid.clone_retained();
}

/**
 * Address: 0x005C1B60 (FUN_005C1B60)
 */
boost::SharedPtrRaw<CIntelGrid> CAiReconDBImpl::ReconGetVCIGrid() const
{
  return mVCIGrid.clone_retained();
}

/**
 * Address: 0x005C08F0 (FUN_005C08F0)
 *
 * What it does:
 * Updates `mFogOfWar` only when a vision grid exists.
 */
void CAiReconDBImpl::ReconSetFogOfWar(const bool enabled)
{
  if (mVisionGrid.px) {
    mFogOfWar = static_cast<std::uint8_t>(enabled ? 1u : 0u);
  }
}

/**
 * Address: 0x005C0910 (FUN_005C0910)
 *
 * What it does:
 * Returns true when fog-of-war mode is enabled and vision grid storage exists.
 */
bool CAiReconDBImpl::ReconGetFogOfWar() const
{
  return mFogOfWar != 0 && mVisionGrid.px != nullptr;
}

/**
 * Address: 0x005C29C0 (FUN_005C29C0, nullsub_1553)
 *
 * What it does:
 * Intentionally empty hook (binary no-op).
 */
void CAiReconDBImpl::UpdateSimChecksum() {}

/**
 * Address: 0x005C15A0 (FUN_005C15A0)
 *
 * What it does:
 * Returns one recon blip entry for `unit` by lower-bound lookup in the typed
 * recon map; returns `nullptr` when lookup resolves to map-end sentinel.
 */
ReconBlip* CAiReconDBImpl::ReconGetBlip(Unit* const unit) const
{
  if (!unit) {
    return nullptr;
  }

  // `lower_bound` answers "the first key not less than this one", which is not
  // the question. For a unit with no blip it returns the next unit's entry, and
  // the only rejection here was against `end()` -- so the caller got somebody
  // else's blip for every unit whose id sorts below some blipped unit's, and a
  // null only for a unit sorting past the last entry in the map.
  //
  // `Unit::UpdateBlipsInRange` (0x006ACC60) gates its candidate list on exactly
  // this call returning null, so a wrong-but-non-null answer puts the wrong
  // entity into the attacker's blip list.
  //
  // Every other lookup in this file already uses the key-matching form via
  // `FindReconBlipRange`; this one is now the same.
  auto* const owner = const_cast<CAiReconDBImpl*>(this);
  auto [first, last] = FindReconBlipRange(owner, unit);
  return (first != last) ? first->second : nullptr;
}

/**
 * Address: 0x005C20C0 (FUN_005C20C0)
 *
 * What it does:
 * Returns non-fake recon blips for one source unit while holding a weak-link
 * guard on the source object during map traversal.
 */
EntitySetTemplate<Entity> CAiReconDBImpl::ReconGetJamingBlips(Unit* const unit)
{
  EntitySetTemplate<Entity> out{};
  if (!unit || unit->DestroyQueued() || !mArmy) {
    return out;
  }

  WeakObject::ScopedWeakLinkGuard sourceGuard(static_cast<WeakObject*>(static_cast<CScriptObject*>(unit)));

  SeedReconMapFromBlipList(this);
  auto [it, end] = FindReconBlipRange(this, unit);
  while (it != end) {
    const auto node = it++;

    ReconBlip* const blip = node->second;
    if (!blip) {
      continue;
    }

    SPerArmyReconInfo* const recon = GetPerArmyReconSlot(blip, mArmy->mConstDat.mArmyIndex);
    if (recon && (recon->mReconFlags & static_cast<std::uint32_t>(RECON_KnownFake)) == 0u) {
      out.Add(reinterpret_cast<Entity*>(blip));
    }
  }
  return out;
}

/**
 * Address: 0x005C05A0 (FUN_005C05A0)
 */
void CAiReconDBImpl::ReconFlushBlipsInRect(const moho::Rect2<int>& rect)
{
  SeedReconMapFromBlipList(this);

  for (auto it = mTempBlips.begin(); it != mTempBlips.end();) {
    ReconBlip* const blip = *it;
    auto* const entity = reinterpret_cast<Entity*>(blip);
    if (entity && IsInsideRectXZ(rect, entity->GetPositionWm3())) {
      ClearPerArmyRecon(this, blip, true);
      it = mTempBlips.erase(it);
    } else {
      ++it;
    }
  }

  for (auto it = mBlipMap.begin(); it != mBlipMap.end();) {
    const auto node = it++;

    ReconBlip* const blip = node->second;
    auto* const entity = reinterpret_cast<Entity*>(blip);
    if (!entity || !IsInsideRectXZ(rect, entity->GetPositionWm3())) {
      continue;
    }

    const ELayer layer = entity->mVarDat.mLayerMask;
    if (layer == LAYER_None || layer == LAYER_Sub) {
      continue;
    }

    ClearPerArmyRecon(this, blip, true);
    (void)mBlipMap.erase(node);
  }

  RebuildBlipListFromMapAndOrphans(this);
}

/**
 * Address: 0x005C36A0 (FUN_005C36A0, ??2CAiReconDBImpl@Moho@@QAE@@Z)
 */
CAiReconDBImpl* CAiReconDBImpl::Create(CArmyImpl* const army, const bool fogOfWar)
{
  return new CAiReconDBImpl(army, fogOfWar);
}

/**
 * Recovery-side helper only (not a distinct binary address): the original
 * constructor inlines `operator new` + `CIntelGrid::CIntelGrid(map, size)`
 * directly at each of its 8 call sites (e.g. 0x005C00A6-0x005C00C5) rather
 * than factoring it into a callable function. Factored here for clarity;
 * each call site still wraps the result via `boost::ResetSharedPtrRawOwning`
 * to match the binary's separate `shared_ptr_CIntelGrid::operator=` call
 * (e.g. 0x005C00D7) rather than binding a custom deleter.
 */
CIntelGrid* CAiReconDBImpl::MakeGrid(STIMap* const map, const std::uint32_t gridSize)
{
  if (!map) {
    return nullptr;
  }

  return new CIntelGrid(map, gridSize);
}


namespace moho
{
  bool SReconKeyLess::operator()(const SReconKey& lhs, const SReconKey& rhs) const noexcept
  {
    return lhs.sourceEntityId < rhs.sourceEntityId;
  }
} // namespace moho
