#include "moho/sim/CSquad.h"

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <new>

#include "moho/containers/TDatList.h"
#include "moho/ai/CAiAttackerImpl.h"
#include "moho/entity/EntityDb.h"
#include "moho/entity/REntityBlueprint.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/COGrid.h"
#include "moho/sim/CPlatoon.h"
#include "moho/sim/Sim.h"
#include "moho/sim/STIMap.h"
#include "moho/unit/core/Unit.h"

#ifdef _MSC_VER
#  include <string.h>
#  define MOHO_STRICMP _stricmp
#else
#  include <strings.h>
#  define MOHO_STRICMP strcasecmp
#endif

namespace moho
{
  gpg::RType* CSquad::sType = nullptr;

  namespace
  {
    [[nodiscard]] EOccupancyCaps ClearSubCapsForWaterLayer(EOccupancyCaps caps, const ELayer layer) noexcept
    {
      if (layer != LAYER_Water) {
        return caps;
      }

      return static_cast<EOccupancyCaps>(
        static_cast<std::uint8_t>(caps) & ~static_cast<std::uint8_t>(EOccupancyCaps::OC_SUB)
      );
    }
  } // namespace

  /**
   * Address: 0x00723E70 (FUN_00723E70, Moho::CSquad::CSquad)
   *
   * IDA signature:
   * Moho::CSquad *__usercall Moho::CSquad::CSquad@<eax>(
   *   Moho::ESquadClass squadClass@<edx>,
   *   Moho::CSquad *this,
   *   Moho::Sim *sim,
   *   const char *name);
   *
   * What it does:
   * Initializes the squad's unit-set storage to its inline state, captures
   * the squad-class tag and optional name, then intrusively links the
   * unit-set node into the sim's `mEntityDB->mRegisteredEntitySets` ring at
   * the back (so per-squad unit-set updates participate in the global entity
   * iteration lane).
   */
  CSquad::CSquad(const ESquadClass squadClass, Sim* const sim, const char* const name)
    : mSim(sim), mSquadClass(squadClass)
  {
    mUnits.ListResetLinks();
    if (name != nullptr) {
      mName.assign(name, std::strlen(name));
    }

    // Insert this squad's unit-set node at the back of the sim's registered
    // entity-set ring. The binary's `entityDB += 3` walks 3 list-pair words
    // (24 bytes) into CEntityDb to reach `mRegisteredEntitySets`.
    auto* const sentinel =
      reinterpret_cast<TDatListItem<SEntitySetTemplateUnit, void>*>(&sim->mEntityDB->mRegisteredEntitySets);
    mUnits.ListLinkBefore(reinterpret_cast<SEntitySetTemplateUnit*>(sentinel));
  }

  /**
   * Address: 0x00723F70 (FUN_00723F70, Moho::CSquad::~CSquad)
   *
   * IDA signature:
   * Moho::TDatListItem_EntitySetTemplate_Unit *__usercall
   *   Moho::CSquad::~CSquad@<eax>(Moho::CSquad *this@<eax>);
   *
   * What it does:
   * The fastvector and string members destruct in declaration order; this
   * destructor only needs to clear the category vector and unlink the
   * intrusive unit-set node. The compiler-generated member dtors handle
   * `mUnits.mVec`, `mName`, and `mCats` heap teardown via `~SEntitySetTemplateUnit`,
   * `~msvc8::string`, and `~msvc8::vector` respectively.
   */
  CSquad::~CSquad() = default;

  /**
   * Address: 0x00725040 (FUN_00725040)
   *
   * What it does:
   * Runs one `CSquad` destructor lane and then releases the object storage with
   * scalar `operator delete`, returning the same pointer.
   */
  [[maybe_unused]] CSquad* DestroySquadAndDeleteStorage(CSquad* const squad)
  {
    squad->~CSquad();
    ::operator delete(squad);
    return squad;
  }

  /**
   * Address: 0x00725580 (FUN_00725580, Moho::CSquad::operator new)
   *
   * IDA signature:
   * Moho::CSquad *__userpurge Moho::CSquad::operator new@<eax>(
   *   Moho::CPlatoon *parentPlatoon@<esi>,
   *   Moho::ESquadClass squadClass,
   *   char *name);
   *
   * What it does:
   * Heap-allocates one squad object, runs the constructor with the parent
   * platoon's `mSim`, and pushes the new squad pointer onto the platoon's
   * `mSquadList` fastvector (growing it via the legacy InsertAt path when at
   * capacity). Also clears `mHasLuaList` so any cached Lua unit list will be
   * recomputed on next request.
   */
  CSquad* CSquad::AllocateOnPlatoon(
    CPlatoon* const parentPlatoon, const ESquadClass squadClass, const char* const name
  )
  {
    parentPlatoon->mHasLuaList = 0;

    void* const storage = ::operator new(sizeof(CSquad));
    auto* const newSquad = ::new (storage) CSquad(squadClass, parentPlatoon->mSim, name);

    parentPlatoon->mSquadList.PushBack(newSquad);
    return newSquad;
  }

  /**
   * Address: 0x00724220 (FUN_00724220, Moho::CSquad::CountUnitsWithBP)
   *
   * What it does:
   * Counts every live squad unit whose blueprint id matches `blueprintId`
   * case-insensitively.
   */
  int CSquad::CountUnitsWithBP(const char* const blueprintId) const
  {
    int count = 0;
    for (Entity* const* slot = mUnits.mVec.begin(); slot != mUnits.mVec.end(); ++slot) {
      Unit* const unit = SEntitySetTemplateUnit::UnitFromEntry(*slot);
      if (unit == nullptr || unit->IsDead() || unit->DestroyQueued() || unit->IsBeingBuilt()) {
        continue;
      }

      const msvc8::string& bpId = unit->GetBlueprint()->mBlueprintId;
      const char* const bpIdData = (bpId.myRes < 0x10u) ? &bpId.bx.buf[0] : bpId.bx.ptr;
      if (MOHO_STRICMP(bpIdData, blueprintId) == 0) {
        ++count;
      }
    }
    return count;
  }

  /**
   * Address: 0x007242B0 (FUN_007242B0, Moho::CSquad::CountUnitsInCategory)
   *
   * What it does:
   * Counts every live squad unit whose blueprint category bit belongs to
   * `categorySet`.
   */
  int CSquad::CountUnitsInCategory(const EntityCategorySet* const categorySet) const
  {
    int count = 0;
    for (Entity* const* slot = mUnits.mVec.begin(); slot != mUnits.mVec.end(); ++slot) {
      Unit* const unit = SEntitySetTemplateUnit::UnitFromEntry(*slot);
      if (unit == nullptr || unit->IsDead() || unit->DestroyQueued() || unit->IsBeingBuilt()) {
        continue;
      }

      const RUnitBlueprint* const blueprint = unit->GetBlueprint();
      if (categorySet->Bits().Contains(blueprint->mCategoryBitIndex)) {
        ++count;
      }
    }
    return count;
  }

  /**
   * Address: 0x007244E0 (FUN_007244E0, Moho::CSquad::CanAttackTarget)
   *
   * IDA signature:
   * char __userpurge Moho::CSquad::CanAttackTarget@<al>(Moho::CSquad *this@<ebx>, Moho::Unit *target);
   *
   * What it does:
   * Walks the squad's live unit list and returns true as soon as one unit's
   * attacker controller reports that it can pick the supplied target entity.
   * Dead units and units without attacker controllers are skipped.
   */
  bool CSquad::CanAttackTarget(Unit* const target)
  {
    Entity* const targetEntity = target != nullptr ? static_cast<Entity*>(target) : nullptr;

    for (Entity* const* slot = mUnits.mVec.begin(); slot != mUnits.mVec.end(); ++slot) {
      Unit* const unit = SEntitySetTemplateUnit::UnitFromEntry(*slot);
      if (unit == nullptr || unit->IsDead()) {
        continue;
      }

      CAiAttackerImpl* const attacker = unit->AiAttacker;
      if (attacker != nullptr && attacker->PickTarget(targetEntity)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Address: 0x00724750 (FUN_00724750, Moho::CSquad::HasUnitWithState)
   *
   * What it does:
   * Iterates squad unit slots and returns true as soon as one live unit
   * reports the requested unit-state lane.
   */
  bool CSquad::HasUnitWithState(const EUnitState state) const
  {
    for (Entity* const* slot = mUnits.mVec.begin(); slot != mUnits.mVec.end(); ++slot) {
      Unit* const unit = SEntitySetTemplateUnit::UnitFromEntry(*slot);
      if (unit == nullptr || unit->IsDead()) {
        continue;
      }

      if (unit->IsUnitState(state)) {
        return true;
      }
    }

    return false;
  }

  /**
   * Address: 0x00724350 (FUN_00724350, Moho::CSquad::AppendUnitsWithBP)
   *
   * IDA signature:
   * void __stdcall Moho::CSquad::AppendUnitsWithBP(
   *   Moho::CSquad *this,
   *   const char *bpName,
   *   int upto,
   *   std::map_uint_Entity *intoVec);
   *
   * What it does:
   * Iterates this squad's unit-set, filters out dead/destroying/under-build
   * units, then matches the remaining units' blueprint id (case-insensitive)
   * against `blueprintId` and adds them to `outUnits` until `maxCount`
   * matches have been collected.
   */
  void CSquad::AppendUnitsWithBP(const char* const blueprintId, const int maxCount, SEntitySetTemplateUnit& outUnits)
  {
    int matchCount = 0;
    for (Entity* const* slot = mUnits.mVec.begin(); slot != mUnits.mVec.end(); ++slot) {
      Unit* const unit = SEntitySetTemplateUnit::UnitFromEntry(*slot);
      if (unit == nullptr || unit->IsDead() || unit->DestroyQueued() || unit->IsBeingBuilt()) {
        continue;
      }

      const msvc8::string& bpId = unit->GetBlueprint()->mBlueprintId;
      const char* const bpIdData = (bpId.myRes < 0x10u) ? &bpId.bx.buf[0] : bpId.bx.ptr;
      if (MOHO_STRICMP(bpIdData, blueprintId) != 0) {
        continue;
      }

      (void)outUnits.AddUnit(unit);
      if (++matchCount >= maxCount) {
        break;
      }
    }
  }

  /**
   * Address: 0x00724400 (FUN_00724400, Moho::CSquad::AppendUnitsInCategory)
   *
   * IDA signature:
   * void __userpurge Moho::CSquad::AppendUnitsInCategory(
   *   Moho::EntityCategory *category@<edi>,
   *   Moho::CSquad *this,
   *   int upto,
   *   std::map_uint_Entity *outUnits);
   *
   * What it does:
   * Iterates this squad's unit list, filters out dead/destroying/under-build
   * units, then appends each unit whose blueprint category bit is set in
   * `categorySet` until `maxCount` accepted units have been added.
   */
  void CSquad::AppendUnitsInCategory(
    const EntityCategorySet* const categorySet, const int maxCount, SEntitySetTemplateUnit& outUnits
  )
  {
    int matchCount = 0;
    for (Entity* const* slot = mUnits.mVec.begin(); slot != mUnits.mVec.end(); ++slot) {
      Unit* const unit = SEntitySetTemplateUnit::UnitFromEntry(*slot);
      if (unit == nullptr || unit->IsDead() || unit->DestroyQueued() || unit->IsBeingBuilt()) {
        continue;
      }

      const RUnitBlueprint* const blueprint = unit->GetBlueprint();
      if (!categorySet->Bits().Contains(blueprint->mCategoryBitIndex)) {
        continue;
      }

      (void)outUnits.AddUnit(unit);
      if (++matchCount >= maxCount) {
        return;
      }
    }
  }

  /**
   * Address: 0x00724550 (FUN_00724550, Moho::CSquad::FitsAt)
   *
   * IDA signature:
   * char __stdcall Moho::CSquad::FitsAt(Moho::CSquad *this, Wm3::Vector3f *pos);
   *
   * What it does:
   * Iterates all live squad units, computes each unit footprint's origin cell
   * for `position`, and returns false as soon as one unit cannot satisfy its
   * motion-type occupancy-cap requirement.
   */
  bool CSquad::FitsAt(const Wm3::Vec3f& position) const
  {
    COGrid* const occupancyGrid = mSim->mOGrid;

    for (Entity* const* slot = mUnits.mVec.begin(); slot != mUnits.mVec.end(); ++slot) {
      Unit* const unit = SEntitySetTemplateUnit::UnitFromEntry(*slot);
      if (unit == nullptr || unit->IsDead()) {
        continue;
      }

      const SFootprint& footprint = unit->GetFootprint();
      SOCellPos cellPos{};
      cellPos.x = static_cast<std::int16_t>(
        static_cast<int>(position.x - static_cast<float>(footprint.mSizeX) * 0.5f)
      );
      cellPos.z = static_cast<std::int16_t>(
        static_cast<int>(position.z - static_cast<float>(footprint.mSizeZ) * 0.5f)
      );

      const RUnitBlueprint* const blueprint = unit->GetBlueprint();
      switch (blueprint->Physics.MotionType) {
      case RULEUMT_Land:
      case RULEUMT_Biped: {
        EOccupancyCaps occupancyCaps = OCCUPY_MobileCheck(footprint, *occupancyGrid->sim->mMapData, cellPos);
        occupancyCaps = ClearSubCapsForWaterLayer(occupancyCaps, unit->mCurrentLayer);
        const EOccupancyCaps fitCaps = OCCUPY_FootprintFits(*occupancyGrid, cellPos, footprint, occupancyCaps);
        if ((static_cast<std::uint8_t>(fitCaps) & static_cast<std::uint8_t>(EOccupancyCaps::OC_LAND)) == 0u) {
          return false;
        }
        break;
      }

      case RULEUMT_Water:
      case RULEUMT_SurfacingSub: {
        EOccupancyCaps occupancyCaps = OCCUPY_MobileCheck(footprint, *occupancyGrid->sim->mMapData, cellPos);
        occupancyCaps = ClearSubCapsForWaterLayer(occupancyCaps, unit->mCurrentLayer);
        const EOccupancyCaps fitCaps = OCCUPY_FootprintFits(*occupancyGrid, cellPos, footprint, occupancyCaps);
        if ((static_cast<std::uint8_t>(fitCaps) & static_cast<std::uint8_t>(EOccupancyCaps::OC_WATER)) == 0u) {
          return false;
        }
        break;
      }

      case RULEUMT_Amphibious:
      case RULEUMT_Hover:
      case RULEUMT_AmphibiousFloating: {
        const EOccupancyCaps fitCaps = OCCUPY_HoverFootprintFits(
          cellPos,
          *occupancyGrid,
          footprint,
          static_cast<EOccupancyCaps>(static_cast<std::uint8_t>(unit->mCurrentLayer))
        );
        if (static_cast<std::uint8_t>(fitCaps) == 0u) {
          return false;
        }
        break;
      }

      default:
        break;
      }
    }

    return true;
  }

  /**
   * Address: 0x00724020 (FUN_00724020, Moho::CSquad::GetCenter)
   *
   * IDA signature:
   * Wm3::Vector3f *__usercall Moho::CSquad::GetCenter@<eax>(
   *   Moho::CSquad *this@<ebx>,
   *   Wm3::Vector3f *outPos@<esi>);
   *
   * What it does:
   * Zeros the destination vector, sums every unit position in the squad, and
   * divides by the live slot count. Empty squads return the zero vector
   * immediately; the fallback max-float lane only appears if the slot count
   * collapses to zero after traversal.
   */
  Wm3::Vector3f* CSquad::GetCenter(Wm3::Vector3f* const outPos) const
  {
    const std::ptrdiff_t slotCount = mUnits.mVec.end() - mUnits.mVec.begin();
    outPos->x = 0.0f;
    outPos->y = 0.0f;
    outPos->z = 0.0f;
    if (slotCount == 0) {
      return outPos;
    }

    for (Entity* const* slot = mUnits.mVec.begin(); slot != mUnits.mVec.end(); ++slot) {
      Unit* const unit = SEntitySetTemplateUnit::UnitFromEntry(*slot);
      const Wm3::Vec3f& unitPosition = unit->GetPosition();
      outPos->x += unitPosition.x;
      outPos->y += unitPosition.y;
      outPos->z += unitPosition.z;
    }

    const std::ptrdiff_t finalSlotCount = mUnits.mVec.end() - mUnits.mVec.begin();
    if (finalSlotCount == 0) {
      constexpr float kFloatMax = std::numeric_limits<float>::max();
      outPos->x = kFloatMax;
      outPos->y = kFloatMax;
      outPos->z = kFloatMax;
      return outPos;
    }

    const float inverseCount = 1.0f / static_cast<float>(finalSlotCount);
    outPos->x *= inverseCount;
    outPos->y *= inverseCount;
    outPos->z *= inverseCount;
    return outPos;
  }
} // namespace moho
