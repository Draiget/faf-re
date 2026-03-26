#include "CInfluenceMap.h"

#include <algorithm>
#include <cmath>
#include <cstddef>
#include <cstdint>
#include <typeinfo>

#include "gpg/core/algorithms/MD5.h"
#include "lua/LuaObject.h"
#include "moho/ai/IAiReconDB.h"
#include "moho/entity/Entity.h"
#include "moho/entity/EntityCategoryLookupResolver.h"
#include "moho/entity/EntityDb.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/ReconBlip.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/Sim.h"

namespace
{
  [[nodiscard]] float DecayThreatLane(const float value, const float decay) noexcept
  {
    if (value <= 0.0f) {
      return value;
    }

    float candidate = value + decay;
    if (candidate > 0.0f) {
      candidate = 0.0f;
    }

    const float reduced = value - decay;
    if (reduced > candidate) {
      candidate = reduced;
    }

    return candidate;
  }

  [[nodiscard]] moho::Entity* FindEntityById(moho::CEntityDb* const entityDb, const std::int32_t id) noexcept
  {
    if (!entityDb) {
      return nullptr;
    }

    for (auto it = entityDb->Entities().begin(); it != entityDb->Entities().end(); ++it) {
      moho::Entity* const entity = *it;
      if (entity && entity->id_ == id) {
        return entity;
      }
    }

    return nullptr;
  }

  [[nodiscard]] bool IsAlliedOrSameArmy(const moho::CArmyImpl* const owner, const moho::CArmyImpl* const source) noexcept
  {
    if (!owner || !source) {
      return false;
    }

    if (owner == source) {
      return true;
    }

    if (source->ArmyId < 0) {
      return false;
    }

    return owner->Allies.Contains(static_cast<std::uint32_t>(source->ArmyId));
  }
} // namespace

namespace moho
{
  gpg::RType* SThreat::sType = nullptr;
  gpg::RType* InfluenceMapEntry::sType = nullptr;
  gpg::RType* InfluenceGrid::sType = nullptr;
  gpg::RType* CInfluenceMap::sType = nullptr;

  gpg::RType* SThreat::StaticGetClass()
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(SThreat));
    }
    return sType;
  }

  gpg::RType* InfluenceMapEntry::StaticGetClass()
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(InfluenceMapEntry));
    }
    return sType;
  }

  gpg::RType* InfluenceGrid::StaticGetClass()
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(InfluenceGrid));
    }
    return sType;
  }

  gpg::RType* CInfluenceMap::StaticGetClass()
  {
    if (!sType) {
      sType = gpg::LookupRType(typeid(CInfluenceMap));
    }
    return sType;
  }

  void SThreat::Clear() noexcept
  {
    overallInfluence = 0.0f;
    influenceStructuresNotMex = 0.0f;
    influenceStructures = 0.0f;
    navalInfluence = 0.0f;
    airInfluence = 0.0f;
    landInfluence = 0.0f;
    experimentalInfluence = 0.0f;
    commanderInfluence = 0.0f;
    artilleryInfluence = 0.0f;
    antiAirInfluence = 0.0f;
    antiSurfaceInfluence = 0.0f;
    antiSubInfluence = 0.0f;
    economyInfluence = 0.0f;
    unknownInfluence = 0.0f;
  }

  void SThreat::RecomputeOverall() noexcept
  {
    overallInfluence = antiSurfaceInfluence + experimentalInfluence + influenceStructures + antiSubInfluence
      + commanderInfluence + navalInfluence + economyInfluence + artilleryInfluence + airInfluence + unknownInfluence
      + antiAirInfluence + landInfluence + influenceStructuresNotMex;
  }

  void SThreat::DecayBy(const SThreat& decayRate) noexcept
  {
    influenceStructuresNotMex = DecayThreatLane(influenceStructuresNotMex, decayRate.influenceStructuresNotMex);
    influenceStructures = DecayThreatLane(influenceStructures, decayRate.influenceStructures);
    navalInfluence = DecayThreatLane(navalInfluence, decayRate.navalInfluence);
    airInfluence = DecayThreatLane(airInfluence, decayRate.airInfluence);
    landInfluence = DecayThreatLane(landInfluence, decayRate.landInfluence);
    experimentalInfluence = DecayThreatLane(experimentalInfluence, decayRate.experimentalInfluence);
    commanderInfluence = DecayThreatLane(commanderInfluence, decayRate.commanderInfluence);
    artilleryInfluence = DecayThreatLane(artilleryInfluence, decayRate.artilleryInfluence);
    antiAirInfluence = DecayThreatLane(antiAirInfluence, decayRate.antiAirInfluence);
    antiSurfaceInfluence = DecayThreatLane(antiSurfaceInfluence, decayRate.antiSurfaceInfluence);
    antiSubInfluence = DecayThreatLane(antiSubInfluence, decayRate.antiSubInfluence);
    economyInfluence = DecayThreatLane(economyInfluence, decayRate.economyInfluence);
    unknownInfluence = DecayThreatLane(unknownInfluence, decayRate.unknownInfluence);
    RecomputeOverall();
  }

  [[nodiscard]] float SThreat::ValueByType(const EThreatType threatType) const noexcept
  {
    switch (threatType) {
      case THREATTYPE_Overall:
      case THREATTYPE_OverallNotAssigned:
        return overallInfluence;
      case THREATTYPE_StructuresNotMex:
        return influenceStructuresNotMex;
      case THREATTYPE_Structures:
        return influenceStructures;
      case THREATTYPE_Naval:
        return navalInfluence;
      case THREATTYPE_Air:
        return airInfluence;
      case THREATTYPE_Land:
        return landInfluence;
      case THREATTYPE_Experimental:
        return experimentalInfluence;
      case THREATTYPE_Commander:
        return commanderInfluence;
      case THREATTYPE_Artillery:
        return artilleryInfluence;
      case THREATTYPE_AntiAir:
        return antiAirInfluence;
      case THREATTYPE_AntiSurface:
        return antiSurfaceInfluence;
      case THREATTYPE_AntiSub:
        return antiSubInfluence;
      case THREATTYPE_Economy:
        return economyInfluence;
      case THREATTYPE_Unknown:
      default:
        return unknownInfluence;
    }
  }

  /**
   * Address: 0x00715030 (FUN_00715030, ??0InfluenceGrid@Moho@@QAE@@Z)
   */
  InfluenceGrid::InfluenceGrid()
    : entries()
    , threats()
    , threat{}
    , decay{}
  {
    threat.Clear();
    decay.Clear();
  }

  /**
   * Address: 0x00716350 (FUN_00716350, ??1InfluenceGrid@Moho@@QAE@@Z)
   */
  InfluenceGrid::~InfluenceGrid()
  {
    threats.clear();
    entries.clear();
  }

  /**
   * Address: 0x00715750 (FUN_00715750, ?GetThreat@InfluenceGrid@Moho@@QBEMW4EThreatType@2@H@Z)
   */
  float InfluenceGrid::GetThreat(const EThreatType threatType, const int army) const
  {
    float result = (threatType == THREATTYPE_OverallNotAssigned) ? 0.0f : threat.ValueByType(threatType);

    if (army >= 0) {
      const std::size_t armyIndex = static_cast<std::size_t>(army);
      if (armyIndex < threats.size()) {
        result += threats[armyIndex].ValueByType(threatType);
      }
      return result;
    }

    for (const SThreat* it = threats.begin(); it != threats.end(); ++it) {
      result += it->ValueByType(threatType);
    }
    return result;
  }

  /**
   * Address: 0x00715130 (FUN_00715130, ?DecayInfluence@InfluenceGrid@Moho@@QAEPAV12@XZ)
   */
  void InfluenceGrid::DecayInfluence()
  {
    threat.DecayBy(decay);
  }

  void InfluenceGrid::EnsureThreatSlots(const std::size_t armyCount)
  {
    while (threats.size() < armyCount) {
      SThreat slot{};
      slot.Clear();
      threats.push_back(slot);
    }
  }

  void InfluenceGrid::ClearPerArmyThreats()
  {
    for (SThreat* it = threats.begin(); it != threats.end(); ++it) {
      it->Clear();
    }
  }

  InfluenceMapEntry* InfluenceGrid::FindEntry(const std::uint32_t entityId)
  {
    InfluenceMapEntry key{};
    key.entityId = entityId;
    const auto it = entries.find(key);
    if (it == entries.end()) {
      return nullptr;
    }

    return const_cast<InfluenceMapEntry*>(&(*it));
  }

  const InfluenceMapEntry* InfluenceGrid::FindEntry(const std::uint32_t entityId) const
  {
    InfluenceMapEntry key{};
    key.entityId = entityId;
    const auto it = entries.find(key);
    if (it == entries.end()) {
      return nullptr;
    }

    return &(*it);
  }

  bool InfluenceGrid::RemoveEntry(const std::uint32_t entityId)
  {
    InfluenceMapEntry key{};
    key.entityId = entityId;
    const auto it = entries.find(key);
    if (it == entries.end()) {
      return false;
    }

    entries.erase(it);
    return true;
  }

  /**
   * Address: 0x00716140 (FUN_00716140, ??0CInfluenceMap@Moho@@QAE@Z)
   */
  CInfluenceMap::CInfluenceMap(const std::int32_t gridSize, Sim* const sim, CArmyImpl* const army)
    : mArmy(army)
    , mTotal(0)
    , mWidth(0)
    , mHeight(0)
    , mGridSize(gridSize)
    , mBlipCells()
    , mMapEntries()
  {
    mMapEntries.clear();
    mBlipCells.clear();

    const STIMap* const mapData = sim ? sim->mMapData : nullptr;
    const CHeightField* const heightField = mapData ? mapData->mHeightField.get() : nullptr;
    if (!heightField || mGridSize <= 0) {
      return;
    }

    mWidth = (heightField->width - 1) / mGridSize;
    mHeight = (heightField->height - 1) / mGridSize;
    mTotal = mWidth * mHeight;

    if (mTotal <= 0) {
      return;
    }

    mMapEntries.resize(static_cast<std::size_t>(mTotal));
    const std::size_t armyCount = sim ? sim->mArmiesList.size() : 0u;
    for (InfluenceGrid* cell = mMapEntries.begin(); cell != mMapEntries.end(); ++cell) {
      cell->EnsureThreatSlots(armyCount);
    }
  }

  /**
   * Address: 0x007163A0 (FUN_007163A0, ??1CInfluenceMap@Moho@@QAE@Z)
   */
  CInfluenceMap::~CInfluenceMap()
  {
    mMapEntries.clear();
    mBlipCells.clear();
  }

  /**
   * Address: 0x00715C60 (FUN_00715C60, ?VectorToCoords@CInfluenceMap@Moho@@AAEHPAV?$Vector3@M@Wm3@@@Z)
   */
  std::int32_t CInfluenceMap::VectorToCoords(const Wm3::Vec3f& pos) const
  {
    if (mGridSize <= 0 || mWidth <= 0 || mHeight <= 0) {
      return 0;
    }

    std::int32_t x = static_cast<std::int32_t>(pos.x) / mGridSize;
    if (x >= (mWidth - 1)) {
      x = mWidth - 1;
    }
    if (x < 0) {
      x = 0;
    }

    std::int32_t z = static_cast<std::int32_t>(pos.z) / mGridSize;
    if (z >= (mHeight - 1)) {
      z = mHeight - 1;
    }
    if (z < 0) {
      z = 0;
    }

    return x + z * mWidth;
  }

  /**
   * Address: 0x00715F30 (FUN_00715F30, ?UpdateBlipPosition@CInfluenceMap@Moho@@QAEXHABV?$Vector3@M@Wm3@@PBVRUnitBlueprint@2@@Z)
   */
  void CInfluenceMap::UpdateBlipPosition(
    const std::uint32_t blipId, const Wm3::Vec3f& position, const RUnitBlueprint* const sourceBlueprint
  )
  {
    const InfluenceMapCellIndex* const knownCell = FindBlipCell(blipId);
    const std::int32_t newCellIndex = VectorToCoords(position);

    if (!knownCell) {
      InsertEntry(blipId, position, sourceBlueprint);
      return;
    }

    const std::int32_t oldCellIndex = knownCell->cellIndex;
    if (oldCellIndex == newCellIndex && oldCellIndex >= 0 && oldCellIndex < mTotal) {
      InfluenceGrid& cell = mMapEntries[static_cast<std::size_t>(oldCellIndex)];
      if (InfluenceMapEntry* const entry = cell.FindEntry(blipId)) {
        entry->threatStrength = 1.0f;
        entry->decayTicks = 10;
        entry->lastPosition = position;
      }
      return;
    }

    RemoveEntry(blipId);
    InsertEntry(blipId, position, sourceBlueprint);
  }

  /**
   * Address: 0x00715FF0 (FUN_00715FF0, ?GetThreatRect@CInfluenceMap@Moho@@QBEMHHH_W4EThreatType@2@H@Z)
   */
  float CInfluenceMap::GetThreatRect(
    const int x, const int z, const int radius, const bool onMap, const EThreatType threatType, const int army
  ) const
  {
    if (mWidth <= 0 || mHeight <= 0 || mMapEntries.empty()) {
      return 0.0f;
    }

    int mapX0 = 0;
    int mapX1 = mWidth - 1;
    int mapZ0 = 0;
    int mapZ1 = mHeight - 1;

    if (onMap && mArmy) {
      const Sim* const sim = mArmy->GetSim();
      const STIMap* const mapData = sim ? sim->mMapData : nullptr;
      if (mapData && mGridSize > 0) {
        mapX0 = mapData->mPlayableRect.x0 / mGridSize;
        mapX1 = mapData->mPlayableRect.x1 / mGridSize;
        mapZ0 = mapData->mPlayableRect.z0 / mGridSize;
        mapZ1 = mapData->mPlayableRect.z1 / mGridSize;
      }
    }

    float totalThreat = 0.0f;
    const int zStart = z - radius;
    const int zEnd = z + radius;

    for (int curZ = zStart; curZ <= zEnd; ++curZ) {
      if (curZ < 0 || curZ >= mHeight) {
        continue;
      }
      if (onMap && (curZ < mapZ0 || curZ > mapZ1)) {
        continue;
      }

      const int xStart = x - radius;
      const int xEnd = x + radius;
      for (int curX = xStart; curX <= xEnd; ++curX) {
        if (curX < 0 || curX >= mWidth) {
          continue;
        }
        if (onMap && (curX < mapX0 || curX > mapX1)) {
          continue;
        }

        const std::int32_t index = curX + curZ * mWidth;
        totalThreat += mMapEntries[static_cast<std::size_t>(index)].GetThreat(threatType, army);
      }
    }

    return totalThreat;
  }

  /**
   * Address: 0x00716E60 (FUN_00716E60, ?GetThreatBetweenPositions@CInfluenceMap@Moho@@QBEMABV?$Vector3@M@Wm3@@0_W4EThreatType@2@H@Z)
   */
  float CInfluenceMap::GetThreatBetweenPositions(
    const Wm3::Vec3f& pos1,
    const Wm3::Vec3f& pos2,
    const bool ring,
    const EThreatType threatType,
    const int armyIndex
  ) const
  {
    if (mWidth <= 0 || mHeight <= 0) {
      return 0.0f;
    }

    const std::int32_t index0 = VectorToCoords(pos1);
    const std::int32_t index1 = VectorToCoords(pos2);

    int x0 = index0 % mWidth;
    int z0 = index0 / mWidth;
    const int x1 = index1 % mWidth;
    const int z1 = index1 / mWidth;

    const int dx = std::abs(x1 - x0);
    const int dz = std::abs(z1 - z0);
    const int sx = (x0 < x1) ? 1 : -1;
    const int sz = (z0 < z1) ? 1 : -1;

    float totalThreat = 0.0f;
    int err = dx - dz;
    while (true) {
      totalThreat += GetThreatRect(x0, z0, 0, ring, threatType, armyIndex);
      if (x0 == x1 && z0 == z1) {
        break;
      }

      const int err2 = err * 2;
      if (err2 > -dz) {
        err -= dz;
        x0 += sx;
      }
      if (err2 < dx) {
        err += dx;
        z0 += sz;
      }
    }

    return totalThreat;
  }

  /**
   * Address: 0x007171D0 (FUN_007171D0, ?GetThreatsAroundPosition@CInfluenceMap@Moho@@QAE?AVLuaObject@LuaPlus@@AAV42@ABV?$Vector3@M@Wm3@@HHW4EThreatType@2@H@Z)
   */
  LuaPlus::LuaObject* CInfluenceMap::GetThreatsAroundPosition(
    LuaPlus::LuaObject* const outObj,
    const Wm3::Vec3f& pos,
    const int ring,
    const bool restrictToPlayable,
    const EThreatType threatType,
    const int armyIndex
  ) const
  {
    if (!outObj) {
      return nullptr;
    }

    LuaPlus::LuaState* const state = outObj->m_state;
    if (!state) {
      return outObj;
    }

    outObj->AssignNewTable(state, 0, 0);

    const std::int32_t centerIndex = VectorToCoords(pos);
    const int centerX = centerIndex % mWidth;
    const int centerZ = centerIndex / mWidth;

    int mapX0 = 0;
    int mapX1 = mWidth - 1;
    int mapZ0 = 0;
    int mapZ1 = mHeight - 1;

    Sim* const sim = mArmy ? mArmy->GetSim() : nullptr;
    if (restrictToPlayable && sim && sim->mMapData && mGridSize > 0) {
      mapX0 = sim->mMapData->mPlayableRect.x0 / mGridSize;
      mapX1 = sim->mMapData->mPlayableRect.x1 / mGridSize;
      mapZ0 = sim->mMapData->mPlayableRect.z0 / mGridSize;
      mapZ1 = sim->mMapData->mPlayableRect.z1 / mGridSize;
    }

    std::int32_t luaIndex = 1;
    for (int z = centerZ - ring; z <= centerZ + ring; ++z) {
      if (z < 0 || z >= mHeight) {
        continue;
      }
      if (restrictToPlayable && (z < mapZ0 || z > mapZ1)) {
        continue;
      }

      for (int x = centerX - ring; x <= centerX + ring; ++x) {
        if (x < 0 || x >= mWidth) {
          continue;
        }
        if (restrictToPlayable && (x < mapX0 || x > mapX1)) {
          continue;
        }

        const std::int32_t cellIndex = x + z * mWidth;
        const float threat = mMapEntries[static_cast<std::size_t>(cellIndex)].GetThreat(threatType, armyIndex);
        if (threat <= 0.0f) {
          continue;
        }

        const float worldX = static_cast<float>((mGridSize / 2) + (x * mGridSize));
        const float worldZ = static_cast<float>((mGridSize / 2) + (z * mGridSize));

        LuaPlus::LuaObject point;
        point.AssignNewTable(state, 0, 4);
        point.SetNumber("x", worldX);
        point.SetNumber("y", 0.0f);
        point.SetNumber("z", worldZ);
        point.SetNumber("threat", threat);
        outObj->SetObject(luaIndex, point);
        ++luaIndex;

        if (sim) {
          const float coords[3] = {worldX, 0.0f, worldZ};
          sim->mContext.Update(&threat, sizeof(threat));
          sim->mContext.Update(coords, sizeof(coords));
        }
      }
    }

    if (sim) {
      const gpg::MD5Digest digest = sim->mContext.Digest();
      const msvc8::string checksum = digest.ToString();
      sim->Logf("after GetThreatsAroundPosition checksum=%s\n", checksum.c_str());
    }

    return outObj;
  }

  /**
   * Address: 0x00716480 (FUN_00716480, ?Update@CInfluenceMap@Moho@@QAEXXZ)
   */
  void CInfluenceMap::Update()
  {
    Sim* const sim = mArmy ? mArmy->GetSim() : nullptr;
    const CategoryWordRangeView* commandCategory = nullptr;
    const CategoryWordRangeView* experimentalCategory = nullptr;
    const CategoryWordRangeView* artilleryCategory = nullptr;
    const CategoryWordRangeView* massExtractorCategory = nullptr;
    if (sim && sim->mRules) {
      commandCategory = sim->mRules->GetEntityCategory("COMMAND");
      experimentalCategory = sim->mRules->GetEntityCategory("EXPERIMENTAL");
      artilleryCategory = sim->mRules->GetEntityCategory("ARTILLERY, STRATEGIC");
      massExtractorCategory = sim->mRules->GetEntityCategory("MASSEXTRACTION");
    }

    for (InfluenceGrid* cell = mMapEntries.begin(); cell != mMapEntries.end(); ++cell) {
      cell->DecayInfluence();
      cell->ClearPerArmyThreats();

      for (auto it = cell->entries.begin(); it != cell->entries.end();) {
        InfluenceMapEntry& entry = const_cast<InfluenceMapEntry&>(*it);

        if (entry.decayTicks > 0) {
          --entry.decayTicks;
        }
        if (entry.decayTicks == 0) {
          entry.threatStrength = DecayThreatLane(entry.threatStrength, entry.threatDecay);
        }

        if (entry.threatStrength <= 0.0f) {
          const float threatStrengthChecksum = entry.threatStrength;
          RemoveBlipCell(entry.entityId);
          it = cell->entries.erase(it);
          if (sim) {
            sim->mContext.Update(&threatStrengthChecksum, sizeof(threatStrengthChecksum));
          }
          continue;
        }

        if (!IsAlliedOrSameArmy(mArmy, entry.sourceArmy) && sim && sim->mEntityDB) {
          Entity* const entity = FindEntityById(sim->mEntityDB, static_cast<std::int32_t>(entry.entityId));
          if (entity) {
            if (ReconBlip* const blip = entity->IsReconBlip()) {
              entry.sourceLayer = static_cast<std::int32_t>(entity->mCurrentLayer);

              const std::int32_t sourceArmyIndex = entry.sourceArmy ? entry.sourceArmy->ArmyId : -1;
              if (sourceArmyIndex >= 0) {
                const SPerArmyReconInfo* const sourceArmyRecon = blip->GetPerArmyReconInfo(sourceArmyIndex);
                if (sourceArmyRecon) {
                  const std::uint32_t flags = sourceArmyRecon->mReconFlags;
                  if ((flags & RECON_KnownFake) != 0u) {
                    entry.threatStrength = 0.0f;
                  } else if ((flags & RECON_Omni) != 0u || (flags & RECON_LOSEver) != 0u) {
                    entry.isDetailed = 1u;
                  }
                }
              }
            }
          }
        }

        const std::int32_t sourceArmyIndex = entry.sourceArmy ? entry.sourceArmy->ArmyId : -1;
        if (
          sourceArmyIndex >= 0 && static_cast<std::size_t>(sourceArmyIndex) < cell->threats.size()
          && entry.sourceBlueprint != nullptr
        ) {
          SThreat& armyThreat = cell->threats[static_cast<std::size_t>(sourceArmyIndex)];
          const float strength = entry.threatStrength;

          const float antiAir = entry.sourceBlueprint->Defense.AirThreatLevel * strength;
          const float antiSurface = entry.sourceBlueprint->Defense.SurfaceThreatLevel * strength;
          const float antiSub = entry.sourceBlueprint->Defense.SubThreatLevel * strength;
          const float economy = entry.sourceBlueprint->Defense.EconomyThreatLevel * strength;
          const float total = antiAir + antiSurface + antiSub + economy;
          armyThreat.overallInfluence += total;

          if (!entry.sourceBlueprint->IsMobile()) {
            if (IsInCategory(massExtractorCategory, entry.sourceBlueprint->mCategoryBitIndex)) {
              armyThreat.influenceStructuresNotMex += total;
            } else {
              armyThreat.influenceStructures += total;
              armyThreat.influenceStructuresNotMex += total;
            }
          } else {
            if (entry.sourceBlueprint->Air.CanFly != 0u) {
              armyThreat.airInfluence += total;
            } else if (entry.sourceLayer == LAYER_Land) {
              armyThreat.landInfluence += total;
            } else if (entry.sourceLayer == LAYER_Water || entry.sourceLayer == LAYER_Seabed || entry.sourceLayer == LAYER_Sub) {
              armyThreat.navalInfluence += total;
            }
          }

          if (entry.isDetailed != 0u) {
            if (IsInCategory(experimentalCategory, entry.sourceBlueprint->mCategoryBitIndex)) {
              armyThreat.experimentalInfluence += total;
            }
            if (IsInCategory(commandCategory, entry.sourceBlueprint->mCategoryBitIndex)) {
              armyThreat.commanderInfluence += total;
            }
            if (IsInCategory(artilleryCategory, entry.sourceBlueprint->mCategoryBitIndex)) {
              armyThreat.artilleryInfluence += total;
            }

            armyThreat.antiAirInfluence += antiAir;
            armyThreat.antiSurfaceInfluence += antiSurface;
            armyThreat.antiSubInfluence += antiSub;
            armyThreat.economyInfluence += economy;
          } else {
            armyThreat.unknownInfluence += total;
          }
        }

        if (sim) {
          sim->mContext.Update(&entry.threatStrength, sizeof(entry.threatStrength));
        }
        ++it;
      }
    }

    if (sim) {
      const gpg::MD5Digest digest = sim->mContext.Digest();
      const msvc8::string checksum = digest.ToString();
      sim->Logf("after inf checksum=%s\n", checksum.c_str());
    }
  }

  CArmyImpl* CInfluenceMap::ResolveSourceArmy(const std::uint32_t blipId) const
  {
    if (!mArmy) {
      return nullptr;
    }

    Sim* const sim = mArmy->GetSim();
    if (!sim) {
      return nullptr;
    }

    const std::uint32_t armyIndex = (blipId >> 20u) & 0xFFu;
    if (armyIndex == 0xFFu || armyIndex >= sim->mArmiesList.size()) {
      return nullptr;
    }

    return sim->mArmiesList[armyIndex];
  }

  const InfluenceMapCellIndex* CInfluenceMap::FindBlipCell(const std::uint32_t blipId) const
  {
    InfluenceMapCellIndex key{};
    key.entityId = blipId;
    const auto it = mBlipCells.find(key);
    if (it == mBlipCells.end()) {
      return nullptr;
    }

    return &(*it);
  }

  void CInfluenceMap::UpsertBlipCell(const std::uint32_t blipId, const std::int32_t cellIndex)
  {
    RemoveBlipCell(blipId);
    mBlipCells.insert(InfluenceMapCellIndex{blipId, cellIndex});
  }

  void CInfluenceMap::RemoveBlipCell(const std::uint32_t blipId)
  {
    InfluenceMapCellIndex key{};
    key.entityId = blipId;
    const auto it = mBlipCells.find(key);
    if (it != mBlipCells.end()) {
      mBlipCells.erase(it);
    }
  }

  void CInfluenceMap::InsertEntry(
    const std::uint32_t blipId, const Wm3::Vec3f& position, const RUnitBlueprint* const sourceBlueprint
  )
  {
    const std::int32_t cellIndex = VectorToCoords(position);
    if (cellIndex < 0 || cellIndex >= mTotal) {
      return;
    }

    InfluenceMapEntry entry{};
    entry.entityId = blipId;
    entry.sourceArmy = ResolveSourceArmy(blipId);
    entry.lastPosition = position;
    entry.sourceBlueprint = sourceBlueprint;
    entry.sourceLayer = LAYER_None;
    entry.isDetailed = 0u;
    entry.pad_1D_1F[0] = 0u;
    entry.pad_1D_1F[1] = 0u;
    entry.pad_1D_1F[2] = 0u;
    entry.threatStrength = 1.0f;
    entry.threatDecay = (sourceBlueprint && sourceBlueprint->IsMobile()) ? 0.02f : 0.0f;
    entry.decayTicks = 10;

    InfluenceGrid& cell = mMapEntries[static_cast<std::size_t>(cellIndex)];
    const auto [it, inserted] = cell.entries.insert(entry);
    if (!inserted) {
      InfluenceMapEntry& mutableEntry = const_cast<InfluenceMapEntry&>(*it);
      mutableEntry = entry;
    }

    UpsertBlipCell(blipId, cellIndex);
  }

  void CInfluenceMap::RemoveEntry(const std::uint32_t blipId)
  {
    const InfluenceMapCellIndex* const blipCell = FindBlipCell(blipId);
    if (!blipCell) {
      return;
    }

    const std::int32_t cellIndex = blipCell->cellIndex;
    if (cellIndex >= 0 && cellIndex < mTotal) {
      mMapEntries[static_cast<std::size_t>(cellIndex)].RemoveEntry(blipId);
    }

    RemoveBlipCell(blipId);
  }

  bool CInfluenceMap::IsInCategory(const CategoryWordRangeView* const category, const std::uint32_t categoryBitIndex)
  {
    return category && category->ContainsBit(categoryBitIndex);
  }
} // namespace moho
