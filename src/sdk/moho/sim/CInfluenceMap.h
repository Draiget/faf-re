#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"
#include "legacy/containers/Set.h"
#include "legacy/containers/Vector.h"
#include "moho/entity/EntityCategoryReflection.h"
#include "Wm3Vector3.h"

namespace LuaPlus
{
  class LuaObject;
}

namespace moho
{
  class CArmyImpl;
  class Sim;
  struct RUnitBlueprint;

  enum EThreatType : std::int32_t
  {
    THREATTYPE_Overall = 0,
    THREATTYPE_OverallNotAssigned = 1,
    THREATTYPE_Structures = 2,
    THREATTYPE_StructuresNotMex = 3,
    THREATTYPE_Naval = 4,
    THREATTYPE_Land = 5,
    THREATTYPE_Air = 6,
    THREATTYPE_Experimental = 7,
    THREATTYPE_Commander = 8,
    THREATTYPE_Artillery = 9,
    THREATTYPE_AntiAir = 10,
    THREATTYPE_AntiSurface = 11,
    THREATTYPE_AntiSub = 12,
    THREATTYPE_Economy = 13,
    THREATTYPE_Unknown = 14,
  };
  static_assert(sizeof(EThreatType) == 0x04, "EThreatType size must be 0x04");

  struct SThreat
  {
    static gpg::RType* sType;
    [[nodiscard]] static gpg::RType* StaticGetClass();

    float overallInfluence;            // +0x00
    float influenceStructuresNotMex;   // +0x04
    float influenceStructures;         // +0x08
    float navalInfluence;              // +0x0C
    float airInfluence;                // +0x10
    float landInfluence;               // +0x14
    float experimentalInfluence;       // +0x18
    float commanderInfluence;          // +0x1C
    float artilleryInfluence;          // +0x20
    float antiAirInfluence;            // +0x24
    float antiSurfaceInfluence;        // +0x28
    float antiSubInfluence;            // +0x2C
    float economyInfluence;            // +0x30
    float unknownInfluence;            // +0x34

    void Clear() noexcept;
    void RecomputeOverall() noexcept;
    void DecayBy(const SThreat& decayRate) noexcept;
    [[nodiscard]] float ValueByType(EThreatType threatType) const noexcept;
  };

  /**
   * Address: 0x0071E760 (FUN_0071E760, func_VectorCpy_SThreat)
   *
   * What it does:
   * Copies one `SThreat` value into `count` consecutive destination slots.
   */
  void CopySThreatValueRange(SThreat* destination, std::uint32_t count, const SThreat* source) noexcept;

  /**
   * Address: 0x0071F6A0 (FUN_0071F6A0, func_VectorMemCpy_SThreat)
   *
   * What it does:
   * Copies one contiguous `SThreat` source range `[sourceBegin, sourceEnd)`
   * into destination storage and returns one-past the last destination slot.
   */
  SThreat* CopySThreatRangeNullable(SThreat* destination, const SThreat* sourceBegin, const SThreat* sourceEnd) noexcept;

  struct InfluenceMapEntry
  {
    static gpg::RType* sType;
    [[nodiscard]] static gpg::RType* StaticGetClass();

    std::uint32_t entityId;              // +0x00
    CArmyImpl* sourceArmy;               // +0x04
    Wm3::Vec3f lastPosition;             // +0x08
    const RUnitBlueprint* sourceBlueprint; // +0x14
    std::int32_t sourceLayer;            // +0x18
    std::uint8_t isDetailed;             // +0x1C
    std::uint8_t pad_1D_1F[0x03];        // +0x1D
    float threatStrength;                // +0x20
    float threatDecay;                   // +0x24
    std::int32_t decayTicks;             // +0x28
  };

  struct InfluenceMapEntryLess
  {
    [[nodiscard]] bool operator()(const InfluenceMapEntry& lhs, const InfluenceMapEntry& rhs) const noexcept
    {
      return lhs.entityId < rhs.entityId;
    }
  };

  struct InfluenceMapCellIndex
  {
    std::uint32_t entityId; // +0x00
    std::int32_t cellIndex; // +0x04
  };

  struct InfluenceMapCellIndexLess
  {
    [[nodiscard]] bool operator()(const InfluenceMapCellIndex& lhs, const InfluenceMapCellIndex& rhs) const noexcept
    {
      return lhs.entityId < rhs.entityId;
    }
  };

  class InfluenceGrid
  {
  public:
    static gpg::RType* sType;
    [[nodiscard]] static gpg::RType* StaticGetClass();

    /**
     * Address: 0x00715030 (FUN_00715030, ??0InfluenceGrid@Moho@@QAE@@Z)
     *
     * What it does:
     * Initializes per-cell influence storage and zeroes aggregated threat lanes.
     */
    InfluenceGrid();

    /**
     * Address: 0x00716350 (FUN_00716350, ??1InfluenceGrid@Moho@@QAE@@Z)
     *
     * What it does:
     * Releases per-cell entry map and per-army threat vector storage.
     */
    ~InfluenceGrid();

    /**
     * Address: 0x00715750 (FUN_00715750, ?GetThreat@InfluenceGrid@Moho@@QBEMW4EThreatType@2@H@Z)
     *
     * What it does:
     * Returns this cell's accumulated threat for one lane with optional army filter.
     */
    [[nodiscard]] float GetThreat(EThreatType threatType, int army) const;

    /**
     * Address: 0x00715130 (FUN_00715130, ?DecayInfluence@InfluenceGrid@Moho@@QAEPAV12@XZ)
     *
     * What it does:
     * Applies per-lane decay to shared threat lanes and recomputes overall.
     */
    void DecayInfluence();

    void EnsureThreatSlots(std::size_t armyCount);
    void ClearPerArmyThreats();
    [[nodiscard]] InfluenceMapEntry* FindEntry(std::uint32_t entityId);
    [[nodiscard]] const InfluenceMapEntry* FindEntry(std::uint32_t entityId) const;
    [[nodiscard]] bool RemoveEntry(std::uint32_t entityId);

  public:
    msvc8::set<InfluenceMapEntry, InfluenceMapEntryLess> entries; // +0x00
    msvc8::vector<SThreat> threats;                               // +0x0C
    SThreat threat;                                               // +0x1C
    SThreat decay;                                                // +0x54
  };

  class CInfluenceMap
  {
  public:
    static gpg::RType* sType;
    [[nodiscard]] static gpg::RType* StaticGetClass();

    /**
     * Address: 0x00715BC0 (FUN_00715BC0, ??0CInfluenceMap@Moho@@QAE@XZ)
     *
     * What it does:
     * Initializes empty influence-map storage for serializer construct paths.
     */
    CInfluenceMap();

    /**
     * Address: 0x00716140 (FUN_00716140, ??0CInfluenceMap@Moho@@QAE@Z)
     *
     * What it does:
     * Binds owner army/sim, computes influence grid dimensions, and initializes
     * one InfluenceGrid per map cell.
     */
    CInfluenceMap(std::int32_t gridSize, Sim* sim, CArmyImpl* army);

    /**
     * Address: 0x007163A0 (FUN_007163A0, ??1CInfluenceMap@Moho@@QAE@Z)
     *
     * What it does:
     * Releases id->cell lookup and per-cell influence grid storage.
     */
    ~CInfluenceMap();

    /**
     * Address: 0x00715C60 (FUN_00715C60, ?VectorToCoords@CInfluenceMap@Moho@@AAEHPAV?$Vector3@M@Wm3@@@Z)
     *
     * What it does:
     * Converts world position to clamped influence-grid linear cell index.
     */
    [[nodiscard]] std::int32_t VectorToCoords(const Wm3::Vec3f& pos) const;

    /**
     * Address: 0x00715F30 (FUN_00715F30, ?UpdateBlipPosition@CInfluenceMap@Moho@@QAEXHABV?$Vector3@M@Wm3@@PBVRUnitBlueprint@2@@Z)
     *
     * What it does:
     * Updates one blip's influence-entry cell, refreshing strength/position when
     * unchanged or re-inserting into a new cell when moved.
     */
    void UpdateBlipPosition(std::uint32_t blipId, const Wm3::Vec3f& position, const RUnitBlueprint* sourceBlueprint);

    /**
     * Address: 0x00715FF0 (FUN_00715FF0, ?GetThreatRect@CInfluenceMap@Moho@@QBEMHHH_W4EThreatType@2@H@Z)
     *
     * What it does:
     * Sums threat over a square neighborhood around `(x, z)` with optional
     * playable-rect restriction.
     */
    [[nodiscard]] float
    GetThreatRect(int x, int z, int radius, bool onMap, EThreatType threatType, int army) const;

    /**
     * Address: 0x00716E60 (FUN_00716E60, ?GetThreatBetweenPositions@CInfluenceMap@Moho@@QBEMABV?$Vector3@M@Wm3@@0_W4EThreatType@2@H@Z)
     *
     * What it does:
     * Samples threat along a grid-aligned path between two world positions.
     */
    [[nodiscard]] float GetThreatBetweenPositions(
      const Wm3::Vec3f& pos1, const Wm3::Vec3f& pos2, bool ring, EThreatType threatType, int armyIndex
    ) const;

    /**
     * Address: 0x007171D0 (FUN_007171D0, ?GetThreatsAroundPosition@CInfluenceMap@Moho@@QAE?AVLuaObject@LuaPlus@@AAV42@ABV?$Vector3@M@Wm3@@HHW4EThreatType@2@H@Z)
     *
     * What it does:
     * Emits positive-threat sample points around a center into a Lua table.
     */
    LuaPlus::LuaObject* GetThreatsAroundPosition(
      LuaPlus::LuaObject* outObj,
      const Wm3::Vec3f& pos,
      int ring,
      bool restrictToPlayable,
      EThreatType threatType,
      int armyIndex
    ) const;

    /**
     * Address: 0x00716480 (FUN_00716480, ?Update@CInfluenceMap@Moho@@QAEXXZ)
     *
     * What it does:
     * Decays/refreshes cell entry strengths and rebuilds per-army threat lanes.
     */
    void Update();

    /**
     * Address: 0x00716B00 (FUN_00716B00, ?AssignThreatAtPosition@CInfluenceMap@Moho@@QAEXABV?$Vector3@M@Wm3@@W4EThreatType@2@MM@Z)
     *
     * What it does:
     * Adds `assignedThreat` to the per-type threat lane of the cell
     * containing `position`, then writes the resulting accumulated
     * threat multiplied by `assignedDecay` into the matching decay
     * lane. When `assignedDecay` is negative the binary substitutes a
     * default `0.01` rate. `THREATTYPE_Overall` and `THREATTYPE_Unknown`
     * both map to the cell's `unknownInfluence` lane in the binary.
     */
    void AssignThreatAtPosition(
      const Wm3::Vec3f& position,
      EThreatType threatType,
      float assignedThreat,
      float assignedDecay
    );

    /**
     * Address: 0x00716FC0 (FUN_00716FC0, ?GetHighestThreatPosition@CInfluenceMap@Moho@@QBE?AV?$Vector3@M@Wm3@@AAMHHW4EThreatType@2@H@Z)
     *
     * What it does:
     * Scans the influence grid (optionally restricted to the playable
     * map rect / a single army) for the cell with the highest threat
     * value of the requested type within `radius` steps and returns
     * the cell's world-space center. The corresponding peak threat
     * value is written to `outThreat`.
     */
    Wm3::Vec3f* GetHighestThreatPosition(
      Wm3::Vec3f* outPosition,
      float* outThreat,
      int radius,
      bool onMap,
      EThreatType threatType,
      int armyIndex
    );

  private:
    using BlipCellSet = msvc8::set<InfluenceMapCellIndex, InfluenceMapCellIndexLess>;

    [[nodiscard]] CArmyImpl* ResolveSourceArmy(std::uint32_t blipId) const;
    [[nodiscard]] const InfluenceMapCellIndex* FindBlipCell(std::uint32_t blipId) const;
    void UpsertBlipCell(std::uint32_t blipId, std::int32_t cellIndex);
    void RemoveBlipCell(std::uint32_t blipId);
    void InsertEntry(std::uint32_t blipId, const Wm3::Vec3f& position, const RUnitBlueprint* sourceBlueprint);
    void RemoveEntry(std::uint32_t blipId);
    [[nodiscard]] static bool IsInCategory(const CategoryWordRangeView* category, std::uint32_t categoryBitIndex);

  public:
    CArmyImpl* mArmy;                     // +0x00
    std::int32_t mTotal;                  // +0x04
    std::int32_t mWidth;                  // +0x08
    std::int32_t mHeight;                 // +0x0C
    std::int32_t mGridSize;               // +0x10
    BlipCellSet mBlipCells;               // +0x14
    msvc8::vector<InfluenceGrid> mMapEntries; // +0x20
  };

  static_assert(sizeof(SThreat) == 0x38, "SThreat size must be 0x38");
  static_assert(sizeof(InfluenceMapEntry) == 0x2C, "InfluenceMapEntry size must be 0x2C");
  static_assert(sizeof(InfluenceMapCellIndex) == 0x08, "InfluenceMapCellIndex size must be 0x08");
  static_assert(sizeof(InfluenceGrid) == 0x8C, "InfluenceGrid size must be 0x8C");
  static_assert(offsetof(InfluenceGrid, entries) == 0x00, "InfluenceGrid::entries offset must be 0x00");
  static_assert(offsetof(InfluenceGrid, threats) == 0x0C, "InfluenceGrid::threats offset must be 0x0C");
  static_assert(offsetof(InfluenceGrid, threat) == 0x1C, "InfluenceGrid::threat offset must be 0x1C");
  static_assert(offsetof(InfluenceGrid, decay) == 0x54, "InfluenceGrid::decay offset must be 0x54");
  static_assert(sizeof(CInfluenceMap) == 0x30, "CInfluenceMap size must be 0x30");
  static_assert(offsetof(CInfluenceMap, mBlipCells) == 0x14, "CInfluenceMap::mBlipCells offset must be 0x14");
  static_assert(offsetof(CInfluenceMap, mMapEntries) == 0x20, "CInfluenceMap::mMapEntries offset must be 0x20");
} // namespace moho
