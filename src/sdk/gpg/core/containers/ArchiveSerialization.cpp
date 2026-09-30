#include "ArchiveSerialization.h"

#include <cstddef>
#include <cstdint>
#include <list>
#include <map>
#include <new>
#include <typeinfo>
#include <utility>
#include <vector>

#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/reflection/SerializationError.h"
#include "gpg/core/reflection/StaticInitPhase.h"
#include "moho/animation/IAniManipulator.h"
#include "moho/audio/CSndParams.h"
#include "moho/entity/PositionHistory.h"
#include "moho/render/CDecalHandle.h"
#include "moho/resource/blueprints/RMeshBlueprint.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/SPhysBody.h"
#include "moho/sim/SPhysConstants.h"
#include "gpg/core/utils/BoostWrappers.h"
#include "gpg/core/utils/Global.h"
#include "lua/LuaObject.h"
#include "lua/LuaPrimitives.h"
#include "moho/ai/EFormationdStatusTypeInfo.h"
#include "moho/ai/CAiBrain.h"
#include "moho/ai/CAiPersonality.h"
#include "moho/ai/CAiFormationInstance.h"
#include "moho/ai/CAiPathFinder.h"
#include "moho/ai/CAiPathSpline.h"
#include "moho/ai/IAiAttacker.h"
#include "moho/ai/IAiBuilder.h"
#include "moho/ai/IAiCommandDispatch.h"
#include "moho/ai/IAiFormationDB.h"
#include "moho/ai/IAiNavigator.h"
#include "moho/ai/IAiReconDB.h"
#include "moho/ai/IAiSiloBuild.h"
#include "moho/ai/IAiSteering.h"
#include "moho/ai/IAiTransport.h"
#include "moho/ai/IFormationInstance.h"
#include "moho/ai/IFormationInstanceCountedPtrReflection.h"
#include "moho/animation/CAniActor.h"
#include "moho/animation/CAniSkel.h"
#include "moho/animation/CAniPose.h"
#include "moho/audio/ISoundManager.h"
#include "moho/command/CCommandDb.h"
#include "moho/debug/RDebugOverlay.h"
#include "moho/entity/CTextureScroller.h"
#include "moho/entity/CollisionBeamEntity.h"
#include "moho/entity/ECollisionBeamEvent.h"
#include "moho/entity/Entity.h"
#include "moho/entity/Motor.h"
#include "moho/entity/EntityDb.h"
#include "moho/entity/intel/CIntelPosHandle.h"
#include "moho/entity/Shield.h"
#include "moho/entity/REntityBlueprintTypeInfo.h"
#include "moho/effects/rendering/CEffectImpl.h"
#include "moho/effects/rendering/IEffectManager.h"
#include "moho/misc/CEconomyEvent.h"
#include "moho/misc/Listener.h"
#include "moho/misc/LaunchInfoBase.h"
#include "moho/misc/Stats.h"
#include "moho/path/PathTables.h"
#include "moho/particles/SWorldBeam.h"
#include "moho/render/CDecalBuffer.h"
#include "moho/resource/ISimResources.h"
#include "moho/resource/CParticleTextureReflection.h"
#include "moho/resource/RScaResource.h"
#include "moho/resource/RScmResource.h"
#include "moho/resource/blueprints/REmitterBlueprint.h"
#include "moho/resource/blueprints/RProjectileBlueprint.h"
#include "moho/resource/blueprints/RTrailBlueprint.h"
#include "moho/path/IPathTraveler.h"
#include "moho/sim/CArmyStats.h"
#include "moho/sim/CDamage.h"
#include "moho/sim/CEconStorage.h"
#include "moho/sim/CEconomy.h"
#include "moho/sim/CInfluenceMap.h"
#include "moho/sim/CRandomStream.h"
#include "moho/sim/CSquad.h"
#include "moho/sim/CIntelGrid.h"
#include "moho/sim/CWldSession.h"
#include "moho/sim/IdPool.h"
#include "moho/sim/ReconBlip.h"
#include "moho/sim/Sim.h"
#include "moho/sim/SConditionTriggerTypes.h"
#include "moho/task/CCommandTask.h"
#include "moho/task/CTaskThread.h"
#include "moho/unit/EUnitCommandQueueStatus.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/tasks/CAcquireTargetTask.h"
#include "moho/unit/tasks/CFireWeaponTask.h"
#include "legacy/containers/Tree.h"
#include "ReadArchive.h"
#include "Rect2.h"
#include "String.h"
#include "WriteArchive.h"

using namespace gpg;

namespace
{
  /**
   * The reflected read/write callbacks a type descriptor installs: resolve the
   * cached `RType` for `T`, then hand the object to the archive. MSVC emits one
   * pair per element type; every recovered pair is cited here.
   */
  template <gpg::RType* (*ResolveType)()>
  /**
   * Address: 0x0050D190 (FUN_0050D190 -- the reflected `read` callback for `Rect2i`; zero callers, unreachable; formerly `ReadRect2iArchiveAdapter` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0050D1D0 (FUN_0050D1D0 -- the reflected `read` callback for `ELayer`; zero callers, unreachable; formerly `ReadELayerArchiveAdapter` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0050D2D0 (FUN_0050D2D0 -- the reflected `read` callback for `Rect2i`; zero callers, unreachable; formerly `ReadRect2iArchiveObjectLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0050D330 (FUN_0050D330 -- the reflected `read` callback for `ELayer`; zero callers, unreachable; formerly `ReadELayerArchiveObjectLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0064A040 (FUN_0064A040 -- the reflected `read` callback for `EEconResource`; zero callers, unreachable; formerly `ReadEEconResourceArchiveAdapter` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0064A0C0 (FUN_0064A0C0 -- the reflected `read` callback for `EEconResource`; zero callers, unreachable; formerly `ReadEEconResourceArchiveObjectLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00658C20 (FUN_00658C20 -- the reflected `read` callback for `CEffectImpl`; zero callers, unreachable; formerly `ReadCEffectImplArchiveAdapter` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00658C60 (FUN_00658C60 -- the reflected `read` callback for `SEntAttachInfo`; zero callers, unreachable; formerly `ReadSEntAttachInfoArchiveAdapter` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00658CA0 (FUN_00658CA0 -- the reflected `read` callback for `SWorldBeam`; zero callers, unreachable; formerly `ReadSWorldBeamArchiveAdapter` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00688C50 (FUN_00688C50 -- the reflected `read` callback for `IdPool`; zero callers, unreachable; formerly `ReadIdPoolArchiveAdapter` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00689190 (FUN_00689190 -- the reflected `read` callback for `IdPool`; zero callers, unreachable; formerly `ReadIdPoolArchiveObjectLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00689B40 (FUN_00689B40 -- the reflected `read` callback for `MapUIntIdPool`; zero callers, unreachable; formerly `ReadMapUIntIdPoolArchiveAdapter` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00689B80 (FUN_00689B80 -- the reflected `read` callback for `ListEntityPtr`; zero callers, unreachable; formerly `ReadListEntityPtrArchiveAdapter` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00689C70 (FUN_00689C70 -- the reflected `read` callback for `MapUIntIdPool`; zero callers, unreachable; formerly `ReadMapUIntIdPoolArchiveObjectLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00689CD0 (FUN_00689CD0 -- the reflected `read` callback for `ListEntityPtr`; zero callers, unreachable; formerly `ReadListEntityPtrArchiveObjectLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0071DB80 (FUN_0071DB80 -- the reflected `read` callback for `InfluenceMapEntry`; zero callers, unreachable; formerly `ReadInfluenceMapEntryArchiveObjectLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0071DBE0 (FUN_0071DBE0 -- the reflected `read` callback for `SThreat`; zero callers, unreachable; formerly `ReadSThreatArchiveObjectLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0071E310 (FUN_0071E310 -- the reflected `read` callback for `MapUIntInfluenceMapEntry`; zero callers, unreachable; formerly `ReadMapUIntInfluenceMapEntryArchiveAdapter` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0071E350 (FUN_0071E350 -- the reflected `read` callback for `VectorSThreat`; zero callers, unreachable; formerly `ReadVectorSThreatArchiveAdapter` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0071EEA0 (FUN_0071EEA0 -- the reflected `read` callback for `MapUIntInfluenceMapEntry`; zero callers, unreachable; formerly `ReadMapUIntInfluenceMapEntryArchiveObjectLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0071EF00 (FUN_0071EF00 -- the reflected `read` callback for `VectorSThreat`; zero callers, unreachable; formerly `ReadVectorSThreatArchiveObjectLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0071FAE0 (FUN_0071FAE0 -- the reflected `read` callback for `MapUIntInt`; zero callers, unreachable; formerly `ReadMapUIntIntArchiveAdapter` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0071FB20 (FUN_0071FB20 -- the reflected `read` callback for `VectorInfluenceGrid`; zero callers, unreachable; formerly `ReadVectorInfluenceGridArchiveAdapter` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0071FDE0 (FUN_0071FDE0 -- the reflected `read` callback for `MapUIntInt`; zero callers, unreachable; formerly `ReadMapUIntIntArchiveObjectLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0071FE40 (FUN_0071FE40 -- the reflected `read` callback for `VectorInfluenceGrid`; zero callers, unreachable; formerly `ReadVectorInfluenceGridArchiveObjectLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0072B620 (FUN_0072B620 -- the reflected `read` callback for `ESquadClass`; zero callers, unreachable; formerly `ReadESquadClassArchiveAdapter` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0072B6A0 (FUN_0072B6A0 -- the reflected `read` callback for `ESquadClass`; zero callers, unreachable; formerly `ReadESquadClassArchiveObjectLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x006941E0 (FUN_006941E0 -- the reflected `read` callback for `EntitySetBase` (called with a null owner ref); zero callers, unreachable; formerly `ReadEntitySetBaseArchiveObjectWithNullOwner` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x005592D0 (FUN_005592D0 -- the reflected `read` callback for `EntId` (called with a null owner ref); zero callers, unreachable; formerly `ReadEntIdArchiveObjectLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x005596F0 (FUN_005596F0 -- the reflected `read` callback for `EntId` (called with a null owner ref); zero callers, unreachable; formerly `ReadEntIdArchiveObjectLane2` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00763BA0 (FUN_00763BA0 -- the reflected `read` callback for `VectorHPathCell` (called with a null owner ref); zero callers, unreachable; formerly `ReadVectorHPathCellArchiveObjectWithNullOwner` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0077A6D0 (FUN_0077A6D0 -- the cached `RType` lookup those callbacks resolve through; callers ; formerly `ResolveInfluenceMapEntryArchiveAdapterType` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   */
  gpg::ReadArchive* ReadArchiveObjectOfType(gpg::ReadArchive* const archive, void* const object, const gpg::RRef& ownerRef)
  {
    archive->Read(ResolveType(), object, ownerRef);
    return archive;
  }

  /**
   * The write half of the pair above.
   */
  template <gpg::RType* (*ResolveType)()>
  /**
   * Address: 0x0050D210 (FUN_0050D210 -- the reflected `write` callback for `Rect2i`; zero callers, unreachable; formerly `WriteRect2iArchiveAdapter` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0050D250 (FUN_0050D250 -- the reflected `write` callback for `ELayer`; zero callers, unreachable; formerly `WriteELayerArchiveAdapter` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0050D300 (FUN_0050D300 -- the reflected `write` callback for `Rect2i`; zero callers, unreachable; formerly `WriteRect2iArchiveObjectLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0050D360 (FUN_0050D360 -- the reflected `write` callback for `ELayer`; zero callers, unreachable; formerly `WriteELayerArchiveObjectLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0064A080 (FUN_0064A080 -- the reflected `write` callback for `EEconResource`; zero callers, unreachable; formerly `WriteEEconResourceArchiveAdapter` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0064A0F0 (FUN_0064A0F0 -- the reflected `write` callback for `EEconResource`; zero callers, unreachable; formerly `WriteEEconResourceArchiveObjectLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00658CE0 (FUN_00658CE0 -- the reflected `write` callback for `CEffectImpl`; zero callers, unreachable; formerly `WriteCEffectImplArchiveAdapter` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00658D20 (FUN_00658D20 -- the reflected `write` callback for `SEntAttachInfo`; zero callers, unreachable; formerly `WriteSEntAttachInfoArchiveAdapter` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00658D60 (FUN_00658D60 -- the reflected `write` callback for `SWorldBeam`; zero callers, unreachable; formerly `WriteSWorldBeamArchiveAdapter` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00688C90 (FUN_00688C90 -- the reflected `write` callback for `IdPool`; zero callers, unreachable; formerly `WriteIdPoolArchiveAdapter` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x006891C0 (FUN_006891C0 -- the reflected `write` callback for `IdPool`; zero callers, unreachable; formerly `WriteIdPoolArchiveObjectLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00689BC0 (FUN_00689BC0 -- the reflected `write` callback for `MapUIntIdPool`; zero callers, unreachable; formerly `WriteMapUIntIdPoolArchiveAdapter` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00689C00 (FUN_00689C00 -- the reflected `write` callback for `ListEntityPtr`; zero callers, unreachable; formerly `WriteListEntityPtrArchiveAdapter` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00689CA0 (FUN_00689CA0 -- the reflected `write` callback for `MapUIntIdPool`; zero callers, unreachable; formerly `WriteMapUIntIdPoolArchiveObjectLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00689D00 (FUN_00689D00 -- the reflected `write` callback for `ListEntityPtr`; zero callers, unreachable; formerly `WriteListEntityPtrArchiveObjectLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00694220 (FUN_00694220 -- the reflected `write` callback for `EntitySetBase` (called with a null owner ref); zero callers, unreachable; formerly `WriteEntitySetBaseArchiveObjectWithNullOwner` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00559310 (FUN_00559310 -- the reflected `write` callback for `EntId` (called with a null owner ref); zero callers, unreachable; formerly `WriteEntIdArchiveObjectLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00559730 (FUN_00559730 -- the reflected `write` callback for `EntId` (called with a null owner ref); zero callers, unreachable; formerly `WriteEntIdArchiveObjectLane2` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0071DBB0 (FUN_0071DBB0 -- the reflected `write` callback for `InfluenceMapEntry`; zero callers, unreachable; formerly `WriteInfluenceMapEntryArchiveObjectLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0071DC10 (FUN_0071DC10 -- the reflected `write` callback for `SThreat`; zero callers, unreachable; formerly `WriteSThreatArchiveObjectLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0071E390 (FUN_0071E390 -- the reflected `write` callback for `MapUIntInfluenceMapEntry`; zero callers, unreachable; formerly `WriteMapUIntInfluenceMapEntryArchiveAdapter` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0071E3D0 (FUN_0071E3D0 -- the reflected `write` callback for `VectorSThreat`; zero callers, unreachable; formerly `WriteVectorSThreatArchiveAdapter` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0071EED0 (FUN_0071EED0 -- the reflected `write` callback for `MapUIntInfluenceMapEntry`; zero callers, unreachable; formerly `WriteMapUIntInfluenceMapEntryArchiveObjectLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0071EF30 (FUN_0071EF30 -- the reflected `write` callback for `VectorSThreat`; zero callers, unreachable; formerly `WriteVectorSThreatArchiveObjectLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0071FB60 (FUN_0071FB60 -- the reflected `write` callback for `MapUIntInt`; zero callers, unreachable; formerly `WriteMapUIntIntArchiveAdapter` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0071FBA0 (FUN_0071FBA0 -- the reflected `write` callback for `VectorInfluenceGrid`; zero callers, unreachable; formerly `WriteVectorInfluenceGridArchiveAdapter` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0071FE10 (FUN_0071FE10 -- the reflected `write` callback for `MapUIntInt`; zero callers, unreachable; formerly `WriteMapUIntIntArchiveObjectLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0071FE70 (FUN_0071FE70 -- the reflected `write` callback for `VectorInfluenceGrid`; zero callers, unreachable; formerly `WriteVectorInfluenceGridArchiveObjectLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0072B660 (FUN_0072B660 -- the reflected `write` callback for `ESquadClass`; zero callers, unreachable; formerly `WriteESquadClassArchiveAdapter` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x0072B6D0 (FUN_0072B6D0 -- the reflected `write` callback for `ESquadClass`; zero callers, unreachable; formerly `WriteESquadClassArchiveObjectLane1` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   * Address: 0x00763BE0 (FUN_00763BE0 -- the reflected `write` callback for `VectorHPathCell` (called with a null owner ref); zero callers, unreachable; formerly `WriteVectorHPathCellArchiveObjectWithNullOwner` in gpg/core/containers/ArchiveSerialization.cpp (RULE ONE), removed 2026-09-10.)
   */
  gpg::WriteArchive* WriteArchiveObjectOfType(gpg::WriteArchive* const archive, const void* const object, const gpg::RRef& ownerRef)
  {
    archive->Write(ResolveType(), object, ownerRef);
    return archive;
  }

  template <class T>
  [[nodiscard]] gpg::RType* CachedCompatRType()
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = gpg::LookupRType(typeid(T));
    }
    return sType;
  }

  template <class T>
  void SaveContiguousArchiveVectorPayload(
    gpg::WriteArchive* const archive,
    const T* const elements,
    const unsigned int count,
    gpg::RType* const elementType,
    const gpg::RRef& ownerRef
  )
  {
    archive->WriteUInt(count);

    for (unsigned int i = 0; i < count; ++i) {
      archive->Write(elementType, elements + i, ownerRef);
    }
  }

  static_assert(sizeof(moho::SPathNeighbor) == 0x08, "SPathNeighbor size must be 0x08");

  /**
   * Address: 0x0076D3C0 (FUN_0076D3C0, Moho::SPathNeighborTypeInfo::Init)
   * Address: 0x0076D3E0 (FUN_0076D3E0, Moho::SPathNeighborTypeInfo::GetName)
   * Address: 0x0076D3F0 (FUN_0076D3F0, Moho::SPathNeighborTypeInfo::dtr)
   *
   * What it does:
   * Reflected leaf `RType` descriptor for `std::pair<Moho::HPathCell,float>`
   * (`moho::SPathNeighbor`, the `{cell, weight}` neighbour the A* pathfinder
   * reflects for save/load). Matches the same scalar-`RType`-leaf shape as
   * `moho::SCollisionInfoTypeInfo` (CAiPathSpline.h/.cpp) and
   * `SUnitOffsetInfoTypeInfo` (CAiFormationInstance.cpp): only `GetName`/
   * `Init` are overridden - the dtor is the compiler-generated `~RType()`,
   * and `GetLexical`/`SetLexical`/`IsIndexed`/`IsPointer`/`IsEnumType`/
   * `Finish` keep the `gpg::RType` base implementation. RTTI-confirmed at
   * `??_7SPathNeighborTypeInfo@Moho@@6B@` (0xE36130, 11 primary slots; only
   * slots 2/3/9 diverge from the RType base, matching dtor/GetName/Init
   * above).
   */
  class SPathNeighborTypeInfo final : public gpg::RType
  {
  public:
    ~SPathNeighborTypeInfo() override = default;

    [[nodiscard]] const char* GetName() const override
    {
      return "SPathNeighbor";
    }

    void Init() override
    {
      size_ = sizeof(moho::SPathNeighbor);
      gpg::RType::Init();
      Finish();
    }
  };
  static_assert(sizeof(SPathNeighborTypeInfo) == 0x64, "SPathNeighborTypeInfo size must be 0x64");


  /**
   * Address: 0x0076D360 (FUN_0076D360, preregister_SPathNeighborTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for
   * `std::pair<Moho::HPathCell,float>`. Reached from `sub_BDCAD0`
   * (`.CRT$XCL`/`__xc_a` static-init table), the same shape as every other
   * scalar `RType` leaf preregistration this session. Fixes a real gap:
   * `SerSaveLoadHelper<SPathNeighbor>::Init` resolves this
   * type via a lazy `gpg::LookupRType(typeid(std::pair<moho::HPathCell,
   * float>))`, which throws `std::runtime_error` if nothing preregistered
   * the type first - this is what the real binary runs before that consumer
   * can ever execute.
   */
  [[nodiscard]] gpg::RType* preregister_SPathNeighborTypeInfo()
  {
    static SPathNeighborTypeInfo typeInfo;
    gpg::PreRegisterRType(typeid(std::pair<moho::HPathCell, float>), &typeInfo);
    return &typeInfo;
  }

  /**
   * `HPathCellSerializer`/`PathQueueSerializer`/`PathQueueImplSerializer`
   * moved out of this file (2026-08-25 investigation): each is now a real
   * `gpg::SerHelperBase`-derived class with a genuine `Init()` override,
   * asm-confirmed against 0x007632D0 / 0x00767080 / 0x00767140 respectively.
   * See `moho::HPathCellSerializer` (moho/ai/HPathCellSerializer.h/.cpp) and
   * `PathQueueSerializerHelper` / `PathQueueImplSerializerHelper`
   * (moho/path/PathTables.cpp).
   *
   * Demangled: gpg::SerSaveLoadHelper<class std::vector<Moho::HPathCell>>
   *
   * `NavPathSerializer` (real ctor `register_NavPathSerializer`,
   * 0x00BDC690, confirmed via vtable_writers class_name
   * `NavPathSerializer@Moho`) is the previously-deferred one from the same
   * investigation. It is now fully recovered: raw asm for `Deserialize`
   * (0x00763190) and `Serialize` (0x007631D0) shows both operate through
   * the `std::vector<Moho::HPathCell>` RType (`gpg::LookupRType(typeid(
   * msvc8::vector<moho::HPathCell>))`, cached), calling `archive->Read/
   * Write(type, objectPtr, RRef{})` directly on the raw object pointer with
   * NO field-offset adjustment and a *fresh empty* owner ref (the real
   * caller's owner ref is not forwarded) -- so this recovery does not need
   * to open up or reinterpret `moho::SNavPath`'s own fields at all; it just
   * has to resolve the right RType and forward the archive call, exactly
   * like every other vector-of-leaf serializer in this file.
   *
   * One real, still-open discrepancy this investigation surfaced but did
   * NOT fix (out of scope for this recovery, doesn't affect its
   * correctness): `moho::SNavPath` (`moho/ai/IAiNavigator.h`) types its
   * `start`/`finish`/`capacity` triple as `SOCellPos*`, but the RTTI
   * evidence above proves the real element type is `HPathCell`. Both are
   * plain `{int16 x; int16 z;}`-shaped 4-byte cells (`SOCellPos` signed,
   * `HPathCell` unsigned) so the byte layout is identical either way and
   * nothing here is unsafe -- but `SNavPath`'s own typing is very likely a
   * pre-existing naming mistake worth a dedicated pass (would ripple into
   * `AppendCells`/`PrependCells`/`AssignCopy`'s `SOCellPos*` parameters and
   * every caller of those methods, so not rushed here).
   */
  class NavPathSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BDC690 (FUN_00BDC690, register_NavPathSerializer)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields. The ctor's atexit target (`sub_C01770`)
     * is a plain unlink thunk, not a mangled destructor, so it is modeled
     * as the compiler's implicit static-destructor registration rather
     * than an explicit call.
     */
    NavPathSerializer();

    /**
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~NavPathSerializer();

    /**
     * Address: 0x00763190 (FUN_00763190, Moho::NavPathSerializer::Deserialize)
     *
     * What it does:
     * Reads one `std::vector<HPathCell>` payload directly at `objectPtr`
     * through the reflected vector type. `version` and the incoming
     * `ownerRef` are unused -- the real body passes a fresh empty `RRef`
     * to the nested archive call rather than forwarding either.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x007631D0 (FUN_007631D0, Moho::NavPathSerializer::Serialize)
     *
     * What it does:
     * Writes one `std::vector<HPathCell>` payload directly at `objectPtr`
     * through the reflected vector type, mirroring `Deserialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00763370 (FUN_00763370, gpg::SerSaveLoadHelper_NavPath::Init)
     *
     * What it does:
     * Lazily resolves the `Moho::NavPath` RTTI (registered under
     * `typeid(moho::SNavPath)` by `NavPathTypeInfo`, whose `GetName()`
     * returns `"NavPath"`) and installs load/save callbacks from this
     * helper object into the type descriptor.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };
  static_assert(offsetof(NavPathSerializer, mLoadCallback) == 0x0C, "NavPathSerializer::mLoadCallback offset must be 0x0C");
  static_assert(offsetof(NavPathSerializer, mSaveCallback) == 0x10, "NavPathSerializer::mSaveCallback offset must be 0x10");
  static_assert(sizeof(NavPathSerializer) == 0x14, "NavPathSerializer size must be 0x14");

  NavPathSerializer::NavPathSerializer()
    : mLoadCallback(&NavPathSerializer::Deserialize)
    , mSaveCallback(&NavPathSerializer::Serialize)
  {}

  NavPathSerializer::~NavPathSerializer() = default;

  void NavPathSerializer::Deserialize(
    gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const
  )
  {
    gpg::RType* const type = CachedCompatRType<msvc8::vector<moho::HPathCell>>();
    const gpg::RRef emptyOwner{};
    archive->Read(type, reinterpret_cast<void*>(objectPtr), emptyOwner);
  }

  void NavPathSerializer::Serialize(
    gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const
  )
  {
    gpg::RType* const type = CachedCompatRType<msvc8::vector<moho::HPathCell>>();
    const gpg::RRef emptyOwner{};
    archive->Write(type, reinterpret_cast<void*>(objectPtr), emptyOwner);
  }

  void NavPathSerializer::Init()
  {
    gpg::RType* const type = CachedCompatRType<moho::SNavPath>();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }

  NavPathSerializer gNavPathSerializerHelper;
  /**
   * `moho::SPathNeighborSerializer`, a `gpg::SerSaveLoadHelper<std::pair<Moho::HPathCell,float>>`:
   *
   * Address: 0x0076D4D0 (FUN_0076D4D0 -- the dynamic initializer constructing this global.)
   * Address: 0x0076D6D0 (FUN_0076D6D0 -- `Init`.)
   * Address: 0x0076D4A0 (FUN_0076D4A0 -- `Deserialize`, into `moho::SerLoadMembers`.)
   * Address: 0x0076D4B0 (FUN_0076D4B0 -- `Serialize`, into `moho::SerSaveMembers`.)
   */
  moho::SPathNeighborSerializer gSPathNeighborSerializerHelper;

  [[nodiscard]] gpg::RType* CachedPathQueueImplType()
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = gpg::REF_FindTypeNamed("Moho::PathQueue::Impl");
      if (sType == nullptr) {
        sType = gpg::REF_FindTypeNamed("PathQueue::Impl");
      }
      if (sType == nullptr) {
        sType = gpg::REF_FindTypeNamed("PathQueue_Impl");
      }
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* CachedSOffsetInfoType()
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = gpg::REF_FindTypeNamed("Moho::SOffsetInfo");
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* CachedSAssignedLocInfoType()
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = gpg::REF_FindTypeNamed("Moho::SAssignedLocInfo");
    }
    return sType;
  }
} // namespace

// Phase-1 pre-registration: run this descriptor registration ahead of every
// consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_SPathNeighborTypeInfo_a41c9e, preregister_SPathNeighborTypeInfo)

namespace gpg
{
  /**
   * Address: 0x00756130 (FUN_00756130, sub_756130)
   *
   * What it does:
   * Thin wrapper that materializes a temporary `RRef_Sim` and copies lanes
   * out.
   */
  gpg::RRef* AssignSimRef(gpg::RRef* const outRef, moho::Sim* const value)
  {
    gpg::RRef tmp{};
    tmp = gpg::MakeRRef<moho::Sim>(value);
    outRef->mObj = tmp.mObj;
    outRef->mType = tmp.mType;
    return outRef;
  }

  /**
   * Address: 0x007742C0 (FUN_007742C0)
   *
   * What it does:
   * Builds one temporary `RRef_CEconomy` and copies its `(mObj,mType)` pair
   * into caller-owned output storage.
   */
  [[maybe_unused]] gpg::RRef* PackRRef_CEconomy(gpg::RRef* const outRef, moho::CEconomy* const value)
  {
    if (outRef == nullptr) {
      return nullptr;
    }

    gpg::RRef temp{};
    temp = gpg::MakeRRef<moho::CEconomy>(value);
    outRef->mObj = temp.mObj;
    outRef->mType = temp.mType;
    return outRef;
  }

  /**
   * Address: 0x00774390 (FUN_00774390)
   *
   * What it does:
   * Builds one temporary `RRef_CEconStorage` and copies its `(mObj,mType)`
   * pair into caller-owned output storage.
   */
  [[maybe_unused]] gpg::RRef* PackRRef_CEconStorage(gpg::RRef* const outRef, moho::CEconStorage* const value)
  {
    if (outRef == nullptr) {
      return nullptr;
    }

    gpg::RRef temp{};
    temp = gpg::MakeRRef<moho::CEconStorage>(value);
    outRef->mObj = temp.mObj;
    outRef->mType = temp.mType;
    return outRef;
  }

  /**
   * Address: 0x00778340 (FUN_00778340)
   *
   * What it does:
   * Builds one temporary `RRef_CTextureScroller` and copies its
   * `(mObj,mType)` pair into caller-owned output storage.
   */
  [[maybe_unused]] gpg::RRef* PackRRef_CTextureScroller(
    gpg::RRef* const outRef,
    moho::CTextureScroller* const value
  )
  {
    if (outRef == nullptr) {
      return nullptr;
    }

    gpg::RRef temp{};
    temp = gpg::MakeRRef<moho::CTextureScroller>(value);
    outRef->mObj = temp.mObj;
    outRef->mType = temp.mType;
    return outRef;
  }

  /**
   * Address: 0x0076A5F0 (FUN_0076A5F0, gpg::RRef_PathQueue_Impl)
   *
   * What it does:
   * Builds one reflected reference for `moho::PathQueue::Impl` using the
   * preregistered named RTTI lane for the opaque impl payload.
   */
  gpg::RRef* RRef_PathQueue_Impl(gpg::RRef* const outRef, moho::PathQueue::Impl* const value)
  {
    if (outRef == nullptr) {
      return nullptr;
    }

    outRef->mObj = value;
    outRef->mType = CachedPathQueueImplType();
    return outRef;
  }

  /**
   * Address: 0x00768CA0 (FUN_00768CA0)
   *
   * What it does:
   * Builds one temporary `RRef_PathQueue_Impl` and copies its `(mObj,mType)`
   * pair into caller-owned output storage.
   */
  [[maybe_unused]] gpg::RRef* PackRRef_PathQueue_Impl(gpg::RRef* const outRef, moho::PathQueue::Impl* const value)
  {
    if (outRef == nullptr) {
      return nullptr;
    }

    gpg::RRef temp{};
    (void)RRef_PathQueue_Impl(&temp, value);
    outRef->mObj = temp.mObj;
    outRef->mType = temp.mType;
    return outRef;
  }

  /**
   * Address: 0x0055D590 (FUN_0055D590)
   *
   * What it does:
   * Writes one contiguous `UnitWeaponInfo` payload by saving the element count
   * and each reflected lane in order.
   */
  void SaveFastVectorUnitWeaponInfo(
    gpg::WriteArchive* const archive,
    int objectPtr,
    int /*version*/,
    gpg::RRef* const ownerRef
  )
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    const auto& weapons =
      *reinterpret_cast<const gpg::core::FastVector<moho::UnitWeaponInfo>*>(static_cast<std::uintptr_t>(objectPtr));
    SaveContiguousArchiveVectorPayload(
      archive,
      weapons.Data(),
      static_cast<unsigned int>(weapons.Size()),
      CachedCompatRType<moho::UnitWeaponInfo>(),
      ownerRef ? *ownerRef : gpg::RRef{}
    );
  }

  // DB-integrity fix: this file previously carried two more unwired
  // duplicates here, `SaveFastVectorSOffsetInfo` (wrongly claiming Address:
  // 0x0056DF80, and using `moho::SUnitOffsetInfo` -- the wrong element type)
  // and `SaveFastVectorSAssignedLocInfo` (wrongly claiming Address:
  // 0x0056E0A0, and using `moho::SFormationOccupiedSlot` -- also the wrong
  // element type). Both real bodies are `moho::SaveFastVectorSOffsetInfo`/
  // `moho::SaveFastVectorSAssignedLocInfo` in CAiFormationInstance.cpp (using
  // the correctly-named `moho::SOffsetInfo`/`moho::SAssignedLocInfo`), which
  // are also the ones actually wired into `FastVectorUIntReflection.cpp`'s
  // `serSaveFunc_ = &moho::SaveFastVectorSOffsetInfo` / `&moho::
  // SaveFastVectorSAssignedLocInfo` (`RFastVectorType<...>::Init()`). Both
  // orphan copies here had zero header declaration and zero callers anywhere
  // in src/sdk -- removed rather than left as dead, address-misattributed
  // code, matching the `SaveFastVectorCPathPoint` resolution just below.

  // DB-integrity fix: this file previously carried a second, unwired
  // `SaveFastVectorCPathPoint` here, wrongly claiming Address: 0x005B4FF0.
  // The real 0x005B4FF0 body (confirmed against the .c/.asm: a direct
  // `(end-begin)/28` count with a plain per-element `WriteArchive::Write`
  // loop, no a runtime-view overlay / `SaveContiguousArchiveVectorPayload`
  // calls anywhere) is `moho`-anonymous-namespace `SaveFastVectorCPathPoint`
  // in CAiPathSpline.cpp, which is also the one actually wired into
  // `FastVectorCPathPointTypeInfo::Init()`'s `serSaveFunc_`. This orphan
  // copy had zero header declaration and zero callers anywhere in
  // src/sdk -- removed rather than left as dead, address-misattributed code.

  /**
   * Address: 0x005C5860 (FUN_005C5860)
   *
   * What it does:
   * Writes one contiguous `vector<SPerArmyReconInfo>` payload by saving the
   * element count and each reflected lane in order.
   */
  void SaveVectorSPerArmyReconInfo(
    gpg::WriteArchive* const archive,
    int objectPtr,
    int /*version*/,
    gpg::RRef* const ownerRef
  )
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    const auto* const storage =
      reinterpret_cast<const msvc8::vector<moho::SPerArmyReconInfo>*>(static_cast<std::uintptr_t>(objectPtr));
    SaveContiguousArchiveVectorPayload(
      archive, storage->data(), static_cast<unsigned int>(storage->size()),
      CachedCompatRType<moho::SPerArmyReconInfo>(), ownerRef ? *ownerRef : gpg::RRef{}
    );
  }

  /**
   * Address: 0x005C5700 (FUN_005C5700)
   *
   * What it does:
   * Reads one contiguous `vector<SPerArmyReconInfo>` payload: element count,
   * then that many reflected `moho::SPerArmyReconInfo` values read into a
   * fresh temporary vector, which replaces the destination vector's storage
   * (releasing the old buffer). Bound as `RType::serLoadFunc_`; `version`/
   * `ownerRef` are unused by this body, mirroring `gpg::
   * DeserializeSimArmyPtrVector` (Reflection.cpp). Unlike its `Save*`
   * sibling above, the binary body has no `archive`/`objectPtr` null guard
   * -- every real call site (`ReadArchive::Read` dispatch through this
   * type's `serLoadFunc_`) always supplies both, so none is added here.
   * The element type is resolved through `moho::SPerArmyReconInfo::sType`
   * directly (lazily populated via `gpg::LookupRType` on first use) rather
   * than through this file's generic `CachedCompatRType<T>()` helper --
   * a real, deliberate difference from the `Save` side confirmed against
   * the `.c`/`.asm` (`Moho::SPerArmyReconInfo::sType` is read and, if null,
   * assigned from `gpg::LookupRType`, matching the class's own public
   * `static gpg::RType* sType` member already used by `gpg::
   * RRef_SPerArmyReconInfo`).
   */
  void LoadVectorSPerArmyReconInfo(
    gpg::ReadArchive* const archive,
    int objectPtr,
    int /*version*/,
    gpg::RRef* /*ownerRef*/
  )
  {
    auto* const outVector =
      reinterpret_cast<msvc8::vector<moho::SPerArmyReconInfo>*>(static_cast<std::uintptr_t>(objectPtr));

    unsigned int count = 0;
    archive->ReadUInt(&count);

    msvc8::vector<moho::SPerArmyReconInfo> loaded;
    loaded.reserve(count);

    if (!moho::SPerArmyReconInfo::sType) {
      moho::SPerArmyReconInfo::sType = gpg::LookupRType(typeid(moho::SPerArmyReconInfo));
    }

    const gpg::RRef emptyOwner{};
    for (unsigned int i = 0; i < count; ++i) {
      moho::SPerArmyReconInfo element{};
      archive->Read(moho::SPerArmyReconInfo::sType, &element, emptyOwner);
      loaded.push_back(element);
    }

    *outVector = std::move(loaded);
  }

  /**
   * Address: 0x00702250 (FUN_00702250)
   *
   * What it does:
   * Writes one contiguous `vector<EntitySetTemplate<Unit>>` payload by saving
   * the element count and each reflected lane in order.
   */
  void SaveVectorEntitySetTemplateUnit(
    gpg::WriteArchive* const archive,
    int objectPtr,
    int /*version*/,
    gpg::RRef* const ownerRef
  )
  {
    if (archive == nullptr || objectPtr == 0) {
      return;
    }

    const auto* const storage = reinterpret_cast<const msvc8::vector<moho::EntitySetTemplate<moho::Unit>>*>(
      static_cast<std::uintptr_t>(objectPtr)
    );
    SaveContiguousArchiveVectorPayload(
      archive, storage->data(), static_cast<unsigned int>(storage->size()),
      CachedCompatRType<moho::EntitySetTemplate<moho::Unit>>(), ownerRef ? *ownerRef : gpg::RRef{}
    );
  }
} // namespace gpg

namespace
{
  constexpr const char* kSerializationCppPath = "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore\\reflection\\serialization.cpp";

  [[noreturn]] void ThrowSerializationError(const char* const message)
  {
    throw SerializationError(message ? message : "");
  }

  [[noreturn]] void ThrowSerializationError(const msvc8::string& message)
  {
    throw SerializationError(message.c_str());
  }

  const char* SafeTypeName(const RType* const type)
  {
    return type ? type->GetName() : "null";
  }

} // namespace

/**
 * Address: 0x0094F5E0 (FUN_0094F5E0, gpg::SerConstructResult::SetOwned)
 *
 * What it does:
 * Transitions one construct-result lane from `RESERVED` to `OWNED`, stores the
 * reflected object reference, and clears the member-load flag when bit 0 in
 * `flags` is set.
 */
void gpg::SerConstructResult::SetOwned(const RRef& ref, const unsigned int flags)
{
  if (mInfo.state != TrackedPointerState::Reserved) {
    gpg::HandleAssertFailure("mInfo.mState == RESERVED", 196, kSerializationCppPath);
  }

  mInfo.object = ref.mObj;
  mInfo.type = ref.mType;
  mInfo.state = TrackedPointerState::Owned;
  if ((flags & 1u) != 0u) {
    mLoadMembers = false;
  }
}

/**
 * Address: 0x0094F630 (FUN_0094F630, gpg::SerConstructResult::SetUnowned)
 *
 * What it does:
 * Transitions one construct-result lane from `RESERVED` to `UNOWNED`, stores
 * the reflected object reference, and clears the member-load flag when bit 0
 * in `flags` is set.
 */
void gpg::SerConstructResult::SetUnowned(const RRef& ref, const unsigned int flags)
{
  if (mInfo.state != TrackedPointerState::Reserved) {
    gpg::HandleAssertFailure("mInfo.mState == RESERVED", 204, kSerializationCppPath);
  }

  mInfo.object = ref.mObj;
  mInfo.type = ref.mType;
  mInfo.state = TrackedPointerState::Unowned;
  if ((flags & 1u) != 0u) {
    mLoadMembers = false;
  }
}

/**
 * Address: 0x0094F680 (FUN_0094F680, gpg::SerConstructResult::SetShared)
 * Mangled: ?SetShared@SerConstructResult@gpg@@QAEXABVRRef@2@I@Z_0
 *
 * What it does:
 * Transitions one construct-result lane from `RESERVED` to `SHARED`, stores
 * the reflected object reference lane directly, and clears the member-load
 * flag when bit 0 in `flags` is set.
 */
void gpg::SerConstructResult::SetShared(const RRef& ref, const unsigned int flags)
{
  if (mInfo.state != TrackedPointerState::Reserved) {
    gpg::HandleAssertFailure("mInfo.mState == RESERVED", 212, kSerializationCppPath);
  }

  mInfo.object = ref.mObj;
  mInfo.type = ref.mType;
  mInfo.state = TrackedPointerState::Shared;
  if ((flags & 1u) != 0u) {
    mLoadMembers = false;
  }
}

/**
 * Address: 0x0094F6D0 (FUN_0094F6D0, gpg::SerConstructResult::SetShared)
 *
 * What it does:
 * Transitions one construct-result lane from `RESERVED` to `SHARED`, takes a
 * reference on `object` and stores it as the reflected object, and clears the
 * member-load flag when bit 0 in `flags` is set.
 */
void gpg::SerConstructResult::SetShared(
  const boost::shared_ptr<void>& object,
  RType* const type,
  const unsigned int flags
)
{
  if (mInfo.state != TrackedPointerState::Reserved) {
    gpg::HandleAssertFailure("mInfo.mState == RESERVED", 220, kSerializationCppPath);
  }

  mInfo.sharedPtr = object;
  mInfo.object = object.get();
  mInfo.type = type;
  mInfo.state = TrackedPointerState::Shared;
  if ((flags & 1u) != 0u) {
    mLoadMembers = false;
  }
}

/**
 * Address: 0x0094F750 (FUN_0094F750, gpg::SerSaveConstructArgsResult::SetOwned)
 * Mangled: ?SetOwned@SerSaveConstructArgsResult@gpg@@QAEXI@Z_0
 *
 * What it does:
 * Transitions one save-construct result lane from `RESERVED` to `OWNED`
 * and clears the write-members flag when bit 0 in `flags` is set.
 */
void gpg::SerSaveConstructArgsResult::SetOwned(const unsigned int flags)
{
  if (mOwnership != TrackedPointerState::Reserved) {
    gpg::HandleAssertFailure("mOwnership == RESERVED", 402, kSerializationCppPath);
  }

  mOwnership = TrackedPointerState::Owned;
  if ((flags & 1u) != 0u) {
    mWriteMembers = false;
  }
}

/**
 * Address: 0x0094F790 (FUN_0094F790, gpg::SerSaveConstructArgsResult::SetUnowned)
 *
 * What it does:
 * Transitions one save-construct result lane from `RESERVED` to `UNOWNED`
 * and clears the write-members flag when bit 0 in `flags` is set.
 */
void gpg::SerSaveConstructArgsResult::SetUnowned(const unsigned int flags)
{
  if (mOwnership != TrackedPointerState::Reserved) {
    gpg::HandleAssertFailure("mOwnership == RESERVED", 409, kSerializationCppPath);
  }

  mOwnership = TrackedPointerState::Unowned;
  if ((flags & 1u) != 0u) {
    mWriteMembers = false;
  }
}

/**
 * Address: 0x0094F7D0 (FUN_0094F7D0, gpg::SerSaveConstructArgsResult::SetShared)
 *
 * What it does:
 * Transitions one save-construct result lane from `RESERVED` to `SHARED`
 * and clears the write-members flag when bit 0 in `flags` is set.
 */
void gpg::SerSaveConstructArgsResult::SetShared(const unsigned int flags)
{
  if (mOwnership != TrackedPointerState::Reserved) {
    gpg::HandleAssertFailure("mOwnership == RESERVED", 416, kSerializationCppPath);
  }

  mOwnership = TrackedPointerState::Shared;
  if ((flags & 1u) != 0u) {
    mWriteMembers = false;
  }
}

/**
 * Address: 0x00953320 (FUN_00953320)
 * Demangled: gpg::WriteArchive::WriteRawPointer
 *
 * What it does:
 * Writes tracked-pointer token payload and serializes newly seen pointees.
 */
void gpg::WriteRawPointer(
  WriteArchive* const archive, const RRef& objectRef, const TrackedPointerState state, const RRef& ownerRef
)
{
  if (!archive) {
    ThrowSerializationError("Error while creating archive: null WriteArchive.");
  }

  if (!objectRef.mObj) {
    archive->WriteMarker(static_cast<int>(ArchiveToken::NullPointer));
    return;
  }

  const auto found = archive->mObjRefs.find(objectRef);
  WriteArchive::TrackedPointerRecord* record = nullptr;

  if (found == archive->mObjRefs.end()) {
    WriteArchive::TrackedPointerRecord fresh{};
    fresh.index = static_cast<int>(archive->mObjRefs.size());
    fresh.ownership = TrackedPointerState::Reserved;

    const auto inserted = archive->mObjRefs.insert({objectRef, fresh});
    record = &inserted.first->second;

    archive->WriteMarker(static_cast<int>(ArchiveToken::NewObject));

    RType* const objectType = objectRef.mType;
    if (!objectType || (!objectType->serConstructFunc_ && !objectType->newRefFunc_)) {
      ThrowSerializationError(STR_Printf(
        "Error while creating archive: encounted a pointer to an object of type \"%s\", but we don't have a "
        "constructor for it.",
        SafeTypeName(objectType)
      ));
    }

    archive->WriteRefCounts(objectType);

    // A type with a save-construct hook writes its own construction arguments
    // here, and may then declare that the member payload must be skipped -- the
    // reader will rebuild the object from those arguments alone. `CSndParams`
    // does exactly that (`SaveConstructArgs` at 0x004E0CD0 writes one
    // `SParamKey` and calls `SetOwned(1)`), which is why the reader can hand
    // back the one shared descriptor for that key instead of a fresh object.
    SerSaveConstructArgsResult saveResult{};

    if (objectType->serSaveConstructArgsFunc_) {
      objectType->serSaveConstructArgsFunc_(
        archive,
        objectRef.mObj,
        objectType->version_,
        const_cast<RRef*>(&ownerRef),
        &saveResult
      );
      if (saveResult.mOwnership == TrackedPointerState::Reserved) {
        gpg::HandleAssertFailure("saveConstructArgsResult.mOwnership != RESERVED", 319, kSerializationCppPath);
      }
    } else {
      saveResult.mOwnership = TrackedPointerState::Unowned;
    }

    if (record->ownership != TrackedPointerState::Reserved) {
      gpg::HandleAssertFailure("iter->second.mOwnership == RESERVED", 321, kSerializationCppPath);
    }
    record->ownership = saveResult.mOwnership;

    if (saveResult.mWriteMembers != 0u) {
      if (!objectType->serSaveFunc_) {
        ThrowSerializationError(STR_Printf(
          "Error while creating archive: encounted an object of type \"%s\", but we don't have a save function for it.",
          SafeTypeName(objectType)
        ));
      }

      objectType->serSaveFunc_(
        archive, reinterpret_cast<int>(objectRef.mObj), objectType->version_, const_cast<RRef*>(&ownerRef)
      );
    }

    archive->WriteMarker(static_cast<int>(ArchiveToken::ObjectTerminator));
  } else {
    record = &found->second;
    if (record->ownership == TrackedPointerState::Reserved) {
      ThrowSerializationError(
        "Error while creating archive: recursively encountered a pointer to an object for which construction data is "
        "still being written"
      );
    }

    archive->WriteMarker(static_cast<int>(ArchiveToken::ExistingPointer));
    archive->WriteInt(record->index);
  }

  if (state == TrackedPointerState::Owned) {
    if (record->ownership != TrackedPointerState::Unowned) {
      ThrowSerializationError("Ownership conflict while writing archive.");
    }
    record->ownership = TrackedPointerState::Owned;
  } else if (state == TrackedPointerState::Shared) {
    if (record->ownership == TrackedPointerState::Owned) {
      ThrowSerializationError("Shared/owned conflict while writing archive.");
    }
    record->ownership = TrackedPointerState::Shared;
  }
}

/**
 * Address: 0x00953720 (FUN_00953720)
 * Demangled: gpg::ReadArchive::ReadRawPointer
 *
 * What it does:
 * Reads pointer token payload and resolves a tracked pointer reference.
 */
TrackedPointerInfo& gpg::ReadRawPointer(ReadArchive* const archive, const RRef& ownerRef)
{
  if (!archive) {
    ThrowSerializationError("Error detected in archive: null ReadArchive.");
  }

  const ArchiveToken token = static_cast<ArchiveToken>(archive->NextMarker());
  if (token == ArchiveToken::NullPointer) {
    archive->mNullTrackedPointer = {};
    return archive->mNullTrackedPointer;
  }

  if (token == ArchiveToken::ExistingPointer) {
    int index = -1;
    archive->ReadInt(&index);

    if (index < 0 || static_cast<size_t>(index) >= archive->mTrackedPtrs.size()) {
      ThrowSerializationError(STR_Printf(
        "Error detected in archive: found a reference to an existing pointer of index %d, but only %d pointers have "
        "been created.",
        index,
        static_cast<int>(archive->mTrackedPtrs.size())
      ));
    }

    TrackedPointerInfo& tracked = archive->mTrackedPtrs[static_cast<size_t>(index)];
    if (tracked.state == TrackedPointerState::Reserved) {
      ThrowSerializationError(
        "Error detected in archive: found a reference to an existing pointer that has not been constructed yet."
      );
    }
    return tracked;
  }

  if (token != ArchiveToken::NewObject) {
    ThrowSerializationError(
      STR_Printf("Error detected in archive: found an invalid token value of %d", static_cast<int>(token))
    );
  }

  // The slot is claimed BEFORE the type handle is read, exactly as the binary
  // does it (0x00953720 computes the index and pushes an empty record before
  // `ReadTypeHandle`). It matters as soon as construct hooks run: `CSndParams`'s
  // hook reads an `SParamKey` out of the stream, and anything nested in there
  // takes the next index. The writer reserves its index at the same point
  // (0x00953320 inserts the record before `WriteRefCounts`), so back-references
  // only line up if both sides claim first and fill in after.
  const size_t trackedIndex = archive->mTrackedPtrs.size();
  archive->mTrackedPtrs.push_back(TrackedPointerInfo{});

  const TypeHandle handle = archive->ReadTypeHandle();
  if (!handle.type) {
    ThrowSerializationError("Error detected in archive: null type handle.");
  }

  SerConstructResult constructResult{};

  if (handle.type->serConstructFunc_) {
    handle.type->serConstructFunc_(
      archive,
      handle.version,
      const_cast<RRef*>(&ownerRef),
      &constructResult
    );
    if (constructResult.mInfo.state == TrackedPointerState::Reserved) {
      gpg::HandleAssertFailure("constructResult.mInfo.mState != RESERVED", 156, kSerializationCppPath);
    }
  } else {
    if (!handle.type->newRefFunc_) {
      ThrowSerializationError(STR_Printf(
        "Error detected in archive: found a pointer to an object of type \"%s\", but we don't have a constructor for "
        "it.",
        SafeTypeName(handle.type)
      ));
    }

    const RRef objectRef = handle.type->newRefFunc_();
    constructResult.mInfo.object = objectRef.mObj;
    constructResult.mInfo.type = objectRef.mType ? objectRef.mType : handle.type;
    constructResult.mInfo.state = TrackedPointerState::Unowned;
  }

  archive->mTrackedPtrs[trackedIndex] = constructResult.mInfo;

  // A construct hook that rebuilt the object from its own arguments clears this
  // flag, and the member payload it skipped on the way out is not in the stream
  // to be read back.
  if (constructResult.mLoadMembers) {
    if (!handle.type->serLoadFunc_) {
      ThrowSerializationError(STR_Printf(
        "Error detected in archive: found an object of type \"%s\", but we don't have a loader for it.",
        SafeTypeName(handle.type)
      ));
    }

    handle.type->serLoadFunc_(
      archive,
      reinterpret_cast<int>(constructResult.mInfo.object),
      handle.version,
      const_cast<RRef*>(&ownerRef)
    );
  }

  if (archive->NextMarker() != static_cast<int>(ArchiveToken::ObjectTerminator)) {
    ThrowSerializationError(STR_Printf(
      "Error detected in archive: data for object of type \"%s\" did not terminate properly.",
      SafeTypeName(handle.type)
    ));
  }

  return archive->mTrackedPtrs[trackedIndex];
}

namespace
{
  /**
   * What it does:
   * Writes `value` as a tracked pointer in `trackedState`, owned by nothing:
   * `WriteRawPointer` of `MakeRRef<TObject>(value)`.
   */
  [[nodiscard]] gpg::RType* ResolveCThrustManipulatorArchiveAdapterType()
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = gpg::REF_FindTypeNamed("Moho::CThrustManipulator");
      if (sType == nullptr) {
        sType = gpg::REF_FindTypeNamed("CThrustManipulator");
      }
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* ResolveRDebugOverlayArchiveAdapterType()
  {
    gpg::RType* type = moho::RDebugOverlay::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::RDebugOverlay));
      moho::RDebugOverlay::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* ResolveREmitterBlueprintArchiveAdapterType()
  {
    gpg::RType* type = moho::REmitterBlueprint::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::REmitterBlueprint));
      moho::REmitterBlueprint::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* ResolveRTrailBlueprintArchiveAdapterType()
  {
    gpg::RType* type = moho::RTrailBlueprint::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::RTrailBlueprint));
      moho::RTrailBlueprint::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* ResolveCollisionBeamEntityArchiveAdapterType()
  {
    gpg::RType* type = moho::CollisionBeamEntity::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::CollisionBeamEntity));
      moho::CollisionBeamEntity::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* ResolveManyToOneCollisionBeamEventArchiveAdapterType()
  {
    gpg::RType* type = moho::ManyToOneListener_ECollisionBeamEvent::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::ManyToOneListener_ECollisionBeamEvent));
      moho::ManyToOneListener_ECollisionBeamEvent::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* ResolveRProjectileBlueprintArchiveAdapterType()
  {
    gpg::RType* type = moho::RProjectileBlueprint::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::RProjectileBlueprint));
      moho::RProjectileBlueprint::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* ResolveEntitySetBaseArchiveAdapterType()
  {
    gpg::RType* type = moho::EntitySetBase::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::EntitySetBase));
      moho::EntitySetBase::sType = type;
    }
    return type;
  }

  /**
   * Address: 0x0050AD20 (FUN_0050AD20)
   *
   * What it does:
   * Forwards one integer lane to `WriteArchive::WriteUByte`.
   */
  [[maybe_unused]] gpg::WriteArchive* WriteUByteArchiveLaneValueFromInt(
    gpg::WriteArchive* const archive,
    const int value
  )
  {
    archive->WriteUByte(static_cast<unsigned __int8>(value));
    return archive;
  }

  /**
   * Address: 0x0050AD40 (FUN_0050AD40)
   *
   * What it does:
   * Dereferences one byte lane and forwards it to `WriteArchive::WriteUByte`.
   */
  [[maybe_unused]] gpg::WriteArchive* WriteUByteArchiveLaneValueFromPointer(
    gpg::WriteArchive* const archive,
    const unsigned __int8* const value
  )
  {
    archive->WriteUByte(*value);
    return archive;
  }

  /**
   * Address: 0x0050AD60 (FUN_0050AD60)
   *
   * What it does:
   * Forwards one integer lane to `WriteArchive::WriteShort`.
   */
  [[maybe_unused]] gpg::WriteArchive* WriteShortArchiveLaneValueFromInt(
    gpg::WriteArchive* const archive,
    const int value
  )
  {
    archive->WriteShort(static_cast<short>(value));
    return archive;
  }

  /**
   * Address: 0x0050AD70 (FUN_0050AD70)
   *
   * What it does:
   * Dereferences one 16-bit lane and forwards it to `WriteArchive::WriteShort`.
   */
  [[maybe_unused]] gpg::WriteArchive* WriteShortArchiveLaneValueFromPointer(
    gpg::WriteArchive* const archive,
    const unsigned short* const value
  )
  {
    archive->WriteShort(static_cast<short>(*value));
    return archive;
  }

  /**
   * Address: 0x0050CD30 (FUN_0050CD30)
   *
   * What it does:
   * Writes two consecutive 32-bit lanes through `WriteArchive::WriteInt`.
   */
  [[maybe_unused]] gpg::WriteArchive* WriteInt32PairArchiveLanes(
    const std::int32_t* const pairValue,
    gpg::WriteArchive* const archive
  )
  {
    archive->WriteInt(pairValue[0]);
    archive->WriteInt(pairValue[1]);
    return archive;
  }

  /**
   * Address: 0x0050CD50 (FUN_0050CD50)
   *
   * What it does:
   * Writes two consecutive float lanes through `WriteArchive::WriteFloat`.
   */
  [[maybe_unused]] gpg::WriteArchive* WriteFloatPairArchiveLanes(
    const float* const pairValue,
    gpg::WriteArchive* const archive
  )
  {
    archive->WriteFloat(pairValue[0]);
    archive->WriteFloat(pairValue[1]);
    return archive;
  }

  /**
   * Address: 0x0050CD70 (FUN_0050CD70)
   *
   * What it does:
   * Writes two consecutive 16-bit signed lanes through `WriteArchive::WriteShort`.
   */
  [[maybe_unused]] gpg::WriteArchive* WriteShortPairArchiveLanesFromSignedPointer(
    const std::int16_t* const pairValue,
    gpg::WriteArchive* const archive
  )
  {
    archive->WriteShort(pairValue[0]);
    archive->WriteShort(pairValue[1]);
    return archive;
  }

  /**
   * Address: 0x0050CD90 (FUN_0050CD90)
   *
   * What it does:
   * Writes two consecutive 16-bit unsigned lanes through `WriteArchive::WriteShort`.
   */
  [[maybe_unused]] gpg::WriteArchive* WriteShortPairArchiveLanesFromUnsignedPointer(
    const unsigned short* const pairValue,
    gpg::WriteArchive* const archive
  )
  {
    archive->WriteShort(static_cast<short>(pairValue[0]));
    archive->WriteShort(static_cast<short>(pairValue[1]));
    return archive;
  }

  /**
   * Address: 0x0050D170 (FUN_0050D170)
   *
   * What it does:
   * Writes one signed 16-bit lane and returns the archive lane.
   */
  [[maybe_unused]] gpg::WriteArchive* WriteShortArchiveLaneAndReturnArchive(
    const std::int16_t value,
    gpg::WriteArchive* const archive
  )
  {
    archive->WriteShort(value);
    return archive;
  }

  /**
   * Address: 0x0050D180 (FUN_0050D180)
   *
   * What it does:
   * Writes one referenced 16-bit lane and returns the archive lane.
   */
  [[maybe_unused]] gpg::WriteArchive* WriteShortArchiveLaneFromPointerAndReturnArchive(
    const unsigned short* const value,
    gpg::WriteArchive* const archive
  )
  {
    archive->WriteShort(static_cast<short>(*value));
    return archive;
  }

  /**
   * Address: 0x0050D290 (FUN_0050D290)
   *
   * What it does:
   * Writes one byte lane through `WriteArchive::WriteUByte` and returns the
   * archive object for chained callsites.
   */
  [[maybe_unused]] gpg::WriteArchive* WriteUByteArchiveLaneAndReturnArchive(
    gpg::WriteArchive* const archive,
    const unsigned __int8 value,
    const int /*unusedStackLane*/
  )
  {
    archive->WriteUByte(value);
    return archive;
  }

  /**
   * Address: 0x0050D2B0 (FUN_0050D2B0)
   *
   * What it does:
   * Writes one referenced byte lane and returns the archive object for
   * chained callsites.
   */
  [[maybe_unused]] gpg::WriteArchive* WriteUByteArchiveLaneFromPointerAndReturnArchive(
    gpg::WriteArchive* const archive,
    const unsigned __int8* const value,
    const int /*unusedStackLane*/
  )
  {
    archive->WriteUByte(*value);
    return archive;
  }
} // namespace
namespace
{
  /**
   * Address: 0x0064B4F0 (FUN_0064B4F0)
   *
   * What it does:
   * Upcasts one reflected reference to `CThrustManipulator` and returns the
   * typed object pointer when the source is compatible.
   */
  [[nodiscard]] moho::CThrustManipulator* func_CastCThrustManipulator(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, ResolveCThrustManipulatorArchiveAdapterType());
    return static_cast<moho::CThrustManipulator*>(upcast.mObj);
  }

  /**
   * Address: 0x00652940 (FUN_00652940)
   *
   * What it does:
   * Upcasts one reflected reference to `RDebugOverlay` and returns the typed
   * object pointer when the source is compatible.
   */
  [[nodiscard]] moho::RDebugOverlay* func_CastRDebugOverlay(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, ResolveRDebugOverlayArchiveAdapterType());
    return static_cast<moho::RDebugOverlay*>(upcast.mObj);
  }

  /**
   * Address: 0x006608F0 (FUN_006608F0)
   *
   * What it does:
   * Upcasts one reflected reference to `REmitterBlueprint` and returns the
   * typed object pointer when the source is compatible.
   */
  [[nodiscard]] moho::REmitterBlueprint* func_CastREmitterBlueprint(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, ResolveREmitterBlueprintArchiveAdapterType());
    return static_cast<moho::REmitterBlueprint*>(upcast.mObj);
  }

  /**
   * Address: 0x00672B00 (FUN_00672B00)
   *
   * What it does:
   * Upcasts one reflected reference to `RTrailBlueprint` and returns the typed
   * object pointer when the source is compatible.
   */
  [[nodiscard]] moho::RTrailBlueprint* func_CastRTrailBlueprint(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, ResolveRTrailBlueprintArchiveAdapterType());
    return static_cast<moho::RTrailBlueprint*>(upcast.mObj);
  }

  /**
   * Address: 0x00675F80 (FUN_00675F80)
   *
   * What it does:
   * Upcasts one reflected reference to `CollisionBeamEntity` and returns the
   * typed object pointer when the source is compatible.
   */
  [[nodiscard]] moho::CollisionBeamEntity* func_CastCollisionBeamEntity(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, ResolveCollisionBeamEntityArchiveAdapterType());
    return static_cast<moho::CollisionBeamEntity*>(upcast.mObj);
  }

  /**
   * Address: 0x00675FC0 (FUN_00675FC0)
   *
   * What it does:
   * Upcasts one reflected reference to `ManyToOneListener_ECollisionBeamEvent`
   * and returns the typed object pointer when the source is compatible.
   */
  [[nodiscard]] moho::ManyToOneListener_ECollisionBeamEvent*
  func_CastManyToOneListener_ECollisionBeamEvent(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, ResolveManyToOneCollisionBeamEventArchiveAdapterType());
    return static_cast<moho::ManyToOneListener_ECollisionBeamEvent*>(upcast.mObj);
  }

  /**
   * Address: 0x0067F0A0 (FUN_0067F0A0)
   *
   * What it does:
   * Upcasts one reflected reference to `RProjectileBlueprint` and returns the
   * typed object pointer when the source is compatible.
   */
  [[nodiscard]] moho::RProjectileBlueprint* func_CastRProjectileBlueprint(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, ResolveRProjectileBlueprintArchiveAdapterType());
    return static_cast<moho::RProjectileBlueprint*>(upcast.mObj);
  }

  /**
   * Address: 0x006898E0 (FUN_006898E0)
   *
   * What it does:
   * Upcasts one reflected reference to `EntitySetBase` and returns the typed
   * object pointer when the source is compatible.
   */
  [[nodiscard]] moho::EntitySetBase* func_CastEntitySetBase(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, ResolveEntitySetBaseArchiveAdapterType());
    return static_cast<moho::EntitySetBase*>(upcast.mObj);
  }
} // namespace
namespace
{
} // namespace
namespace
{
  /**
   * Address: 0x0069EF60 (FUN_0069EF60)
   *
   * What it does:
   * Writes one intrusive-list-head-adjusted
   * `gpg::RRef_ManyToOneListener_EProjectileImpactEvent` lane as `unowned`
   * tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromManyToOneListener_EProjectileImpactEventIntrusiveHeadLane1_Impl(
    gpg::WriteArchive* archive,
    const moho::ManyToOneBroadcaster<moho::EProjectileImpactEvent>* broadcaster
  )
  {
    // `slot - 4` back to the listener that owns the weak-link head the
    // broadcaster points at; `GetListener()` is that decode, and it also folds
    // in the null/sentinel cases the open-coded form tested by hand.
    moho::ManyToOneListener<moho::EProjectileImpactEvent>* const listener =
      (broadcaster != nullptr) ? broadcaster->GetListener() : nullptr;

    gpg::RRef listenerRef{};
    listenerRef = gpg::MakeRRef<moho::ManyToOneListener<moho::EProjectileImpactEvent>>(listener);
    gpg::WriteRawPointer(archive, listenerRef, gpg::TrackedPointerState::Unowned, gpg::RRef{});
  }

  /**
   * Address: 0x00675170 (FUN_00675170)
   *
   * What it does:
   * Writes one intrusive-list-head-adjusted
   * `gpg::RRef_ManyToOneListener_ECollisionBeamEvent` lane as `unowned`
   * tracked-pointer state into one write archive lane.
   */
  void SaveUnownedRawPointerFromManyToOneListener_ECollisionBeamEventIntrusiveHeadLane1_Impl(
    gpg::WriteArchive* archive,
    const moho::ManyToOneBroadcaster<moho::ECollisionBeamEvent>* broadcaster
  )
  {
    // `slot - 4` back to the listener that owns the weak-link head the
    // broadcaster points at; `GetListener()` is that decode, and it also folds
    // in the null/sentinel cases the open-coded form tested by hand.
    moho::ManyToOneListener<moho::ECollisionBeamEvent>* const listener =
      (broadcaster != nullptr) ? broadcaster->GetListener() : nullptr;

    gpg::RRef listenerRef{};
    listenerRef = gpg::MakeRRef<moho::ManyToOneListener_ECollisionBeamEvent>(listener);
    gpg::WriteRawPointer(archive, listenerRef, gpg::TrackedPointerState::Unowned, gpg::RRef{});
  }
} // namespace
namespace
{
} // namespace

namespace
{
  [[nodiscard]] gpg::RType* ResolveCDamageArchiveAdapterType()
  {
    gpg::RType* type = moho::CDamage::sType;
    if (type == nullptr) {
      type = gpg::LookupRType(typeid(moho::CDamage));
      moho::CDamage::sType = type;
    }
    return type;
  }

  [[nodiscard]] gpg::RType* ResolveShieldArchiveAdapterType()
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = gpg::REF_FindTypeNamed("Moho::Shield");
      if (sType == nullptr) {
        sType = gpg::LookupRType(typeid(moho::Shield));
      }
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* ResolveListenerNavPathArchiveAdapterType()
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = gpg::REF_FindTypeNamed("Moho::Listener<Moho::NavPath const &>");
      if (sType == nullptr) {
        sType = gpg::REF_FindTypeNamed("Listener<Moho::NavPath const &>");
      }
      if (sType == nullptr) {
        sType = gpg::REF_FindTypeNamed("Moho::Listener_NavPath");
      }
      if (sType == nullptr) {
        sType = gpg::LookupRType(typeid(moho::Listener<const moho::SNavPath&>));
      }
    }
    return sType;
  }

  [[nodiscard]] gpg::RType* ResolveIPathTravelerArchiveAdapterType()
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = gpg::REF_FindTypeNamed("Moho::IPathTraveler");
      if (sType == nullptr) {
        sType = gpg::REF_FindTypeNamed("IPathTraveler");
      }
      if (sType == nullptr) {
        sType = gpg::LookupRType(typeid(moho::IPathTraveler));
      }
    }
    return sType;
  }

  /**
   * Address: 0x0073AD60 (FUN_0073AD60)
   *
   * What it does:
   * Upcasts one reflected reference to `CDamage` and returns the typed object pointer when the source is compatible.
   */
  [[nodiscard]] moho::CDamage* func_CastCDamage(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, ResolveCDamageArchiveAdapterType());
    return static_cast<moho::CDamage*>(upcast.mObj);
  }

  /**
   * Address: 0x00755AC0 (FUN_00755AC0)
   *
   * What it does:
   * Upcasts one reflected reference to `Shield` and returns the typed object pointer when the source is compatible.
   */
  [[nodiscard]] moho::Shield* func_CastShield(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, ResolveShieldArchiveAdapterType());
    return static_cast<moho::Shield*>(upcast.mObj);
  }

  /**
   * Address: 0x00764420 (FUN_00764420)
   *
   * What it does:
   * Upcasts one reflected reference to `Listener<NavPath const&>` and returns the typed object pointer when the source is
   * compatible.
   */
  [[nodiscard]] moho::Listener<const moho::SNavPath&>* func_CastListener_NavPath(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, ResolveListenerNavPathArchiveAdapterType());
    return static_cast<moho::Listener<const moho::SNavPath&>*>(upcast.mObj);
  }

  /**
   * Address: 0x0076AE30 (FUN_0076AE30)
   *
   * What it does:
   * Upcasts one reflected reference to `IPathTraveler` and returns the typed object pointer when the source is compatible.
   */
  [[nodiscard]] moho::IPathTraveler* func_CastIPathTraveler(const gpg::RRef& source)
  {
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, ResolveIPathTravelerArchiveAdapterType());
    return static_cast<moho::IPathTraveler*>(upcast.mObj);
  }
} // namespace

namespace gpg
{
  /**
   * Address: 0x0069EF60 (FUN_0069EF60,
   *   `gpg::SaveUnownedRawPointerFromManyToOneListener_EProjectileImpactEventIntrusiveHeadLane1`)
   *
   * File-scope trampoline that exposes the global mangled symbol the
   * cross-TU caller expects. The real body lives in an anonymous
   * namespace earlier in this TU (around line 6488) so it has
   * internal linkage; the call site at
   * `ProjectileStartupRegistrations.cpp:511` looks up the symbol as
   * `gpg::Save...` (forward-decl-in-`namespace gpg` ABI) and
   * previously fell back to the no-op stub in
   * `EngineUnrecoveredStubs.cpp`.
   *
   * Caller body audit
   * (`ProjectileStartupRegistrations.cpp:508`):
   * the address is stored as `&gpg::SaveUnowned...` into a
   * reflection-table save-callback slot — no rewire needed; the
   * symbol resolution now reaches the real body.
   */
  void SaveUnownedRawPointerFromManyToOneListener_EProjectileImpactEventIntrusiveHeadLane1(
    gpg::WriteArchive* archive, std::uint32_t* intrusiveListHeadSlot
  )
  {
    ::SaveUnownedRawPointerFromManyToOneListener_EProjectileImpactEventIntrusiveHeadLane1_Impl(
      archive, reinterpret_cast<const moho::ManyToOneBroadcaster<moho::EProjectileImpactEvent>*>(intrusiveListHeadSlot)
    );
  }

  /**
   * Address: 0x00675170 (FUN_00675170,
   *   `gpg::SaveUnownedRawPointerFromManyToOneListener_ECollisionBeamEventIntrusiveHeadLane1`)
   *
   * File-scope trampoline that exposes the global mangled symbol the
   * cross-TU caller expects. The real body lives in an anonymous
   * namespace earlier in this TU (around line 7684, now suffixed
   * `_Impl`) so it has internal linkage; the call site is
   * `CollisionBeamStartupRegistrations.cpp`'s
   * `RManyToOneBroadcasterCollisionBeamEventTypeInfo::Init`, which stores
   * `&gpg::SaveUnownedRawPointerFromManyToOneListener_ECollisionBeamEventIntrusiveHeadLane1`
   * into the `serSaveFunc_` reflection-table save-callback slot -- the
   * exact sibling pattern already established for
   * `SaveUnownedRawPointerFromManyToOneListener_EProjectileImpactEventIntrusiveHeadLane1`
   * immediately above.
   */
  void SaveUnownedRawPointerFromManyToOneListener_ECollisionBeamEventIntrusiveHeadLane1(
    gpg::WriteArchive* archive, std::uint32_t* intrusiveListHeadSlot
  )
  {
    ::SaveUnownedRawPointerFromManyToOneListener_ECollisionBeamEventIntrusiveHeadLane1_Impl(
      archive, reinterpret_cast<const moho::ManyToOneBroadcaster<moho::ECollisionBeamEvent>*>(intrusiveListHeadSlot)
    );
  }
} // namespace gpg

/**
 * Address: 0x00923D20 (FUN_00923D20, func_serialize_fromstring)
 *
 * IDA signature:
 * int __cdecl func_serialize_fromstring(lua_State *L);
 *
 * What it does:
 * Implements the Lua-visible `serialize.fromstring(str)` entry point:
 * wraps the input string in a `std::stringstream`, builds a
 * `gpg::TextReadArchive` over it via `gpg::CreateTextReadArchive`, then
 * repeatedly deserializes one reflected `TObject` value per call and
 * pushes it onto the Lua stack until a void/terminator value is read,
 * returning the count of values pushed. Referenced as a `lua_CFunction`
 * from a registration table anchored at `??_7UdataSerializer@@6B@`+0x1C
 * (0x00D47074) -- this is a plain Lua C-function callback, not a
 * polymorphic virtual call (its calling convention has no implicit
 * `this`).
 */
int LuaSerializeFromString(lua_State* const L)
{
  std::size_t length = 0;
  const char* const data = luaL_checklstring(L, 1, &length);

  const boost::shared_ptr<std::istream> stream(
    new std::stringstream(std::string(data, length), std::ios_base::in | std::ios_base::out)
  );

  gpg::ReadArchive* const archive = gpg::CreateTextReadArchive(stream);

  lua_settop(L, 0);

  static gpg::RType* sObjectType = nullptr;
  if (sObjectType == nullptr) {
    sObjectType = gpg::LookupRType(typeid(LuaPlus::TObject));
  }

  for (;;) {
    const int top = lua_gettop(L);
    lua_settop(L, top + 1);
    LuaPlus::TObject* const slot = L->top - 1;

    gpg::RRef ownerRef{};
    ownerRef = gpg::MakeRRef<lua_State>(L);

    archive->Read(sObjectType, slot, ownerRef);
    if (slot->tt == 0) {
      break;
    }
  }

  --L->top;
  const int pushedCount = lua_gettop(L);

  if (archive != nullptr) {
    delete archive;
  }

  return pushedCount;
}

/**
 * Address: 0x00923AC0 (FUN_00923AC0, func_serialize_tostring)
 *
 * IDA signature:
 * int __cdecl func_serialize_tostring(lua_State *L);
 *
 * What it does:
 * Implements the Lua-visible `serialize.tostring(...)` entry point, the exact
 * inverse of `serialize.fromstring` above: drops the GC threshold, opens a
 * `gpg::TextWriteArchive` over a fresh `std::stringstream`, serializes every
 * argument currently on the stack as a reflected `TObject`, appends the
 * null-typed terminator value that `fromstring`'s read loop stops on, and
 * pushes the accumulated text back to Lua as a single string. Returns 1.
 *
 * Referenced as a `lua_CFunction` from the `serializelib` registration table
 * at 0x00D47068 (slot 0x00D4706C, keyed "tostring"), which
 * `luaopen_serialize` (0x00923690) hands to `luaL_openlib` - a plain C
 * callback, not a virtual, so there is no implicit `this`.
 */
int LuaSerializeToString(lua_State* const L)
{
  lua_setgcthreshold(L, 0);

  const int argumentCount = lua_gettop(L);

  // 0x00923AD8: operator new(0x88) then basic_stringstream(mode 3). The
  // shared_ptr binds the ostream sub-object at +8 (0x00923B0C) while the
  // control block owns the whole stringstream, so `buffer` stays valid for
  // the str() read below.
  std::stringstream* const buffer = new std::stringstream(std::ios_base::in | std::ios_base::out);
  const boost::shared_ptr<std::ostream> stream(buffer);

  gpg::WriteArchive* const archive = gpg::CreateTextWriteArchive(stream);

  static gpg::RType* sObjectType = nullptr;
  if (sObjectType == nullptr) {
    sObjectType = gpg::LookupRType(typeid(LuaPlus::TObject));
  }

  // 0x00923B4A-0x00923BA8: walks the argument frame from base upward and stops
  // early on the first slot whose type tag is zero.
  for (int index = 1; index <= argumentCount; ++index) {
    LuaPlus::TObject* const slot = &L->base[index - 1];
    if (slot->tt == 0) {
      break;
    }

    gpg::RRef ownerRef{};
    ownerRef = gpg::MakeRRef<lua_State>(L);

    archive->Write(sObjectType, slot, ownerRef);
  }

  // 0x00923BC0-0x00923BF6: one trailing write of a null object through a null
  // owner ref. This is the terminator LuaSerializeFromString's loop reads.
  const void* terminator = nullptr;
  const gpg::RRef nullOwnerRef{};
  archive->Write(sObjectType, &terminator, nullOwnerRef);

  // 0x00923BFB: std::stringstream::str(), which forwards to the embedded
  // stringbuf at +0x0C (FUN_008D4A80 -> FUN_0047B610).
  const std::string text = buffer->str();
  lua_pushlstring(L, text.data(), text.size());

  if (archive != nullptr) {
    delete archive;
  }

  return 1;
}

namespace moho
{
  /**
   * Address: 0x0076D760 (FUN_0076D760)
   *
   * What it does:
   * Reads the cell through its reflected type, then the weight.
   */
  void SerLoadMembers(gpg::ReadArchive* const archive, SPathNeighbor& neighbor)
  {
    archive->Read(gpg::RTypeOf<HPathCell>(), &neighbor.first, gpg::RRef{});
    archive->ReadFloat(&neighbor.second);
  }

  /**
   * Address: 0x0076D7B0 (FUN_0076D7B0)
   *
   * What it does:
   * Writes the cell through its reflected type, then the weight.
   */
  void SerSaveMembers(gpg::WriteArchive* const archive, const SPathNeighbor& neighbor)
  {
    archive->Write(gpg::RTypeOf<HPathCell>(), &neighbor.first, gpg::RRef{});
    archive->WriteFloat(neighbor.second);
  }
} // namespace moho
