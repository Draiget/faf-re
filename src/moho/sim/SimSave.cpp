#include "moho/sim/SimPrivate.h"

#include <string_view>

#include "moho/lua/SCR_String.h"
#include "moho/sim/FafGameVersion.h"

namespace
{

  gpg::RType* LookupRTypeWithTinyThreadCache(const std::type_info& dynamicTypeInfo)
  {
    struct CachedTypeInfoEntry
    {
      const std::type_info* typeInfo;
      gpg::RType* type;
    };

    thread_local std::array<CachedTypeInfoEntry, 3> cache{};

    for (std::size_t i = 0; i < cache.size(); ++i) {
      const CachedTypeInfoEntry& entry = cache[i];
      if (entry.typeInfo == nullptr || entry.type == nullptr) {
        continue;
      }

      if (entry.typeInfo == &dynamicTypeInfo || *entry.typeInfo == dynamicTypeInfo) {
        if (i != 0u) {
          const CachedTypeInfoEntry hit = entry;
          for (std::size_t j = i; j > 0u; --j) {
            cache[j] = cache[j - 1u];
          }
          cache[0] = hit;
        }
        return cache[0].type;
      }
    }

    gpg::RType* const resolved = gpg::LookupRType(dynamicTypeInfo);
    for (std::size_t i = cache.size() - 1u; i > 0u; --i) {
      cache[i] = cache[i - 1u];
    }
    cache[0] = CachedTypeInfoEntry{&dynamicTypeInfo, resolved};
    return resolved;
  }

  /**
   * Address: 0x00585690 (FUN_00585690, func_RRefSim)
   *
   * IDA signature:
   * gpg::RRef *__cdecl func_RRefSim(gpg::RRef *outRef, Moho::Sim *sim);
   *
   * What it does:
   * Builds owner `RRef` for Sim serializer paths. Exact `Sim` pointers keep
   * static type; derived runtime types are resolved and back-adjusted to the
   * complete object start.
   */
  gpg::RRef MakeSimOwnerRef(Sim* sim)
  {
    gpg::RType* const simType = gpg::RTypeOf<Sim>();

    gpg::RRef out{};
    out.mObj = sim;
    out.mType = simType;
    if (!sim) {
      return out;
    }

    const std::type_info& dynamicTypeInfo = typeid(*sim);
    if (dynamicTypeInfo == typeid(Sim)) {
      return out;
    }

    gpg::RType* const dynamicType = LookupRTypeWithTinyThreadCache(dynamicTypeInfo);

    std::int32_t baseOffset = 0;
    const bool isDerived = dynamicType && simType && dynamicType->IsDerivedFrom(simType, &baseOffset);
    GPG_ASSERT(isDerived);
    if (!isDerived) {
      out.mType = dynamicType ? dynamicType : simType;
      return out;
    }

    out.mObj = static_cast<void*>(reinterpret_cast<char*>(sim) - baseOffset);
    out.mType = dynamicType;
    return out;
  }


  void WriteArchiveUIntCompat(gpg::WriteArchive* archive, const std::uint32_t value)
  {
    if (!archive) {
      return;
    }

    if constexpr (requires(gpg::WriteArchive* a) { a->WriteUInt(0u); }) {
      archive->WriteUInt(static_cast<unsigned int>(value));
    } else {
      archive->WriteULong(static_cast<unsigned long>(value));
    }
  }

  [[nodiscard]] gpg::RType* ResolveRect2iRType()
  {
    gpg::RType* rectType = gpg::Rect2i::sType;
    if (rectType == nullptr) {
      rectType = gpg::LookupRType(typeid(gpg::Rect2<int>));
      gpg::Rect2i::sType = rectType;
    }
    return rectType;
  }
}


/**
 * Address: 0x00745020 (FUN_00745020, ?SerMapData@Sim@Moho@@AAEXAAVWriteArchive@gpg@@H@Z)
 *
 * What it does:
 * Serializes map playable-rect state by writing:
 * - one `Rect2i` copied from `mMapData->mPlayableRect`;
 * - the size of `mLoadedMapRects` (+0x0A08);
 * - each loaded `Rect2i` element.
 */
void Sim::SerMapData(gpg::WriteArchive* const archive)
{
  if (!archive) {
    return;
  }

  const gpg::Rect2i playableRect = mMapData->mPlayableRect;
  gpg::RRef nullOwnerRef{};
  archive->Write(ResolveRect2iRType(), &playableRect, nullOwnerRef);

  WriteArchiveUIntCompat(archive, static_cast<std::uint32_t>(mLoadedMapRects.size()));
  for (gpg::Rect2i& loadedRect : mLoadedMapRects) {
    gpg::RRef elementOwnerRef{};
    archive->Write(ResolveRect2iRType(), &loadedRect, elementOwnerRef);
  }
}

/**
 * Address: 0x00745120 (FUN_00745120, ?SerMapData@Sim@Moho@@AAEXAAVReadArchive@gpg@@H@Z)
 *
 * What it does:
 * Reads the playable rectangle and applies it to `mMapData`, reads the loaded
 * map-rect list into `mLoadedMapRects`, then makes `mCachedMapRects` a copy of
 * it (`resize` 0x0074D930 + `std::copy` 0x00753860).
 *
 * The cached list is resized even when the archive held no rectangles
 * (0x00745258..0x00745261 run unconditionally), so a load always leaves it the
 * same length as the loaded list. The overlay version skipped both steps for
 * an empty list and kept whatever the cache held before the load.
 */
void Sim::SerMapData(gpg::ReadArchive* const archive)
{
  if (!archive) {
    return;
  }

  gpg::Rect2i playableRect{};
  gpg::RRef ownerRef{};
  archive->Read(ResolveRect2iRType(), &playableRect, ownerRef);
  (void)mMapData->SetPlayableMapRect(playableRect);

  std::uint32_t rectCount = 0;
  archive->ReadUInt(&rectCount);

  mLoadedMapRects.resize(rectCount, gpg::Rect2i{});
  for (gpg::Rect2i& loadedRect : mLoadedMapRects) {
    gpg::RRef elementOwnerRef{};
    archive->Read(ResolveRect2iRType(), &loadedRect, elementOwnerRef);
  }

  mCachedMapRects.resize(mLoadedMapRects.size(), gpg::Rect2i{});
  (void)std::copy(mLoadedMapRects.begin(), mLoadedMapRects.end(), mCachedMapRects.begin());
}

/**
 * Address: 0x007452B0 (FUN_007452B0, ?SerArmies@Sim@Moho@@AAEXAAVWriteArchive@gpg@@H@Z)
 *
 * What it does:
 * Serializes owned army pointers from `mArmiesList` as count + owned
 * `SimArmy` raw-pointer entries.
 */
void Sim::SerArmies(gpg::WriteArchive* const archive)
{
  if (!archive) {
    return;
  }

  const std::uint32_t armyCount = static_cast<std::uint32_t>(mArmiesList.size());
  WriteArchiveUIntCompat(archive, armyCount);

  gpg::RRef ownerRef{};
  for (CArmyImpl* const army : mArmiesList) {
    archive->WritePointer<moho::SimArmy>(army, gpg::TrackedPointerState::Owned, ownerRef);
  }
}

/**
 * Address: 0x00745330 (FUN_00745330, ?SerArmies@Sim@Moho@@AAEXAAVReadArchive@gpg@@H@Z)
 *
 * What it does:
 * Reads owned army pointers from archive into `mArmiesList` using
 * archive-count resize + per-entry owned pointer load.
 */
void Sim::SerArmies(gpg::ReadArchive* const archive)
{
  if (!archive) {
    return;
  }

  unsigned int armyCount = 0u;
  archive->ReadUInt(&armyCount);

  mArmiesList.resize(static_cast<std::size_t>(armyCount));

  gpg::RRef nullOwner{};
  for (std::size_t i = 0; i < static_cast<std::size_t>(armyCount); ++i) {
    SimArmy* loadedArmy = nullptr;
    archive->ReadPointerOwned(&loadedArmy, &nullOwner);
    mArmiesList[i] = static_cast<CArmyImpl*>(loadedArmy);
  }
}

/**
 * Address: 0x007456D0 (FUN_007456D0, ?SerDirtyEnts@Sim@Moho@@AAEXAAVWriteArchive@gpg@@H@Z)
 *
 * What it does:
 * Writes one unowned entity-pointer chain from `mCoordEntities` and
 * terminates the stream with a null entity sentinel.
 */
void Sim::SerDirtyEnts(gpg::WriteArchive* const archive)
{
  if (!archive) {
    return;
  }

  const gpg::RRef nullOwner{};
  for (Entity* const entity : mCoordEntities.owners()) {
    archive->WritePointer<moho::Entity>(entity, gpg::TrackedPointerState::Unowned, nullOwner);
  }

  archive->WritePointer<moho::Entity>(nullptr, gpg::TrackedPointerState::Unowned, nullOwner);
}

/**
 * Address: 0x00745760 (FUN_00745760, ?SerDirtyEnts@Sim@Moho@@AAEXAAVReadArchive@gpg@@H@Z)
 *
 * What it does:
 * Reads one unowned entity-pointer stream and relinks each loaded entity's
 * coord-node into `mCoordEntities` until a null sentinel is encountered.
 */
void Sim::SerDirtyEnts(gpg::ReadArchive* const archive)
{
  if (!archive) {
    return;
  }

  gpg::RRef ownerRef{};
  Entity* entity = nullptr;
  (void)archive->ReadPointer(&entity, &ownerRef);
  while (entity != nullptr) {
    entity->ListLinkBefore(&mCoordEntities);
    ownerRef = gpg::RRef{};
    (void)archive->ReadPointer(&entity, &ownerRef);
  }
}
namespace
{
  /**
   * Address: 0x00744E50 (FUN_00744E50, sub_744E50)
   *
   * IDA signature:
   * void __usercall sub_744E50(gpg::ReadArchive* archive@<esi>, LuaPlus::LuaObject table);
   *
   * What it does:
   * Reads (key, value) LuaObject pairs from `archive` and assigns each into
   * `table` until a nil-key sentinel is read. Used to restore the sim's Lua
   * globals table at the end of the load-serialization pass. `table` is taken by
   * value (an owned copy destroyed on return), matching the binary.
   */
  void ReadLuaTableEntriesFromArchive(gpg::ReadArchive* const archive, LuaPlus::LuaObject table)
  {
    gpg::RType* luaObjectType = LuaPlus::LuaObject::sType;
    if (!luaObjectType) {
      luaObjectType = gpg::LookupRType(typeid(LuaPlus::LuaObject));
      LuaPlus::LuaObject::sType = luaObjectType;
    }

    while (true) {
      LuaPlus::LuaObject key;
      gpg::RRef keyRef{};
      archive->Read(luaObjectType, &key, keyRef);
      if (key.IsNil()) {
        break;
      }

      LuaPlus::LuaObject value;
      gpg::RRef valueRef{};
      archive->Read(luaObjectType, &value, valueRef);
      table.SetObject(key, value);
    }
  }

  /**
   * Address: 0x007551C0 (the save half, nine `PreCreatedPtr` calls at
   * 0x0075520A..0x00755391) and 0x00754C60 (the load half, nine
   * `TrackPointer` calls at 0x00754C95..0x00754E1C)
   *
   * What it does:
   * Names the nine objects that already exist on both ends of a sim archive
   * before any payload moves: the sim itself, its Lua state, the game rules
   * and the footprint blueprint they own, the map, the path tables, and the
   * three task stages.
   *
   * Registering them up front is what lets everything nested below refer to
   * them by index instead of by value. It is not an optimisation: none of
   * those types carries a construct or new-ref callback, so a nested write
   * that met one of them for the first time would have nothing to build it
   * with and would raise `SerializationError`. A blueprint's save-construct
   * arguments are exactly that case -- they lead with the owning
   * `RRuleGameRules*` -- which is why the serializer opens here.
   *
   * Both halves register the same nine in the same order, which is also what
   * keeps the two tracked-pointer tables index-aligned.
   */
  void CollectSimArchiveRoots(moho::Sim* const sim, gpg::RRef (&outRoots)[9])
  {
    outRoots[0] = MakeSimOwnerRef(sim);
    outRoots[1] = gpg::MakeRRef<LuaPlus::LuaState>(sim->mLuaState);
    outRoots[2] = gpg::MakeRRef<moho::RRuleGameRules>(sim->mRules);
    outRoots[3] = gpg::MakeRRef<moho::SRuleFootprintsBlueprint>(const_cast<moho::SRuleFootprintsBlueprint*>(sim->mRules->GetFootprints()));
    (void)gpg::RRef_STIMap(&outRoots[4], sim->mMapData);
    outRoots[5] = gpg::MakeRRef<moho::PathTables>(sim->mPathTables);
    outRoots[6] = gpg::MakeRRef<moho::CTaskStage>(&sim->mTaskStageA);
    outRoots[7] = gpg::MakeRRef<moho::CTaskStage>(&sim->mDiskWatcherTaskStage);
    outRoots[8] = gpg::MakeRRef<moho::CTaskStage>(&sim->mTaskStageB);
  }
}


/**
  * Alias of FUN_00754C60 (non-canonical helper lane).
 *
 * What it does:
 * Core Sim load-serialization routine used by Sim serializer callback.
 */
void Sim::SerializeLoadBody(gpg::ReadArchive* archive)
{
  if (!archive) {
    return;
  }

  const gpg::RRef ownerRef{};
  gpg::RRef roots[9]{};
  CollectSimArchiveRoots(this, roots);
  for (const gpg::RRef& root : roots) {
    (void)archive->TrackPointer(root);
  }

  (void)SCR_LuaDoString("ResetSyncTable()", mLuaState);
  SerMapData(archive);
  archive->ReadUInt(&mCurTick);

  CRandomStream* random = nullptr;
  archive->ReadPointerOwned(&random, &ownerRef);
  delete std::exchange(mRngState, random);
  SPhysConstants* physics = nullptr;
  archive->ReadPointerOwned(&physics, &ownerRef);
  delete std::exchange(mPhysConstants, physics);

  // The grid is constructed with this Sim; its serializer registers that
  // existing instance rather than constructing a replacement pointer.
  archive->Read(gpg::RTypeOf<COGrid>(), mOGrid, ownerRef);
  IAiFormationDB* formation = nullptr;
  archive->ReadPointerOwned(&formation, &ownerRef);
  delete std::exchange(mFormationDB, static_cast<CAiFormationDBImpl*>(formation));

  {
    boost::shared_ptr<ISimResources> resources;
    archive->ReadPointerShared(&resources, &ownerRef);
    mSimResources.reset_from_owner(boost::static_pointer_cast<CSimResources>(resources));
  }
  SerArmies(archive);

  CCommandDB* commands = nullptr;
  archive->ReadPointerOwned(&commands, &ownerRef);
  delete std::exchange(mCommandDB, commands);
  archive->ReadUInt(&mReserved98C);

  CDecalBuffer* decals = nullptr;
  archive->ReadPointerOwned(&decals, &ownerRef);
  delete std::exchange(mDecalBuffer, decals);
  IEffectManager* effects = nullptr;
  archive->ReadPointerOwned(&effects, &ownerRef);
  delete std::exchange(mEffectManager, static_cast<CEffectManagerImpl*>(effects));
  ISoundManager* sound = nullptr;
  archive->ReadPointerOwned(&sound, &ownerRef);
  delete std::exchange(mSoundManager, static_cast<CSimSoundManager*>(sound));

  archive->Read(gpg::RTypeOf<CTaskStage>(), &mTaskStageA, ownerRef);
  archive->Read(gpg::RTypeOf<CTaskStage>(), &mDiskWatcherTaskStage, ownerRef);
  archive->Read(gpg::RTypeOf<CTaskStage>(), &mTaskStageB, ownerRef);
  SerVars(archive);
  archive->Read(gpg::RTypeOf<decltype(mShields)>(), &mShields, ownerRef);
  SerDirtyEnts(archive);
  archive->ReadBool(&mCheatsEnabled);
  archive->ReadBool(&mGameOver);

  EntityDB* entities = nullptr;
  archive->ReadPointerOwned(&entities, &ownerRef);
  delete std::exchange(mEntityDB, entities);

  LuaPlus::LuaObject globals = mLuaState->GetGlobals();
  ReadLuaTableEntriesFromArchive(archive, globals);

  // Engine addition (replay keyframes): after the entities, whose load dirties these caches.
  if (gSimExactArchive.load(std::memory_order_relaxed)) {
    // Not reachable from the globals, and without it a table with holes reports a shorter length,
    // so `table.insert` writes over a live entry.
    ReadLuaTableEntriesFromArchive(archive, mLuaState->GetTableSizes());
    mPathTables->LoadExact(archive);
    mOGrid->mEntityOccupationManager.LoadBucketOrder(archive, *mEntityDB);
    // The entities' load rebuilt these bits differently from play: a prop's footprint is not
    // occupied again, and a release clears cells a neighbour also covers until something re-marks them.
    for (gpg::BitArray2D* const bits : {&mOGrid->terrainOccupation, &mOGrid->waterOccupation, &mOGrid->mOccupation}) {
      archive->ReadBytes(reinterpret_cast<char*>(bits->ptr), static_cast<std::size_t>(bits->size) * sizeof(std::int32_t));
    }
  }
}

/**
 * Address: 0x00745390 (FUN_00745390, ?SerVars@Sim@Moho@@AAEXAAVWriteArchive@gpg@@H@Z)
 *
 * What it does:
 * Writes active sim-console variables as `(name, lexical value)` string pairs
 * and terminates the lane with an empty string name sentinel.
 */
void Sim::SerVars(gpg::WriteArchive* archive)
{
  if (!archive) {
    return;
  }

  const std::size_t simVarCount = mSimVars.size();
  for (std::size_t i = 0; i < simVarCount; ++i) {
    CSimConVarInstanceBase* const simVar = mSimVars[i];
    if (!simVar) {
      continue;
    }

    fa::string varName(simVar->mName ? simVar->mName : "");
    archive->WriteString(&varName);

    gpg::RRef valueRef{};
    simVar->GetValueRef(&valueRef);
    fa::string lexical = valueRef.GetLexical();
    archive->WriteString(&lexical);
  }

  fa::string endOfVars;
  archive->WriteString(&endOfVars);
}

/**
 * Address: 0x00745500 (FUN_00745500, ?SerVars@Sim@Moho@@AAEXAAVReadArchive@gpg@@H@Z)
 * Mangled: ?SerVars@Sim@Moho@@AAEXAAVReadArchive@gpg@@H@Z
 *
 * IDA signature:
 * void __stdcall Moho::Sim::SerVars(Moho::Sim *this, gpg::ReadArchive &archive, int);
 *
 * What it does:
 * Load counterpart of SerVars(WriteArchive*): restores console-variable
 * overrides. Reads a var name; while non-empty, reads its lexical value,
 * looks the name up in the `simcons` sim-command registry, and (when found)
 * resolves/creates the per-Sim CSimConVarInstanceBase indexed by
 * CSimConVarBase::mIndex, growing `mSimVars` to the global convar-index
 * counter, then applies the value through the instance's reflection RRef via
 * SetLexical. Unknown names are logged.
 */
void Sim::SerVars(gpg::ReadArchive* const archive)
{
  if (!archive) {
    return;
  }

  fa::string varName;
  archive->ReadString(&varName);
  while (!varName.empty()) {
    fa::string varValue;
    archive->ReadString(&varValue);

    // `simcons` map value is a CSimConVarBase (only convar entries are saved by
    // SerVars(WriteArchive*)); the binary's virtual Identity() adjustment is a
    // no-op for this single-inheritance chain, so a static_cast is 1:1.
    CSimConVarBase* const conVar = static_cast<CSimConVarBase*>(FindRegisteredSimConCommand(varName.c_str()));
    if (!conVar) {
      Logf("Reference to unknown console variable: %s", varName.c_str());
    } else {
      const std::size_t index = static_cast<std::size_t>(conVar->mIndex);
      if (mSimVars.size() <= index) {
        // Binary reserves to the global convar count in one shot (not index+1).
        mSimVars.resize(static_cast<std::size_t>(GetSimConVarIndexCounter()), nullptr);
      }

      CSimConVarInstanceBase* instance = mSimVars[index];
      if (!instance) {
        instance = conVar->CreateInstance();
        mSimVars[index] = instance;
      }

      gpg::RRef valueRef{};
      instance->GetValueRef(&valueRef);
      valueRef.SetLexical(varValue.c_str());
    }

    archive->ReadString(&varName);
  }
}

/**
 * Address: 0x007551C0 (FUN_007551C0, ?Dump@CMauiControl@Moho@@UAEXXZ_0)
 *
 * What it does:
 * Core Sim save-serialization routine used by Sim serializer callback.
 */
void Sim::SerializeSaveBody(gpg::WriteArchive* archive)
{
  if (!archive) {
    return;
  }

  const gpg::RRef ownerRef{};
  gpg::RRef roots[9]{};
  CollectSimArchiveRoots(this, roots);
  for (const gpg::RRef& root : roots) {
    (void)archive->PreCreatedPtr(root);
  }

  (void)SCR_LuaDoString("ResetSyncTable()", mLuaState);
  SerMapData(archive);
  archive->WriteUInt(mCurTick);
  archive->WritePointer(mRngState, gpg::TrackedPointerState::Owned, ownerRef);
  archive->WritePointer(mPhysConstants, gpg::TrackedPointerState::Owned, ownerRef);
  archive->Write(gpg::RTypeOf<COGrid>(), mOGrid, ownerRef);
  archive->WritePointer(static_cast<IAiFormationDB*>(mFormationDB), gpg::TrackedPointerState::Owned, ownerRef);
  archive->WritePointer(static_cast<ISimResources*>(mSimResources.px), gpg::TrackedPointerState::Shared, ownerRef);
  SerArmies(archive);
  archive->WritePointer(mCommandDB, gpg::TrackedPointerState::Owned, ownerRef);
  archive->WriteUInt(mReserved98C);
  archive->WritePointer(mDecalBuffer, gpg::TrackedPointerState::Owned, ownerRef);
  archive->WritePointer(static_cast<IEffectManager*>(mEffectManager), gpg::TrackedPointerState::Owned, ownerRef);
  archive->WritePointer(static_cast<ISoundManager*>(mSoundManager), gpg::TrackedPointerState::Owned, ownerRef);

  archive->Write(gpg::RTypeOf<CTaskStage>(), &mTaskStageA, ownerRef);
  archive->Write(gpg::RTypeOf<CTaskStage>(), &mDiskWatcherTaskStage, ownerRef);
  archive->Write(gpg::RTypeOf<CTaskStage>(), &mTaskStageB, ownerRef);
  SerVars(archive);
  archive->Write(gpg::RTypeOf<decltype(mShields)>(), &mShields, ownerRef);
  SerDirtyEnts(archive);
  archive->WriteBool(mCheatsEnabled);
  archive->WriteBool(mGameOver);
  archive->WritePointer(mEntityDB, gpg::TrackedPointerState::Owned, ownerRef);

  LuaPlus::LuaObject globals = mLuaState->GetGlobals();
  (void)func_ArchiveWriteLuaObj(archive, &globals);

  // Engine addition (replay keyframes): see SerializeLoadBody.
  if (gSimExactArchive.load(std::memory_order_relaxed)) {
    LuaPlus::LuaObject tableSizes = mLuaState->GetTableSizes();
    (void)func_ArchiveWriteLuaObj(archive, &tableSizes);
    mPathTables->SaveExact(archive);
    mOGrid->mEntityOccupationManager.SaveBucketOrder(archive, *mEntityDB);
    for (gpg::BitArray2D* const bits : {&mOGrid->terrainOccupation, &mOGrid->waterOccupation, &mOGrid->mOccupation}) {
      archive->WriteBytes(reinterpret_cast<char*>(bits->ptr), static_cast<std::size_t>(bits->size) * sizeof(std::int32_t));
    }
  }
}

/**
 * Address: 0x007449A0 (FUN_007449A0, ?Load@Sim@Moho@@AAEXPAVLaunchInfoLoad@2@@Z)
 * Mangled: ?Load@Sim@Moho@@AAEXPAVLaunchInfoLoad@2@@Z
 *
 * IDA signature:
 * void __stdcall Moho::Sim::Load(Moho::Sim *this, Moho::LaunchInfoLoad *loadInfo);
 *
 * What it does:
 * Load-game initialization pass. Deserializes this Sim from the saved archive,
 * refreshes heightfield bounds, re-arms every loaded unit's intel handles and
 * re-binds each loaded prop into the entity DB bounded-prop queue, then re-syncs
 * the playable rectangle and fires the `OnPostLoad` Lua callback.
 */
void Sim::Load(LaunchInfoLoad* const loadInfo)
{
  gpg::ReadArchive* const archive = loadInfo->mReadArchive;

  // Engine addition (.plans/water-levels/PLAN.md): the water bodies, as Setup builds them for a new
  // game, from the map's own terrain before a keyframe's flattened rects or the save change it, so
  // a client loading a game fills them exactly as the others did at its start. Only a session with
  // them on, for a scenario that names them, parses it here.
  if (FAF_IsSimFixActive(EFafSimFix::WaterBodies) &&
      std::string_view(loadInfo->mScenarioInfo.c_str(), loadInfo->mScenarioInfo.size()).find("WaterBodies") !=
        std::string_view::npos) {
    LuaPlus::LuaObject scenarioInfo{};
    (void)SCR_FromString(&scenarioInfo, loadInfo->mScenarioInfo, mLuaState);
    mMapData->InstallWaterBodies(scenarioInfo);
  }

  // Engine addition (replay keyframes): the archive keeps only the rects of flattened terrain, and
  // the beat count goes on from the recorded game's. The driver's opening sync publishes the beat
  // before the keyframe's again, and SIM_FinishKeyframeRestore puts back what that sync changes.
  const SSimKeyframeHeader* const keyframe = SIM_KeyframeRestore();
  if (keyframe != nullptr) {
    CHeightField* const stamped = mMapData->mHeightField.get();
    for (const SSimFlatten& flatten : keyframe->flattens) {
      const gpg::Rect2i rect{flatten.x0, flatten.z0, flatten.x1, flatten.z1};
      stamped->SetElevationRect(rect, &flatten.elevation);
    }
    mCurBeat = keyframe->beat - 1u;
    // No collection until SIM_FinishKeyframeRestore: what the load leaves unreachable has to stay,
    // as it did in the game until its next collection.
    mLuaState->m_state->l_G->GCthreshold = 0xFFFFFFFFu;
  }

  // Deserialize this Sim instance from the saved archive. A failure is logged,
  // the archive section is closed as aborted, and the error rethrown
  // (std::exception, FuncInfo 0x00F0C2D4 try state 0, handler 0x00744C54).
  gpg::RRef ownerRef{};
  try {
    if (!Sim::sType) {
      Sim::sType = gpg::LookupRType(typeid(Sim));
    }
    archive->Read(Sim::sType, this, ownerRef);
  } catch (const std::exception& error) {
    gpg::Warnf("Error loading saved game: %s", error.what());
    loadInfo->mReadArchive->EndSection(true);
    throw;
  }
  loadInfo->mReadArchive->EndSection(false);

  // Refresh the heightfield bounds to the full grid.
  {
    CHeightField* const heightField = mMapData->mHeightField.get();
    const gpg::Rect2i fullBounds{0, 0, 0x7FFFFFFF, 0x7FFFFFFF};
    heightField->UpdateBounds(fullBounds);
  }

  // Walk every loaded entity: re-arm its intel handles (AddViz) and re-bind any
  // prop entity into the entity DB bounded-prop priority queue. 0x00744A48..0x00744A55
  // start at the first node of `mAllUnits` and end at its header, the whole map.
  for (const auto& [entityId, entity] : mEntityDB->mAllUnits) {
    (void)entityId;
    if (!entity) {
      continue;
    }

    if (CIntel* const intel = entity->mIntelManager; intel != nullptr) {
      for (const IntelHandle& handle : intel->mIntelHandles) {
        if (handle) {
          handle->AddViz();
        }
      }
    }

    if (Prop* const prop = entity->IsProp(); prop != nullptr && prop->mHandleIndex != -1) {
      prop->mHandleIndex = mEntityDB->AddBoundedProp(prop);
    }
  }

  // Engine addition (replay keyframes): the rest tells a new session about the loaded game, and
  // OnPostLoad changes the sim while doing so (lua/SimPingGroup.lua forks a thread). A keyframe
  // has to continue the game as it was. What the session's start built is garbage now; it goes
  // here, or the first real collection would take it off the keyframe's counters.
  if (keyframe != nullptr) {
    SIM_ResolveKeyframeFormationPointers();
    lua_collectkeepingweaktables(mLuaState->m_state);
    mLuaState->m_state->l_G->GCthreshold = 0xFFFFFFFFu;
    return;
  }

  // Re-sync the playable rectangle through /lua/SimSync.lua::SyncPlayableRect.
  // Only the call is guarded (runtime_error, try state 8, handler 0x00744C11).
  {
    const LuaPlus::LuaObject simSyncModule = SCR_Import(mLuaState, "/lua/SimSync.lua");
    const LuaPlus::LuaFunction<> syncPlayableRect(simSyncModule["SyncPlayableRect"]);
    try {
      const gpg::Rect2i playableRect = mMapData->mPlayableRect;
      const LuaPlus::LuaObject rectObject = SCR_ToLua<gpg::Rect2<int>>(mLuaState, playableRect);
      syncPlayableRect.Call_Object(rectObject);
    } catch (const fa::runtime_error& error) {
      gpg::Warnf("Error running SyncPlayableRect in /lua/SimSync.lua: %s", error.what());
    }
  }

  // Fire the OnPostLoad Lua callback; lookup and call are guarded
  // (std::exception, try states 10..14, handler 0x00744C36).
  try {
    const LuaPlus::LuaFunction<> onPostLoad(mLuaState->GetGlobal("OnPostLoad"));
    onPostLoad.Call();
  } catch (const std::exception& error) {
    gpg::Warnf("OnPostLoad() failed: %s", error.what());
  }
}

/**
 * Address: 0x0074AFB0 (FUN_0074AFB0, ?SaveState@Sim@Moho@@QAEXAAVWriteArchive@gpg@@@Z)
 *
 * What it does:
 * Checks NIS-state save gate through `/lua/cinematics.lua::IsOpEnded`,
 * then writes this `Sim` object to the supplied archive.
 */
void Sim::SaveState(gpg::WriteArchive* const archive)
{
  // No handler here: a script error, or a module without IsOpEnded (the
  // LuaFunction constructor raises that), reaches the caller like the throw.
  const LuaPlus::LuaObject cinematics = SCR_Import(mLuaState, "/lua/cinematics.lua");
  const LuaPlus::LuaFunction<bool> isOpEnded{cinematics["IsOpEnded"]};
  if (isOpEnded.Call_x_Bool()) {
    throw std::runtime_error("Attemped Save in NIS mode");
  }

  gpg::RRef ownerRef{};
  if (!Sim::sType) {
    Sim::sType = gpg::LookupRType(typeid(Sim));
  }

  archive->Write(Sim::sType, this, ownerRef);
  archive->EndSection(false);
}
