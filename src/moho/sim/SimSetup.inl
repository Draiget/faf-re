// Part of Sim.cpp, included there: Sim setup, creation and post-initialization.

/**
 * Address: 0x00744060 (FUN_00744060, ?Setup@Sim@Moho@@AAEXPAVLaunchInfoNew@2@@Z)
 * Mangled: ?Setup@Sim@Moho@@AAEXPAVLaunchInfoNew@2@@Z
 *
 * IDA signature:
 * void __stdcall Moho::Sim::Setup(Moho::Sim *this, Moho::LaunchInfoNew *info);
 *
 * What it does:
 * New-game initialization pass, populating the subsystems the constructor left
 * null and running the Lua `SetupSession`/`BeginSession` callbacks around
 * `CreateArmies`/`PostInitialize`. See the class declaration for the ordered
 * list of subsystems constructed here.
 */
void Sim::Setup(LaunchInfoNew* const info)
{
  mCheatsEnabled = info->mCheatsEnabled;
  SIM_ResetFlattenLog(); // engine addition (replay keyframes)

  // Disk-watcher task, staged on the disk-watcher task stage.
  (void)CTask::CreateTaskThread(new ScrDiskWatcherTask(mLuaState), &mDiskWatcherTaskStage, true);

  // Decal buffer.
  {
    auto* const newDecalBuffer = new CDecalBuffer(this);
    CDecalBuffer* const previousDecalBuffer = mDecalBuffer;
    mDecalBuffer = newDecalBuffer;
    if (previousDecalBuffer) {
      delete previousDecalBuffer;
    }
  }

  // Per-run RNG stream seeded from the launch info.
  {
    auto* const newRng = new CRandomStream(static_cast<std::uint32_t>(info->mInitSeed));
    CRandomStream* const previousRng = mRngState;
    mRngState = newRng;
    if (previousRng) {
      delete previousRng;
    }
  }

  // Physics constants (gravity = (0, -4.9, 0)).
  {
    auto* const newPhys = new SPhysConstants();
    SPhysConstants* const previousPhys = mPhysConstants;
    mPhysConstants = newPhys;
    delete previousPhys;
  }

  // Build the ScenarioInfo.ArmySetup Lua table from the army name/setup strings.
  // The scenario table is deserialized from the launch info's ScenarioInfo blob,
  // and each army's setup table from its entry in the army-setup string vector.
  LuaPlus::LuaObject scenarioInfo{};
  (void)SCR_FromString(&scenarioInfo, info->mScenarioInfo, mLuaState);

  fa::vector<LuaPlus::LuaObject> armySetupObjects{};
  LuaPlus::LuaObject armySetupTable{};
  armySetupTable.AssignNewTable(mLuaState, 0, 0);

  const std::size_t armyCount = info->mStrVec.size();
  for (std::size_t armyIndex = 0; armyIndex < armyCount; ++armyIndex) {
    LuaPlus::LuaObject armySetup{};
    (void)SCR_FromString(&armySetup, info->mStrVec.begin()[armyIndex], mLuaState);
    armySetup.SetInteger("ArmyIndex", static_cast<std::int32_t>(armyIndex + 1));
    armySetupObjects.push_back(armySetup);

    // Engine addition: the host chose this table. An ArmyName that is not a
    // string made GetString raise a Lua error out of sim construction; such an
    // army is named by its slot the way FAF names armies.
    const LuaPlus::LuaObject armyNameObject = armySetup["ArmyName"];
    const fa::string armyName = armyNameObject.IsString()
      ? fa::string(armyNameObject.GetString())
      : gpg::STR_Printf("ARMY_%d", static_cast<int>(armyIndex + 1));
    armySetupTable.SetObject(armyName.c_str(), armySetup);
  }
  scenarioInfo.SetObject("ArmySetup", armySetupTable);
  mLuaState->GetGlobals().SetObject("ScenarioInfo", scenarioInfo);

  // Engine addition (.plans/water-levels/PLAN.md): the map's water bodies, before any script asks
  // for a water level. Sea only unless the session has EFafSimFix::WaterBodies on.
  mMapData->InstallWaterBodies(scenarioInfo);

  // SetupSession() Lua callback. Only the call is guarded (runtime_error,
  // FuncInfo 0x00F29640 try state 12, handler 0x00744414).
  {
    const LuaPlus::LuaFunction<> setupSession(mLuaState->GetGlobal("SetupSession"));
    try {
      setupSession.Call();
    } catch (const fa::runtime_error& error) {
      gpg::Warnf("Error running SetupSession in SimInit.lua: %s", error.what());
    }
  }

  // Refresh heightfield bounds to the full grid.
  {
    CHeightField* const heightField = mMapData->mHeightField.get();
    const gpg::Rect2i fullBounds{0, 0, 0x7FFFFFFF, 0x7FFFFFFF};
    heightField->UpdateBounds(fullBounds);
  }

  // Formation database.
  {
    auto* const newFormationDB = new CAiFormationDBImpl();
    newFormationDB->mSim = this;
    CAiFormationDBImpl* const previousFormationDB = mFormationDB;
    mFormationDB = newFormationDB;
    if (previousFormationDB) {
      delete previousFormationDB;
    }
  }

  // Sim resources (shared-pointer lane). The binary assigns a freshly-owned
  // control block (use_count = 1); build one via the deleter ctor and transfer
  // ownership into the member (which starts null).
  {
    auto* const newResources = new CSimResources();
    boost::SharedPtrRaw<CSimResources> owningResources(
      newResources, [](CSimResources* const p) noexcept { delete p; });
    mSimResources.px = owningResources.px;
    mSimResources.pi = owningResources.pi;
    owningResources.px = nullptr;
    owningResources.pi = nullptr;
  }

  // Resolve ScenarioInfo.Options for the army/post-init callbacks.
  LuaPlus::LuaObject scenarioInfoOptions = mLuaState->GetGlobals().Lookup("ScenarioInfo.Options");

  // Entity database.
  {
    auto* const newEntityDB = new EntityDB();
    EntityDB* const previousEntityDB = mEntityDB;
    mEntityDB = newEntityDB;
    if (previousEntityDB) {
      delete previousEntityDB;
    }
  }

  // Command database.
  {
    auto* const newCommandDB = new CCommandDB(this);
    CCommandDB* const previousCommandDB = mCommandDB;
    mCommandDB = newCommandDB;
    if (previousCommandDB) {
      delete previousCommandDB;
    }
  }

  // Effect manager (interface-owned).
  {
    auto* const newEffectManager = new CEffectManagerImpl(this);
    CEffectManagerImpl* const previousEffectManager = mEffectManager;
    mEffectManager = newEffectManager;
    if (previousEffectManager) {
      delete previousEffectManager;
    }
  }

  // Create the armies from the scenario launch info.
  CreateArmies(info->mArmyLaunchInfo, armySetupObjects, scenarioInfoOptions);

  // Optional sound manager: only when a non-empty engine list is configured and
  // sound is not disabled.
  // Engine addition (plan WPL.4): the configuration is the client's, tested through
  // sSoundEnabled (CSimSoundManager.h).
  if (sSoundEnabled != nullptr && sSoundEnabled()) {
    auto* const newSoundManager = new CSimSoundManager(this);
    CSimSoundManager* const previousSoundManager = mSoundManager;
    mSoundManager = newSoundManager;
    if (previousSoundManager) {
      delete previousSoundManager;
    }
  }

  // Spawn scenario props unless /noprops was requested. Each record's blueprint
  // id is resolved through the rules and instantiated at its stored transform.
  if (!CFG_GetArgOption("/noprops", 0u, nullptr)) {
    CWldProps* const props = info->mProps;
    int propCount = 0;
    if (props != nullptr && !props->mEntries.empty()) {
      propCount = static_cast<int>(props->mEntries.size());
      for (const CWldPropEntry* entry = props->mEntries.begin(); entry != props->mEntries.end(); ++entry) {
        (void)PROP_Create(this, entry->mTransform, entry->mBlueprintPath.c_str());
      }
    }
    gpg::Warnf(" NUM PROPS = %d", propCount);
  }

  // Engine addition (dedicated-server plan WPL.18): the Lua pairs() order, for headless
  // --lua-pairs. Off by default.
  if (sim_LuaPairsDumpPath != nullptr) {
    DumpLuaPairsOrder(mLuaState->m_state, sim_LuaPairsDumpPath);
  }

  // BeginSession() Lua callback: lookup and call are both guarded
  // (std::exception, FuncInfo 0x00F29640 try states 22..26, handler 0x007448AA).
  try {
    const LuaPlus::LuaFunction<> beginSession(mLuaState->GetGlobal("BeginSession"));
    beginSession.Call();
  } catch (const std::exception& error) {
    gpg::Warnf("BeginSession() failed: %s", error.what());
  }

  // Final post-initialization pass (prebuilt units, etc.).
  PostInitialize(scenarioInfoOptions);
}

/**
 * Address: 0x007433B0 (FUN_007433B0,
 * ?Create@Sim@Moho@@SAPAV12@ABV?$shared_ptr@ULaunchInfoBase@Moho@@@boost@@@Z)
 * Mangled: ?Create@Sim@Moho@@SAPAV12@ABV?$shared_ptr@ULaunchInfoBase@Moho@@@boost@@@Z
 *
 * IDA signature:
 * Moho::Sim *__thiscall Moho::Sim::Create(boost::shared_ptr<LaunchInfoBase> *launchInfo);
 *
 * What it does:
 * Factory entry point and coupling hub for the Sim construction chain. Allocates
 * one Sim (operator new of 0xAF8 bytes), constructs it from the launch info,
 * publishes it as the `sInstance` singleton, and dispatches to `Setup` (new
 * game) or `Load` (saved game). Throws `std::runtime_error` when the launch info
 * is neither a `LaunchInfoNew` nor a `LaunchInfoLoad`.
 */
Sim* Sim::Create(const boost::SharedPtrRaw<LaunchInfoBase>& launchInfo)
{
  LaunchInfoBase* const info = launchInfo.px;

  // Allocate + placement-construct the Sim (0xAF8-byte layout). The EH unwind of
  // this `new` expression is what references ~Sim in the binary.
  Sim* const sim = new Sim(info);
  Sim::sInstance = sim;

  if (LaunchInfoNew* const newInfo = info->GetNew(); newInfo != nullptr) {
    sim->Setup(newInfo);
    return sim;
  }

  if (LaunchInfoLoad* const loadInfo = info->GetLoad(); loadInfo != nullptr) {
    sim->Load(loadInfo);
    return sim;
  }

  const fa::string message =
    gpg::STR_Printf("Unknown subclass of LaunchInfoBase: %s", typeid(*info).name());
  throw std::runtime_error(message.c_str());
}

/**
 * Address: 0x007458E0 (FUN_007458E0, ??1Sim@Moho@@UAE@XZ)
 * Mangled: ??1Sim@Moho@@UAE@XZ
 *
 * IDA signature:
 * void __stdcall Moho::Sim::~Sim(Moho::Sim *this);
 *
 * What it does:
 * Reverse-construction teardown. Stops the task stages, deletes every owned
 * subsystem (formation/effect/decal/sound/entity/command DBs, occupation grid,
 * path tables, RNG, sim vars, physics constants, map, Lua state), rotates and
 * deletes retained synclog files, cancels the rules Lua export, and drains the
 * per-beat pending-ref slot lane. All container / shared_ptr / task-stage
 * members are destroyed automatically after this body runs; the singleton
 * pointer is cleared.
 */
Sim::~Sim()
{
  // Engine addition (issue #216): a dump still owed is taken while the state it describes exists.
  CDesyncRecorder::Detach(*this);

  // Stop the three task stages (disk-watcher + two sim task stages).
  mDiskWatcherTaskStage.Teardown();
  mTaskStageA.Teardown();
  mTaskStageB.Teardown();

  // Formation DB (interface-owned; virtual delete).
  if (mFormationDB) {
    delete mFormationDB;
    mFormationDB = nullptr;
  }

  // Occupation grid.
  if (mOGrid) {
    delete mOGrid;
    mOGrid = nullptr;
  }

  // Command DB.
  if (mCommandDB) {
    delete mCommandDB;
    mCommandDB = nullptr;
  }

  // Armies (each entry owned).
  for (std::size_t i = 0; i < mArmiesList.size(); ++i) {
    if (mArmiesList[i]) {
      delete mArmiesList[i];
      mArmiesList[i] = nullptr;
    }
  }

  // Entity DB.
  if (mEntityDB) {
    delete mEntityDB;
    mEntityDB = nullptr;
    EntityMemoryManager::Instance().Clear();
  }

  // Random stream (raw storage; no destructor in the binary).
  if (mRngState) {
    delete mRngState;
    mRngState = nullptr;
  }

  // Path tables.
  if (mPathTables) {
    delete mPathTables;
    mPathTables = nullptr;
  }

  // Sim convar instances (interface-owned).
  for (CSimConVarInstanceBase*& simVar : mSimVars) {
    if (simVar) {
      delete simVar;
      simVar = nullptr;
    }
  }

  // Effect manager (interface-owned).
  if (mEffectManager) {
    delete mEffectManager;
    mEffectManager = nullptr;
  }

  // Decal buffer.
  if (mDecalBuffer) {
    delete mDecalBuffer;
    mDecalBuffer = nullptr;
  }

  // Sound manager (interface-owned).
  if (mSoundManager) {
    delete mSoundManager;
    mSoundManager = nullptr;
  }

  // Close and rotate the synclog: retain the current line for desync-free runs,
  // then delete each retained log file recorded in mDesyncLogLines.
  if (mLog) {
    std::fclose(mLog);
    mLog = nullptr;
    if (mIsDesyncFree) {
      mDesyncLogLines.push_back(mDesyncLogLine);
    }
  }
  while (!mDesyncLogLines.empty()) {
    const fa::string logFile = mDesyncLogLines.front();
    (void)mDesyncLogLines.erase(mDesyncLogLines.begin());
    if (!::DeleteFileA(logFile.c_str())) {
      gpg::Warnf("Error deleting sim log file: %s", logFile.c_str());
    }
  }

  // Cancel the rules Lua export, then destroy the Lua state.
  mRules->CancelExport(mLuaState);
  if (mLuaState) {
    delete mLuaState;
    mLuaState = nullptr;
  }

  // Clear the global "current sim" singleton (before member teardown, matching
  // the binary ordering).
  Sim::sInstance = nullptr;

  // `mDeletionQueue`'s destructor (0x0074DF10, +0xA48), at its place in the
  // member teardown order this body spells out.
  mDeletionQueue.clear_and_release();

  // Physics constants (raw storage).
  if (mPhysConstants) {
    delete mPhysConstants;
    mPhysConstants = nullptr;
  }

  // Map data.
  if (mMapData) {
    delete mMapData;
    mMapData = nullptr;
  }

  // Remaining container / shared_ptr / task-stage / sync-filter members are
  // destroyed by their own destructors after this body returns, matching the
  // binary's compiler-generated member teardown pass.
}

/**
 * Address: 0x00746310 (FUN_00746310,
 * ?CreateArmies@Sim@Moho@@QAEXABV?$vector@UArmyLaunchInfo@Moho@@V?$allocator@UArmyLaunchInfo@Moho@@@std@@@std@@ABV?$vector@VLuaObject@LuaPlus@@V?$allocator@VLuaObject@LuaPlus@@@std@@@4@ABVLuaObject@LuaPlus@@@Z)
 *
 * IDA signature:
 * void __stdcall Moho::Sim::CreateArmies(Sim *this,
 *                                        std::vector<ArmyLaunchInfo> const *launchInfo,
 *                                        std::vector<LuaObject> const *armySetupObjects,
 *                                        LuaObject const *scenarioInfoOptions);
 *
 * What it does:
 * Resizes `mArmiesList` to the number of scenario army-launch entries, allocates
 * one `CArmyImpl` per slot via `AllocateScenarioArmy`, then fires the Lua
 * `OnCreateArmyBrain(armyIndex+1, brain, armyName, playerName)` callback per
 * army with a `try/Warnf` guard. The focus-army flag passed into the allocator
 * is true when the iteration index equals `mSyncFilter.focusArmy`.
 */
void Sim::CreateArmies(
  const fa::vector<ArmyLaunchInfo>& launchInfo,
  const fa::vector<LuaPlus::LuaObject>& armySetupObjects,
  const LuaPlus::LuaObject& scenarioInfoOptions
)
{
  const std::size_t armyCount = launchInfo.size();
  mArmiesList.resize(armyCount);

  for (std::size_t armyIndex = 0; armyIndex < armyCount; ++armyIndex) {
    const bool isFocusArmy =
      (static_cast<std::int32_t>(armyIndex) == mSyncFilter.focusArmy);

    CArmyImpl* const army = AllocateScenarioArmy(
      this,
      static_cast<std::int32_t>(armyIndex),
      launchInfo[armyIndex],
      armySetupObjects[armyIndex],
      scenarioInfoOptions,
      isFocusArmy
    );
    mArmiesList[armyIndex] = army;

    try {
      const LuaPlus::LuaObject globals = mLuaState->GetGlobals();
      const LuaPlus::LuaFunction<> onCreateArmyBrain(globals["OnCreateArmyBrain"]);
      CAiBrain* const brain = army->GetArmyBrain();
      onCreateArmyBrain.Call_IntBrainStr2(
        static_cast<unsigned int>(armyIndex + 1),
        brain != nullptr ? &brain->mLuaObj : nullptr,
        army->mConstDat.mArmyName.c_str(),
        army->mConstDat.mPlayerName.c_str()
      );
    } catch (const std::exception& ex) {
      gpg::Warnf("Error running OnCreateArmyBrain: %s", ex.what());
    }
  }
}

/**
 * Address: 0x007464D0 (FUN_007464D0, ?PostInitialize@Sim@Moho@@QAEXABVLuaObject@LuaPlus@@@Z)
 *
 * What it does:
 * Checks launch option `PrebuiltUnits`; when enabled (`"On"`), calls the
 * global Lua function `InitializePrebuiltUnits` once for each non-civilian
 * army using the army name string.
 */
void Sim::PostInitialize(const LuaPlus::LuaObject& launchOptions)
{
  const LuaPlus::LuaObject prebuiltUnitsOption = launchOptions["PrebuiltUnits"];
  if (prebuiltUnitsOption.IsNil()) {
    return;
  }

  const std::string prebuiltUnitsMode(prebuiltUnitsOption.GetString());
  if (prebuiltUnitsMode != "On") {
    return;
  }

  for (CArmyImpl* const army : mArmiesList) {
    if (army->mConstDat.mIsCivilian != 0u) {
      continue;
    }

    const LuaPlus::LuaObject globals = mLuaState->GetGlobals();
    const LuaPlus::LuaFunction<> initializePrebuiltUnits(globals["InitializePrebuiltUnits"]);
    try {
      initializePrebuiltUnits(army->mConstDat.mArmyName.c_str());
    } catch (const std::exception& ex) {
      gpg::Warnf("Error running InitializePrebuiltUnits: %s", ex.what());
    }
  }
}

/**
 * Address: 0x00545A40 (FUN_00545A40, ?GetResources@Sim@Moho@@QBEPBVISimResources@2@XZ)
 *
 * What it does:
 * Returns the currently bound simulation resources interface lane.
 */
const ISimResources* Sim::GetResources() const
{
  return mSimResources.px;
}

/**
 * Address: 0x00746720 (FUN_00746720, ?GetDebugCanvas@Sim@Moho@@QAEPAVCDebugCanvas@2@XZ)
 */
CDebugCanvas* Sim::GetDebugCanvas()
{
  if (!mDebugCanvas1) {
    mDebugCanvas1.reset(new CDebugCanvas());
  }
  return mDebugCanvas1.get();
}

/**
 * Address: 0x007467F0 (FUN_007467F0, ?RegisterEntitySet@Sim@Moho@@QAEXPAVEntitySetBase@2@@Z)
 *
 * What it does:
 * Unlinks one entity-set node from its current ring and inserts it into the
 * sim EntityDB registered-set list.
 */
void Sim::RegisterEntitySet(EntitySetBase* const set)
{
  if (!set || !mEntityDB) {
    return;
  }

  mEntityDB->RegisterEntitySet(*set);
}

/**
 * Address: 0x007538C0 (FUN_007538C0, boost::shared_ptr_SParticleBuffer::shared_ptr_SParticleBuffer)
 *
 * What it does:
 * Constructs one `shared_ptr<SParticleBuffer>` from one raw particle-buffer
 * pointer lane.
 */
boost::shared_ptr<SParticleBuffer>* ConstructSharedParticleBufferFromRaw(
  boost::shared_ptr<SParticleBuffer>* const outBuffer,
  SParticleBuffer* const buffer
)
{
  return ::new (outBuffer) boost::shared_ptr<SParticleBuffer>(buffer);
}

/**
 * Address: 0x00751220 (FUN_00751220, boost::shared_ptr_SParticleBuffer::operator=)
 *
 * What it does:
 * Rebinds one `shared_ptr<SParticleBuffer>` from a raw pointer and releases
 * prior ownership.
 */
boost::shared_ptr<SParticleBuffer>* AssignSharedParticleBufferFromRaw(
  boost::shared_ptr<SParticleBuffer>* const outBuffer,
  SParticleBuffer* const buffer
)
{
  outBuffer->reset(buffer);
  return outBuffer;
}

/**
 * Address: 0x00743180 (FUN_00743180)
 *
 * What it does:
 * Copies one `shared_ptr<CHeightField>` lane and retains the control block.
 */
boost::shared_ptr<CHeightField>* CopySharedHeightFieldPtr(
  boost::shared_ptr<CHeightField>* const destination,
  const boost::shared_ptr<CHeightField>* const source
)
{
  if (destination == nullptr || source == nullptr) {
    return destination;
  }

  *destination = *source;
  return destination;
}
