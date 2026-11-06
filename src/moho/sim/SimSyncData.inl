// Part of Sim.cpp, included there: sync data, blips and logging.

/**
 * Address: 0x00560940 (FUN_00560940)
 */
SSyncSizes SSyncData::GetSizes() const
{
  SSyncSizes sizes{};
  sizes.mAudioRequests = static_cast<std::int32_t>(mAudioRequests.Size());
  sizes.mArmyUpdates = static_cast<std::int32_t>(mArmyUpdates.size());
  sizes.mEntityUpdates = static_cast<std::int32_t>(mEntityUpdates.size());
  sizes.mUnitUpdates = static_cast<std::int32_t>(mUnitUpdates.size());
  sizes.mCommandPackets = static_cast<std::int32_t>(mPublishedCommandPackets.size());
  return sizes;
}

/**
 * Address: 0x00560A00 (FUN_00560A00, Moho::SSyncData::ReserveSizes)
 */
void SSyncData::ReserveSizes(const SSyncSizes& sizes)
{
  mAudioRequests.Reserve(static_cast<std::size_t>(sizes.mAudioRequests));
  mArmyUpdates.reserve(static_cast<std::size_t>(sizes.mArmyUpdates));
  mEntityUpdates.reserve(static_cast<std::size_t>(sizes.mEntityUpdates));
  mUnitUpdates.reserve(static_cast<std::size_t>(sizes.mUnitUpdates));
  mPublishedCommandPackets.reserve(static_cast<std::size_t>(sizes.mCommandPackets));
}

/**
 * Address: 0x00744F70 (FUN_00744F70, sub_744F70)
 *
 * IDA signature:
 * int __cdecl sub_744F70(int a1, int a2)
 *
 * What it does:
 * Ser-load callback thunk: forwards archive/object args to 0x00754C60.
 * Extra serializer callback args are ignored in retail.
 */
void moho::SimSerializerLoadThunk(gpg::ReadArchive* archive, std::intptr_t objectPtr, int, gpg::RRef*)
{
  if (objectPtr == 0) {
    return;
  }

  reinterpret_cast<Sim*>(objectPtr)->SerializeLoadBody(archive);
}

/**
 * Address: 0x00744F80 (FUN_00744F80, sub_744F80)
 *
 * IDA signature:
 * void __cdecl sub_744F80(Moho::CMauiControl *a1)
 *
 * What it does:
 * Ser-save callback thunk: forwards archive/object args to 0x007551C0.
 * Extra serializer callback args are ignored in retail.
 */
void moho::SimSerializerSaveThunk(gpg::WriteArchive* archive, std::intptr_t objectPtr, int, gpg::RRef*)
{
  if (objectPtr == 0) {
    return;
  }

  reinterpret_cast<Sim*>(objectPtr)->SerializeSaveBody(archive);
}

/**
 * Address: 0x00747460 (FUN_00747460, ?GetSimVar@Sim@Moho@@QAEPAVCSimConVarInstanceBase@2@PAVCSimConVarBase@2@@Z)
 *
 * Moho::CSimConVarBase *
 *
 * IDA signature:
 * Moho::CSimConVarInstanceBase *__usercall Moho::Sim::GetSimVar@<eax>(Moho::Sim *this@<edi>, Moho::CSimConVarBase
 * *var@<ebx>);
 *
 * What it does:
 * Returns the cached Sim convar instance for `var->mIndex`, creating it on first access.
 */
CSimConVarInstanceBase* Sim::GetSimVar(CSimConVarBase* var)
{
  if (!var) {
    return nullptr;
  }

  const std::size_t index = static_cast<std::size_t>(var->mIndex);
  if (mSimVars.size() <= index) {
    mSimVars.resize(index + 1u, nullptr);
  }

  CSimConVarInstanceBase* instance = mSimVars[index];
  if (instance) {
    return instance;
  }

  instance = var->CreateInstance();
  mSimVars[index] = instance;
  return instance;
}


#if FAF_SERVER_MODE
namespace moho
{
  CSyncObserver* sSyncObserver = nullptr;
  // Held by `Sync` from its walk to `OnSyncWalkDone`, so a caller that removes the observer
  // knows no call into it is still running on the sim's thread.
  std::mutex sSyncObserverLock;
  ISyncRouting* sSyncRouting = nullptr;
} // namespace moho

namespace
{
  /** A command source's Lua runs under its army's focus while the routing is on (plan WP6.2). */
  struct SSyncRoutingCommand
  {
    Sim& sim;
    ISyncRouting* routing;
    explicit SSyncRoutingCommand(Sim& owner)
      : sim(owner)
      , routing(sSyncRouting)
    {
      if (routing != nullptr) {
        routing->EnterCommand(sim);
      }
    }
    ~SSyncRoutingCommand()
    {
      if (routing != nullptr) {
        routing->LeaveCommand(sim);
      }
    }
  };
} // namespace

void Sim::SetSyncRouting(ISyncRouting* const routing) noexcept
{
  sSyncRouting = routing;
}

void Sim::SetSyncObserver(CSyncObserver* const observer) noexcept
{
  const std::lock_guard<std::mutex> guard(sSyncObserverLock);
  sSyncObserver = observer;
}

CSyncObserver* Sim::SyncObserver() noexcept
{
  const std::lock_guard<std::mutex> guard(sSyncObserverLock);
  return sSyncObserver;
}
#endif

/**
 * Address: 0x00743370 (FUN_00743370, func_FormatBeatStr)
 *
 * What it does:
 * Builds one checksum-log file path as `<prefix>beat%05d.log`.
 */
[[nodiscard]] static fa::string FormatBeatLogFilePath(const fa::string& logFilePrefix, const int beat)
{
  return gpg::STR_Printf("%sbeat%05d.log", logFilePrefix.c_str(), beat);
}

/**
 * Address: 0x0074ADB0 (FUN_0074ADB0, ?FlushLog@Sim@Moho@@AAEXXZ)
 *
 * What it does:
 * Closes the active checksum log file, trims retained stale log files,
 * and opens the current beat log file.
 */
void Sim::FlushLog()
{
  // Engine addition (issue #216): the recorder closes the same beat, the one just retired.
  if (CDesyncRecorder* const recorder = CDesyncRecorder::For(this)) {
    recorder->EndBeat(*this, static_cast<int>(mCurBeat) - 1);
  }

  if (!mLog) {
    return;
  }

  std::fclose(mLog);
  mLog = nullptr;

  if (!sim_KeepAllLogFiles && mIsDesyncFree) {
    mDesyncLogLines.push_back(mDesyncLogLine);
  }

  const int checksumPeriod = ReadSimConVarInt(this, &gSimConVar_sim_ChecksumPeriod, 0);
  const int retainedLogCount = checksumPeriod + 20;
  while (static_cast<int>(mDesyncLogLines.size()) > retainedLogCount) {
    const fa::string staleLogPath = mDesyncLogLines.front();
    mDesyncLogLines.erase(mDesyncLogLines.begin());

    if (!DeleteFileA(staleLogPath.c_str())) {
      gpg::Warnf("Error deleting sim log file: %s", staleLogPath.c_str());
    }
  }

  mDesyncLogLine = FormatBeatLogFilePath(mLogFilePrefix, static_cast<int>(mCurBeat));
  if (fopen_s(&mLog, mDesyncLogLine.c_str(), "w") != 0) {
    mLog = nullptr;
  }
  mIsDesyncFree = true;
}
namespace
{
  // EntId family nibble 3 is the recon-blip family (EntityDb.cpp's
  // kAllUnitsMidFamilyBoundaryKey / kAllUnitsShieldFamilyBoundaryKey pair).
  constexpr std::uint32_t kReconBlipFamilyBeginId = 0x30000000u;
  constexpr std::uint32_t kReconBlipFamilyEndId = 0x40000000u;
}

namespace moho
{
  /// Engine addition: switch for MD5UpdateBatch (batched checksum updates). Live; same digests.
  bool sim_ParallelCoords = true;
  // The trace is text only: the checksum is the same with it or without it.
  bool dbg_RulesTraceAlways = false;

  bool sim_ReconOverlap = true;

  bool sim_ParallelUnitSyncRefresh = true;

  bool sim_ChecksumBatching = true;
}

namespace moho
{
  TConVar<bool> gTConVar_dbg_RulesTraceAlways(
    "dbg_RulesTraceAlways",
    "Write the rules checksum's text trace to a temporary file at every session start (1), or only when a desync "
    "recorder is recording (0, the default), since no one else reads it.",
    &dbg_RulesTraceAlways
  );

  TConVar<bool> gTConVar_sim_ParallelCoords(
    "sim_ParallelCoords",
    "Advance entity coordinates (transforms, history, collision bounds) on sim workers; relinks and intel stay serial (needs sim_Workers > 0).",
    &sim_ParallelCoords
  );
  TConVar<bool> gTConVar_sim_ReconOverlap(
    "sim_ReconOverlap",
    "With sim_ParallelRecon, refresh the recon blips of the armies before the beat's ReconTick army on sim workers while that ReconTick runs; any engine call from its Lua waits for them first (same recon).",
    &sim_ReconOverlap
  );
  TConVar<bool> gTConVar_sim_ParallelUnitSyncRefresh(
    "sim_ParallelUnitSyncRefresh",
    "Refresh each synced unit's own sync block (weapon info, silo counts, target ids, poses) on sim workers before the sync walk (needs sim_Workers > 0; same packet).",
    &sim_ParallelUnitSyncRefresh
  );
  TConVar<bool> gTConVar_sim_ChecksumBatching(
    "sim_ChecksumBatching",
    "Feed each entity's checksum bytes to MD5 in one run instead of field by field (same digests).",
    &sim_ChecksumBatching
  );

  TConVar<bool> gTConVar_sim_MD5Unrolled(
    "sim_MD5Unrolled",
    "Run MD5 blocks unrolled instead of as the table-driven loop (same digests).",
    &gpg::md5_UnrolledBlocks
  );

  TConVar<bool> gTConVar_mem_SmallBlockIndexTable(
    "mem_SmallBlockIndexTable",
    "x86 allocator: find a block's size class by table instead of a binary search (same class).",
    &gpg::mem_SmallBlockIndexTable
  );
}



/**
 * Address: 0x005C3710 (FUN_005C3710, sub_5C3710)
 *
 * What it does:
 * Refreshes command/visibility blips for the active sim frame.
 */
void Sim::RefreshBlips()
{
  // 0x005C3710 walks `mEntityDB->mAllUnits` from lower_bound(0x30000000) to
  // lower_bound(0x40000000) -- the recon-blip id family -- through
  // `CUnitIterAllArmies::Next`, refreshing each blip from its source unit.
  auto& entities = mEntityDB->mAllUnits;
  const auto blipsEnd = entities.lower_bound(kReconBlipFamilyEndId);
  for (auto it = entities.lower_bound(kReconBlipFamilyBeginId); it != blipsEnd; ++it) {
    static_cast<ReconBlip*>(it->second)->Refresh();
  }
}

void moho::SIM_DescribeStateForDesync(const Sim& sim, std::string& out)
{
  const auto line = [&out](const char* const format, auto... args) {
    char buffer[512];
    const int written = std::snprintf(buffer, sizeof(buffer), format, args...);
    if (written > 0) {
      out.append(buffer, std::min(static_cast<std::size_t>(written), sizeof(buffer) - 1u));
    }
  };

  line("beat %u tick %u\n", sim.mCurBeat, sim.mCurTick);
  line("sim_ChecksumPeriod=%d\n", SIM_GetChecksumPeriod(sim));

  out += "Armies\n";
  for (CArmyImpl* const army : sim.mArmiesList) {
    if (army == nullptr) {
      continue;
    }
    const SEconTotals& economy = army->GetEconomy()->economy;
    line(
      "  %d \"%s\" [%s]\n", army->mConstDat.mArmyIndex, army->mConstDat.mPlayerName.raw_data_unsafe(),
      army->mConstDat.mArmyName.raw_data_unsafe()
    );
    line("    mStored=%.9g,%.9g\n", economy.mStored.ENERGY, economy.mStored.MASS);
    line("    mIncome=%.9g,%.9g\n", economy.mIncome.ENERGY, economy.mIncome.MASS);
    line("    mReclaimed=%.9g,%.9g\n", economy.mReclaimed.ENERGY, economy.mReclaimed.MASS);
    line("    mLastUseRequested=%.9g,%.9g\n", economy.mLastUseRequested.ENERGY, economy.mLastUseRequested.MASS);
    line("    mLastUseActual=%.9g,%.9g\n", economy.mLastUseActual.ENERGY, economy.mLastUseActual.MASS);
  }

  // `mAllUnits` holds every live entity, ordered by id, so two players' lists line up.
  out += "Entities\n";
  for (auto it = sim.mEntityDB->mAllUnits.begin(); it != sim.mEntityDB->mAllUnits.end(); ++it) {
    Entity* const entity = it->second;
    if (entity == nullptr) {
      continue;
    }
    const float health = entity->mVarDat.mHealth;
    const float* const pos = reinterpret_cast<const float*>(&entity->mVarDat.mCurTransform.pos_);
    const float* const rot = reinterpret_cast<const float*>(&entity->mVarDat.mCurTransform.orient_);
    Wm3::Vec3f velocity{};
    ReadEntityVelocity(entity, &velocity);
    const char* const blueprintId = ResolveBlueprintIdCString(entity);
    line(
      "0x%08x bp=%s army=%d layer=%d health=%.9g [0x%08x]\n", static_cast<std::uint32_t>(entity->id_),
      blueprintId != nullptr ? blueprintId : "", entity->ArmyRef != nullptr ? entity->ArmyRef->mConstDat.mArmyIndex : -1,
      static_cast<int>(entity->mVarDat.mLayerMask), health, FloatBits(health)
    );
    line(
      "  pos=<%.9g,%.9g,%.9g> [0x%08x 0x%08x 0x%08x]\n", pos[0], pos[1], pos[2], FloatBits(pos[0]), FloatBits(pos[1]),
      FloatBits(pos[2])
    );
    line(
      "  rot=<%.9g,%.9g,%.9g,%.9g> [0x%08x 0x%08x 0x%08x 0x%08x]\n", rot[0], rot[1], rot[2], rot[3], FloatBits(rot[0]),
      FloatBits(rot[1]), FloatBits(rot[2]), FloatBits(rot[3])
    );
    line(
      "  vel=<%.9g,%.9g,%.9g> [0x%08x 0x%08x 0x%08x]\n", velocity.x, velocity.y, velocity.z, FloatBits(velocity.x),
      FloatBits(velocity.y), FloatBits(velocity.z)
    );
    if (Unit* const unit = entity->IsUnit(); unit != nullptr && unit->CommandQueue != nullptr) {
      if (const CUnitCommand* const command = unit->CommandQueue->GetCurrentCommand(); command != nullptr) {
        line("  command=0x%08x type=%d\n", static_cast<std::uint32_t>(command->mConstDat.cmd), static_cast<int>(command->mVarDat.mCmdType));
      }
    }
  }
}

int moho::SIM_GetChecksumPeriod(const Sim& sim)
{
  return ReadSimConVarInt(const_cast<Sim*>(&sim), &gSimConVar_sim_ChecksumPeriod, 1);
}

void moho::SIM_ApplyDesyncTestNudge(Sim& sim)
{
  // Once per sim: the first checksum beat at or after the requested one, on the lowest-id unit the
  // checksum covers that beat (the dirty entities), so the next hash differs.
  static const Sim* sNudged = nullptr;
  if (sim_DesyncTestNudgeBeat < 0 || static_cast<int>(sim.mCurBeat) < sim_DesyncTestNudgeBeat || sNudged == &sim) {
    return;
  }
  Unit* target = nullptr;
  for (Entity* const entity : sim.mCoordEntities.owners()) {
    Unit* const unit = entity->IsUnit();
    if (unit != nullptr && unit->mVarDat.mHealth > 0.0f && (target == nullptr || unit->id_ < target->id_)) {
      target = unit;
    }
  }
  if (target == nullptr) {
    return;
  }
  sNudged = &sim;
  const float before = target->mVarDat.mHealth;
  target->mVarDat.mHealth = std::nextafter(before, std::numeric_limits<float>::infinity());
  gpg::Warnf(
    "sim_DesyncTestNudgeBeat: unit 0x%08x health %.9g -> %.9g at beat %u (this client only)",
    static_cast<std::uint32_t>(target->id_), before, static_cast<double>(target->mVarDat.mHealth), sim.mCurBeat
  );
}
namespace
{
  /**
   * Generic (end_ - first_) / sizeof(T) size helper used by the
   * three non-inlined `size()` thunks the binary emits for the
   * `SDebugWorldText`, `SDebugScreenText`, and `SDebugDecal` debug
   * vector specializations. The first-pointer null-guard mirrors
   * the binary's early-out for uninitialized vectors.
   */
  template <class TDebugRecord>
  [[nodiscard]] std::size_t DebugVectorSizeThunk(const fa::vector<TDebugRecord>* const vec) noexcept
  {
    const TDebugRecord* const first = vec ? vec->data() : nullptr;
    if (first == nullptr) {
      return 0u;
    }
    return vec->size();
  }
}



/**
 * Address: 0x00452110 (FUN_00452110, sub_452110)
 *
 * IDA signature:
 * int __thiscall sub_452110(int *this);
 *
 * What it does:
 * Out-of-line `fa::vector<SDebugWorldText>::size()` specialization
 * thunk used by `CDebugCanvas::worldText`. Returns zero when the
 * vector's `first_` pointer is still null, matching the binary's
 * early-out; otherwise returns `(last_ - first_) / sizeof(SDebugWorldText)`
 * (element size `0x30`).
 */
std::size_t GetDebugWorldTextCount(const fa::vector<SDebugWorldText>* const worldText) noexcept
{
  return DebugVectorSizeThunk<SDebugWorldText>(worldText);
}

/**
 * Address: 0x00452160 (FUN_00452160, sub_452160)
 *
 * IDA signature:
 * int __thiscall sub_452160(int *this);
 *
 * What it does:
 * Out-of-line `fa::vector<SDebugScreenText>::size()` specialization
 * thunk (element size `0x48`). Same shape as
 * `GetDebugWorldTextCount`.
 */
std::size_t GetDebugScreenTextCount(const fa::vector<SDebugScreenText>* const screenText) noexcept
{
  return DebugVectorSizeThunk<SDebugScreenText>(screenText);
}

/**
 * Address: 0x004521B0 (FUN_004521B0, sub_4521B0)
 *
 * IDA signature:
 * int __thiscall sub_4521B0(int *this);
 *
 * What it does:
 * Out-of-line `fa::vector<SDebugDecal>::size()` specialization
 * thunk (element size `0x34`). Same shape as
 * `GetDebugWorldTextCount`.
 */
std::size_t GetDebugDecalCount(const fa::vector<SDebugDecal>* const decals) noexcept
{
  return DebugVectorSizeThunk<SDebugDecal>(decals);
}

/**
 * Address: 0x0044F880 (FUN_0044F880, Moho::QuatCrossAdd)
 *
 * What it does:
 * Builds a quaternion that rotates normalized `v1` toward normalized `v2`.
 *
 * The half-vector construction: normalize v1 and v2, normalize their sum,
 * and read the rotation off dot(add, v1) plus v1 x add. The scalar lands in
 * memory lane 0 and the cross terms in lanes 1..3, which is `Wm3::Quaternionf`
 * `.w` then `.x/.y/.z` -- the same scalar-first layout `QuatToMatrix`
 * (0x00452FD0) consumes, where lane 0 is the term that appears in no
 * diagonal.
 *
 * An earlier pass read `FUN_0044F880.c`'s `dest->x = <dot>` literally and put
 * the scalar in `.x`. IDA's own struct for this type names offset 0 `x`, so
 * that line is lane 0, not `Wm3`'s `.x` (which is `m_afTuple[1]`). Every
 * caller feeds the result straight into `MultQuadVec` -- `AddWireCircle`
 * below, `CD3DPrimBatcher::DRAW_Circle` -- so the shift rotated every
 * debug/prim circle out of its own plane.
 *
 * Self-check: v1 == v2 gives add == v1, dot == 1 and a zero cross, i.e. the
 * identity {1,0,0,0}. Under the shifted form it gave {0,1,0,0}, a
 * half-turn about X for two identical vectors.
 *
 * Degenerate half-vector (v1 and v2 opposed): `fcompi` + `jbe` at 0x0044F8E1
 * takes the fallback when `!(Normalize(add) > 0)`, so NaN takes it too. The
 * fallback (0x0044F970..0x0044F9A3) is a half turn about a CALLER-SUPPLIED
 * axis, passed in `edi`: `NormalizeVectorInto(&v1copy, *edi)`, then
 * `{w = 0, x/y/z = that normalised axis}`. It is not a half turn about v1.
 * Callers and their asm-proven fallback axes: `QuatFromVecRot` (0x0069AAF3,
 * (0,1,0)); `CDebugCanvas::AddWireCircle` (0x00450050),
 * `CDebugCanvas::AddWireSphere` (0x00450139), `DRAW_WireCircle`
 * (0x00453EF0) and `DRAW_Circle` (0x00456220), all (1,0,0).
 */
Wm3::Quaternionf* moho::QuatCrossAdd(
  Wm3::Quaternionf* const dest, Wm3::Vector3f v1, Wm3::Vector3f v2, const Wm3::Vector3f& fallbackAxis
)
{
  Wm3::Vector3f::Normalize(&v1);
  Wm3::Vector3f::Normalize(&v2);

  Wm3::Vector3f add{
    v2.x + v1.x,
    v1.y + v2.y,
    v1.z + v2.z,
  };

  if (!(Wm3::Vector3f::Normalize(&add) > 0.0f)) {
    // Opposed inputs: a half turn about the caller's fallback axis - scalar 0,
    // the normalised axis in the imaginary lanes.
    (void)NormalizeVectorInto(&v1, fallbackAxis);
    dest->x = v1.x;
    dest->y = v1.y;
    dest->z = v1.z;
    dest->w = 0.0f;
    return dest;
  }

  // 0x0044F920..0x0044F952 sums the dot as (z + y) + x.
  dest->w = ((add.z * v1.z) + (v1.y * add.y)) + (add.x * v1.x);
  dest->x = (add.z * v1.y) - (v1.z * add.y);
  dest->y = (v1.z * add.x) - (add.z * v1.x);
  dest->z = (add.y * v1.x) - (v1.y * add.x);
  return dest;
}

/**
 * Address: 0x00746280 (FUN_00746280, ?Logf@Sim@Moho@@QAAXPBDZZ)
 *
 * What it does:
 * Writes one formatted line into the active sim log stream when logging is enabled.
 */
void Sim::Logf(const char* fmt, ...)
{
  va_list args;
  va_start(args, fmt);

  // Engine addition (issue #216): the desync recorder keeps the same text in memory. It formats
  // from a copy of `args`, so the file below still gets them unread.
  if (CDesyncRecorder* const recorder = CDesyncRecorder::For(this)) {
    recorder->Append(fmt, args);
  }

  if (mLog) {
    (void)vfprintf(mLog, fmt, args);
  }

  va_end(args);
}

/**
 * Address: 0x007462A0 (FUN_007462A0, ?Printf@Sim@Moho@@QAAXPBDZZ)
 *
 * What it does:
 * Formats one line and appends it into `mPrintField`.
 */
void Sim::Printf(const char* fmt, ...)
{
  va_list args;
  va_start(args, fmt);

  const char* format = fmt;
#if FAF_SERVER_MODE
  if (sSyncRouting != nullptr && sSyncRouting->FocusForLua() >= 0) {
    (void)sSyncRouting->Print(gpg::STR_Va(format, args));
    va_end(args);
    return;
  }
#endif
  mPrintField.push_back(gpg::STR_Va(format, args));

  va_end(args);
}

namespace
{
  bool sim_PrepareLuaStateEarly = true;
  moho::TConVar<bool> gTConVar_sim_PrepareLuaStateEarly(
    "sim_PrepareLuaStateEarly",
    "Build the sim's Lua state (bindings and the rules' blueprints) on a helper thread while the session loads, for "
    "the sim to take (1, the default), or build it when the sim is created (0). Read when a session load reaches it.",
    &sim_PrepareLuaStateEarly
  );

  /**
   * Engine addition: the part of `Sim::Sim` that builds its Lua state from the rules alone - a
   * fresh state, the core and sim init sets, then the rules' blueprints - either on the sim
   * thread or ahead of it (SIM_PrepareLuaState). The binding of the sim itself to the state
   * follows in the constructor.
   */
  LuaPlus::LuaState* BuildSimLuaState(RRuleGameRules* const rules)
  {
    auto* const state = new LuaPlus::LuaState(LuaPlus::LuaState::LIB_BASE);
    lua::NameLuaVm(state->m_state, "Sim"); // diagnostics label only

    if (CScrLuaInitFormSet* const coreSet = SCR_FindLuaInitFormSet("Core"); coreSet != nullptr) {
      coreSet->RunInits(state);
    }
    if (CScrLuaInitFormSet* const simSet = SCR_FindLuaInitFormSet("Sim"); simSet != nullptr) {
      simSet->RunInits(state);
    }

    gpg::LogScopeEntry luaBpScope(fa::string("MEM: %i bytes LUABP"));
    rules->ExportToLuaState(state);
    luaBpScope.Emit();
    return state;
  }

  /// Engine addition: the state SIM_PrepareLuaState is building, and the rules it is for.
  struct PreparedSimLuaState
  {
    std::mutex lock;
    const RRuleGameRules* rules = nullptr;
    std::thread builder;
    LuaPlus::LuaState* state = nullptr; // written by `builder`, read after joining it
  };

  // Never destroyed: a thread still joinable at exit would terminate the process.
  PreparedSimLuaState& Prepared()
  {
    static auto* const prepared = new PreparedSimLuaState();
    return *prepared;
  }

  // With `prepared.lock` held: waits for the builder and hands over what it built, or null.
  LuaPlus::LuaState* TakePreparedLocked(PreparedSimLuaState& prepared)
  {
    if (prepared.builder.joinable()) {
      prepared.builder.join();
    }
    prepared.rules = nullptr;
    return std::exchange(prepared.state, nullptr);
  }

  // With `prepared.lock` held: drops what the builder made, export binding first.
  void DiscardPreparedLocked(PreparedSimLuaState& prepared)
  {
    RRuleGameRules* const rules = const_cast<RRuleGameRules*>(prepared.rules);
    if (LuaPlus::LuaState* const state = TakePreparedLocked(prepared); state != nullptr) {
      rules->CancelExport(state);
      delete state;
    }
  }

  // The state prepared for `rules`, once its builder is done, or null.
  LuaPlus::LuaState* TakePreparedLuaState(const RRuleGameRules* const rules)
  {
    PreparedSimLuaState& prepared = Prepared();
    const std::lock_guard<std::mutex> guard(prepared.lock);
    return (rules != nullptr && prepared.rules == rules) ? TakePreparedLocked(prepared) : nullptr;
  }
} // namespace

void moho::SIM_PrepareLuaState(RRuleGameRules* const rules)
{
  if (rules == nullptr || !sim_PrepareLuaStateEarly) {
    return;
  }
#if defined(_M_X64) || defined(__x86_64__)
  // A table array the sim thread sizes into the binary's 896-byte class passes a block of the
  // sim's free list (SimBlockLane::PassTopBlock), and a helper thread never does. The list is
  // empty until a sim frees a formation or projectile; one a previous game in this process left
  // has the state built on the sim thread, as before.
  if (!SimBlockLane::FreeBlocks().empty()) {
    return;
  }
#endif

  PreparedSimLuaState& prepared = Prepared();
  const std::lock_guard<std::mutex> guard(prepared.lock);
  DiscardPreparedLocked(prepared);
  prepared.rules = rules;
  prepared.builder = std::thread([rules, &prepared] {
    // The precision the sim thread builds it under.
    platform::SetX87PrecisionControl(_PC_24);
    gpg::SetThreadName(0xFFFFFFFFu, "Sim Lua prep");
    try {
      prepared.state = BuildSimLuaState(rules);
    } catch (const std::exception& error) {
      gpg::Warnf("Preparing the sim's Lua state failed, the sim builds its own: %s", error.what());
    }
  });
}

void moho::SIM_FinishPreparingLuaState()
{
  PreparedSimLuaState& prepared = Prepared();
  const std::lock_guard<std::mutex> guard(prepared.lock);
  if (prepared.builder.joinable()) {
    prepared.builder.join();
  }
}

void moho::SIM_DiscardPreparedLuaState(const RRuleGameRules* const rules)
{
  PreparedSimLuaState& prepared = Prepared();
  const std::lock_guard<std::mutex> guard(prepared.lock);
  if (rules != nullptr && prepared.rules == rules) {
    DiscardPreparedLocked(prepared);
  }
}

// Global "current sim" singleton and reflection type descriptor.
Sim* Sim::sInstance = nullptr;

/**
 * Address: 0x007434D0 (FUN_007434D0, ??0Sim@Moho@@AAE@PAULaunchInfoBase@1@@Z)
 * Mangled: ??0Sim@Moho@@AAE@PAULaunchInfoBase@1@@Z
 *
 * IDA signature:
 * Moho::Sim *__stdcall Moho::Sim::Sim(Moho::Sim *this, Moho::LaunchInfoBase *info);
 *
 * What it does:
 * Placement-constructed factory constructor. Establishes the full 0xAF8 Sim
 * layout, seeds the command-source vector + focus army from the launch info,
 * optionally opens the synclog file, builds a fresh Lua state, runs the "core"
 * and "sim" init sets, loads `simInit.lua`/`saveload.lua`, loads terrain types,
 * allocates the occupation grid and path tables, then exports the rules to Lua
 * and seeds the rolling sim checksum.
 */
Sim::Sim(LaunchInfoBase* const info)
  : ICommandSink()
  , mLog(nullptr)
  , mIsDesyncFree(true)
  , mEffectManager(nullptr)
  , mSoundManager(nullptr)
  , mRules(info->mGameRules)
  , mMapData(nullptr)
  , mLuaState(nullptr)
  , mGameEnded(false)
  , mGameOver(false)
  , mPausedByCommandSource(-1)
  , mSingleStep(false)
  , mAdvancedThisTick(false)
  , mCheatsEnabled(false)
  , mReserved8E7(false)
  , mCurBeat(0)
  , mDidProcess(true)
  , mCurTick(0)
  , mRngState(nullptr)
  , mOGrid(nullptr)
  , mCurCommandSource(255)
  , mPathTables(nullptr)
  , mFormationDB(nullptr)
  , mEntityDB(nullptr)
  , mCommandDB(nullptr)
  , mReserved98C(0)
  , mReserved990(0)
  , mDecalBuffer(nullptr)
  , mPhysConstants(nullptr)
  , mRequestXMLArmyStatsSubmit(false)
  , mSyncArmy(-1)
  , mDidSync(false)
{
  // POD lanes the compiler does not default-init are cleared here to match the
  // binary's explicit member zeroing.
  mSyncReserveUnused = 0;
  mSyncSizes = SSyncSizes{};
  mContext.Reset();

  // Seed the command-source vector from the launch info block, then mark the
  // "no source" sentinel and adopt the focus army.
  (void)CopyConstructCommandSourceVector(info->mCommandSources.mSrcs, &mCommandSources);

  // Optionally open the per-beat synclog when /synclog was requested.
  fa::vector<fa::string> synclogArgs;
  if (CFG_GetArgOption("/synclog", 1u, &synclogArgs) && !synclogArgs.empty()) {
    const fa::string& synclogDir = synclogArgs.front();
    ::CreateDirectoryA(synclogDir.c_str(), nullptr);

    const fa::string filenamePrefix = LOG_GenerateFilenamePrefix();
    const fa::string prefixWithSlash = synclogDir + fa::string("/");
    mLogFilePrefix.assign(prefixWithSlash + filenamePrefix, 0, fa::string::npos);

    ::CreateDirectoryA(mLogFilePrefix.c_str(), nullptr);
    (void)mLogFilePrefix.append("/", 1u);

    const fa::string beatFile = FormatBeatLogFilePath(mLogFilePrefix, static_cast<int>(mCurBeat));
    mLog = std::fopen(beatFile.c_str(), "w");
  }

  // Engine addition (issue #216): the desync recorder starts with beat 0, as the file does.
  CDesyncRecorder::Attach(*this);

  Logf("********** beat %d **********\n", mCurBeat);

  // Adopt ownership of the map data (moved out of the launch info).
  STIMap* const previousMap = mMapData;
  mMapData = info->mMap;
  info->mMap = nullptr;
  if (previousMap) {
    delete previousMap;
  }

  mSyncFilter.focusArmy = info->mCommandSources.mOriginalSource;

  // A fresh Lua state with the core + sim init form sets and the rules' blueprints, then this
  // Sim bound as its global userdata. Engine addition: the state the session loader had built
  // ahead of the sim (SIM_PrepareLuaState) when there is one, otherwise built here; the binary
  // bound the Sim and set the debug hook before running the init sets, none of which reads them.
  {
    LuaPlus::LuaState* newState = TakePreparedLuaState(mRules);
    if (newState == nullptr) {
      newState = BuildSimLuaState(mRules);
    }
    LuaPlus::LuaState* const previousState = mLuaState;
    mLuaState = newState;
    if (previousState) {
      delete previousState;
    }
  }
  lua_setglobaluserdata(mLuaState->m_state, this);
  if (SCR_IsDebugWindowActive()) {
    lua_sethook(mLuaState->m_state, &moho::DebugLuaHook, 4, 0);
  }
  mLuaState->m_luaTask = reinterpret_cast<CLuaTask*>(&mDiskWatcherTaskStage);
  static_cast<RRuleGameRulesImpl*>(mRules)->OnSimHasBlueprints();

  {
    LuaPlus::LuaObject globals = mLuaState->GetGlobals();
    globals.SetString("__language", info->mLanguage.c_str());
  }

  (void)SCR_LuaDoScript(mLuaState, "/lua/simInit.lua", nullptr);
  (void)SCR_LuaDoScript(mLuaState, "/lua/system/saveload.lua", nullptr);
  mMapData->LoadTerrainTypes(mLuaState);

  // Allocate the occupation grid.
  {
    gpg::LogScopeEntry ogridScope(fa::string("MEM: %i bytes OGRID"));
    auto* const newGrid = new COGrid(this);
    COGrid* const previousGrid = mOGrid;
    mOGrid = newGrid;
    if (previousGrid) {
      delete previousGrid;
    }
    ogridScope.Emit();
  }

  // Allocate the path tables sized to the interior of the heightfield.
  {
    CHeightField* const heightField = mMapData->mHeightField.get();
    const std::int32_t interiorWidth = heightField->width - 1;
    const std::int32_t interiorHeight = heightField->height - 1;
    const SRuleFootprintsBlueprint* const footprints = mRules->GetFootprints();
    auto* const newTables = new PathTables(*footprints, mOGrid, interiorWidth, interiorHeight);
    PathTables* const previousTables = mPathTables;
    mPathTables = newTables;
    if (previousTables) {
      delete previousTables;
    }
  }

  // Seed the rolling sim checksum from the rules and log the initial digest.
  // Engine addition: a recorder that isn't recording drops the text, so with one like that only the
  // /synclog file, if any, gets the trace (dbg_RulesTraceAlways 1: every session writes it, as before).
  CDesyncRecorder* const recorder = CDesyncRecorder::For(this);
  if (recorder != nullptr && (recorder->IsRecording() || dbg_RulesTraceAlways)) {
    // Engine addition (issue #216): REF_UpdateMD5 traces into a FILE*, so the recorder takes the
    // rules trace through a temporary file the CRT deletes when it is closed; the /synclog file,
    // when there is one, gets the same text. A recorder keeping checksums only would drop the
    // text, so it gets none and the checksum is taken as without a recorder.
    std::FILE* const trace = std::tmpfile();
    if (trace == nullptr) {
      gpg::Warnf("Desync recorder: no temporary file for the rules trace; beat 0 is recorded without it");
    }
    mRules->UpdateChecksum(&mContext, trace);
    if (trace != nullptr) {
      std::rewind(trace);
      char chunk[64 * 1024];
      std::size_t got = 0;
      while ((got = std::fread(chunk, 1u, sizeof(chunk), trace)) > 0u) {
        recorder->Append(chunk, got);
        if (mLog) {
          (void)std::fwrite(chunk, 1u, got, mLog);
        }
      }
      (void)std::fclose(trace);
    }
  } else {
    mRules->UpdateChecksum(&mContext, mLog);
  }
  const gpg::MD5Digest digest = mContext.Digest();
  Logf("SimChecksum after rules: %s\n", digest.ToString().c_str());
}
