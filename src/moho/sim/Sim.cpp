#include "moho/lua/ScrLuaUserData.h"
#include "moho/sim/SimPrivate2.h"
#include "moho/entity/EntityMemoryManager.h"
#include "moho/sim/SimBlockLane.h"

#include <mutex>
#include <thread>

#include "platform/X87Precision.h"

namespace moho
{

  /// Engine addition: the light recon refreshes before the heavy army run next to its ReconTick.
  extern bool sim_ReconOverlap;
}

namespace
{
  /// Plan WPL.18: one table's keys in `lua_next` order, `depth` levels down into tables under
  /// string keys (at the top level only into `moho`). Other keys print as their number or
  /// type, never as an address.
  void DumpLuaTableKeys(lua_State* const state, std::FILE* const out, const std::string& path, const int depth)
  {
    lua_pushnil(state);
    while (lua_next(state, -2) != 0) {
      const int keyType = lua_type(state, -2);
      std::string name;
      if (keyType == LUA_TSTRING) {
        name = lua_tostring(state, -2);
      } else if (keyType == LUA_TNUMBER) {
        char number[32];
        std::snprintf(number, sizeof(number), "[%.14g]", static_cast<double>(lua_tonumber(state, -2)));
        name = number;
      } else {
        name = std::string("<") + lua_typename(state, keyType) + ">";
      }
      const std::string child = path.empty() ? name : path + "." + name;
      std::fprintf(out, "%s %s\n", child.c_str(), lua_typename(state, lua_type(state, -1)));
      if (depth > 0 && keyType == LUA_TSTRING && lua_type(state, -1) == LUA_TTABLE && (!path.empty() || name == "moho")) {
        DumpLuaTableKeys(state, out, child, depth - 1);
      }
      lua_settop(state, -2); // pop the value, keep the key for lua_next
    }
  }

  /// Plan WPL.18: the globals' `pairs()` order and that of the `moho` class tables.
  void DumpLuaPairsOrder(lua_State* const state, const char* const path)
  {
    std::FILE* out = nullptr;
    if (state == nullptr || fopen_s(&out, path, "w") != 0 || out == nullptr) {
      gpg::Warnf("cannot write the Lua pairs order to %s", path);
      return;
    }
    const int top = lua_gettop(state);
    lua_pushvalue(state, LUA_GLOBALSINDEX);
    DumpLuaTableKeys(state, out, "", 2);
    lua_settop(state, top);
    std::fclose(out);
  }
}




// Engine addition (dedicated-server plan WPL.4), declared in CSimSoundManager.h.
moho::SoundEnabledHook moho::sSoundEnabled = nullptr;

std::uint8_t moho::ren_Steering = 0;
bool moho::sim_KeepAllLogFiles = false;
bool moho::sim_ShowDamage = false;
const char* moho::sim_LuaPairsDumpPath = nullptr;
namespace moho
{

  struct CPrfTimeLogItem
  {
    const char* messageFormat = nullptr;
    std::uint32_t reserved0 = 0;
    double scale = 0.0;
    gpg::time::Timer timer{};

    /**
     * Address: 0x004A3580 (FUN_004A3580, ??1CPrfTimeLogItem@Moho@@QAE@XZ)
     *
     * What it does:
     * Logs one scoped profile duration using the configured scale factor.
     */
    ~CPrfTimeLogItem();
  };

#if defined(_M_IX86)
  static_assert(sizeof(CPrfTimeLogItem) == 0x18, "CPrfTimeLogItem size must be 0x18");
#endif
}



/**
 * Address: 0x004A3580 (FUN_004A3580, ??1CPrfTimeLogItem@Moho@@QAE@XZ)
 *
 * What it does:
 * Logs one scoped profile duration using the configured scale factor.
 */
moho::CPrfTimeLogItem::~CPrfTimeLogItem()
{
  gpg::Logf(messageFormat, gpg::time::CyclesToSeconds(timer.ElapsedCycles()) * scale);
}
namespace
{
  [[nodiscard]] fa::string BuildMd5TraceIndent(const std::size_t indentDepth)
  {
    fa::string indent{};
    (void)indent.resize(indentDepth * 2u, ' ');
    return indent;
  }

  void PrintMd5TraceLexical(FILE* const traceFile, const std::size_t indentDepth, const fa::string& lexical)
  {
    if (traceFile == nullptr) {
      return;
    }

    const fa::string indent = BuildMd5TraceIndent(indentDepth);
    std::fprintf(traceFile, "%s%s\n", indent.c_str(), lexical.c_str());
  }

  void PrintMd5TraceFieldPrefix(FILE* const traceFile, const std::size_t indentDepth, const char* const fieldName)
  {
    if (traceFile == nullptr) {
      return;
    }

    const fa::string indent = BuildMd5TraceIndent(indentDepth);
    std::fprintf(traceFile, "%s%s:\n", indent.c_str(), fieldName != nullptr ? fieldName : "");
  }

  void PrintMd5TraceIndexPrefix(FILE* const traceFile, const std::size_t indentDepth, const std::uint32_t index)
  {
    if (traceFile == nullptr) {
      return;
    }

    const fa::string indent = BuildMd5TraceIndent(indentDepth);
    std::fprintf(traceFile, "%s[%u]:\n", indent.c_str(), index);
  }
}




/**
 * Address: 0x004A4920 (FUN_004A4920)
 * Mangled: ?REF_UpdateMD5@Moho@@YAXAAVMD5Context@gpg@@ABVRRef@3@PAU_iobuf@@H@Z
 *
 * What it does:
 * Walks a reflected value tree, emits optional textual trace output, and
 * folds deterministic value bytes/shape into the provided MD5 context.
 * Called per blueprint by `RRuleGameRulesImpl::UpdateChecksum`, which seeds
 * every session's checksum.
 */
void moho::REF_UpdateMD5(
  gpg::MD5Context& md5,
  const gpg::RRef& ref,
  std::FILE* const traceFile,
  const int indentDepth
)
{
  gpg::RType* const refType = ref.mType;
  const std::size_t depth = static_cast<std::size_t>(indentDepth);
  const bool isPrimitiveLike =
    refType == gpg::RTypeOf<char>() || refType == gpg::RTypeOf<short>() || refType == gpg::RTypeOf<int>() || refType == gpg::RTypeOf<long>()
    || refType == gpg::RTypeOf<signed char>() || refType == gpg::RTypeOf<unsigned char>() || refType == gpg::RTypeOf<float>()
    || refType == gpg::RTypeOf<bool>() || refType->IsEnumType() != nullptr;

  if (isPrimitiveLike) {
    if (traceFile != nullptr) {
      PrintMd5TraceLexical(traceFile, depth, ref.GetLexical());
    }
    md5.Update(ref.mObj, static_cast<std::size_t>(refType->size_));
    return;
  }

  if (refType == gpg::RTypeOf<fa::string>()) {
    if (traceFile != nullptr) {
      PrintMd5TraceLexical(traceFile, depth, ref.GetLexical());
    }
    const auto& stringValue = *static_cast<const fa::string*>(ref.mObj);
    md5.Update(stringValue.c_str(), stringValue.size() + 1u);
    return;
  }

  const std::size_t fieldCount = refType->fields_.size();
  for (std::size_t fieldIndex = 0; fieldIndex < fieldCount; ++fieldIndex) {
    PrintMd5TraceFieldPrefix(traceFile, depth, refType->fields_[fieldIndex].mName);
    REF_UpdateMD5(md5, ref.GetField(static_cast<int>(fieldIndex)), traceFile, indentDepth + 1);
  }

  if (const gpg::RIndexed* const pointerType = refType->IsPointer(); pointerType != nullptr) {
    const std::uint32_t pointerCount = static_cast<std::uint32_t>(pointerType->GetCount(ref.mObj));
    md5.Update(&pointerCount, sizeof(pointerCount));

    if (pointerCount != 0u) {
      REF_UpdateMD5(md5, pointerType->SubscriptIndex(ref.mObj, 0), traceFile, indentDepth);
    } else if (traceFile != nullptr) {
      const fa::string indent = BuildMd5TraceIndent(depth);
      std::fprintf(traceFile, "%s<NULL>\n", indent.c_str());
    }
    return;
  }

  const gpg::RIndexed* const indexedType = refType->IsIndexed();
  if (indexedType == nullptr) {
    return;
  }

  const std::uint32_t indexedCount = static_cast<std::uint32_t>(indexedType->GetCount(ref.mObj));
  md5.Update(&indexedCount, sizeof(indexedCount));

  for (std::uint32_t index = 0; index < indexedCount; ++index) {
    PrintMd5TraceIndexPrefix(traceFile, depth, index);
    REF_UpdateMD5(md5, indexedType->SubscriptIndex(ref.mObj, static_cast<int>(index)), traceFile, indentDepth + 1);
  }
}
namespace
{
  constexpr const char* kFlattenMapRectOutsideBoundaryWarning =
    "Attempted to flatten terrain outside map boundary! Operation Failed!";
  constexpr const char* kSetArmyColorSyntaxText = "syntax: SetArmyColor(army,r,g,b)";
  constexpr const char* kSetArmyColorInvalidArmyText = "Invalid army %i";
  constexpr const char* kDbgUsageText = "usage: %s [name]";

  /// 0x00E352F4, pushed to Sim::Printf when fewer than five tokens are given.
  constexpr const char* kDebugSetPlayableRectUsageText = "usage: DebugSetPlayableRect x0 y0 x1 y1";
  /// 0x00E35114, pushed to Sim::Printf when `STIMap::SetPlayableMapRect` refuses the rect.
  constexpr const char* kDebugSetPlayableRectInvalidText = "Attempted to set an invalid playable rect.";
  /// 0x00E3531C, the Sim-Lua mirror `gpg::STR_Printf` builds at 0x0075D739.
  constexpr const char* kDebugSetPlayableRectSyncFormat = "SyncPlayableRect({ x0=%s, x1=%s, y0=%s, y1=%s })";

  /// 0x0064BEC7, pushed to Sim::Printf when the amount argument is missing.
  constexpr const char* kDamageUnitUsageText = "Syntax: DamageUnit <amount>";
  /// 0x0064BE2D ("Debug"), the damage type DamageUnit reports.
  constexpr const char* kDamageUnitDamageType = "Debug";
  constexpr const char* kDbgAvailableOverlaysText = "Available overlays";
  constexpr const char* kDbgUnknownOverlayText = "Unknown debug overlay: %s";
  constexpr const char* kDbgAmbiguousOverlayText = "Ambiguous debug overlay: %s.";
  constexpr const char* kDbgCouldBeAnyOfText = "Could be any of:";
  constexpr const char* kUnknownArmyMessage = "Unknown army: %s";
  constexpr const char* kUnexpectedArmyTypeMessage = "Unexpected type for army object";

  /**
   * Address: 0x005794A0 (FUN_005794A0)
   *
   * What it does:
   * Returns the `Sim::mRules` pointer lane.
   */
  [[maybe_unused]] [[nodiscard]] RRuleGameRules* ReadSimRulesLane(Sim* const sim) noexcept
  {
    return sim != nullptr ? sim->mRules : nullptr;
  }

  /**
   * Address: 0x005794B0 (FUN_005794B0)
   *
   * What it does:
   * Returns the `Sim::mMapData` pointer lane.
   */
  [[maybe_unused]] [[nodiscard]] STIMap* ReadSimMapDataLane(Sim* const sim) noexcept
  {
    return sim != nullptr ? sim->mMapData : nullptr;
  }










  template <class THandler>
  void ForEachSelectedUnit(EntitySetTemplate<Unit>* const selectedUnits, THandler&& handler)
  {
    if (selectedUnits == nullptr) {
      return;
    }

    for (Entity* const* it = selectedUnits->mVec.begin(); it != selectedUnits->mVec.end(); ++it) {
      Unit* const unit = static_cast<Unit*>(*it);
      if (unit != nullptr) {
        handler(*unit);
      }
    }
  }

  bool ParseBoolLiteral(const char* text, bool& outValue)
  {
    if (gpg::STR_EqualsNoCase(text, "true")) {
      outValue = true;
      return true;
    }

    if (gpg::STR_EqualsNoCase(text, "false")) {
      outValue = false;
      return true;
    }

    return false;
  }

  [[nodiscard]]
  CEconStorage* GetArmyEconStorage(CArmyImpl& army) noexcept
  {
    CSimArmyEconomyInfo* const economyInfo = army.GetEconomy();
    return economyInfo != nullptr ? economyInfo->storageDelta : nullptr;
  }


  /**
   * Address: 0x006E0850 (FUN_006E0850)
   *
   * What it does:
   * Extracts the low 24-bit command-id/index payload lane from packed command
   * id storage.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t ExtractPackedCommandIdLow24Bits(const std::uint32_t* const packedValue)
    noexcept
  {
    return packedValue != nullptr ? (*packedValue & 0x00FFFFFFu) : 0u;
  }

  [[nodiscard]] CUnitCommand* AddIssueDataToCommandDb(
    CCommandDB* const commandDb,
    const SSTICommandIssueData& issueData
  )
  {
    return commandDb ? commandDb->AddIssueData(issueData) : nullptr;
  }

  [[nodiscard]] bool IsUnitIdleState(Unit* const unit) noexcept
  {
    if (unit == nullptr || unit->CommandQueue == nullptr) {
      return true;
    }

    return unit->CommandQueue->GetCurrentCommand() == nullptr;
  }

  /**
   * Address: 0x006EF660 (FUN_006EF660, sub_6EF660)
   *
   * What it does:
   * For `TransportReverseLoadUnits`, replaces the incoming selected-unit set
   * with one best transport candidate plus the requested target unit.
   */
  void RetargetReverseLoadUnits(
    const SSTICommandIssueData& issueData,
    Sim* const sim,
    EntitySetTemplate<Unit>& selectedUnits
  )
  {
    if (sim == nullptr || issueData.mCommandType != EUnitCommandType::UNITCOMMAND_TransportReverseLoadUnits) {
      return;
    }

    EntitySetTemplate<Unit> originalSelection{};
    for (Entity* const* it = selectedUnits.mVec.begin(); it != selectedUnits.mVec.end(); ++it) {
      originalSelection.mVec.PushBack(*it);
    }
    selectedUnits.Clear();

    Entity* const targetEntity = FindEntityById(sim->mEntityDB, static_cast<EntId>(issueData.mTarget.mEntityId));
    Unit* const targetUnit = targetEntity != nullptr ? targetEntity->IsUnit() : nullptr;
    if (targetUnit == nullptr || targetUnit->IsDead() || !targetUnit->IsMobile()) {
      return;
    }

    const RUnitBlueprint* const targetBlueprint = targetUnit->GetBlueprint();
    Unit* bestTransport = nullptr;
    float bestScore = gpg::pInf;

    for (Entity* const* it = originalSelection.mVec.begin(); it != originalSelection.mVec.end(); ++it) {
      Unit* const candidate = static_cast<Unit*>(*it);
      if (candidate == nullptr || candidate->IsDead() || candidate->IsBeingBuilt()) {
        continue;
      }

      if (!candidate->IsInCategory("TRANSPORTATION") && !candidate->IsInCategory("AIRSTAGINGPLATFORM")
          && !candidate->IsInCategory("TELEPORTATION")) {
        continue;
      }

      IAiTransport* const transport = candidate->AiTransport;
      if (transport == nullptr || !transport->TransportHasSpaceFor(targetBlueprint)) {
        continue;
      }

      const Wm3::Vec3f& targetPos = targetUnit->GetPosition();
      const Wm3::Vec3f& candidatePos = candidate->GetPosition();
      const float dx = candidatePos.x - targetPos.x;
      const float dz = candidatePos.z - targetPos.z;
      float score = std::sqrt((dx * dx) + (dz * dz));
      if (IsUnitIdleState(candidate)) {
        score *= 0.5f;
      }

      if (score < bestScore) {
        bestScore = score;
        bestTransport = candidate;
      }
    }

    if (bestTransport != nullptr) {
      (void)selectedUnits.Add(bestTransport);
      (void)selectedUnits.Add(targetUnit);
    }
  }

  /**
   * Address: 0x006F14D0 (FUN_006F14D0, Moho::UNIT_IssueFactoryCommand)
   *
   * What it does:
   * Iterates selected factories, rejects invalid/no-rush/transported lanes,
   * lazily allocates one shared command, then enqueues it into each eligible
   * factory builder queue (optionally clearing queue first).
   */
  [[nodiscard]] CUnitCommand* IssueFactoryCommandToSelectedUnitsImpl(
    Sim* const sim,
    const EntitySetTemplate<Unit>& selectedUnits,
    const SSTICommandIssueData& commandIssueData,
    const bool clearQueue
  )
  {
    if (!sim) {
      return nullptr;
    }

    // 0x006F1530..0x006F1596 tests the raw target; decoding it here would draw
    // from the sim RNG (replay 27960975 desynced at beat 31123).
    CAiTarget noRushTarget{};
    noRushTarget.targetType = commandIssueData.mTarget.mType;
    noRushTarget.position = commandIssueData.mTarget.mPos;

    CUnitCommand* issuedCommand = nullptr;
    for (Entity* const* it = selectedUnits.mVec.begin(); it != selectedUnits.mVec.end(); ++it) {
      Unit* const unit = static_cast<Unit*>(*it);
      if (!unit || unit->IsDead()) {
        continue;
      }

      if (unit->TransportedByRef.GetObjectPtr() != nullptr) {
        continue;
      }

      if (IsOutsideArmyNoRushRadius(unit->ArmyRef, noRushTarget)) {
        continue;
      }

      auto* const builder = static_cast<CAiBuilderImpl*>(unit->AiBuilder);
      if (!builder || !builder->BuilderIsFactory()) {
        continue;
      }

      if (!issuedCommand) {
        issuedCommand = AddIssueDataToCommandDb(sim->mCommandDB, commandIssueData);
        if (!issuedCommand) {
          break;
        }
        issuedCommand->mUnknownFlag142 = true;
      }

      if (clearQueue) {
        builder->BuilderClearFactoryCommandQueue();
      }

      builder->BuilderAddFactoryCommand(issuedCommand, -1);
    }

    if (!issuedCommand) {
      ReleaseCommandIdIfUnconsumed(sim->mCommandDB, commandIssueData.nextCommandId);
    }

    return issuedCommand;
  }

  /**
   * Address: 0x006F12C0 (FUN_006F12C0, UNIT_IssueCommand)
   *
   * What it does:
   * Validates each selected unit through `func_ProcessUnitCommand`, creates one
   * shared command object lazily, and appends/inserts it into eligible queues.
   */
  [[nodiscard]] CUnitCommand* IssueCommandToSelectedUnitsImpl(
    Sim* const sim,
    EntitySetTemplate<Unit>& selectedUnits,
    const SSTICommandIssueData& commandIssueData,
    const bool clearQueue
  )
  {
    if (sim == nullptr || sim->mCommandDB == nullptr) {
      ReleaseCommandIdIfUnconsumed(sim ? sim->mCommandDB : nullptr, commandIssueData.nextCommandId);
      return nullptr;
    }

    // 0x006F12FC copies the selection (0x0057D3F0) and works on the copy from
    // here on, so the reverse-load retarget never edits the caller's set.
    EntitySetTemplate<Unit> issueUnits(selectedUnits);
    RetargetReverseLoadUnits(commandIssueData, sim, issueUnits);

    CUnitCommand* issuedCommand = nullptr;
    // 0x006F12C0: the append-vs-insert decision reads the issue data's +0x08
    // lane (`mIndex`, the id of the queued command to insert before; -1 =
    // append), not the freshly allocated id at +0x00. Reading +0x00 here made
    // every ordinary order look like an insert before an id that is not in
    // the queue, so nothing was ever queued and the unit stayed idle.
    const std::uint32_t insertBeforeTopByte = static_cast<std::uint32_t>(commandIssueData.mIndex) & 0xFF000000u;
    const bool appendByDefault = insertBeforeTopByte == 0xFF000000u;

    for (Entity* const* it = issueUnits.mVec.begin(); it != issueUnits.mVec.end(); ++it) {
      Unit* const unit = static_cast<Unit*>(*it);

      // 0x006F1392 runs the per-unit check first; only then does 0x006F13A2
      // skip a unit without a command queue.
      if (!ProcessIssuedUnitCommand(sim, commandIssueData, unit, clearQueue, issueUnits)) {
        continue;
      }

      CUnitCommandQueue* const queue = unit->CommandQueue;
      if (queue == nullptr) {
        continue;
      }

      const std::size_t queueSize = queue->mCommandVec.size();
      if (queueSize > 500u && !clearQueue) {
        continue;
      }

      if (issuedCommand == nullptr) {
        issuedCommand = AddIssueDataToCommandDb(sim->mCommandDB, commandIssueData);
        if (issuedCommand == nullptr) {
          break;
        }
      }

      if (clearQueue) {
        queue->mCommandType = commandIssueData.mCommandType;
        queue->ClearCommandQueue();
      }

      if (appendByDefault) {
        queue->AddCommandToQueue(issuedCommand);
        continue;
      }

      const int insertIndex = queue->FindCommandIndex(static_cast<CmdId>(commandIssueData.mIndex));
      if (insertIndex >= 0) {
        queue->InsertCommandToQueue(issuedCommand, insertIndex);
      }
    }

    // 0x006F145A..0x006F1481: the id is handed back only when no command was
    // created; a created command is returned even if no queue took it.
    if (issuedCommand == nullptr) {
      ReleaseCommandIdIfUnconsumed(sim->mCommandDB, commandIssueData.nextCommandId);
    }

    return issuedCommand;
  }

  // 0x00748AA0 resolves unit blueprints from RResId via RRuleGameRules::GetUnitBlueprint.
  const RUnitBlueprint* ResolveUnitBlueprint(RRuleGameRules* rules, const RResId& blueprintId)
  {
    if (!rules) {
      return nullptr;
    }

    return rules->GetUnitBlueprint(blueprintId);
  }

  /**
   * Address: 0x006EF150 (FUN_006EF150, func_GetUnitBlueprint)
   *
   * What it does:
   * Resolves one Lua blueprint-id argument into `RUnitBlueprint*`, raising a
   * typed Lua error for non-string non-nil values.
   */
  [[nodiscard]] RUnitBlueprint* ResolveUnitBlueprintFromLuaArgumentImpl(
    LuaPlus::LuaState* const state,
    const LuaPlus::LuaStackObject& blueprintObject,
    const char* const functionName
  )
  {
    if (!state || !state->m_state || !blueprintObject.m_state || !blueprintObject.m_state->m_state) {
      return nullptr;
    }

    lua_State* const rawState = blueprintObject.m_state->m_state;
    if (lua_isstring(rawState, blueprintObject.m_stackIndex)) {
      const char* const blueprintIdText = lua_tostring(rawState, blueprintObject.m_stackIndex);
      if (blueprintIdText == nullptr) {
        blueprintObject.TypeError("string");
      }

      RResId lookupId{};
      gpg::STR_InitFilename(&lookupId.name, blueprintIdText);

      Sim* const sim = ResolveGlobalSim(state->m_state);
      if (sim == nullptr || sim->mRules == nullptr) {
        return nullptr;
      }

      return sim->mRules->GetUnitBlueprint(lookupId);
    }

    if (lua_type(rawState, blueprintObject.m_stackIndex) != 0) {
      const LuaPlus::LuaObject blueprintValue(blueprintObject);
      const char* const typeName = blueprintValue.TypeName();
      LuaPlus::LuaState::Error(
        state,
        "Invalid blueprint in %s; expected a string but got a %s",
        functionName != nullptr ? functionName : "",
        typeName != nullptr ? typeName : ""
      );
    }

    return nullptr;
  }

  // Ground truth (`FUN_00748AA0`, `Sim::CreateUnit`'s inlined call to this
  // helper; confirmed from the .asm's literal `call Moho__EulerRollToQuat`)
  // builds the spawn orientation via `Moho::EulerRollToQuat`, which writes
  // this engine's scalar-first convention directly -- not
  // `Wm3::Quatf::MakeFromAxisAngle` (a FAF-added WildMagic-style helper that
  // writes cos(half) into the native `.w` lane), which produced a
  // `.w`-scalar-tagged-as-`.x` quaternion for every spawned unit's initial
  // heading. Same pattern as `Unit::PredictAheadBomb`'s earlier fix.
  VTransform BuildUnitSpawnTransform(const SCoordsVec2& pos, const float heading)
  {
    const Wm3::Vec3f headingAxis{0.0f, 1.0f, 0.0f};
    Wm3::Quatf orientation{};
    (void)EulerRollToQuat(&headingAxis, &orientation, heading);
    const Wm3::Vec3f worldPosition{pos.x, 0.0f, pos.z};
    return VTransform(worldPosition, orientation);
  }


  // 0x00748D50 queues silo builds through CAiSiloBuildImpl (0=tactical, 1=nuke).
  bool QueueSiloBuildRequest(Unit* unit, const int modeIndex)
  {
    if (!unit || !unit->AiSiloBuild) {
      return false;
    }

    return unit->AiSiloBuild->SiloAddBuild(static_cast<ESiloType>(modeIndex));
  }

  // 0x00748CD0 applies orientation+position in one call via Entity::Warp.
  void ApplyWarpTransform(Entity* entity, const VTransform& transform)
  {
    if (!entity) {
      return;
    }

    entity->Warp(transform);
  }

  /**
   * Address: 0x00754C60 (FUN_00754C60, sub_754C60)
   *
   * What it does:
   * Core Sim load-serialization routine used by Sim serializer callback.
   */
  [[maybe_unused]] gpg::RType* FindRTypeByNameAny(const std::initializer_list<const char*>& names)
  {
    gpg::TypeMap& map = gpg::GetRTypeMap();
    for (const char* name : names) {
      if (!name || !*name) {
        continue;
      }
      auto it = map.find(name);
      if (it != map.end()) {
        return it->second;
      }
      for (auto jt = map.begin(); jt != map.end(); ++jt) {
        const char* registered = jt->first;
        if (registered && std::strstr(registered, name) != nullptr) {
          return jt->second;
        }
      }
    }
    return nullptr;
  }


  bool IsSimDebugCheatsEnabled()
  {
    return moho::console::SimDebugCheatsEnabled();
  }

  bool IsSimReportCheatsEnabled()
  {
    return moho::console::SimReportCheatsEnabled();
  }

  int GetCallStackFrames(std::uintptr_t* outFrames)
  {
    return moho::console::PlatformGetCallStack(outFrames, 0x10u);
  }

  void FormatCallStack(fa::string* outText, const int frameCount, const std::uintptr_t* frames)
  {
    moho::console::PlatformFormatCallstack(outText, frameCount, frames);
  }
}

namespace moho
{
  /**
   * Preview-only `IPathTraveler` implementation used by `Sim::path_GeneratePreview`
   * (the `path_GeneratePreview` SimCon command) to run a background pathfind on
   * behalf of a UI drag-to-move preview.
   *
   * RTTI: vftable@0x00E35D5C, 12 primary slots (inherited from `Moho::IPathTraveler`,
   * `??_7PathPreviewFinder@Moho@@6B@`); bases `Moho::IPathTraveler` (mdisp=0),
   * `.?AV?$DListItem@VIPathTraveler@Moho@@X@gpg@@` (mdisp=4, `IPathTraveler`'s
   * base), `boost::noncopyable` (mdisp=4) - all already
   * covered by deriving from the already-recovered `Moho::IPathTraveler`.
   */
  class PathPreviewFinder final : public IPathTraveler
  {
  public:
    /**
     * Address: 0x007647E0 (FUN_007647E0, ??0PathPreviewFinder@Moho@@QAE@@Z)
     *
     * What it does:
     * Binds the finder to its owning army, resolves the owning `Sim`/`COGrid`
     * and the army's path-preview callback owner through `CArmyImpl::GetSim`/
     * `CArmyImpl::GetPathFinder`, and clears the active preview endpoints.
     */
    explicit PathPreviewFinder(CArmyImpl* owningArmy) noexcept;

    // Moho::IPathTraveler overrides (RTTI vftable slots 0-11).
    [[nodiscard]] const SFootprint* GetFootprint() const override;
    [[nodiscard]] bool CanTraverseCell(const SOCellPos& cellPos) const override;
    [[nodiscard]] bool IsInBounds(const SOCellPos& fromCell, const SOCellPos& toCell, float* edgeCost) const override;
    [[nodiscard]] float GetHeuristicCost(const SOCellPos& cellPos) const override;
    void GetAnchorCell(HPathCell* outCell) const override;
    [[nodiscard]] bool IsGoalCandidateCell(const SOCellPos& cellPos) const override;
    void OnPathAccepted(const SNavPath& path) override;
    [[nodiscard]] bool ShouldSearchRect(const gpg::Rect2i& rect) const override;
    void OnPathSearchCancelled() override;
    void OnPathRejected(const SNavPath& path) override;
    [[nodiscard]] std::int32_t GetPathcap() const override;
    void GetResultCell(HPathCell* outCell) const override;

    /**
     * Address: 0x00764880 (FUN_00764880)
     *
     * What it does:
     * Updates the preview finder start/goal lanes when footprint traversal state
     * changes, then requeues the finder at the front of the callback-owner list.
     */
    void ApplySearchEndpoints(const SFootprint* footprint, const SOCellPos& startCell, const SOCellPos& goalCell);

    /**
     * Address: 0x00764900 (FUN_00764900)
     *
     * What it does:
     * Detaches this finder from the callback-owner queue and clears its current
     * footprint lane, when a footprint is currently active.
     */
    void ResetQueuedFootprint();

  public:
    CArmyImpl* mOwnerContext;         // +0x0C
    Sim* mSim;                        // +0x10
    COGrid* mOGrid;                   // +0x14
    PathQueue* mPathQueue;            // +0x18: the owning army's path queue (`CArmyImpl::PathFinder`)
    SOCellPos mStartCell;             // +0x1C
    SOCellPos mGoalCell;              // +0x20
    const SFootprint* mFootprint;     // +0x24
    bool mStartCellIsTraversable;     // +0x28 (asm: OCCUPY_FootprintFits tested against mStartCell, not mGoalCell)
  };

  static_assert(offsetof(PathPreviewFinder, mOwnerContext) == 0x0C, "PathPreviewFinder::mOwnerContext offset");
  static_assert(offsetof(PathPreviewFinder, mSim) == 0x10, "PathPreviewFinder::mSim offset");
  static_assert(offsetof(PathPreviewFinder, mOGrid) == 0x14, "PathPreviewFinder::mOGrid offset");
  static_assert(offsetof(PathPreviewFinder, mPathQueue) == 0x18, "PathPreviewFinder::mPathQueue offset");
  static_assert(offsetof(PathPreviewFinder, mStartCell) == 0x1C, "PathPreviewFinder::mStartCell offset");
  static_assert(offsetof(PathPreviewFinder, mGoalCell) == 0x20, "PathPreviewFinder::mGoalCell offset");
  static_assert(offsetof(PathPreviewFinder, mFootprint) == 0x24, "PathPreviewFinder::mFootprint offset");
  static_assert(offsetof(PathPreviewFinder, mStartCellIsTraversable) == 0x28, "PathPreviewFinder::mStartCellIsTraversable offset");
  static_assert(sizeof(PathPreviewFinder) == 0x2C, "PathPreviewFinder size must be 0x2C");

  PathPreviewFinder::PathPreviewFinder(CArmyImpl* const owningArmy) noexcept
    : IPathTraveler()
    , mOwnerContext(owningArmy)
    , mSim(owningArmy->GetSim())
    , mOGrid(mSim->mOGrid)
    , mPathQueue(static_cast<PathQueue*>(owningArmy->GetPathFinder()))
    , mStartCell{0, 0}
    , mGoalCell{0, 0}
    , mFootprint(nullptr)
    , mStartCellIsTraversable(false)
  {
  }

  /**
   * Address: 0x007657D0 (FUN_007657D0)
   *
   * What it does:
   * Destroys one heap-allocated `PathPreviewFinder` by invoking its real
   * (implicit) destructor chain -- see `PathPreviewFinder.h` for the full
   * cross-emission evidence -- then releasing the allocation.
   */
  void DeletePathPreviewFinder(PathPreviewFinder* const finder) noexcept
  {
    delete finder;
  }
}

namespace
{
  /**
   * Address: 0x00763DC0 (FUN_00763DC0)
   * Address: 0x00764760 (FUN_00764760)
   *
   * What it does:
   * Copies one contiguous 32-bit lane range `[sourceBegin, sourceEnd)` into
   * destination storage and returns one-past the copied destination cursor.
   */
  [[maybe_unused]] std::uint32_t* CopyDwordRangeNullable(
    std::uint32_t* destination,
    const std::uint32_t* const sourceBegin,
    const std::uint32_t* const sourceEnd
  ) noexcept
  {
    std::uintptr_t destinationAddress = reinterpret_cast<std::uintptr_t>(destination);
    for (const std::uint32_t* source = sourceBegin; source != sourceEnd; ++source) {
      if (destinationAddress != 0u) {
        *reinterpret_cast<std::uint32_t*>(destinationAddress) = *source;
      }
      destinationAddress += sizeof(std::uint32_t);
    }

    return reinterpret_cast<std::uint32_t*>(destinationAddress);
  }

  /**
   * Address: 0x00764610 (FUN_00764610)
   *
   * What it does:
   * Adapter lane that forwards one dword-range copy into the canonical
   * `CopyDwordRangeNullable` helper.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t* CopyDwordRangeNullableAdapterLaneA(
    const std::uint32_t* const sourceBegin,
    const std::uint32_t* const sourceEnd,
    std::uint32_t* const destination
  ) noexcept
  {
    return CopyDwordRangeNullable(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x007646F0 (FUN_007646F0)
   *
   * What it does:
   * Secondary adapter lane that forwards one dword-range copy into
   * `CopyDwordRangeNullable`.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t* CopyDwordRangeNullableAdapterLaneB(
    const std::uint32_t* const sourceBegin,
    const std::uint32_t* const sourceEnd,
    std::uint32_t* const destination
  ) noexcept
  {
    return CopyDwordRangeNullable(destination, sourceBegin, sourceEnd);
  }

  /**
   * Address: 0x00764720 (FUN_00764720)
   *
   * What it does:
   * Third adapter lane that forwards one dword-range copy into
   * `CopyDwordRangeNullable`.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t* CopyDwordRangeNullableAdapterLaneC(
    const std::uint32_t* const sourceBegin,
    const std::uint32_t* const sourceEnd,
    std::uint32_t* const destination
  ) noexcept
  {
    return CopyDwordRangeNullable(destination, sourceBegin, sourceEnd);
  }
}

namespace moho
{
  const SFootprint* PathPreviewFinder::GetFootprint() const
  {
    return mFootprint;
  }

  bool PathPreviewFinder::CanTraverseCell(const SOCellPos& cellPos) const
  {
    return static_cast<std::uint8_t>(
             OCCUPY_FootprintFits(*mOGrid, cellPos, *mFootprint, EOccupancyCaps::OC_ANY)
           ) != 0u;
  }

  // Address: 0x007647A0 (FUN_007647A0) -- always-in-bounds policy for preview traversal.
  bool PathPreviewFinder::IsInBounds(const SOCellPos&, const SOCellPos&, float*) const
  {
    return true;
  }

  float PathPreviewFinder::GetHeuristicCost(const SOCellPos& cellPos) const
  {
    const float deltaX = std::fabs(static_cast<float>(mGoalCell.x - cellPos.x));
    const float deltaZ = std::fabs(static_cast<float>(mGoalCell.z - cellPos.z));
    constexpr float kDiagScale = 0.41421354f;
    constexpr float kPreviewCostScale = 1.01f;
    const float baseCost = (deltaZ <= deltaX) ? ((deltaZ * kDiagScale) + deltaX) : ((deltaX * kDiagScale) + deltaZ);
    return baseCost * kPreviewCostScale;
  }

  // Address: 0x00764A00 (FUN_00764A00) -- writes the current preview anchor cell into the output lane.
  void PathPreviewFinder::GetAnchorCell(HPathCell* const outCell) const
  {
    outCell->x = static_cast<std::uint16_t>(mStartCell.x);
    outCell->z = static_cast<std::uint16_t>(mStartCell.z);
  }

  bool PathPreviewFinder::IsGoalCandidateCell(const SOCellPos& cellPos) const
  {
    return cellPos.x == mGoalCell.x && cellPos.z == mGoalCell.z;
  }

  /**
   * Address: 0x00764A80 (FUN_00764A80)
   *
   * What it does:
   * Publishes the accepted/rejected path's cells to the owning army through
   * `CArmyImpl::SetUnknownVectorWithMeta` (vtable slot +0x5C on the owner),
   * reusing the same generic word-vector-with-meta payload
   * (`Moho::SArmyVectorWithMeta`) `CArmyImpl` uses for its variable-data copy
   * lane: each 4-byte `SOCellPos` cell is packed into one `mWords` element and
   * the previous footprint pointer is carried in `mMetaWord`. Clears the
   * active footprint lane before publishing.
   */
  void PathPreviewFinder::OnPathAccepted(const SNavPath& path)
  {
    SArmyVectorWithMeta payload{};
    const std::size_t cellCount = path.Count();
    payload.mWords.resize(cellCount);
    for (std::size_t i = 0; i < cellCount; ++i) {
      payload.mWords[i] = std::bit_cast<std::uint32_t>(path.start[i]);
    }
    payload.mMetaWord = reinterpret_cast<std::uintptr_t>(mFootprint);
    mFootprint = nullptr;

    mOwnerContext->SetUnknownVectorWithMeta(&payload);
  }

  bool PathPreviewFinder::ShouldSearchRect(const gpg::Rect2i& rect) const
  {
    const auto inRect = [&rect](const SOCellPos& cell) {
      return cell.x >= rect.x0 && cell.x < rect.x1 && cell.z >= rect.z0 && cell.z < rect.z1;
    };
    return inRect(mStartCell) || inRect(mGoalCell);
  }

  // Address: 0x007647B0 (FUN_007647B0, nullsub_2211) -- no-op cancellation callback.
  void PathPreviewFinder::OnPathSearchCancelled()
  {
  }

  /**
   * Address: 0x00764B60 (FUN_00764B60)
   *
   * What it does:
   * The binary is a tail-call thunk (`jmp [[this]+0x18]`) into this finder's
   * own `OnPathAccepted` vtable slot, i.e. a rejected search publishes the
   * same cell payload as an accepted one.
   */
  void PathPreviewFinder::OnPathRejected(const SNavPath& path)
  {
    OnPathAccepted(path);
  }

  /**
   * Address: 0x00764B70 (FUN_00764B70)
   *
   * What it does:
   * Reads the current `path_TimeoutPreview` sim-convar value from the owning
   * sim lane used by path-preview traversal callbacks.
   */
  std::int32_t PathPreviewFinder::GetPathcap() const
  {
    CSimConVarInstanceBase* const instance = mSim->GetSimVar(&gSimConVar_path_TimeoutPreview);
    return *reinterpret_cast<const std::int32_t*>(instance->GetValueStorage());
  }

  // Address: 0x007647D0 (FUN_007647D0) -- clears one output result-cell lane.
  void PathPreviewFinder::GetResultCell(HPathCell* const outCell) const
  {
    outCell->x = 0;
    outCell->z = 0;
  }

  void PathPreviewFinder::ApplySearchEndpoints(
    const SFootprint* const footprint,
    const SOCellPos& startCell,
    const SOCellPos& goalCell
  )
  {
    if (mFootprint == footprint && mStartCellIsTraversable) {
      return;
    }

    mStartCell = startCell;
    mGoalCell = goalCell;
    mFootprint = footprint;
    // asm evidence (0x007648A9-0x007648B7): OCCUPY_FootprintFits is tested
    // against the just-assigned mStartCell, not mGoalCell.
    mStartCellIsTraversable =
      static_cast<std::uint8_t>(OCCUPY_FootprintFits(*mOGrid, mStartCell, *footprint, EOccupancyCaps::OC_ANY)) != 0u;

    // `PathQueue::QueueTraveler`, inlined (0x007648BC..0x007648EF): unlink,
    // self-link, append before the queue's pending sentinel.
    mPathQueue->QueueTraveler(*this);
  }

  void PathPreviewFinder::ResetQueuedFootprint()
  {
    if (mFootprint == nullptr) {
      return;
    }

    ListUnlink();
    mFootprint = nullptr;
  }
}

namespace
{
  /**
   * Address: 0x00764B90 (FUN_00764B90)
   *
   * What it does:
   * Chooses one live unit from the candidate unit-set lane that has a resolved
   * footprint and the largest blueprint size-Z lane.
   */
  Unit* PathPreviewSelectLargestUnit(const EntitySetTemplate<Unit>* const unitSet)
  {
    if (!unitSet) {
      return nullptr;
    }

    Unit* bestUnit = nullptr;
    float bestSizeZ = 0.0f;
    for (Entity* const entry : unitSet->mVec) {
      // The set stores the units' `Entity` bases (+0x08); the binary steps back
      // with a plain pointer adjust (0x00764B9A..0x00764BA6), no `IsUnit()`.
      Unit* const unit = static_cast<Unit*>(entry);
      if (!unit) {
        continue;
      }

      const RUnitBlueprint* const blueprint = unit->GetBlueprint();
      if (!blueprint || !blueprint->Physics.ResolvedFootprint || unit->IsBeingBuilt()) {
        continue;
      }

      if (blueprint->mSizeZ > bestSizeZ) {
        bestSizeZ = blueprint->mSizeZ;
        bestUnit = unit;
      }
    }

    return bestUnit;
  }

  /**
   * The command list a path preview ends on: a factory's own build queue when
   * it has one (`IAiBuilder` slot 8, 0x00764C2B), otherwise the unit's command
   * queue (`Unit::CommandQueue` +0x4B4, list at +0x0C).
   */
  [[nodiscard]] const fa::vector<WeakPtr<CUnitCommand>>* PathPreviewCommandList(Unit& unit)
  {
    if (IAiBuilder* const builder = unit.AiBuilder; builder != nullptr) {
      const fa::vector<WeakPtr<CUnitCommand>>& factoryQueue = builder->BuilderGetFactoryCommandQueue();
      if (!factoryQueue.empty()) {
        return &factoryQueue;
      }
    }

    return unit.CommandQueue != nullptr ? &unit.CommandQueue->mCommandVec : nullptr;
  }

  /**
   * Commands the preview looks past: bit `type` of the 64-bit mask
   * 0x2'D80000EA (`_allshl` 0x00B57F00, then `and eax, 0D80000EAh` /
   * `and edx, 2` at 0x00764C92). A shift of 64 or more clears the bit, as
   * `_allshl` does.
   */
  [[nodiscard]] bool PathPreviewSkipsCommand(const EUnitCommandType commandType) noexcept
  {
    constexpr std::uint64_t kSkippedCommandMask = 0x2D80000EAull;
    const auto shift = static_cast<std::uint32_t>(commandType);
    const std::uint64_t bit = shift < 64u ? (std::uint64_t{1} << shift) : 0u;
    return (bit & kSkippedCommandMask) != 0u;
  }

  /**
   * Address: 0x00764C10 (FUN_00764C10)
   *
   * What it does:
   * Chooses one terminal target position from queued command-target handles
   * (walking newest-to-oldest), then falls back to the unit position lane.
   */
  Wm3::Vector3f* PathPreviewResolveEndPosition(Wm3::Vector3f* const outPos, Unit* const unit)
  {
    if (const fa::vector<WeakPtr<CUnitCommand>>* const commands = PathPreviewCommandList(*unit); commands != nullptr) {
      // Newest first. The binary dereferences each command without a null
      // test (`[esi+98h]` at 0x00764C80), so a dead entry is not skipped here.
      for (std::size_t index = commands->size(); index != 0u; --index) {
        CUnitCommand* const command = (*commands)[index - 1u].GetObjectPtr();
        if (PathPreviewSkipsCommand(command->mVarDat.mCmdType)) {
          continue;
        }

        const Wm3::Vec3f targetPos = command->mTarget.GetTargetPosGun(false);
        outPos->x = targetPos.x;
        outPos->y = targetPos.y;
        outPos->z = targetPos.z;
        return outPos;
      }
    }

    const Wm3::Vec3f& unitPos = unit->GetPosition();
    outPos->x = unitPos.x;
    outPos->y = unitPos.y;
    outPos->z = unitPos.z;
    return outPos;
  }
}

namespace moho
{
  /**
   * Address: 0x00764CF0 (FUN_00764CF0, Moho::Sim::path_GeneratePreview)
   *
   * IDA signature:
   * void __cdecl Moho::Sim::path_GeneratePreview(
   *   Moho::Sim* sim, std::vector<std::string>* commandArgs, Wm3::Vector3f* worldPos,
   *   Moho::CArmyImpl* focusArmy, Moho::EntitySetTemplate<Unit>* selectedUnits);
   *
   * What it does:
   * `path_GeneratePreview` SimCon command. Picks the largest selected unit with
   * a resolved footprint that isn't being built; if one exists, lazily creates
   * (or reuses) the army's cached `PathPreviewFinder`, resolves the search
   * start cell (the unit's current position, or its queued end-of-command
   * target when the command's second argument is `"end"`) and goal cell (the
   * mouse world position) footprint-centered, and applies them to the finder.
   * If no eligible unit is selected, clears any cached preview finder and its
   * published-path payload on the army. Every branch feeds the desync MD5
   * hash and mirrors it to the sim log, matching the binary exactly so replay
   * checksums stay reproducible.
   */
  int Sim::path_GeneratePreview(
    Sim* const sim,
    CSimConCommand::ParsedCommandArgs* const commandArgs,
    Wm3::Vector3f* const worldPos,
    CArmyImpl* const focusArmy,
    EntitySetTemplate<Unit>* const selectedUnits
  )
  {
    if (focusArmy == nullptr) {
      return 0;
    }

    SSTIArmyConstantData armyConstData{};
    focusArmy->CopyArmyConstantData(&armyConstData);
    sim->mContext.Update(&armyConstData.mArmyIndex, sizeof(armyConstData.mArmyIndex));
    sim->Logf("path preview for army %d\n", armyConstData.mArmyIndex);

    boost::shared_ptr<PathPreviewFinder> previewFinder{};
    focusArmy->GetUnknownSharedRef(reinterpret_cast<boost::SharedPtrRaw<void>*>(&previewFinder));

    Unit* const unit = PathPreviewSelectLargestUnit(selectedUnits);
    if (unit != nullptr) {
      // `mov ecx, [esi+70h]` at 0x00764D7C: the unit's entity id (Entity+0x68,
      // the Entity base sitting at Unit+0x08) is hashed and logged.
      const EntId unitId = unit->id_;
      sim->mContext.Update(&unitId, sizeof(unitId));
      sim->Logf("  unit=0x%08x\n", static_cast<std::uint32_t>(unitId));

      if (!previewFinder) {
        previewFinder = boost::shared_ptr<PathPreviewFinder>(new PathPreviewFinder(focusArmy));
        focusArmy->SetUnknownSharedRef(reinterpret_cast<boost::SharedPtrRaw<void>*>(&previewFinder));
      }

      Wm3::Vector3f resolvedEndPos{};
      const bool wantsEndPosition =
        commandArgs->size() > 1 && (*commandArgs)[1] == "end";
      const Wm3::Vector3f& sourcePos = wantsEndPosition
        ? *PathPreviewResolveEndPosition(&resolvedEndPos, unit)
        : unit->GetPosition();

      const RUnitBlueprint* const blueprint = unit->GetBlueprint();
      const SFootprint* const footprint = blueprint->Physics.ResolvedFootprint;
      const float halfSizeX = footprint->mSizeX * 0.5f;
      const float halfSizeZ = footprint->mSizeZ * 0.5f;

      SOCellPos start{};
      start.x = static_cast<std::int16_t>(sourcePos.x - halfSizeX);
      start.z = static_cast<std::int16_t>(sourcePos.z - halfSizeZ);

      SOCellPos goal{};
      goal.x = static_cast<std::int16_t>(worldPos->x - halfSizeX);
      goal.z = static_cast<std::int16_t>(worldPos->z - halfSizeZ);

      sim->mContext.Update(worldPos, sizeof(*worldPos));
      sim->Logf("  mousePos=<%f,%f,%f>\n", worldPos->x, worldPos->y, worldPos->z);
      sim->mContext.Update(&start, sizeof(start));
      sim->Logf("  start=<%d,%d>\n", start.x, start.z);
      sim->mContext.Update(&goal, sizeof(goal));
      sim->Logf("  goal=<%d,%d>\n", goal.x, goal.z);

      previewFinder->ApplySearchEndpoints(footprint, start, goal);
    } else {
      const std::int32_t noUnitSentinel = -1;
      sim->mContext.Update(&noUnitSentinel, sizeof(noUnitSentinel));
      sim->Logf("  no unit\n");

      if (previewFinder) {
        previewFinder->ResetQueuedFootprint();

        boost::shared_ptr<PathPreviewFinder> clearedFinder{};
        focusArmy->SetUnknownSharedRef(reinterpret_cast<boost::SharedPtrRaw<void>*>(&clearedFinder));

        SArmyVectorWithMeta clearedPayload{};
        focusArmy->SetUnknownVectorWithMeta(&clearedPayload);
      }
    }

    return 0;
  }
}

namespace
{

  [[nodiscard]] bool TryParseArmyIndexArg(const std::string& text, std::size_t& outIndex) noexcept
  {
    if (text.empty()) {
      return false;
    }

    char* end = nullptr;
    const long parsed = std::strtol(text.c_str(), &end, 10);
    if (end == text.c_str() || (end && *end != '\0') || parsed < 0) {
      return false;
    }

    outIndex = static_cast<std::size_t>(parsed);
    return true;
  }

  template <typename THandler>
  void ForEachTargetArmyUnit(
    Sim* const sim, const CSimConCommand::ParsedCommandArgs* const commandArgs, THandler&& handler
  )
  {
    if (!sim || !sim->mEntityDB) {
      return;
    }

    const bool hasArmyFilters = commandArgs && commandArgs->size() > 1u;
    std::vector<std::size_t> targetArmyIndices;
    if (hasArmyFilters) {
      targetArmyIndices.reserve(commandArgs->size() - 1u);
      for (std::size_t argIndex = 1u; argIndex < commandArgs->size(); ++argIndex) {
        std::size_t parsedIndex = 0u;
        if (!TryParseArmyIndexArg((*commandArgs)[argIndex], parsedIndex)) {
          continue;
        }

        if (parsedIndex >= sim->mArmiesList.size()) {
          continue;
        }

        CArmyImpl* const army = sim->mArmiesList[parsedIndex];
        if (!army) {
          continue;
        }

        if (std::find(targetArmyIndices.begin(), targetArmyIndices.end(), parsedIndex) == targetArmyIndices.end()) {
          targetArmyIndices.push_back(parsedIndex);
        }
      }

      if (targetArmyIndices.empty()) {
        return;
      }
    }

    ForEachAllArmyUnit(sim, [&](Unit* const unit) {
      if (!unit || !unit->ArmyRef) {
        return;
      }

      if (hasArmyFilters) {
        const std::size_t armyIndex = static_cast<std::size_t>(unit->ArmyRef->mConstDat.mArmyIndex);
        if (std::find(targetArmyIndices.begin(), targetArmyIndices.end(), armyIndex) == targetArmyIndices.end()) {
          return;
        }
      }

      handler(*unit);
    });
  }

  enum class PurgeCategory : std::uint8_t
  {
    All = 0u,
    Projectile = 1u,
    Unit = 2u,
    Shield = 3u,
    Other = 4u,
    Prop = 5u,
    Unknown = 0xFFu
  };

  [[nodiscard]] PurgeCategory ParsePurgeCategory(const std::string& token)
  {
    const char* const text = token.c_str();
    if (gpg::STR_EqualsNoCase(text, "all") || gpg::STR_StartsWithNoCase(text, "entity")) {
      return PurgeCategory::All;
    }
    if (gpg::STR_StartsWithNoCase(text, "projectile")) {
      return PurgeCategory::Projectile;
    }
    if (gpg::STR_StartsWithNoCase(text, "unit")) {
      return PurgeCategory::Unit;
    }
    if (gpg::STR_StartsWithNoCase(text, "shield")) {
      return PurgeCategory::Shield;
    }
    if (gpg::STR_StartsWithNoCase(text, "other")) {
      return PurgeCategory::Other;
    }
    if (gpg::STR_StartsWithNoCase(text, "prop")) {
      return PurgeCategory::Prop;
    }
    return PurgeCategory::Unknown;
  }

  [[nodiscard]] bool EntityMatchesPurgeCategory(const Entity& entity, const PurgeCategory category)
  {
    Entity& mutableEntity = const_cast<Entity&>(entity);
    switch (category) {
    case PurgeCategory::All:
      return true;
    case PurgeCategory::Projectile:
      return mutableEntity.IsProjectile() != nullptr;
    case PurgeCategory::Unit:
      return mutableEntity.IsUnit() != nullptr;
    case PurgeCategory::Shield:
      return mutableEntity.IsShield() != nullptr;
    case PurgeCategory::Prop:
      return mutableEntity.IsProp() != nullptr;
    case PurgeCategory::Other:
      return mutableEntity.IsUnit() == nullptr && mutableEntity.IsProjectile() == nullptr &&
        mutableEntity.IsShield() == nullptr && mutableEntity.IsProp() == nullptr;
    default:
      return false;
    }
  }

  [[nodiscard]] bool EntityMatchesPurgeArmyFilter(const Entity& entity, const int armyFilter) noexcept
  {
    if (armyFilter < 0) {
      return true;
    }

    const auto armyIndex = static_cast<std::uint8_t>(armyFilter & 0xFF);
    return ExtractEntityIdSourceIndex(static_cast<std::uint32_t>(entity.id_)) == armyIndex;
  }

  [[nodiscard]] bool ShouldDestroyEntityForPurge(const Entity& entity) noexcept
  {
    return entity.mVarDat.mIsDead == 0u && entity.DestroyQueuedFlag == 0u && entity.mOnDestroyDispatched == 0u;
  }

  // Every walk below goes forward from the head's +0x04 slot, as `Sim::dbg`
  // (0x00651B00) does for both rings (`mov esi, [esi+4]`).
  [[nodiscard]] auto RegisteredDebugOverlayClasses()
  {
    return GetDbgOverlays().owners_member<RDebugOverlayClass, &RDebugOverlayClass::mOverlayClassLink>();
  }

  [[nodiscard]] gpg::RType* TryFindExactDebugOverlayType(const std::string& requestedName) noexcept
  {
    for (RDebugOverlayClass* const overlayClass : RegisteredDebugOverlayClasses()) {
      const char* const overlayName = overlayClass->mOverlayToken.c_str();
      if (overlayName != nullptr && gpg::STR_CompareNoCase(overlayName, requestedName.c_str()) == 0) {
        return overlayClass;
      }
    }

    return nullptr;
  }

  /**
   * Address: 0x00652060 (FUN_00652060, std::vector<const RDebugOverlayClass*>::push_back)
   *
   * What it does:
   * Per-T canonical-template-helper binding for the engine-instantiated
   * `std::vector<const RDebugOverlayClass*>::push_back(const&)` fast/slow-path
   * body (4-byte element stride: raw pointer). Rewiring the inline
   * `outMatches.push_back(overlayClass);` site through this helper preserves
   * the MSVC8 per-T template emission symbol shape.
   */
  void PushBackDebugOverlayClassPtrVector(
    std::vector<const RDebugOverlayClass*>& destination,
    const RDebugOverlayClass* const value)
  {
    destination.push_back(value);
  }

  void CollectPrefixDebugOverlayTypes(
    const std::string& requestedName,
    std::vector<const RDebugOverlayClass*>& outMatches
  )
  {
    for (const RDebugOverlayClass* const overlayClass : RegisteredDebugOverlayClasses()) {
      const char* const overlayName = overlayClass->mOverlayToken.c_str();
      if (overlayName != nullptr && gpg::STR_StartsWithNoCase(overlayName, requestedName.c_str())) {
        PushBackDebugOverlayClassPtrVector(outMatches, overlayClass);
      }
    }
  }

  void PrintAvailableDebugOverlayList(Sim& sim)
  {
    sim.Printf(kDbgAvailableOverlaysText);

    for (const RDebugOverlayClass* const overlayClass : RegisteredDebugOverlayClasses()) {
      sim.Printf("  %s - %s", overlayClass->GetName(), overlayClass->mOverlayDescription.c_str());
    }
  }

  [[nodiscard]] RDebugOverlay* FindDebugOverlayInstanceByType(Sim& sim, const gpg::RType& overlayType) noexcept
  {
    for (RDebugOverlay* const overlay : sim.mDebugOverlays.owners()) {
      if (overlay->GetClass() == &overlayType) {
        return overlay;
      }
    }

    return nullptr;
  }

  [[nodiscard]] RDebugOverlay* CreateDebugOverlayInstance(gpg::RType& overlayType)
  {
    return RDebugOverlay::NewPtr(overlayType);
  }

  void RemoveDebugOverlayInstance(RDebugOverlay& overlay)
  {
    // 0x00651E6D: the deleting destructor alone; `~RDebugOverlay` unlinks.
    delete &overlay;
  }
}

namespace moho
{
  [[nodiscard]] CUnitCommand* IssueFactoryCommandToSelectedUnits(
    Sim* const sim,
    const EntitySetTemplate<Unit>& selectedUnits,
    const SSTICommandIssueData& commandIssueData,
    const bool clearQueue
  )
  {
    return ::IssueFactoryCommandToSelectedUnitsImpl(sim, selectedUnits, commandIssueData, clearQueue);
  }

  [[nodiscard]] CUnitCommand* IssueCommandToSelectedUnits(
    Sim* const sim,
    EntitySetTemplate<Unit>& selectedUnits,
    const SSTICommandIssueData& commandIssueData,
    const bool clearQueue
  )
  {
    return ::IssueCommandToSelectedUnitsImpl(sim, selectedUnits, commandIssueData, clearQueue);
  }

  [[nodiscard]] RUnitBlueprint* ResolveUnitBlueprintFromLuaArgument(
    LuaPlus::LuaState* const state,
    const LuaPlus::LuaStackObject& blueprintObject,
    const char* const functionName
  )
  {
    return ::ResolveUnitBlueprintFromLuaArgumentImpl(state, blueprintObject, functionName);
  }
}



#include "SimSyncData.inl"

#include "SimSetup.inl"

#include "SimChecksum.inl"

#include "SimEntities.inl"

#include "SimDebugQueries.inl"

#include "SimShutdown.inl"

#include "SimFromLua.inl"
