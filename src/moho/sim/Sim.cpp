#include "moho/lua/ScrLuaUserData.h"
#include "moho/sim/SimPrivate2.h"

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
  [[nodiscard]] msvc8::string BuildMd5TraceIndent(const std::size_t indentDepth)
  {
    msvc8::string indent{};
    (void)indent.resize(indentDepth * 2u, ' ');
    return indent;
  }

  void PrintMd5TraceLexical(FILE* const traceFile, const std::size_t indentDepth, const msvc8::string& lexical)
  {
    if (traceFile == nullptr) {
      return;
    }

    const msvc8::string indent = BuildMd5TraceIndent(indentDepth);
    std::fprintf(traceFile, "%s%s\n", indent.c_str(), lexical.c_str());
  }

  void PrintMd5TraceFieldPrefix(FILE* const traceFile, const std::size_t indentDepth, const char* const fieldName)
  {
    if (traceFile == nullptr) {
      return;
    }

    const msvc8::string indent = BuildMd5TraceIndent(indentDepth);
    std::fprintf(traceFile, "%s%s:\n", indent.c_str(), fieldName != nullptr ? fieldName : "");
  }

  void PrintMd5TraceIndexPrefix(FILE* const traceFile, const std::size_t indentDepth, const std::uint32_t index)
  {
    if (traceFile == nullptr) {
      return;
    }

    const msvc8::string indent = BuildMd5TraceIndent(indentDepth);
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

  if (refType == gpg::RTypeOf<msvc8::string>()) {
    if (traceFile != nullptr) {
      PrintMd5TraceLexical(traceFile, depth, ref.GetLexical());
    }
    const auto& stringValue = *static_cast<const msvc8::string*>(ref.mObj);
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
      const msvc8::string indent = BuildMd5TraceIndent(depth);
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

  [[nodiscard]] bool ParseRectFromLuaArguments(
    LuaPlus::LuaState* const state,
    const char* const helpText,
    gpg::Rect2f& outRect
  )
  {
    if (!state || !state->m_state) {
      return false;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount < 1 || argumentCount > 4) {
      LuaPlus::LuaState::Error(state, "%s\n  expected between %d and %d args, but got %d", helpText, 1, 4, argumentCount);
    }

    if (argumentCount == 1) {
      const LuaPlus::LuaObject rectObject(LuaPlus::LuaStackObject(state, 1));
      outRect = SCR_FromLuaCopy<gpg::Rect2f>(rectObject);
      return true;
    }

    LuaPlus::LuaStackObject x0Arg(state, 1);
    if (lua_type(rawState, 1) != LUA_TNUMBER) {
      x0Arg.TypeError("number");
    }
    outRect.x0 = static_cast<float>(lua_tonumber(rawState, 1));

    LuaPlus::LuaStackObject z0Arg(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      z0Arg.TypeError("number");
    }
    outRect.z0 = static_cast<float>(lua_tonumber(rawState, 2));

    LuaPlus::LuaStackObject x1Arg(state, 3);
    if (lua_type(rawState, 3) != LUA_TNUMBER) {
      x1Arg.TypeError("number");
    }
    outRect.x1 = static_cast<float>(lua_tonumber(rawState, 3));

    LuaPlus::LuaStackObject z1Arg(state, 4);
    if (lua_type(rawState, 4) != LUA_TNUMBER) {
      z1Arg.TypeError("number");
    }
    outRect.z1 = static_cast<float>(lua_tonumber(rawState, 4));
    return true;
  }

  [[nodiscard]] bool IsEntityPositionInsideRect(const Entity* const entity, const gpg::Rect2f& rect) noexcept
  {
    if (entity == nullptr) {
      return false;
    }

    const Wm3::Vec3f& position = entity->GetPositionWm3();
    return rect.Contains(position.x, position.z);
  }

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



  [[nodiscard]] IUnit* ResolveIUnitBridge(UserUnit* const unit) noexcept
  {
    return unit ? static_cast<IUnit*>(unit) : nullptr;
  }

  [[nodiscard]] const IUnit* ResolveIUnitBridge(const UserUnit* const unit) noexcept
  {
    return unit ? static_cast<const IUnit*>(unit) : nullptr;
  }


  [[nodiscard]] UserEntity*
  FindUserSessionEntityById(CWldSession* const session, const std::int32_t entityId) noexcept
  {
    if (session == nullptr) {
      return nullptr;
    }

    return session->LookupEntityId(entityId);
  }







  [[nodiscard]] EntityCategorySet* ResolveEntityCategorySetFromLuaObject(const LuaPlus::LuaObject& object)
  {
    LuaPlus::LuaObject payload(object);
    if (payload.IsTable()) {
      payload = moho::SCR_GetLuaTableField(payload.GetActiveState(), payload, "_c_object");
    }

    if (!payload.IsUserData()) {
      return nullptr;
    }

    const gpg::RRef userDataRef = moho::SCR_UserDataRef(payload);
    if (!userDataRef.mObj) {
      return nullptr;
    }

    if (gpg::RType* const expectedType = gpg::RTypeOf<EntityCategorySet>(); expectedType != nullptr) {
      const gpg::RRef upcast = gpg::REF_UpcastPtr(userDataRef, expectedType);
      if (upcast.mObj != nullptr) {
        return static_cast<EntityCategorySet*>(upcast.mObj);
      }
    }

    const char* const typeName = userDataRef.GetTypeName();
    if (typeName != nullptr
        && (std::strstr(typeName, "EntityCategory") != nullptr || std::strstr(typeName, "BVSet") != nullptr)) {
      return static_cast<EntityCategorySet*>(userDataRef.mObj);
    }

    return nullptr;
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

  [[nodiscard]]
  BVIntSet& AsBitSet(SimSubRes3& slot) noexcept
  {
    return *reinterpret_cast<BVIntSet*>(&slot);
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
  gpg::RType* FindRTypeByNameAny(const std::initializer_list<const char*>& names)
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

  gpg::RType* RequireRTypeByNameAny(const std::initializer_list<const char*>& names)
  {
    gpg::RType* type = FindRTypeByNameAny(names);
    GPG_ASSERT(type != nullptr);
    return type;
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

  void FormatCallStack(msvc8::string* outText, const int frameCount, const std::uintptr_t* frames)
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
  [[nodiscard]] const msvc8::vector<WeakPtr<CUnitCommand>>* PathPreviewCommandList(Unit& unit)
  {
    if (IAiBuilder* const builder = unit.AiBuilder; builder != nullptr) {
      const msvc8::vector<WeakPtr<CUnitCommand>>& factoryQueue = builder->BuilderGetFactoryCommandQueue();
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
    if (const msvc8::vector<WeakPtr<CUnitCommand>>* const commands = PathPreviewCommandList(*unit); commands != nullptr) {
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
[[nodiscard]] static msvc8::string FormatBeatLogFilePath(const msvc8::string& logFilePrefix, const int beat)
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
    const msvc8::string staleLogPath = mDesyncLogLines.front();
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
  [[nodiscard]] std::size_t DebugVectorSizeThunk(const msvc8::vector<TDebugRecord>* const vec) noexcept
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
 * Out-of-line `msvc8::vector<SDebugWorldText>::size()` specialization
 * thunk used by `CDebugCanvas::worldText`. Returns zero when the
 * vector's `first_` pointer is still null, matching the binary's
 * early-out; otherwise returns `(last_ - first_) / sizeof(SDebugWorldText)`
 * (element size `0x30`).
 */
std::size_t GetDebugWorldTextCount(const msvc8::vector<SDebugWorldText>* const worldText) noexcept
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
 * Out-of-line `msvc8::vector<SDebugScreenText>::size()` specialization
 * thunk (element size `0x48`). Same shape as
 * `GetDebugWorldTextCount`.
 */
std::size_t GetDebugScreenTextCount(const msvc8::vector<SDebugScreenText>* const screenText) noexcept
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
 * Out-of-line `msvc8::vector<SDebugDecal>::size()` specialization
 * thunk (element size `0x34`). Same shape as
 * `GetDebugWorldTextCount`.
 */
std::size_t GetDebugDecalCount(const msvc8::vector<SDebugDecal>* const decals) noexcept
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
  msvc8::vector<msvc8::string> synclogArgs;
  if (CFG_GetArgOption("/synclog", 1u, &synclogArgs) && !synclogArgs.empty()) {
    const msvc8::string& synclogDir = synclogArgs.front();
    ::CreateDirectoryA(synclogDir.c_str(), nullptr);

    const msvc8::string filenamePrefix = LOG_GenerateFilenamePrefix();
    const msvc8::string prefixWithSlash = synclogDir + msvc8::string("/");
    mLogFilePrefix.assign(prefixWithSlash + filenamePrefix, 0, msvc8::string::npos);

    ::CreateDirectoryA(mLogFilePrefix.c_str(), nullptr);
    (void)mLogFilePrefix.append("/", 1u);

    const msvc8::string beatFile = FormatBeatLogFilePath(mLogFilePrefix, static_cast<int>(mCurBeat));
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

  // Build a fresh Lua state, bind this Sim as the global userdata, and run the
  // registered core + sim init form sets.
  {
    auto* const newState = new LuaPlus::LuaState(LuaPlus::LuaState::LIB_BASE);
    LuaPlus::LuaState* const previousState = mLuaState;
    mLuaState = newState;
    if (previousState) {
      delete previousState;
    }
  }
  lua::NameLuaVm(mLuaState->m_state, "Sim"); // diagnostics label only
  lua_setglobaluserdata(mLuaState->m_state, this);

  if (CScrLuaInitFormSet* const coreSet = SCR_FindLuaInitFormSet("Core"); coreSet != nullptr) {
    coreSet->RunInits(mLuaState);
  }
  if (CScrLuaInitFormSet* const simSet = SCR_FindLuaInitFormSet("Sim"); simSet != nullptr) {
    simSet->RunInits(mLuaState);
  }
  if (SCR_IsDebugWindowActive()) {
    lua_sethook(mLuaState->m_state, &moho::DebugLuaHook, 4, 0);
  }
  mLuaState->m_luaTask = reinterpret_cast<CLuaTask*>(&mDiskWatcherTaskStage);

  {
    gpg::LogScopeEntry luaBpScope(msvc8::string("MEM: %i bytes LUABP"));
    mRules->ExportToLuaState(mLuaState);
    luaBpScope.Emit();
  }
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
    gpg::LogScopeEntry ogridScope(msvc8::string("MEM: %i bytes OGRID"));
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
    // when there is one, gets the same text.
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

  msvc8::vector<LuaPlus::LuaObject> armySetupObjects{};
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
    const msvc8::string armyName = armyNameObject.IsString()
      ? msvc8::string(armyNameObject.GetString())
      : gpg::STR_Printf("ARMY_%d", static_cast<int>(armyIndex + 1));
    armySetupTable.SetObject(armyName.c_str(), armySetup);
  }
  scenarioInfo.SetObject("ArmySetup", armySetupTable);
  mLuaState->GetGlobals().SetObject("ScenarioInfo", scenarioInfo);

  // SetupSession() Lua callback. Only the call is guarded (runtime_error,
  // FuncInfo 0x00F29640 try state 12, handler 0x00744414).
  {
    const LuaPlus::LuaFunction<> setupSession(mLuaState->GetGlobal("SetupSession"));
    try {
      setupSession.Call();
    } catch (const msvc8::runtime_error& error) {
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

  const msvc8::string message =
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
    const msvc8::string logFile = mDesyncLogLines.front();
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
  const msvc8::vector<ArmyLaunchInfo>& launchInfo,
  const msvc8::vector<LuaPlus::LuaObject>& armySetupObjects,
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

/**
 * Address: 0x00746820 (FUN_00746820, ?GetParticleBuffer@Sim@Moho@@QAEPAUSParticleBuffer@2@XZ)
 *
 * What it does:
 * Returns the shared particle buffer, allocating and binding it lazily on
 * first use.
 */
SParticleBuffer* Sim::GetParticleBuffer()
{
  // Engine addition (sim_ParallelEffects): an effect tick on a sim worker appends to its chunk's
  // buffer, which CEffectManagerImpl::TickParallel then commits here in list order.
  if (SParticleBuffer* const chunkBuffer = EffectTickChunkParticleBuffer(); chunkBuffer != nullptr) {
    return chunkBuffer;
  }

  if (!mParticleBuffer) {
    (void)AssignSharedParticleBufferFromRaw(&mParticleBuffer, new SParticleBuffer());
  }

  return mParticleBuffer.get();
}

/**
 * Address: 0x0062CBD0 (FUN_0062CBD0, ?CenterOfMap@Sim@Moho@@QBE?AV?$Vector3@M@Wm3@@XZ)
 *
 * What it does:
 * Computes the center of the current map in terrain grid coordinates from
 * the backing heightfield dimensions and returns a zero-elevation vector.
 */
Wm3::Vec3f Sim::CenterOfMap() const
{
  const CHeightField* const field = mMapData->GetHeightField();

  Wm3::Vec3f center{};
  center.x = static_cast<float>(field->width - 1) * 0.5f;
  center.y = 0.0f;
  center.z = static_cast<float>(field->height - 1) * 0.5f;
  return center;
}

LuaPlus::LuaState* Sim::GetLuaState() const noexcept
{
  return mLuaState;
}

/**
 * Address: 0x00747180 (FUN_00747180, Moho::Sim::CheatsEnabled)
 *
 * What it does:
 * Logs the attempt, tracks its command source, hashes the enabled flag,
 * and returns whether the current simulation permits cheats.
 */
bool Sim::CheatsEnabled()
{
  if (mCheatsEnabled) {
    if (IsSimReportCheatsEnabled()) {
      gpg::Warnf("%s is cheating!", GetCurrentCommandSourceName());
    }
  } else {
    gpg::Warnf("%s is trying to cheat!", GetCurrentCommandSourceName());
  }

  if (IsSimDebugCheatsEnabled()) {
    // 0x00747230/0x0074723D refer to the same array after stack-argument pushes.
    std::uintptr_t frames[16]{};
    msvc8::string callstackText{};
    const int frameCount = GetCallStackFrames(frames);
    FormatCallStack(&callstackText, frameCount, frames);
    Logf("%s", callstackText.c_str());
  }

  if (mCurCommandSource != kInvalidCommandSource) {
    const int cheaterSource = static_cast<int>(mCurCommandSource);
    const auto it = std::find(mCheaters.begin(), mCheaters.end(), cheaterSource);
    if (it == mCheaters.end()) {
      mCheaters.push_back(cheaterSource);
    }
  }

  mContext.Update(&mCheatsEnabled, 1u);
  return mCheatsEnabled;
}

/**
 * Address: 0x00747320 (FUN_00747320, ?OkayToMessWith@Sim@Moho@@QAE_NPAVSimArmy@2@@Z)
 *
 * What it does:
 * Validates whether current command source may issue actions on one army, with
 * cheat fallback when source authorization fails.
 */
bool Sim::OkayToMessWith(SimArmy* army)
{
  auto* armyImpl = static_cast<CArmyImpl*>(army);
  if (!armyImpl) {
    return CheatsEnabled();
  }

  if (armyImpl->mVarDat.mIsOutOfGame) {
    return false;
  }

  const uint32_t sourceId = static_cast<uint32_t>(mCurCommandSource);
  if (sourceId != kInvalidCommandSource && armyImpl->mVarDat.mValidCommandSources.Contains(sourceId)) {
    return true;
  }

  return CheatsEnabled();
}

/**
 * Address: 0x00747360 (FUN_00747360, ?OkayToMessWith@Sim@Moho@@QAE_NPAVEntity@2@@Z)
 *
 * What it does:
 * Resolves entity owner army and delegates permission checks to army-level policy.
 */
bool Sim::OkayToMessWith(Entity* entity)
{
  return OkayToMessWith(entity ? static_cast<SimArmy*>(entity->ArmyRef) : nullptr);
}

/**
 * Address: 0x007473B0 (FUN_007473B0, ?OkayToMessWith@Sim@Moho@@QAE_NPAVCUnitCommand@2@@Z)
 *
 * What it does:
 * Checks each command unit-set entry against command-source permissions and
 * requires cheats for unusable or unauthorized entries.
 */
bool Sim::OkayToMessWith(CUnitCommand* cmd)
{
  if (!cmd) {
    return false;
  }

  Entity** unitSetIt = cmd->mUnitSet.mVec.begin();
  Entity** unitSetEnd = cmd->mUnitSet.mVec.end();
  if (unitSetIt == unitSetEnd) {
    return true;
  }

  while (unitSetIt != unitSetEnd) {
    Unit* const unit = static_cast<Unit*>(*unitSetIt);
    if (unit == nullptr) {
      if (!CheatsEnabled()) {
        return false;
      }
      ++unitSetIt;
      continue;
    }

    Entity* entity = unit;
    if (!OkayToMessWith(entity)) {
      return false;
    }

    ++unitSetIt;
  }

  return true;
}

/**
 * Address: 0x00743120 (FUN_00743120, Moho::SDesyncInfo::SDesyncInfo)
 *
 * What it does:
 * Initializes one desync entry from beat/army metadata and both checksum
 * digest payloads.
 */
SDesyncInfo::SDesyncInfo(const std::int32_t beatValue, const std::int32_t armyValue, const gpg::MD5Digest& expectedHash, const gpg::MD5Digest& remoteHash)
  : beat(beatValue)
  , army(armyValue)
  , hash1(expectedHash)
  , hash2(remoteHash)
{}

/**
 * Address: 0x007487C0 (FUN_007487C0, ?VerifyChecksum@Sim@Moho@@UAEXABVMD5Digest@gpg@@H@Z)
 *
 * What it does:
 * Validates one remote beat checksum against the local rolling hash ring,
 * records a desync entry on mismatch, and clears the cached desync log list.
 */
void Sim::VerifyChecksum(const gpg::MD5Digest& checksum, const CSeqNo beat)
{
  if (mCurCommandSource == kInvalidCommandSource) {
    return;
  }

  const int oldestBeat = static_cast<int>(mCurBeat) - 128;
  if (beat < oldestBeat) {
    Logf(
      "Ignoring verify of beat %d because that was %d beats ago and we only have data for %d beats.",
      beat,
      static_cast<int>(mCurBeat) - beat,
      128
    );
    return;
  }

  if (beat >= static_cast<int>(mCurBeat)) {
    Logf("Ignoring verify of beat %d because it is in the future.", beat);
    return;
  }

  gpg::MD5Digest* expected = &mSimHashes[beat & 0x7F];

  // Engine addition (issue #216): every compared report, matching or not, so a dump shows who
  // agrees with whom.
  if (CDesyncRecorder* const recorder = CDesyncRecorder::For(this)) {
    recorder->NoteChecksum(*this, beat, mCurCommandSource, checksum, *expected);
  }

  if (std::memcmp(expected, &checksum, sizeof(gpg::MD5Digest)) == 0) {
    return;
  }

  const SDesyncInfo desync(beat, mCurCommandSource, *expected, checksum);
  mDesyncs.push_back(desync);

  const msvc8::string incomingHash = checksum.ToString();
  const msvc8::string simHash = expected->ToString();

  gpg::Warnf(
    "Checksum for beat %d mismatched: %s (sim) != %s (%s).",
    beat,
    simHash.c_str(),
    incomingHash.c_str(),
    GetCurrentCommandSourceName()
  );

  mIsDesyncFree = false;
  mDesyncLogLines.clear();
}

/**
 * Address: 0x00748960 (FUN_00748960, ?RequestPause@Sim@Moho@@UAEXXZ)
 */
void Sim::RequestPause()
{
  if (mPausedByCommandSource != -1) {
    return;
  }

  if (mCurCommandSource == kInvalidCommandSource ||
      static_cast<std::size_t>(mCurCommandSource) >= mCommandSources.size()) {
    return;
  }

  // Three-way, not two: only a timeout budget of exactly zero refuses the
  // pause. A negative budget means unlimited, and pauses without spending
  // anything -- which is what every local player has, since SessionStartup
  // seeds `mTimeouts = -1`.
  //
  //   0x00748985  test edx, edx
  //   0x00748987  jz   locret_74899A       ; == 0, refuse
  //   0x00748989  jle  short loc_74898E    ; <  0, skip the decrement
  //   0x0074898B  add  dword ptr [eax], -1 ; >  0, spend one
  //   0x0074898E  mov  [ecx+8E0h], eax     ; both surviving paths pause
  int& timeouts = mCommandSources[mCurCommandSource].mTimeouts;
  if (timeouts == 0) {
    return;
  }

  if (timeouts > 0) {
    --timeouts;
  }
  mPausedByCommandSource = mCurCommandSource;
}

/**
 * Address: 0x007489A0 (FUN_007489A0, ?Resume@Sim@Moho@@UAEXXZ)
 */
void Sim::Resume()
{
  if (mCurCommandSource != kInvalidCommandSource) {
    mPausedByCommandSource = -1;
  }
}

/**
 * Address: 0x007489C0 (FUN_007489C0, ?SingleStep@Sim@Moho@@UAEXXZ)
 */
void Sim::SingleStep()
{
  if (mPausedByCommandSource != -1 && mCurCommandSource != kInvalidCommandSource) {
    mSingleStep = true;
  }
}

/**
 * Address: 0x007489E0 (FUN_007489E0)
 *
 * Moho::SUnitConstructionParams const &, bool
 *
 * IDA signature:
 * Moho::Unit *__userpurge Moho::Sim::CreateUnit@<eax>(Moho::SUnitConstructionParams *params@<esi>, char doCallback);
 *
 * What it does:
 * Applies army unit-cap checks and creates a Unit when caps allow.
 */
Unit* Sim::CreateUnit(const SUnitConstructionParams& params, const bool doCallback)
{
  if (!params.mArmy || !params.mBlueprint) {
    return nullptr;
  }

  if (!params.mArmy->IgnoreUnitCap()) {
    const float unitCap = params.mArmy->GetUnitCap();
    if (params.mArmy->GetArmyUnitCostTotal() + params.mBlueprint->General.CapCost > unitCap) {
      if (doCallback) {
        if (CAiBrain* const brain = params.mArmy->GetArmyBrain()) {
          brain->CallbackStr("OnUnitCapLimitReached");
        }
      }
      return nullptr;
    }
  }

  return new Unit(params);
}

Unit* Sim::CreateUnitForScript(const SUnitConstructionParams& params, const bool doCallback)
{
  return CreateUnit(params, doCallback);
}

/**
 * The inlined construction in `cfunc_CreateInitialArmyUnitL` (0x00709340); see
 * the declaration in Sim.h for the evidence that no unit-cap gate stands in
 * front of it.
 */
Unit* Sim::CreateInitialArmyUnit(const SUnitConstructionParams& params)
{
  if (!params.mArmy || !params.mBlueprint) {
    return nullptr;
  }

  return new (std::nothrow) Unit(params);
}

/**
 * Address: 0x007468E0 (FUN_007468E0, ?TransferUnit@Sim@Moho@@QAEPAVUnit@2@PAV32@PAVSimArmy@2@@Z)
 * Mangled: ?TransferUnit@Sim@Moho@@QAEPAVUnit@2@PAV32@PAVSimArmy@2@@Z
 *
 * IDA signature:
 * Moho::Unit *__thiscall Moho::Sim::TransferUnit(Moho::Sim *this, Moho::Unit *unit, Moho::CArmyImpl *newArmy);
 *
 * What it does:
 * Recursively transfers `unit` (plus its transport-carried cargo and attached
 * child units) to `newArmy`. Drains the transport storage, detaches child units
 * (splicing each child's `TransportedByRef` weak link out of its chain),
 * recursively transfers cargo and children, constructs a replacement Unit owned
 * by `newArmy`, migrates pose / health / custom name, re-populates transport
 * storage, re-attaches the transferred children, then destroys the original.
 * Returns the replacement Unit, or nullptr when the source is dead/destroy-queued
 * or the new army is over its unit cap.
 */
Unit* Sim::TransferUnit(Unit* const unit, CArmyImpl* const newArmy)
{
  if (!unit || unit->IsDead() || unit->DestroyQueued()) {
    return nullptr;
  }

  // Cargo transferred out of this unit's transport storage (parallel to
  // transferredCargo below), and the children transferred after detach.
  msvc8::vector<Unit*> transferredCargo;    // v57 (result of recursive transfer of stored units)
  msvc8::vector<Unit*> transferredChildren; // v56 (result of recursive transfer of attached units)
  msvc8::vector<Unit*> detachedChildren;    // v63 (mobile attached units, pre-detach)
  msvc8::vector<int> childParentBones;      // v65 (each child's mParentBoneIndex, captured pre-detach)
  msvc8::vector<int> childChildBones;       // v64 (each child's mChildBoneIndex, captured pre-detach)

  // --- Phase A: drain transport storage and recursively transfer the cargo ---
  if (IAiTransport* const transport = unit->AiTransport) {
    msvc8::vector<Unit*> storedCargo; // a2a

    EntitySetTemplate<Unit> storedUnits = transport->TransportGetStoredUnits();
    for (Unit* const storedUnit : storedUnits) {
      VTransform storedTransform{};
      storedTransform.orient_.w = 1.0f; // scratch out-transform (identity), receives the removed pose
      storedTransform.orient_.x = 0.0f;
      storedTransform.orient_.y = 0.0f;
      storedTransform.orient_.z = 0.0f;
      storedTransform.pos_.x = 0.0f;
      storedTransform.pos_.y = 0.0f;
      storedTransform.pos_.z = 0.0f;
      unit->AiTransport->TransportRemoveFromStorage(storedUnit, storedTransform);
      storedCargo.push_back(storedUnit);
    }

    for (Unit* const storedUnit : storedCargo) {
      Unit* const transferred = TransferUnit(storedUnit, newArmy);
      transferredCargo.push_back(transferred);
    }

    // 0x007469C0 jumps straight to the replacement unit (0x00746CC2) when
    // there is no transport, so the attached-child capture, detach and
    // transfer below run only for units that have one.
    // --- Phase B: capture mobile attached child units and their attach bones ---
    const msvc8::vector<Entity*>& attached = unit->GetAttachedEntities();
    for (Entity* const attachedEntity : attached) {
      if (!attachedEntity) {
        continue;
      }
      Unit* const child = attachedEntity->IsUnit();
      if (!child || !attachedEntity->IsMobile() || attachedEntity->mVarDat.mIsDead || attachedEntity->DestroyQueuedFlag) {
        continue;
      }
      detachedChildren.push_back(attachedEntity->IsUnit());
      childChildBones.push_back(attachedEntity->mAttachInfo.mChildBoneIndex);
      childParentBones.push_back(attachedEntity->mAttachInfo.mParentBoneIndex);
    }

    // --- Phase C: detach each captured child and unlink its transport weak-ref ---
    for (Unit* const child : detachedChildren) {
      child->DetachFrom(unit, true);
      child->TransportedByRef.UnlinkFromOwnerChain();
    }

    // --- Phase D: recursively transfer the detached children ---
    for (Unit* const child : detachedChildren) {
      Unit* const transferred = TransferUnit(child, newArmy);
      transferredChildren.push_back(transferred);
    }
  }

  // --- Phase F: construct the replacement unit under the new army ---
  const ELayer sourceLayer = unit->mVarDat.mLayerMask;
  const VTransform sourceTransform = unit->GetTransform();
  const RUnitBlueprint* const sourceBlueprint = unit->GetBlueprint();

  SUnitConstructionParams params(
    static_cast<std::int32_t>(sourceLayer),
    sourceTransform,
    newArmy,
    sourceBlueprint,
    nullptr,
    true
  );
  // The transfer path forces fixed-elevation on unconditionally (the layer==0 gate
  // that the shared ctor applies is not present in the shipped transfer code).
  params.mFixElevation = 1;

  Unit* const newUnit = CreateUnit(params, false);
  if (!newUnit) {
    // --- Phase H: creation failed (unit cap) — notify the army's brain script ---
    if (!newArmy->IgnoreUnitCap()) {
      if (CAiBrain* const brain = newArmy->GetArmyBrain()) {
        brain->RunScript("OnFailedUnitTransfer");
      }
    }
    return nullptr;
  }

  // --- Phase G: migrate pose, health, and custom name onto the replacement ---
  newUnit->SetPoses(unit->AniActor->GetPriorPoseShared(), unit->AniActor->GetPoseShared());

  if (unit->mVarDat.mHealth != newUnit->mVarDat.mHealth) {
    newUnit->SetHealth(unit->mVarDat.mHealth);
  }

  newUnit->SetCustomName(unit->GetCustomName());

  // --- Phase G (transport): re-populate storage and re-attach children ---
  if (newUnit->AiTransport) {
    for (Unit* const cargo : transferredCargo) {
      if (cargo) {
        newUnit->AiTransport->TransportAddToStorage(cargo);
      }
    }

    const std::size_t childCount = transferredChildren.size();
    for (std::size_t i = 0; i < childCount; ++i) {
      Unit* const child = transferredChildren[i];
      if (!child) {
        continue;
      }

      const int parentBoneIndex = childParentBones[i];
      const int childBoneIndex = childChildBones[i];

      // Re-attach the transferred child to the replacement unit. The attach payload
      // reuses the captured bone indices with an identity relative transform.
      SEntAttachInfo attachInfo(newUnit, childBoneIndex, parentBoneIndex, VTransform{});

      child->AttachTo(attachInfo);
      // Detach the temporary attach node from the replacement's weak chain; the
      // durable linkage now lives in the child's own mAttachInfo.
      attachInfo.mAttachTargetWeak.UnlinkFromOwnerChain();

      newUnit->AiTransport->TransportAssignSlot(child, parentBoneIndex);

      if (newUnit->AiTransport) {
        // Resolve the attach bone's name and fire the child's OnTransportAttach
        // script, matching the transport attach path.
        const boost::shared_ptr<const CAniSkel> skeleton = newUnit->AniActor->GetSkeleton();
        const CAniSkel* const skel = skeleton.get();
        const char* boneName = nullptr;
        if (skel) {
          const SAniSkelBone* const bones = skel->mBones.begin();
          const std::size_t boneCount = static_cast<std::size_t>(skel->mBones.end() - bones);
          if (bones && static_cast<std::size_t>(parentBoneIndex) < boneCount) {
            boneName = bones[static_cast<std::size_t>(parentBoneIndex)].mBoneName;
          }
        }
        if (boneName) {
          newUnit->RunScriptStringUnit("OnTransportAttach", boneName, child);
        }
      }
    }
  }

  // --- Phase G (finalize): clear source footprint occupancy for static units ---
  if (!newUnit->IsMobile()) {
    unit->FootprintDown = false;
  }

  unit->Destroy();
  return newUnit;
}

/**
 * Address: 0x00748AA0 (FUN_00748AA0)
 *
 * unsigned int, Moho::RResId const &, Moho::SCoordsVec2 const &, float
 *
 * What it does:
 * Cheat-gated unit creation entrypoint; resolves unit blueprint, builds construction params,
 * and forwards into Sim::CreateUnit(const SUnitConstructionParams&, bool).
 */
void Sim::CreateUnit(const uint32_t armyIndex, const RResId& blueprintId, const SCoordsVec2& pos, const float heading)
{
  if (!CheatsEnabled()) {
    return;
  }

  if (armyIndex >= mArmiesList.size()) {
    return;
  }

  CArmyImpl* const army = mArmiesList[armyIndex];
  if (!army || army->mVarDat.mIsOutOfGame) {
    return;
  }

  const RUnitBlueprint* const blueprint = ResolveUnitBlueprint(mRules, blueprintId);
  if (!blueprint) {
    Logf(
      "CreateUnit: unresolved blueprint '%s' requested by %s.\n",
      blueprintId.name.c_str(),
      GetCurrentCommandSourceName()
    );
    return;
  }

  SUnitConstructionParams params(
    0,
    BuildUnitSpawnTransform(pos, heading),
    army,
    blueprint,
    nullptr,
    true
  );
  // 0x00748BE7 clears only the elevation byte (+0x25). mUseLayerOverride stays 1
  // from the ctor, so the Unit ctor keeps the requested heading instead of
  // resetting it (or drawing a random yaw for SpawnRandomRotation blueprints).
  params.mFixElevation = 0;

  (void)CreateUnit(params, true);
}

/**
 * Address: 0x00748C00 (FUN_00748C00)
 *
 * What it does:
 * `ICommandSink` slot 7, a cheat command: creates prop `blueprint` at `loc`,
 * unrotated. Formerly split into a free `SpawnPropByBlueprint`, which added a
 * null/empty-blueprint early-out the binary does not have.
 */
void Sim::CreateProp(const char* const blueprint, const Wm3::Vec3f& loc)
{
  if (!CheatsEnabled()) {
    return;
  }

  // 0x00748C15..0x00748C5D: identity orientation, then the position.
  VTransform transform;
  transform.pos_ = loc;
  (void)PROP_Create(this, transform, blueprint);
}

/**
 * Address: 0x00748C80 (FUN_00748C80)
 *
 * What it does:
 * Looks up an entity by id, validates command-source ownership, then
 * destroys the entity through `Entity::Destroy()`.
 */
void Sim::DestroyEntity(const EntId entityId)
{
  Entity* entity = FindEntityById(mEntityDB, entityId);
  if (!entity || !OkayToMessWith(entity)) {
    return;
  }

  entity->Destroy();
}

/**
 * Address: 0x00748CD0 (FUN_00748CD0, ?WarpEntity@Sim@Moho@@UAEXVEntId@2@ABVVTransform@2@@Z)
 */
void Sim::WarpEntity(const EntId entityId, const VTransform& transform)
{
  if (!CheatsEnabled()) {
    return;
  }

  Entity* entity = FindEntityById(mEntityDB, entityId);
  if (!entity) {
    return;
  }

  ApplyWarpTransform(entity, transform);
}

/**
 * Address: 0x00748D50 (FUN_00748D50, ?ProcessInfoPair@Sim@Moho@@UAEXVEntId@2@VStrArg@gpg@@1@Z)
 *
 * What it does:
 * Applies one UI/info key-value command lane to a controllable live unit.
 */
void Sim::ProcessInfoPair(const EntId entityId, const gpg::StrArg key, const gpg::StrArg val)
{
  Entity* const entity = FindEntityById(mEntityDB, entityId);
  if (!entity || !OkayToMessWith(entity) || entity->mVarDat.mIsDead != 0u) {
    return;
  }

  if (gpg::STR_EqualsNoCase(key, "SetFireState")) {
    Unit* const unit = entity->IsUnit();
    if (!unit) {
      return;
    }

    EFireState fireState = static_cast<EFireState>(0);
    gpg::RRef fireStateRef{};
    fireStateRef = gpg::MakeRRef<moho::EFireState>(&fireState);
    (void)fireStateRef.SetLexical(val);
    if (static_cast<std::uint32_t>(fireState) <= 2u) {
      unit->SetFireState(static_cast<int>(fireState));
    }

    return;
  }

  if (gpg::STR_EqualsNoCase(key, "SetAutoMode")) {
    Unit* const unit = entity->IsUnit();
    bool value = false;
    if (unit && ParseBoolLiteral(val, value)) {
      unit->SetAutoMode(value);
    }

    return;
  }

  if (gpg::STR_EqualsNoCase(key, "SetAutoSurfaceMode")) {
    Unit* const unit = entity->IsUnit();
    bool value = false;
    if (unit && ParseBoolLiteral(val, value)) {
      unit->SetAutoSurfaceMode(value);
    }

    return;
  }

  if (gpg::STR_EqualsNoCase(key, "SetRepeatQueue")) {
    Unit* const unit = entity->IsUnit();
    bool value = false;
    if (unit && ParseBoolLiteral(val, value)) {
      unit->SetRepeatQueue(value);
    }

    return;
  }

  if (gpg::STR_EqualsNoCase(key, "SetPaused")) {
    Unit* const unit = entity->IsUnit();
    bool value = false;
    if (unit && ParseBoolLiteral(val, value)) {
      unit->SetPaused(value);
    }

    return;
  }

  if (gpg::STR_EqualsNoCase(key, "SiloBuildTactical")) {
    Unit* const unit = entity->IsUnit();
    if (unit && gpg::STR_EqualsNoCase(val, "add")) {
      QueueSiloBuildRequest(unit, 0);
    }

    return;
  }

  if (gpg::STR_EqualsNoCase(key, "SiloBuildNuke")) {
    Unit* const unit = entity->IsUnit();
    if (unit && gpg::STR_EqualsNoCase(val, "add")) {
      QueueSiloBuildRequest(unit, 1);
    }

    return;
  }

  if (gpg::STR_EqualsNoCase(key, "CustomName")) {
    Unit* const unit = entity->IsUnit();
    if (unit) {
      unit->SetCustomName(std::string(val ? val : ""));
    }

    return;
  }

  if (gpg::STR_EqualsNoCase(key, "ToggleScriptBit")) {
    Unit* const unit = entity->IsUnit();
    if (unit) {
      unit->ToggleScriptBit(std::atoi(val));
    }

    return;
  }

  if (gpg::STR_EqualsNoCase(key, "PlayNoStagingPlatformsVO")) {
    Unit* const unit = entity->IsUnit();
    if (!unit) {
      return;
    }

    (void)unit->ArmyRef->GetArmyBrain()->RunScript("OnPlayNoStagingPlatformsVO");
    return;
  }

  if (gpg::STR_EqualsNoCase(key, "PlayBusyStagingPlatformsVO")) {
    Unit* const unit = entity->IsUnit();
    if (!unit) {
      return;
    }

    (void)unit->ArmyRef->GetArmyBrain()->RunScript("OnPlayBusyStagingPlatformsVO");
    return;
  }
}

/**
 * Address: 0x00749A70 (FUN_00749A70)
 *
 * char const *, LuaPlus::LuaObject const &
 *
 * IDA signature:
 * void __thiscall Moho::Sim::ExecuteLuaInSim(
 *   Moho::Sim *this,
 *   char const *functionName,
 *   LuaPlus::LuaObject const &args);
 *
 * What it does:
 * Cheat-gated: calls the global Lua function `functionName` with `args` and
 * restores the stack top. A script error, including a name that is not a
 * function (the LuaFunction constructor raises that), is logged instead of
 * reaching the command decoder.
 */
void Sim::ExecuteLuaInSim(const char* const functionName, const LuaPlus::LuaObject& args)
{
  if (!CheatsEnabled()) {
    return;
  }

#if FAF_SERVER_MODE
  const SSyncRoutingCommand routingCommand(*this);
#endif
  try {
    lua_State* const state = mLuaState->m_state;
    const int savedTop = lua_gettop(state);
    const LuaPlus::LuaFunction<> function{mLuaState->GetGlobal(functionName)};
    function.Call_Object(args);
    lua_settop(state, savedTop);
  } catch (const std::exception& error) {
    gpg::Warnf("Error running global lua function '%s':\n%s", functionName, error.what());
  }
}

// Given moho:: linkage rather than internal: the shipped binary had this
// file-static beside its only caller, but our tree recovers that caller
// (ISSUE_FactoryCommand) into CWldSession.cpp, so an internal-linkage body
// here can never satisfy it - it was one of the /FORCE-swallowed LNK2019s.

/**
 * Address: 0x00749B60 (FUN_00749B60, ?LuaSimCallback@Sim@Moho@@UAEXPBDABVLuaObject@LuaPlus@@ABV?$BVSet@HUEntIdUniverse@Moho@@@2@@Z)
 *
 * What it does:
 * Imports `/lua/SimCallbacks.lua`, resolves `DoCallback`, builds an optional
 * selected-unit table, then executes `DoCallback(callbackName,args,units)`.
 */
void Sim::LuaSimCallback(
  const char* callbackName, const LuaPlus::LuaObject& args, const BVSet<EntId, EntIdUniverse>& entities
)
{
  LuaPlus::LuaObject selectedUnits(mLuaState);
  if (!entities.Empty()) {
    selectedUnits.AssignNewTable(mLuaState, 0, 0);

    // `end()` is re-evaluated every pass, as the binary's loop calls
    // 0x006E7A00 each time round.
    int luaIndex = 1;
    for (BVSet<EntId, EntIdUniverse>::const_iterator it = entities.begin(); it != entities.end(); ++it) {
      Entity* const entity = FindEntityById(mEntityDB, *it);
      if (!entity) {
        continue;
      }

      Unit* const unit = entity->IsUnit();
      if (!unit) {
        continue;
      }

      selectedUnits.SetObject(luaIndex, unit->GetLuaObject());
      ++luaIndex;
    }
  }

#if FAF_SERVER_MODE
  const SSyncRoutingCommand routingCommand(*this);
#endif
  // A script error is logged, not propagated: the binary's only handler here is
  // `catch (lua_RuntimeError&)` (FuncInfo 0x00EE1C84, funclet 0x00749D74).
  // Without it one bad UI callback (e.g. a wrong-arity Issue* call inside
  // SimCallbacks.lua) unwinds out of the sim thread and terminates the game.
  try {
    lua_State* const state = mLuaState->m_state;
    const int oldTop = lua_gettop(state);
    const LuaPlus::LuaObject simCallbacksModule = SCR_Import(mLuaState, "/lua/SimCallbacks.lua");
    const LuaPlus::LuaFunction<> doCallback(simCallbacksModule["DoCallback"]);
    doCallback(callbackName, args, selectedUnits);
    lua_settop(state, oldTop);
  } catch (const lua_RuntimeError& error) {
    gpg::Warnf("Error running sim lua callback function '%s':\n%s", callbackName, error.what());
  }
}

/**
 * Address: 0x0070A4C0 (FUN_0070A4C0, Moho::Sim::SetArmyColor)
 *
 * IDA signature:
 * int __cdecl Moho::Sim::SetArmyColor(
 *   Moho::Sim* sim,
 *   std::vector<std::string>* commandArgs,
 *   Wm3::Vector3<float>* worldPos,
 *   Moho::CArmyImpl* focusArmy,
 *   Moho::EntitySetTemplate<Unit>* selectedUnits);
 *
 * What it does:
 * Parses and applies the `SetArmyColor` sim-console command.
 */
int Sim::SetArmyColor(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)worldPos;
  (void)focusArmy;
  (void)selectedUnits;

  if (!sim || !commandArgs || commandArgs->size() < 5u) {
    if (sim) {
      sim->Printf(kSetArmyColorSyntaxText);
    }
    return 0;
  }

  const int armyIndex = std::atoi((*commandArgs)[1].c_str());
  const int red = std::atoi((*commandArgs)[2].c_str());
  const int green = std::atoi((*commandArgs)[3].c_str());
  const int blue = std::atoi((*commandArgs)[4].c_str());
  const std::uint32_t packedColor = PackOpaqueArmyColor(red, green, blue);

  if (armyIndex < 0 || static_cast<std::size_t>(armyIndex) >= sim->mArmiesList.size()) {
    sim->Printf(kSetArmyColorInvalidArmyText, armyIndex);
    return 0;
  }

  CArmyImpl* const army = sim->mArmiesList[static_cast<std::size_t>(armyIndex)];
  if (!army) {
    sim->Printf(kSetArmyColorInvalidArmyText, armyIndex);
    return 0;
  }

  army->mVarDat.mPlayerColorBgra = packedColor;
  army->mVarDat.mArmyColorBgra = packedColor;
  return 0;
}

/**
 * Address: 0x0064BD20 (FUN_0064BD20, Moho::Sim::DamageUnit)
 *
 * IDA signature:
 * void callcnv_33 Moho::Sim::DamageUnit(Moho::Sim *a1, std::vector_string *a4,
 *     Wm3::Vector3f *a3, Moho::CArmyImpl *_B0, std::vector_WeakObject_IUnit *a5);
 *
 * What it does:
 * `DamageUnit <amount>` console command - see the declaration. The binary
 * open-codes both weak-pointer operations as owner-chain walks: the instigator
 * detach at 0x0064BDE6..0x0064BDFD and the per-unit target rebind at
 * 0x0064BE60..0x0064BEA9. Both are exactly `WeakPtr<T>::Set`, so they are
 * expressed through it rather than re-spelled here.
 */
int Sim::DamageUnit(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)worldPos;
  (void)focusArmy;

  if (commandArgs == nullptr || commandArgs->size() < 2u) {
    sim->Printf(kDamageUnitUsageText);
    return 0;
  }

  CDamage damage(sim);
  damage.mMethod = CDamage_SINGLE_TARGET;
  damage.mAmount = static_cast<float>(std::atof(commandArgs->at(1).c_str()));

  // 0x0064BDE6: the instigator the CDamage constructor installed is unlinked
  // again, so debug damage is attributed to nobody.
  damage.mInstigator.Set(nullptr);

  // 0x0064BE01..0x0064BE36: the shared zero vector at 0x00F3D21C.
  damage.mVector = Wm3::Vec3f{0.0f, 0.0f, 0.0f};
  damage.mType = kDamageUnitDamageType;
  damage.mDamageFriendly = 1u;

  if (selectedUnits == nullptr) {
    return 0;
  }

  for (Entity* const entity : selectedUnits->mVec) {
    damage.mTarget.Set(entity);
    SIM_Damage(sim, damage);
  }

  return 0;
}

/**
 * Address: 0x00651B00 (FUN_00651B00, Moho::Sim::dbg)
 *
 * What it does:
 * Toggles one debug overlay by name, or prints available overlays and
 * prefix-match diagnostics when selection is omitted/ambiguous.
 */
int Sim::dbg(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)worldPos;
  (void)focusArmy;
  (void)selectedUnits;

  if (sim == nullptr) {
    return 0;
  }

  if (commandArgs == nullptr || commandArgs->empty()) {
    PrintAvailableDebugOverlayList(*sim);
    return 0;
  }

  if (commandArgs->size() > 2u) {
    sim->Printf(kDbgUsageText, commandArgs->front().c_str());
    return 0;
  }

  if (commandArgs->size() < 2u) {
    PrintAvailableDebugOverlayList(*sim);
    return 0;
  }

  const std::string& requestedOverlayName = commandArgs->at(1);

  gpg::RType* selectedType = TryFindExactDebugOverlayType(requestedOverlayName);
  if (selectedType == nullptr) {
    std::vector<const RDebugOverlayClass*> prefixMatches;
    CollectPrefixDebugOverlayTypes(requestedOverlayName, prefixMatches);

    if (prefixMatches.empty()) {
      sim->Printf(kDbgUnknownOverlayText, requestedOverlayName.c_str());
      PrintAvailableDebugOverlayList(*sim);
      return 0;
    }

    if (prefixMatches.size() > 1u) {
      sim->Printf(kDbgAmbiguousOverlayText, requestedOverlayName.c_str());
      sim->Printf(kDbgCouldBeAnyOfText);
      for (const RDebugOverlayClass* const overlayClass : prefixMatches) {
        if (overlayClass == nullptr) {
          continue;
        }
        sim->Printf("  %s - %s", overlayClass->GetName(), overlayClass->mOverlayDescription.c_str());
      }
      return 0;
    }

    selectedType = const_cast<RDebugOverlayClass*>(prefixMatches.front());
  }

  if (selectedType == nullptr) {
    return 0;
  }

  if (RDebugOverlay* const existingOverlay = FindDebugOverlayInstanceByType(*sim, *selectedType);
      existingOverlay != nullptr) {
    RemoveDebugOverlayInstance(*existingOverlay);
    return 0;
  }

  // 0x00651E52: no null test (`NewPtr` asserts its result); unlink, then
  // link before the head.
  sim->mDebugOverlays.push_back(CreateDebugOverlayInstance(*selectedType));

  return 0;
}

/**
 * Address: 0x006D17B0 (FUN_006D17B0, Moho::Sim::DebugSetConsumptionActive)
 *
 * What it does:
 * Enables upkeep consumption for each currently selected unit.
 */
int Sim::DebugSetConsumptionActive(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)sim;
  (void)commandArgs;
  (void)worldPos;
  (void)focusArmy;

  ForEachSelectedUnit(selectedUnits, [](Unit& unit) {
    unit.SetConsumptionActive(true);
  });
  return 0;
}

/**
 * Address: 0x006D17F0 (FUN_006D17F0, Moho::Sim::DebugSetConsumptionInActive)
 *
 * What it does:
 * Disables upkeep consumption for each currently selected unit.
 */
int Sim::DebugSetConsumptionInActive(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)sim;
  (void)commandArgs;
  (void)worldPos;
  (void)focusArmy;

  ForEachSelectedUnit(selectedUnits, [](Unit& unit) {
    unit.SetConsumptionActive(false);
  });
  return 0;
}

/**
 * Address: 0x006D1830 (FUN_006D1830, Moho::Sim::DebugSetProductionActive)
 *
 * What it does:
 * Marks selected units as production-active and dispatches
 * `OnProductionActive`.
 */
int Sim::DebugSetProductionActive(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)sim;
  (void)commandArgs;
  (void)worldPos;
  (void)focusArmy;

  ForEachSelectedUnit(selectedUnits, [](Unit& unit) {
    unit.ProductionActive = true;
    unit.RunScript("OnProductionActive");
  });
  return 0;
}

/**
 * Address: 0x006D1880 (FUN_006D1880, Moho::Sim::DebugSetProductionInActive)
 *
 * What it does:
 * Marks selected units as production-inactive and dispatches
 * `OnProductionInActive`.
 */
int Sim::DebugSetProductionInActive(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)sim;
  (void)commandArgs;
  (void)worldPos;
  (void)focusArmy;

  ForEachSelectedUnit(selectedUnits, [](Unit& unit) {
    unit.ProductionActive = false;
    unit.RunScript("OnProductionInActive");
  });
  return 0;
}

/**
 * Address: 0x006D18D0 (FUN_006D18D0, Moho::Sim::DebugAIStatesOn)
 *
 * What it does:
 * Enables per-unit AI debug-state display for currently selected units.
 */
int Sim::DebugAIStatesOn(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)sim;
  (void)commandArgs;
  (void)worldPos;
  (void)focusArmy;

  ForEachSelectedUnit(selectedUnits, [](Unit& unit) {
    unit.mDebugAIStates = true;
  });
  return 0;
}

/**
 * Address: 0x006D1900 (FUN_006D1900, Moho::Sim::DebugAIStatesOff)
 *
 * What it does:
 * Disables per-unit AI debug-state display for currently selected units and
 * clears published AI debug stats.
 */
int Sim::DebugAIStatesOff(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)sim;
  (void)commandArgs;
  (void)worldPos;
  (void)focusArmy;

  ForEachSelectedUnit(selectedUnits, [](Unit& unit) {
    unit.mDebugAIStates = false;
    unit.ShowAIDebugInfo(false);
  });
  return 0;
}

/**
 * Address: 0x0075ED00 (FUN_0075ED00, Moho::Sim::TrackStats)
 *
 * What it does:
 * Parses `TrackStats <true|false|reset>` and either toggles selected-unit
 * tracking for the focus army or clears `RealTimeStats` for all armies.
 */
int Sim::TrackStats(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)worldPos;

  if (sim == nullptr || commandArgs == nullptr || commandArgs->size() < 2) {
    const char* const commandName =
      (commandArgs != nullptr && !commandArgs->empty()) ? commandArgs->front().c_str() : "TrackStats";
    if (sim != nullptr) {
      sim->Printf("usage: %s <true|false|reset>", commandName);
    }
    return 0;
  }

  const std::string& mode = (*commandArgs)[1];
  if (mode != "reset") {
    const bool enableTracking = (mode == "true");
    ForEachSelectedUnit(selectedUnits, [focusArmy, enableTracking](Unit& unit) {
      if (unit.ArmyRef != focusArmy) {
        return;
      }

      // 0x0075EE21: the byte at unit+0x200, i.e. Entity+0x1F8.
      unit.RealtimeStatsEnabled = enableTracking ? 1u : 0u;
    });
    return 0;
  }

  for (CArmyImpl* const army : sim->mArmiesList) {
    if (army == nullptr) {
      continue;
    }

    CArmyStats* const armyStats = army->GetArmyStats();
    if (armyStats != nullptr) {
      armyStats->Delete("RealTimeStats");
    }
  }

  return 0;
}
namespace
{

  /**
   * Address: 0x0075FDB0 (FUN_0075FDB0)
   *
   * What it does:
   * Sorts one contiguous `DumpUnitsCountEntry` range by descending population
   * count using the binary lane's non-stable ordering contract.
   *
   * The binary's hand-rolled introsort variant recursively invokes the MSVC8
   * `_Adjust_heap` sift-down lane on this element type -- see
   * `Address: 0x00760590 (FUN_00760590` on the `DumpUnitsCountEntry`
   * instantiation cited in `legacy/algorithms/Sort.h`'s `adjust_heap`
   * template. `std::sort` in modern C++20 encapsulates the same heapify +
   * partition + insertion-sort machinery with identical worst-case order,
   * so the explicit heapify helper disappears at the intent-first source
   * level while preserving binary-equivalent ordering for finite inputs.
   */
  void SortDumpUnitsCountEntries(
    DumpUnitsCountEntry* const begin,
    DumpUnitsCountEntry* const end,
    const std::int32_t depthLimit,
    const std::int32_t userContext
  )
  {
    (void)depthLimit;
    (void)userContext;
    if (begin == nullptr || end == nullptr || begin >= end) {
      return;
    }

    std::sort(begin, end, [](const DumpUnitsCountEntry& lhs, const DumpUnitsCountEntry& rhs) {
      return lhs.count > rhs.count;
    });
  }
}



/**
 * Address: 0x0075EE50 (FUN_0075EE50, Moho::Sim::DumpUnits)
 *
 * What it does:
 * Aggregates live units by blueprint owner pointer, sorts by descending
 * population, and logs one `"<blueprintId> <count>"` line per entry.
 */
int Sim::DumpUnits(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)commandArgs;
  (void)worldPos;
  (void)focusArmy;
  (void)selectedUnits;

  if (sim == nullptr || sim->mEntityDB == nullptr) {
    return 0;
  }

  // ABI: msvc8::vector so counts.push_back(...) names the MSVC8 STL grow lane
  // vector<DumpUnitsCountEntry>::_Insert_n (FUN_0075F810) on the capacity-full
  // path, matching the original binary; std::vector would inline its own grow.
  msvc8::vector<DumpUnitsCountEntry> counts;
  EntityDB* const entityDb = sim->mEntityDB;
  CEntityDbAllUnitsNode* node = entityDb->AllUnitsEnd(0u);
  CEntityDbAllUnitsNode* const end = entityDb->AllUnitsEnd();
  while (node != end) {
    Unit* const unit = EntityDB::UnitFromAllUnitsNode(node);
    node = EntityDB::NextAllUnitsNode(node);
    if (unit == nullptr) {
      continue;
    }

    const RUnitBlueprint* const blueprint = unit->GetBlueprint();
    auto found = std::find_if(counts.begin(), counts.end(), [blueprint](const DumpUnitsCountEntry& entry) {
      return entry.blueprint == blueprint;
    });
    if (found == counts.end()) {
      counts.push_back(DumpUnitsCountEntry{blueprint, 1});
    } else {
      ++found->count;
    }
  }

  if (!counts.empty()) {
    DumpUnitsCountEntry* const begin = counts.data();
    DumpUnitsCountEntry* const finish = begin + counts.size();
    const auto depthLimit = static_cast<std::int32_t>(counts.size());
    SortDumpUnitsCountEntries(begin, finish, depthLimit, 0);
  }

  for (const DumpUnitsCountEntry& entry : counts) {
    if (entry.blueprint == nullptr) {
      continue;
    }

    gpg::Logf("%s %i", entry.blueprint->mBlueprintId.c_str(), entry.count);
  }

  return 0;
}

/**
 * Address: 0x0075D7A0 (FUN_0075D7A0, Moho::Sim::DebugDumpArmyStats)
 *
 * IDA signature:
 * void __cdecl Moho::Sim::DebugDumpArmyStats(
 *     Moho::Sim *sim, std::vector_string *commandArgs, Wm3::Vector3f *worldPos,
 *     Moho::CArmyImpl *focusArmy, std::vector_WeakObject_IUnit *selectedUnits);
 *
 * What it does:
 * `DebugDumpArmyStats <armyIndex>` console callback. With fewer than two
 * tokens it prints the usage line; otherwise it parses the index, looks that
 * army up in `mArmiesList` (`[edx+910h]`/`[edx+914h]` at 0x0075D7F5 and
 * 0x0075D802) and, when the slot holds a live army, dumps its stat snapshot
 * through `CArmyStats::DumpStats` (0x0075D838).
 *
 * The binary indexes `mArmiesList` twice - once to load the army pointer at
 * 0x0075D814 and once for the `GetArmyStats` call at 0x0075D82E - so the
 * inlined bounds check appears twice, and the failing arm at 0x0075D840 is
 * the usual null-deref trap. Only the first index can actually fail, so the
 * recovered form keeps the single guard the source expressed.
 */
int Sim::DebugDumpArmyStats(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)worldPos;
  (void)focusArmy;
  (void)selectedUnits;

  if (commandArgs == nullptr || commandArgs->size() < 2u) {
    sim->Printf("usage: DebugDumpArmyStats armyIndex");
    return 0;
  }

  const auto armyIndex = static_cast<std::size_t>(std::atoi((*commandArgs)[1].c_str()));
  if (armyIndex >= sim->mArmiesList.size()) {
    return 0;
  }

  if (CArmyImpl* const army = sim->mArmiesList[armyIndex]; army != nullptr) {
    army->GetArmyStats()->DumpStats();
  }

  return 0;
}

/**
 * Address: 0x0064BB80 (FUN_0064BB80, Moho::Sim::SallyShears)
 *
 * What it does:
 * Toggles fog-of-war state across every army recon database.
 */
int Sim::SallyShears(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)commandArgs;
  (void)worldPos;
  (void)focusArmy;
  (void)selectedUnits;

  if (sim == nullptr) {
    return 0;
  }

  for (CArmyImpl* const army : sim->mArmiesList) {
    if (army == nullptr) {
      continue;
    }

    CAiReconDBImpl* const reconDb = army->GetReconDB();
    if (reconDb == nullptr) {
      continue;
    }

    reconDb->ReconSetFogOfWar(!reconDb->ReconGetFogOfWar());
  }

  return 0;
}
namespace
{
  constexpr std::uint64_t kInt64SignBitMask = 0x8000000000000000ull;
  constexpr std::uint64_t kInt64MagnitudeMask = 0x7FFFFFFFFFFFFFFFull;
  // 0x0064BA94..0x0064BAA4: fild of the sign-bit-only qword, then fchs: +2^63.
  constexpr double kSignedInt64HighBitContribution = 9223372036854775808.0;

  [[nodiscard]] float ConvertSignedStorageLaneToFloat(const std::uint64_t lane) noexcept
  {
    double value = static_cast<double>(lane & kInt64MagnitudeMask);
    if ((lane & kInt64SignBitMask) != 0ull) {
      value += kSignedInt64HighBitContribution;
    }
    return static_cast<float>(value);
  }

  /**
   * Address: 0x0064BA60 (FUN_0064BA60)
   *
   * What it does:
   * Converts `SEconTotals::mMaxStorage` signed 64-bit ENERGY/MASS lanes into a
   * pair of float lanes using the original sign-bit split conversion path.
   */
  [[nodiscard]] SEconPair* BuildSignedMaxStorageFloatPair(
    SEconPair* const outPair,
    const SEconTotals& totals
  ) noexcept
  {
    outPair->ENERGY = ConvertSignedStorageLaneToFloat(totals.mMaxStorage.ENERGY);
    outPair->MASS = ConvertSignedStorageLaneToFloat(totals.mMaxStorage.MASS);
    return outPair;
  }
}



/**
 * Address: 0x0064BBE0 (FUN_0064BBE0, Moho::Sim::BlingBling)
 *
 * What it does:
 * Increases focus-army extra storage by 10000 energy/mass and credits current
 * resources by the updated max-storage lanes.
 */
int Sim::BlingBling(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)commandArgs;
  (void)worldPos;
  (void)selectedUnits;

  if (focusArmy == nullptr) {
    if (sim != nullptr) {
      sim->Printf("No focus army.");
    }
    return 0;
  }

  CSimArmyEconomyInfo* const economyInfo = focusArmy->GetEconomy();
  CEconStorage* const storage = GetArmyEconStorage(*focusArmy);
  if (economyInfo == nullptr || storage == nullptr) {
    return 0;
  }

  (void)storage->Chng(-1);
  storage->mAmt.energy += 10000.0f;
  storage->mAmt.mass += 10000.0f;
  (void)storage->Chng(1);

  // 0x0064BC79..0x0064BC96 adds into economy-info +0x08 (this tick's banked
  // resources), not the stored totals; the next economy tick moves it into storage.
  SEconPair grantedStorage{};
  (void)BuildSignedMaxStorageFloatPair(&grantedStorage, economyInfo->economy);
  economyInfo->mResources.ENERGY += grantedStorage.ENERGY;
  economyInfo->mResources.MASS += grantedStorage.MASS;

  return 0;
}

/**
 * Address: 0x0064BCA0 (FUN_0064BCA0, Moho::Sim::ZeroExtraStorage)
 *
 * What it does:
 * Zeroes focus-army extra-storage lanes after removing and reapplying storage
 * delta contribution.
 */
int Sim::ZeroExtraStorage(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)commandArgs;
  (void)worldPos;
  (void)selectedUnits;

  if (focusArmy == nullptr) {
    if (sim != nullptr) {
      sim->Printf("No focus army.");
    }
    return 0;
  }

  CEconStorage* const storage = GetArmyEconStorage(*focusArmy);
  if (storage == nullptr) {
    return 0;
  }

  (void)storage->Chng(-1);
  storage->mAmt.energy = 0.0f;
  storage->mAmt.mass = 0.0f;
  (void)storage->Chng(1);
  return 0;
}

/**
 * Address: 0x0064BF00 (FUN_0064BF00, Moho::Sim::AddImpulse)
 *
 * What it does:
 * Parses three impulse components, applies the impulse to each selected
 * unit's motion controller, and forces each selected unit into `LAYER_Air`.
 */
int Sim::AddImpulse(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)worldPos;
  (void)focusArmy;

  if (sim == nullptr || commandArgs == nullptr || commandArgs->size() < 4u) {
    if (sim != nullptr) {
      const int got = commandArgs != nullptr ? static_cast<int>(commandArgs->size()) : 0;
      sim->Printf("Insufficient args: got %i, expected %i", got, 4);
    }
    return 0;
  }

  const Wm3::Vector3f impulse{
    static_cast<float>(std::atof(commandArgs->at(1).c_str())),
    static_cast<float>(std::atof(commandArgs->at(2).c_str())),
    static_cast<float>(std::atof(commandArgs->at(3).c_str()))
  };

  ForEachSelectedUnit(selectedUnits, [&impulse](Unit& unit) {
    if (unit.UnitMotion != nullptr) {
      // 0x0064BFF3: `push 0; push &impulse; call CUnitMotion::AddImpulse`.
      unit.UnitMotion->AddImpulse(impulse, false);
    }
    unit.SetCurrentLayer(LAYER_Air);
  });

  return 0;
}

/**
 * Address: 0x005C37B0 (FUN_005C37B0, Moho::Sim::ReconFlush)
 *
 * What it does:
 * Flushes every army recon database currently attached to this sim.
 */
int Sim::ReconFlush(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)commandArgs;
  (void)worldPos;
  (void)focusArmy;
  (void)selectedUnits;

  if (!sim) {
    return 0;
  }

  for (CArmyImpl* const army : sim->mArmiesList) {
    if (!army) {
      continue;
    }

    CAiReconDBImpl* const reconDb = army->GetReconDB();
    if (reconDb) {
      reconDb->Flush();
    }
  }

  return 0;
}

/**
 * Address: 0x00684D00 (FUN_00684D00, Moho::Sim::Purge)
 *
 * What it does:
 * Purges entities by category token and optional army filter.
 */
int Sim::Purge(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)worldPos;
  (void)focusArmy;
  (void)selectedUnits;

  if (!sim || !sim->mEntityDB || !commandArgs || commandArgs->size() < 2u) {
    return 0;
  }

  const std::string& categoryToken = commandArgs->at(1);
  const PurgeCategory category = ParsePurgeCategory(categoryToken);
  if (category == PurgeCategory::Unknown) {
    sim->Printf("Unknown type %s", categoryToken.c_str());
    return 0;
  }

  int armyFilter = -1;
  if (commandArgs->size() > 2u) {
    armyFilter = std::atoi(commandArgs->at(2).c_str());
  }

  std::vector<Entity*> targets;
  for (const auto& [entityId, entity] : sim->mEntityDB->mAllUnits) {
    if (!entity) {
      continue;
    }

    if (!EntityMatchesPurgeCategory(*entity, category)) {
      continue;
    }

    if (!EntityMatchesPurgeArmyFilter(*entity, armyFilter)) {
      continue;
    }

    if (!ShouldDestroyEntityForPurge(*entity)) {
      continue;
    }

    targets.push_back(entity);
  }

  for (Entity* const entity : targets) {
    if (entity) {
      entity->Destroy();
    }
  }

  return 0;
}

/**
 * Address: 0x006B6B40 (FUN_006B6B40, Moho::Sim::KillAll)
 *
 * What it does:
 * Kills every unit in the requested armies, or every army when no army
 * indexes are supplied.
 */
int Sim::KillAll(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)worldPos;
  (void)focusArmy;
  (void)selectedUnits;

  ForEachTargetArmyUnit(sim, commandArgs, [](Unit& unit) {
    unit.Kill(nullptr, "", 0.0f);
  });
  return 0;
}

/**
 * Address: 0x006B6DC0 (FUN_006B6DC0, Moho::Sim::DestroyAll)
 *
 * What it does:
 * Destroys every unit in the requested armies, or every army when no army
 * indexes are supplied.
 */
int Sim::DestroyAll(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)worldPos;
  (void)focusArmy;
  (void)selectedUnits;

  ForEachTargetArmyUnit(sim, commandArgs, [](Unit& unit) {
    static_cast<Entity&>(unit).Destroy();
  });
  return 0;
}

/**
 * Address: 0x006540A0 (FUN_006540A0)
 *
 * What it does:
 * Returns the effect-manager pointer lane stored on one `Sim` runtime object.
 */
[[nodiscard]] CEffectManagerImpl* ReadEffectManagerLane(const Sim* const sim)
{
  return sim->mEffectManager;
}

/**
 * Address: 0x0065E9D0 (FUN_0065E9D0, Moho::Sim::efx_NewEmitter)
 *
 * What it does:
 * Creates one emitter at the cursor world position when a blueprint name is
 * provided.
 */
int Sim::efx_NewEmitter(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)focusArmy;
  (void)selectedUnits;

  if (!sim || !worldPos || !Wm3::Vector3f::IsntNaN(worldPos) || !commandArgs) {
    return 0;
  }

  CEffectManagerImpl* const effectManager = ReadEffectManagerLane(sim);
  if (effectManager == nullptr) {
    return 0;
  }

  if (commandArgs->size() < 2u) {
    return 0;
  }

  const std::string& blueprintName = commandArgs->at(1);
  effectManager->CreateEmitter(*worldPos, blueprintName.c_str(), -1);
  return 0;
}

/**
 * Address: 0x0065EA50 (FUN_0065EA50, Moho::Sim::efx_AttachEmitter)
 *
 * What it does:
 * Uses command arg #1 as the target bone name and command args #2..N as
 * emitter blueprint tokens, then attaches each emitter token to each selected
 * unit when the primary emitter blueprint resolves in rules.
 */
int Sim::efx_AttachEmitter(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)worldPos;
  (void)focusArmy;

  if (!sim || !sim->mRules || !commandArgs || !selectedUnits) {
    return 0;
  }

  CEffectManagerImpl* const effectManager = ReadEffectManagerLane(sim);
  if (effectManager == nullptr) {
    return 0;
  }

  if (commandArgs->size() < 3u) {
    return 0;
  }

  const std::string& boneName = commandArgs->at(1);
  const std::string& primaryEmitterBlueprint = commandArgs->at(2);

  RResId emitterId{};
  gpg::STR_InitFilename(&emitterId.name, primaryEmitterBlueprint.c_str());
  if (sim->mRules->GetEmitterBlueprint(emitterId) == nullptr) {
    return 0;
  }

  ForEachSelectedUnit(selectedUnits, [&](Unit& unit) {
    Entity* const entity = static_cast<Entity*>(&unit);
    for (std::size_t index = 2u; index < commandArgs->size(); ++index) {
      const std::string& emitterBlueprint = commandArgs->at(index);
      const int boneIndex = entity->ResolveBoneIndex(boneName.c_str());
      effectManager->CreateAttachedEmitter(entity, boneIndex, emitterBlueprint.c_str(), -1);
    }
  });

  return 0;
}

/**
 * Address: 0x0066BD90 (FUN_0066BD90, func_AddLightParticle_SimConFunc)
 *
 * What it does:
 * Parses optional `lifetime`, `size`, and `texture` args, then creates a light
 * particle using `ramp_white_01` as the secondary texture.
 */
int Sim::AddLightParticle(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)focusArmy;
  (void)selectedUnits;

  if (!sim || !worldPos || !Wm3::Vector3f::IsntNaN(worldPos)) {
    return 0;
  }

  CEffectManagerImpl* const effectManager = ReadEffectManagerLane(sim);
  if (effectManager == nullptr) {
    return 0;
  }

  float lifetime = 2.0f;
  float size = 1.0f;
  msvc8::string texturePrimary{};

  if (commandArgs && commandArgs->size() > 1u) {
    for (std::size_t i = 1u; i < commandArgs->size(); ++i) {
      const std::string& key = commandArgs->at(i);
      const std::string* value = (i + 1u < commandArgs->size()) ? &commandArgs->at(i + 1u) : nullptr;
      if (!value) {
        continue;
      }

      if (key == "lifetime") {
        lifetime = static_cast<float>(std::atof(value->c_str()));
      } else if (key == "size") {
        size = static_cast<float>(std::atof(value->c_str()));
      } else if (key == "texture") {
        texturePrimary.assign_owned(value->c_str());
      }
    }
  }

  const msvc8::string textureSecondary("ramp_white_01");
  effectManager->CreateLightParticle(*worldPos, texturePrimary, textureSecondary, size, lifetime, -1);
  return 0;
}

/**
 * Address: 0x00734F50 (FUN_00734F50, Moho::Sim::Log)
 *
 * What it does:
 * Joins command args #1..N with spaces and logs the resulting text via
 * `gpg::Logf("%s", ...)`.
 */
int Sim::Log(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)sim;
  (void)worldPos;
  (void)focusArmy;
  (void)selectedUnits;

  std::string joined;
  if (commandArgs != nullptr && commandArgs->size() > 1u) {
    joined = commandArgs->at(1);
    for (std::size_t i = 2u; i < commandArgs->size(); ++i) {
      joined.push_back(' ');
      joined += commandArgs->at(i);
    }
  }

  gpg::Logf("%s", joined.c_str());
  return 0;
}

/**
 * Address: 0x00734FF0 (FUN_00734FF0, Moho::Sim::SimWarn)
 *
 * What it does:
 * Joins command args #1..N with spaces and warns using `gpg::Warnf("%s", ...)`.
 */
int Sim::SimWarn(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)sim;
  (void)worldPos;
  (void)focusArmy;
  (void)selectedUnits;

  std::string joined;
  if (commandArgs != nullptr && commandArgs->size() > 1u) {
    joined = commandArgs->at(1);
    for (std::size_t i = 2u; i < commandArgs->size(); ++i) {
      joined.push_back(' ');
      joined += commandArgs->at(i);
    }
  }

  gpg::Warnf("%s", joined.c_str());
  return 0;
}

/**
 * Address: 0x00735090 (FUN_00735090, Moho::Sim::SimError)
 *
 * What it does:
 * Joins command args #1..N with spaces and terminates with
 * `gpg::Die("%s", ...)`. Returns `int` because it's invoked as a Lua C
 * function (which require an `int` return slot for the result count); the
 * function is in practice noreturn via `gpg::Die`/`std::abort` but the
 * `[[noreturn]]` attribute can't be applied to non-void return types
 * (C4646), so it is omitted here.
 */
int Sim::SimError(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)sim;
  (void)worldPos;
  (void)focusArmy;
  (void)selectedUnits;

  std::string joined;
  if (commandArgs != nullptr && commandArgs->size() > 1u) {
    joined = commandArgs->at(1);
    for (std::size_t i = 2u; i < commandArgs->size(); ++i) {
      joined.push_back(' ');
      joined += commandArgs->at(i);
    }
  }

  gpg::Die("%s", joined.c_str());
  std::abort();
}

/**
 * Address: 0x00699D20 (FUN_00699D20, Moho::Sim::sim_Gravity)
 *
 * Moho::Sim *, std::vector<msvc8::string> *
 *
 * What it does:
 * Prints the current gravity value, or parses a new scalar and stores it as
 * the downward gravity acceleration on the active sim.
 */
int Sim::sim_Gravity(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)worldPos;
  (void)focusArmy;
  (void)selectedUnits;

  if (sim == nullptr || commandArgs == nullptr || commandArgs->empty()) {
    if (sim != nullptr) {
      sim->Printf("usage: %s [new-value]", "sim_Gravity");
      sim->Printf("    where new-value is in ogrids/(second^2)");
    }
    return 0;
  }

  if (sim->mPhysConstants == nullptr) {
    return 0;
  }

  Wm3::Vector3f& gravity = sim->mPhysConstants->mGravity;
  if (commandArgs->size() == 1u) {
    sim->Printf("Gravity is %.2f ogrids/(second^2) down.", -gravity.y);
    return 0;
  }

  if (commandArgs->size() == 2u) {
    float newGravity = 0.0f;
    const std::string& argument = commandArgs->at(1);
    if (::sscanf_s(argument.c_str(), "%f", &newGravity) == 1) {
      gravity.y = -newGravity;
      sim->Printf("Changing gravity to %.2f ogrids/(second^2) down.", newGravity);
    } else {
      sim->Printf("Invalid number: %s", argument.c_str());
    }
    return 0;
  }

  sim->Printf("usage: %s [new-value]", commandArgs->front().c_str());
  sim->Printf("    where new-value is in ogrids/(second^2)");
  return 0;
}

/**
 * Address: 0x00735110 (FUN_00735110, Moho::Sim::SimAssert)
 *
 * What it does:
 * No-op debug command callback lane.
 */
int Sim::SimAssert(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)sim;
  (void)commandArgs;
  (void)worldPos;
  (void)focusArmy;
  (void)selectedUnits;
  return 0;
}

/**
 * Address: 0x00735120 (FUN_00735120, Moho::Sim::SimCrash)
 *
 * What it does:
 * Triggers an intentional null-write crash for debug fault testing.
 */
int Sim::SimCrash(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)sim;
  (void)commandArgs;
  (void)worldPos;
  (void)focusArmy;
  (void)selectedUnits;

  *reinterpret_cast<volatile std::uint32_t*>(0) = 0u;
  return 0;
}

/**
 * Address: 0x0074B610 (FUN_0074B610, Moho::Sim::sim_DebugCrash)
 *
 * What it does:
 * Triggers an intentional null-write crash for debug fault testing.
 */
int Sim::sim_DebugCrash(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)sim;
  (void)commandArgs;
  (void)worldPos;
  (void)focusArmy;
  (void)selectedUnits;

  *reinterpret_cast<volatile std::uint32_t*>(0) = 0u;
  return 0;
}

/**
 * Address: 0x00734BA0 (FUN_00734BA0, Moho::Sim::sim_TestFunc)
 *
 * What it does:
 * Debug console-command stub for the `sim_TestFunc` test entry: prints this
 * sim instance's own address and returns.
 */
int Sim::sim_TestFunc(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)commandArgs;
  (void)worldPos;
  (void)focusArmy;
  (void)selectedUnits;

  sim->Printf("sim=%p", static_cast<const void*>(sim));
  return 0;
}

/**
 * Address: 0x0074B3F0 (FUN_0074B3F0, Moho::Sim::ScenarioMethod)
 *
 * What it does:
 * Looks up one scenario callback in `ScenarioInfo.Env` using command arg #1
 * and invokes it if present; warns when the callback is undefined.
 */
int Sim::ScenarioMethod(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)worldPos;
  (void)focusArmy;
  (void)selectedUnits;

  if (commandArgs == nullptr) {
    return 0;
  }

  const int argumentCount = static_cast<int>(commandArgs->size());
  if (argumentCount < 2 || sim == nullptr || sim->mLuaState == nullptr) {
    return argumentCount;
  }

  const std::string& methodName = commandArgs->at(1);
  LuaPlus::LuaObject globals = sim->mLuaState->GetGlobals();
  LuaPlus::LuaObject scenarioInfoObject = globals["ScenarioInfo"];
  LuaPlus::LuaObject scenarioEnvObject = scenarioInfoObject["Env"];
  LuaPlus::LuaObject scenarioMethodObject = scenarioEnvObject[methodName.c_str()];

  if (scenarioMethodObject) {
    LuaPlus::LuaFunction scenarioMethodFunction(scenarioMethodObject);
    scenarioMethodFunction.Call();
  } else {
    gpg::Warnf("ScenarioMethod '%s' not defined", methodName.c_str());
  }

  return 0;
}

/**
 * Address: 0x007595C0 (FUN_007595C0, Moho::Sim::SimLua)
 *
 * What it does:
 * Builds one Lua expression from sim-command args #1..N, exposes the first
 * selected unit as global `__selected_unit`, executes the expression, then
 * clears `__selected_unit`.
 */
int Sim::SimLua(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)worldPos;
  (void)focusArmy;

  if (sim == nullptr || commandArgs == nullptr || commandArgs->size() < 2u || sim->mLuaState == nullptr) {
    return 0;
  }

  auto clearSelectedUnitGlobal = [sim]() {
    lua_State* const rawState = sim->mLuaState != nullptr ? sim->mLuaState->GetCState() : nullptr;
    if (rawState == nullptr) {
      return;
    }

    lua_pushnil(rawState);
    lua_setglobal(rawState, "__selected_unit");
  };

  LuaPlus::LuaObject globals = sim->mLuaState->GetGlobals();
  Unit* selectedUnit = nullptr;
  if (selectedUnits != nullptr && selectedUnits->mVec.begin() != selectedUnits->mVec.end()) {
    selectedUnit = static_cast<Unit*>(*selectedUnits->mVec.begin());
  }

  if (selectedUnit != nullptr) {
    LuaPlus::LuaObject selectedUnitObject = selectedUnit->GetLuaObject();
    globals.SetObject("__selected_unit", selectedUnitObject);
  } else {
    clearSelectedUnitGlobal();
  }

  std::string commandText = commandArgs->at(1);
  for (std::size_t argIndex = 2u; argIndex < commandArgs->size(); ++argIndex) {
    commandText.push_back(' ');
    commandText += commandArgs->at(argIndex);
  }

  sim->Printf("%s", commandText.c_str());
  (void)SCR_LuaDoString(commandText.c_str(), sim->mLuaState);
  clearSelectedUnitGlobal();
  return 0;
}

/**
 * Address: 0x0075D5D0 (FUN_0075D5D0, Moho::Sim::DebugSetPlayableRect)
 *
 * IDA signature:
 * void __cdecl Moho::Sim::DebugSetPlayableRect(Moho::Sim *sim, std::vector_string *commandArgs);
 *
 * What it does:
 * `DebugSetPlayableRect x0 y0 x1 y1`. Parses the four bounds with `atoi` into
 * a `gpg::Rect2i` laid out `{x0, z0, x1, z1}` (0x0075D6A6..0x0075D6C2 stores
 * arg1 -> x0, arg2 -> z0, arg3 -> x1, arg4 -> z1), asks the sim's `STIMap` to
 * clamp and adopt it, and on success mirrors the change into Sim Lua by
 * running `SyncPlayableRect({ ... })`. The Lua mirror is built from the *raw
 * argument tokens*, not from the clamped rectangle - 0x0075D6EF re-reads the
 * argument vector and pushes the four strings in the order
 * `x0=arg1, x1=arg3, y0=arg2, y1=arg4`.
 */
int Sim::DebugSetPlayableRect(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)worldPos;
  (void)focusArmy;
  (void)selectedUnits;

  if (commandArgs == nullptr || commandArgs->size() < 5u) {
    sim->Printf(kDebugSetPlayableRectUsageText);
    return 0;
  }

  const gpg::Rect2i playableRect{
    std::atoi(commandArgs->at(1u).c_str()),
    std::atoi(commandArgs->at(2u).c_str()),
    std::atoi(commandArgs->at(3u).c_str()),
    std::atoi(commandArgs->at(4u).c_str())
  };

  if (!sim->mMapData->SetPlayableMapRect(playableRect)) {
    sim->Printf(kDebugSetPlayableRectInvalidText);
    return 0;
  }

  const msvc8::string syncCommand = gpg::STR_Printf(
    kDebugSetPlayableRectSyncFormat,
    commandArgs->at(1u).c_str(),
    commandArgs->at(3u).c_str(),
    commandArgs->at(2u).c_str(),
    commandArgs->at(4u).c_str()
  );
  (void)SCR_LuaDoString(syncCommand.c_str(), sim->mLuaState);
  return 0;
}

/**
 * Address: 0x0075D860 (FUN_0075D860, Moho::Sim::DebugMoveCamera)
 *
 * What it does:
 * Builds and executes `DebugMoveCamera(x0,y0,x1,y1)` in Sim Lua from command
 * args #1..#4.
 */
int Sim::DebugMoveCamera(
  Sim* const sim,
  CSimConCommand::ParsedCommandArgs* const commandArgs,
  Wm3::Vector3f* const worldPos,
  CArmyImpl* const focusArmy,
  EntitySetTemplate<Unit>* const selectedUnits
)
{
  (void)worldPos;
  (void)focusArmy;
  (void)selectedUnits;

  if (sim == nullptr) {
    return 0;
  }

  if (commandArgs == nullptr || commandArgs->size() < 5u) {
    sim->Printf("usage: DebugMoveCamera x0 y0 x1 y1");
    return 0;
  }

  const msvc8::string commandText = gpg::STR_Printf(
    "DebugMoveCamera(%s,%s,%s,%s)",
    commandArgs->at(1).c_str(),
    commandArgs->at(2).c_str(),
    commandArgs->at(3).c_str(),
    commandArgs->at(4).c_str()
  );
  (void)SCR_LuaDoString(commandText.c_str(), sim->mLuaState);
  return 0;
}


/**
 * Address: 0x007457F0 (FUN_007457F0, ?Shutdown@Sim@Moho@@QAEXXZ)
 *
 * What it does:
 * Destroys live units, drains the deferred deletion queue, shuts down the
 * sim sound manager, and latches `mDidProcess`.
 */
void Sim::Shutdown()
{
  // 0x007457F3..0x00745827 walks `mAllUnits` - the id-keyed tree every entity
  // registers itself in through `Entity::StandardInit` - and calls
  // `Entity::Destroy` on each node's value, with no type filter and no null
  // test:
  //
  //   0x007457F3  mov ecx, [esi+984h]   ; mEntityDB
  //   0x007457F9  mov eax, [ecx+4]      ; mAllUnits._Myhead  (the map is at +0)
  //   0x007457FC  mov eax, [eax]        ; _Myhead->_Left, i.e. begin()
  //   0x00745810  mov eax, [eax+10h]    ; node->second, the Entity*
  //   0x00745813  call 0x679AF0         ; Entity::Destroy
  //   0x0074581C  call 0x5C87A0         ; ++it
  //   0x00745825  cmp eax, edi / jne    ; until end()
  //
  // This used to walk `EntityDB::Entities()`, a hand-kept side table of
  // entity pointers that could outlive its entries; it was removed
  // 2026-09-22. `mAllUnits` cannot: `~Entity` -> `ReleaseId` erases the node.
  //
  // `Destroy()` only sets a flag, pushes to the deletion queue and relinks the
  // coord node - it never erases from `mAllUnits` - so walking the tree while
  // calling it is safe, which is why the binary does exactly that.
  //
  // Retire props and other entities too: the driver's final Sync publishes
  // their interface removals before world teardown releases the blueprints.
  if (mEntityDB != nullptr) {
    for (auto& entry : mEntityDB->mAllUnits) {
      // `DoReserveId` (0x00684480) inserts `{id, nullptr}` before
      // `StandardInit` fills the slot in, so a reserved-but-unbuilt id can
      // still be in the tree. The binary does not test for it; this does,
      // because it costs one compare and the alternative is a null `this`.
      Entity* const entity = entry.second;
      if (entity != nullptr) {
        entity->Destroy();
      }
    }
  }

  while (!mDeletionQueue.empty()) {
    void* const queuedObject = mDeletionQueue.front();
    mDeletionQueue.pop_front();
    RunQueuedDestroy(queuedObject);
  }

  if (mSoundManager != nullptr) {
    mSoundManager->Shutdown();
  }

  mDidProcess = true;
}

/**
 * Address: 0x0074B100 (FUN_0074B100, ?EndGame@Sim@Moho@@UAEXXZ)
 *
 * What it does:
 * Marks the sim as ended.
 */
void Sim::EndGame()
{
  mGameEnded = true;
}

/**
 * Address: 0x005859B0 (FUN_005859B0, Moho::Sim::ArmyCount)
 *
 * What it does:
 * Returns the number of army slots in the sim army list.
 */
int Sim::ArmyCount() const
{
  return static_cast<int>(mArmiesList.size());
}
namespace
{

  /**
   * Address: 0x00528DF0 (FUN_00528DF0)
   *
   * What it does:
   * Uses the active blueprint TLS lane and forwards one mesh-blueprint
   * registration callback into the canonical state registration routine.
   */
  [[maybe_unused]] int RegisterMeshBlueprintFromTlsLane(LuaPlus::LuaState* const state)
  {
    (void)&moho::BlueprintLoaderContext().mRules->mMeshBlueprints;
    (void)RegisterMeshBlueprintFromState(state);
    return 0;
  }

  /**
   * Address: 0x00528EB0 (FUN_00528EB0)
   *
   * What it does:
   * Uses the active blueprint TLS lane and forwards one trail-emitter
   * registration callback into the canonical state registration routine.
   */
  [[maybe_unused]] int RegisterTrailEmitterBlueprintFromTlsLane(LuaPlus::LuaState* const state)
  {
    (void)&moho::BlueprintLoaderContext().mRules->mTrailBlueprints;
    return RegisterTrailEmitterBlueprintFromState(state);
  }

  /**
   * Address: 0x00528F60 (FUN_00528F60)
   *
   * What it does:
   * Uses the active blueprint TLS lane and forwards one emitter-blueprint
   * registration callback into the canonical state registration routine.
   */
  [[maybe_unused]] int RegisterEmitterBlueprintFromTlsLane(LuaPlus::LuaState* const state)
  {
    (void)&moho::BlueprintLoaderContext().mRules->mEmitterBlueprints;
    return RegisterEmitterBlueprintFromState(state);
  }

  /**
   * Address: 0x00529010 (FUN_00529010)
   *
   * What it does:
   * Uses the active blueprint TLS lane and forwards one beam-blueprint
   * registration callback into the canonical state registration routine.
   */
  [[maybe_unused]] int RegisterBeamBlueprintFromTlsLane(LuaPlus::LuaState* const state)
  {
    (void)&moho::BlueprintLoaderContext().mRules->mBeamBlueprints;
    return RegisterBeamBlueprintFromState(state);
  }

  /**
   * Address: 0x005290C0 (FUN_005290C0)
   *
   * What it does:
   * Ticks one background-load progress update directly from the worker's
   * blueprint-loader context and returns the legacy success code.
   */
  [[maybe_unused]] int BlueprintLoaderUpdateProgressFromLoaderContext()
  {
    TickBlueprintLoaderProgressFromLoaderContext();
    return 0;
  }
}



/**
 * Address: 0x00BC8E50 (FUN_00BC8E50, register_RegisterUnitBlueprint_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_RegisterUnitBlueprint_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_RegisterUnitBlueprint_LuaFuncDef()
{
  return func_RegisterUnitBlueprint_LuaFuncDef();
}

/**
 * Address: 0x00BC8E60 (FUN_00BC8E60, register_RegisterPropBlueprint_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_RegisterPropBlueprint_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_RegisterPropBlueprint_LuaFuncDef()
{
  return func_RegisterPropBlueprint_LuaFuncDef();
}

/**
 * Address: 0x00BC8E70 (FUN_00BC8E70, register_RegisterProjectileBlueprint_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_RegisterProjectileBlueprint_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_RegisterProjectileBlueprint_LuaFuncDef()
{
  return func_RegisterProjectileBlueprint_LuaFuncDef();
}

/**
 * Address: 0x00BC8E80 (FUN_00BC8E80, register_RegisterMeshBlueprint_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_RegisterMeshBlueprint_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_RegisterMeshBlueprint_LuaFuncDef()
{
  return func_RegisterMeshBlueprint_LuaFuncDef();
}

/**
 * Address: 0x00BC8E90 (FUN_00BC8E90, register_RegisterTrailEmitterBlueprint_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_RegisterTrailEmitterBlueprint_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_RegisterTrailEmitterBlueprint_LuaFuncDef()
{
  return func_RegisterTrailEmitterBlueprint_LuaFuncDef();
}

/**
 * Address: 0x00BC8EA0 (FUN_00BC8EA0, register_RegisterEmitterBlueprint_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_RegisterEmitterBlueprint_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::register_RegisterEmitterBlueprint_LuaFuncDef()
{
  return func_RegisterEmitterBlueprint_LuaFuncDef();
}

/**
 * Address: 0x00BC8EB0 (FUN_00BC8EB0, j_func_RegisterBeamBlueprint_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_RegisterBeamBlueprint_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::j_func_RegisterBeamBlueprint_LuaFuncDef()
{
  return func_RegisterBeamBlueprint_LuaFuncDef();
}

/**
 * Address: 0x00BC8EC0 (FUN_00BC8EC0, j_func_BlueprintLoaderUpdateProgress_LuaFuncDef)
 *
 * What it does:
 * Startup thunk that forwards registration to `func_BlueprintLoaderUpdateProgress_LuaFuncDef`.
 */
moho::CScrLuaInitForm* moho::j_func_BlueprintLoaderUpdateProgress_LuaFuncDef()
{
  return func_BlueprintLoaderUpdateProgress_LuaFuncDef();
}

/**
 * Address: 0x0074B110 (FUN_0074B110, ?SIM_FromLuaState@Moho@@YAPAVSim@1@PAVLuaState@LuaPlus@@@Z)
 *
 * What it does:
 * Returns the global Sim pointer carried on the Lua state's global user-data.
 */
Sim* moho::SIM_FromLuaState(LuaPlus::LuaState* const state)
{
  return ResolveGlobalSim(state->m_state);
}

/**
 * Address: 0x0074B120 (FUN_0074B120, ?FlattenMapRect@Sim@Moho@@QAEXABV?$Rect2@H@gpg@@M@Z)
 * Mangled: ?FlattenMapRect@Sim@Moho@@QAEXABV?$Rect2@H@gpg@@M@Z
 *
 * IDA signature:
 * void __thiscall Moho::Sim::FlattenMapRect(Moho::Sim *this, const gpg::Rect2i &rect, float elevation);
 *
 * What it does:
 * Clamps the requested rect to the heightfield, stamps `elevation` into every
 * covered cell, records the flattened rect into both map-rect accumulation
 * lists, then re-seats each live land/seabed unit overlapping the flattened
 * area onto the new terrain.
 */
void Sim::FlattenMapRect(const gpg::Rect2i& rect, const float elevation)
{
  CHeightField* const heightField = mMapData->mHeightField.get();

  // Clamp the requested rect (expanded by one on the far edges) to the map's
  // valid cell range: [x0, min(width-1, x1+1)] x [z0, min(height-1, z1+1)].
  gpg::Rect2i clampedRect{};
  clampedRect.x0 = rect.x0;
  clampedRect.z0 = rect.z0;
  clampedRect.x1 = std::min(heightField->width - 1, rect.x1 + 1);
  clampedRect.z1 = std::min(heightField->height - 1, rect.z1 + 1);

  if (rect.x0 >= clampedRect.x1 || rect.z0 >= clampedRect.z1) {
    gpg::Warnf(kFlattenMapRectOutsideBoundaryWarning);
    return;
  }

  heightField->SetElevationRect(clampedRect, &elevation);
  SIM_NoteFlatten({clampedRect.x0, clampedRect.z0, clampedRect.x1, clampedRect.z1, elevation}); // keyframes

  // Record the flattened rect (near edges pulled back by one, far edges kept
  // clamped) into the cached and loaded map-rect lists.
  const int loX = std::max(0, rect.x0 - 1);
  const int loZ = std::max(0, rect.z0 - 1);
  const gpg::Rect2i flattenedRect{loX, loZ, clampedRect.x1, clampedRect.z1};
  mCachedMapRects.push_back(flattenedRect);
  mLoadedMapRects.push_back(flattenedRect);

  // Build the world-space query box covering the flattened area. Center is the
  // rect midpoint; extents span the full clamped rect (Y half-extent 100).
  Wm3::Vector3f boxCenter{};
  boxCenter.x = static_cast<float>(loX + clampedRect.x1) * 0.5f;
  boxCenter.y = 0.0f;
  boxCenter.z = static_cast<float>(loZ + clampedRect.z1) * 0.5f;

  Wm3::Vector3f boxExtents{};
  boxExtents.x = static_cast<float>(clampedRect.x1 - loX);
  boxExtents.y = 100.0f;
  boxExtents.z = static_cast<float>(clampedRect.z1 - loZ);

  const VAxes3 boxAxes{Wm3::Quaternionf(0.0f, 0.0f, 0.0f, 0.0f)};
  const Wm3::Box3f queryBox{boxCenter, &boxAxes.vX, &boxExtents.x};

  gpg::core::FastVectorN<CollisionResult, 10> hits{};
  mOGrid->CollectEntitiesInBox(hits, ENTITYTYPE_Unit, queryBox);

  for (const CollisionResult& hit : hits) {
    Unit* const unit = hit.sourceEntity->IsUnit();
    if (unit == nullptr) {
      continue;
    }
    if (unit->IsDead() || unit->DestroyQueued()) {
      continue;
    }
    if (unit->mVarDat.mLayerMask != LAYER_Land && unit->mVarDat.mLayerMask != LAYER_Seabed) {
      continue;
    }

    CUnitMotion* const motion = unit->UnitMotion;
    if (motion != nullptr) {
      // Defer the re-seat to the motion controller's next surface-collision pass.
      motion->mProcessSurfaceCollision = true;
      continue;
    }

    // No motion controller: warp the unit onto the freshly-flattened terrain now.
    unit->Warp(unit->GetTransform());
  }
}

/**
 * Address: 0x00707D60 (FUN_00707D60, ?ARMY_FromLuaState@Moho@@YAPAVSimArmy@1@PAVLuaState@LuaPlus@@VLuaObject@4@@Z)
 *
 * What it does:
 * Resolves a Lua army selector (number or name) into `CArmyImpl*`.
 */
CArmyImpl* moho::ARMY_FromLuaState(LuaPlus::LuaState* const state, const LuaPlus::LuaObject& armyObject)
{
  Sim* const sim = SIM_FromLuaState(state);
  if (!sim) {
    return nullptr;
  }

  if (armyObject.IsNumber()) {
    const int requestedArmy = armyObject.GetInteger();
    const int zeroBasedArmy = requestedArmy - 1;
    CArmyImpl* army = nullptr;

    if (zeroBasedArmy >= 0 && static_cast<std::size_t>(zeroBasedArmy) < sim->mArmiesList.size()) {
      army = sim->mArmiesList[static_cast<std::size_t>(zeroBasedArmy)];
    }

    if (!army) {
      if (zeroBasedArmy >= 0) {
        LuaPlus::LuaState::Error(state, "Invalid army %d", zeroBasedArmy);
      } else {
        LuaPlus::LuaState::Error(state, "Invalid army %d. (Use a 1-based index)", requestedArmy);
      }
    }
    return army;
  }

  if (armyObject.IsString()) {
    const std::string_view armyName = armyObject.GetString() ? armyObject.GetString() : "";
    const ArmyListCursor begin = sim->mArmiesList.begin();
    const ArmyListCursor end = sim->mArmiesList.end();
    const ArmyListCursor match = func_GetArmyWithName(begin, end, armyName);

    if (match == end) {
      LuaPlus::LuaState::Error(state, kUnknownArmyMessage, armyName.data());
      return nullptr;
    }

    return *match;
  }

  LuaPlus::LuaState::Error(state, kUnexpectedArmyTypeMessage);
  return nullptr;
}

/**
 * Address: 0x00707F40 (FUN_00707F40, ?ARMY_IndexFromLuaState@Moho@@YAHPAVLuaState@LuaPlus@@VLuaObject@3@@Z)
 *
 * What it does:
 * Resolves a Lua army selector (number or name) into a zero-based index.
 */
int moho::ARMY_IndexFromLuaState(LuaPlus::LuaState* const state, const LuaPlus::LuaObject& armyObject)
{
  Sim* const sim = SIM_FromLuaState(state);
  if (!sim) {
    return -1;
  }

  if (armyObject.IsNumber()) {
    const int requestedArmy = armyObject.GetInteger();
    if (requestedArmy > 0) {
      return requestedArmy - 1;
    }

    if (requestedArmy == 0) {
      LuaPlus::LuaState::Error(state, "Invalid army %d, (Use a 1-based index)", 0);
    }
    return -1;
  }

  if (armyObject.IsString()) {
    const std::string_view armyName = armyObject.GetString() ? armyObject.GetString() : "";
    const ArmyListCursor begin = sim->mArmiesList.begin();
    const ArmyListCursor end = sim->mArmiesList.end();
    const ArmyListCursor match = func_GetArmyWithName(begin, end, armyName);

    if (match == end) {
      LuaPlus::LuaState::Error(state, kUnknownArmyMessage, armyName.data());
      return -1;
    }

    CArmyImpl* const army = *match;
    return army ? army->mConstDat.mArmyIndex : -1;
  }

  return -1;
}

gpg::RType* Sim::sType = nullptr;
namespace
{
  // Address: 0x010BA3F0 -- process-global `SimSerializer` singleton.
  SimSerializer gSimSerializer;
}



/**
 * Address: 0x00BDBC90 (FUN_00BDBC90, dynamic initializer for the global
 * `SimSerializer` singleton)
 */
SimSerializer::SimSerializer()
  : mSerLoadFunc(&SimSerializerLoadThunk)
  , mSerSaveFunc(&SimSerializerSaveThunk)
{}

/**
 * Address: 0x0074CFB0 (FUN_0074CFB0, Moho::SimSerializer::Init)
 */
void SimSerializer::Init()
{
  gpg::RType* const type = gpg::LookupRType(typeid(Sim));
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mSerLoadFunc;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSerSaveFunc;
}

/**
 * Address: 0x007432B0 (FUN_007432B0, sub_7432B0)
 */
const char* SimTypeInfo::GetName() const
{
  return "Sim";
}

/**
 * Address: 0x00743290 (FUN_00743290, sub_743290)
 */
void SimTypeInfo::Init()
{
  size_ = sizeof(Sim);
  // 0x0074329A calls nullsub_45 (0x008D8680), which is RType::Init in this build.
  gpg::RType::Init();
  Finish();
}

/**
 * Address: 0x00743230 (FUN_00743230, preregister_SimTypeInfo)
 *
 * What it does:
 * Constructs/preregisters RTTI metadata for `moho::Sim`.
 */
[[nodiscard]] gpg::RType* preregister_SimTypeInfo()
{
  static SimTypeInfo typeInfo;
  gpg::PreRegisterRType(typeid(Sim), &typeInfo);
  return &typeInfo;
}
namespace moho
{

/**
 * Address: 0x00597CD0 (FUN_00597CD0, Moho::Sim::DoCollisionsFor)
 *
 * IDA signature:
 * void __cdecl Moho::Sim::DoCollisionsFor(Moho::Sim *sim, Moho::Unit *unit,
 *   gpg::fastvector_n<CollisionResult,10> *collisions);
 *
 * What it does:
 * Physical surface-collision resolution for `unit` against the pre-gathered
 * `collisions` box query. See header. The impulse math is a mass-weighted
 * separation along the XZ plane.
 */
void Sim::DoCollisionsFor(
  Sim* const sim, Unit* const owner, gpg::core::FastVectorN<CollisionResult, 10>* const collisions
)
{
  constexpr float kMinPenetration = 0.001f;      // dword_DFF0AC
  constexpr float kMinSeparationSq = 0.000001f;  // flt_DFFBE8 (1e-6)
  constexpr float kMaxSpeedFactor = 0.1f;        // dbl_E4F710+4
  constexpr float kMinPushFactor = 0.1f;         // dbl_E4F710+4 (reused as impulse-share cutoff)
  constexpr float kHalfExtentScale = 0.5f;       // flt_E4F724

  // Debug/dead/queued/naval short-circuits (asm 0x597CE4-0x597D26).
  if (ReadSimConVarBool(sim, &gSimConVar_AI_DebugCollision, false) || owner->mIsNaval || owner->IsDead() ||
      owner->DestroyQueued()) {
    return;
  }

  // Owner mass proxy + a per-owner approach-speed factor: the smaller of
  // (blueprint MaxSpeed * 0.1) and the current velocity magnitude
  // (asm 0x597D33-0x597DDA: `comiss share, speed; jbe` keeps `share` only
  // when it does not exceed `speed`). MaxSpeed lives at blueprint
  // Physics.MaxSpeed.
  const RUnitBlueprint* const ownerBlueprint = owner->GetBlueprint();
  const float ownerMass = BlueprintCollisionMass(*ownerBlueprint);

  const Wm3::Vec3f ownerVelocity = owner->GetVelocity();
  const float ownerSpeed =
    std::sqrt((ownerVelocity.x * ownerVelocity.x) + (ownerVelocity.y * ownerVelocity.y) +
      (ownerVelocity.z * ownerVelocity.z));
  const float maxSpeedShare = ownerBlueprint->Physics.MaxSpeed * kMaxSpeedFactor;
  const float approachSpeed = (maxSpeedShare > ownerSpeed) ? ownerSpeed : maxSpeedShare;

  for (const CollisionResult& hit : *collisions) {
    // Skip shallow contacts and empty records (asm 0x597E2D-0x597E4A).
    if (hit.penetrationDepth < kMinPenetration) {
      continue;
    }
    Entity* const contact = hit.sourceEntity;
    if (contact == nullptr) {
      continue;
    }

    // Props receive their OnCollision Lua callback (self, other, dir, depth).
    // `other` is the colliding unit: 0x00598660 pushes exactly one dword for
    // that argument (0x005986F5 `mov eax,[edx]` then `push eax` at
    // 0x00598700), alongside `self` copied from `this+0x20` and the four
    // floats, so what the Lua side receives is a single object pointer.
    //
    // This used to pass `*(const LuaPlus::LuaObject*)sim`, on the reading that
    // the shipped call's first argument slot holds the `Sim*`. It cannot:
    // `Sim` derives from `ICommandSink` and has nothing LuaObject-shaped at
    // offset 0, so `m_state` came out as the vtable pointer and LuaPlus threw
    // `state->l_G == m_state->m_state->l_G` on every prop collision - caught
    // and logged by `RunScriptOnCollision`, so the only symptom was that no
    // prop ever ran its collision script. IDA names that slot `a1` after
    // `DoCollisionsFor`'s first parameter, but MSVC reuses a dead argument
    // slot for a local and the decompile of this function is not reliable
    // enough to say which local; the Lua contract
    // `Prop:OnCollision(other, x, y, z, depth)` is.
    if (contact->IsProp() != nullptr) {
      contact->RunScriptOnCollision(
        owner,
        hit.direction.x,
        hit.direction.y,
        hit.direction.z,
        hit.penetrationDepth
      );
    }

    // Physical resolution only applies to unit contacts (asm 0x597EA9-0x597EB9).
    Unit* const candidate = contact->IsUnit();
    if (candidate == nullptr) {
      continue;
    }

    // Ignore "source" units (self/attached/air/etc.) and airborne colliders
    // (asm 0x597EBF-0x597ED9). mode 2 = blocker/collision-scan policy.
    if (func_IsSourceUnit(2, *owner, candidate) || candidate->mIsAir) {
      continue;
    }

    // Two units executing the exact same head command are cooperating (e.g.
    // one build order): abort the whole pass to avoid fighting them apart
    // (asm 0x597EDF-0x597F06).
    CUnitCommandQueue* const ownerQueue = owner->CommandQueue;
    if (ownerQueue->GetCurrentCommand() != nullptr) {
      CUnitCommand* const candidateCommand = candidate->CommandQueue->GetCurrentCommand();
      if (ownerQueue->GetCurrentCommand() == candidateCommand) {
        return;
      }
    }

    // Only mobile colliders on a different formation layer are resolved
    // (asm 0x597F0C-0x597F28).
    if (!candidate->IsMobile() || owner->IsSameFormationLayerWith(candidate)) {
      continue;
    }

    // Separation direction on the XZ plane, from the candidate's current
    // position toward the owner's previous-frame ("last move") position. The
    // Hex-Rays export labels the owner reference as `mVarDat.mLastTransform.pos`
    // (asm 0x597F3A/0x597F47); AdvanceCoords (FUN_00678F10, asm 0x678F20 copy)
    // proves `mVarDat.mLastTransform` is the Entity previous-frame transform at
    // +0xB8 whose position lane is Entity::PrevPosition (+0xC8) — accessed by
    // name here rather than through the export's mis-sized offsets.
    const Wm3::Vec3f& candidatePos = candidate->GetPosition();
    Wm3::Vector3f pushDir{};
    pushDir.x = owner->mVarDat.mLastTransform.pos_.x - candidatePos.x;
    pushDir.y = 0.0f;
    pushDir.z = owner->mVarDat.mLastTransform.pos_.z - candidatePos.z;

    // Coincident units get a random XZ jitter so they can still separate
    // (asm 0x597F73-0x597FD5).
    const float separationSq = (pushDir.z * pushDir.z) + (pushDir.x * pushDir.x);
    if (separationSq < kMinSeparationSq) {
      CRandomStream* const rng = sim->mRngState;
      pushDir.x = rng->FRand(-1.0f, 1.0f);
      pushDir.y = 0.0f;
      pushDir.z = rng->FRand(-1.0f, 1.0f);
    }
    Wm3::Vector3f::Normalize(&pushDir);

    // Push magnitude = max(halfMaxFootprint, penetration) + approachSpeed
    // (asm 0x597FE4-0x59802B). halfMaxFootprint = 0.5 * max(sizeX, sizeZ).
    float maxFootprintDim = ownerBlueprint->mSizeX;
    if (ownerBlueprint->mSizeZ > maxFootprintDim) {
      maxFootprintDim = ownerBlueprint->mSizeZ;
    }
    // 0x0059800A-0x0059801B: `comiss half, depth` / `jbe` keeps the depth, so
    // an unordered depth (not rejected by the 0.001 gate above) survives.
    const float halfFootprint = maxFootprintDim * kHalfExtentScale;
    float pushMagnitude = hit.penetrationDepth;
    if (halfFootprint > pushMagnitude) {
      pushMagnitude = halfFootprint;
    }
    pushMagnitude += approachSpeed;

    // Mass-weighted momentum split (asm 0x598031-0x59807A):
    //   candidateShare = ownerMass / (ownerMass + candidateMass)
    //   ownerShare     = 1 - candidateShare
    // A heavier owner claims a larger candidateShare, shoving the candidate
    // more while itself yielding less. The two AddImpulse branches below apply
    // these complementary shares.
    const float candidateMass = BlueprintCollisionMass(*candidate->GetBlueprint());
    const float candidateShare = ownerMass / (candidateMass + ownerMass);
    const float ownerShare = 1.0f - candidateShare;

    // Owner impulse (asm 0x598080-0x59811F): pushes the owner away from the
    // candidate, scaled by pushMagnitude and the owner's share.
    if (ownerShare > kMinPushFactor && CollisionImpulseAllowed(*owner, *candidate) &&
        !owner->IsUnitState(UNITSTATE_Immobile)) {
      const Wm3::Vector3f ownerImpulse{
        (pushDir.x * pushMagnitude) * ownerShare,
        (pushDir.y * pushMagnitude) * ownerShare,
        (pushDir.z * pushMagnitude) * ownerShare,
      };
      owner->UnitMotion->AddImpulse(ownerImpulse, false);
    }

    // Candidate impulse (asm 0x598131-0x5981E3): pushes the candidate the
    // opposite way (negated pushDir), scaled by pushMagnitude and the
    // candidate's share.
    if (candidateShare > kMinPushFactor && CollisionImpulseAllowed(*candidate, *owner) &&
        !candidate->IsUnitState(UNITSTATE_Immobile)) {
      const Wm3::Vector3f candidateImpulse{
        (-pushDir.x * pushMagnitude) * candidateShare,
        (-pushDir.y * pushMagnitude) * candidateShare,
        (-pushDir.z * pushMagnitude) * candidateShare,
      };
      candidate->UnitMotion->AddImpulse(candidateImpulse, false);
    }
  }
}

/**
 * Address: 0x0062DA50 (FUN_0062DA50, ?LocationIsFree@Sim@Moho@@SA_NPAV12@PAVUnit@2@PAV?$Rect2@H@gpg@@D@Z)
 *
 * IDA signature:
 * bool __cdecl Moho::Sim::LocationIsFree(Moho::Sim *sim, Moho::Unit *ignore,
 *   gpg::Rect2i *loc, char requireIdle);
 *
 * What it does:
 * Returns true when the ogrid cell rectangle `loc` is clear of live blocking
 * units (see header).
 */
bool Sim::LocationIsFree(Sim* const sim, Unit* const ignore, gpg::Rect2i* const loc, const char requireIdle)
{
  // Identity-oriented query box centered on the rect, Y half-extent 100.
  Wm3::Vector3f boxCenter{};
  boxCenter.x = static_cast<float>(loc->x0 + loc->x1) * 0.5f;
  boxCenter.y = 0.0f;
  boxCenter.z = static_cast<float>(loc->z0 + loc->z1) * 0.5f;

  Wm3::Vector3f boxExtents{};
  boxExtents.x = static_cast<float>(loc->x1 - loc->x0) * 0.5f;
  boxExtents.y = 100.0f;
  boxExtents.z = static_cast<float>(loc->z1 - loc->z0) * 0.5f;

  const VAxes3 boxAxes{Wm3::Quaternionf(1.0f, 0.0f, 0.0f, 0.0f)};
  const Wm3::Box3f queryBox{boxCenter, &boxAxes.vX, &boxExtents.x};

  gpg::core::FastVectorN<CollisionResult, 10> hits{};
  sim->mOGrid->CollectEntitiesInBox(hits, ENTITYTYPE_Unit, queryBox);

  for (const CollisionResult& hit : hits) {
    Unit* const unit = hit.sourceEntity->IsUnit();
    if (unit == nullptr) {
      continue;
    }
    if (unit->IsDead() || unit == ignore) {
      continue;
    }

    // requireIdle gate: only idle units (no active head command) count as
    // blockers. Idle = null queue, empty queue, or a null/sentinel head weak-ptr.
    if (requireIdle) {
      CUnitCommandQueue* const queue = unit->CommandQueue;
      bool idle = (queue == nullptr);
      if (!idle) {
        const msvc8::vector<WeakPtr<CUnitCommand>>& commands = queue->mCommandVec;
        if (commands.empty()) {
          idle = true;
        } else {
          const WeakPtr<CUnitCommand>& head = commands.data()[0];
          idle = head.GetObjectPtr() == nullptr;
        }
      }
      if (!idle) {
        continue;
      }
    }

    if (unit->mVarDat.mLayerMask == LAYER_Air) {
      continue;
    }

    bool blocks;
    if (unit->IsMobile()) {
      blocks = true;
    } else {
      // Static unit: blocks only when its blueprint skirt rect overlaps `loc`.
      const Wm3::Vec3f& unitPos = unit->GetPosition();
      SCoordsVec2 unitCoords{};
      unitCoords.x = unitPos.x;
      unitCoords.z = unitPos.z;
      const gpg::Rect2f skirt = unit->GetBlueprint()->GetSkirtRect(unitCoords);

      const float locX1 = static_cast<float>(loc->x1);
      const float locX0 = static_cast<float>(loc->x0);
      const float locZ0 = static_cast<float>(loc->z0);
      const float locZ1 = static_cast<float>(loc->z1);
      blocks = locX1 > skirt.x0 && skirt.x1 > locX0 && locZ1 > skirt.z0 && skirt.z1 > locZ0 &&
        skirt.x1 > skirt.x0 && skirt.z0 < skirt.z1 && locX1 > locX0 && locZ0 < locZ1;
    }

    if (blocks) {
      // Blocking unit found. Exempt it only if it is stored in `ignore`'s transport.
      if (ignore == nullptr) {
        return false;
      }
      IAiTransport* const transport = ignore->AiTransport;
      if (transport == nullptr || !transport->TransportIsStoredUnit(unit)) {
        return false;
      }
    }
  }

  return true;
}
namespace
{
  // Per-cell displacement gate shared by both search phases. (cellCenterX,
  // cellCenterZ) is the candidate footprint-center; on success writes the
  // reserved rect and returns true. Mirrors FUN_0062DD40 asm 0x62E235-0x62E42E.
  [[nodiscard]] bool TryDisplacementCell(
    Sim& sim, COGrid& oGrid, Unit& blocker, const SFootprint& footprint,
    const gpg::Rect2i& buildRect, const float cellCenterX, const float cellCenterZ,
    gpg::Rect2i& outRect)
  {
    const int x0 = static_cast<int>(std::lrint(cellCenterX - static_cast<float>(footprint.mSizeX) * 0.5f));
    const int z0 = static_cast<int>(std::lrint(cellCenterZ - static_cast<float>(footprint.mSizeZ) * 0.5f));
    gpg::Rect2i rect{};
    rect.x0 = static_cast<std::int16_t>(x0);
    rect.z0 = static_cast<std::int16_t>(z0);
    rect.x1 = static_cast<std::int16_t>(x0 + footprint.mSizeX);
    rect.z1 = static_cast<std::int16_t>(z0 + footprint.mSizeZ);

    // Only test cells that (partly) escape the build rect; a candidate fully
    // inside the rect (and non-degenerate) is skipped.
    const bool insideAndValid = rect.x1 >= buildRect.x0 && buildRect.x1 >= rect.x0 &&
      rect.z1 >= buildRect.z0 && buildRect.z1 >= rect.z0 && buildRect.x0 < buildRect.x1 &&
      buildRect.z0 < buildRect.z1 && rect.x0 < rect.x1 && rect.z0 < rect.z1;
    if (insideAndValid) {
      return false;
    }

    const SOCellPos cellPos{static_cast<std::int16_t>(x0), static_cast<std::int16_t>(z0)};
    EOccupancyCaps caps = OCCUPY_MobileCheck(footprint, *sim.mMapData, cellPos);
    if (blocker.mVarDat.mLayerMask == LAYER_Water) {
      caps = static_cast<EOccupancyCaps>(
        static_cast<std::uint8_t>(caps) & ~static_cast<std::uint8_t>(EOccupancyCaps::OC_SUB));
    }
    if (static_cast<std::uint8_t>(OCCUPY_FootprintFits(oGrid, cellPos, footprint, caps)) == 0) {
      return false;
    }
    if (!blocker.CanReserveOgridRect(rect)) {
      return false;
    }
    if (!Sim::LocationIsFree(&sim, &blocker, &rect, 0)) {
      return false;
    }
    outRect = rect;
    return true;
  }

  // Phase 1: integer DDA line walk from the blocker toward a point pushed 3x the
  // rect extent along the escape direction, reconstructed from struct_Line
  // (FUN_0040D860, step=1) + the walk (FUN_0062DD40 asm 0x62E1E0-0x62E4AB).
  [[nodiscard]] bool TryPlaceAlongLine(
    Sim& sim, COGrid& oGrid, Unit& blocker, const SFootprint& footprint,
    const gpg::Rect2i& buildRect, const float blockerX, const float blockerZ,
    const float farX, const float farZ, gpg::Rect2i& outRect)
  {
    const float x1 = farX + 0.5f;      // far
    const float x2 = blockerX + 0.5f;  // blocker
    const float z1 = blockerZ + 0.5f;  // blocker
    const float z2 = farZ + 0.5f;      // far

    // FUN_0040D860: each axis runs blocker -> far, mirrored (and masked) when
    // the far end lies below the blocker.
    const int dirMaskX = (x1 < x2) ? -1 : 0;
    const float p0x = (dirMaskX != 0) ? -x2 : x2;  // cursorX origin (blocker)
    const float p0z = (dirMaskX != 0) ? -x1 : x1;  // xLimit (far)
    const int dirMaskZ = (z2 < z1) ? -1 : 0;
    const float p0y = (dirMaskZ != 0) ? -z1 : z1;  // cursorZ origin (blocker)
    const float p1x = (dirMaskZ != 0) ? -z2 : z2;  // zLimit (far)

    const float extentX = p0z - p0x;
    const float extentZ = p1x - p0y;
    // FUN_0040D860's inlined floor (0x0040D908, 0x0040D93A); the step-1 mask is -1.
    int cursorX = msvc8::FloorToIntX87(p0x);
    int cursorZ = msvc8::FloorToIntX87(p0y);

    for (;;) {
      const int cellDX = dirMaskX ^ cursorX;
      const int cellDZ = dirMaskZ ^ cursorZ;
      if (TryDisplacementCell(sim, oGrid, blocker, footprint, buildRect,
                              static_cast<float>(cellDX), static_cast<float>(cellDZ), outRect)) {
        return true;
      }

      const int advancedX = cursorX + 1;
      const int advancedZ = cursorZ + 1;
      const float errX = (static_cast<float>(advancedX) - p0z) * extentZ;
      const float errZ = (static_cast<float>(advancedZ) - p1x) * extentX;
      if (errZ <= errX) {
        cursorZ = advancedZ;
      } else {
        cursorX = advancedX;
      }
      if (static_cast<float>(cursorX) > p0z) {
        return false;
      }
      if (static_cast<float>(cursorZ) > p1x) {
        return false;
      }
    }
  }

  // Phase 2: expanding square-ring perimeter scan (900-cell cap), ring stride
  // 4*max(sizeX,sizeZ). Mirrors FUN_0062DD40 asm 0x62E4B1-0x62E90B.
  [[nodiscard]] bool TryPlaceInRing(
    Sim& sim, COGrid& oGrid, Unit& blocker, const SFootprint& footprint,
    const gpg::Rect2i& buildRect, gpg::Rect2i& outRect)
  {
    const int ringStep = 4 * std::max<int>(footprint.mSizeX, footprint.mSizeZ);
    const Wm3::Vec3f& pos = blocker.GetPosition();

    int cellsTested = 0;
    for (int radius = 1; cellsTested < 900; ++radius) {
      for (int row = -radius; row <= radius; ++row) {
        const int colStep = (row == -radius || row == radius) ? 1 : (2 * radius);
        for (int col = -radius; col <= radius; col += colStep) {
          ++cellsTested;
          // 0x0062E5A1..0x0062E626: the outer (row) offset moves along X and
          // the inner (column) offset along Z.
          const float cellX = pos.x + static_cast<float>(row * ringStep);
          const float cellZ = static_cast<float>(col * ringStep) + pos.z;
          if (TryDisplacementCell(sim, oGrid, blocker, footprint, buildRect, cellX, cellZ, outRect)) {
            return true;
          }
        }
      }
    }
    return false;
  }
}



/**
 * Address: 0x0062DD40 (FUN_0062DD40, Moho::SIM_TryToBuild)
 *
 * IDA signature:
 * void __cdecl Moho::SIM_TryToBuild(Moho::Sim *sim, Moho::CArmyImpl *army,
 *   gpg::Rect2i *rect, char requireIdle);
 *
 * What it does:
 * Clears a pending build rect of the army's own stationary/air mobile units by
 * relocating each to the nearest free footprint cell (a line walk toward the
 * rect, then an expanding ring scan), committing the new ogrid occupation and
 * issuing a one-cell navigator goal so the unit vacates the site.
 */
void SIM_TryToBuild(Sim* const sim, CArmyImpl* const army, gpg::Rect2i* const rect, const char requireIdle)
{
  COGrid* const oGrid = sim->mOGrid;

  const float centerX = static_cast<float>(rect->x0 + rect->x1) * 0.5f;
  const float centerZ = static_cast<float>(rect->z0 + rect->z1) * 0.5f;

  Wm3::Vector3f boxCenter{centerX, 0.0f, centerZ};
  Wm3::Vector3f boxExtents{};
  boxExtents.x = static_cast<float>(rect->x1 - rect->x0) * 0.5f;
  boxExtents.y = 100.0f;
  boxExtents.z = static_cast<float>(rect->z1 - rect->z0) * 0.5f;

  const float pushExtent = (boxExtents.z > boxExtents.x) ? boxExtents.z : boxExtents.x;

  const VAxes3 boxAxes{Wm3::Quaternionf(1.0f, 0.0f, 0.0f, 0.0f)};
  const Wm3::Box3f queryBox{boxCenter, &boxAxes.vX, &boxExtents.x};

  gpg::core::FastVectorN<CollisionResult, 10> hits{};
  oGrid->CollectEntitiesInBox(hits, ENTITYTYPE_Unit, queryBox);

  // Collect our own mobile blockers that are air or currently at rest (moving
  // ground units will clear on their own), not in the air layer, not dead, and
  // (when requireIdle) idle.
  std::vector<Unit*> blockers{};
  for (const CollisionResult& hit : hits) {
    Unit* const unit = hit.sourceEntity->IsUnit();
    if (unit == nullptr || !unit->IsMobile()) {
      continue;
    }
    const bool airOrAtRest =
      unit->mIsAir || (unit->mVarDat.mCurTransform.pos_ == unit->mVarDat.mLastTransform.pos_);
    if (!airOrAtRest || unit->mVarDat.mLayerMask == LAYER_Air || unit->IsDead()) {
      continue;
    }
    if (unit->ArmyRef != army) {
      continue;
    }
    if (requireIdle && !unit->IsIdleState()) {
      continue;
    }
    blockers.push_back(unit);
  }

  for (Unit* const blocker : blockers) {
    const SFootprint& footprint = blocker->GetFootprint();
    gpg::Rect2i placedRect{};
    bool placed = false;

    // Phase 1: line walk toward a point pushed away from the rect center.
    const Wm3::Vec3f& blockerPos = blocker->GetPosition();
    float dirX = blockerPos.x - centerX;
    float dirZ = blockerPos.z - centerZ;
    Wm3::Vector3f delta{dirX, 0.0f, dirZ};
    const Wm3::Vector3f zeroVec{0.0f, 0.0f, 0.0f};
    float unitDirX;
    float unitDirZ;
    if (delta == zeroVec) {
      unitDirX = 0.0f;
      unitDirZ = 1.0f;
    } else {
      const float len = std::sqrt((dirX * dirX) + (dirZ * dirZ));
      if (len <= 0.000001f) {
        unitDirX = 0.0f;
        unitDirZ = 0.0f;
      } else {
        // 0x0062E0A9..0x0062E0D8: one reciprocal, multiplied into each lane.
        const float inverseLength = 1.0f / len;
        unitDirX = dirX * inverseLength;
        unitDirZ = dirZ * inverseLength;
      }
    }
    const float farX = blockerPos.x + (unitDirX * pushExtent) * 3.0f;
    const float farZ = blockerPos.z + (unitDirZ * pushExtent) * 3.0f;
    placed = TryPlaceAlongLine(*sim, *oGrid, *blocker, footprint, *rect,
                               blockerPos.x, blockerPos.z, farX, farZ, placedRect);

    // Phase 2: expanding ring scan if the line walk found no free cell.
    if (!placed) {
      placed = TryPlaceInRing(*sim, *oGrid, *blocker, footprint, *rect, placedRect);
    }
    if (!placed) {
      continue;
    }

    blocker->FreeOgridRect();
    blocker->ReservedOgridRectMinX = placedRect.x0;
    blocker->ReservedOgridRectMinZ = placedRect.z0;
    blocker->ReservedOgridRectMaxX = placedRect.x1;
    blocker->ReservedOgridRectMaxZ = placedRect.z1;
    blocker->SimulationRef->mOGrid->OccupyRect(placedRect);

    if (IAiNavigator* const navigator = blocker->AiNavigator) {
      const SOCellPos goalCell{static_cast<std::int16_t>(placedRect.x0), static_cast<std::int16_t>(placedRect.z0)};
      const SNavGoal goal{goalCell};
      navigator->SetGoal(goal);
    }
  }

  // 0x0062EA31..0x0062EA4F: every collected blocker -- placed or not -- then
  // gives its reserved rect back; only the navigator goals remain.
  for (Unit* const blocker : blockers) {
    blocker->FreeOgridRect();
  }
}
}




// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(preregister_SimTypeInfo_e0dc23, preregister_SimTypeInfo)

namespace
{
  /**
   * Drives this file's Lua binder registrations.
   *
   * In the shipped binary each `register_*_LuaFuncDef` thunk is a
   * compiler-generated dynamic initializer, so the CRT's static-init array
   * calls every one of them before `main`. Nothing in this tree reproduces
   * that array, so a recovered thunk that no source line names is simply
   * never run - the binder is never constructed, the form never joins its
   * init-form set, and the global it publishes is missing at runtime with no
   * diagnostic beyond FAF's own "access to nonexistent global variable".
   *
   * This object is that call, and it is also the source-level invocation
   * that keeps the thunks out of the linker's dead-strip.
   */
  struct SimLuaBinderBootstrap
  {
    SimLuaBinderBootstrap()
    {
      (void)::moho::register_RegisterUnitBlueprint_LuaFuncDef();
      (void)::moho::register_RegisterPropBlueprint_LuaFuncDef();
      (void)::moho::register_RegisterProjectileBlueprint_LuaFuncDef();
      (void)::moho::register_RegisterMeshBlueprint_LuaFuncDef();
      (void)::moho::register_RegisterTrailEmitterBlueprint_LuaFuncDef();
      (void)::moho::register_RegisterEmitterBlueprint_LuaFuncDef();
    }
  };

  const SimLuaBinderBootstrap gSimLuaBinderBootstrap{};
} // namespace
namespace
{
  /**
   * Drives this file's Lua binder definitions.
   *
   * Each `func_*_LuaFuncDef` builds a function-local `CScrLuaBinder` and
   * links it into its init-form set. In the shipped binary they are reached
   * through compiler-generated dynamic initializers that the CRT's static-init
   * array runs before `main`; nothing here reproduces that array, so a
   * definition no source line names is never run - the binder is never
   * constructed, the form never joins its set, and the Lua global or method it
   * publishes is simply absent, with no diagnostic beyond FAF's own "access to
   * nonexistent global variable".
   *
   * This object is that call, and the source-level invocation that keeps these
   * definitions off the linker's dead-strip list.
   */
  struct SimLuaFuncDefBootstrap
  {
    SimLuaFuncDefBootstrap()
    {
      (void)::moho::func_SpecFootprints_LuaFuncDef();
      (void)::moho::func_RandomSim_LuaFuncDef();
      (void)::moho::func_SelectedUnit_LuaFuncDef();
      (void)::moho::func_SimConExecute_LuaFuncDef();
      (void)::moho::func_TryCopyPose_LuaFuncDef();
      (void)::moho::func_FlattenMapRect_LuaFuncDef();
      (void)::moho::func_ParseEntityCategorySim_LuaFuncDef();
      (void)::moho::func_EntityCategoryContainsSim_LuaFuncDef();
      (void)::moho::func_EntityCategoryFilterDownSim_LuaFuncDef();
      (void)::moho::func_EntityCategoryCount_LuaFuncDef();
      (void)::moho::func_EntityCategoryCountAroundPosition_LuaFuncDef();
      (void)::moho::func_Warp_LuaFuncDef();
      (void)::moho::func_ChangeUnitArmy_LuaFuncDef();
      (void)::moho::func_DebugGetSelection_LuaFuncDef();
      (void)::moho::func_IsEntity_LuaFuncDef();
      (void)::moho::func_IsUnit_LuaFuncDef();
      (void)::moho::func_IsProp_LuaFuncDef();
      (void)::moho::func_IsBlip_LuaFuncDef();
      (void)::moho::func_IsProjectile_LuaFuncDef();
      (void)::moho::func_IsCollisionBeam_LuaFuncDef();
      (void)::moho::func_BlueprintLoaderUpdateProgress_LuaFuncDef();
      (void)::moho::func_RegisterBeamBlueprint_LuaFuncDef();
      (void)::moho::func_SessionIsReplaySim_LuaFuncDef();
      (void)::moho::func_SetFocusArmySim_LuaFuncDef();
      (void)::moho::func_GetTimeForProfileSim_LuaFuncDef();
      (void)::moho::func_GetMouseWorldPosSim_LuaFuncDef();
      (void)::moho::func_GetDepositsAroundPoint_LuaFuncDef();
      (void)::moho::func_SetCommandSourceSim_LuaFuncDef();
      // FAF FA-Binary-Patches additions, not in the shipped registration sequence.
      (void)::moho::func_printSim_LuaFuncDef();
      (void)::moho::func_CheatsEnabled_LuaFuncDef();
      (void)::moho::func_GetCurrentCommandSource_LuaFuncDef();
      (void)::moho::func_GenerateRandomOrientation_LuaFuncDef();
      (void)::moho::func_GetGameTimeSecondsSim_LuaFuncDef();
      (void)::moho::func_GetGameTick_LuaFuncDef();
      (void)::moho::func_GetSystemTimeSecondsOnlyForProfileUse_LuaFuncDef();
      (void)::moho::func_GetEntitiesInRect_LuaFuncDef();
      (void)::moho::func_GetUnitsInRect_LuaFuncDef();
      (void)::moho::func_GetReclaimablesInRect_LuaFuncDef();
      (void)::moho::func_GetMapSize_LuaFuncDef();
      (void)::moho::func_GetTerrainHeight_LuaFuncDef();
      (void)::moho::func_GetSurfaceHeight_LuaFuncDef();
      (void)::moho::func_GetTerrainTypeOffset_LuaFuncDef();
      (void)::moho::func_GetTerrainType_LuaFuncDef();
      (void)::moho::func_SetTerrainType_LuaFuncDef();
      (void)::moho::func_SetTerrainTypeRect_LuaFuncDef();
      (void)::moho::func_FlushIntelInRect_LuaFuncDef();
      (void)::moho::func_SetArmyStatsSyncArmy_LuaFuncDef();
      (void)::moho::func_GetUnitBlueprintByName_LuaFuncDef();
      (void)::moho::func_DrawLine_LuaFuncDef();
      (void)::moho::func_DrawLinePop_LuaFuncDef();
      (void)::moho::func_DrawCircle_LuaFuncDef();
      (void)::moho::func_EntityAttachTo_LuaFuncDef();
      (void)::moho::func_EntitySetOrientation_LuaFuncDef();
      (void)::moho::func_EntitySetPosition_LuaFuncDef();
      (void)::moho::func_EntityGetPosition_LuaFuncDef();
      (void)::moho::func_EntityGetPositionXYZ_LuaFuncDef();
      (void)::moho::func_EntityIsIntelEnabled_LuaFuncDef();
      (void)::moho::func_EntityEnableIntel_LuaFuncDef();
      (void)::moho::func_EntityDisableIntel_LuaFuncDef();
      (void)::moho::func_EntitySetIntelRadius_LuaFuncDef();
      (void)::moho::func_EntityGetIntelRadius_LuaFuncDef();
      (void)::moho::func_EntityInitIntel_LuaFuncDef();
      (void)::moho::func_EntityAddShooter_LuaFuncDef();
      (void)::moho::func_EntityRemoveShooter_LuaFuncDef();
      (void)::moho::func_CreateProp_LuaFuncDef();
      (void)::moho::func_EntityCreatePropAtBone_LuaFuncDef();
      (void)::moho::func_CreateResourceDeposit_LuaFuncDef();
      (void)::moho::func_ShouldCreateInitialArmyUnits_LuaFuncDef();
      (void)::moho::func_ListArmies_LuaFuncDef();
      (void)::moho::func_GetArmyBrain_LuaFuncDef();
      (void)::moho::func_SetArmyStart_LuaFuncDef();
      (void)::moho::func_GenerateArmyStart_LuaFuncDef();
      (void)::moho::func_ArmyInitializePrebuiltUnits_LuaFuncDef();
      (void)::moho::func_SetIgnoreArmyUnitCap_LuaFuncDef();
      (void)::moho::func_SetIgnorePlayableRect_LuaFuncDef();
      (void)::moho::func_IsAllySim_LuaFuncDef();
      (void)::moho::func_IsEnemySim_LuaFuncDef();
      (void)::moho::func_IsNeutralSim_LuaFuncDef();
      (void)::moho::func_ArmyIsCivilian_LuaFuncDef();
      (void)::moho::func_SetArmyFactionIndex_LuaFuncDef();
      (void)::moho::func_OkayToMessWithArmy_LuaFuncDef();
      (void)::moho::func_ArmyIsOutOfGame_LuaFuncDef();
      (void)::moho::func_SetArmyOutOfGame_LuaFuncDef();
      (void)::moho::func_SetAlliance_LuaFuncDef();
      (void)::moho::func_SetAllianceOneWay_LuaFuncDef();
      (void)::moho::func_SetAlliedVictory_LuaFuncDef();
      (void)::moho::func_ArmyGetHandicap_LuaFuncDef();
      (void)::moho::func_SetArmyEconomy_LuaFuncDef();
      (void)::moho::func_GetArmyUnitCostTotal_LuaFuncDef();
      (void)::moho::func_GetArmyUnitCap_LuaFuncDef();
      (void)::moho::func_SetArmyUnitCap_LuaFuncDef();
      (void)::moho::func_SetArmyAIPersonality_LuaFuncDef();
      (void)::moho::func_SetArmyShowScore_LuaFuncDef();
      (void)::moho::func_SetArmyPlans_LuaFuncDef();
      (void)::moho::func_InitializeArmyAI_LuaFuncDef();
      (void)::moho::func_SetArmyColor_LuaFuncDef();
      (void)::moho::func_EndGame_LuaFuncDef();
      (void)::moho::func_IsGameOver_LuaFuncDef();
      (void)::moho::func_GetEntityById_LuaFuncDef();
      (void)::moho::func_GetUnitByIdSim_LuaFuncDef();
      (void)::moho::func_SetPlayableRect_LuaFuncDef();
      (void)::moho::func_GetFocusArmySim_LuaFuncDef();
      (void)::moho::func_AudioSetLanguageSim_LuaFuncDef();
      (void)::moho::func_HasLocalizedVOSim_LuaFuncDef();
      (void)::moho::func_SubmitXMLArmyStats_LuaFuncDef();
      (void)::moho::func_PlayLoop_LuaFuncDef();
      (void)::moho::func_StopLoop_LuaFuncDef();
    }
  };

  const SimLuaFuncDefBootstrap gSimLuaFuncDefBootstrap{};
}

/**
 * Address: 0x00C00EC0 (FUN_00C00EC0, Moho::SimSerializer::~SimSerializer)
 */
SimSerializer::~SimSerializer() = default;

/**
 * Address: 0x007432C0 (FUN_007432C0, sub_7432C0)
 */
SimTypeInfo::~SimTypeInfo() = default;
