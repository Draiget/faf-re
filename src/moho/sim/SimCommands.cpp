#include "moho/sim/SimPrivate.h"

namespace
{




  CUnitCommand* FindCommandById(CCommandDB* commandDb, const CmdId cmdId)
  {
    if (!commandDb || !commandDb->commands.header_ptr()) {
      return nullptr;
    }

    auto it = commandDb->commands.find(cmdId);
    if (it == commandDb->commands.end()) {
      return nullptr;
    }

    // The map's mapped type is a CUnitCommand pointer, not a value: the binary's
    // node is {left,parent,right,key@0x0C,CUnitCommand*@0x10,color@0x14,isNil@0x15}
    // (see CommandDbMapNodeRuntime in CCommandDb.cpp), so the stored slot is
    // already the command pointer.
    return it->second;
  }

  void InitSimDebugEntitySet(EntitySetTemplate<Unit>& outSet)
  {
    outSet.mNext = &outSet;
    outSet.mPrev = &outSet;
    outSet.mVec.RebindInlineNoFree();
  }

  void DestroySimDebugEntitySet(EntitySetTemplate<Unit>& set)
  {
    set.mVec.ResetStorageToInline();

    if (set.mNext != nullptr && set.mPrev != nullptr) {
      set.ListUnlink();
      return;
    }

    set.mNext = &set;
    set.mPrev = &set;
  }

  CSimConCommand* FindSimConCommand(const std::string& commandName)
  {
    return moho::FindRegisteredSimConCommand(commandName);
  }

  [[nodiscard]]
  bool IsSimCommandWhitespace(const char ch) noexcept
  {
    return gpg::STR_IsAsciiWhitespace(ch);
  }

  enum class SimCommandTerminator
  {
    None,
    NextCommand,
    Comment,
  };

  void ParseOneSimCommand(const std::string& input, std::vector<std::string>& outTokens, std::string& outRemainder)
  {
    outTokens.clear();
    outRemainder.clear();

    std::string token;
    token.reserve(input.size());

    bool inQuotes = false;
    bool escaping = false;
    SimCommandTerminator terminator = SimCommandTerminator::None;
    std::size_t splitIndex = input.size();

    for (std::size_t i = 0; i < input.size(); ++i) {
      const char ch = input[i];

      if (escaping) {
        token.push_back(ch);
        escaping = false;
        continue;
      }

      if (inQuotes && ch == '\\') {
        escaping = true;
        continue;
      }

      if (ch == '"') {
        inQuotes = !inQuotes;
        continue;
      }

      if (!inQuotes && ch == ';') {
        terminator = SimCommandTerminator::NextCommand;
        splitIndex = i;
        break;
      }

      if (!inQuotes && ch == '#') {
        terminator = SimCommandTerminator::Comment;
        splitIndex = i;
        break;
      }

      if (!inQuotes && IsSimCommandWhitespace(ch)) {
        if (!token.empty()) {
          outTokens.push_back(token);
          token.clear();
        }
        continue;
      }

      token.push_back(ch);
    }

    if (escaping) {
      token.push_back('\\');
    }

    if (!token.empty()) {
      outTokens.push_back(token);
    }

    if (terminator == SimCommandTerminator::NextCommand && splitIndex + 1u <= input.size()) {
      outRemainder.assign(input, splitIndex + 1u, std::string::npos);
      return;
    }

    outRemainder.clear();
  }

  [[nodiscard]]
  bool SimCommandTokenNeedsQuotes(const std::string& token)
  {
    if (token.empty()) {
      return true;
    }

    for (const char ch : token) {
      if (IsSimCommandWhitespace(ch) || ch == ';' || ch == '#') {
        return true;
      }
    }

    return false;
  }

  [[nodiscard]]
  std::string UnparseSimCommand(const std::vector<std::string>& tokens)
  {
    std::string text;

    for (std::size_t i = 0; i < tokens.size(); ++i) {
      if (i != 0u) {
        text.push_back(' ');
      }

      const std::string& token = tokens[i];
      if (!SimCommandTokenNeedsQuotes(token)) {
        text.append(token);
        continue;
      }

      text.push_back('"');
      for (const char ch : token) {
        if (ch == '\\' || ch == '"') {
          text.push_back('\\');
        }
        text.push_back(ch);
      }
      text.push_back('"');
    }

    return text;
  }
}


/**
 * Address: 0x007466D0 (FUN_007466D0, ?GetCurrentCommandSource@Sim@Moho@@QBEPBUSSTICommandSource@2@XZ)
 *
 * What it does:
 * Returns the current command-source lane, or `nullptr` for sentinel id.
 */
const SSTICommandSource* Sim::GetCurrentCommandSource() const
{
  const CommandSourceId sourceId = static_cast<CommandSourceId>(mCurCommandSource);
  if (sourceId == kInvalidCommandSource) {
    return nullptr;
  }

  return &mCommandSources[static_cast<std::size_t>(sourceId)];
}

/**
 * Address: 0x007466F0 (FUN_007466F0, ?GetCurrentCommandSourceName@Sim@Moho@@QBEPBDXZ)
 *
 * What it does:
 * Returns current command-source name or fallback sentinel text when source id is invalid.
 */
const char* Sim::GetCurrentCommandSourceName() const
{
  const SSTICommandSource* const source = GetCurrentCommandSource();
  if (!source) {
    return "???";
  }

  return source->mName.c_str();
}

/**
 * Address: 0x00748650 (FUN_00748650, ?SetCommandSource@Sim@Moho@@UAEXI@Z)
 */
void Sim::SetCommandSource(const CommandSourceId sourceId)
{
  if (sourceId == kInvalidCommandSource || sourceId < static_cast<CommandSourceId>(mCommandSources.size())) {
    mCurCommandSource = static_cast<int32_t>(sourceId);
    return;
  }

  gpg::Warnf("Sim::SetCommandSource(%d): invalid source -- ignoring following commands.", sourceId);
  mCurCommandSource = static_cast<int32_t>(kInvalidCommandSource);
}

/**
 * Address: 0x007486B0 (FUN_007486B0, ?OnCommandSourceTerminated@Sim@Moho@@UAEXXZ)
 */
void Sim::OnCommandSourceTerminated()
{
  Logf("Command source %s terminated tick %d\n", GetCurrentCommandSourceName(), mCurTick);
  mContext.Update(&mCurCommandSource, 4u);
  mContext.Update(&mCurTick, 4u);

  if (mPausedByCommandSource == mCurCommandSource) {
    Resume();
  }

  for (std::size_t i = 0; i < mArmiesList.size(); ++i) {
    CArmyImpl* army = mArmiesList[i];
    if (!army) {
      continue;
    }

    if (!army->mVarDat.mValidCommandSources.Contains(static_cast<uint32_t>(mCurCommandSource))) {
      continue;
    }

    army->OnCommandSourceTerminated(static_cast<uint32_t>(mCurCommandSource));
  }
}

/**
 * Address: 0x007491C0 (FUN_007491C0, ?ValidateNewCommandId@Sim@Moho@@AAE_NVCmdId@2@PBD@Z)
 *
 * CmdId, const char*
 *
 * What it does:
 * Validates one incoming command id against active command source byte and
 * rejects already-allocated command ids in the command DB map.
 *
 * Real disassembly calls `std::map_uint_CUnitCommand::find` (`sub_6E1940`,
 * cited on `rb_tree::find_node` in `RbTree.h`) directly against
 * `mCommandDB->mCommands` and rejects only when the found node is real and
 * its value is non-null (`a1 == head || !a1->_Myval.cmd` -> allow). It does
 * not null-check `mCommandDB` or the map head first -- both guards were a
 * `CCommandDb` reach-in artifact; `mCommandDB->commands` is
 * `CCommandDB`'s own real typed member (`CCommandDb.h`) and is always valid
 * once `Sim` is constructed.
 */
bool Sim::ValidateNewCommandId(const CmdId cmdId, const char* callsiteName) const
{
  const char* callsite = callsiteName ? callsiteName : "Sim";

  if (mCurCommandSource == kInvalidCommandSource) {
    gpg::Warnf("%s: ignoring issue of cmd id 0x%08x because there is no command source active.", callsite, cmdId);
    return false;
  }

  const uint32_t sourceByte = static_cast<uint32_t>(static_cast<uint8_t>(cmdId >> 24));
  const uint32_t currentSource = static_cast<uint32_t>(mCurCommandSource);
  if (sourceByte != currentSource) {
    gpg::Warnf(
      "%s: ignoring issue of cmd id 0x%08x from %s because the id's source (%u) is wrong (should be %u)",
      callsite,
      cmdId,
      GetCurrentCommandSourceName(),
      sourceByte,
      currentSource
    );
    return false;
  }

  const auto existingIt = mCommandDB->commands.find(cmdId);
  if (existingIt == mCommandDB->commands.end() || existingIt->second == nullptr) {
    return true;
  }

  gpg::Warnf(
    "%s: ignoring issue of cmd id 0x%08x from %s because it is already in use.",
    callsite,
    cmdId,
    GetCurrentCommandSourceName()
  );
  return false;
}

/**
 * Address: 0x00749290 (FUN_00749290)
 *
 * What it does:
 * Validates command-id ownership, filters selected units through sim command
 * access rules, and forwards the recovered shared-command dispatch to unit
 * queues.
 */
void Sim::IssueCommand(
  const BVSet<EntId, EntIdUniverse>& entities, const SSTICommandIssueData& commandIssueData, const bool clearQueue
)
{
  if (!ValidateNewCommandId(commandIssueData.nextCommandId, "IssueCommand")) {
    return;
  }

  EntitySetTemplate<Unit> selectedUnits{};

  auto collectUnit = [this, &selectedUnits](const EntId entId) {
    Entity* entity = FindEntityById(mEntityDB, entId);
    if (!entity || !OkayToMessWith(entity)) {
      return;
    }

    Unit* unit = entity->IsUnit();
    if (!unit) {
      return;
    }

    (void)selectedUnits.Add(unit);
  };

  entities.ForEachValue([&collectUnit](const unsigned int value) {
    collectUnit(static_cast<EntId>(value));
  });

  // 0x00749411..0x0074945E: the DestroySelf cheat test follows the entity loop
  // directly, so CheatsEnabled() (which folds its flag into the checksum) runs
  // even when nothing was selected, and a refused order returns without
  // releasing the command id.
  if (commandIssueData.mCommandType == EUnitCommandType::UNITCOMMAND_DestroySelf && !CheatsEnabled()) {
    return;
  }

  if (selectedUnits.Empty()) {
    ReleaseCommandIdIfUnconsumed(mCommandDB, commandIssueData.nextCommandId);
    return;
  }

  (void)IssueCommandToSelectedUnits(this, selectedUnits, commandIssueData, clearQueue);
}

/**
 * Address: 0x007494B0 (FUN_007494B0)
 *
 * What it does:
 * Validates command-id ownership, gathers controllable factory units, and
 * issues one shared factory command to every eligible builder.
 */
void Sim::IssueFactoryCommand(
  const BVSet<EntId, EntIdUniverse>& entities, const SSTICommandIssueData& commandIssueData, const bool clearQueue
)
{
  if (!ValidateNewCommandId(commandIssueData.nextCommandId, "IssueFactoryCommand")) {
    return;
  }

  // 0x00749593 / 0x007495E8: unlike `IssueCommand`, an entity this command
  // source may not control (out-of-game army, or unauthorised without cheats)
  // abandons the whole order -- straight to the epilogue, nothing issued and
  // no id released. A missing entity or a non-unit is only skipped.
  EntitySetTemplate<Unit> selectedFactories{};
  bool rejected = false;
  entities.ForEachValue([this, &selectedFactories, &rejected](const unsigned int value) {
    if (rejected) {
      return;
    }

    Entity* const entity = FindEntityById(mEntityDB, static_cast<EntId>(value));
    if (!entity) {
      return;
    }
    if (!OkayToMessWith(entity)) {
      rejected = true;
      return;
    }

    if (Unit* const unit = entity->IsUnit(); unit != nullptr) {
      (void)selectedFactories.Add(unit);
    }
  });

  if (rejected) {
    return;
  }

  if (selectedFactories.Empty()) {
    ReleaseCommandIdIfUnconsumed(mCommandDB, commandIssueData.nextCommandId);
    return;
  }

  (void)IssueFactoryCommandToSelectedUnits(this, selectedFactories, commandIssueData, clearQueue);
}

/**
 * Address: 0x00749680 (FUN_00749680, ?IncreaseCommandCount@Sim@Moho@@UAEXVCmdId@2@H@Z)
 */
void Sim::IncreaseCommandCount(const CmdId cmdId, const int count)
{
  CUnitCommand* command = FindCommandById(mCommandDB, cmdId);
  if (command && OkayToMessWith(command)) {
    command->IncreaseCount(count);
  }
}

/**
 * Address: 0x007496E0 (FUN_007496E0, ?DecreaseCommandCount@Sim@Moho@@UAEXVCmdId@2@H@Z)
 */
void Sim::DecreaseCommandCount(const CmdId cmdId, const int count)
{
  CUnitCommand* command = FindCommandById(mCommandDB, cmdId);
  if (command && OkayToMessWith(command)) {
    command->DecreaseCount(count);
  }
}

/**
 * Address: 0x00749740 (FUN_00749740, ?SetCommandTarget@Sim@Moho@@UAEXVCmdId@2@ABUSSTITarget@2@@Z)
 */
void Sim::SetCommandTarget(const CmdId cmdId, const SSTITarget& target)
{
  CUnitCommand* command = FindCommandById(mCommandDB, cmdId);
  if (!command || !OkayToMessWith(command)) {
    return;
  }

  CAiTarget aiTarget{};
  aiTarget.DecodeFromSSTITarget(target, this);
  command->SetTarget(aiTarget);
}

/**
 * Address: 0x00749800 (FUN_00749800, ?SetCommandType@Sim@Moho@@UAEXVCmdId@2@W4EUnitCommandType@2@@Z)
 */
void Sim::SetCommandType(const CmdId cmdId, const EUnitCommandType commandType)
{
  CUnitCommand* command = FindCommandById(mCommandDB, cmdId);
  if (!command || !OkayToMessWith(command)) {
    return;
  }

  command->mVarDat.mCmdType = commandType;
  command->mNeedsUpdate = true;
}

/**
 * Address: 0x00749860 (FUN_00749860, ?SetCommandCells@Sim@Moho@@UAEXVCmdId@2@ABV?$fastvector@USOCellPos@Moho@@@gpg@@ABV?$Vector3@M@Wm3@@@Z)
 */
void Sim::SetCommandCells(
  const CmdId cmdId, const gpg::core::FastVector<SOCellPos>& cells, const Wm3::Vector3<float>& targetPosition
)
{
  CUnitCommand* command = FindCommandById(mCommandDB, cmdId);
  if (!command || !OkayToMessWith(command)) {
    return;
  }

  command->mVarDat.mCells.clear();
  command->mVarDat.mCells.reserve(cells.Size());
  for (std::size_t i = 0; i < cells.Size(); ++i) {
    command->mVarDat.mCells.push_back(cells[i]);
  }
  command->mNeedsUpdate = true;

  CAiTarget aiTarget{};
  aiTarget.targetType = EAiTargetType::AITARGET_Ground;
  aiTarget.position = targetPosition;
  aiTarget.targetPoint = -1;
  aiTarget.targetIsMobile = false;
  command->SetTarget(aiTarget);
}

/**
 * Address: 0x00749970 (FUN_00749970, ?RemoveCommandFromUnitQueue@Sim@Moho@@UAEXVCmdId@2@VEntId@2@@Z)
 */
void Sim::RemoveCommandFromUnitQueue(const CmdId cmdId, const EntId unitId)
{
  // 0x0074997B..0x007499F9: the unit comes from the sim's entity DB (not from
  // the command's own unit set), and the checks run entity, entity
  // permission, command, command permission -- in that order.
  Entity* const entity = FindEntityById(mEntityDB, unitId);
  CUnitCommand* const command = FindCommandById(mCommandDB, cmdId);
  if (!entity || !OkayToMessWith(entity)) {
    return;
  }
  if (!command || !OkayToMessWith(command)) {
    return;
  }

  Unit* const unit = entity->IsUnit();
  if (!unit || unit->IsDead()) {
    return;
  }

  CUnitCommandQueue* commandQueue = unit->CommandQueue;
  if (commandQueue && commandQueue->FindCommandIndex(command->mConstDat.cmd) != -1) {
    commandQueue->RemoveCommandFromQueue(command);
    return;
  }

  IAiBuilder* const builder = unit->AiBuilder;
  if (!builder) {
    return;
  }

  if (builder->BuilderContainsCommand(command)) {
    builder->BuilderRemoveFactoryCommand(command);
  }
}

/**
 * Address: 0x00734870 (FUN_00734870, func_TryParseSimCommand)
 *
 * IDA signature:
 * void __cdecl func_TryParseSimCommand(
 *   Moho::Sim *sim,
 *   char *commandText,
 *   Wm3::Vector3<float> *worldPos,
 *   Moho::CArmyImpl *focusArmy,
 *   Moho::EntitySetTemplate<Unit> *selectedUnits);
 *
 * What it does:
 * Parses one or more sim debug command segments, resolves each segment through
 * the global `simcons` registry, applies cheat gating, and dispatches through
 * CSimConCommand virtual handlers.
 */
void Sim::TryParseSimCommand(
  const char* command,
  const Wm3::Vector3<float>& worldPos,
  CArmyImpl* focusArmy,
  EntitySetTemplate<Unit>& selectedUnits
)
{
  const char* const rawCommandText = command ? command : "";
  std::string remaining = rawCommandText;
  Wm3::Vector3<float>* const mutableWorldPos = const_cast<Wm3::Vector3<float>*>(&worldPos);

  while (!remaining.empty()) {
    std::vector<std::string> parsedCommand;
    std::string nextCommandChain;
    ParseOneSimCommand(remaining, parsedCommand, nextCommandChain);

    if (!parsedCommand.empty()) {
      CSimConCommand* const simCommand = FindSimConCommand(parsedCommand.front());
      if (!simCommand) {
        Printf("Unknown sim command '%s' [invoked by %s]", parsedCommand.front().c_str(), GetCurrentCommandSourceName());
      } else {
        // 0x00734963 skips the check when the stored flag is nonzero.
        const bool requiresCheat = simCommand->mAllowWithoutCheats == 0;
        if (requiresCheat && !CheatsEnabled()) {
          return;
        }

        if (requiresCheat) {
          const std::string commandText = UnparseSimCommand(parsedCommand);
          Printf("%s: %s", GetCurrentCommandSourceName(), commandText.c_str());
        }

        try {
          (void)simCommand->Run(this, &parsedCommand, mutableWorldPos, focusArmy, &selectedUnits);
        } catch (const std::exception& ex) {
          const char* const errorText = ex.what() ? ex.what() : "<unknown>";
          gpg::Warnf("error running sim console command %s: %s", rawCommandText, errorText);

          if (requiresCheat) {
            Printf("error running sim console command %s: %s", rawCommandText, errorText);
          }
        }
      }
    }

    remaining = nextCommandChain;
  }
}

/**
 * Address: 0x00749DA0 (FUN_00749DA0)
 *
 * What it does:
 * Collects selected units into a temporary entity-set payload and forwards the
 * parsed command line through the sim debug parser chain.
 */
void Sim::ExecuteDebugCommand(
  const char* command,
  const Wm3::Vector3<float>& worldPos,
  const uint32_t focusArmy,
  const BVSet<EntId, EntIdUniverse>& entities
)
{
  EntitySetTemplate<Unit> selectedUnits{};
  InitSimDebugEntitySet(selectedUnits);

  auto appendSelectedUnit = [this, &selectedUnits](const EntId entId) {
    Entity* entity = FindEntityById(mEntityDB, entId);
    if (!entity) {
      return;
    }

    Unit* unit = entity->IsUnit();
    if (!unit) {
      return;
    }

    (void)selectedUnits.Add(unit);
  };

  entities.ForEachValue([&appendSelectedUnit](const unsigned int value) {
    appendSelectedUnit(static_cast<EntId>(value));
  });

  CArmyImpl* focusArmyPtr = nullptr;
  if (focusArmy < mArmiesList.size()) {
    focusArmyPtr = mArmiesList[focusArmy];
  }

  // 0x00734870 parser chain is now lifted in native C++ via TryParseSimCommand().
  TryParseSimCommand(command, worldPos, focusArmyPtr, selectedUnits);
  DestroySimDebugEntitySet(selectedUnits);
}
