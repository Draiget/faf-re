// Engine addition (dedicated-server plan WPL.4, WPR.11): the user Lua state's
// global functions that lived in Sim.cpp (UserLuaInitSet: session, selection,
// frames, special files, focus army, ...), moved out unchanged so the
// simulation's objects carry no user-world code. Listed in sources.cmake
// directly after Sim.cpp: its bootstrap below registers these forms in the
// order Sim.cpp's did, so the user init set keeps its order.
#include "moho/sim/Sim.h"
#include "legacy/math/X87Math.h"
#include "gpg/core/algorithms/MD5.h"
#include "gpg/core/utils/Global.h"
#include "moho/sim/CSimConCommand.h"
#include "moho/sim/CSimConVarBase.h"
#include "moho/sim/SimDriver.h"

#include <algorithm>
#include <array>
#include <bit>
#include <cmath>
#include <cstdarg>
#include <cstdio>
#include <cstddef>
#include <cstdarg>
#include <cstdio>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <initializer_list>
#include <limits>
#include <map>
#include <new>
#include <stdexcept>
#include <set>
#include <string>
#include <string_view>
#include <type_traits>
#include <typeinfo>
#include <utility>
#include <vector>

#include <Windows.h>
#include <intrin.h>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/streams/MemBufferStream.h"
#include "gpg/core/time/Timer.h"
#include "gpg/core/utils/Logging.h"
#include "legacy/containers/Map.h"
#include "legacy/containers/Vector.h"
#include "moho/ai/CAiBrain.h"
#include "moho/ai/CAiBuilderImpl.h"
#include "moho/ai/IAiBuilder.h"
#include "moho/ai/CAiFormationDBImpl.h"
#include "moho/ai/CAiReconDBImpl.h"
#include "moho/sim/SimWorkerPool.h"
#include "moho/sim/UnitUpdateFill.h"
#include "moho/ai/CAiSiloBuildImpl.h"
#include "moho/ai/IAiTransport.h"
#include "moho/animation/CAniActor.h"
#include "moho/animation/CAniPose.h"
#include "moho/animation/CAniSkel.h"
#include "moho/audio/AudioEngine.h"
#include "moho/audio/CUserSoundManager.h"
#include "moho/audio/CSimSoundManager.h"
#include "moho/audio/CSndParams.h"
#include "moho/audio/HSound.h"
#include "platform/WxWidgets.h"
#include <wx/app.h>
#include <wx/dialog.h>
#include <wx/sizer.h>
#include <wx/treectrl.h>
#include <wx/treelistctrl.h>
#include "moho/command/CCommandDb.h"
#include "moho/command/CommandIssueHelper.h"
#include "moho/sim/BuildQueueCommandDecrement.h"
#include "moho/sim/CDamage.h"
#include "moho/command/SSTICommandIssueData.h"
#include "moho/client/Localization.h"
#include "moho/console/CConCommand.h"
#include "moho/console/CVarAccess.h"
#include "moho/debug/RDebugOverlayClass.h"
#include "moho/entity/Entity.h"
#include "moho/collision/CColPrimitiveBase.h"
#include "moho/entity/EntityDb.h"
#include "moho/entity/EntityCategoryReflection.h"
#include "moho/entity/CollisionBeamEntity.h"
#include "moho/entity/EntityId.h"
#include "moho/entity/intel/CIntel.h"
#include "moho/entity/intel/CIntelPosHandle.h"
#include "moho/entity/EntityPositionWatchEntry.h"
#include "moho/entity/Prop.h"
#include "moho/entity/UserEntity.h"
#include "moho/ai/CAiPathFinder.h"
#include "moho/path/IPathTraveler.h"
#include "moho/path/PathTables.h"
#include "moho/particles/SParticleBuffer.h"
#include "moho/render/camera/CameraImpl.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/render/camera/VTransform.h"
#include "moho/render/CDecalBuffer.h"
#include "moho/effects/rendering/CEffectManagerImpl.h"
#include "moho/render/d3d/CD3DDevice.h"
#include "moho/render/d3d/CD3DFont.h"
#include "moho/render/d3d/CD3DPrimBatcher.h"
#include "moho/render/textures/CD3DBatchTexture.h"
#include "lua/LuaError.h"
#include "lua/LuaRuntimeTypes.h"
#include "lua/LuaTableIterator.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/lua/SCR_Color.h"
#include "moho/lua/SCR_FromLua.h"
#include "moho/lua/SCR_String.h"
#include "moho/lua/SCR_ToLua.h"
#include "moho/math/MathReflection.h"
#include "moho/math/QuaternionMath.h"
#include "moho/resource/RResId.h"
#include "moho/resource/RScmResource.h"
#include "moho/resource/CSimResources.h"
#include "moho/resource/blueprints/RBeamBlueprint.h"
#include "moho/resource/blueprints/REmitterBlueprint.h"
#include "moho/resource/blueprints/RMeshBlueprint.h"
#include "moho/resource/blueprints/RPropBlueprint.h"
#include "moho/resource/blueprints/RProjectileBlueprint.h"
#include "moho/resource/blueprints/RTrailBlueprint.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/projectile/Projectile.h"
#include "moho/script/CScriptEvent.h"
#include "moho/script/CScriptObject.h"
#include "moho/misc/LaunchInfoBase.h"
#include "moho/misc/ScrDebugHooks.h"
#include "moho/sim/CWldMap.h"
#include "moho/task/CLuaTask.h"
#include "moho/task/ScrDiskWatcherTask.h"
#include "moho/sim/SRuleFootprintsBlueprint.h"
#include "moho/misc/FileWaitHandleSet.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/net/CClientManagerImpl.h"
#include "moho/sim/BlueprintLoaderContext.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CArmyStats.h"
#include "moho/sim/CBackgroundTaskControl.h"
#include "gpg/core/containers/BitArray2D.h"
#include "moho/ai/IAiNavigator.h"
#include "moho/path/SNavGoal.h"
#include "moho/sim/COGrid.h"
#include "moho/sim/SFootprint.h"
#include "moho/sim/SOCellPos.h"
#include "moho/sim/EAllianceTypeInfo.h"
#include "moho/sim/CEconStorage.h"
#include "moho/sim/CSimArmyEconomyInfo.h"
#include "moho/sim/SPhysConstants.h"
#include "moho/sim/PathPreviewFinder.h"
#include "moho/sim/SpecialFileType.h"
#include "moho/sim/STIMap.h"
#include "moho/sim/CWldSession.h"
#include "moho/math/Vector3f.h"
#include "moho/containers/BVSet.h"
#include "moho/sim/ReconBlip.h"
#include "moho/sim/UserArmy.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/SSTICommandSource.h"
#include "moho/sim/STIMapReflection.h"
#include "moho/ui/CUIManager.h"
#include "moho/unit/core/IUnit.h"
#include "moho/unit/core/EIntelTypeInfo.h"
#include "moho/unit/core/SUnitConstructionParams.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/core/UserUnit.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/CUnitCommandQueue.h"
#include "moho/unit/CUnitMotion.h"
#include "moho/sim/SimDebugCommandRegistrations.h"

#include "gpg/core/reflection/StaticInitPhase.h"
#include "lua/LuaCrashDump.h"

using namespace moho;
using EntId = std::int32_t;

// Engine addition: helpers shared with the file these functions came from.
namespace
{
  [[nodiscard]] gpg::RType* CachedCScriptObjectPointerType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = CScriptObject::GetPointerType();
    }
    return sType;
  }
  /**
   * The reflected reference is assembled from the userdata HEADER, not read out
   * of its payload. This fork carries the `gpg::RType*` in `Udata::len`, and the
   * value itself starts one header past the allocation, which is exactly what
   * `LuaPlus::LuaObject::GetUserData` (0x00907540) does:
   *
   *     lea edx, [ecx+10h]   ; mObj  = payload, laid out after the header
   *     mov ecx, [ecx+0Ch]   ; mType = Udata::len reinterpreted as RType*
   *
   * Reading `*(gpg::RRef*)lua_touserdata(...)` instead - as this helper used to -
   * takes the first eight payload bytes as if they were a reference. For a
   * `_c_object` slot those bytes are the `CScriptObject*` value followed by
   * whatever the allocator left, so every upcast failed and each caller reported
   * "Expected a game object" for a perfectly good object.
   */
  [[nodiscard]] gpg::RRef ExtractLuaUserDataRef(const LuaPlus::LuaObject& userDataObject)
  {
    if (!userDataObject.IsUserData()) {
      return gpg::RRef{};
    }

    return userDataObject.GetUserData();
  }

  [[nodiscard]] gpg::RType* CachedUserUnitType()
  {
    static gpg::RType* sType = nullptr;
    if (!sType) {
      sType = gpg::LookupRType(typeid(UserUnit));
    }
    return sType;
  }
  [[nodiscard]] CScriptObject** ExtractScriptObjectSlotFromLuaObject(const LuaPlus::LuaObject& object)
  {
    LuaPlus::LuaObject payload(object);
    if (payload.IsTable()) {
      payload = moho::SCR_GetLuaTableField(payload.GetActiveState(), payload, "_c_object");
    }

    if (!payload.IsUserData()) {
      return nullptr;
    }

    const gpg::RRef userDataRef = ExtractLuaUserDataRef(payload);
    if (!userDataRef.mObj) {
      return nullptr;
    }

    const gpg::RRef upcast = gpg::REF_UpcastPtr(userDataRef, CachedCScriptObjectPointerType());
    return static_cast<CScriptObject**>(upcast.mObj);
  }
  /**
   * Address: 0x008B5BB0 (FUN_008B5BB0, sub_8B5BB0)
   *
   * What it does:
   * Finds one command-issue helper by command id in the session command-manager
   * map and returns the mapped helper pointer, or `nullptr` when absent.
   *
   * Real disassembly (`std::map_CmdId_CommandIssueHelper::find`, FUN_008B6160,
   * cited on `rb_tree::find_node` in `RbTree.h`) is a plain
   * `commandManager->mCommands.find(cmdId)`; this used to reach in through a
   * bespoke `CommandDbMapStorageView`/`CommandDbMapNodeView` pair
   * (`CommandIssueMapOf` + `FindCommandNode`) that hand-walked the same real
   * `msvc8::map<CmdId, UserCommandIssueHelper*> CommandManager::mCommands`
   * (`CommandManager.h`) member instead of calling it.
   */
  [[nodiscard]] UserCommandIssueHelper* FindCommandIssueHelperInManager(
    CommandManager* const commandManager,
    const CmdId cmdId
  ) noexcept
  {
    if (commandManager == nullptr) {
      return nullptr;
    }

    const auto it = commandManager->mCommands.find(cmdId);
    if (it == commandManager->mCommands.end()) {
      return nullptr;
    }

    return it->second;
  }
  constexpr const char* kExpectedGameObjectError = "Expected a game object. (Did you call with '.' instead of ':'?)";
  constexpr const char* kIncorrectGameObjectTypeError =
    "Incorrect type of game object.  (Did you call with '.' instead of ':'?)";
  [[nodiscard]] IUnit* ResolveIUnitBridge(UserUnit* const unit) noexcept
  {
    return unit ? static_cast<IUnit*>(unit) : nullptr;
  }

  void AppendSelectionUnitUnique(msvc8::vector<UserUnit*>& selectionUnits, UserUnit* const unit)
  {
    if (unit == nullptr) {
      return;
    }

    if (std::find(selectionUnits.begin(), selectionUnits.end(), unit) == selectionUnits.end()) {
      selectionUnits.push_back(unit);
    }
  }
  [[nodiscard]] std::int64_t BuildScriptBitMask(const int bitIndex) noexcept
  {
    const std::uint32_t bitShift = static_cast<std::uint32_t>(bitIndex);
    return bitShift < 64u ? static_cast<std::int64_t>(1ull << bitShift) : 0;
  }
  [[nodiscard]] msvc8::string BuildSpecialFilePathDirectory(const moho::ESpecialFileType type)
  {
    switch (type) {
      case moho::ESpecialFileType::SaveGame:
      case moho::ESpecialFileType::CampaignSave:
        return USER_GetSaveGameDir();
      case moho::ESpecialFileType::Replay:
        return USER_GetReplayDir();
      case moho::ESpecialFileType::Screenshot:
        return USER_GetScreenshotDir();
    }
    return msvc8::string{};
  }
  [[nodiscard]] msvc8::string BuildSpecialFilePathExtension(const moho::ESpecialFileType type)
  {
    switch (type) {
      case moho::ESpecialFileType::SaveGame:
        return USER_GetSaveGameExt();
      case moho::ESpecialFileType::Replay:
        return USER_GetReplayExt();
      case moho::ESpecialFileType::Screenshot:
        return msvc8::string("bmp");
      case moho::ESpecialFileType::CampaignSave:
        return USER_GetCampaignSaveExt();
    }
    return msvc8::string{};
  }
  [[nodiscard]] gpg::RType* CachedERuleBPUnitCommandCapsType()
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = gpg::LookupRType(typeid(moho::ERuleBPUnitCommandCaps));
    }
    return sType;
  }
  [[nodiscard]] gpg::RType* CachedEUnitCommandTypeType()
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = gpg::LookupRType(typeid(moho::EUnitCommandType));
    }
    return sType;
  }
  [[nodiscard]] UserCommandIssueHelper* FindCommandIssueHelper(CWldSession* const session, const CmdId cmdId)
  {
    if (!session || !session->mCommandManager) {
      return nullptr;
    }

    CommandManager* const commandManager = session->mCommandManager;
    return FindCommandIssueHelperInManager(commandManager, cmdId);
  }
  [[nodiscard]] UserEntity*
  FindUserSessionEntityById(CWldSession* const session, const std::int32_t entityId) noexcept
  {
    if (session == nullptr) {
      return nullptr;
    }

    return session->LookupEntityId(entityId);
  }
  /**
   * Address: 0x008ADF40 (FUN_008ADF40, func_GetVoiceDir)
   *
   * What it does:
   * Checks whether `/sounds/voice/<language>` exists in the mounted virtual
   * file-system lane.
   */
  [[nodiscard]] bool HasLocalizedVoiceDirectory(const msvc8::string& language)
  {
    const msvc8::string voiceDirectory = gpg::STR_Printf("/sounds/voice/%s", language.c_str());
    return FILE_GetFileInfo(voiceDirectory.c_str(), nullptr, false);
  }
  constexpr const char* kAddSelectUnitsHelpText = "Add these units to the currently Selected lists";
  constexpr const char* kAddToSessionExtraSelectListHelpText = "Add unit to the session extra select list";
  constexpr const char* kAudioSetLanguageUserHelpText = "AudioSetLanguage(name)";
  constexpr const char* kClearBuildTemplatesHelpText = "clear and disable the build templates.";
  constexpr const char* kClearFrameHelpText =
    "ClearFrame(int head) - destroy all controls in frame, nil head will clear all frames";
  constexpr const char* kClearSessionExtraSelectListHelpText = "Clear the session extra select list";
  constexpr const char* kCopyCurrentReplayHelpText =
    "CopyCurrentReplay(string profile, string newFilename) - copy the current replay to another file";
  constexpr const char* kCreateUnitAtMouseHelpText = "CreateUnitAtMouse";
  constexpr const char* kCurrentTimeHelpText =
    "Get the current time in seconds, counting from 0 at application start. This is wall-clock time and is unaffected by gameplay.";
  constexpr const char* kDeleteCommandHelpText = "DeleteCommand(id)";
  constexpr const char* kEjectSessionClientHelpText =
    "EjectSessionClient(int clientIndex) -- eject another client from your session";
  constexpr const char* kEngineStartFrontEndUIHelpText =
    "EngineStartFrontEndUI() - kill current UI and start main menu from top";
  constexpr const char* kEngineStartSplashScreensHelpText =
    "EngineStartSplashScreens() - kill current UI and start splash screens";
  constexpr const char* kEntityCategoryContainsUserHelpText = "See if a unit category contains this unit";
  constexpr const char* kEntityCategoryContainsUserNoSessionText = "EntityCategoryContains: no session loaded";
  constexpr const char* kEntityCategoryFilterDownUserHelpText =
    "Filter a list of units to only those found in the category";
  constexpr const char* kEntityCategoryFilterDownUserInvalidCategoryText =
    "EntityCategoryFilterDown: expected an entity category object";
  constexpr const char* kEntityCategoryFilterDownUserNoSessionText = "EntityCategoryFilterDown: no session loaded";
  constexpr const char* kEntityCategoryFilterOutHelpText =
    "Filter a list of units to exclude those found in the category";
  constexpr const char* kEntityCategoryFilterOutInvalidCategoryText =
    "EntityCategoryFilterOut: expected an entity category object";
  constexpr const char* kEntityCategoryFilterOutNoSessionText = "EntityCategoryFilterOut: no session loaded";
  constexpr const char* kExecLuaInSimHelpText = "Execute some lua code in the sim";
  constexpr const char* kExitApplicationHelpText = "ExitApplication - request that the application shut down";
  constexpr const char* kExitGameHelpText = "ExitGame() - Quits the sim, but not the app";
  constexpr const char* kFormatTimeHelpText =
    "string FormatTime(seconds) - format a string displaying the time specified in seconds";
  constexpr const char* kGameTickUserHelpText =
    "Get the current game time in ticks. The game time is the simulation time, that stops when the game is paused.";
  constexpr const char* kGameTimeUserHelpText =
    "Get the current game time in seconds. The game time is the simulation time, that stops when the game is paused.";
  constexpr const char* kGenerateBuildTemplateFromSelectionHelpText =
    "generate and enable build templates from the current selection.";
  constexpr const char* kGetArmiesTableHelpText = "armyInfo GetArmiesTable()";
  constexpr const char* kGetArmyAvatarsHelpText = "table GetArmyAvatars() - return a table of avatar units for the army";
  constexpr const char* kGetArmyScoreHelpText = "int GetArmyScore(armyIndex)";
  constexpr const char* kGetAssistingUnitsListHelpText = "Get a list of units assisting me";
  constexpr const char* kGetAttachedUnitsListHelpText = "Get a list of units blueprint attached to transports";
  constexpr const char* kGetCurrentUIStateHelpText =
    "state GetCurrentUIState() - returns 'splash', 'frontend' or 'game' depending on the current state of the ui";
  constexpr const char* kGetEconomyTotalsHelpText = "table GetEconomyTotals()";
  constexpr const char* kGetEconomyTotalsMissingSessionWarning =
    "Attempt to call GetEconomyTotals before world sessions exists.";
  constexpr const char* kGetFocusArmyUserHelpText = "GetFocusArmy()";
  constexpr const char* kGetFrameHelpText = "frame GetFrame(int head) - return the root UI frame for a given head";
  constexpr const char* kGetGameSpeedHelpText = "Return the current game speed";
  constexpr const char* kGetGameTimeHelpText =
    "string GetGameTime() - returns a formatted string displaying the time the game has been played";
  constexpr const char* kGetGameTimeSecondsUserHelpText = "float GetGameTimeSeconds() - returns game time in seconds";
  constexpr const char* kGetIdleEngineersHelpText =
    "table GetIdleEngineers() - return a table of idle engineer units for the army";
  constexpr const char* kGetIdleFactoriesHelpText =
    "table GetIdleFactories() - return a table of idle factory units for the army";
  constexpr const char* kGetMouseScreenPosHelpText = "vector GetMouseScreenPos()";
  constexpr const char* kGetMouseWorldPosUserHelpText = "vector GetMouseWorldPos()";
  constexpr const char* kGetNumRootFramesHelpText =
    "int GetNumRootFrames() - returns the current number of root frames (typically one per head";
  constexpr const char* kGetResourceSharingHelpText = "bool GetResourceSharing()";
  constexpr const char* kGetSelectedUnitsHelpText = "table GetSelectedUnits() - return a table of the currently selected units";
  constexpr const char* kGetSimRateHelpText = "number GetSimRate()";
  constexpr const char* kGetSimTicksPerSecondHelpText = "int GetSimTicksPerSecond()";
  constexpr const char* kGetSpecialFileInfoHelpText =
    "table GetSpecialFileInfo(string profileName, string basename, string type) - get information on a profile based file, nil if unable to find";
  constexpr const char* kGetSpecialFilePathHelpText =
    "string GetSpecialFilePath(string profilename, string filename, string type) - Given the base name of a special file, retuns the complete path";
  constexpr const char* kGetSpecialFilesHelpText =
    "table GetSpecialFiles(string type)- returns a table of strings which are the names of files in special locations (currently SaveFile, Replay)";
  constexpr const char* kGetSpecialFolderHelpText = "string GetSpecialFolder(string type)";
  constexpr const char* kGetSystemTimeHelpText =
    "string GetSystemTime() - returns a formatted string displaying the System time";
  constexpr const char* kGetSystemTimeSecondsHelpText =
    "float GetSystemTimeSeconds() - returns System time in seconds";
  constexpr const char* kGetUnitByIdUserHelpText = "GetUnitById(id)";
  constexpr const char* kGetUnitCommandFromCommandCapErrorHelpText = "string GetUnitCommandFromCommandCap(string)";
  constexpr const char* kGetUnitCommandFromCommandCapHelpText =
    "string GetUnitCommandFromCommandCap(string) - given a RULEUCC type command, return the equivalent UNITCOMMAND command";
  constexpr const char* kGetValidAttackingUnitsHelpText =
    "table GetValidAttackingUnits() - return a table of the currently selected units";
  constexpr const char* kHasLocalizedVOUserHelpText = "HasLocalizedVO(languageCode)";
  constexpr CommandSourceId kInvalidCommandSource = 0xFF;
  constexpr const char* kIsAllyUserHelpText = "IsAlly(army1,army2)";
  constexpr const char* kIsEnemyUserHelpText = "IsEnemy(army1,army2)";
  constexpr const char* kIsNeutralUserHelpText = "IsNeutral(army1,army2)";
  constexpr const char* kIsObserverHelpText = "IsObserver()";
  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";
  constexpr const char* kLuaInvalidBoolWarning = "%s\n  invalid argument %d, use as boolean";
  constexpr const char* kNoActiveSessionPeriodText = "No active session.";
  constexpr const char* kNoActiveSessionText = "No active session";
  constexpr const char* kNoSessionStartedText = "No session started.";
  constexpr const char* kParseEntityCategoryUserHelpText = "parse a string to generate a new entity category";
  constexpr const char* kParseEntityCategoryUserNoSessionText = "ParseEntityCategory: no session loaded";
  constexpr const char* kRandomUserHelpText = "Random([[min,] max])";
  constexpr const char* kRemoveFromSessionExtraSelectListHelpText = "Remove unit from the session extra select list";
  constexpr const char* kRemoveProfileDirectoriesHelpText =
    "RemoveProfileDirectories(string profile) - Removes the profile directory and all special files";
  constexpr const char* kRemoveSpecialFileHelpText =
    "RemoveSpecialFile(string profilename, string basename, string type) - remove a profile based file from the disc";
  constexpr const char* kRenderOverlayEconomyHelpText = "RenderOverlayEconomy(bool)";
  constexpr const char* kRenderOverlayIntelHelpText = "RenderOverlayIntel(bool)";
  constexpr const char* kRenderOverlayMilitaryHelpText = "RenderOverlayMilitary(bool)";
  constexpr const char* kRestartSessionHelpText = "RestartSession() - Restart the current mission/skirmish/etc";
  constexpr const char* kSelectUnitsHelpText = "Select the specified units";
  constexpr const char* kSessionCanRestartHelpText = "Return true iff the active session can be restarted.";
  constexpr const char* kSessionEndGameHelpText =
    "End the current game session.  The session says active, we just disconnect from everyone else and freeze play.";
  constexpr const char* kSessionGetLocalCommandSourceHelpText =
    "Return the local command source.  Returns 0 if the local client can't issue commands.";
  constexpr const char* kSessionGetLocalCommandSourceNoActiveSessionText =
    "SessionGetLocalCommandSource(): no active session.";
  constexpr const char* kSessionGetScenarioInfoHelpText =
    "Return the table of scenario info that was originally passed to the sim on launch.";
  constexpr const char* kSessionGetScenarioInfoNoActiveSessionText = "no active session.";
  constexpr const char* kSessionIsActiveHelpText = "Return true iff there is a session currently running";
  constexpr const char* kSessionIsBeingRecordedHelpText = "Return true iff the active session is a being recorded.";
  constexpr const char* kSessionIsGameOverHelpText = "Return true iff the session has been won or lost yet.";
  constexpr const char* kSessionIsGameOverNoActiveSessionText = "SessionIsGameOver(): no active session.";
  constexpr const char* kSessionIsMultiplayerHelpText = "Return true iff the active session is a multiplayer session.";
  constexpr const char* kSessionIsObservingAllowedHelpText =
    "Return true iff observing is allowed in the active session.";
  constexpr const char* kSessionIsPausedHelpText = "Return true iff the session is paused.";
  constexpr const char* kSessionIsPausedNoActiveSessionText = "SessionIsPaused(): no active session.";
  constexpr const char* kSessionIsReplayUserHelpText = "Return true iff the active session is a replay session.";
  constexpr const char* kSessionRequestPauseHelpText = "Pause the world simulation.";
  constexpr const char* kSessionRequestPauseNoActiveSessionText = "SessionRequestPause(): no active session.";
  constexpr const char* kSessionResumeHelpText = "Resume the world simulation.";
  constexpr const char* kSessionResumeNoActiveSessionText = "SessionResume(): no active session.";
  constexpr const char* kSetAutoModeHelpText = "See if anyone in the list is auto building";
  constexpr const char* kSetAutoSurfaceModeHelpText = "See if anyone in the list is auto surfacing";
  constexpr const char* kSetFocusArmyUserHelpText = "SetFocusArmy(armyIndex or -1)";
  constexpr const char* kSetGameSpeedHelpText = "Set the desired game speed";
  constexpr const char* kSetInvertMidMouseButtonHelpText = "SetInvertMidMouseButton";
  constexpr const char* kSetOverlayFiltersHelpText = "SetOverlayFilters(list)";
  constexpr const char* kSetPausedHelpText = "Pause builders in this list";
  constexpr const char* kSimCallbackHelpText =
    "SimCallback(callback[,bool]): Execute a lua function in sim\n"
    "callback = {\n"
    "   Func    =   function name (in the SimCallbacks.lua module) to call\n"
    "   Args    =   Arguments as a lua object\n"
    "}\n"
    "If bool is specified and true, sends the current selection with the command\n";
  constexpr const char* kSyncPlayableRectHelpText = "SyncPlayableRect(region)";
  constexpr const char* kTeamColorModeHelpText = "TeamColorMode(bool)";

  // Help texts of the sim functions the user state registers too (moho/sim/Sim.cpp).
  constexpr const char* kGetTimeForProfileHelpText = "(OriginTime)";
  constexpr const char* kGetDepositsAroundPointHelpText = "(X, Z, Radius, Type)";

  /**
   * FA-Binary-Patches section/TeamColorMode.cpp (`TeamColorMode` stub): reads
   * hex colours separated by any non-hex character ("ffrrggbb,ffrrggbb,...")
   * into `teamcolors` from slot 0; slots the text does not reach keep their
   * values. The stub steps past the terminator after the last colour and keeps
   * parsing whatever follows the string, and has no slot limit; this stops at
   * the terminator and after the palette's 32 slots.
   */
  void ParseTeamColorPalette(const char* const text)
  {
    const char* cursor = text;
    for (std::size_t slot = 0; *cursor != '\0' && slot < moho::kTeamColorPaletteSize; ++slot) {
      std::uint32_t color = 0u;
      for (;; ++cursor) {
        const char c = *cursor;
        std::uint32_t digit = 0u;
        if (c >= '0' && c <= '9') {
          digit = static_cast<std::uint32_t>(c - '0');
        } else if (c >= 'A' && c <= 'F') {
          digit = static_cast<std::uint32_t>(c - 'A' + 10);
        } else if (c >= 'a' && c <= 'f') {
          digit = static_cast<std::uint32_t>(c - 'a' + 10);
        } else {
          break;
        }
        color = (color << 4) + digit;
      }
      moho::teamcolors[slot] = color;
      if (*cursor == '\0') {
        break;
      }
      ++cursor;
    }
  }
  constexpr const char* kToggleScriptBitExpectedArgsText = "ToggleScriptBit(units, bit, curState)";
  constexpr const char* kToggleScriptBitHelpText = "Set the right fire state for the units passed in";
  constexpr const char* kUiLayerNotInitializedText = "UI layer has not been initialized.";
  constexpr const char* kValidateUnitsListHelpText = "Validate a list of units ";
  constexpr const char* kWorldIsLoadingHelpText = "bool = WorldIsLoading()";
  constexpr const char* kWorldIsPlayingHelpText = "bool = WorldIsPlaying()";
  constexpr const char* kWrongLuaStateText = "wrong lua state.";
  /**
   * Address: 0x008B49D0 (FUN_008B49D0, sub_8B49D0)
   *
   * What it does:
   * Queues one local "decrease count" edit of `deltaCount`.
   *
   * Address: 0x008B4960 (FUN_008B4960 -- the "increase count" sibling, the same
   * body with kind 1; zero callers and no references in the image, a
   * linker-retained copy nothing runs.)
   */
  void QueueCommandIssueDecreaseCountEvent(UserCommandIssueHelper& helper, const CmdId cmdId, const std::int32_t deltaCount)
  {
    UserCommandIssueLocalEvent event(cmdId, ECommandIssueEvent::DecreaseCount);
    event.mCount = deltaCount;
    helper.mLocalQueue.push_back(event);
  }
  [[nodiscard]] CmdId ReadLuaCommandIdArg(LuaPlus::LuaState* const state, const int stackIndex)
  {
    LuaPlus::LuaStackObject arg(state, stackIndex);
    if (lua_type(state->m_state, stackIndex) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&arg, "integer");
    }

    // Binary lane uses an x87 integer-store conversion and consumes the low dword.
    const std::int64_t truncated = static_cast<std::int64_t>(lua_tonumber(state->m_state, stackIndex));
    return static_cast<CmdId>(static_cast<std::uint32_t>(truncated));
  }
  [[nodiscard]] const RUnitBlueprint* ResolveEntityCategoryFilterBlueprint(
    const LuaPlus::LuaObject& valueObject,
    CWldSession* const session,
    LuaPlus::LuaState* const state
  )
  {
    if (valueObject.IsString()) {
      const char* const blueprintText = valueObject.GetString();
      if (!blueprintText || !session || !session->mRules) {
        return nullptr;
      }

      RResId blueprintId{};
      gpg::STR_SetFilename(&blueprintId.name, blueprintText);
      return session->mRules->GetUnitBlueprint(blueprintId);
    }

    UserUnit* const userUnit = SCR_FromLua_UserUnit(valueObject, state);
    if (!userUnit) {
      return nullptr;
    }

    const IUnit* const iunitBridge = ResolveIUnitBridge(userUnit);
    return iunitBridge ? iunitBridge->GetBlueprint() : nullptr;
  }
  [[nodiscard]] Sim* ResolveGlobalSim(lua_State* const luaContext) noexcept
  {
    if (!luaContext || !luaContext->l_G) {
      return nullptr;
    }
    return luaContext->l_G->globalUserData;
  }
  [[nodiscard]] UserUnit* ResolveSelectableTransportAttachmentParent(UserUnit* const unit) noexcept
  {
    if (unit == nullptr) {
      return nullptr;
    }

    auto* const entity = reinterpret_cast<UserEntity*>(unit);
    const std::uint32_t attachmentParentRef = entity->mVariableData.mAttachmentParentRef;
    if (attachmentParentRef == 0u || attachmentParentRef == ToRaw(EEntityIdSentinel::Invalid)) {
      return nullptr;
    }

    UserEntity* const attachmentParentEntity = FindUserSessionEntityById(
      entity->mSession,
      static_cast<std::int32_t>(attachmentParentRef)
    );
    if (attachmentParentEntity == nullptr || !attachmentParentEntity->IsSelectable()) {
      return nullptr;
    }

    UserUnit* const attachmentParentUnit = attachmentParentEntity->IsUserUnit();
    if (attachmentParentUnit == nullptr) {
      return nullptr;
    }

    static const msvc8::string kTransportationCategory("TRANSPORTATION");
    return attachmentParentEntity->IsInCategory(kTransportationCategory) ? attachmentParentUnit : nullptr;
  }
  [[nodiscard]] UserUnit* ResolveUserUnitOptional(const LuaPlus::LuaObject& object, LuaPlus::LuaState* const state)
  {
    CScriptObject** const scriptObjectSlot = ExtractScriptObjectSlotFromLuaObject(object);
    if (scriptObjectSlot == nullptr) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kExpectedGameObjectError);
      return nullptr;
    }

    CScriptObject* const scriptObject = *scriptObjectSlot;
    if (scriptObject == nullptr) {
      return nullptr;
    }

    const gpg::RRef sourceRef = SCR_MakeScriptObjectRef(scriptObject);
    const gpg::RRef upcast = gpg::REF_UpcastPtr(sourceRef, CachedUserUnitType());
    if (!upcast.mObj) {
      luaL_error(state ? state->GetActiveCState() : nullptr, kIncorrectGameObjectTypeError);
      return nullptr;
    }

    return static_cast<UserUnit*>(upcast.mObj);
  }
  [[noreturn]] void ThrowInvalidSpecialFileType(const char* const lexical)
  {
    throw std::runtime_error(gpg::STR_Printf("Invalid special file type %s", lexical != nullptr ? lexical : "").to_std());
  }
  [[nodiscard]] bool TryParseSpecialFileType(
    const char* const lexical,
    moho::ESpecialFileType& outType
  ) noexcept
  {
    if (lexical == nullptr) {
      return false;
    }

    const std::string_view text(lexical);
    if (text == "SaveGame" || text == "SFT_SaveGame") {
      outType = moho::ESpecialFileType::SaveGame;
      return true;
    }
    if (text == "Replay" || text == "SFT_Replay") {
      outType = moho::ESpecialFileType::Replay;
      return true;
    }
    if (text == "Screenshot" || text == "SFT_Screenshot") {
      outType = moho::ESpecialFileType::Screenshot;
      return true;
    }
    if (text == "CampaignSave" || text == "SFT_CampaignSave") {
      outType = moho::ESpecialFileType::CampaignSave;
      return true;
    }

    char* end = nullptr;
    const long numericValue = std::strtol(lexical, &end, 10);
    if (end != lexical && end != nullptr && *end == '\0' && numericValue >= 0 && numericValue <= 3) {
      outType = static_cast<moho::ESpecialFileType>(numericValue);
      return true;
    }

    return false;
  }
  [[nodiscard]] CScrLuaInitFormSet& UserLuaInitSet()
  {
    if (CScrLuaInitFormSet* const set = moho::SCR_FindLuaInitFormSet("User"); set != nullptr) {
      return *set;
    }

    static CScrLuaInitFormSet fallbackSet("User");
    return fallbackSet;
  }
} // namespace


/**
 * Address: 0x008B9B80 (FUN_008B9B80, cfunc_ParseEntityCategoryUserL)
 *
 * What it does:
 * Parses one category expression string and returns a new entity-category
 * userdata object.
 */
int moho::cfunc_ParseEntityCategoryUserL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kParseEntityCategoryUserHelpText, 1, argumentCount);
  }

  CWldSession* const session = WLD_GetActiveSession();
  RRuleGameRulesImpl* const rules = session ? session->mRules : nullptr;
  if (!rules) {
    LuaPlus::LuaState::Error(state, kParseEntityCategoryUserNoSessionText);
  }

  LuaPlus::LuaStackObject categoryTextArg(state, 1);
  const char* categoryText = lua_tostring(rawState, 1);
  if (!categoryText) {
    categoryTextArg.TypeError("string");
    categoryText = "";
  }

  EntityCategorySet parsedCategory = rules->ParseEntityCategory(categoryText);

  LuaPlus::LuaObject out;
  (void)func_NewEntityCategory(state, &out, &parsedCategory);
  out.PushStack(state);
  return 1;
}

/**
 * Address: 0x008B9B00 (FUN_008B9B00, cfunc_ParseEntityCategoryUser)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_ParseEntityCategoryUserL`.
 */
int moho::cfunc_ParseEntityCategoryUser(lua_State* const luaContext)
{
  return cfunc_ParseEntityCategoryUserL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008B9B20 (FUN_008B9B20, func_ParseEntityCategoryUser_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `ParseEntityCategory`.
 */
moho::CScrLuaInitForm* moho::func_ParseEntityCategoryUser_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "ParseEntityCategory",
    &moho::cfunc_ParseEntityCategoryUser,
    nullptr,
    "<global>",
    kParseEntityCategoryUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x00840840 (FUN_00840840, cfunc_GetUnitCommandFromCommandCap)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to
 * `cfunc_GetUnitCommandFromCommandCapL`.
 */
int moho::cfunc_GetUnitCommandFromCommandCap(lua_State* const luaContext)
{
  return cfunc_GetUnitCommandFromCommandCapL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00840860 (FUN_00840860, func_GetUnitCommandFromCommandCap_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for
 * `GetUnitCommandFromCommandCap`.
 */
moho::CScrLuaInitForm* moho::func_GetUnitCommandFromCommandCap_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetUnitCommandFromCommandCap",
    &moho::cfunc_GetUnitCommandFromCommandCap,
    nullptr,
    "<global>",
    kGetUnitCommandFromCommandCapHelpText
  );
  return &binder;
}

/**
 * Address: 0x00821F50 (FUN_00821F50, Moho::UnitCommandCapToCommandType)
 *
 * What it does:
 * Converts one command-capability enum into the matching unit command enum.
 */
moho::EUnitCommandType moho::UnitCommandCapToCommandType(const ERuleBPUnitCommandCaps commandCap)
{
  if (commandCap > RULEUCC_Tactical) {
    if (commandCap > RULEUCC_Pause) {
      if (commandCap > RULEUCC_Reclaim) {
        if (commandCap == RULEUCC_SpecialAction) {
          return EUnitCommandType::UNITCOMMAND_SpecialAction;
        }
      } else {
        switch (commandCap) {
        case RULEUCC_Reclaim:
          return EUnitCommandType::UNITCOMMAND_Reclaim;
        case RULEUCC_Overcharge:
          return EUnitCommandType::UNITCOMMAND_OverCharge;
        case RULEUCC_Dive:
          return EUnitCommandType::UNITCOMMAND_Dive;
        default:
          break;
        }
      }
    } else {
      if (commandCap == RULEUCC_Pause) {
        return EUnitCommandType::UNITCOMMAND_Pause;
      }

      if (commandCap > RULEUCC_SiloBuildTactical) {
        if (commandCap == RULEUCC_SiloBuildNuke) {
          return EUnitCommandType::UNITCOMMAND_BuildSiloNuke;
        }
        if (commandCap == RULEUCC_Sacrifice) {
          return EUnitCommandType::UNITCOMMAND_Sacrifice;
        }
      } else {
        switch (commandCap) {
        case RULEUCC_SiloBuildTactical:
          return EUnitCommandType::UNITCOMMAND_BuildSiloTactical;
        case RULEUCC_Teleport:
          return EUnitCommandType::UNITCOMMAND_Teleport;
        case RULEUCC_Ferry:
          return EUnitCommandType::UNITCOMMAND_Ferry;
        default:
          break;
        }
      }
    }

    return EUnitCommandType::UNITCOMMAND_None;
  }

  if (commandCap == RULEUCC_Tactical) {
    return EUnitCommandType::UNITCOMMAND_Tactical;
  }

  if (commandCap > RULEUCC_Repair) {
    if (commandCap > RULEUCC_CallTransport) {
      if (commandCap == RULEUCC_Nuke) {
        return EUnitCommandType::UNITCOMMAND_Nuke;
      }
    } else {
      switch (commandCap) {
      case RULEUCC_CallTransport:
        return EUnitCommandType::UNITCOMMAND_TransportLoadUnits;
      case RULEUCC_Capture:
        return EUnitCommandType::UNITCOMMAND_Capture;
      case RULEUCC_Transport:
        return EUnitCommandType::UNITCOMMAND_TransportUnloadUnits;
      default:
        break;
      }
    }

    return EUnitCommandType::UNITCOMMAND_None;
  }

  if (commandCap == RULEUCC_Repair) {
    return EUnitCommandType::UNITCOMMAND_Repair;
  }

  switch (commandCap) {
  case RULEUCC_Move:
    return EUnitCommandType::UNITCOMMAND_Move;
  case RULEUCC_Stop:
    return EUnitCommandType::UNITCOMMAND_Stop;
  case RULEUCC_Attack:
    return EUnitCommandType::UNITCOMMAND_Attack;
  case RULEUCC_Guard:
    return EUnitCommandType::UNITCOMMAND_Guard;
  case RULEUCC_Patrol:
    return EUnitCommandType::UNITCOMMAND_Patrol;
  default:
    return EUnitCommandType::UNITCOMMAND_None;
  }
}

/**
 * Address: 0x008408C0 (FUN_008408C0, cfunc_GetUnitCommandFromCommandCapL)
 *
 * What it does:
 * Converts one `RULEUCC` lexical token to its corresponding `UNITCOMMAND`
 * lexical token and returns it as a Lua string.
 */
int moho::cfunc_GetUnitCommandFromCommandCapL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetUnitCommandFromCommandCapErrorHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaStackObject commandCapArg(state, 1);
  const char* const commandCapLexical = lua_tostring(rawState, 1);
  if (commandCapLexical == nullptr) {
    commandCapArg.TypeError("string");
  }

  ERuleBPUnitCommandCaps commandCap = RULEUCC_None;
  gpg::RRef commandCapRef(&commandCap, CachedERuleBPUnitCommandCapsType());
  (void)commandCapRef.SetLexical(commandCapLexical);

  EUnitCommandType commandType = moho::UnitCommandCapToCommandType(commandCap);

  gpg::RRef commandTypeRef(&commandType, CachedEUnitCommandTypeType());
  const msvc8::string commandTypeLexical = commandTypeRef.GetLexical();
  lua_pushstring(rawState, commandTypeLexical.c_str());
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x0088D970 (FUN_0088D970, cfunc_EjectSessionClientL)
 *
 * What it does:
 * Validates one client index argument and ejects the selected non-local
 * client from the active session.
 */
int moho::cfunc_EjectSessionClientL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEjectSessionClientHelpText, 1, argumentCount);
  }

  auto* const simDriver = dynamic_cast<CSimDriver*>(WLD_GetDriver());
  if (simDriver == nullptr) {
    LuaPlus::LuaState::Error(state, kNoActiveSessionPeriodText);
  }

  IClientManager* const clientManager = simDriver->GetClientManager();
  if (clientManager == nullptr) {
    LuaPlus::LuaState::Error(state, kNoActiveSessionPeriodText);
  }

  LuaPlus::LuaStackObject clientIndexArg{};
  clientIndexArg.m_state = state;
  clientIndexArg.m_stackIndex = 1;
  if (lua_type(rawState, 1) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&clientIndexArg, "integer");
  }

  const int clientIndex = static_cast<int>(lua_tonumber(rawState, 1));
  const int clientCount = static_cast<int>(clientManager->NumberOfClients());
  if (clientIndex < 1 || clientIndex > clientCount) {
    LuaPlus::LuaState::Error(state, "Invalid client index %d, must be >= 1 and <= %d", clientIndex, clientCount);
  }

  IClient* const targetClient = clientManager->GetClient(clientIndex - 1);
  if (targetClient == nullptr) {
    LuaPlus::LuaState::Error(state, "Invalid client index %d, must be >= 1 and <= %d", clientIndex, clientCount);
  }

  if (targetClient == clientManager->GetLocalClient()) {
    LuaPlus::LuaState::Error(state, "Can't eject ourselves!");
  }

  targetClient->Eject();
  return 0;
}

/**
 * Address: 0x0088D8F0 (FUN_0088D8F0, cfunc_EjectSessionClient)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_EjectSessionClientL`.
 */
int moho::cfunc_EjectSessionClient(lua_State* const luaContext)
{
  return cfunc_EjectSessionClientL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0088D910 (FUN_0088D910, func_EjectSessionClient_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `EjectSessionClient`.
 */
moho::CScrLuaInitForm* moho::func_EjectSessionClient_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "EjectSessionClient",
    &moho::cfunc_EjectSessionClient,
    nullptr,
    "<global>",
    kEjectSessionClientHelpText
  );
  return &binder;
}

/**
 * Address: 0x0088DF50 (FUN_0088DF50, cfunc_WorldIsLoadingL)
 *
 * What it does:
 * Returns whether the current world frame action is loading or preload.
 */
int moho::cfunc_WorldIsLoadingL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kWorldIsLoadingHelpText, 0, argumentCount);
  }

  const EWldFrameAction frameAction = WLD_GetFrameAction();
  lua_pushboolean(
    state->m_state,
    frameAction == EWldFrameAction::Loading || frameAction == EWldFrameAction::Preload
  );
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x0088DED0 (FUN_0088DED0, cfunc_WorldIsLoading)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_WorldIsLoadingL`.
 */
int moho::cfunc_WorldIsLoading(lua_State* const luaContext)
{
  return cfunc_WorldIsLoadingL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0088DEF0 (FUN_0088DEF0, func_WorldIsLoading_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `WorldIsLoading`.
 */
moho::CScrLuaInitForm* moho::func_WorldIsLoading_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "WorldIsLoading",
    &moho::cfunc_WorldIsLoading,
    nullptr,
    "<global>",
    kWorldIsLoadingHelpText
  );
  return &binder;
}

/**
 * Address: 0x0088E030 (FUN_0088E030, cfunc_WorldIsPlayingL)
 *
 * What it does:
 * Returns whether the current world frame action is actively playing.
 */
int moho::cfunc_WorldIsPlayingL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kWorldIsPlayingHelpText, 0, argumentCount);
  }

  lua_pushboolean(state->m_state, WLD_GetFrameAction() == EWldFrameAction::Playing);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x0088DFB0 (FUN_0088DFB0, cfunc_WorldIsPlaying)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_WorldIsPlayingL`.
 */
int moho::cfunc_WorldIsPlaying(lua_State* const luaContext)
{
  return cfunc_WorldIsPlayingL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0088DFD0 (FUN_0088DFD0, func_WorldIsPlaying_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `WorldIsPlaying`.
 */
moho::CScrLuaInitForm* moho::func_WorldIsPlaying_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "WorldIsPlaying",
    &moho::cfunc_WorldIsPlaying,
    nullptr,
    "<global>",
    kWorldIsPlayingHelpText
  );
  return &binder;
}

/**
 * Address: 0x0088E260 (FUN_0088E260, cfunc_GetGameSpeedL)
 *
 * What it does:
 * Returns the current requested sim speed from the active client manager.
 */
int moho::cfunc_GetGameSpeedL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetGameSpeedHelpText, 0, argumentCount);
  }

  ISTIDriver* const activeDriver = WLD_GetDriver();
  if (activeDriver == nullptr) {
    LuaPlus::LuaState::Error(state, kNoActiveSessionPeriodText);
  }

  CClientManagerImpl* const clientManager = activeDriver->GetClientManager();
  lua_pushnumber(state->m_state, static_cast<float>(clientManager->GetSimRateRequested()));
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x0088E1E0 (FUN_0088E1E0, cfunc_GetGameSpeed)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_GetGameSpeedL`.
 */
int moho::cfunc_GetGameSpeed(lua_State* const luaContext)
{
  return cfunc_GetGameSpeedL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0088E200 (FUN_0088E200, func_GetGameSpeed_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetGameSpeed`.
 */
moho::CScrLuaInitForm* moho::func_GetGameSpeed_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetGameSpeed",
    &moho::cfunc_GetGameSpeed,
    nullptr,
    "<global>",
    kGetGameSpeedHelpText
  );
  return &binder;
}

/**
 * Address: 0x0088E360 (FUN_0088E360, cfunc_SetGameSpeedL)
 *
 * What it does:
 * Validates one requested speed and forwards it to the active client manager.
 */
int moho::cfunc_SetGameSpeedL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetGameSpeedHelpText, 1, argumentCount);
  }

  ISTIDriver* const activeDriver = WLD_GetDriver();
  if (activeDriver == nullptr) {
    LuaPlus::LuaState::Error(state, kNoActiveSessionPeriodText);
  }

  if (WLD_CanAdjustSimRate()) {
    CClientManagerImpl* const clientManager = activeDriver->GetClientManager();
    LuaPlus::LuaStackObject speedArg(state, 1);
    if (lua_type(state->m_state, 1) != LUA_TNUMBER) {
      LuaPlus::LuaStackObject::TypeError(&speedArg, "integer");
    }

    const int requestedSpeed = static_cast<int>(lua_tonumber(state->m_state, 1));
    clientManager->SetSimRate(requestedSpeed);
  }

  return 0;
}

/**
 * Address: 0x0088E2E0 (FUN_0088E2E0, cfunc_SetGameSpeed)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_SetGameSpeedL`.
 */
int moho::cfunc_SetGameSpeed(lua_State* const luaContext)
{
  return cfunc_SetGameSpeedL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0088E300 (FUN_0088E300, func_SetGameSpeed_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SetGameSpeed`.
 */
moho::CScrLuaInitForm* moho::func_SetGameSpeed_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetGameSpeed",
    &moho::cfunc_SetGameSpeed,
    nullptr,
    "<global>",
    kSetGameSpeedHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BDEC0 (FUN_008BDEC0, cfunc_AddToSessionExtraSelectListL)
 *
 * What it does:
 * Reads one user-unit Lua object and adds it to world-session extra selection.
 */
int moho::cfunc_AddToSessionExtraSelectListL(LuaPlus::LuaState* const state)
{
  if (CWldSession* const session = WLD_GetActiveSession(); session != nullptr) {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAddToSessionExtraSelectListHelpText, 1, argumentCount);
    }

    LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
    UserUnit* const userUnit = SCR_FromLua_UserUnit(unitObject, state);
    UserEntity* const userEntity = userUnit;  // base conversion, not a reinterpretation
    session->AddToExtraSelectList(userEntity);
  }

  return 0;
}

/**
 * Address: 0x008BDE40 (FUN_008BDE40, cfunc_AddToSessionExtraSelectList)
 *
 * What it does:
 * Unwraps Lua callback state and dispatches to
 * `cfunc_AddToSessionExtraSelectListL`.
 */
int moho::cfunc_AddToSessionExtraSelectList(lua_State* const luaContext)
{
  return cfunc_AddToSessionExtraSelectListL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BDE60 (FUN_008BDE60, func_AddToSessionExtraSelectList_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for
 * `AddToSessionExtraSelectList`.
 */
moho::CScrLuaInitForm* moho::func_AddToSessionExtraSelectList_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "AddToSessionExtraSelectList",
    &moho::cfunc_AddToSessionExtraSelectList,
    nullptr,
    "<global>",
    kAddToSessionExtraSelectListHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BDFF0 (FUN_008BDFF0, cfunc_RemoveFromSessionExtraSelectListL)
 *
 * What it does:
 * Reads one user-unit Lua object and removes it from world-session extra
 * selection.
 */
int moho::cfunc_RemoveFromSessionExtraSelectListL(LuaPlus::LuaState* const state)
{
  if (CWldSession* const session = WLD_GetActiveSession(); session != nullptr) {
    const int argumentCount = lua_gettop(state->m_state);
    if (argumentCount != 1) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kRemoveFromSessionExtraSelectListHelpText, 1, argumentCount);
    }

    LuaPlus::LuaObject unitObject(LuaPlus::LuaStackObject(state, 1));
    UserUnit* const userUnit = SCR_FromLua_UserUnit(unitObject, state);
    UserEntity* const userEntity = userUnit;  // base conversion, not a reinterpretation
    session->RemoveFromExtraSelectList(userEntity);
  }

  return 0;
}

/**
 * Address: 0x008BDF70 (FUN_008BDF70, cfunc_RemoveFromSessionExtraSelectList)
 *
 * What it does:
 * Unwraps Lua callback state and dispatches to
 * `cfunc_RemoveFromSessionExtraSelectListL`.
 */
int moho::cfunc_RemoveFromSessionExtraSelectList(lua_State* const luaContext)
{
  return cfunc_RemoveFromSessionExtraSelectListL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BDF90 (FUN_008BDF90, func_RemoveFromSessionExtraSelectList_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for
 * `RemoveFromSessionExtraSelectList`.
 */
moho::CScrLuaInitForm* moho::func_RemoveFromSessionExtraSelectList_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "RemoveFromSessionExtraSelectList",
    &moho::cfunc_RemoveFromSessionExtraSelectList,
    nullptr,
    "<global>",
    kRemoveFromSessionExtraSelectListHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BE0D0 (FUN_008BE0D0, cfunc_ClearSessionExtraSelectList)
 *
 * What it does:
 * Validates zero-argument call shape and clears the active session extra
 * selection set when a world session exists.
 */
int moho::cfunc_ClearSessionExtraSelectList(lua_State* const luaContext)
{
  LuaPlus::LuaState* const state = LuaPlus::LuaState::CastState(luaContext);
  CWldSession* const activeSession = WLD_GetActiveSession();
  if (activeSession == nullptr) {
    return 0;
  }

  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kClearSessionExtraSelectListHelpText, 0, argumentCount);
  }

  activeSession->ClearExtraSelectList();
  return 0;
}

/**
 * Address: 0x008BE120 (FUN_008BE120, func_ClearSessionExtraSelectList_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for
 * `ClearSessionExtraSelectList`.
 */
moho::CScrLuaInitForm* moho::func_ClearSessionExtraSelectList_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "ClearSessionExtraSelectList",
    &moho::cfunc_ClearSessionExtraSelectList,
    nullptr,
    "<global>",
    kClearSessionExtraSelectListHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BE1C0 (FUN_008BE1C0, cfunc_CurrentTime)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_CurrentTimeL`.
 */
int moho::cfunc_CurrentTime(lua_State* const luaContext)
{
  return cfunc_CurrentTimeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BE1E0 (FUN_008BE1E0, func_CurrentTime_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `CurrentTime`.
 */
moho::CScrLuaInitForm* moho::func_CurrentTime_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "CurrentTime",
    &moho::cfunc_CurrentTime,
    nullptr,
    "<global>",
    kCurrentTimeHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BE240 (FUN_008BE240, cfunc_CurrentTimeL)
 *
 * What it does:
 * Validates zero-argument call shape and returns wall-clock elapsed seconds.
 */
int moho::cfunc_CurrentTimeL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCurrentTimeHelpText, 0, argumentCount);
  }

  lua_pushnumber(rawState, gpg::time::GetSystemTimer().ElapsedSeconds());
  return 1;
}

/**
 * Address: 0x008BE2A0 (FUN_008BE2A0, cfunc_GameTime)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_GameTimeL`.
 */
int moho::cfunc_GameTime(lua_State* const luaContext)
{
  return cfunc_GameTimeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BE2C0 (FUN_008BE2C0, func_GameTime_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GameTime`.
 */
moho::CScrLuaInitForm* moho::func_GameTime_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GameTime",
    &moho::cfunc_GameTime,
    nullptr,
    "<global>",
    kGameTimeUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BE320 (FUN_008BE320, cfunc_GameTimeL)
 *
 * What it does:
 * Returns current game time in seconds from the active world session.
 */
int moho::cfunc_GameTimeL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGameTimeUserHelpText, 0, argumentCount);
  }

  const CWldSession* const session = WLD_GetActiveSession();
  if (!session) {
    LuaPlus::LuaState::Error(state, kNoActiveSessionText);
  }

  const float gameTimeSeconds = (static_cast<float>(session->mGameTick) + session->mTimeSinceLastTick) * 0.1f;
  lua_pushnumber(rawState, gameTimeSeconds);
  return 1;
}

/**
 * Address: 0x008BE3A0 (FUN_008BE3A0, cfunc_GameTick)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_GameTickL`.
 */
int moho::cfunc_GameTick(lua_State* const luaContext)
{
  return cfunc_GameTickL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BE3C0 (FUN_008BE3C0, func_GameTick_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GameTick`.
 */
moho::CScrLuaInitForm* moho::func_GameTick_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GameTick",
    &moho::cfunc_GameTick,
    nullptr,
    "<global>",
    kGameTickUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BE420 (FUN_008BE420, cfunc_GameTickL)
 *
 * What it does:
 * Returns current game time in ticks from the active world session.
 */
int moho::cfunc_GameTickL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGameTickUserHelpText, 0, argumentCount);
  }

  const CWldSession* const session = WLD_GetActiveSession();
  if (!session) {
    LuaPlus::LuaState::Error(state, kNoActiveSessionText);
  }

  lua_pushnumber(rawState, static_cast<float>(session->mGameTick));
  return 1;
}

/**
 * Address: 0x008BE490 (FUN_008BE490, cfunc_IsAllyUser)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_IsAllyUserL`.
 */
int moho::cfunc_IsAllyUser(lua_State* const luaContext)
{
  return cfunc_IsAllyUserL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BE4B0 (FUN_008BE4B0, func_IsAllyUser_LuaFuncDef)
 *
 * What it does:
 * Publishes the user-lane Lua binder definition for global `IsAlly`.
 */
moho::CScrLuaInitForm* moho::func_IsAllyUser_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "IsAlly",
    &moho::cfunc_IsAllyUser,
    nullptr,
    "<global>",
    kIsAllyUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BE510 (FUN_008BE510, cfunc_IsAllyUserL)
 *
 * What it does:
 * Resolves `(army1, army2)` and returns whether army1 treats army2 as ally.
 */
int moho::cfunc_IsAllyUserL(LuaPlus::LuaState* const state)
{
  if (!WLD_GetActiveSession()) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIsAllyUserHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject firstArmyObject(LuaPlus::LuaStackObject(state, 1));
  UserArmy* const firstArmy = USER_ResolveArmyFromLuaState(state, firstArmyObject);
  const LuaPlus::LuaObject secondArmyObject(LuaPlus::LuaStackObject(state, 2));
  UserArmy* const secondArmy = USER_ResolveArmyFromLuaState(state, secondArmyObject);

  const bool isAlly = firstArmy != nullptr && secondArmy != nullptr && firstArmy->IsAlly(secondArmy->mArmyIndex);
  lua_pushboolean(rawState, isAlly ? 1 : 0);
  return 1;
}

/**
 * Address: 0x008BE5D0 (FUN_008BE5D0, cfunc_IsEnemyUser)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_IsEnemyUserL`.
 */
int moho::cfunc_IsEnemyUser(lua_State* const luaContext)
{
  return cfunc_IsEnemyUserL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BE5F0 (FUN_008BE5F0, func_IsEnemyUser_LuaFuncDef)
 *
 * What it does:
 * Publishes the user-lane Lua binder definition for global `IsEnemy`.
 */
moho::CScrLuaInitForm* moho::func_IsEnemyUser_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "IsEnemy",
    &moho::cfunc_IsEnemyUser,
    nullptr,
    "<global>",
    kIsEnemyUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BE650 (FUN_008BE650, cfunc_IsEnemyUserL)
 *
 * What it does:
 * Resolves `(army1, army2)` and returns whether army1 treats army2 as enemy.
 */
int moho::cfunc_IsEnemyUserL(LuaPlus::LuaState* const state)
{
  if (!WLD_GetActiveSession()) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIsEnemyUserHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject firstArmyObject(LuaPlus::LuaStackObject(state, 1));
  UserArmy* const firstArmy = USER_ResolveArmyFromLuaState(state, firstArmyObject);
  const LuaPlus::LuaObject secondArmyObject(LuaPlus::LuaStackObject(state, 2));
  UserArmy* const secondArmy = USER_ResolveArmyFromLuaState(state, secondArmyObject);

  const bool isEnemy = firstArmy != nullptr && secondArmy != nullptr &&
    firstArmy->mVarDat.mEnemies.Contains(secondArmy->mArmyIndex);
  lua_pushboolean(rawState, isEnemy ? 1 : 0);
  return 1;
}

namespace
{
  /**
   * Address: 0x00707BF0 (FUN_00707BF0, func_IsNeutral)
   *
   * What it does:
   * Returns whether `targetArmyIndex` is in one neutral-relation bitset lane.
   * Legacy behavior treats `0xFFFFFFFF` as neutral by default.
   */
  [[nodiscard]] bool IsArmyMarkedNeutral(const std::uint32_t targetArmyIndex, const moho::BVIntSet& neutralSet) noexcept
  {
    if (targetArmyIndex == std::numeric_limits<std::uint32_t>::max()) {
      return true;
    }

    return neutralSet.Contains(targetArmyIndex);
  }
} // namespace

/**
 * Address: 0x008BE710 (FUN_008BE710, cfunc_IsNeutral)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_IsNeutralL`.
 */
int moho::cfunc_IsNeutral(lua_State* const luaContext)
{
  return cfunc_IsNeutralL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BE730 (FUN_008BE730, func_IsNeutral_LuaFuncDef)
 *
 * What it does:
 * Publishes the user-lane Lua binder definition for global `IsNeutral`.
 */
moho::CScrLuaInitForm* moho::func_IsNeutral_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "IsNeutral",
    &moho::cfunc_IsNeutral,
    nullptr,
    "<global>",
    kIsNeutralUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BE790 (FUN_008BE790, cfunc_IsNeutralL)
 *
 * What it does:
 * Resolves `(army1, army2)` and returns whether army1 treats army2 as neutral.
 */
int moho::cfunc_IsNeutralL(LuaPlus::LuaState* const state)
{
  if (!WLD_GetActiveSession()) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIsNeutralUserHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaObject firstArmyObject(LuaPlus::LuaStackObject(state, 1));
  UserArmy* const firstArmy = USER_ResolveArmyFromLuaState(state, firstArmyObject);
  const LuaPlus::LuaObject secondArmyObject(LuaPlus::LuaStackObject(state, 2));
  UserArmy* const secondArmy = USER_ResolveArmyFromLuaState(state, secondArmyObject);

  const bool isNeutral = firstArmy != nullptr && secondArmy != nullptr
    && IsArmyMarkedNeutral(secondArmy->mArmyIndex, firstArmy->mVarDat.mNeutrals);
  lua_pushboolean(rawState, isNeutral ? 1 : 0);
  return 1;
}

/**
 * Address: 0x008BE8D0 (FUN_008BE8D0, cfunc_SyncPlayableRectL)
 *
 * What it does:
 * Reads one rect table and synchronizes active-session playable bounds +
 * user-entity visibility against that rectangle.
 */
int moho::cfunc_SyncPlayableRectL(LuaPlus::LuaState* const state)
{
  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr || state == nullptr || state->m_state == nullptr) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSyncPlayableRectHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject rectObject(LuaPlus::LuaStackObject(state, 1));
  const gpg::Rect2i playableRect = SCR_FromLuaCopy<gpg::Rect2<int>>(rectObject);
  session->SyncPlayableRect(playableRect);
  return 0;
}

/**
 * Address: 0x008BE850 (FUN_008BE850, cfunc_SyncPlayableRect)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_SyncPlayableRectL`.
 */
int moho::cfunc_SyncPlayableRect(lua_State* const luaContext)
{
  return cfunc_SyncPlayableRectL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BE870 (FUN_008BE870, func_SyncPlayableRect_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SyncPlayableRect`.
 */
moho::CScrLuaInitForm* moho::func_SyncPlayableRect_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SyncPlayableRect",
    &moho::cfunc_SyncPlayableRect,
    nullptr,
    "<global>",
    kSyncPlayableRectHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BE980 (FUN_008BE980, cfunc_RandomUser)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_RandomUserL`.
 */
int moho::cfunc_RandomUser(lua_State* const luaContext)
{
  return cfunc_RandomUserL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BE9A0 (FUN_008BE9A0, func_RandomUser_LuaFuncDef)
 *
 * What it does:
 * Publishes the user-lane Lua binder definition for global `Random`.
 */
moho::CScrLuaInitForm* moho::func_RandomUser_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "Random",
    &moho::cfunc_RandomUser,
    nullptr,
    "<global>",
    kRandomUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BEA00 (FUN_008BEA00, cfunc_RandomUserL)
 *
 * What it does:
 * Produces one random float or integer range sample from the process-wide
 * random stream for `Random([[min,] max])`.
 */
int moho::cfunc_RandomUserL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount > 2) {
    LuaPlus::LuaState::Error(
      state,
      "%s\n  expected between %d and %d args, but got %d",
      kRandomUserHelpText,
      0,
      2,
      argumentCount
    );
  }

  boost::mutex::scoped_lock randomLock(math_GlobalRandomMutex);
  if (argumentCount == 0) {
    // 0x008BEB38..0x008BEB4D: `fild; jge; fadd 2^32; fmul [0x00E4F7B0]`, the
    // float 2^-32 (0x2F800000), stored to float once.
    constexpr float kInvTwoTo32 = 0x1p-32f;
    const float value = msvc8::MulTwisterWord(kInvTwoTo32, math_GlobalRandomStream.twister.NextUInt32());
    lua_pushnumber(rawState, value);
    return 1;
  }

  if (argumentCount == 1) {
    const int maxValue = LuaPlus::LuaStackObject(state, 1).GetInteger();
    const std::uint32_t randomValue = math_GlobalRandomStream.twister.NextUInt32();
    const std::uint32_t scaledValue = static_cast<std::uint32_t>(
      (static_cast<std::uint64_t>(static_cast<std::uint32_t>(maxValue)) * static_cast<std::uint64_t>(randomValue)) >>
      32u
    );
    const int result = static_cast<int>(scaledValue + 1u);
    lua_pushnumber(rawState, static_cast<float>(result));
    return 1;
  }

  const int minValue = LuaPlus::LuaStackObject(state, 1).GetInteger();
  const int maxValue = LuaPlus::LuaStackObject(state, 2).GetInteger();
  const std::uint32_t randomValue = math_GlobalRandomStream.twister.NextUInt32();
  const std::uint32_t span = (static_cast<std::uint32_t>(maxValue) + 1u) - static_cast<std::uint32_t>(minValue);
  const std::uint32_t scaledOffset =
    static_cast<std::uint32_t>((static_cast<std::uint64_t>(span) * static_cast<std::uint64_t>(randomValue)) >> 32u);
  const int result = static_cast<int>(static_cast<std::uint32_t>(minValue) + scaledOffset);
  lua_pushnumber(rawState, static_cast<float>(result));
  return 1;
}

/**
 * Address: 0x008B9D10 (FUN_008B9D10, cfunc_EntityCategoryContainsUserL)
 *
 * What it does:
 * Tests whether arg#1 category set contains arg#2 unit/blueprint category.
 */
int moho::cfunc_EntityCategoryContainsUserL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityCategoryContainsUserHelpText, 2, argumentCount);
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (!session || !session->mRules) {
    LuaPlus::LuaState::Error(state, kEntityCategoryContainsUserNoSessionText);
  }

  const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 1));
  EntityCategorySet* const categorySet = func_GetCObj_EntityCategory(categoryObject); // 0x005575E0: raises on a non-category

  const LuaPlus::LuaObject valueObject(LuaPlus::LuaStackObject(state, 2));
  const RUnitBlueprint* const blueprint = ResolveEntityCategoryFilterBlueprint(valueObject, session, state);

  const bool contains =
    categorySet != nullptr && blueprint != nullptr && categorySet->Bits().Contains(blueprint->mCategoryBitIndex);
  lua_pushboolean(rawState, contains ? 1 : 0);
  return 1;
}

/**
 * Address: 0x008B9C90 (FUN_008B9C90, cfunc_EntityCategoryContainsUser)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_EntityCategoryContainsUserL`.
 */
int moho::cfunc_EntityCategoryContainsUser(lua_State* const luaContext)
{
  return cfunc_EntityCategoryContainsUserL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008B9CB0 (FUN_008B9CB0, func_EntityCategoryContainsUser_LuaFuncDef)
 *
 * What it does:
 * Publishes the user-lane Lua binder definition for `EntityCategoryContains`.
 */
moho::CScrLuaInitForm* moho::func_EntityCategoryContainsUser_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "EntityCategoryContains",
    &moho::cfunc_EntityCategoryContainsUser,
    nullptr,
    "<global>",
    kEntityCategoryContainsUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x008B9F70 (FUN_008B9F70, cfunc_EntityCategoryFilterDownUserL)
 *
 * What it does:
 * Filters arg#2 values into a result table by keeping entries whose resolved
 * unit blueprint category bit is present in arg#1 category set.
 */
int moho::cfunc_EntityCategoryFilterDownUserL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityCategoryFilterDownUserHelpText, 2, argumentCount);
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (!session || !session->mRules) {
    LuaPlus::LuaState::Error(state, kEntityCategoryFilterDownUserNoSessionText);
  }

  if (lua_type(rawState, 1) == 0 || lua_type(rawState, 2) == 0) {
    return 0;
  }

  const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 1));
  EntityCategorySet* const categorySet = func_GetCObj_EntityCategory(categoryObject); // 0x005575E0: raises on a non-category
  if (!categorySet) {
    LuaPlus::LuaState::Error(state, kEntityCategoryFilterDownUserInvalidCategoryText);
  }

  const LuaPlus::LuaObject sourceListObject(LuaPlus::LuaStackObject(state, 2));
  LuaPlus::LuaObject resultObject(state);
  resultObject.AssignNewTable(state, 0, 0u);

  int resultIndex = 1;
  const int sourceCount = sourceListObject.GetCount();
  for (int sourceIndex = 1; sourceIndex <= sourceCount; ++sourceIndex) {
    LuaPlus::LuaObject valueObject = sourceListObject[sourceIndex];
    const RUnitBlueprint* const blueprint = ResolveEntityCategoryFilterBlueprint(valueObject, session, state);
    if (!blueprint) {
      continue;
    }

    if (categorySet->Bits().Contains(blueprint->mCategoryBitIndex)) {
      resultObject.SetObject(resultIndex, valueObject); // 0x008BA177: plain table set
      ++resultIndex;
    }
  }

  resultObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x008B9EF0 (FUN_008B9EF0, cfunc_EntityCategoryFilterDownUser)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_EntityCategoryFilterDownUserL`.
 */
int moho::cfunc_EntityCategoryFilterDownUser(lua_State* const luaContext)
{
  return cfunc_EntityCategoryFilterDownUserL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008B9F10 (FUN_008B9F10, func_EntityCategoryFilterDownUser_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `EntityCategoryFilterDown`.
 */
moho::CScrLuaInitForm* moho::func_EntityCategoryFilterDownUser_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "EntityCategoryFilterDown",
    &moho::cfunc_EntityCategoryFilterDownUser,
    nullptr,
    "<global>",
    kEntityCategoryFilterDownUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BA2A0 (FUN_008BA2A0, cfunc_EntityCategoryFilterOutL)
 *
 * What it does:
 * Filters arg#2 values into a result table by excluding entries whose resolved
 * unit blueprint category bit is present in arg#1 category set.
 */
int moho::cfunc_EntityCategoryFilterOutL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEntityCategoryFilterOutHelpText, 2, argumentCount);
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (!session || !session->mRules) {
    LuaPlus::LuaState::Error(state, kEntityCategoryFilterOutNoSessionText);
  }

  const LuaPlus::LuaObject categoryObject(LuaPlus::LuaStackObject(state, 1));
  EntityCategorySet* const categorySet = func_GetCObj_EntityCategory(categoryObject); // 0x005575E0: raises on a non-category
  if (!categorySet) {
    LuaPlus::LuaState::Error(state, kEntityCategoryFilterOutInvalidCategoryText);
  }

  const LuaPlus::LuaObject sourceListObject(LuaPlus::LuaStackObject(state, 2));
  LuaPlus::LuaObject resultObject(state);
  resultObject.AssignNewTable(state, 0, 0u);

  int resultIndex = 1;
  const int sourceCount = sourceListObject.GetCount();
  for (int sourceIndex = 1; sourceIndex <= sourceCount; ++sourceIndex) {
    LuaPlus::LuaObject valueObject = sourceListObject[sourceIndex];

    const RUnitBlueprint* const blueprint = ResolveEntityCategoryFilterBlueprint(valueObject, session, state);
    if (!blueprint) {
      continue;
    }

    if (!categorySet->Bits().Contains(blueprint->mCategoryBitIndex)) {
      resultObject.SetObject(resultIndex, valueObject); // 0x008BA4A9: plain table set
      ++resultIndex;
    }
  }

  resultObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x008BA220 (FUN_008BA220, cfunc_EntityCategoryFilterOut)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_EntityCategoryFilterOutL`.
 */
int moho::cfunc_EntityCategoryFilterOut(lua_State* const luaContext)
{
  return cfunc_EntityCategoryFilterOutL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BA240 (FUN_008BA240, func_EntityCategoryFilterOut_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `EntityCategoryFilterOut`.
 */
moho::CScrLuaInitForm* moho::func_EntityCategoryFilterOut_LuaFuncDef()
{
  // User, not Sim. The binary links this one into scr_UserInits
  // (FUN_008BA240) - the UI reads it while the front end comes up, and the
  // Sim set is not run against the user Lua state at all.
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "EntityCategoryFilterOut",
    &moho::cfunc_EntityCategoryFilterOut,
    nullptr,
    "<global>",
    kEntityCategoryFilterOutHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BA540 (FUN_008BA540, cfunc_ExecLuaInSim)
 *
 * What it does:
 * Unwraps raw Lua callback context and dispatches to `cfunc_ExecLuaInSimL`.
 */
int moho::cfunc_ExecLuaInSim(lua_State* const luaContext)
{
  return cfunc_ExecLuaInSimL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BA560 (FUN_008BA560, func_ExecLuaInSim_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `ExecLuaInSim`.
 */
moho::CScrLuaInitForm* moho::func_ExecLuaInSim_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "ExecLuaInSim",
    &moho::cfunc_ExecLuaInSim,
    nullptr,
    "<global>",
    kExecLuaInSimHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BA5C0 (FUN_008BA5C0, cfunc_ExecLuaInSimL)
 *
 * What it does:
 * Reads `(functionName,args)` from Lua and forwards one
 * `ExecuteLuaInSim(functionName,args)` request through the active sim driver.
 */
int moho::cfunc_ExecLuaInSimL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kExecLuaInSimHelpText, 2, argumentCount);
  }

  LuaPlus::LuaStackObject functionNameArg(state, 1);
  const char* functionNameText = lua_tostring(state->m_state, 1);
  if (!functionNameText) {
    LuaPlus::LuaStackObject::TypeError(&functionNameArg, "string");
    functionNameText = "";
  }

  const std::string functionName(functionNameText);
  if (ISTIDriver* const activeDriver = WLD_GetDriver(); activeDriver != nullptr) {
    LuaPlus::LuaObject callbackArgs(LuaPlus::LuaStackObject(state, 2));
    activeDriver->ExecuteLuaInSim(functionName.c_str(), callbackArgs);
  }
  return 0;
}

/**
 * Address: 0x008BA770 (FUN_008BA770, cfunc_SimCallbackL)
 *
 * What it does:
 * Reads callback payload (`Func`,`Args`) and optional selection forwarding
 * flag, then marshals `CMDST_LuaSimCallback` through the active sim driver.
 */
int moho::cfunc_SimCallbackL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount < 1 || argumentCount > 2) {
    LuaPlus::LuaState::Error(
      state,
      "%s\n  expected between %d and %d args, but got %d",
      kSimCallbackHelpText,
      1,
      2,
      argumentCount
    );
  }

  lua_settop(rawState, 2);

  lua_pushstring(rawState, "Func");
  lua_gettable(rawState, 1);
  const int callbackNameIndex = lua_gettop(rawState);
  LuaPlus::LuaStackObject callbackNameArg(state, callbackNameIndex);

  const char* callbackNameText = lua_tostring(rawState, callbackNameIndex);
  if (!callbackNameText) {
    LuaPlus::LuaStackObject::TypeError(&callbackNameArg, "string");
    callbackNameText = "";
  }
  const msvc8::string callbackName(callbackNameText);

  lua_pushstring(rawState, "Args");
  lua_gettable(rawState, 1);
  LuaPlus::LuaObject callbackArgs(LuaPlus::LuaStackObject(state, lua_gettop(rawState)));

  LuaPlus::LuaStackObject includeSelectionArg(state, 2);
  BVSet<EntId, EntIdUniverse> selectedEntities{};

  if (LuaPlus::LuaStackObject::GetBoolean(&includeSelectionArg)) {
    if (CWldSession* const session = WLD_GetActiveSession(); session != nullptr) {
      msvc8::vector<UserUnit*> selectedUnits{};
      session->GetSelectionUnits(selectedUnits);
      for (UserUnit* const selectedUnit : selectedUnits) {
        IUnit* const iunitBridge = ResolveIUnitBridge(selectedUnit);
        if (!iunitBridge) {
          continue;
        }

        selectedEntities.Bits().Add(static_cast<unsigned int>(iunitBridge->GetEntityId()));
      }
    }
  }

  if (ISTIDriver* const activeDriver = WLD_GetDriver(); activeDriver != nullptr) {
    activeDriver->LuaSimCallback(callbackName.c_str(), callbackArgs, selectedEntities);
  }
  return 0;
}

/**
 * Address: 0x008BA6F0 (FUN_008BA6F0, cfunc_SimCallback)
 *
 * What it does:
 * Unwraps raw Lua callback context and dispatches to `cfunc_SimCallbackL`.
 */
int moho::cfunc_SimCallback(lua_State* const luaContext)
{
  return cfunc_SimCallbackL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BA710 (FUN_008BA710, func_SimCallback_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SimCallback`.
 */
moho::CScrLuaInitForm* moho::func_SimCallback_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SimCallback",
    &moho::cfunc_SimCallback,
    nullptr,
    "<global>",
    kSimCallbackHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BADE0 (FUN_008BADE0, cfunc_SetAutoModeL)
 *
 * What it does:
 * Reads `(unitTable, enabled)` and emits one `SetAutoMode` info-pair per
 * live user-unit entry.
 */
int moho::cfunc_SetAutoModeL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetAutoModeHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject unitListObject(LuaPlus::LuaStackObject(state, 1));
  LuaPlus::LuaStackObject enabledArg(state, 2);
  const bool enabled = LuaPlus::LuaStackObject::GetBoolean(&enabledArg);

  if (!unitListObject.IsTable()) {
    return 0;
  }

  const int unitCount = unitListObject.GetCount();
  for (int unitIndex = 1; unitIndex <= unitCount; ++unitIndex) {
    LuaPlus::LuaObject valueObject = unitListObject[unitIndex];
    UserUnit* const userUnit = SCR_FromLua_UserUnit(valueObject, state);
    IUnit* const iunitBridge = ResolveIUnitBridge(userUnit);
    if (!iunitBridge || iunitBridge->IsDead()) {
      continue;
    }

    if (ISTIDriver* const activeDriver = WLD_GetDriver(); activeDriver != nullptr) {
      activeDriver->ProcessInfoPair(
        iunitBridge->GetEntityId(),
        "SetAutoMode",
        enabled ? "true" : "false"
      );
    }
  }

  return 0;
}

/**
 * Address: 0x008BAD60 (FUN_008BAD60, cfunc_SetAutoMode)
 *
 * What it does:
 * Unwraps raw Lua callback context and dispatches to `cfunc_SetAutoModeL`.
 */
int moho::cfunc_SetAutoMode(lua_State* const luaContext)
{
  return cfunc_SetAutoModeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BAD80 (FUN_008BAD80, func_SetAutoMode_LuaFuncDef)
 *
 * What it does:
 * Publishes the global user-Lua binder for `SetAutoMode`.
 */
moho::CScrLuaInitForm* moho::func_SetAutoMode_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetAutoMode",
    &moho::cfunc_SetAutoMode,
    nullptr,
    "<global>",
    kSetAutoModeHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BB360 (FUN_008BB360, cfunc_SetAutoSurfaceModeL)
 *
 * What it does:
 * Reads `(unitTable, enabled)` and emits one `SetAutoSurfaceMode` info-pair
 * per live user-unit entry.
 */
int moho::cfunc_SetAutoSurfaceModeL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetAutoSurfaceModeHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject unitListObject(LuaPlus::LuaStackObject(state, 1));
  LuaPlus::LuaStackObject enabledArg(state, 2);
  const bool enabled = LuaPlus::LuaStackObject::GetBoolean(&enabledArg);

  if (!unitListObject.IsTable()) {
    return 0;
  }

  const int unitCount = unitListObject.GetCount();
  for (int unitIndex = 1; unitIndex <= unitCount; ++unitIndex) {
    LuaPlus::LuaObject valueObject = unitListObject[unitIndex];
    UserUnit* const userUnit = SCR_FromLua_UserUnit(valueObject, state);
    IUnit* const iunitBridge = ResolveIUnitBridge(userUnit);
    if (!iunitBridge || iunitBridge->IsDead()) {
      continue;
    }

    if (ISTIDriver* const activeDriver = WLD_GetDriver(); activeDriver != nullptr) {
      activeDriver->ProcessInfoPair(
        iunitBridge->GetEntityId(),
        "SetAutoSurfaceMode",
        enabled ? "true" : "false"
      );
    }
  }

  return 0;
}

/**
 * Address: 0x008BB2E0 (FUN_008BB2E0, cfunc_SetAutoSurfaceMode)
 *
 * What it does:
 * Unwraps raw Lua callback context and dispatches to `cfunc_SetAutoSurfaceModeL`.
 */
int moho::cfunc_SetAutoSurfaceMode(lua_State* const luaContext)
{
  return cfunc_SetAutoSurfaceModeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BB300 (FUN_008BB300, func_SetAutoSurfaceMode_LuaFuncDef)
 *
 * What it does:
 * Publishes the user-lane Lua binder definition for `SetAutoSurfaceMode`.
 */
moho::CScrLuaInitForm* moho::func_SetAutoSurfaceMode_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetAutoSurfaceMode",
    &moho::cfunc_SetAutoSurfaceMode,
    nullptr,
    "<global>",
    kSetAutoSurfaceModeHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BBE60 (FUN_008BBE60, cfunc_ToggleScriptBitL)
 *
 * What it does:
 * Reads `(unitTable, bit, currentState)` and emits `ToggleScriptBit`
 * info-pairs for live units whose toggle-cap lane exposes that bit and whose
 * current script-bit value matches `currentState`.
 */
int moho::cfunc_ToggleScriptBitL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kToggleScriptBitExpectedArgsText, 3, argumentCount);
  }

  LuaPlus::LuaObject unitListObject(LuaPlus::LuaStackObject(state, 1));

  LuaPlus::LuaStackObject bitArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    bitArg.TypeError("integer");
  }
  const int bitIndex = static_cast<int>(lua_tonumber(rawState, 2));

  LuaPlus::LuaStackObject currentStateArg(state, 3);
  const bool currentState = currentStateArg.GetBoolean();

  char bitText[0x10]{};
  std::snprintf(bitText, sizeof(bitText), "%d", bitIndex);

  if (unitListObject.IsTable()) {
    const int unitCount = unitListObject.GetCount();
    for (int unitIndex = 1; unitIndex <= unitCount; ++unitIndex) {
      LuaPlus::LuaObject valueObject = unitListObject[unitIndex];
      UserUnit* const userUnit = SCR_FromLua_UserUnit(valueObject, state);
      IUnit* const iunitBridge = ResolveIUnitBridge(userUnit);
      if (!iunitBridge || iunitBridge->IsDead()) {
        continue;
      }

      const std::uint32_t toggleCapMask = 1u << (static_cast<std::uint32_t>(bitIndex) & 0x1Fu);
      if ((iunitBridge->GetAttributes().toggleCapsMask & toggleCapMask) == 0u) {
        continue;
      }

      // `cdq` at 0x008BBFE9: the bits are widened as a signed 32-bit value.
      const auto scriptBits = static_cast<std::int64_t>(static_cast<std::int32_t>(userUnit->mUnitVarDat.mScriptbits));
      const bool scriptBitStateMatches = (scriptBits & BuildScriptBitMask(bitIndex)) != 0;
      if (scriptBitStateMatches != currentState) {
        continue;
      }

      if (ISTIDriver* const activeDriver = WLD_GetDriver(); activeDriver != nullptr) {
        activeDriver->ProcessInfoPair(iunitBridge->GetEntityId(), "ToggleScriptBit", bitText);
      }
    }
  }

  return 0;
}

/**
 * Address: 0x008BBDE0 (FUN_008BBDE0, cfunc_ToggleScriptBit)
 *
 * What it does:
 * Unwraps raw Lua callback context and dispatches to `cfunc_ToggleScriptBitL`.
 */
int moho::cfunc_ToggleScriptBit(lua_State* const luaContext)
{
  return cfunc_ToggleScriptBitL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BBE00 (FUN_008BBE00, func_ToggleScriptBit_LuaFuncDef)
 *
 * What it does:
 * Publishes the user-lane Lua binder definition for `ToggleScriptBit`.
 */
moho::CScrLuaInitForm* moho::func_ToggleScriptBit_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "ToggleScriptBit",
    &moho::cfunc_ToggleScriptBit,
    nullptr,
    "<global>",
    kToggleScriptBitHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BC100 (FUN_008BC100, cfunc_SetPausedL)
 *
 * What it does:
 * Reads `(unitTable, paused)` and emits one `SetPaused` info-pair per live
 * user-unit entry while callback dispatch remains enabled.
 */
int moho::cfunc_SetPausedL(LuaPlus::LuaState* const state)
{
  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetPausedHelpText, 2, argumentCount);
  }

  LuaPlus::LuaObject unitListObject(LuaPlus::LuaStackObject(state, 1));
  LuaPlus::LuaStackObject pausedArg(state, 2);
  const bool paused = pausedArg.GetBoolean();

  if (unitListObject.IsTable()) {
    const int unitCount = unitListObject.GetCount();
    for (int unitIndex = 1; unitIndex <= unitCount; ++unitIndex) {
      LuaPlus::LuaObject valueObject = unitListObject[unitIndex];
      UserUnit* const userUnit = SCR_FromLua_UserUnit(valueObject, state);
      IUnit* const iunitBridge = ResolveIUnitBridge(userUnit);
      if (!iunitBridge || iunitBridge->IsDead()) {
        continue;
      }

      if (ISTIDriver* const activeDriver = WLD_GetDriver(); activeDriver != nullptr) {
        activeDriver->ProcessInfoPair(
          iunitBridge->GetEntityId(),
          "SetPaused",
          paused ? "true" : "false"
        );
      }
    }
  }

  return 0;
}

/**
 * Address: 0x008BC080 (FUN_008BC080, cfunc_SetPaused)
 *
 * What it does:
 * Unwraps raw Lua callback context and dispatches to `cfunc_SetPausedL`.
 */
int moho::cfunc_SetPaused(lua_State* const luaContext)
{
  return cfunc_SetPausedL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BC0A0 (FUN_008BC0A0, func_SetPaused_LuaFuncDef)
 *
 * What it does:
 * Publishes the user-lane Lua binder definition for `SetPaused`.
 */
moho::CScrLuaInitForm* moho::func_SetPaused_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetPaused",
    &moho::cfunc_SetPaused,
    nullptr,
    "<global>",
    kSetPausedHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BC280 (FUN_008BC280, cfunc_GetAttachedUnitsList)
 *
 * What it does:
 * Unwraps Lua callback state and dispatches to `cfunc_GetAttachedUnitsListL`.
 */
int moho::cfunc_GetAttachedUnitsList(lua_State* const luaContext)
{
  return cfunc_GetAttachedUnitsListL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BC2A0 (FUN_008BC2A0, func_GetAttachedUnitsList_LuaFuncDef)
 *
 * What it does:
 * Publishes the user-lane Lua binder definition for `GetAttachedUnitsList`.
 */
moho::CScrLuaInitForm* moho::func_GetAttachedUnitsList_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetAttachedUnitsList",
    &moho::cfunc_GetAttachedUnitsList,
    nullptr,
    "<global>",
    kGetAttachedUnitsListHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BC300 (FUN_008BC300, cfunc_GetAttachedUnitsListL)
 *
 * What it does:
 * Builds one Lua table containing alive attached user-unit script objects for
 * each source unit in the input table.
 */
int moho::cfunc_GetAttachedUnitsListL(LuaPlus::LuaState* const state)
{
  if (!WLD_GetActiveSession() || state == nullptr || state->m_state == nullptr) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetAttachedUnitsListHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject unitListObject(LuaPlus::LuaStackObject(state, 1));
  LuaPlus::LuaObject resultObject(state);
  resultObject.AssignNewTable(state, 0, 0);

  if (unitListObject.IsTable()) {
    int resultIndex = 1;
    const int unitCount = unitListObject.GetCount();
    for (int unitIndex = 1; unitIndex <= unitCount; ++unitIndex) {
      const LuaPlus::LuaObject sourceUnitObject = unitListObject[unitIndex];
      UserUnit* const sourceUnit = SCR_FromLua_UserUnit(sourceUnitObject, state);
      IUnit* const sourceUnitBridge = ResolveIUnitBridge(sourceUnit);
      if (sourceUnitBridge == nullptr || sourceUnitBridge->IsDead()) {
        continue;
      }

      UserEntity* const sourceEntity = reinterpret_cast<UserEntity*>(sourceUnit);
      CWldSession* const session = sourceEntity->mSession;
      if (session == nullptr) {
        continue;
      }

      for (const SSTIEntityAttachInfo& attachment : sourceEntity->mVariableData.mAuxValueVector) {
        UserEntity* const attachedEntity = FindUserSessionEntityById(session, attachment.mAttachedEntityId);
        if (attachedEntity == nullptr || attachedEntity->mVariableData.mIsDead != 0u) {
          continue;
        }

        UserUnit* const attachedUnit = attachedEntity->IsUserUnit();
        IUnit* const attachedUnitBridge = ResolveIUnitBridge(attachedUnit);
        if (attachedUnitBridge == nullptr) {
          continue;
        }

        LuaPlus::LuaObject attachedUnitObject = attachedUnitBridge->GetLuaObject();
        // 0x008BC4C9: `LuaObject::Insert(i, obj)` (Lua `table.insert`), not a raw store.
        resultObject.Insert(resultIndex, attachedUnitObject);
        ++resultIndex;
      }
    }
  }

  resultObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x008BC5F0 (FUN_008BC5F0, cfunc_ValidateUnitsListL)
 *
 * What it does:
 * Filters one input unit table down to alive, non-destroy-queued unit Lua
 * objects and returns the filtered table.
 */
int moho::cfunc_ValidateUnitsListL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  if (!WLD_GetActiveSession()) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kValidateUnitsListHelpText, 1, argumentCount);
  }

  LuaPlus::LuaObject unitListObject(LuaPlus::LuaStackObject(state, 1));
  LuaPlus::LuaObject resultObject(state);
  resultObject.AssignNewTable(state, 0, 0);

  if (unitListObject.IsTable()) {
    const int unitCount = unitListObject.GetCount();
    for (int unitIndex = 1; unitIndex <= unitCount; ++unitIndex) {
      LuaPlus::LuaObject unitObject = unitListObject[unitIndex];
      UserUnit* const userUnit = ResolveUserUnitOptional(unitObject, state);
      IUnit* const iunitBridge = ResolveIUnitBridge(userUnit);
      if (!iunitBridge || iunitBridge->IsDead() || iunitBridge->DestroyQueued()) {
        continue;
      }

      LuaPlus::LuaObject unitLuaObject = iunitBridge->GetLuaObject();
      // 0x008BC72C: `LuaObject::Insert(obj)` -- the Lua `table.insert(t, v)` append.
      resultObject.Insert(unitLuaObject);
    }
  }

  resultObject.PushStack(state);
  return 1;
}

/**
 * Address: 0x008BC570 (FUN_008BC570, cfunc_ValidateUnitsList)
 *
 * What it does:
 * Unwraps raw Lua callback context and dispatches to
 * `cfunc_ValidateUnitsListL`.
 */
int moho::cfunc_ValidateUnitsList(lua_State* const luaContext)
{
  return cfunc_ValidateUnitsListL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BC590 (FUN_008BC590, func_ValidateUnitsList_LuaFuncDef)
 *
 * What it does:
 * Publishes the user-lane Lua binder definition for `ValidateUnitsList`.
 */
moho::CScrLuaInitForm* moho::func_ValidateUnitsList_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "ValidateUnitsList",
    &moho::cfunc_ValidateUnitsList,
    nullptr,
    "<global>",
    kValidateUnitsListHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BC7A0 (FUN_008BC7A0, cfunc_GetAssistingUnitsList)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to
 * `cfunc_GetAssistingUnitsListL`.
 */
int moho::cfunc_GetAssistingUnitsList(lua_State* const luaContext)
{
  return cfunc_GetAssistingUnitsListL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BC7C0 (FUN_008BC7C0, func_GetAssistingUnitsList_LuaFuncDef)
 *
 * What it does:
 * Publishes the user-lane Lua binder definition for `GetAssistingUnitsList`.
 */
moho::CScrLuaInitForm* moho::func_GetAssistingUnitsList_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetAssistingUnitsList",
    &moho::cfunc_GetAssistingUnitsList,
    nullptr,
    "<global>",
    kGetAssistingUnitsListHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BC820 (FUN_008BC820, cfunc_GetAssistingUnitsListL)
 *
 * What it does:
 * Returns one Lua array of focused-army pod units that are assisting one of
 * the input units (or the unit itself when matching POD filters).
 */
int moho::cfunc_GetAssistingUnitsListL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr || session->mRules == nullptr) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetAssistingUnitsListHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject sourceUnitsObject(LuaPlus::LuaStackObject(state, 1));
  LuaPlus::LuaObject resultTable(state);
  resultTable.AssignNewTable(state, 0, 0u);

  const EntityCategorySet* const podStagingCategoryRange = session->mRules->GetEntityCategory("PODSTAGINGPLATFORM");
  const EntityCategorySet* const podCategoryRange = session->mRules->GetEntityCategory("POD");
  const EntityCategorySet* const podStagingCategory =
    podStagingCategoryRange != nullptr ? reinterpret_cast<const EntityCategorySet*>(podStagingCategoryRange) : nullptr;
  const EntityCategorySet* const podCategory =
    podCategoryRange != nullptr ? reinterpret_cast<const EntityCategorySet*>(podCategoryRange) : nullptr;
  const UserArmy* const focusArmy = session->GetFocusUserArmy();
  if (!sourceUnitsObject.IsTable() || podCategory == nullptr || focusArmy == nullptr) {
    resultTable.PushStack(state);
    return 1;
  }

  std::set<UserUnit*> emittedUnits{};

  const int sourceCount = sourceUnitsObject.GetCount();
  for (int sourceIndex = 1; sourceIndex <= sourceCount; ++sourceIndex) {
    const LuaPlus::LuaObject sourceObject = sourceUnitsObject[sourceIndex];
    UserUnit* const sourceUnit = ResolveUserUnitOptional(sourceObject, state);
    IUnit* const sourceBridge = ResolveIUnitBridge(sourceUnit);
    if (sourceBridge == nullptr || sourceBridge->IsDead() || sourceUnit->IsBeingBuilt()) {
      continue;
    }

    const REntityBlueprint* const sourceBlueprint = sourceBridge->GetBlueprint();
    const bool sourceIsPodStaging =
      (podStagingCategory != nullptr) && (sourceBlueprint != nullptr)
      && EntityCategory::HasBlueprint(sourceBlueprint, podStagingCategory);
    const bool sourceIsPod =
      (sourceBlueprint != nullptr) && EntityCategory::HasBlueprint(sourceBlueprint, podCategory);
    if (!sourceIsPodStaging && !sourceIsPod) {
      continue;
    }

    // Every entity in the session. The private walker this replaced returned
    // null unless the map head's `_Isnil` byte was set at +0x15, and the
    // session's own hand-written tree kept that flag at +0x19, so this loop
    // never ran and the query always came back empty.
    for (const auto& [entityId, entity] : session->mEntities) {
      if (entity == nullptr) {
        continue;
      }

      UserUnit* const candidateUnit = entity->IsUserUnit();
      IUnit* const candidateBridge = ResolveIUnitBridge(candidateUnit);
      if (candidateBridge == nullptr || candidateBridge->IsDead() || candidateUnit->IsBeingBuilt()) {
        continue;
      }

      UserEntity* const candidateEntity = reinterpret_cast<UserEntity*>(candidateUnit);
      if (candidateEntity->mArmy != focusArmy) {
        continue;
      }

      const REntityBlueprint* const candidateBlueprint = candidateBridge->GetBlueprint();
      if (candidateBlueprint == nullptr || !EntityCategory::HasBlueprint(candidateBlueprint, podCategory)) {
        continue;
      }

      // 0x008BCADF: kept when the candidate is the source or was built by it.
      if (candidateUnit != sourceUnit && candidateUnit->GetCreator() != sourceUnit) {
        continue;
      }

      if (!emittedUnits.insert(candidateUnit).second) {
        continue;
      }

      LuaPlus::LuaObject unitObject = candidateBridge->GetLuaObject();
      // 0x008BCB3E: `LuaObject::Insert(obj)` -- the Lua `table.insert(t, v)` append.
      resultTable.Insert(unitObject);
    }
  }

  resultTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x008BCC30 (FUN_008BCC30, cfunc_GetArmyAvatars)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetArmyAvatarsL`.
 */
int moho::cfunc_GetArmyAvatars(lua_State* const luaContext)
{
  return cfunc_GetArmyAvatarsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BCC50 (FUN_008BCC50, func_GetArmyAvatars_LuaFuncDef)
 *
 * What it does:
 * Publishes the user-lane Lua binder definition for `GetArmyAvatars`.
 */
moho::CScrLuaInitForm* moho::func_GetArmyAvatars_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetArmyAvatars",
    &moho::cfunc_GetArmyAvatars,
    nullptr,
    "<global>",
    kGetArmyAvatarsHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BCCB0 (FUN_008BCCB0, cfunc_GetArmyAvatarsL)
 *
 * What it does:
 * Returns one Lua array of focus-army avatar unit script objects.
 */
int moho::cfunc_GetArmyAvatarsL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr || session->GetFocusArmy() == nullptr) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetArmyAvatarsHelpText, 0, argumentCount);
  }

  const msvc8::vector<WeakPtr<UserUnit>> avatars = session->GetFocusArmy()->GetAvatars();
  if (avatars.empty()) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  LuaPlus::LuaObject resultTable(state);
  resultTable.AssignNewTable(state, static_cast<std::int32_t>(avatars.size()), 0u);

  std::int32_t luaIndex = 1;
  for (const WeakPtr<UserUnit>& avatar : avatars) {
    if (UserUnit* const unit = avatar.GetObjectPtr(); unit != nullptr) {
      LuaPlus::LuaObject unitObject = unit->GetLuaObject();
      resultTable.SetObject(luaIndex, unitObject);
      ++luaIndex;
    }
  }

  resultTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x008BCE70 (FUN_008BCE70, cfunc_GetIdleEngineers)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetIdleEngineersL`.
 */
int moho::cfunc_GetIdleEngineers(lua_State* const luaContext)
{
  return cfunc_GetIdleEngineersL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BCE90 (FUN_008BCE90, func_GetIdleEngineers_LuaFuncDef)
 *
 * What it does:
 * Publishes the user-lane Lua binder definition for `GetIdleEngineers`.
 */
moho::CScrLuaInitForm* moho::func_GetIdleEngineers_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetIdleEngineers",
    &moho::cfunc_GetIdleEngineers,
    nullptr,
    "<global>",
    kGetIdleEngineersHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BCEF0 (FUN_008BCEF0, cfunc_GetIdleEngineersL)
 *
 * What it does:
 * Returns one Lua array of focus-army idle engineer unit script objects.
 */
int moho::cfunc_GetIdleEngineersL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr || session->GetFocusArmy() == nullptr) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetIdleEngineersHelpText, 0, argumentCount);
  }

  WeakSet<UserUnit> idleUnits = session->GetFocusArmy()->GetIdleEngineers();
  if (idleUnits.Size() == 0) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  LuaPlus::LuaObject resultTable(state);
  resultTable.AssignNewTable(state, static_cast<std::int32_t>(idleUnits.Size()), 0u);

  std::int32_t luaIndex = 1;
  for (UserUnit* const unit : idleUnits) {
    if (unit != nullptr) {
      LuaPlus::LuaObject unitObject = unit->GetLuaObject();
      resultTable.SetObject(luaIndex, unitObject);
      ++luaIndex;
    }
  }

  resultTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x008BD100 (FUN_008BD100, cfunc_GetIdleFactories)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetIdleFactoriesL`.
 */
int moho::cfunc_GetIdleFactories(lua_State* const luaContext)
{
  return cfunc_GetIdleFactoriesL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BD120 (FUN_008BD120, func_GetIdleFactories_LuaFuncDef)
 *
 * What it does:
 * Publishes the user-lane Lua binder definition for `GetIdleFactories`.
 */
moho::CScrLuaInitForm* moho::func_GetIdleFactories_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetIdleFactories",
    &moho::cfunc_GetIdleFactories,
    nullptr,
    "<global>",
    kGetIdleFactoriesHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BD180 (FUN_008BD180, cfunc_GetIdleFactoriesL)
 *
 * What it does:
 * Returns one Lua array of focus-army idle factory unit script objects.
 */
int moho::cfunc_GetIdleFactoriesL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr || session->GetFocusArmy() == nullptr) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetIdleFactoriesHelpText, 0, argumentCount);
  }

  WeakSet<UserUnit> idleUnits = session->GetFocusArmy()->GetIdleFactories();
  if (idleUnits.Size() == 0) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  LuaPlus::LuaObject resultTable(state);
  resultTable.AssignNewTable(state, static_cast<std::int32_t>(idleUnits.Size()), 0u);

  std::int32_t luaIndex = 1;
  for (UserUnit* const unit : idleUnits) {
    if (unit != nullptr) {
      LuaPlus::LuaObject unitObject = unit->GetLuaObject();
      resultTable.SetObject(luaIndex, unitObject);
      ++luaIndex;
    }
  }

  resultTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x008BD680 (FUN_008BD680, cfunc_GetSelectedUnitsL)
 *
 * What it does:
 * Builds and returns a Lua array containing currently selected unit script objects.
 */
int moho::cfunc_GetSelectedUnitsL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (!session) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetSelectedUnitsHelpText, 0, argumentCount);
  }

  msvc8::vector<UserUnit*> selectedUnits{};
  session->GetSelectionUnits(selectedUnits);
  if (selectedUnits.empty()) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  LuaPlus::LuaObject resultTable(state);
  resultTable.AssignNewTable(state, static_cast<std::int32_t>(selectedUnits.size()), 0u);

  std::int32_t resultIndex = 1;
  for (UserUnit* const selectedUnit : selectedUnits) {
    IUnit* const iunitBridge = ResolveIUnitBridge(selectedUnit);
    if (!iunitBridge) {
      continue;
    }

    LuaPlus::LuaObject unitObject = iunitBridge->GetLuaObject();
    resultTable.SetObject(resultIndex, unitObject);
    ++resultIndex;
  }

  resultTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x008BD600 (FUN_008BD600, cfunc_GetSelectedUnits)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetSelectedUnitsL`.
 */
int moho::cfunc_GetSelectedUnits(lua_State* const luaContext)
{
  return cfunc_GetSelectedUnitsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BD620 (FUN_008BD620, func_GetSelectedUnits_LuaFuncDef)
 *
 * What it does:
 * Creates/returns the global Lua binder form for `GetSelectedUnits`.
 */
moho::CScrLuaInitForm* moho::func_GetSelectedUnits_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetSelectedUnits",
    &moho::cfunc_GetSelectedUnits,
    nullptr,
    "<global>",
    kGetSelectedUnitsHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BD410 (FUN_008BD410, cfunc_GetValidAttackingUnitsL)
 *
 * IDA signature:
 * int __cdecl cfunc_GetValidAttackingUnitsL(LuaPlus::LuaState *state);
 *
 * What it does:
 * Builds and returns a Lua array of the currently-selected units that can attack
 * the hovered target (via `CWldSession::GetValidAttackingUnits`), each as its
 * script object. Returns nil when the set is empty.
 */
int moho::cfunc_GetValidAttackingUnitsL(LuaPlus::LuaState* const state)
{
  CWldSession* const session = WLD_GetActiveSession();
  if (!session) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetValidAttackingUnitsHelpText, 0, argumentCount);
  }

  msvc8::vector<UserUnit*> validUnits{};
  session->GetValidAttackingUnits(validUnits);
  if (validUnits.empty()) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  LuaPlus::LuaObject resultTable(state);
  resultTable.AssignNewTable(state, static_cast<std::int32_t>(validUnits.size()), 0u);

  std::int32_t resultIndex = 1;
  for (UserUnit* const validUnit : validUnits) {
    IUnit* const iunitBridge = ResolveIUnitBridge(validUnit);
    if (!iunitBridge) {
      continue;
    }

    LuaPlus::LuaObject unitObject = iunitBridge->GetLuaObject();
    resultTable.SetObject(resultIndex, unitObject);
    ++resultIndex;
  }

  resultTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x008BD5C0 (FUN_008BD5C0, cfunc_GetValidAttackingUnits)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetValidAttackingUnitsL`.
 */
int moho::cfunc_GetValidAttackingUnits(lua_State* const luaContext)
{
  return cfunc_GetValidAttackingUnitsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BD3B0 (FUN_008BD3B0, func_GetValidAttackingUnits_LuaFuncDef)
 *
 * What it does:
 * Publishes the user-lane global Lua binder form for `GetValidAttackingUnits`.
 */
moho::CScrLuaInitForm* moho::func_GetValidAttackingUnits_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetValidAttackingUnits",
    &moho::cfunc_GetValidAttackingUnits,
    nullptr,
    "<global>",
    kGetValidAttackingUnitsHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BD870 (FUN_008BD870, cfunc_SelectUnits)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_SelectUnitsL`.
 */
int moho::cfunc_SelectUnits(lua_State* const luaContext)
{
  return cfunc_SelectUnitsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BD890 (FUN_008BD890, func_SelectUnits_LuaFuncDef)
 *
 * What it does:
 * Publishes the user-lane Lua binder definition for `SelectUnits`.
 */
moho::CScrLuaInitForm* moho::func_SelectUnits_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SelectUnits",
    &moho::cfunc_SelectUnits,
    nullptr,
    "<global>",
    kSelectUnitsHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BD8F0 (FUN_008BD8F0, cfunc_SelectUnitsL)
 *
 * What it does:
 * Builds one validated selection set from Lua input units and applies it to
 * the world session. FAF hot-patch (FA-Binary-Patches SelecUnitsTableFix): the
 * result table's AssignNewTable (0x008BD9BF) and PushStack (0x008BDBA6) are
 * NOPed and 0x008BDC18 returns 0, so nothing is returned.
 */
int moho::cfunc_SelectUnitsL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSelectUnitsHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject sourceUnitsObject(LuaPlus::LuaStackObject(state, 1));

  msvc8::vector<UserUnit*> selectionUnits{};
  if (sourceUnitsObject.IsTable()) {
    const int unitCount = sourceUnitsObject.GetCount();
    for (int unitIndex = 1; unitIndex <= unitCount; ++unitIndex) {
      const LuaPlus::LuaObject unitObject = sourceUnitsObject[unitIndex];
      UserUnit* const userUnit = ResolveUserUnitOptional(unitObject, state);
      IUnit* const iunitBridge = ResolveIUnitBridge(userUnit);
      if (!iunitBridge || iunitBridge->IsDead() || iunitBridge->DestroyQueued()) {
        continue;
      }

      UserEntity* const userEntity = userUnit;  // base conversion, not a reinterpretation
      if (userEntity != nullptr && userEntity->IsSelectable()) {
        AppendSelectionUnitUnique(selectionUnits, userUnit);
      } else if (UserUnit* const attachmentParent = ResolveSelectableTransportAttachmentParent(userUnit);
                 attachmentParent != nullptr) {
        AppendSelectionUnitUnique(selectionUnits, attachmentParent);
      }
    }
  }

  session->SetSelectionUnits(selectionUnits);
  return 0;
}

/**
 * Address: 0x008BDC30 (FUN_008BDC30, cfunc_AddSelectUnits)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_AddSelectUnitsL`.
 */
int moho::cfunc_AddSelectUnits(lua_State* const luaContext)
{
  return cfunc_AddSelectUnitsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008BDC50 (FUN_008BDC50, func_AddSelectUnits_LuaFuncDef)
 *
 * What it does:
 * Publishes the user-lane Lua binder definition for `AddSelectUnits`.
 */
moho::CScrLuaInitForm* moho::func_AddSelectUnits_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "AddSelectUnits",
    &moho::cfunc_AddSelectUnits,
    nullptr,
    "<global>",
    kAddSelectUnitsHelpText
  );
  return &binder;
}

/**
 * Address: 0x008BDCB0 (FUN_008BDCB0, cfunc_AddSelectUnitsL)
 *
 * What it does:
 * Adds validated selectable units from Lua input to current selection and
 * applies the merged set back into the world session.
 */
int moho::cfunc_AddSelectUnitsL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAddSelectUnitsHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaObject sourceUnitsObject(LuaPlus::LuaStackObject(state, 1));
  msvc8::vector<UserUnit*> mergedSelection{};
  session->GetSelectionUnits(mergedSelection);

  if (sourceUnitsObject.IsTable()) {
    const int unitCount = sourceUnitsObject.GetCount();
    for (int unitIndex = 1; unitIndex <= unitCount; ++unitIndex) {
      const LuaPlus::LuaObject unitObject = sourceUnitsObject[unitIndex];
      UserUnit* const userUnit = ResolveUserUnitOptional(unitObject, state);
      UserEntity* const userEntity = userUnit;  // base conversion, not a reinterpretation
      if (userEntity == nullptr || !userEntity->IsSelectable()) {
        continue;
      }
      AppendSelectionUnitUnique(mergedSelection, userUnit);
    }
  }

  session->SetSelectionUnits(mergedSelection);
  return 0;
}

/**
 * Address: 0x0083F000 (FUN_0083F000, func_EngineStartSplashScreens)
 *
 * What it does:
 * Casts Lua callback state, validates zero args, and starts splash-screen UI.
 */
int moho::func_EngineStartSplashScreens(lua_State* const luaContext)
{
  LuaPlus::LuaState* const state = LuaPlus::LuaState::CastState(luaContext);
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEngineStartSplashScreensHelpText, 0, argumentCount);
  }

  UI_StartSplashScreens();
  return 0;
}

/**
 * Address: 0x0083F040 (FUN_0083F040, func_EngineStartSplashScreens_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `EngineStartSplashScreens`.
 */
moho::CScrLuaInitForm* moho::func_EngineStartSplashScreens_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "EngineStartSplashScreens",
    &moho::func_EngineStartSplashScreens,
    nullptr,
    "<global>",
    kEngineStartSplashScreensHelpText
  );
  return &binder;
}

/**
 * Address: 0x0083F0E0 (FUN_0083F0E0, cfunc_EngineStartFrontEndUI)
 *
 * What it does:
 * Casts Lua callback state, validates zero args, and starts front-end UI.
 */
int moho::cfunc_EngineStartFrontEndUI(lua_State* const luaContext)
{
  LuaPlus::LuaState* const state = LuaPlus::LuaState::CastState(luaContext);
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kEngineStartFrontEndUIHelpText, 0, argumentCount);
  }

  UI_StartFrontEnd();
  return 0;
}

/**
 * Address: 0x0083F120 (FUN_0083F120, func_EngineStartFrontEndUI_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `EngineStartFrontEndUI`.
 */
moho::CScrLuaInitForm* moho::func_EngineStartFrontEndUI_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "EngineStartFrontEndUI",
    &moho::cfunc_EngineStartFrontEndUI,
    nullptr,
    "<global>",
    kEngineStartFrontEndUIHelpText
  );
  return &binder;
}

/**
 * Address: 0x0083F1C0 (FUN_0083F1C0, cfunc_ExitApplication)
 *
 * What it does:
 * Casts Lua callback state, validates zero args, and requests app shutdown.
 */
int moho::cfunc_ExitApplication(lua_State* const luaContext)
{
  LuaPlus::LuaState* const state = LuaPlus::LuaState::CastState(luaContext);
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kExitApplicationHelpText, 0, argumentCount);
  }

  wxTheApp->ExitMainLoop();
  return 0;
}

/**
 * Address: 0x0083F210 (FUN_0083F210, func_ExitApplication_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `ExitApplication`.
 */
moho::CScrLuaInitForm* moho::func_ExitApplication_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "ExitApplication",
    &moho::cfunc_ExitApplication,
    nullptr,
    "<global>",
    kExitApplicationHelpText
  );
  return &binder;
}

/**
 * Address: 0x0083F2B0 (FUN_0083F2B0, cfunc_ExitGame)
 *
 * What it does:
 * Casts Lua callback state, validates zero args, and requests sim exit.
 */
int moho::cfunc_ExitGame(lua_State* const luaContext)
{
  return cfunc_ExitGameL(LuaPlus::LuaState::CastState(luaContext));
}

/**
 * Address: 0x0083F360 (FUN_0083F360, sub_83F360)
 *
 * What it does:
 * Validates zero args and requests world-frame action `Exit`.
 */
int moho::cfunc_ExitGameL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kExitGameHelpText, 0, argumentCount);
  }

  if (WLD_GetFrameAction() != EWldFrameAction::Inactive) {
    WLD_SetFrameAction(EWldFrameAction::Exit);
  }

  return 0;
}

/**
 * Address: 0x0083F300 (FUN_0083F300, func_ExitGame_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `ExitGame`.
 */
moho::CScrLuaInitForm* moho::func_ExitGame_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "ExitGame",
    &moho::cfunc_ExitGame,
    nullptr,
    "<global>",
    kExitGameHelpText
  );
  return &binder;
}

/**
 * Address: 0x0083F3A0 (FUN_0083F3A0, cfunc_RestartSession)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_RestartSessionL`.
 */
int moho::cfunc_RestartSession(lua_State* const luaContext)
{
  return cfunc_RestartSessionL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0083F3C0 (FUN_0083F3C0, func_RestartSession_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `RestartSession`.
 */
moho::CScrLuaInitForm* moho::func_RestartSession_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "RestartSession",
    &moho::cfunc_RestartSession,
    nullptr,
    "<global>",
    kRestartSessionHelpText
  );
  return &binder;
}

/**
 * Address: 0x0083F420 (FUN_0083F420, cfunc_RestartSessionL)
 *
 * What it does:
 * Validates zero arguments and requests world-frame action `CreateSession`
 * when restart prerequisites are present.
 */
int moho::cfunc_RestartSessionL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kRestartSessionHelpText, 0, argumentCount);
  }

  if (WLD_GetFrameAction() != EWldFrameAction::Inactive) {
    CWldSession* const session = WLD_GetActiveSession();
    if (session != nullptr && session->mLaunchInfo.get() != nullptr) {
      WLD_SetFrameAction(EWldFrameAction::CreateSession);
    }
  }

  return 0;
}

/**
 * Address: 0x0083F470 (FUN_0083F470, cfunc_GetFrame)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetFrameL`.
 */
int moho::cfunc_GetFrame(lua_State* const luaContext)
{
  return cfunc_GetFrameL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0083F490 (FUN_0083F490, func_GetFrame_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetFrame`.
 */
moho::CScrLuaInitForm* moho::func_GetFrame_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetFrame",
    &moho::cfunc_GetFrame,
    nullptr,
    "<global>",
    kGetFrameHelpText
  );
  return &binder;
}

/**
 * Address: 0x0083F4F0 (FUN_0083F4F0, cfunc_GetFrameL)
 *
 * What it does:
 * Resolves one root UI frame index and pushes the corresponding Lua frame
 * object when it belongs to the same root Lua state.
 */
int moho::cfunc_GetFrameL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetFrameHelpText, 1, argumentCount);
  }

  CUIManager* const uiManager = static_cast<CUIManager*>(UI_GetManager());
  if (uiManager == nullptr || !uiManager->HasFrames()) {
    LuaPlus::LuaState::Error(state, kUiLayerNotInitializedText);
    return 1;
  }

  LuaPlus::LuaStackObject headArg(state, 1);
  if (lua_type(rawState, 1) != LUA_TNUMBER) {
    headArg.TypeError("number");
  }

  const int frameHead = static_cast<int>(lua_tonumber(rawState, 1));
  if (frameHead < 0 || static_cast<std::size_t>(frameHead) >= uiManager->mFrames.Size()) {
    return 0;
  }

  CMauiFrame* const frame = uiManager->mFrames[static_cast<std::size_t>(frameHead)].get();
  if (frame == nullptr) {
    return 0;
  }

  if (frame->mLuaObj.m_state != state->m_rootState) {
    return 0;
  }

  frame->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x0083F5D0 (FUN_0083F5D0, cfunc_ClearFrame)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_ClearFrameL`.
 */
int moho::cfunc_ClearFrame(lua_State* const luaContext)
{
  return cfunc_ClearFrameL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0083F5F0 (FUN_0083F5F0, func_ClearFrame_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `ClearFrame`.
 */
moho::CScrLuaInitForm* moho::func_ClearFrame_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "ClearFrame",
    &moho::cfunc_ClearFrame,
    nullptr,
    "<global>",
    kClearFrameHelpText
  );
  return &binder;
}

/**
 * Address: 0x0083F650 (FUN_0083F650, cfunc_ClearFrameL)
 *
 * What it does:
 * Clears one frame by index or all frames when the optional argument is nil.
 */
int moho::cfunc_ClearFrameL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount >= 2) {
    LuaPlus::LuaState::Error(
      state,
      "%s\n  expected between %d and %d args, but got %d",
      kClearFrameHelpText,
      0,
      1,
      argumentCount
    );
  }

  lua_settop(rawState, 1);

  CUIManager* const uiManager = static_cast<CUIManager*>(UI_GetManager());
  if (uiManager == nullptr || !uiManager->HasFrames()) {
    LuaPlus::LuaState::Error(state, kUiLayerNotInitializedText);
    return 0;
  }

  int frameHead = -1;
  if (lua_type(rawState, 1) != LUA_TNIL) {
    LuaPlus::LuaStackObject headArg(state, 1);
    frameHead = static_cast<int>(headArg.ToNumber());
  }

  uiManager->ClearChildren(frameHead);
  return 0;
}

/**
 * Address: 0x0083F700 (FUN_0083F700, cfunc_GetNumRootFrames)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetNumRootFramesL`.
 */
int moho::cfunc_GetNumRootFrames(lua_State* const luaContext)
{
  return cfunc_GetNumRootFramesL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0083F720 (FUN_0083F720, func_GetNumRootFrames_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetNumRootFrames`.
 */
moho::CScrLuaInitForm* moho::func_GetNumRootFrames_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetNumRootFrames",
    &moho::cfunc_GetNumRootFrames,
    nullptr,
    "<global>",
    kGetNumRootFramesHelpText
  );
  return &binder;
}

/**
 * Address: 0x0083F780 (FUN_0083F780, cfunc_GetNumRootFramesL)
 *
 * What it does:
 * Pushes the current root-frame count as a Lua number.
 */
int moho::cfunc_GetNumRootFramesL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetNumRootFramesHelpText, 0, argumentCount);
  }

  CUIManager* const uiManager = static_cast<CUIManager*>(UI_GetManager());
  if (uiManager != nullptr && uiManager->HasFrames()) {
    lua_pushnumber(rawState, static_cast<float>(uiManager->mFrames.Size()));
    (void)lua_gettop(rawState);
  } else {
    LuaPlus::LuaState::Error(state, kUiLayerNotInitializedText);
  }

  return 1;
}

/**
 * Address: 0x0083F880 (FUN_0083F880, cfunc_GetEconomyTotalsL)
 *
 * What it does:
 * Builds and returns one table containing focus-army economy totals.
 */
int moho::cfunc_GetEconomyTotalsL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetEconomyTotalsHelpText, 0, argumentCount);
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    gpg::Warnf(kGetEconomyTotalsMissingSessionWarning);
    return 0;
  }

  const UserArmy* const focusArmy = session->GetFocusUserArmy();
  const SEconTotals zeroTotals{};
  const SEconTotals& totals = focusArmy ? focusArmy->mVarDat.mEconomyTotals : zeroTotals;

  LuaPlus::LuaObject stored(state);
  stored.AssignNewTable(state, 2, 0u);
  LuaPlus::LuaObject income(state);
  income.AssignNewTable(state, 2, 0u);
  LuaPlus::LuaObject reclaimed(state);
  reclaimed.AssignNewTable(state, 2, 0u);
  LuaPlus::LuaObject lastUseRequested(state);
  lastUseRequested.AssignNewTable(state, 2, 0u);
  LuaPlus::LuaObject lastUseActual(state);
  lastUseActual.AssignNewTable(state, 2, 0u);
  LuaPlus::LuaObject maxStorage(state);
  maxStorage.AssignNewTable(state, 2, 0u);

  constexpr std::array<const char*, 2> kResourceLexical = {"ENERGY", "MASS"};
  const std::array<float, 2> storedValues = {totals.mStored.ENERGY, totals.mStored.MASS};
  const std::array<float, 2> incomeValues = {totals.mIncome.ENERGY, totals.mIncome.MASS};
  const std::array<float, 2> reclaimedValues = {totals.mReclaimed.ENERGY, totals.mReclaimed.MASS};
  const std::array<float, 2> requestedValues = {totals.mLastUseRequested.ENERGY, totals.mLastUseRequested.MASS};
  const std::array<float, 2> actualValues = {totals.mLastUseActual.ENERGY, totals.mLastUseActual.MASS};
  const std::array<std::uint32_t, 2> storageValues = {
    static_cast<std::uint32_t>(totals.mMaxStorage.ENERGY),
    static_cast<std::uint32_t>(totals.mMaxStorage.MASS)
  };

  for (std::size_t resourceIndex = 0; resourceIndex < kResourceLexical.size(); ++resourceIndex) {
    const char* const key = kResourceLexical[resourceIndex];
    stored.SetNumber(key, storedValues[resourceIndex]);
    income.SetNumber(key, incomeValues[resourceIndex]);
    reclaimed.SetNumber(key, reclaimedValues[resourceIndex]);
    lastUseRequested.SetNumber(key, requestedValues[resourceIndex]);
    lastUseActual.SetNumber(key, actualValues[resourceIndex]);
    maxStorage.SetInteger(key, static_cast<std::int32_t>(storageValues[resourceIndex]));
  }

  LuaPlus::LuaObject totalsTable(state);
  totalsTable.AssignNewTable(state, 6, 0u);
  totalsTable.SetObject("stored", stored);
  totalsTable.SetObject("income", income);
  totalsTable.SetObject("reclaimed", reclaimed);
  totalsTable.SetObject("lastUseRequested", lastUseRequested);
  totalsTable.SetObject("lastUseActual", lastUseActual);
  totalsTable.SetObject("maxStorage", maxStorage);

  totalsTable.PushStack(state);
  return 1;
}

/**
 * Address: 0x0083F800 (FUN_0083F800, cfunc_GetEconomyTotals)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetEconomyTotalsL`.
 */
int moho::cfunc_GetEconomyTotals(lua_State* const luaContext)
{
  return cfunc_GetEconomyTotalsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0083F820 (FUN_0083F820, func_GetEconomyTotals_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetEconomyTotals`.
 */
moho::CScrLuaInitForm* moho::func_GetEconomyTotals_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetEconomyTotals",
    &moho::cfunc_GetEconomyTotals,
    nullptr,
    "<global>",
    kGetEconomyTotalsHelpText
  );
  return &binder;
}

/**
 * Address: 0x0083FED0 (FUN_0083FED0, cfunc_GetResourceSharing)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetResourceSharingL`.
 */
int moho::cfunc_GetResourceSharing(lua_State* const luaContext)
{
  return cfunc_GetResourceSharingL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x0083FEF0 (FUN_0083FEF0, func_GetResourceSharing_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetResourceSharing`.
 */
moho::CScrLuaInitForm* moho::func_GetResourceSharing_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetResourceSharing",
    &moho::cfunc_GetResourceSharing,
    nullptr,
    "<global>",
    kGetResourceSharingHelpText
  );
  return &binder;
}

/**
 * Address: 0x0083FF50 (FUN_0083FF50, cfunc_GetResourceSharingL)
 *
 * What it does:
 * Pushes whether the focused user army has resource sharing enabled.
 */
int moho::cfunc_GetResourceSharingL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetResourceSharingHelpText, 0, argumentCount);
  }

  const CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    gpg::Warnf(kGetEconomyTotalsMissingSessionWarning);
    return 0;
  }

  bool isResourceSharingEnabled = false;
  const int focusArmyIndex = session->FocusArmy;
  if (focusArmyIndex >= 0) {
    const std::size_t armyIndex = static_cast<std::size_t>(focusArmyIndex);
    if (armyIndex < session->userArmies.size()) {
      const UserArmy* const focusedArmy = session->userArmies[armyIndex];
      if (focusedArmy != nullptr && focusedArmy->mVarDat.mIsResourceSharingEnabled != 0u) {
        isResourceSharingEnabled = true;
      }
    }
  }

  lua_pushboolean(rawState, isResourceSharingEnabled ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x008420A0 (FUN_008420A0, cfunc_GetCurrentUIState)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetCurrentUIStateL`.
 */
int moho::cfunc_GetCurrentUIState(lua_State* const luaContext)
{
  return cfunc_GetCurrentUIStateL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008420C0 (FUN_008420C0, func_GetCurrentUIState_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetCurrentUIState`.
 */
moho::CScrLuaInitForm* moho::func_GetCurrentUIState_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetCurrentUIState",
    &moho::cfunc_GetCurrentUIState,
    nullptr,
    "<global>",
    kGetCurrentUIStateHelpText
  );
  return &binder;
}

/**
 * Address: 0x00842120 (FUN_00842120, cfunc_GetCurrentUIStateL)
 *
 * What it does:
 * Pushes current UI-state lexical value (`splash`, `frontend`, or `game`).
 */
int moho::cfunc_GetCurrentUIStateL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetCurrentUIStateHelpText, 0, argumentCount);
  }

  gpg::RRef currentUiStateRef{};
  gpg::RRef::CurrentUIState(&currentUiStateRef);
  const msvc8::string lexical = currentUiStateRef.GetLexical();
  lua_pushstring(rawState, lexical.c_str());
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x0083FFE0 (FUN_0083FFE0, cfunc_GetSimTicksPerSecond)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetSimTicksPerSecondL`.
 */
int moho::cfunc_GetSimTicksPerSecond(lua_State* const luaContext)
{
  return cfunc_GetSimTicksPerSecondL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00840000 (FUN_00840000, func_GetSimTicksPerSecond_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetSimTicksPerSecond`.
 */
moho::CScrLuaInitForm* moho::func_GetSimTicksPerSecond_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetSimTicksPerSecond",
    &moho::cfunc_GetSimTicksPerSecond,
    nullptr,
    "<global>",
    kGetSimTicksPerSecondHelpText
  );
  return &binder;
}

/**
 * Address: 0x00840060 (FUN_00840060, cfunc_GetSimTicksPerSecondL)
 *
 * What it does:
 * Pushes fixed simulation ticks-per-second (10.0) as a Lua number.
 */
int moho::cfunc_GetSimTicksPerSecondL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetSimTicksPerSecondHelpText, 0, argumentCount);
  }

  lua_pushnumber(rawState, 10.0);
  return 1;
}

/**
 * Address: 0x00897780 (FUN_00897780, cfunc_SessionRequestPause)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_SessionRequestPauseL`.
 */
int moho::cfunc_SessionRequestPause(lua_State* const luaContext)
{
  return cfunc_SessionRequestPauseL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008977A0 (FUN_008977A0, func_SessionRequestPause_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SessionRequestPause`.
 */
moho::CScrLuaInitForm* moho::func_SessionRequestPause_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SessionRequestPause",
    &moho::cfunc_SessionRequestPause,
    nullptr,
    "<global>",
    kSessionRequestPauseHelpText
  );
  return &binder;
}

/**
 * Address: 0x00897800 (FUN_00897800, cfunc_SessionRequestPauseL)
 *
 * What it does:
 * Requests world-session pause from Lua after validating active session.
 */
int moho::cfunc_SessionRequestPauseL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSessionRequestPauseHelpText, 0, argumentCount);
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, kSessionRequestPauseNoActiveSessionText);
  }

  session->RequestPause();
  return 0;
}

/**
 * Address: 0x00897850 (FUN_00897850, cfunc_SessionResume)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_SessionResumeL`.
 */
int moho::cfunc_SessionResume(lua_State* const luaContext)
{
  return cfunc_SessionResumeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00897870 (FUN_00897870, func_SessionResume_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SessionResume`.
 */
moho::CScrLuaInitForm* moho::func_SessionResume_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SessionResume",
    &moho::cfunc_SessionResume,
    nullptr,
    "<global>",
    kSessionResumeHelpText
  );
  return &binder;
}

/**
 * Address: 0x008978D0 (FUN_008978D0, cfunc_SessionResumeL)
 *
 * What it does:
 * Requests world-session resume from Lua after validating active session.
 */
int moho::cfunc_SessionResumeL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSessionResumeHelpText, 0, argumentCount);
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, kSessionResumeNoActiveSessionText);
  }

  session->Resume();
  return 0;
}

/**
 * Address: 0x00897920 (FUN_00897920, cfunc_SessionIsPaused)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_SessionIsPausedL`.
 */
int moho::cfunc_SessionIsPaused(lua_State* const luaContext)
{
  return cfunc_SessionIsPausedL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00897940 (FUN_00897940, func_SessionIsPaused_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SessionIsPaused`.
 */
moho::CScrLuaInitForm* moho::func_SessionIsPaused_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SessionIsPaused",
    &moho::cfunc_SessionIsPaused,
    nullptr,
    "<global>",
    kSessionIsPausedHelpText
  );
  return &binder;
}

/**
 * Address: 0x008979A0 (FUN_008979A0, cfunc_SessionIsPausedL)
 *
 * What it does:
 * Pushes pause state from replay/requested/non-local session lanes.
 */
int moho::cfunc_SessionIsPausedL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, kSessionIsPausedNoActiveSessionText);
  }

  std::uint8_t isPaused = 0;
  if (session->IsReplay) {
    isPaused = session->mReplayIsPaused;
  } else if (session->mRequestingPauseState != 0u) {
    isPaused = session->mRequestingPause;
  } else {
    isPaused = session->mSessionPauseStateA;
  }

  lua_pushboolean(state->m_state, isPaused != 0u ? 1 : 0);
  return 1;
}

/**
 * Address: 0x00897A00 (FUN_00897A00, cfunc_SessionIsGameOver)
 *
 * What it does:
 * Pushes whether the active world-session game-over flag is set.
 */
int moho::cfunc_SessionIsGameOver(lua_State* const luaContext)
{
  LuaPlus::LuaState* const state = LuaPlus::LuaState::CastState(luaContext);
  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, kSessionIsGameOverNoActiveSessionText);
  }

  lua_pushboolean(state->m_state, session->IsGameOver != 0u ? 1 : 0);
  return 1;
}

/**
 * Address: 0x00897A50 (FUN_00897A50, func_SessionIsGameOver_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SessionIsGameOver`.
 */
moho::CScrLuaInitForm* moho::func_SessionIsGameOver_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SessionIsGameOver",
    &moho::cfunc_SessionIsGameOver,
    nullptr,
    "<global>",
    kSessionIsGameOverHelpText
  );
  return &binder;
}

/**
 * Address: 0x00897C70 (FUN_00897C70, cfunc_SessionGetLocalCommandSource)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to
 * `cfunc_SessionGetLocalCommandSourceL`.
 */
int moho::cfunc_SessionGetLocalCommandSource(lua_State* const luaContext)
{
  return cfunc_SessionGetLocalCommandSourceL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00897C90 (FUN_00897C90, func_SessionGetLocalCommandSource_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SessionGetLocalCommandSource`.
 */
moho::CScrLuaInitForm* moho::func_SessionGetLocalCommandSource_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SessionGetLocalCommandSource",
    &moho::cfunc_SessionGetLocalCommandSource,
    nullptr,
    "<global>",
    kSessionGetLocalCommandSourceHelpText
  );
  return &binder;
}

/**
 * Address: 0x00897CF0 (FUN_00897CF0, cfunc_SessionGetLocalCommandSourceL)
 *
 * What it does:
 * Returns one-based local command-source id (`0` when unavailable).
 */
int moho::cfunc_SessionGetLocalCommandSourceL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSessionGetLocalCommandSourceHelpText, 0, argumentCount);
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, kSessionGetLocalCommandSourceNoActiveSessionText);
  }

  int localCommandSource = session->ourCmdSource;
  if (localCommandSource == static_cast<int>(kInvalidCommandSource)) {
    localCommandSource = 0;
  } else {
    ++localCommandSource;
  }

  lua_pushnumber(rawState, static_cast<float>(localCommandSource));
  return 1;
}

/**
 * Address: 0x00897D70 (FUN_00897D70, cfunc_SessionIsReplayUser)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_SessionIsReplayUserL`.
 */
int moho::cfunc_SessionIsReplayUser(lua_State* const luaContext)
{
  return cfunc_SessionIsReplayUserL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00897D90 (FUN_00897D90, func_SessionIsReplayUser_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SessionIsReplay`.
 */
moho::CScrLuaInitForm* moho::func_SessionIsReplayUser_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SessionIsReplay",
    &moho::cfunc_SessionIsReplayUser,
    nullptr,
    "<global>",
    kSessionIsReplayUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x00897DF0 (FUN_00897DF0, cfunc_SessionIsReplayUserL)
 *
 * What it does:
 * Pushes whether the active world-session is replay-backed.
 */
int moho::cfunc_SessionIsReplayUserL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSessionIsReplayUserHelpText, 0, argumentCount);
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, kSessionGetScenarioInfoNoActiveSessionText);
  }

  lua_pushboolean(rawState, session->IsReplay ? 1 : 0);
  return 1;
}

/**
 * Address: 0x00897E60 (FUN_00897E60, cfunc_SessionIsBeingRecorded)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to
 * `cfunc_SessionIsBeingRecordedL`.
 */
int moho::cfunc_SessionIsBeingRecorded(lua_State* const luaContext)
{
  return cfunc_SessionIsBeingRecordedL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00897E80 (FUN_00897E80, func_SessionIsBeingRecorded_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SessionIsBeingRecorded`.
 */
moho::CScrLuaInitForm* moho::func_SessionIsBeingRecorded_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SessionIsBeingRecorded",
    &moho::cfunc_SessionIsBeingRecorded,
    nullptr,
    "<global>",
    kSessionIsBeingRecordedHelpText
  );
  return &binder;
}

/**
 * Address: 0x00897EE0 (FUN_00897EE0, cfunc_SessionIsBeingRecordedL)
 *
 * What it does:
 * Pushes whether the active world-session is currently being recorded.
 */
int moho::cfunc_SessionIsBeingRecordedL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSessionIsBeingRecordedHelpText, 0, argumentCount);
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, kSessionGetScenarioInfoNoActiveSessionText);
  }

  lua_pushboolean(rawState, session->IsBeingRecorded ? 1 : 0);
  return 1;
}

/**
 * Address: 0x00897F50 (FUN_00897F50, cfunc_SessionIsMultiplayer)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_SessionIsMultiplayerL`.
 */
int moho::cfunc_SessionIsMultiplayer(lua_State* const luaContext)
{
  return cfunc_SessionIsMultiplayerL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00897F70 (FUN_00897F70, func_SessionIsMultiplayer_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SessionIsMultiplayer`.
 */
moho::CScrLuaInitForm* moho::func_SessionIsMultiplayer_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SessionIsMultiplayer",
    &moho::cfunc_SessionIsMultiplayer,
    nullptr,
    "<global>",
    kSessionIsMultiplayerHelpText
  );
  return &binder;
}

/**
 * Address: 0x00897FD0 (FUN_00897FD0, cfunc_SessionIsMultiplayerL)
 *
 * What it does:
 * Pushes whether the active world-session is multiplayer.
 */
int moho::cfunc_SessionIsMultiplayerL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSessionIsMultiplayerHelpText, 0, argumentCount);
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, kSessionGetScenarioInfoNoActiveSessionText);
  }

  lua_pushboolean(rawState, session->IsMultiplayer ? 1 : 0);
  return 1;
}

/**
 * Address: 0x00898040 (FUN_00898040, cfunc_SessionIsObservingAllowed)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to
 * `cfunc_SessionIsObservingAllowedL`.
 */
int moho::cfunc_SessionIsObservingAllowed(lua_State* const luaContext)
{
  return cfunc_SessionIsObservingAllowedL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00898060 (FUN_00898060, func_SessionIsObservingAllowed_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SessionIsObservingAllowed`.
 */
moho::CScrLuaInitForm* moho::func_SessionIsObservingAllowed_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SessionIsObservingAllowed",
    &moho::cfunc_SessionIsObservingAllowed,
    nullptr,
    "<global>",
    kSessionIsObservingAllowedHelpText
  );
  return &binder;
}

/**
 * Address: 0x008980C0 (FUN_008980C0, cfunc_SessionIsObservingAllowedL)
 *
 * What it does:
 * Pushes whether observing is enabled for the active world-session.
 */
int moho::cfunc_SessionIsObservingAllowedL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSessionIsObservingAllowedHelpText, 0, argumentCount);
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, kSessionGetScenarioInfoNoActiveSessionText);
  }

  lua_pushboolean(rawState, session->IsObservingAllowed ? 1 : 0);
  return 1;
}

/**
 * Address: 0x00898130 (FUN_00898130, cfunc_SessionCanRestart)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_SessionCanRestartL`.
 */
int moho::cfunc_SessionCanRestart(lua_State* const luaContext)
{
  return cfunc_SessionCanRestartL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00898150 (FUN_00898150, func_SessionCanRestart_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SessionCanRestart`.
 */
moho::CScrLuaInitForm* moho::func_SessionCanRestart_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SessionCanRestart",
    &moho::cfunc_SessionCanRestart,
    nullptr,
    "<global>",
    kSessionCanRestartHelpText
  );
  return &binder;
}

/**
 * Address: 0x008981B0 (FUN_008981B0, cfunc_SessionCanRestartL)
 *
 * What it does:
 * Pushes whether restart launch metadata exists for the active session.
 */
int moho::cfunc_SessionCanRestartL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSessionCanRestartHelpText, 0, argumentCount);
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, kSessionGetScenarioInfoNoActiveSessionText);
  }

  lua_pushboolean(rawState, session->mLaunchInfo.get() != nullptr ? 1 : 0);
  return 1;
}

/**
 * Address: 0x00898220 (FUN_00898220, cfunc_SessionIsActive)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_SessionIsActiveL`.
 */
int moho::cfunc_SessionIsActive(lua_State* const luaContext)
{
  return cfunc_SessionIsActiveL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00898240 (FUN_00898240, func_SessionIsActive_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SessionIsActive`.
 */
moho::CScrLuaInitForm* moho::func_SessionIsActive_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SessionIsActive",
    &moho::cfunc_SessionIsActive,
    nullptr,
    "<global>",
    kSessionIsActiveHelpText
  );
  return &binder;
}

/**
 * Address: 0x008982A0 (FUN_008982A0, cfunc_SessionIsActiveL)
 *
 * What it does:
 * Pushes whether any world-session is currently active.
 */
int moho::cfunc_SessionIsActiveL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSessionIsActiveHelpText, 0, argumentCount);
  }

  lua_pushboolean(rawState, WLD_GetActiveSession() != nullptr ? 1 : 0);
  return 1;
}

/**
 * Address: 0x008982F0 (FUN_008982F0, cfunc_SessionGetScenarioInfo)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to
 * `cfunc_SessionGetScenarioInfoL`.
 */
int moho::cfunc_SessionGetScenarioInfo(lua_State* const luaContext)
{
  return cfunc_SessionGetScenarioInfoL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00898310 (FUN_00898310, func_SessionGetScenarioInfo_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SessionGetScenarioInfo`.
 */
moho::CScrLuaInitForm* moho::func_SessionGetScenarioInfo_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SessionGetScenarioInfo",
    &moho::cfunc_SessionGetScenarioInfo,
    nullptr,
    "<global>",
    kSessionGetScenarioInfoHelpText
  );
  return &binder;
}

/**
 * Address: 0x00898370 (FUN_00898370, cfunc_SessionGetScenarioInfoL)
 *
 * What it does:
 * Validates user-lua state ownership and pushes the active session
 * `ScenarioInfo` table.
 */
int moho::cfunc_SessionGetScenarioInfoL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSessionGetScenarioInfoHelpText, 0, argumentCount);
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (!session) {
    LuaPlus::LuaState::Error(state, kSessionGetScenarioInfoNoActiveSessionText);
  }

  if (state->m_rootState != session->mState) {
    LuaPlus::LuaState::Error(state, kWrongLuaStateText);
  }

  const LuaPlus::LuaObject scenarioInfo = session->GetScenarioInfo();
  scenarioInfo.PushStack(state);
  return 1;
}

/**
 * Address: 0x00898430 (FUN_00898430, cfunc_SessionEndGame)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_SessionEndGameL`.
 */
int moho::cfunc_SessionEndGame(lua_State* const luaContext)
{
  return cfunc_SessionEndGameL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00898450 (FUN_00898450, func_SessionEndGame_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SessionEndGame`.
 */
moho::CScrLuaInitForm* moho::func_SessionEndGame_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SessionEndGame",
    &moho::cfunc_SessionEndGame,
    nullptr,
    "<global>",
    kSessionEndGameHelpText
  );
  return &binder;
}

/**
 * Address: 0x008984B0 (FUN_008984B0, j_func_SessionEndGame)
 *
 * What it does:
 * Validates zero args, then disconnects every client from the active sim
 * driver. The world session is deliberately left alive - the help text spells
 * this out: play freezes, it is not torn down.
 *
 * In game version 3835's exe FAF's old desync fix has overwritten the first
 * nine bytes at 0x008984B0 with a `jmp` into `.exxt` (0x0128F9A0) + four
 * `nop`s, so IDA shows only the replacement - which wraps this same logic in
 * a quit handshake (a `WaitForSingleObject` of up to 9.5 s for the other
 * clients' acknowledgement, then zeroing its client table). FA-Binary-Patches
 * #173 (Remove old desync-fix code, 3840) removed it. The engine's own body is
 * still present in the image directly behind the patch, and it is what this
 * recovery follows:
 *
 *   0x008984B9  push eax / call lua_gettop / test eax,eax / jz 0x008984D8
 *   0x008984C6  push eax, 0, esi(help), "%s\n  expected %d args, but got %d",
 *               edi(state) -> LuaPlus::LuaState::Error
 *   0x008984D8  mov eax, sSimDriver ; test ; jnz 0x008984F1
 *   0x008984E3  push "no active session." / edi -> LuaState::Error
 *   0x008984F1  mov edx,[esi] / mov eax,[edx+4] / call eax
 *   0x008984F9  xor eax,eax / ret
 *
 * `[vtable+0x04]` is slot 1 on `ISTIDriver`, `DisconnectClients`.
 */
int moho::cfunc_SessionEndGameL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSessionEndGameHelpText, 0, argumentCount);
  }

  ISTIDriver* const driver = WLD_GetDriver();
  if (driver == nullptr) {
    LuaPlus::LuaState::Error(state, kSessionGetScenarioInfoNoActiveSessionText);
    return 0;
  }

  driver->DisconnectClients();
  return 0;
}

/**
 * Address: 0x00842BD0 (FUN_00842BD0, func_GetMouseWorldPosUser_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetMouseWorldPos`.
 */
moho::CScrLuaInitForm* moho::func_GetMouseWorldPosUser_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetMouseWorldPos",
    &moho::cfunc_GetMouseWorldPos,
    nullptr,
    "<global>",
    kGetMouseWorldPosUserHelpText
  );
  return &binder;
}

/**
 * What it does:
 * Publishes the user-lane Lua binder definition for global
 * `GetTimeForProfile`, the same body as the sim one (section/GetTimeForProfile.cpp
 * registers both; the name string 0x01293D36 is referenced from 0x012924BE and
 * 0x0129251D).
 */
moho::CScrLuaInitForm* moho::func_GetTimeForProfileUser_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetTimeForProfile",
    &moho::cfunc_GetTimeForProfileSim,
    nullptr,
    "<global>",
    kGetTimeForProfileHelpText
  );
  return &binder;
}

/**
 * What it does:
 * Publishes the user-lane Lua binder definition for global
 * `GetDepositsAroundPoint` (section/SimGetDepositsAroundPoint.cpp `UIRegFunc
 * SGDAPRegDesc`).
 */
moho::CScrLuaInitForm* moho::func_GetDepositsAroundPointUser_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetDepositsAroundPoint",
    &moho::cfunc_GetDepositsAroundPointUser,
    nullptr,
    "<global>",
    kGetDepositsAroundPointHelpText
  );
  return &binder;
}

/**
 * Address: 0x00842D10 (FUN_00842D10, cfunc_GetMouseScreenPos)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetMouseScreenPosL`.
 */
int moho::cfunc_GetMouseScreenPos(lua_State* const luaContext)
{
  return cfunc_GetMouseScreenPosL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00842D30 (FUN_00842D30, func_GetMouseScreenPos_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetMouseScreenPos`.
 */
moho::CScrLuaInitForm* moho::func_GetMouseScreenPos_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetMouseScreenPos",
    &moho::cfunc_GetMouseScreenPos,
    nullptr,
    "<global>",
    kGetMouseScreenPosHelpText
  );
  return &binder;
}

/**
 * Address: 0x00842D90 (FUN_00842D90, cfunc_GetMouseScreenPosL)
 *
 * What it does:
 * Pushes current screen-space mouse position as one Lua vector.
 */
int moho::cfunc_GetMouseScreenPosL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetMouseScreenPosHelpText, 0, argumentCount);
  }

  const CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, kNoSessionStartedText);
  }

  const LuaPlus::LuaObject screenPositionObject = SCR_ToLua<Wm3::Vector2<float>>(state, session->CursorScreenPos);
  screenPositionObject.PushStack(state);
  return 1;
}

/**
 * FAF FA-Binary-Patches (section/CopyToClipBoard.cpp, LuaCopyToClipboard):
 * `CopyToClipboard(val):bool`.
 *
 * What it does:
 * Puts the one argument, as a string read as UTF-8, on the Windows clipboard
 * through `WIN_CopyToClipboard` (0x004F2730) and returns whether that worked.
 * Any other argument count raises the engine's "expected 1 args" error under
 * the patch's own function name.
 */
int moho::cfunc_CopyToClipboard(lua_State* const luaContext)
{
  LuaPlus::LuaState* const state = SCR_ResolveBindingState(luaContext);
  const int argumentCount = lua_gettop(luaContext);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, "LuaCopyToClipboard", 1, argumentCount);
  }

  // The patch converts `lua_tostring` with `wstring(const char*)`, i.e.
  // `gpg::STR_Utf8ToWide` (0x00938720). A non-string argument (nil) copies
  // the empty string here instead of handing that conversion a null pointer.
  const char* const text = lua_tostring(luaContext, 1);
  const std::wstring wideText = gpg::STR_Utf8ToWide(text != nullptr ? text : "");
  lua_pushboolean(luaContext, WIN_CopyToClipboard(wideText.c_str()) ? 1 : 0);
  return 1;
}

moho::CScrLuaInitForm* moho::func_CopyToClipboard_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "CopyToClipboard",
    &moho::cfunc_CopyToClipboard,
    nullptr,
    "<global>",
    "CopyToClipboard(val):bool"
  );
  return &binder;
}

/**
 * FAF FA-Binary-Patches (section/GetHighlightCommand.cpp, UIGetHighlightCommand):
 * `GetHighlightCommand() - return table of command or nil`.
 *
 * What it does:
 * For the command the cursor highlights (`CWldSession::HighlightCommandId`,
 * -1 for none), looked up in the session command manager
 * (`FindCommandIssueHelperInManager`, 0x008B5BB0), returns
 * `{commandType, x, y, z, commandId, targetId?, blueprintId?}`: the command
 * type, the target position, the id, the target entity id as a decimal string
 * unless it is the empty id 0xF0000000, and the build blueprint id when there
 * is one. Returns nothing otherwise.
 */
int moho::cfunc_GetHighlightCommand(lua_State* const luaContext)
{
  // The patch reads the session global without a check; without a session
  // there is nothing to highlight.
  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    return 0;
  }
  const CmdId commandId = session->HighlightCommandId;
  if (commandId == -1) {
    return 0;
  }
  const UserCommandIssueHelper* const command = FindCommandIssueHelper(session, commandId);
  if (command == nullptr) {
    return 0;
  }

  const auto setNumber = [luaContext](const char* const key, const lua_Number value) {
    lua_pushstring(luaContext, key);
    lua_pushnumber(luaContext, value);
    lua_rawset(luaContext, -3);
  };
  const SSTITarget& target = command->mVariableData.mTarget1;

  lua_newtable(luaContext);
  setNumber("commandType", static_cast<lua_Number>(static_cast<std::int32_t>(command->mVariableData.mCmdType)));
  setNumber("x", static_cast<lua_Number>(target.mPos.x));
  setNumber("y", static_cast<lua_Number>(target.mPos.y));
  setNumber("z", static_cast<lua_Number>(target.mPos.z));
  setNumber("commandId", static_cast<lua_Number>(commandId));

  constexpr std::uint32_t kNoTargetEntityId = 0xF0000000U;
  if (target.mEntityId != kNoTargetEntityId) {
    char targetIdText[16];
    std::snprintf(targetIdText, sizeof(targetIdText), "%d", static_cast<std::int32_t>(target.mEntityId));
    lua_pushstring(luaContext, "targetId");
    lua_pushstring(luaContext, targetIdText);
    lua_rawset(luaContext, -3);
  }

  if (const REntityBlueprint* const blueprint = command->mConstantData.blueprint; blueprint != nullptr) {
    lua_pushstring(luaContext, "blueprintId");
    lua_pushstring(luaContext, blueprint->mBlueprintId.c_str());
    lua_rawset(luaContext, -3);
  }
  return 1;
}

moho::CScrLuaInitForm* moho::func_GetHighlightCommand_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetHighlightCommand",
    &moho::cfunc_GetHighlightCommand,
    nullptr,
    "<global>",
    "GetHighlightCommand() - return table of command or nil"
  );
  return &binder;
}

/**
 * Address: 0x00842E60 (FUN_00842E60, cfunc_SetFocusArmyUser)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_SetFocusArmyUserL`.
 */
int moho::cfunc_SetFocusArmyUser(lua_State* const luaContext)
{
  return cfunc_SetFocusArmyUserL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00842E80 (FUN_00842E80, func_SetFocusArmyUser_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SetFocusArmy`.
 */
moho::CScrLuaInitForm* moho::func_SetFocusArmyUser_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetFocusArmy",
    &moho::cfunc_SetFocusArmyUser,
    nullptr,
    "<global>",
    kSetFocusArmyUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x00842EE0 (FUN_00842EE0, cfunc_SetFocusArmyUserL)
 *
 * What it does:
 * Validates one-based army index input and requests focus-army update.
 */
int moho::cfunc_SetFocusArmyUserL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetFocusArmyUserHelpText, 1, argumentCount);
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, kNoSessionStartedText);
  }

  LuaPlus::LuaStackObject indexArg(state, 1);
  if (lua_type(rawState, 1) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&indexArg, "integer");
  }

  int focusArmyIndex = static_cast<int>(lua_tonumber(rawState, 1));
  if (focusArmyIndex != -1) {
    const int maxArmyIndexOneBased = static_cast<int>(session->userArmies.size());
    if (focusArmyIndex < 1 || focusArmyIndex > maxArmyIndexOneBased) {
      LuaPlus::LuaState::Error(
        state,
        "Invalid army index of %d; must be between 1 and %d inclusive.",
        focusArmyIndex,
        maxArmyIndexOneBased
      );
    }

    --focusArmyIndex;
  }

  session->RequestFocusArmy(focusArmyIndex);
  return 0;
}

/**
 * Address: 0x00842FD0 (FUN_00842FD0, cfunc_GetFocusArmyUser)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetFocusArmyUserL`.
 */
int moho::cfunc_GetFocusArmyUser(lua_State* const luaContext)
{
  return cfunc_GetFocusArmyUserL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00842FF0 (FUN_00842FF0, func_GetFocusArmyUser_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetFocusArmy`.
 */
moho::CScrLuaInitForm* moho::func_GetFocusArmyUser_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetFocusArmy",
    &moho::cfunc_GetFocusArmyUser,
    nullptr,
    "<global>",
    kGetFocusArmyUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x00843050 (FUN_00843050, cfunc_GetFocusArmyUserL)
 *
 * What it does:
 * Pushes the focused army as a one-based Lua index (`-1` when unset).
 */
int moho::cfunc_GetFocusArmyUserL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetFocusArmyUserHelpText, 0, argumentCount);
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, kNoSessionStartedText);
  }

  int focusArmy = session->FocusArmy;
  if (focusArmy != -1) {
    ++focusArmy;
  }

  lua_pushnumber(rawState, static_cast<float>(focusArmy));
  return 1;
}

/**
 * Address: 0x008430D0 (FUN_008430D0, cfunc_IsObserver)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_IsObserverL`.
 */
int moho::cfunc_IsObserver(lua_State* const luaContext)
{
  return cfunc_IsObserverL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008430F0 (FUN_008430F0, func_IsObserver_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `IsObserver`.
 */
moho::CScrLuaInitForm* moho::func_IsObserver_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "IsObserver",
    &moho::cfunc_IsObserver,
    nullptr,
    "<global>",
    kIsObserverHelpText
  );
  return &binder;
}

/**
 * Address: 0x00843150 (FUN_00843150, cfunc_IsObserverL)
 *
 * What it does:
 * Pushes whether the active focus army has no owning `UserArmy` entry.
 */
int moho::cfunc_IsObserverL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIsObserverHelpText, 0, argumentCount);
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, kNoSessionStartedText);
  }

  UserArmy* focusArmy = nullptr;
  const int focusArmyIndex = session->FocusArmy;
  if (focusArmyIndex >= 0) {
    focusArmy = session->userArmies[static_cast<std::size_t>(focusArmyIndex)];
  }

  lua_pushboolean(rawState, focusArmy == nullptr);
  return 1;
}

/**
 * Address: 0x008431D0 (FUN_008431D0, cfunc_GetGameTime)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetGameTimeL`.
 */
int moho::cfunc_GetGameTime(lua_State* const luaContext)
{
  return cfunc_GetGameTimeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008431F0 (FUN_008431F0, func_GetGameTime_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetGameTime`.
 */
moho::CScrLuaInitForm* moho::func_GetGameTime_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetGameTime",
    &moho::cfunc_GetGameTime,
    nullptr,
    "<global>",
    kGetGameTimeHelpText
  );
  return &binder;
}

/**
 * Address: 0x00843250 (FUN_00843250, cfunc_GetGameTimeL)
 *
 * What it does:
 * Formats active-session simulation time as `HH:MM:SS` and returns one Lua
 * string result.
 */
int moho::cfunc_GetGameTimeL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetGameTimeHelpText, 0, argumentCount);
  }

  CWldSession* session = WLD_GetActiveSession();
  if (!session) {
    LuaPlus::LuaState::Error(state, kNoSessionStartedText);
    session = WLD_GetActiveSession();
    if (!session) {
      LuaPlus::LuaState::Error(state, kNoActiveSessionText);
    }
  }

  // 0x008432C6..0x008432DA: `fild tick; fadd timeSinceLastTick; fmul 0.1f`
  // (0x00E4F714 holds the float 0x3DCCCCCD), then __ftol2_sse.
  const int wholeSeconds = static_cast<int>((static_cast<float>(session->mGameTick) + session->mTimeSinceLastTick) * 0.1f);
  const auto signedSeconds = static_cast<long long>(wholeSeconds);
  const bool isNegative = signedSeconds < 0;
  const unsigned long long absoluteSeconds = isNegative
    ? static_cast<unsigned long long>(-(signedSeconds + 1)) + 1ULL
    : static_cast<unsigned long long>(signedSeconds);
  const int hours = static_cast<int>((absoluteSeconds / 3600ULL) % 24ULL);
  const int minutes = static_cast<int>((absoluteSeconds / 60ULL) % 60ULL);
  const int seconds = static_cast<int>(absoluteSeconds % 60ULL);

  char formatted[16]{};
  std::snprintf(
    formatted,
    sizeof(formatted),
    isNegative ? "-%02d:%02d:%02d" : "%02d:%02d:%02d",
    hours,
    minutes,
    seconds
  );

  lua_pushstring(rawState, formatted);
  return 1;
}

/**
 * Address: 0x00843380 (FUN_00843380, cfunc_GetGameTimeSecondsUser)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetGameTimeSecondsUserL`.
 */
int moho::cfunc_GetGameTimeSecondsUser(lua_State* const luaContext)
{
  return cfunc_GetGameTimeSecondsUserL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008433A0 (FUN_008433A0, func_GetGameTimeSecondsUser_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetGameTimeSeconds`.
 */
moho::CScrLuaInitForm* moho::func_GetGameTimeSecondsUser_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetGameTimeSeconds",
    &moho::cfunc_GetGameTimeSecondsUser,
    nullptr,
    "<global>",
    kGetGameTimeSecondsUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x00843400 (FUN_00843400, cfunc_GetGameTimeSecondsUserL)
 *
 * What it does:
 * Pushes active-session elapsed game time in seconds as a Lua number.
 */
int moho::cfunc_GetGameTimeSecondsUserL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetGameTimeSecondsUserHelpText, 0, argumentCount);
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, kNoActiveSessionText);
  }

  const float gameTimeSeconds = (static_cast<float>(session->mGameTick) + session->mTimeSinceLastTick) * 0.1f;
  lua_pushnumber(rawState, gameTimeSeconds);
  return 1;
}

/**
 * Address: 0x00843480 (FUN_00843480, cfunc_GetSystemTime)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetSystemTimeL`.
 */
int moho::cfunc_GetSystemTime(lua_State* const luaContext)
{
  return cfunc_GetSystemTimeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008434A0 (FUN_008434A0, func_GetSystemTime_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetSystemTime`.
 */
moho::CScrLuaInitForm* moho::func_GetSystemTime_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetSystemTime",
    &moho::cfunc_GetSystemTime,
    nullptr,
    "<global>",
    kGetSystemTimeHelpText
  );
  return &binder;
}

/**
 * Address: 0x00843500 (FUN_00843500, cfunc_GetSystemTimeL)
 *
 * What it does:
 * Formats process-system elapsed seconds as `HH:MM:SS` and returns one Lua
 * string result.
 */
int moho::cfunc_GetSystemTimeL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetSystemTimeHelpText, 0, argumentCount);
  }

  const auto totalSeconds = static_cast<long long>(gpg::time::GetSystemTimer().ElapsedSeconds());
  const bool isNegative = totalSeconds < 0;
  const unsigned long long absoluteSeconds = isNegative
    ? static_cast<unsigned long long>(-(totalSeconds + 1)) + 1ULL
    : static_cast<unsigned long long>(totalSeconds);
  const int hours = static_cast<int>((absoluteSeconds / 3600ULL) % 24ULL);
  const int minutes = static_cast<int>((absoluteSeconds / 60ULL) % 60ULL);
  const int seconds = static_cast<int>(absoluteSeconds % 60ULL);

  char formatted[16]{};
  std::snprintf(
    formatted,
    sizeof(formatted),
    isNegative ? "-%02d:%02d:%02d" : "%02d:%02d:%02d",
    hours,
    minutes,
    seconds
  );

  lua_pushstring(rawState, formatted);
  return 1;
}

/**
 * Address: 0x008435F4 (FUN_008435F4)
 * Address: 0x008365B4 (FUN_008365B4)
 *
 * What it does:
 * Normalizes Lua callback entry calling convention and forwards to
 * `cfunc_GetSystemTimeSecondsL`.
 */
static int cfunc_GetSystemTimeSecondsDispatch(lua_State* const luaContext)
{
  return moho::cfunc_GetSystemTimeSecondsL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008435F0 (FUN_008435F0, cfunc_GetSystemTimeSeconds)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetSystemTimeSecondsL`.
 */
int moho::cfunc_GetSystemTimeSeconds(lua_State* const luaContext)
{
  return cfunc_GetSystemTimeSecondsDispatch(luaContext);
}

/**
 * Address: 0x00843610 (FUN_00843610, func_GetSystemTimeSeconds_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetSystemTimeSeconds`.
 */
moho::CScrLuaInitForm* moho::func_GetSystemTimeSeconds_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetSystemTimeSeconds",
    &moho::cfunc_GetSystemTimeSeconds,
    nullptr,
    "<global>",
    kGetSystemTimeSecondsHelpText
  );
  return &binder;
}

/**
 * Address: 0x00843670 (FUN_00843670, cfunc_GetSystemTimeSecondsL)
 *
 * What it does:
 * Pushes process-system elapsed time in seconds as a Lua number.
 */
int moho::cfunc_GetSystemTimeSecondsL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetSystemTimeSecondsHelpText, 0, argumentCount);
  }

  lua_pushnumber(rawState, gpg::time::GetSystemTimer().ElapsedSeconds());
  return 1;
}

/**
 * Address: 0x00843750 (FUN_00843750, cfunc_FormatTimeL)
 *
 * What it does:
 * Validates one numeric seconds argument and returns a formatted `HH:MM:SS`
 * text value for Lua scripts.
 */
int moho::cfunc_FormatTimeL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kFormatTimeHelpText, 1, argumentCount);
  }

  if (!WLD_GetActiveSession()) {
    LuaPlus::LuaState::Error(state, kNoSessionStartedText);
  }

  LuaPlus::LuaStackObject secondsArg(state, 1);
  if (lua_type(rawState, 1) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&secondsArg, "number");
  }

  const auto totalSeconds = static_cast<long long>(lua_tonumber(rawState, 1));
  const bool isNegative = totalSeconds < 0;
  const unsigned long long absoluteSeconds = isNegative
    ? static_cast<unsigned long long>(-(totalSeconds + 1)) + 1ULL
    : static_cast<unsigned long long>(totalSeconds);
  const int hours = static_cast<int>((absoluteSeconds / 3600ULL) % 24ULL);
  const int minutes = static_cast<int>((absoluteSeconds / 60ULL) % 60ULL);
  const int seconds = static_cast<int>(absoluteSeconds % 60ULL);

  char formatted[16]{};
  std::snprintf(
    formatted,
    sizeof(formatted),
    isNegative ? "-%02d:%02d:%02d" : "%02d:%02d:%02d",
    hours,
    minutes,
    seconds
  );

  lua_pushstring(rawState, formatted);
  return 1;
}

/**
 * Address: 0x008436D0 (FUN_008436D0, cfunc_FormatTime)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_FormatTimeL`.
 */
int moho::cfunc_FormatTime(lua_State* const luaContext)
{
  return cfunc_FormatTimeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008436F0 (FUN_008436F0, func_FormatTime_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `FormatTime`.
 */
moho::CScrLuaInitForm* moho::func_FormatTime_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "FormatTime",
    &moho::cfunc_FormatTime,
    nullptr,
    "<global>",
    kFormatTimeHelpText
  );
  return &binder;
}

/**
 * Address: 0x008438A0 (FUN_008438A0, cfunc_GetSimRate)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetSimRateL`.
 */
int moho::cfunc_GetSimRate(lua_State* const luaContext)
{
  return cfunc_GetSimRateL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008438C0 (FUN_008438C0, func_GetSimRate_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetSimRate`.
 */
moho::CScrLuaInitForm* moho::func_GetSimRate_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetSimRate",
    &moho::cfunc_GetSimRate,
    nullptr,
    "<global>",
    kGetSimRateHelpText
  );
  return &binder;
}

/**
 * Address: 0x00843920 (FUN_00843920, cfunc_GetSimRateL)
 *
 * What it does:
 * Pushes the current client-manager simulation rate as a Lua number.
 */
int moho::cfunc_GetSimRateL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetSimRateHelpText, 0, argumentCount);
  }

  if (!WLD_GetActiveSession()) {
    LuaPlus::LuaState::Error(state, kNoSessionStartedText);
  }

  ISTIDriver* const activeDriver = WLD_GetDriver();
  CClientManagerImpl* const clientManager = activeDriver->GetClientManager();
  lua_pushnumber(rawState, static_cast<float>(clientManager->GetSimRate()));
  return 1;
}

/**
 * Address: 0x008439A0 (FUN_008439A0, cfunc_GetArmiesTable)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetArmiesTableL`.
 */
int moho::cfunc_GetArmiesTable(lua_State* const luaContext)
{
  return cfunc_GetArmiesTableL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008439C0 (FUN_008439C0, func_GetArmiesTable_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetArmiesTable`.
 */
moho::CScrLuaInitForm* moho::func_GetArmiesTable_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetArmiesTable",
    &moho::cfunc_GetArmiesTable,
    nullptr,
    "<global>",
    kGetArmiesTableHelpText
  );
  return &binder;
}

/**
 * Address: 0x008485C0 (FUN_008485C0)
 *
 * What it does:
 * Copies one `UserArmy*` vector lane into caller scratch storage for stable
 * iteration during Lua table materialization.
 */
static msvc8::vector<moho::UserArmy*>* SnapshotUserArmyVector(
  const msvc8::vector<moho::UserArmy*>& source,
  msvc8::vector<moho::UserArmy*>* const outSnapshot
)
{
  if (outSnapshot == nullptr) {
    return nullptr;
  }

  *outSnapshot = source;
  return outSnapshot;
}

/**
 * Address: 0x00843A20 (FUN_00843A20, cfunc_GetArmiesTableL)
 *
 * What it does:
 * Builds and returns one Lua table describing session armies and command
 * source authorization lanes.
 */
int moho::cfunc_GetArmiesTableL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetArmiesTableHelpText, 0, argumentCount);
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, kNoSessionStartedText);
  }

  msvc8::vector<UserArmy*> armiesSnapshot{};
  SnapshotUserArmyVector(session->userArmies, &armiesSnapshot);
  const msvc8::vector<UserArmy*>& armies = armiesSnapshot;
  const std::size_t armyCount = armies.size();

  LuaPlus::LuaObject result(state);
  result.AssignNewTable(state, 0, 0u);
  result.SetInteger("numArmies", static_cast<std::int32_t>(armyCount));

  int focusArmy = session->FocusArmy;
  if (focusArmy != -1) {
    ++focusArmy;
  }
  result.SetInteger("focusArmy", focusArmy);

  LuaPlus::LuaObject armiesTable(state);
  armiesTable.AssignNewTable(state, static_cast<int>(armyCount), 0u);

  for (std::size_t armyIndex = 0; armyIndex < armyCount; ++armyIndex) {
    UserArmy* const army = armies[armyIndex];

    LuaPlus::LuaObject armyEntry(state);
    armyEntry.AssignNewTable(state, 0, 0u);
    armyEntry.SetString("name", army->mArmyName.c_str());
    armyEntry.SetString("nickname", army->mPlayerName.c_str());
    armyEntry.SetInteger("faction", army->mVarDat.mFaction);

    const LuaPlus::LuaObject playerColor = SCR_EncodeColor(state, army->mVarDat.mPlayerColorBgra);
    armyEntry.SetObject("color", playerColor);

    const LuaPlus::LuaObject iconColor = SCR_EncodeColor(state, army->mVarDat.mArmyColorBgra);
    armyEntry.SetObject("iconColor", iconColor);

    armyEntry.SetBoolean("showScore", army->mVarDat.mShowScore != 0u);
    armyEntry.SetBoolean("civilian", army->mIsCivilian != 0u);
    armyEntry.SetBoolean("human", gpg::STR_CompareNoCase(army->mVarDat.mArmyType.c_str(), "human") == 0);
    armyEntry.SetBoolean("outOfGame", army->mVarDat.mIsOutOfGame != 0u);

    LuaPlus::LuaObject authorizedCommandSources(state);
    authorizedCommandSources.AssignNewTable(state, 0, 0u);
    const BVIntSet& validSources = army->mVarDat.mValidCommandSources;
    int luaSourceIndex = 1;
    const std::size_t usedWords = static_cast<std::size_t>(validSources.mWords.end_ - validSources.mWords.start_);
    for (std::size_t wordIndex = 0; wordIndex < usedWords; ++wordIndex) {
      const std::uint32_t wordBits = validSources.mWords.start_[wordIndex];
      if (wordBits == 0u) {
        continue;
      }

      for (std::uint32_t bit = 0; bit < 32u; ++bit) {
        if ((wordBits & (1u << bit)) == 0u) {
          continue;
        }
        const std::uint32_t sourceId =
          static_cast<std::uint32_t>((static_cast<std::int32_t>(validSources.mFirstWordIndex) + static_cast<std::int32_t>(wordIndex)) * 32u + bit);
        authorizedCommandSources.SetInteger(luaSourceIndex++, static_cast<std::int32_t>(sourceId + 1u));
      }
    }

    armyEntry.SetObject("authorizedCommandSources", authorizedCommandSources);
    armiesTable.SetObject(static_cast<std::int32_t>(armyIndex + 1u), armyEntry);
  }

  result.SetObject("armiesTable", armiesTable);
  result.PushStack(state);
  return 1;
}

/**
 * Address: 0x00843E50 (FUN_00843E50, cfunc_GetArmyScore)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetArmyScoreL`.
 */
int moho::cfunc_GetArmyScore(lua_State* const luaContext)
{
  return cfunc_GetArmyScoreL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00843E70 (FUN_00843E70, func_GetArmyScore_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetArmyScore`.
 */
moho::CScrLuaInitForm* moho::func_GetArmyScore_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetArmyScore",
    &moho::cfunc_GetArmyScore,
    nullptr,
    "<global>",
    kGetArmyScoreHelpText
  );
  return &binder;
}

/**
 * Address: 0x00843ED0 (FUN_00843ED0, cfunc_GetArmyScoreL)
 *
 * What it does:
 * Validates one argument and active-session precondition for the
 * `GetArmyScore` global Lua callback lane.
 */
int moho::cfunc_GetArmyScoreL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetArmyScoreHelpText, 1, argumentCount);
  }

  if (WLD_GetActiveSession() == nullptr) {
    LuaPlus::LuaState::Error(state, kNoSessionStartedText);
  }

  return 0;
}

/**
 * Address: 0x00843F20 (FUN_00843F20, cfunc_DeleteCommand)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_DeleteCommandL`.
 */
int moho::cfunc_DeleteCommand(lua_State* const luaContext)
{
  return cfunc_DeleteCommandL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00843F40 (FUN_00843F40, func_DeleteCommand_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `DeleteCommand`.
 */
moho::CScrLuaInitForm* moho::func_DeleteCommand_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "DeleteCommand",
    &moho::cfunc_DeleteCommand,
    nullptr,
    "<global>",
    kDeleteCommandHelpText
  );
  return &binder;
}

/**
 * Address: 0x00843FA0 (FUN_00843FA0, cfunc_DeleteCommandL)
 *
 * What it does:
 * Looks up one command issue helper by Lua command id and marshals one
 * `DecreaseCommandCount` request through the active sim driver, then records
 * one local helper queue update for the same command id/count delta.
 */
int moho::cfunc_DeleteCommandL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kDeleteCommandHelpText, 1, argumentCount);
  }

  const CmdId commandId = ReadLuaCommandIdArg(state, 1);

  CWldSession* const session = WLD_GetActiveSession();
  if (!session) {
    LuaPlus::LuaState::Error(state, "No active session!");
    return 0;
  }

  UserCommandIssueHelper* const commandIssue = FindCommandIssueHelper(session, commandId);
  if (!commandIssue) {
    return 0;
  }

  if (ISTIDriver* const activeDriver = WLD_GetDriver(); activeDriver != nullptr) {
    // The driver marshals the decrement and returns the resulting command
    // cookie; the event is queued with that cookie (FUN_00843FA0 passes the
    // DecreaseCommandCount result, not the input command id).
    const CmdId resultCookie = activeDriver->DecreaseCommandCount(commandIssue->mConstantData.cmd, 1);
    QueueCommandIssueDecreaseCountEvent(*commandIssue, resultCookie, 1);
  }

  return 0;
}

/**
 * Address: 0x00836980 (FUN_00836980, cfunc_DecreaseBuildCountInQueueL)
 *
 * IDA signature:
 * int __usercall cfunc_DecreaseBuildCountInQueueL@<eax>(LuaPlus::LuaState *a1@<eax>);
 *
 * What it does:
 * Lua worker for `DecreaseBuildCountInQueue(queueIndex, count)`. Reads the
 * 1-based factory build-queue item index and a decrement count, then walks that
 * item's queued command ids from the most recently queued command backward. For
 * each command still tracked by a live command-issue helper it marshals a
 * `DecreaseCommandCount` through the active sim driver (clamped to the helper's
 * remaining effective build count) and records the matching local decrease-count
 * update event, stopping once the requested count has been fully consumed.
 */
int moho::cfunc_DecreaseBuildCountInQueueL(LuaPlus::LuaState* const state)
{
  constexpr const char* kDecreaseBuildCountInQueueHelpText = "DecreaseBuildCountInQueue(queueIndex, count)";

  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kDecreaseBuildCountInQueueHelpText, 2, argumentCount);
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (!session) {
    LuaPlus::LuaState::Error(state, "No active session!");
    return 0;
  }

  LuaPlus::LuaStackObject queueIndexArg(state, 1);
  if (lua_type(state->m_state, 1) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&queueIndexArg, "integer");
  }
  const int oneBasedQueueIndex = static_cast<int>(static_cast<std::int64_t>(lua_tonumber(state->m_state, 1)));

  LuaPlus::LuaStackObject countArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&countArg, "integer");
  }
  std::int32_t remaining = static_cast<std::int32_t>(lua_tonumber(state->m_state, 2));

  const CmdId* commandBegin = nullptr;
  const CmdId* commandEnd = nullptr;
  CurrentBuildQueueItemCommands(oneBasedQueueIndex, &commandBegin, &commandEnd);

  // Walk the item's queued command ids from the last-queued command backward.
  for (const CmdId* cursor = commandEnd; cursor != commandBegin; --cursor) {
    const CmdId commandId = *(cursor - 1);

    UserCommandIssueHelper* const helper = FindCommandIssueHelper(session, commandId);
    if (helper == nullptr) {
      continue;
    }

    const std::int32_t available = QueuedBuildCommandCount(*helper);
    std::int32_t take = remaining;
    if (remaining <= available) {
      remaining = 0;
    } else {
      take = available;
      remaining -= available;
    }

    // The driver marshals the decrement and returns the resulting command cookie;
    // the local event is queued with that cookie (not the input command id).
    ISTIDriver* const activeDriver = WLD_GetDriver();
    const CmdId resultCookie = activeDriver->DecreaseCommandCount(helper->mConstantData.cmd, take);
    QueueCommandIssueDecreaseCountEvent(*helper, resultCookie, take);

    if (remaining <= 0) {
      break;
    }
  }

  return 0;
}

/**
 * Address: 0x00836740 (FUN_00836740, cfunc_IncreaseBuildCountInQueueL)
 *
 * IDA signature:
 * int __usercall cfunc_IncreaseBuildCountInQueueL@<eax>(LuaPlus::LuaState *a1@<eax>);
 *
 * What it does:
 * Lua worker for `IncreaseBuildCountInQueue(queueIndex, count)`. Reads the 1-based
 * factory build-queue item index and a count, then walks that item's queued
 * command ids from the most recently queued command backward. Re-issues the first
 * live factory-build command found (helper present, resolved type == BuildFactory,
 * count > 0) via `ISSUE_IncreaseCommandCount(helper, count)` and stops.
 */
int moho::cfunc_IncreaseBuildCountInQueueL(LuaPlus::LuaState* const state)
{
  // Binary reuses the Decrease help string verbatim here (copy-paste in the
  // original 2007 source: luadef_IncreaseBuildCountInQueue.mHelp -> the Decrease
  // text, proven by the string xref at FUN_008366E0).
  constexpr const char* kIncreaseBuildCountInQueueHelpText = "DecreaseBuildCountInQueue(queueIndex, count)";

  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kIncreaseBuildCountInQueueHelpText, 2, argumentCount);
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (!session) {
    LuaPlus::LuaState::Error(state, "No active session!");
    return 0;
  }

  LuaPlus::LuaStackObject queueIndexArg(state, 1);
  if (lua_type(state->m_state, 1) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&queueIndexArg, "integer");
  }
  const int oneBasedQueueIndex = static_cast<int>(static_cast<std::int64_t>(lua_tonumber(state->m_state, 1)));

  LuaPlus::LuaStackObject countArg(state, 2);
  if (lua_type(state->m_state, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&countArg, "integer");
  }
  const int count = static_cast<int>(lua_tonumber(state->m_state, 2));

  const CmdId* commandBegin = nullptr;
  const CmdId* commandEnd = nullptr;
  CurrentBuildQueueItemCommands(oneBasedQueueIndex, &commandBegin, &commandEnd);

  // Walk the item's queued command ids from the last-queued command backward,
  // re-issuing the first live factory-build command found and stopping.
  for (const CmdId* cursor = commandEnd; cursor != commandBegin; --cursor) {
    const CmdId commandId = *(cursor - 1);

    UserCommandIssueHelper* const helper = FindCommandIssueHelper(session, commandId);
    if (helper == nullptr) {
      continue;
    }

    if (ResolveCommandIssueHelperCommandType(*helper)
          == EUnitCommandType::UNITCOMMAND_BuildFactory
        && count > 0) {
      ISSUE_IncreaseCommandCount(helper, count);
      break;
    }
  }

  return 0;
}

/**
 * Address: 0x008440A0 (FUN_008440A0, cfunc_GetSpecialFiles)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetSpecialFilesL`.
 */
int moho::cfunc_GetSpecialFiles(lua_State* const luaContext)
{
  return cfunc_GetSpecialFilesL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008440C0 (FUN_008440C0, func_GetSpecialFiles_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetSpecialFiles`.
 */
moho::CScrLuaInitForm* moho::func_GetSpecialFiles_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetSpecialFiles",
    &moho::cfunc_GetSpecialFiles,
    nullptr,
    "<global>",
    kGetSpecialFilesHelpText
  );
  return &binder;
}

/**
 * Address: 0x00844120 (FUN_00844120, cfunc_GetSpecialFilesL)
 *
 * What it does:
 * Resolves one special-file type and returns a Lua table containing grouped
 * profile file basenames plus directory/extension metadata.
 */
int moho::cfunc_GetSpecialFilesL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetSpecialFilesHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaStackObject typeArg(state, 1);
  const char* const specialFileTypeLexical = lua_tostring(rawState, 1);
  if (specialFileTypeLexical == nullptr) {
    typeArg.TypeError("string");
  }

  moho::ESpecialFileType specialFileType = moho::ESpecialFileType::SaveGame;
  if (!TryParseSpecialFileType(specialFileTypeLexical, specialFileType)) {
    ThrowInvalidSpecialFileType(specialFileTypeLexical);
  }

  std::string directory{};
  std::string extension{};
  msvc8::map<msvc8::string, msvc8::vector<msvc8::string>> filesByProfile{};
  USER_GetSpecialFiles(specialFileType, directory, extension, filesByProfile);

  LuaPlus::LuaObject filesTable(state);
  filesTable.AssignNewTable(state, 0, 0);

  for (const auto& [profileName, profileFiles] : filesByProfile) {
    LuaPlus::LuaObject profileTable(state);
    profileTable.AssignNewTable(state, 0, 0);

    std::int32_t fileIndex = 1;
    for (const msvc8::string& fileNameWithExtension : profileFiles) {
      const msvc8::string baseFileName = FILE_Base(fileNameWithExtension.c_str(), true);
      profileTable.SetString(fileIndex, baseFileName.c_str());
      ++fileIndex;
    }

    filesTable.SetObject(profileName.c_str(), profileTable);
  }

  LuaPlus::LuaObject result(state);
  result.AssignNewTable(state, 0, 0);
  result.SetObject("files", filesTable);
  result.SetString("directory", directory.c_str());
  result.SetString("extension", extension.c_str());
  result.PushStack(state);
  return 1;
}

/**
 * Address: 0x00844540 (FUN_00844540, cfunc_GetSpecialFilePath)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetSpecialFilePathL`.
 */
int moho::cfunc_GetSpecialFilePath(lua_State* const luaContext)
{
  return cfunc_GetSpecialFilePathL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00844560 (FUN_00844560, func_GetSpecialFilePath_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetSpecialFilePath`.
 */
moho::CScrLuaInitForm* moho::func_GetSpecialFilePath_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetSpecialFilePath",
    &moho::cfunc_GetSpecialFilePath,
    nullptr,
    "<global>",
    kGetSpecialFilePathHelpText
  );
  return &binder;
}

/**
 * Address: 0x008445C0 (FUN_008445C0, cfunc_GetSpecialFilePathL)
 *
 * What it does:
 * Resolves `(profile, filename, specialType)` and pushes one absolute
 * user-special-file path (`directory\\profile\\filename.extension`).
 */
int moho::cfunc_GetSpecialFilePathL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetSpecialFilePathHelpText, 3, argumentCount);
  }

  const LuaPlus::LuaStackObject profileArg(state, 1);
  const char* const profileName = lua_tostring(rawState, 1);
  if (profileName == nullptr) {
    profileArg.TypeError("string");
  }

  const LuaPlus::LuaStackObject fileNameArg(state, 2);
  const char* const fileName = lua_tostring(rawState, 2);
  if (fileName == nullptr) {
    fileNameArg.TypeError("string");
  }

  const LuaPlus::LuaStackObject typeArg(state, 3);
  const char* const specialFileTypeLexical = lua_tostring(rawState, 3);
  if (specialFileTypeLexical == nullptr) {
    typeArg.TypeError("string");
  }

  moho::ESpecialFileType specialFileType = moho::ESpecialFileType::SaveGame;
  if (!TryParseSpecialFileType(specialFileTypeLexical, specialFileType)) {
    ThrowInvalidSpecialFileType(specialFileTypeLexical);
  }

  const msvc8::string directory = BuildSpecialFilePathDirectory(specialFileType);
  const msvc8::string extension = BuildSpecialFilePathExtension(specialFileType);
  const msvc8::string fullPath = directory + "\\" + profileName + "\\" + fileName + "." + extension;

  lua_pushstring(rawState, fullPath.c_str());
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x00844C30 (FUN_00844C30, cfunc_GetSpecialFolder)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetSpecialFolderL`.
 */
int moho::cfunc_GetSpecialFolder(lua_State* const luaContext)
{
  return cfunc_GetSpecialFolderL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00844C50 (FUN_00844C50, func_GetSpecialFolder_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetSpecialFolder`.
 */
moho::CScrLuaInitForm* moho::func_GetSpecialFolder_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetSpecialFolder",
    &moho::cfunc_GetSpecialFolder,
    nullptr,
    "<global>",
    kGetSpecialFolderHelpText
  );
  return &binder;
}

/**
 * Address: 0x00844CB0 (FUN_00844CB0, cfunc_GetSpecialFolderL)
 *
 * What it does:
 * Resolves one special-file type and pushes the matching root folder path.
 */
int moho::cfunc_GetSpecialFolderL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetSpecialFolderHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaStackObject typeArg(state, 1);
  const char* const specialFileTypeLexical = lua_tostring(rawState, 1);
  if (specialFileTypeLexical == nullptr) {
    typeArg.TypeError("string");
  }

  moho::ESpecialFileType specialFileType = moho::ESpecialFileType::SaveGame;
  if (!TryParseSpecialFileType(specialFileTypeLexical, specialFileType)) {
    ThrowInvalidSpecialFileType(specialFileTypeLexical);
  }

  const msvc8::string directory = BuildSpecialFilePathDirectory(specialFileType);
  lua_pushstring(rawState, directory.c_str());
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x00844F10 (FUN_00844F10, cfunc_RemoveSpecialFile)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_RemoveSpecialFileL`.
 */
int moho::cfunc_RemoveSpecialFile(lua_State* const luaContext)
{
  return cfunc_RemoveSpecialFileL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00844F30 (FUN_00844F30, func_RemoveSpecialFile_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `RemoveSpecialFile`.
 */
moho::CScrLuaInitForm* moho::func_RemoveSpecialFile_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "RemoveSpecialFile",
    &moho::cfunc_RemoveSpecialFile,
    nullptr,
    "<global>",
    kRemoveSpecialFileHelpText
  );
  return &binder;
}

/**
 * Address: 0x00844F90 (FUN_00844F90, cfunc_RemoveSpecialFileL)
 *
 * What it does:
 * Builds one profile-scoped special-file path and recycles it from disk.
 */
int moho::cfunc_RemoveSpecialFileL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kRemoveSpecialFileHelpText, 3, argumentCount);
  }

  const LuaPlus::LuaStackObject typeArg(state, 3);
  const char* const specialFileTypeLexical = lua_tostring(rawState, 3);
  if (specialFileTypeLexical == nullptr) {
    typeArg.TypeError("string");
  }

  moho::ESpecialFileType specialFileType = moho::ESpecialFileType::SaveGame;
  if (!TryParseSpecialFileType(specialFileTypeLexical, specialFileType)) {
    ThrowInvalidSpecialFileType(specialFileTypeLexical);
  }

  msvc8::string directory;
  msvc8::string extension;
  switch (specialFileType) {
    case moho::ESpecialFileType::SaveGame:
      directory = USER_GetSaveGameDir();
      extension = USER_GetSaveGameExt();
      break;
    case moho::ESpecialFileType::Replay:
      directory = USER_GetReplayDir();
      extension = USER_GetReplayExt();
      break;
    case moho::ESpecialFileType::CampaignSave:
      directory = USER_GetSaveGameDir();
      extension = USER_GetCampaignSaveExt();
      break;
    case moho::ESpecialFileType::Screenshot:
    default:
      ThrowInvalidSpecialFileType(specialFileTypeLexical);
  }

  const LuaPlus::LuaStackObject profileArg(state, 1);
  const char* const profileName = lua_tostring(rawState, 1);
  if (profileName == nullptr) {
    profileArg.TypeError("string");
  }

  const LuaPlus::LuaStackObject baseNameArg(state, 2);
  const char* const baseName = lua_tostring(rawState, 2);
  if (baseName == nullptr) {
    baseNameArg.TypeError("string");
  }

  const msvc8::string fullPath = directory + profileName + "\\" + baseName + "." + extension;
  DISK_Recycle(fullPath.c_str());
  return 0;
}

/**
 * Address: 0x00845540 (FUN_00845540, cfunc_GetSpecialFileInfo)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_GetSpecialFileInfoL`.
 */
int moho::cfunc_GetSpecialFileInfo(lua_State* const luaContext)
{
  return cfunc_GetSpecialFileInfoL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00845560 (FUN_00845560, func_GetSpecialFileInfo_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `GetSpecialFileInfo`.
 */
moho::CScrLuaInitForm* moho::func_GetSpecialFileInfo_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetSpecialFileInfo",
    &moho::cfunc_GetSpecialFileInfo,
    nullptr,
    "<global>",
    kGetSpecialFileInfoHelpText
  );
  return &binder;
}

/**
 * Address: 0x008455C0 (FUN_008455C0, cfunc_GetSpecialFileInfoL)
 *
 * What it does:
 * Returns metadata table for one profile-scoped special file, or `nil` when
 * the file does not exist.
 */
int moho::cfunc_GetSpecialFileInfoL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 3) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetSpecialFileInfoHelpText, 3, argumentCount);
  }

  const LuaPlus::LuaStackObject typeArg(state, 3);
  const char* const specialFileTypeLexical = lua_tostring(rawState, 3);
  if (specialFileTypeLexical == nullptr) {
    typeArg.TypeError("string");
  }

  moho::ESpecialFileType specialFileType = moho::ESpecialFileType::SaveGame;
  if (!TryParseSpecialFileType(specialFileTypeLexical, specialFileType)) {
    ThrowInvalidSpecialFileType(specialFileTypeLexical);
  }

  msvc8::string directory;
  msvc8::string extension;
  switch (specialFileType) {
    case moho::ESpecialFileType::SaveGame:
      directory = USER_GetSaveGameDir();
      extension = USER_GetSaveGameExt();
      break;
    case moho::ESpecialFileType::Replay:
      directory = USER_GetReplayDir();
      extension = USER_GetReplayExt();
      break;
    case moho::ESpecialFileType::CampaignSave:
      directory = USER_GetSaveGameDir();
      extension = USER_GetCampaignSaveExt();
      break;
    case moho::ESpecialFileType::Screenshot:
    default:
      ThrowInvalidSpecialFileType(specialFileTypeLexical);
  }

  const LuaPlus::LuaStackObject profileArg(state, 1);
  const char* const profileName = lua_tostring(rawState, 1);
  if (profileName == nullptr) {
    profileArg.TypeError("string");
  }

  const LuaPlus::LuaStackObject baseNameArg(state, 2);
  const char* const baseName = lua_tostring(rawState, 2);
  if (baseName == nullptr) {
    baseNameArg.TypeError("string");
  }

  const msvc8::string fullPath = directory + profileName + "\\" + baseName + "." + extension;
  const std::wstring widePath = gpg::STR_Utf8ToWide(fullPath.c_str());

  WIN32_FILE_ATTRIBUTE_DATA attributeData{};
  if (::GetFileAttributesExW(widePath.c_str(), GetFileExInfoStandard, &attributeData) == FALSE) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  LuaPlus::LuaObject fileInfo(state);
  fileInfo.AssignNewTable(state, 0, 0u);
  fileInfo.SetBoolean("IsFolder", (attributeData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0u);
  fileInfo.SetBoolean("ReadOnly", (attributeData.dwFileAttributes & FILE_ATTRIBUTE_READONLY) != 0u);
  fileInfo.SetInteger("SizeBytes", static_cast<std::int32_t>(attributeData.nFileSizeLow));

  ULARGE_INTEGER writeTimeStamp{};
  writeTimeStamp.LowPart = attributeData.ftLastWriteTime.dwLowDateTime;
  writeTimeStamp.HighPart = attributeData.ftLastWriteTime.dwHighDateTime;
  const msvc8::string stampText = gpg::STR_Printf("%016llx", static_cast<unsigned long long>(writeTimeStamp.QuadPart));
  fileInfo.SetString("TimeStamp", stampText.c_str());

  FILETIME localWriteFileTime{};
  SYSTEMTIME localWriteTime{};
  (void)::FileTimeToLocalFileTime(&attributeData.ftLastWriteTime, &localWriteFileTime);
  (void)::FileTimeToSystemTime(&localWriteFileTime, &localWriteTime);

  LuaPlus::LuaObject writeTimeTable(state);
  writeTimeTable.AssignNewTable(state, 0, 0u);
  writeTimeTable.SetInteger("year", static_cast<std::int32_t>(localWriteTime.wYear));
  writeTimeTable.SetInteger("month", static_cast<std::int32_t>(localWriteTime.wMonth));
  writeTimeTable.SetInteger("mday", static_cast<std::int32_t>(localWriteTime.wDay));
  writeTimeTable.SetInteger("wday", static_cast<std::int32_t>(localWriteTime.wDayOfWeek));
  writeTimeTable.SetInteger("hour", static_cast<std::int32_t>(localWriteTime.wHour));
  writeTimeTable.SetInteger("minute", static_cast<std::int32_t>(localWriteTime.wMinute));
  writeTimeTable.SetInteger("second", static_cast<std::int32_t>(localWriteTime.wSecond));
  fileInfo.SetObject("WriteTime", writeTimeTable);

  fileInfo.PushStack(state);
  return 1;
}

/**
 * Address: 0x00845DF0 (FUN_00845DF0, cfunc_RemoveProfileDirectories)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to
 * `cfunc_RemoveProfileDirectoriesL`.
 */
int moho::cfunc_RemoveProfileDirectories(lua_State* const luaContext)
{
  return cfunc_RemoveProfileDirectoriesL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00845E10 (FUN_00845E10, func_RemoveProfileDirectories_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `RemoveProfileDirectories`.
 */
moho::CScrLuaInitForm* moho::func_RemoveProfileDirectories_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "RemoveProfileDirectories",
    &moho::cfunc_RemoveProfileDirectories,
    nullptr,
    "<global>",
    kRemoveProfileDirectoriesHelpText
  );
  return &binder;
}

/**
 * Address: 0x00845E70 (FUN_00845E70, cfunc_RemoveProfileDirectoriesL)
 *
 * What it does:
 * Recycles replay/save profile-scoped directories and companion lanes for one
 * profile string.
 */
int moho::cfunc_RemoveProfileDirectoriesL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kRemoveProfileDirectoriesHelpText, 1, argumentCount);
  }

  const LuaPlus::LuaStackObject profileArg(state, 1);
  const char* const profileName = lua_tostring(state->m_state, 1);
  if (profileName == nullptr) {
    profileArg.TypeError("string");
  }

  // Binary lane calls replay/save directory helpers twice each before recycling.
  const msvc8::string replayProfilePathA = USER_GetReplayDir() + profileName;
  const msvc8::string saveProfilePathA = USER_GetSaveGameDir() + profileName;
  const msvc8::string replayProfilePathB = USER_GetReplayDir() + profileName;
  const msvc8::string saveProfilePathB = USER_GetSaveGameDir() + profileName;

  DISK_Recycle(replayProfilePathA.c_str());
  DISK_Recycle(saveProfilePathA.c_str());
  DISK_Recycle(replayProfilePathB.c_str());
  DISK_Recycle(saveProfilePathB.c_str());
  return 0;
}

/**
 * Address: 0x00846200 (FUN_00846200, cfunc_CopyCurrentReplay)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_CopyCurrentReplayL`.
 */
int moho::cfunc_CopyCurrentReplay(lua_State* const luaContext)
{
  return cfunc_CopyCurrentReplayL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00846220 (FUN_00846220, func_CopyCurrentReplay_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `CopyCurrentReplay`.
 */
moho::CScrLuaInitForm* moho::func_CopyCurrentReplay_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "CopyCurrentReplay",
    &moho::cfunc_CopyCurrentReplay,
    nullptr,
    "<global>",
    kCopyCurrentReplayHelpText
  );
  return &binder;
}

/**
 * Address: 0x00846280 (FUN_00846280, cfunc_CopyCurrentReplayL)
 *
 * What it does:
 * Copies the localized `LastGame` replay from one profile lane to a new replay
 * filename in that profile.
 */
int moho::cfunc_CopyCurrentReplayL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 2) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCopyCurrentReplayHelpText, 2, argumentCount);
  }

  const LuaPlus::LuaStackObject profileArg(state, 1);
  const char* const profileName = lua_tostring(state->m_state, 1);
  if (profileName == nullptr) {
    profileArg.TypeError("string");
  }

  const LuaPlus::LuaStackObject filenameArg(state, 2);
  const char* const newFilename = lua_tostring(state->m_state, 2);
  if (newFilename == nullptr) {
    filenameArg.TypeError("string");
  }

  const msvc8::string replayDirectory = USER_GetReplayDir();
  const msvc8::string replayExtension = USER_GetReplayExt();
  const msvc8::string localizedLastGame = Loc(USER_GetLuaState(), "<LOC Engine0030>LastGame");
  const msvc8::string replayPrefix = replayDirectory + profileName + "\\";

  const msvc8::string sourcePath = replayPrefix + localizedLastGame + "." + replayExtension;
  const msvc8::string destinationPath = replayPrefix + newFilename + "." + replayExtension;

  const std::wstring destinationWide = gpg::STR_Utf8ToWide(destinationPath.c_str());
  const std::wstring sourceWide = gpg::STR_Utf8ToWide(sourcePath.c_str());
  if (::CopyFileW(sourceWide.c_str(), destinationWide.c_str(), FALSE) == FALSE) {
    const msvc8::string lastError = WIN_GetLastError();
    gpg::Logf("Unable to copy replay file: %s", lastError.c_str());
  }
  return 0;
}

/**
 * Address: 0x00846F70 (FUN_00846F70, cfunc_SetOverlayFilters)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_SetOverlayFiltersL`.
 */
int moho::cfunc_SetOverlayFilters(lua_State* const luaContext)
{
  return cfunc_SetOverlayFiltersL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00846F90 (FUN_00846F90, func_SetOverlayFilters_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `SetOverlayFilters`.
 */
moho::CScrLuaInitForm* moho::func_SetOverlayFilters_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetOverlayFilters",
    &moho::cfunc_SetOverlayFilters,
    nullptr,
    "<global>",
    kSetOverlayFiltersHelpText
  );
  return &binder;
}

/**
 * Address: 0x008471C0 (FUN_008471C0, cfunc_GenerateBuildTemplateFromSelection)
 *
 * IDA signature:
 * int __cdecl cfunc_GenerateBuildTemplateFromSelection(LuaPlus::LuaState *a1);
 *
 * What it does:
 * Lua callback for the global `GenerateBuildTemplateFromSelection()` binding.
 * Resolves the LuaPlus state wrapper (result unused) and, when a world session
 * is active, regenerates its build templates from the current selection.
 * Pushes no return values.
 */
int moho::cfunc_GenerateBuildTemplateFromSelection(lua_State* const luaContext)
{
  (void)LuaPlus::LuaState::CastState(luaContext);

  if (CWldSession* const session = WLD_GetActiveSession(); session != nullptr) {
    session->GenerateBuildTemplates();
  }

  return 0;
}

/**
 * Address: 0x008471F0 (FUN_008471F0, func_GenerateBuildTemplateFromSelection_LuaFuncDef)
 *
 * What it does:
 * Publishes global `GenerateBuildTemplateFromSelection()` Lua binder metadata.
 */
moho::CScrLuaInitForm* moho::func_GenerateBuildTemplateFromSelection_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GenerateBuildTemplateFromSelection",
    &moho::cfunc_GenerateBuildTemplateFromSelection,
    nullptr,
    "<global>",
    kGenerateBuildTemplateFromSelectionHelpText
  );
  return &binder;
}

/**
 * Address: 0x00846FF0 (FUN_00846FF0, cfunc_SetOverlayFiltersL)
 *
 * What it does:
 * Reads one Lua table of overlay filter strings and replaces
 * `CWldSession::mOverlayFilters`.
 */
int moho::cfunc_SetOverlayFiltersL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSetOverlayFiltersHelpText, 1, argumentCount);
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (!session) {
    return 0;
  }

  LuaPlus::LuaObject filterTable(LuaPlus::LuaStackObject(state, 1));
  if (!filterTable.IsTable()) {
    return 0;
  }

  msvc8::vector<msvc8::string> parsedFilters{};
  for (LuaPlus::LuaTableIterator iter(&filterTable, 1); !iter.m_isDone; iter.Next()) {
    LuaPlus::LuaObject filterValue = iter.GetValue();
    const char* const filterText = filterValue.GetString();
    parsedFilters.push_back(msvc8::string(filterText, std::strlen(filterText)));
  }

  session->mOverlayFilters = std::move(parsedFilters);
  return 0;
}

/**
 * Address: 0x00847A20 (FUN_00847A20, cfunc_ClearBuildTemplates)
 *
 * What it does:
 * Clears user-session build-template state when a world session is active.
 */
int moho::cfunc_ClearBuildTemplates(lua_State* const luaContext)
{
  (void)LuaPlus::LuaState::CastState(luaContext);
  if (CWldSession* const session = WLD_GetActiveSession()) {
    session->ClearBuildTemplates();
  }
  return 0;
}

/**
 * Address: 0x00847A50 (FUN_00847A50, func_ClearBuildTemplates_LuaFuncDef)
 *
 * What it does:
 * Publishes the global user-Lua binder definition for `ClearBuildTemplates`.
 */
moho::CScrLuaInitForm* moho::func_ClearBuildTemplates_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "ClearBuildTemplates",
    &moho::cfunc_ClearBuildTemplates,
    nullptr,
    "<global>",
    kClearBuildTemplatesHelpText
  );
  return &binder;
}

/**
 * Address: 0x00847AD0 (FUN_00847AD0, cfunc_RenderOverlayMilitary)
 *
 * What it does:
 * Retains legacy `RenderOverlayMilitary(bool)` argument validation and emits a
 * deprecation warning.
 */
int moho::cfunc_RenderOverlayMilitary(lua_State* const luaContext)
{
  LuaPlus::LuaState* const state = LuaPlus::LuaState::CastState(luaContext);
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kRenderOverlayMilitaryHelpText, 1, argumentCount);
  }
  gpg::Warnf("RenderOverlayMilitary is deprecated");
  return 0;
}

/**
 * Address: 0x00847B20 (FUN_00847B20, func_RenderOverlayMilitary_LuaFuncDef)
 *
 * What it does:
 * Publishes the global user-Lua binder definition for `RenderOverlayMilitary`.
 */
moho::CScrLuaInitForm* moho::func_RenderOverlayMilitary_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "RenderOverlayMilitary",
    &moho::cfunc_RenderOverlayMilitary,
    nullptr,
    "<global>",
    kRenderOverlayMilitaryHelpText
  );
  return &binder;
}

/**
 * Address: 0x00847BC0 (FUN_00847BC0, cfunc_RenderOverlayIntel)
 *
 * What it does:
 * Retains legacy `RenderOverlayIntel(bool)` argument validation and emits a
 * deprecation warning.
 */
int moho::cfunc_RenderOverlayIntel(lua_State* const luaContext)
{
  LuaPlus::LuaState* const state = LuaPlus::LuaState::CastState(luaContext);
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kRenderOverlayIntelHelpText, 1, argumentCount);
  }
  gpg::Warnf("RenderOverlayIntel is deprecated");
  return 0;
}

/**
 * Address: 0x00847C10 (FUN_00847C10, func_RenderOverlayIntel_LuaFuncDef)
 *
 * What it does:
 * Publishes the global user-Lua binder definition for `RenderOverlayIntel`.
 */
moho::CScrLuaInitForm* moho::func_RenderOverlayIntel_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "RenderOverlayIntel",
    &moho::cfunc_RenderOverlayIntel,
    nullptr,
    "<global>",
    kRenderOverlayIntelHelpText
  );
  return &binder;
}

/**
 * Address: 0x00847CB0 (FUN_00847CB0, cfunc_RenderOverlayEconomy)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to
 * `cfunc_RenderOverlayEconomyL`.
 */
int moho::cfunc_RenderOverlayEconomy(lua_State* const luaContext)
{
  return cfunc_RenderOverlayEconomyL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00847CD0 (FUN_00847CD0, func_RenderOverlayEconomy_LuaFuncDef)
 *
 * What it does:
 * Publishes the global user-Lua binder definition for
 * `RenderOverlayEconomy`.
 */
moho::CScrLuaInitForm* moho::func_RenderOverlayEconomy_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "RenderOverlayEconomy",
    &moho::cfunc_RenderOverlayEconomy,
    nullptr,
    "<global>",
    kRenderOverlayEconomyHelpText
  );
  return &binder;
}

/**
 * Address: 0x00847D30 (FUN_00847D30, cfunc_RenderOverlayEconomyL)
 *
 * What it does:
 * Reads one Lua bool and updates the active user session economy-overlay flag.
 */
int moho::cfunc_RenderOverlayEconomyL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kRenderOverlayEconomyHelpText, 1, argumentCount);
  }

  if (CWldSession* const session = WLD_GetActiveSession()) {
    const LuaPlus::LuaStackObject enabledArg(state, 1);
    session->DisplayEconomyOverlay = enabledArg.GetBoolean();
  }
  return 0;
}

/**
 * Address: 0x00847D90 (FUN_00847D90, cfunc_TeamColorMode)
 *
 * What it does:
 * Unwraps Lua callback context and dispatches to `cfunc_TeamColorModeL`.
 */
int moho::cfunc_TeamColorMode(lua_State* const luaContext)
{
  return cfunc_TeamColorModeL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00847DB0 (FUN_00847DB0, func_TeamColorMode_LuaFuncDef)
 *
 * What it does:
 * Publishes the global user-Lua binder definition for `TeamColorMode`.
 */
moho::CScrLuaInitForm* moho::func_TeamColorMode_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "TeamColorMode",
    &moho::cfunc_TeamColorMode,
    nullptr,
    "<global>",
    kTeamColorModeHelpText
  );
  return &binder;
}

/**
 * Address: 0x00847E10 (FUN_00847E10, cfunc_TeamColorModeL)
 *
 * What it does:
 * A Lua bool turns the active user session's team-color mode on or off. FAF
 * hot-patch (FA-Binary-Patches TeamColorMode, 0x00847E51): a string such as
 * "ffrrggbb,ffrrggbb,..." instead fills the per-army palette `teamcolors` in
 * army order and leaves the mode alone.
 */
int moho::cfunc_TeamColorModeL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kTeamColorModeHelpText, 1, argumentCount);
  }

  if (CWldSession* const session = WLD_GetActiveSession()) {
    const LuaPlus::LuaStackObject modeArg(state, 1);
    const int argumentType = lua_type(state->m_state, 1);
    if (argumentType == LUA_TSTRING || argumentType == LUA_TNUMBER) {
      ParseTeamColorPalette(lua_tostring(state->m_state, 1));
      return 0;
    }
    if (argumentType != LUA_TBOOLEAN) {
      modeArg.TypeError("bool");
    }
    session->mTeamColorMode = modeArg.GetBoolean();
  }
  return 0;
}

/**
 * Address: 0x00847E70 (FUN_00847E70, cfunc_GetUnitByIdUser)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GetUnitByIdUserL`.
 */
int moho::cfunc_GetUnitByIdUser(lua_State* const luaContext)
{
  return cfunc_GetUnitByIdUserL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x00847E90 (FUN_00847E90, func_GetUnitByIdUser_LuaFuncDef)
 *
 * What it does:
 * Publishes the global user-Lua binder definition for `GetUnitById`.
 */
moho::CScrLuaInitForm* moho::func_GetUnitByIdUser_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "GetUnitById",
    &moho::cfunc_GetUnitByIdUser,
    nullptr,
    "<global>",
    kGetUnitByIdUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x00847EF0 (FUN_00847EF0, cfunc_GetUnitByIdUserL)
 *
 * What it does:
 * Resolves one entity id through user-session map lanes and returns the
 * matching user-unit Lua object, or `nil` when no unit is found.
 */
int moho::cfunc_GetUnitByIdUserL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGetUnitByIdUserHelpText, 1, argumentCount);
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  const LuaPlus::LuaStackObject entityIdArg(state, 1);
  const char* entityIdText = lua_tostring(rawState, 1);
  if (entityIdText == nullptr) {
    entityIdArg.TypeError("string");
    entityIdText = "";
  }

  const std::int32_t entityId = std::atoi(entityIdText);
  UserEntity* const entity = FindUserSessionEntityById(session, entityId);
  UserUnit* const userUnit = entity ? entity->IsUserUnit() : nullptr;
  if (userUnit == nullptr) {
    lua_pushnil(rawState);
    (void)lua_gettop(rawState);
    return 1;
  }

  userUnit->mLuaObj.PushStack(state);
  return 1;
}

/**
 * Address: 0x0128B2F9 (FUN_0128B2F9, cfunc_SetInvertMidMouseButton)
 *
 * What it does:
 * Reads one Lua boolean, patches middle-mouse scrub opcodes to add/sub mode,
 * and preserves page protection around the patch write.
 */
int moho::cfunc_SetInvertMidMouseButton(lua_State* const luaContext)
{
  const int argumentCount = lua_gettop(luaContext);
  if (argumentCount != 1) {
    gpg::Warnf(kLuaExpectedArgsWarning, kSetInvertMidMouseButtonHelpText, 1, argumentCount);
  }

  if (lua_type(luaContext, 1) != LUA_TBOOLEAN) {
    gpg::Warnf(kLuaInvalidBoolWarning, kSetInvertMidMouseButtonHelpText, 1);
  }

  const bool invertMiddleMouse = lua_toboolean(luaContext, 1) != 0;
  UI_SetInvertMidMouseScrub(invertMiddleMouse);
  return 0;
}

/**
 * What it does:
 * Publishes the global Lua binder definition for `SetInvertMidMouseButton`.
 *
 * The shipped build carries this binding in its `.exxt` patch section rather
 * than a `func_*_LuaFuncDef` factory, so there is no address to cite for the
 * factory itself - only for the bound worker, `cfunc_SetInvertMidMouseButton`
 * at 0x0128B2F9. `/lua/options/options.lua` calls the global from the
 * `invert_middle_mouse_button` option's `set` handler, which runs at startup,
 * so without this registration every options pass died on "access to
 * nonexistent global variable".
 */
moho::CScrLuaInitForm* moho::func_SetInvertMidMouseButton_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "SetInvertMidMouseButton",
    &moho::cfunc_SetInvertMidMouseButton,
    nullptr,
    "<global>",
    kSetInvertMidMouseButtonHelpText
  );
  return &binder;
}

/**
 * Address: 0x007B5170 (FUN_007B5170, cfunc_CreateUnitAtMouse)
 *
 * What it does:
 * Unwraps Lua callback context and forwards to `cfunc_CreateUnitAtMouseL`.
 */
int moho::cfunc_CreateUnitAtMouse(lua_State* const luaContext)
{
  return cfunc_CreateUnitAtMouseL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007B5190 (FUN_007B5190, func_CreateUnitAtMouse_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `CreateUnitAtMouse`.
 */
moho::CScrLuaInitForm* moho::func_CreateUnitAtMouse_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "CreateUnitAtMouse",
    &moho::cfunc_CreateUnitAtMouse,
    nullptr,
    "<global>",
    kCreateUnitAtMouseHelpText
  );
  return &binder;
}

/**
 * Address: 0x007B51E0 (FUN_007B51E0, cfunc_CreateUnitAtMouseL)
 *
 * What it does:
 * Reads `(blueprintId, armyIndex, offsetX, offsetZ, rotation)`, resolves one
 * unit blueprint, snaps non-mobile units to footprint-aligned map cells, and
 * submits one create-unit command through the active sim driver.
 */
int moho::cfunc_CreateUnitAtMouseL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 5) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCreateUnitAtMouseHelpText, 5, argumentCount);
  }

  CWldSession* const session = WLD_GetActiveSession();
  if (session == nullptr) {
    LuaPlus::LuaState::Error(state, "No active session.");
    return 0;
  }

  LuaPlus::LuaStackObject blueprintArg(state, 1);
  const char* const blueprintText = lua_tostring(rawState, 1);
  if (!blueprintText) {
    LuaPlus::LuaStackObject::TypeError(&blueprintArg, "string");
  }

  RResId lookupId{};
  gpg::STR_InitFilename(&lookupId.name, blueprintText ? blueprintText : "");

  RUnitBlueprint* const blueprint = session->mRules ? session->mRules->GetUnitBlueprint(lookupId) : nullptr;
  if (!blueprint) {
    LuaPlus::LuaState::Error(state, "Unknown unit kind: %s", blueprintText ? blueprintText : "");
    return 0;
  }

  LuaPlus::LuaStackObject armyIndexArg(state, 2);
  if (lua_type(rawState, 2) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&armyIndexArg, "integer");
  }
  const int armyIndex = static_cast<int>(lua_tonumber(rawState, 2));

  const int armyCount = static_cast<int>(session->userArmies.size());
  if (armyIndex < 0 || armyIndex >= armyCount) {
    LuaPlus::LuaState::Error(
      state,
      "Invalid army index, must be >= 0 and < %d but got %d.",
      armyCount,
      armyIndex
    );
    return 0;
  }

  LuaPlus::LuaStackObject offsetZArg(state, 4);
  if (lua_type(rawState, 4) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&offsetZArg, "number");
  }
  const float offsetZ = static_cast<float>(lua_tonumber(rawState, 4));

  LuaPlus::LuaStackObject offsetXArg(state, 3);
  if (lua_type(rawState, 3) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&offsetXArg, "number");
  }
  const float offsetX = static_cast<float>(lua_tonumber(rawState, 3));

  SCoordsVec2 spawnPos{};
  spawnPos.x = session->CursorWorldPos.x + offsetX;
  spawnPos.z = session->CursorWorldPos.z + offsetZ;

  LuaPlus::LuaStackObject rotationArg(state, 5);
  if (lua_type(rawState, 5) != LUA_TNUMBER) {
    LuaPlus::LuaStackObject::TypeError(&rotationArg, "number");
  }
  const float rotation = static_cast<float>(lua_tonumber(rawState, 5));

  if (!blueprint->IsMobile()) {
    Sim* const sim = ResolveGlobalSim(rawState);
    STIMap* const map = sim ? sim->mMapData : nullptr;
    if (map != nullptr) {
      const float anchorZ = spawnPos.z - (static_cast<float>(blueprint->mFootprint.mSizeZ) * 0.5f);
      const float anchorX = spawnPos.x - (static_cast<float>(blueprint->mFootprint.mSizeX) * 0.5f);

      SOCellPos anchorCell{};
      anchorCell.x = static_cast<std::int16_t>(static_cast<int>(anchorX));
      anchorCell.z = static_cast<std::int16_t>(static_cast<int>(anchorZ));

      const Wm3::Vector3f alignedPos = COORDS_ToWorldPos(
        map,
        anchorCell,
        static_cast<ELayer>(blueprint->mFootprint.mOccupancyCaps),
        static_cast<int>(blueprint->mFootprint.mSizeX),
        static_cast<int>(blueprint->mFootprint.mSizeZ)
      );
      spawnPos.x = alignedPos.x;
      spawnPos.z = alignedPos.z;
    }
  }

  ISTIDriver* const activeDriver = WLD_GetDriver();
  if (activeDriver != nullptr) {
    RResId createId{};
    gpg::STR_CopyFilename(&createId.name, &blueprint->mBlueprintId);
    activeDriver->CreateUnit(static_cast<std::uint32_t>(armyIndex), createId, spawnPos, rotation);
  }

  return 0;
}

/**
 * Address: 0x008ADFF0 (FUN_008ADFF0, cfunc_AudioSetLanguageUser)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_AudioSetLanguageUserL`.
 */
int moho::cfunc_AudioSetLanguageUser(lua_State* const luaContext)
{
  return cfunc_AudioSetLanguageUserL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008AE010 (FUN_008AE010, func_AudioSetLanguageUser_LuaFuncDef)
 *
 * What it does:
 * Publishes user-lane global `AudioSetLanguage(name)` Lua binder definition.
 */
moho::CScrLuaInitForm* moho::func_AudioSetLanguageUser_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "AudioSetLanguage",
    &moho::cfunc_AudioSetLanguageUser,
    nullptr,
    "<global>",
    kAudioSetLanguageUserHelpText
  );
  return &binder;
}

/**
 * Address: 0x008AE070 (FUN_008AE070, cfunc_AudioSetLanguageUserL)
 *
 * What it does:
 * Validates one language code, then rebuilds localized voice/tutorial engines
 * when the normalized language tag changes and localized VO data exists.
 */
int moho::cfunc_AudioSetLanguageUserL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kAudioSetLanguageUserHelpText, 1, argumentCount);
  }

  LuaPlus::LuaStackObject languageArg(state, 1);
  const char* languageText = lua_tostring(state->m_state, 1);
  if (languageText == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&languageArg, "string");
    languageText = "";
  }

  const msvc8::string normalizedLanguage = gpg::STR_ToLower(languageText);
  CUserSoundManager* const userSound = static_cast<CUserSoundManager*>(USER_GetSound());
  if (userSound == nullptr) {
    return 0;
  }

  if (normalizedLanguage == userSound->mLanguageTag || !HasLocalizedVoiceDirectory(normalizedLanguage)) {
    return 0;
  }

  msvc8::string localizedRootPath = gpg::STR_Printf("/sounds/voice/%s", normalizedLanguage.c_str());
  if (AudioEngine* const voiceEngine = userSound->mTutorialEngine.get(); voiceEngine != nullptr) {
    voiceEngine->Shutdown();
  }
  userSound->mTutorialEngine = AudioEngine::Create(localizedRootPath.c_str());

  localizedRootPath.append("/tutorials");
  if (AudioEngine* const tutorialEngine = userSound->mAmbientEngine.get(); tutorialEngine != nullptr) {
    tutorialEngine->Shutdown();
  }
  userSound->mAmbientEngine = AudioEngine::Create(localizedRootPath.c_str());

  userSound->mLanguageTag.assign(normalizedLanguage, 0u, msvc8::string::npos);
  return 0;
}

/**
 * Address: 0x008AE300 (FUN_008AE300, cfunc_HasLocalizedVOUserL)
 *
 * What it does:
 * Returns whether the requested localized voice directory exists.
 */
int moho::cfunc_HasLocalizedVOUserL(LuaPlus::LuaState* const state)
{
  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kHasLocalizedVOUserHelpText, 1, argumentCount);
  }

  LuaPlus::LuaStackObject languageArg(state, 1);
  const char* languageText = lua_tostring(state->m_state, 1);
  if (languageText == nullptr) {
    LuaPlus::LuaStackObject::TypeError(&languageArg, "string");
    languageText = "";
  }

  const msvc8::string language(languageText);
  lua_pushboolean(state->m_state, HasLocalizedVoiceDirectory(language) ? 1 : 0);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x008AE280 (FUN_008AE280, cfunc_HasLocalizedVOUser)
 *
 * What it does:
 * Unwraps Lua callback state and forwards to `cfunc_HasLocalizedVOUserL`.
 */
int moho::cfunc_HasLocalizedVOUser(lua_State* const luaContext)
{
  return cfunc_HasLocalizedVOUserL(moho::SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x008AE2A0 (FUN_008AE2A0, func_HasLocalizedVOUser_LuaFuncDef)
 *
 * What it does:
 * Publishes the global Lua binder definition for `HasLocalizedVO`.
 */
moho::CScrLuaInitForm* moho::func_HasLocalizedVOUser_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    "HasLocalizedVO",
    &moho::cfunc_HasLocalizedVOUser,
    nullptr,
    "<global>",
    kHasLocalizedVOUserHelpText
  );
  return &binder;
}

namespace
{
  /**
   * Engine addition (dedicated-server plan WPL.4): drives this file's Lua binder
   * definitions, the calls Sim.cpp's SimLuaFuncDefBootstrap made for them, in
   * the same order (see that object for why a bootstrap is needed).
   */
  struct UserLuaFuncDefBootstrap
  {
    UserLuaFuncDefBootstrap()
    {
      (void)::moho::func_ParseEntityCategoryUser_LuaFuncDef();
      (void)::moho::func_GetUnitCommandFromCommandCap_LuaFuncDef();
      (void)::moho::func_EjectSessionClient_LuaFuncDef();
      (void)::moho::func_WorldIsLoading_LuaFuncDef();
      (void)::moho::func_WorldIsPlaying_LuaFuncDef();
      (void)::moho::func_GetGameSpeed_LuaFuncDef();
      (void)::moho::func_SetGameSpeed_LuaFuncDef();
      (void)::moho::func_AddToSessionExtraSelectList_LuaFuncDef();
      (void)::moho::func_RemoveFromSessionExtraSelectList_LuaFuncDef();
      (void)::moho::func_ClearSessionExtraSelectList_LuaFuncDef();
      (void)::moho::func_CurrentTime_LuaFuncDef();
      (void)::moho::func_GameTime_LuaFuncDef();
      (void)::moho::func_GameTick_LuaFuncDef();
      (void)::moho::func_IsAllyUser_LuaFuncDef();
      (void)::moho::func_IsEnemyUser_LuaFuncDef();
      (void)::moho::func_IsNeutral_LuaFuncDef();
      (void)::moho::func_SyncPlayableRect_LuaFuncDef();
      (void)::moho::func_RandomUser_LuaFuncDef();
      (void)::moho::func_EntityCategoryContainsUser_LuaFuncDef();
      (void)::moho::func_EntityCategoryFilterDownUser_LuaFuncDef();
      (void)::moho::func_EntityCategoryFilterOut_LuaFuncDef();
      (void)::moho::func_ExecLuaInSim_LuaFuncDef();
      (void)::moho::func_SimCallback_LuaFuncDef();
      (void)::moho::func_SetAutoMode_LuaFuncDef();
      (void)::moho::func_SetAutoSurfaceMode_LuaFuncDef();
      (void)::moho::func_ToggleScriptBit_LuaFuncDef();
      (void)::moho::func_SetPaused_LuaFuncDef();
      (void)::moho::func_GetAttachedUnitsList_LuaFuncDef();
      (void)::moho::func_ValidateUnitsList_LuaFuncDef();
      (void)::moho::func_GetAssistingUnitsList_LuaFuncDef();
      (void)::moho::func_GetArmyAvatars_LuaFuncDef();
      (void)::moho::func_GetIdleEngineers_LuaFuncDef();
      (void)::moho::func_GetIdleFactories_LuaFuncDef();
      (void)::moho::func_GetSelectedUnits_LuaFuncDef();
      (void)::moho::func_GetValidAttackingUnits_LuaFuncDef();
      (void)::moho::func_SelectUnits_LuaFuncDef();
      (void)::moho::func_AddSelectUnits_LuaFuncDef();
      (void)::moho::func_EngineStartSplashScreens_LuaFuncDef();
      (void)::moho::func_EngineStartFrontEndUI_LuaFuncDef();
      (void)::moho::func_ExitApplication_LuaFuncDef();
      (void)::moho::func_ExitGame_LuaFuncDef();
      (void)::moho::func_RestartSession_LuaFuncDef();
      (void)::moho::func_GetFrame_LuaFuncDef();
      (void)::moho::func_ClearFrame_LuaFuncDef();
      (void)::moho::func_GetNumRootFrames_LuaFuncDef();
      (void)::moho::func_GetEconomyTotals_LuaFuncDef();
      (void)::moho::func_GetResourceSharing_LuaFuncDef();
      (void)::moho::func_GetCurrentUIState_LuaFuncDef();
      (void)::moho::func_GetSimTicksPerSecond_LuaFuncDef();
      (void)::moho::func_SessionRequestPause_LuaFuncDef();
      (void)::moho::func_SessionResume_LuaFuncDef();
      (void)::moho::func_SessionIsPaused_LuaFuncDef();
      (void)::moho::func_SessionIsGameOver_LuaFuncDef();
      (void)::moho::func_SessionGetLocalCommandSource_LuaFuncDef();
      (void)::moho::func_SessionIsReplayUser_LuaFuncDef();
      (void)::moho::func_SessionIsBeingRecorded_LuaFuncDef();
      (void)::moho::func_SessionIsMultiplayer_LuaFuncDef();
      (void)::moho::func_SessionIsObservingAllowed_LuaFuncDef();
      (void)::moho::func_SessionCanRestart_LuaFuncDef();
      (void)::moho::func_SessionIsActive_LuaFuncDef();
      (void)::moho::func_SessionGetScenarioInfo_LuaFuncDef();
      (void)::moho::func_SessionEndGame_LuaFuncDef();
      (void)::moho::func_GetMouseWorldPosUser_LuaFuncDef();
      (void)::moho::func_GetMouseScreenPos_LuaFuncDef();
      (void)::moho::func_CopyToClipboard_LuaFuncDef();
      (void)::moho::func_GetTimeForProfileUser_LuaFuncDef();
      (void)::moho::func_GetDepositsAroundPointUser_LuaFuncDef();
      (void)::moho::func_GetHighlightCommand_LuaFuncDef();
      (void)::moho::func_SetFocusArmyUser_LuaFuncDef();
      (void)::moho::func_SetInvertMidMouseButton_LuaFuncDef();
      (void)::moho::func_GetFocusArmyUser_LuaFuncDef();
      (void)::moho::func_IsObserver_LuaFuncDef();
      (void)::moho::func_GetGameTime_LuaFuncDef();
      (void)::moho::func_GetGameTimeSecondsUser_LuaFuncDef();
      (void)::moho::func_GetSystemTime_LuaFuncDef();
      (void)::moho::func_GetSystemTimeSeconds_LuaFuncDef();
      (void)::moho::func_FormatTime_LuaFuncDef();
      (void)::moho::func_GetSimRate_LuaFuncDef();
      (void)::moho::func_GetArmiesTable_LuaFuncDef();
      (void)::moho::func_GetArmyScore_LuaFuncDef();
      (void)::moho::func_DeleteCommand_LuaFuncDef();
      (void)::moho::func_GetSpecialFiles_LuaFuncDef();
      (void)::moho::func_GetSpecialFilePath_LuaFuncDef();
      (void)::moho::func_GetSpecialFolder_LuaFuncDef();
      (void)::moho::func_RemoveSpecialFile_LuaFuncDef();
      (void)::moho::func_GetSpecialFileInfo_LuaFuncDef();
      (void)::moho::func_RemoveProfileDirectories_LuaFuncDef();
      (void)::moho::func_CopyCurrentReplay_LuaFuncDef();
      (void)::moho::func_SetOverlayFilters_LuaFuncDef();
      (void)::moho::func_GenerateBuildTemplateFromSelection_LuaFuncDef();
      (void)::moho::func_ClearBuildTemplates_LuaFuncDef();
      (void)::moho::func_RenderOverlayMilitary_LuaFuncDef();
      (void)::moho::func_RenderOverlayIntel_LuaFuncDef();
      (void)::moho::func_RenderOverlayEconomy_LuaFuncDef();
      (void)::moho::func_TeamColorMode_LuaFuncDef();
      (void)::moho::func_GetUnitByIdUser_LuaFuncDef();
      (void)::moho::func_CreateUnitAtMouse_LuaFuncDef();
      (void)::moho::func_AudioSetLanguageUser_LuaFuncDef();
      (void)::moho::func_HasLocalizedVOUser_LuaFuncDef();
    }
  };

  const UserLuaFuncDefBootstrap gUserLuaFuncDefBootstrap{};
} // namespace
