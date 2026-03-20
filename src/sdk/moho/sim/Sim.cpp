#include "Sim.h"
#include "moho/sim/CSimConVarBase.h"
#include "SimDriver.h"

#include <algorithm>
#include <cctype>
#include <cstdarg>
#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <cstring>
#include <exception>
#include <initializer_list>
#include <limits>
#include <new>
#include <typeinfo>
#include <vector>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Logging.h"
#include "moho/ai/CAiFormationDBImpl.h"
#include "moho/ai/CAiReconDBImpl.h"
#include "moho/ai/CAiSiloBuildImpl.h"
#include "moho/ai/CAiTransportCommandOps.h"
#include "moho/command/CCommandDb.h"
#include "moho/console/CVarAccess.h"
#include "moho/entity/Entity.h"
#include "moho/entity/EntityDb.h"
#include "moho/entity/EntityId.h"
#include "moho/entity/Prop.h"
#include "moho/path/PathTables.h"
#include "moho/render/camera/VTransform.h"
#include "moho/render/CDecalBuffer.h"
#include "moho/render/CEffectManagerImpl.h"
#include "moho/resource/blueprints/RPropBlueprint.h"
#include "moho/resource/blueprints/RUnitBlueprint.h"
#include "moho/script/CScriptObject.h"
#include "moho/sim/CArmyImpl.h"
#include "moho/sim/CSimArmyEconomyInfo.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/sim/SSTICommandSource.h"
#include "moho/unit/core/SUnitConstructionParams.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/CUnitCommand.h"
#include "moho/unit/CUnitCommandQueue.h"

using namespace moho;
using EntId = std::int32_t;

namespace gpg
{
  enum class TrackedPointerState : int
  {
    Unowned = 1,
    Owned = 2,
  };

  struct TrackedPointerInfo
  {
    void* object;
    gpg::RType* type;
  };

  TrackedPointerInfo ReadRawPointer(ReadArchive* archive, const gpg::RRef& ownerRef);
  void WriteRawPointer(
    WriteArchive* archive, const gpg::RRef& objectRef, TrackedPointerState state, const gpg::RRef& ownerRef
  );
  gpg::RRef REF_UpcastPtr(const gpg::RRef& source, const gpg::RType* targetType);
} // namespace gpg

namespace
{
  constexpr CommandSourceId kInvalidCommandSource = 0xFF;
  constexpr std::uintptr_t kReleaseCommandIdEa = 0x006E0EC0u;
  constexpr std::uintptr_t kTryParseSimCommandEa = 0x00734870u;

  void CopySyncMaskBlock(SSyncFilterMaskBlock& dst, const SSyncFilterMaskBlock& src)
  {
    dst.rawWord = src.rawWord;
    dst.masks.ResetFrom(src.masks);
  }

  void CopySyncFilter(SSyncFilter& dst, const SSyncFilter& src)
  {
    dst.focusArmy = src.focusArmy;
    dst.geoCams = src.geoCams;
    CopySyncMaskBlock(dst.maskA, src.maskA);
    dst.optionFlag = src.optionFlag;
    CopySyncMaskBlock(dst.maskB, src.maskB);
  }

  struct PropCreateTransformWords
  {
    float orientX;
    float orientY;
    float orientZ;
    float orientW;
    float posX;
    float posY;
    float posZ;
  };

  static_assert(sizeof(PropCreateTransformWords) == 0x1C, "PropCreateTransformWords size must be 0x1C");

  bool EqualsIgnoreCase(const char* lhs, const char* rhs)
  {
    if (!lhs || !rhs) {
      return false;
    }

    return _stricmp(lhs, rhs) == 0;
  }

  bool ParseBoolLiteral(const char* text, bool& outValue)
  {
    if (EqualsIgnoreCase(text, "true")) {
      outValue = true;
      return true;
    }

    if (EqualsIgnoreCase(text, "false")) {
      outValue = false;
      return true;
    }

    return false;
  }

  bool ParseIntLiteral(const char* text, int& outValue)
  {
    if (!text) {
      return false;
    }

    char* endPtr = nullptr;
    const long parsed = std::strtol(text, &endPtr, 10);
    if (endPtr == text || (endPtr && *endPtr != '\0')) {
      return false;
    }
    if (parsed < static_cast<long>(std::numeric_limits<int>::min()) ||
        parsed > static_cast<long>(std::numeric_limits<int>::max())) {
      return false;
    }

    outValue = static_cast<int>(parsed);
    return true;
  }

  CUnitCommand* FindCommandById(CCommandDb* commandDb, const CmdId cmdId)
  {
    if (!commandDb || !commandDb->commands.header_ptr()) {
      return nullptr;
    }

    auto it = commandDb->commands.find(cmdId);
    if (it == commandDb->commands.end()) {
      return nullptr;
    }

    return &it->second;
  }

  Entity* FindEntityById(CEntityDb* entityDb, const EntId id)
  {
    if (!entityDb) {
      return nullptr;
    }

    for (auto it = entityDb->Entities().begin(); it != entityDb->Entities().end(); ++it) {
      Entity* entity = *it;
      if (entity && entity->id_ == id) {
        return entity;
      }
    }

    return nullptr;
  }

  struct IntrusiveSetNode
  {
    IntrusiveSetNode* mNext;
    IntrusiveSetNode* mPrev;
  };

  static_assert(sizeof(IntrusiveSetNode) == 0x08, "IntrusiveSetNode size must be 0x08");

  using SimDebugEntitySet = SEntitySetTemplateUnit;

  static_assert(sizeof(SimDebugEntitySet) == 0x28, "SimDebugEntitySet size must be 0x28");

  void InitSimDebugEntitySet(SimDebugEntitySet& outSet)
  {
    outSet.mNext = &outSet;
    outSet.mPrev = &outSet;
    outSet.mVec.RebindInlineNoFree();
  }

  void DestroySimDebugEntitySet(SimDebugEntitySet& set)
  {
    set.mVec.ResetStorageToInline();

    auto* const next = static_cast<IntrusiveSetNode*>(set.mNext);
    auto* const prev = static_cast<IntrusiveSetNode*>(set.mPrev);
    if (next != nullptr && prev != nullptr) {
      next->mPrev = prev;
      prev->mNext = next;
    }

    set.mNext = &set;
    set.mPrev = &set;
  }

  bool ContainsEntity(const SimDebugEntitySet& set, Entity* entity)
  {
    for (Entity* const* it = set.mVec.begin(); it != set.mVec.end(); ++it) {
      if (*it == entity) {
        return true;
      }
    }

    return false;
  }

  void AppendUniqueEntity(SimDebugEntitySet& set, Entity* entity)
  {
    if (!entity || ContainsEntity(set, entity)) {
      return;
    }
    set.mVec.PushBack(entity);
  }

  void TryParseSimCommand(
    Sim* sim,
    const char* command,
    const Wm3::Vector3<float>& worldPos,
    CArmyImpl* focusArmy,
    SimDebugEntitySet& selectedUnits
  )
  {
    using Fn = void(__cdecl*)(Sim*, char*, int, int, int);
    auto fn = reinterpret_cast<Fn>(kTryParseSimCommandEa);
    fn(
      sim,
      const_cast<char*>(command ? command : ""),
      static_cast<int>(reinterpret_cast<std::uintptr_t>(const_cast<Wm3::Vector3<float>*>(&worldPos))),
      static_cast<int>(reinterpret_cast<std::uintptr_t>(focusArmy)),
      static_cast<int>(reinterpret_cast<std::uintptr_t>(&selectedUnits))
    );
  }

  void ReleaseCommandIdIfUnconsumed(CCommandDb* commandDb, const CmdId cmdId)
  {
    if (!commandDb) {
      return;
    }

    if ((static_cast<std::uint32_t>(cmdId) & 0xFF000000u) == 0xFF000000u) {
      return;
    }

    using Fn = int(__stdcall*)(CCommandDb*, CmdId);
    auto fn = reinterpret_cast<Fn>(kReleaseCommandIdEa);
    (void)fn(commandDb, cmdId);
  }

  // 0x00748AA0 resolves unit blueprints from RResId via RRuleGameRules::GetUnitBlueprint.
  const RUnitBlueprint* ResolveUnitBlueprint(RRuleGameRules* rules, const RResId& blueprintId)
  {
    if (!rules) {
      return nullptr;
    }

    return rules->GetUnitBlueprint(blueprintId);
  }

  VTransform BuildUnitSpawnTransform(const SCoordsVec2& pos, const float heading)
  {
    const Wm3::Vec3f headingAxis{0.0f, 1.0f, 0.0f};
    const Wm3::Quatf orientation = Wm3::Quatf::FromAxisAngle(headingAxis, heading);
    const Wm3::Vec3f worldPosition{pos.x, 0.0f, pos.z};
    return VTransform(worldPosition, orientation);
  }

  /**
   * Address: 0x004A92A0 (FUN_004A92A0, func_StringSetFilename)
   *
   * What it does:
   * Lowercases a filename/id string and canonicalizes separators ('\\' -> '/').
   */
  void NormalizeFilenameLowerSlash(std::string& inOut)
  {
    for (std::size_t i = 0; i < inOut.size(); ++i) {
      const unsigned char ch = static_cast<unsigned char>(inOut[i]);
      inOut[i] = static_cast<char>(std::tolower(ch));
      if (inOut[i] == '\\') {
        inOut[i] = '/';
      }
    }
  }

  /**
   * Address: 0x006FB420 (FUN_006FB420)
   *
   * IDA signature:
   * Moho::Prop * __cdecl Moho::PROP_Create(Moho::Sim *, Moho::VTransform const &, char const *);
   *
   * What it does:
   * Normalizes the prop blueprint id and resolves `RPropBlueprint` from game rules.
   */
  RPropBlueprint* ResolvePropBlueprintById(RRuleGameRules* rules, const char* blueprintId)
  {
    if (!rules || !blueprintId || !*blueprintId) {
      return nullptr;
    }

    // Binary chain:
    // - 0x0051E2E0 func_StringInitFilename
    // - 0x004A92A0 func_StringSetFilename
    std::string normalizedBlueprintId = blueprintId;
    NormalizeFilenameLowerSlash(normalizedBlueprintId);

    const msvc8::string normalizedArg(normalizedBlueprintId.c_str());
    return rules->GetPropBlueprint(normalizedArg);
  }

  /**
   * Address: 0x006FB3B0 (FUN_006FB3B0)
   *
   * IDA signature:
   * Moho::Prop * __cdecl Moho::PROP_Create(Moho::Sim *, Moho::VTransform const &, Moho::RPropBlueprint const *);
   *
   * What it does:
   * Allocates `Prop` (0x288 bytes) and calls `Prop::Prop(sim, blueprint, trans)`.
   *
   * Recovery status:
   * Depends on `Entity::Entity` (0x00677C90) and `Prop::Prop` (0x006F9D90) source lift.
   */
  Prop* CreatePropFromBlueprintResolved(Sim* sim, const VTransform& transform, const RPropBlueprint* blueprint)
  {
    return Prop::CreateFromBlueprintResolved(sim, blueprint, transform);
  }

  /**
   * Address: 0x00748C00 (FUN_00748C00)
   *
   * What it does:
   * Builds an identity transform at world position and executes PROP_Create chain.
   */
  void SpawnPropByBlueprint(Sim* sim, RRuleGameRules* rules, const char* blueprintId, const Wm3::Vec3f& worldPos)
  {
    if (!sim || !blueprintId || !*blueprintId) {
      return;
    }

    PropCreateTransformWords words{};
    // VTransform quaternion lanes are stored as (w,x,y,z) in the first four floats.
    words.orientX = 1.0f; // identity scalar lane
    words.posX = worldPos.x;
    words.posY = worldPos.y;
    words.posZ = worldPos.z;

    VTransform spawnXform{};
    static_assert(
      sizeof(VTransform) == sizeof(PropCreateTransformWords), "VTransform size must be 0x1C for prop spawn path"
    );
    std::memcpy(&spawnXform, &words, sizeof(spawnXform));

    const RPropBlueprint* blueprint = ResolvePropBlueprintById(rules, blueprintId);
    (void)CreatePropFromBlueprintResolved(sim, spawnXform, blueprint);
  }

  // 0x00748D50 queues silo builds through CAiSiloBuildImpl (0=tactical, 1=nuke).
  bool QueueSiloBuildRequest(Unit* unit, const int modeIndex)
  {
    if (!unit || !unit->AiSiloBuild) {
      return false;
    }

    return unit->AiSiloBuild->TryEnqueue(static_cast<SiloType>(modeIndex));
  }

  // 0x00748CD0 applies orientation+position in one call via Entity::Warp.
  void ApplyWarpTransform(Entity* entity, const VTransform& transform)
  {
    if (!entity) {
      return;
    }

    entity->Warp(transform);
  }

  struct RUnitBlueprintIdView
  {
    msvc8::string id;
  };

  static_assert(
    sizeof(RUnitBlueprintIdView) == sizeof(msvc8::string), "RUnitBlueprintIdView layout must match msvc8::string"
  );

  const char* ResolveBlueprintIdCString(const Entity* entity)
  {
    if (!entity || !entity->BluePrint) {
      return "";
    }

    const auto* blueprint = reinterpret_cast<const RUnitBlueprintIdView*>(entity->BluePrint);
    return blueprint->id.raw_data_unsafe();
  }

  std::uint32_t FloatBits(const float value)
  {
    std::uint32_t bits = 0;
    std::memcpy(&bits, &value, sizeof(bits));
    return bits;
  }

  void ReadEntityVelocity(Entity* entity, Wm3::Vec3f* outVelocity)
  {
    if (!entity || !outVelocity) {
      return;
    }

    *outVelocity = entity->GetVelocity();
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

  gpg::RRef MakeSimOwnerRef(Sim* sim)
  {
    static gpg::RType* simType = nullptr;
    if (!simType) {
      simType = gpg::LookupRType(typeid(Sim));
    }

    gpg::RRef out{};
    out.mObj = sim;
    out.mType = simType;
    if (!sim) {
      return out;
    }

    gpg::RType* dynamicType = simType;
    try {
      dynamicType = gpg::LookupRType(typeid(*sim));
    } catch (...) {
      dynamicType = simType;
    }

    std::int32_t baseOffset = 0;
    if (dynamicType && simType && dynamicType->IsDerivedFrom(simType, &baseOffset)) {
      out.mObj =
        reinterpret_cast<void*>(reinterpret_cast<std::uintptr_t>(sim) - static_cast<std::uintptr_t>(baseOffset));
      out.mType = dynamicType;
    }
    return out;
  }

  void SaveObjectByRType(
    gpg::WriteArchive* archive,
    void* object,
    const std::initializer_list<const char*>& typeNames,
    const gpg::RRef& ownerRef
  )
  {
    gpg::RType* type = RequireRTypeByNameAny(typeNames);
    GPG_ASSERT(type != nullptr && type->serSaveFunc_ != nullptr);
    type->serSaveFunc_(archive, reinterpret_cast<int>(object), type->version_, const_cast<gpg::RRef*>(&ownerRef));
  }

  void LoadObjectByRType(
    gpg::ReadArchive* archive,
    void* object,
    const std::initializer_list<const char*>& typeNames,
    const gpg::RRef& ownerRef
  )
  {
    gpg::RType* type = RequireRTypeByNameAny(typeNames);
    GPG_ASSERT(type != nullptr && type->serLoadFunc_ != nullptr);
    type->serLoadFunc_(archive, reinterpret_cast<int>(object), type->version_, const_cast<gpg::RRef*>(&ownerRef));
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

  void SavePointerByRType(
    gpg::WriteArchive* archive,
    void* object,
    const std::initializer_list<const char*>& typeNames,
    const gpg::TrackedPointerState state,
    const gpg::RRef& ownerRef
  )
  {
    gpg::RRef objectRef{};
    objectRef.mObj = object;
    objectRef.mType = RequireRTypeByNameAny(typeNames);
    gpg::WriteRawPointer(archive, objectRef, state, ownerRef);
  }

  void* LoadPointerByRType(
    gpg::ReadArchive* archive, const std::initializer_list<const char*>& typeNames, const gpg::RRef& ownerRef
  )
  {
    const gpg::TrackedPointerInfo tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RType* expected = RequireRTypeByNameAny(typeNames);
    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;
    const gpg::RRef casted = gpg::REF_UpcastPtr(source, expected);
    GPG_ASSERT(casted.mObj != nullptr);
    return casted.mObj ? casted.mObj : tracked.object;
  }

  void SaveMapDataBestEffort(
    gpg::WriteArchive* archive, gpg::Rect2i* playableRect1, gpg::Rect2i* playableRect2, const gpg::RRef& ownerRef
  )
  {
    // 0x00745020 serializes map playable rectangles and cached tile rect list.
    // Current reconstruction keeps the two known Rect2 slots.
    SaveObjectByRType(archive, playableRect1, {"Rect2<int>", "gpg::Rect2<int>"}, ownerRef);
    SaveObjectByRType(archive, playableRect2, {"Rect2<int>", "gpg::Rect2<int>"}, ownerRef);
  }

  void LoadMapDataBestEffort(
    gpg::ReadArchive* archive, gpg::Rect2i* playableRect1, gpg::Rect2i* playableRect2, const gpg::RRef& ownerRef
  )
  {
    // 0x00745120 deserializes map playable rectangles and cached tile rect list.
    LoadObjectByRType(archive, playableRect1, {"Rect2<int>", "gpg::Rect2<int>"}, ownerRef);
    LoadObjectByRType(archive, playableRect2, {"Rect2<int>", "gpg::Rect2<int>"}, ownerRef);
  }

  void SaveTaskStages(
    gpg::WriteArchive* archive,
    CTaskStage* stageA,
    CTaskStage* diskWatcherStage,
    CTaskStage* stageB,
    const gpg::RRef& ownerRef
  )
  {
    SaveObjectByRType(archive, stageA, {"CTaskStage", "Moho::CTaskStage"}, ownerRef);
    SaveObjectByRType(archive, diskWatcherStage, {"CTaskStage", "Moho::CTaskStage"}, ownerRef);
    SaveObjectByRType(archive, stageB, {"CTaskStage", "Moho::CTaskStage"}, ownerRef);
  }

  void LoadTaskStages(
    gpg::ReadArchive* archive,
    CTaskStage* stageA,
    CTaskStage* diskWatcherStage,
    CTaskStage* stageB,
    const gpg::RRef& ownerRef
  )
  {
    LoadObjectByRType(archive, stageA, {"CTaskStage", "Moho::CTaskStage"}, ownerRef);
    LoadObjectByRType(archive, diskWatcherStage, {"CTaskStage", "Moho::CTaskStage"}, ownerRef);
    LoadObjectByRType(archive, stageB, {"CTaskStage", "Moho::CTaskStage"}, ownerRef);
  }

  struct SimGlobalDebugHooks
  {
    // 0x010A63A4: debug window singleton pointer.
    void** debugWindowSlot;
    // 0x004B5C70: debug Lua hook callback.
    lua_Hook debugLuaHook;
  };

  const SimGlobalDebugHooks& GetSimGlobalDebugHooks()
  {
    static const SimGlobalDebugHooks hooks{
      reinterpret_cast<void**>(0x010A63A4u),
      reinterpret_cast<lua_Hook>(0x004B5C70u),
    };
    return hooks;
  }

  bool IsSimDebugCheatsEnabled()
  {
    return moho::console::SimDebugCheatsEnabled();
  }

  bool IsSimReportCheatsEnabled()
  {
    return moho::console::SimReportCheatsEnabled();
  }

  int GetCallStackFrames(unsigned int* outFrames)
  {
    return moho::console::PlatformGetCallStack(outFrames, 0x10u);
  }

  void FormatCallStack(msvc8::string* outText, const int frameCount, const unsigned int* frames)
  {
    moho::console::PlatformFormatCallstack(outText, frameCount, frames);
  }

  CSimConVarBase* PathBackgroundUpdateConVar()
  {
    return moho::console::SimPathBackgroundUpdateConVar();
  }

  CSimConVarBase* PathBackgroundBudgetConVar()
  {
    return moho::console::SimPathBackgroundBudgetConVar();
  }

  CSimConVarBase* ChecksumPeriodConVar()
  {
    return moho::console::SimChecksumPeriodConVar();
  }

  bool IsDebugWindowEnabled()
  {
    const SimGlobalDebugHooks& hooks = GetSimGlobalDebugHooks();
    return hooks.debugWindowSlot && (*hooks.debugWindowSlot != nullptr);
  }

  lua_Hook GetDebugLuaHook()
  {
    return GetSimGlobalDebugHooks().debugLuaHook;
  }

  void RulesUpdateLuaState(RRuleGameRules* rules, LuaPlus::LuaState* luaState)
  {
    if (!rules) {
      return;
    }

    rules->UpdateLuaState(luaState);
  }

  void* GetSimVarStorage(CSimConVarInstanceBase* instance)
  {
    if (!instance) {
      return nullptr;
    }

    return instance->GetValueStorage();
  }

  bool ReadSimConVarBool(Sim* sim, CSimConVarBase* conVar, const bool defaultValue)
  {
    auto* instance = sim ? sim->GetSimVar(conVar) : nullptr;
    void* valuePtr = GetSimVarStorage(instance);
    if (!valuePtr) {
      return defaultValue;
    }
    return *reinterpret_cast<const uint8_t*>(valuePtr) != 0;
  }

  int ReadSimConVarInt(Sim* sim, CSimConVarBase* conVar, const int defaultValue)
  {
    auto* instance = sim ? sim->GetSimVar(conVar) : nullptr;
    void* valuePtr = GetSimVarStorage(instance);
    if (!valuePtr) {
      return defaultValue;
    }
    return *reinterpret_cast<const int*>(valuePtr);
  }

  void TickTaskStage(CTaskStage* stage)
  {
    if (!stage) {
      return;
    }

    stage->UserFrame();
  }

  void UpdatePaths(PathTables* pathTables, const int budget)
  {
    if (!pathTables) {
      return;
    }

    int pathBudget = budget;
    pathTables->UpdateBackground(&pathBudget);
  }

  template <typename Fn>
  void ForEachAllArmyUnit(CEntityDb* entityDb, Fn&& fn)
  {
    if (!entityDb) {
      return;
    }

    // 0x006B6AA0 / 0x005C87A0 iterate all army units in retail.
    // In source we walk the typed entity DB and keep only Unit owners.
    for (Entity* entity : entityDb->Entities()) {
      if (!entity) {
        continue;
      }

      Unit* unit = entity->IsUnit();
      if (!unit) {
        continue;
      }

      fn(unit);
    }
  }

  void TickEffectManager(CEffectManagerImpl* effectManager)
  {
    if (!effectManager) {
      return;
    }

    effectManager->Tick();
  }

  void PurgeDestroyedEffects(CEffectManagerImpl* effectManager)
  {
    if (!effectManager) {
      return;
    }

    effectManager->PurgeDestroyedEffects();
  }

  void UpdateFormationDb(CAiFormationDBImpl* formationDb)
  {
    if (!formationDb) {
      return;
    }

    formationDb->Update();
  }

  void AdvanceCoords(Entity* entity)
  {
    if (!entity) {
      return;
    }

    entity->AdvanceCoords();
  }

  void RunQueuedDestroy(void* queuedObject)
  {
    if (!queuedObject) {
      return;
    }

    Entity* entity = static_cast<Entity*>(queuedObject);
    entity->OnDestroy();
  }

  void CleanupDecals(CDecalBuffer* decalBuffer)
  {
    if (decalBuffer) {
      decalBuffer->CleanupTick();
    }
  }

  void TickDebugOverlay(RDebugOverlay* overlay, Sim* sim)
  {
    if (!overlay || !sim) {
      return;
    }
    overlay->Tick(sim);
  }
} // namespace

/**
 * Address: 0x00754C60 (FUN_00754C60, sub_754C60)
 *
 * What it does:
 * Core Sim load-serialization routine used by Sim serializer callback.
 */
void Sim::SerializeLoadBody(gpg::ReadArchive* archive)
{
  if (!archive) {
    return;
  }

  const gpg::RRef ownerRef = MakeSimOwnerRef(this);

  // 0x00754C60 order recovered from IDA/decomp.
  LoadMapDataBestEffort(archive, &mPlayableRect1, &mPlayableRect2, ownerRef);
  archive->ReadUInt(&mCurTick);

  mRngState =
    static_cast<CRandomStream*>(LoadPointerByRType(archive, {"CRandomStream", "Moho::CRandomStream"}, ownerRef));
  mPhysConstants =
    static_cast<SPhysConstants*>(LoadPointerByRType(archive, {"SPhysConstants", "Moho::SPhysConstants"}, ownerRef));
  mOGrid = static_cast<COGrid*>(LoadPointerByRType(archive, {"COGrid", "Moho::COGrid"}, ownerRef));
  mFormationDB =
    static_cast<CAiFormationDBImpl*>(LoadPointerByRType(archive, {"IAiFormationDB", "Moho::IAiFormationDB"}, ownerRef));
  mEntityDB =
    static_cast<CEntityDb*>(LoadPointerByRType(archive, {"EntityDB", "CEntityDB", "Moho::EntityDB"}, ownerRef));
  archive->ReadUInt(&mReserved98C);
  mDecalBuffer =
    static_cast<CDecalBuffer*>(LoadPointerByRType(archive, {"CDecalBuffer", "Moho::CDecalBuffer"}, ownerRef));
  mEffectManager =
    static_cast<CEffectManagerImpl*>(LoadPointerByRType(archive, {"IEffectManager", "Moho::IEffectManager"}, ownerRef));
  mSoundManager =
    static_cast<CSimSoundManager*>(LoadPointerByRType(archive, {"ISoundManager", "Moho::ISoundManager"}, ownerRef));

  LoadTaskStages(archive, &mTaskStageA, &mDiskWatcherTaskStage, &mTaskStageB, ownerRef);
  LoadObjectByRType(archive, &mShields, {"std::list<Moho::Shield *>", "list<Moho::Shield *>"}, ownerRef);

  bool bitFlag = false;
  archive->ReadBool(&bitFlag);
  mCheatsEnabled = bitFlag;
  archive->ReadBool(&bitFlag);
  mGameOver = bitFlag;

  mCommandDB =
    static_cast<CCommandDb*>(LoadPointerByRType(archive, {"CCommandDB", "CCommandDb", "Moho::CCommandDB"}, ownerRef));
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

  const gpg::RRef ownerRef = MakeSimOwnerRef(this);

  // 0x007551C0 order recovered from IDA/decomp.
  SaveMapDataBestEffort(archive, &mPlayableRect1, &mPlayableRect2, ownerRef);
  WriteArchiveUIntCompat(archive, mCurTick);

  SavePointerByRType(
    archive, mRngState, {"CRandomStream", "Moho::CRandomStream"}, gpg::TrackedPointerState::Owned, ownerRef
  );
  SavePointerByRType(
    archive, mPhysConstants, {"SPhysConstants", "Moho::SPhysConstants"}, gpg::TrackedPointerState::Owned, ownerRef
  );
  SavePointerByRType(archive, mOGrid, {"COGrid", "Moho::COGrid"}, gpg::TrackedPointerState::Owned, ownerRef);
  SavePointerByRType(
    archive, mFormationDB, {"IAiFormationDB", "Moho::IAiFormationDB"}, gpg::TrackedPointerState::Owned, ownerRef
  );
  SavePointerByRType(
    archive, mEntityDB, {"EntityDB", "CEntityDB", "Moho::EntityDB"}, gpg::TrackedPointerState::Owned, ownerRef
  );
  WriteArchiveUIntCompat(archive, mReserved98C);
  SavePointerByRType(
    archive, mDecalBuffer, {"CDecalBuffer", "Moho::CDecalBuffer"}, gpg::TrackedPointerState::Owned, ownerRef
  );
  SavePointerByRType(
    archive, mEffectManager, {"IEffectManager", "Moho::IEffectManager"}, gpg::TrackedPointerState::Owned, ownerRef
  );
  SavePointerByRType(
    archive, mSoundManager, {"ISoundManager", "Moho::ISoundManager"}, gpg::TrackedPointerState::Owned, ownerRef
  );

  SaveTaskStages(archive, &mTaskStageA, &mDiskWatcherTaskStage, &mTaskStageB, ownerRef);
  SaveObjectByRType(archive, &mShields, {"std::list<Moho::Shield *>", "list<Moho::Shield *>"}, ownerRef);

  archive->WriteBool(mCheatsEnabled);
  archive->WriteBool(mGameOver);
  SavePointerByRType(
    archive, mCommandDB, {"CCommandDB", "CCommandDb", "Moho::CCommandDB"}, gpg::TrackedPointerState::Owned, ownerRef
  );
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
void moho::SimSerializerLoadThunk(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef*)
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
void moho::SimSerializerSaveThunk(gpg::WriteArchive* archive, int objectPtr, int, gpg::RRef*)
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

/**
 * Address: 0x007474B0 (FUN_007474B0)
 *
 * What it does:
 * Produces one sync packet from current Sim state and requested filter values.
 *
 * Recovery status:
 * Partial lift. Keeps filter-transfer behavior and minimal beat packet publication
 * so CSimDriver queue/event flow stays consistent while full body recovery is pending.
 */
void Sim::Sync(const SSyncFilter& filter, SSyncData*& outSyncData)
{
  CopySyncFilter(mSyncFilter, filter);

  delete outSyncData;
  outSyncData = new SSyncData{};
  outSyncData->mCurBeat = static_cast<int32_t>(mCurBeat);

  // +0x08FC latch: cleared by Sync after one beat is fully published.
  mDidProcess = false;
}

/**
 * Address: 0x005C3710 (FUN_005C3710, sub_5C3710)
 *
 * What it does:
 * Refreshes command/visibility blips for the active sim frame.
 */
void Sim::RefreshBlips()
{
  if (!mCommandDB || !mCommandDB->commands.header_ptr()) {
    return;
  }

  for (auto it = mCommandDB->commands.begin(); it != mCommandDB->commands.end(); ++it) {
    it->second.RefreshBlipState();
  }
}

/**
 * Address: 0x0074A640 (FUN_0074A640, sub_74A640)
 *
 * What it does:
 * Rebuilds the per-beat simulation checksum digest.
 */
void Sim::UpdateChecksum()
{
  auto logChecksumDigest = [this]() {
    if (!mLog) {
      return;
    }

    const msvc8::string digestText = mContext.Digest().ToString();
    Logf("      %s\n", digestText.c_str());
  };

  const bool shouldUpdateReconChecksum = (mCurBeat % 100u) == 0u;

  Logf("Armies\n");
  for (auto it = mArmiesList.begin(); it != mArmiesList.end(); ++it) {
    CArmyImpl* const army = *it;
    Logf("  \"%s\" [%s]\n", army->ArmyName.raw_data_unsafe(), army->ArmyTypeText.raw_data_unsafe());

    const SEconTotals& economy = army->GetEconomy()->economy;
    mContext.Update(&economy, sizeof(economy));
    if (mLog) {
      Logf("    mStored=%.1f,%.1f\n", economy.mStored.ENERGY, economy.mStored.MASS);
      Logf("    mIncome=%.1f,%.1f\n", economy.mIncome.ENERGY, economy.mIncome.MASS);
      Logf("    mReclaimed=%.1f,%.1f\n", economy.mReclaimed.ENERGY, economy.mReclaimed.MASS);
      Logf("    mLastUseRequested=%.1f,%.1f\n", economy.mLastUseRequested.ENERGY, economy.mLastUseRequested.MASS);
      Logf("    mLastUseActual=%.1f,%.1f\n", economy.mLastUseActual.ENERGY, economy.mLastUseActual.MASS);
      const std::uint64_t energyStorageBits = economy.mMaxStorage.ENERGY;
      Logf(
        "    mMaxStorage.ENERGY=%I64\n",
        static_cast<std::uint32_t>(energyStorageBits & 0xFFFFFFFFu),
        static_cast<std::uint32_t>(energyStorageBits >> 32)
      );
      const std::uint64_t massStorageBits = economy.mMaxStorage.MASS;
      Logf(
        "    mMaxStorage.MASS=%I64\n",
        static_cast<std::uint32_t>(massStorageBits & 0xFFFFFFFFu),
        static_cast<std::uint32_t>(massStorageBits >> 32)
      );
      logChecksumDigest();
    }

    if (shouldUpdateReconChecksum) {
      Logf("    CAiReconDBImpl::UpdateSimChecksum()\n");
      army->GetReconDB()->UpdateSimChecksum();
    }

    logChecksumDigest();
  }

  Logf("Dirty Entities\n");
  for (Entity* entity : mCoordEntities.owners_member<Entity, &Entity::mCoordNode>()) {
    const std::uint32_t entityId = static_cast<std::uint32_t>(entity->id_);
    mContext.Update(&entityId, sizeof(entityId));
    if (mLog) {
      Logf("  0x%08x\n", entityId);
      logChecksumDigest();
    }

    const float health = entity->Health;
    mContext.Update(&health, sizeof(health));
    if (mLog) {
      Logf("    health: %.1f 0x%08x\n", health, FloatBits(health));
      logChecksumDigest();
    }

    const char* blueprintId = ResolveBlueprintIdCString(entity);
    if (blueprintId) {
      mContext.Update(blueprintId, std::strlen(blueprintId) + 1u);
    } else {
      mContext.Update("<NULL>", 6u);
    }
    if (mLog) {
      Logf("    bp:%s\n", blueprintId ? blueprintId : "");
      logChecksumDigest();
    }

    mContext.Update(&entity->Orientation, 0x1Cu);
    if (mLog) {
      const float* const pos = reinterpret_cast<const float*>(&entity->Position);
      const float* const rot = reinterpret_cast<const float*>(&entity->Orientation);
      Logf(
        "    pos: <%7.2f,%7.2f,%7.2f> [0x%08x 0x%08x 0x%08x]\n",
        pos[0],
        pos[1],
        pos[2],
        FloatBits(pos[0]),
        FloatBits(pos[1]),
        FloatBits(pos[2])
      );
      Logf(
        "    rot: <%7.4f,%7.4f,%7.4f,%7.4f> [0x%08x 0x%08x 0x%08x 0x%08x]\n",
        rot[0],
        rot[1],
        rot[2],
        rot[3],
        FloatBits(rot[0]),
        FloatBits(rot[1]),
        FloatBits(rot[2]),
        FloatBits(rot[3])
      );
      logChecksumDigest();
    }

    Wm3::Vec3f velocity{};
    ReadEntityVelocity(entity, &velocity);
    mContext.Update(&velocity, sizeof(velocity));
    if (mLog) {
      Logf(
        "   vel: <%7.2f,%7.2f,%7.2f> [0x%08x 0x%08x 0x%08x]\n",
        velocity.x,
        velocity.y,
        velocity.z,
        FloatBits(velocity.x),
        FloatBits(velocity.y),
        FloatBits(velocity.z)
      );
      logChecksumDigest();
    }
  }

  constexpr std::size_t kRngMtBytes = sizeof(CMersenneTwister::StateWords);
  static_assert(kRngMtBytes == 0x9C0u, "Mt19937 payload must remain 0x9C0 bytes");
  mContext.Update(&mRngState->twister.state[0], static_cast<unsigned int>(kRngMtBytes));
  mContext.Update(&mRngState->hasMarsagliaPair, 1u);
  if (mRngState->hasMarsagliaPair) {
    mContext.Update(&mRngState->marsagliaPair, 4u);
  }
}

// 0x00746280
std::FILE* Sim::Logf(const char* fmt, ...)
{
  va_list args;
  va_start(args, fmt);

  if (mLog) {
    vfprintf(mLog, fmt, args);
  }

  va_end(args);
  return mLog;
}

// 0x007466F0
const char* Sim::GetCurrentCommandSourceName() const
{
  if (mCurCommandSource == kInvalidCommandSource ||
      static_cast<std::size_t>(mCurCommandSource) >= mCommandSources.size()) {
    return "???";
  }

  return mCommandSources[mCurCommandSource].mName.c_str();
}

LuaPlus::LuaState* Sim::GetLuaState() const noexcept
{
  return mLuaState;
}

// 0x00747180
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
    struct CallStackScratch
    {
      unsigned int a3[2];
      unsigned int a4[15];
    };

    CallStackScratch scratch{};
    msvc8::string callstackText{};

    const int frameCount = GetCallStackFrames(scratch.a3);
    FormatCallStack(&callstackText, frameCount, scratch.a4);
    Logf("%s", callstackText.raw_data_unsafe());

    if (callstackText.myRes >= 0x10 && callstackText.bx.ptr) {
      ::operator delete(callstackText.bx.ptr);
    }
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

// 0x00747320
bool Sim::OkayToMessWith(SimArmy* army)
{
  auto* armyImpl = static_cast<CArmyImpl*>(army);
  if (!armyImpl) {
    return CheatsEnabled();
  }

  if (armyImpl->IsOutOfGame) {
    return false;
  }

  const uint32_t sourceId = static_cast<uint32_t>(mCurCommandSource);
  if (sourceId != kInvalidCommandSource && armyImpl->MohoSetValidCommandSources.Contains(sourceId)) {
    return true;
  }

  return CheatsEnabled();
}

// 0x00747360
bool Sim::OkayToMessWith(Entity* entity)
{
  return OkayToMessWith(entity ? static_cast<SimArmy*>(entity->ArmyRef) : nullptr);
}

// 0x007473B0
bool Sim::OkayToMessWith(CUnitCommand* cmd)
{
  if (!cmd) {
    return false;
  }

  CScriptObject** unitSetIt = cmd->mUnitSet.mVec.begin();
  CScriptObject** unitSetEnd = cmd->mUnitSet.mVec.end();
  if (unitSetIt == unitSetEnd) {
    return true;
  }

  while (unitSetIt != unitSetEnd) {
    CScriptObject* scriptObject = *unitSetIt;
    if (!SCommandUnitSet::IsUsableEntry(scriptObject)) {
      if (!CheatsEnabled()) {
        return false;
      }
      ++unitSetIt;
      continue;
    }

    Entity* entity = static_cast<Entity*>(scriptObject);
    if (!OkayToMessWith(entity)) {
      return false;
    }

    ++unitSetIt;
  }

  return true;
}

// 0x00748650
void Sim::SetCommandSource(const CommandSourceId sourceId)
{
  if (sourceId == kInvalidCommandSource || sourceId < static_cast<CommandSourceId>(mCommandSources.size())) {
    mCurCommandSource = static_cast<int32_t>(sourceId);
    return;
  }

  gpg::Warnf("Sim::SetCommandSource(%d): invalid source -- ignoring following commands.", sourceId);
  mCurCommandSource = static_cast<int32_t>(kInvalidCommandSource);
}

// 0x007486B0
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

    if (!army->MohoSetValidCommandSources.Contains(static_cast<uint32_t>(mCurCommandSource))) {
      continue;
    }

    army->OnCommandSourceTerminated(static_cast<uint32_t>(mCurCommandSource));
  }
}

// 0x007487C0
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
  if (std::memcmp(expected, &checksum, sizeof(gpg::MD5Digest)) == 0) {
    return;
  }

  SDesyncInfo desync{};
  desync.hash1 = *expected;
  desync.hash2 = checksum;
  desync.beat = beat;
  desync.army = mCurCommandSource;
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
}

// 0x00748960
void Sim::RequestPause()
{
  if (mPausedByCommandSource != -1) {
    return;
  }

  if (mCurCommandSource == kInvalidCommandSource ||
      static_cast<std::size_t>(mCurCommandSource) >= mCommandSources.size()) {
    return;
  }

  int& timeouts = mCommandSources[mCurCommandSource].mTimeouts;
  if (timeouts <= 0) {
    return;
  }

  --timeouts;
  mPausedByCommandSource = mCurCommandSource;
}

// 0x007489A0
void Sim::Resume()
{
  if (mCurCommandSource != kInvalidCommandSource) {
    mPausedByCommandSource = -1;
  }
}

// 0x007489C0
void Sim::SingleStep()
{
  if (mPausedByCommandSource != -1 && mCurCommandSource != kInvalidCommandSource) {
    mSingleStep = true;
  }
}

// 0x007491C0
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
      "%s: ignoring issue of cmd id 0x%08x from %s because the id's source (%u) is wrong (should be %u).",
      callsite,
      cmdId,
      GetCurrentCommandSourceName(),
      sourceByte,
      currentSource
    );
    return false;
  }

  if (mCommandDB && mCommandDB->commands.header_ptr()) {
    const auto it = mCommandDB->commands.find(cmdId);
    if (it != mCommandDB->commands.end()) {
      gpg::Warnf(
        "%s: ignoring issue of cmd id 0x%08x from %s because it is already in use.",
        callsite,
        cmdId,
        GetCurrentCommandSourceName()
      );
      return false;
    }
  }

  return true;
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
          reinterpret_cast<CScriptObject*>(brain)->CallbackStr("OnUnitCapLimitReached");
        }
      }
      return nullptr;
    }
  }

  // The constructor body at 0x006A53F0 is still pending reconstruction.
  // Keep the cap-gate behavior exact, but avoid a partial/incorrect Unit object.
  Logf(
    "CreateUnit(params: bp=%s, army=%d): Unit constructor path (0x006A53F0) pending lift.\n",
    params.mBlueprint->mBlueprintId.raw_data_unsafe(),
    params.mArmy->ArmyId
  );
  return nullptr;
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
  if (!army || army->IsOutOfGame) {
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

  SUnitConstructionParams params{};
  params.mArmy = army;
  params.mBlueprint = blueprint;
  params.mTransform = BuildUnitSpawnTransform(pos, heading);
  params.mUseLayerOverride = 0;
  params.mFixElevation = 0;
  params.mLayer = 0;
  params.mLinkSourceUnit = nullptr;
  params.mComplete = 1;

  (void)CreateUnit(params, true);
}

/**
 * Address: 0x00748C00 (FUN_00748C00)
 *
 * What it does:
 * Cheat-gated prop creation entry point for sim commands.
 */
void Sim::CreateProp(const char* blueprint, const Wm3::Vec3f& loc)
{
  if (!CheatsEnabled()) {
    return;
  }

  SpawnPropByBlueprint(this, mRules, blueprint, loc);
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

// 0x00748CD0
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

// 0x00748D50
void Sim::ProcessInfoPair(void* id, const char* key, const char* val)
{
  const EntId entityId = static_cast<EntId>(reinterpret_cast<std::uintptr_t>(id));
  Entity* entity = FindEntityById(mEntityDB, entityId);
  if (!entity || !OkayToMessWith(entity)) {
    return;
  }

  Unit* unit = entity->IsUnit();
  if (!unit || unit->IsDead()) {
    return;
  }

  bool boolValue = false;

  if (EqualsIgnoreCase(key, "SetAutoMode")) {
    if (ParseBoolLiteral(val, boolValue)) {
      unit->SetAutoMode(boolValue);
    }
    return;
  }

  if (EqualsIgnoreCase(key, "SetAutoSurfaceMode")) {
    if (ParseBoolLiteral(val, boolValue)) {
      unit->SetAutoSurfaceMode(boolValue);
    }
    return;
  }

  if (EqualsIgnoreCase(key, "CustomName")) {
    unit->SetCustomName(std::string(val ? val : ""));
    return;
  }

  if (EqualsIgnoreCase(key, "SiloBuildTactical")) {
    if (EqualsIgnoreCase(val, "add")) {
      QueueSiloBuildRequest(unit, 0);
    }
    return;
  }

  if (EqualsIgnoreCase(key, "SiloBuildNuke")) {
    if (EqualsIgnoreCase(val, "add")) {
      QueueSiloBuildRequest(unit, 1);
    }
    return;
  }

  if (EqualsIgnoreCase(key, "SetRepeatQueue")) {
    if (ParseBoolLiteral(val, boolValue)) {
      unit->SetRepeatQueue(boolValue);
    }
    return;
  }

  if (EqualsIgnoreCase(key, "SetPaused")) {
    if (ParseBoolLiteral(val, boolValue)) {
      unit->SetPaused(boolValue);
    }
    return;
  }

  if (EqualsIgnoreCase(key, "SetFireState")) {
    int fireState = 0;
    if (ParseIntLiteral(val, fireState) && fireState >= 0 && fireState <= 2) {
      unit->SetFireState(fireState);
    }
    return;
  }

  if (EqualsIgnoreCase(key, "ToggleScriptBit")) {
    int bitIndex = 0;
    if (ParseIntLiteral(val, bitIndex)) {
      unit->ToggleScriptBit(bitIndex);
    }
    return;
  }

  if (EqualsIgnoreCase(key, "PlayNoStagingPlatformsVO")) {
    static_cast<CScriptObject*>(unit)->CallbackStr("OnPlayNoStagingPlatformsVO");
    return;
  }

  if (EqualsIgnoreCase(key, "PlayBusyStagingPlatformsVO")) {
    static_cast<CScriptObject*>(unit)->CallbackStr("OnPlayBusyStagingPlatformsVO");
    return;
  }

  Logf(
    "ProcessInfoPair(entity=%d, key=%s, val=%s): key path not yet lifted.\n",
    entityId,
    key ? key : "<null>",
    val ? val : "<null>"
  );
}

/**
 * Address: 0x00749290 (FUN_00749290)
 *
 * What it does:
 * Validates command-id ownership, collects selected units, and (for now) keeps
 * id lifecycle consistent while full dispatch recovery remains in progress.
 */
void Sim::IssueCommand(
  const BVSet<EntId, EntIdUniverse>& entities, const SSTICommandIssueData& commandIssueData, const bool clearQueue
)
{
  if (!ValidateNewCommandId(commandIssueData.nextCommandId, "IssueCommand")) {
    return;
  }

  std::vector<Unit*> selectedUnits;
  selectedUnits.reserve(entities.Bits().Count());

  auto collectUnit = [this, &selectedUnits](const EntId entId) {
    Entity* entity = FindEntityById(mEntityDB, entId);
    if (!entity || !OkayToMessWith(entity)) {
      return;
    }

    Unit* unit = entity->IsUnit();
    if (!unit) {
      return;
    }

    if (std::find(selectedUnits.begin(), selectedUnits.end(), unit) == selectedUnits.end()) {
      selectedUnits.push_back(unit);
    }
  };

  entities.ForEachValue([&collectUnit](const unsigned int value) {
    collectUnit(static_cast<EntId>(value));
  });

  if (selectedUnits.empty()) {
    ReleaseCommandIdIfUnconsumed(mCommandDB, commandIssueData.nextCommandId);
    return;
  }

  // 0x00749290 gates command type 31 behind CheatsEnabled().
  const int commandType = static_cast<int>(commandIssueData.mCommandType);
  if (commandType == 31 && !CheatsEnabled()) {
    ReleaseCommandIdIfUnconsumed(mCommandDB, commandIssueData.nextCommandId);
    return;
  }

  // Full UNIT_IssueCommand dispatch (0x006F12C0) still depends on local
  // helper containers built by 0x0057DDD0 / 0x005796A0.
  Logf(
    "IssueCommand(cmd=0x%08x, units=%zu, clear=%d, type=%d): dispatch path pending lift.\n",
    commandIssueData.nextCommandId,
    selectedUnits.size(),
    clearQueue ? 1 : 0,
    commandType
  );
  ReleaseCommandIdIfUnconsumed(mCommandDB, commandIssueData.nextCommandId);
}

/**
 * Address: 0x007494B0 (FUN_007494B0)
 *
 * What it does:
 * Validates command-id ownership, collects selected factory units, and preserves
 * command-id recycling while factory dispatch lift is still pending.
 */
void Sim::IssueFactoryCommand(
  const BVSet<EntId, EntIdUniverse>& entities, const SSTICommandIssueData& commandIssueData, const bool clearQueue
)
{
  if (!ValidateNewCommandId(commandIssueData.nextCommandId, "IssueFactoryCommand")) {
    return;
  }

  std::vector<Unit*> selectedFactories;
  selectedFactories.reserve(entities.Bits().Count());

  auto collectFactory = [this, &selectedFactories](const EntId entId) {
    Entity* entity = FindEntityById(mEntityDB, entId);
    if (!entity || !OkayToMessWith(entity)) {
      return;
    }

    Unit* unit = entity->IsUnit();
    if (!unit) {
      return;
    }

    if (std::find(selectedFactories.begin(), selectedFactories.end(), unit) == selectedFactories.end()) {
      selectedFactories.push_back(unit);
    }
  };

  entities.ForEachValue([&collectFactory](const unsigned int value) {
    collectFactory(static_cast<EntId>(value));
  });

  if (selectedFactories.empty()) {
    ReleaseCommandIdIfUnconsumed(mCommandDB, commandIssueData.nextCommandId);
    return;
  }

  // Full dispatch path calls 0x006F14D0 after helper-list setup.
  Logf(
    "IssueFactoryCommand(cmd=0x%08x, factories=%zu, clear=%d): dispatch path pending lift.\n",
    commandIssueData.nextCommandId,
    selectedFactories.size(),
    clearQueue ? 1 : 0
  );
  ReleaseCommandIdIfUnconsumed(mCommandDB, commandIssueData.nextCommandId);
}

// 0x00749680
void Sim::IncreaseCommandCount(const CmdId cmdId, const int count)
{
  CUnitCommand* command = FindCommandById(mCommandDB, cmdId);
  if (command && OkayToMessWith(command)) {
    command->IncreaseCount(count);
  }
}

// 0x007496E0
void Sim::DecreaseCommandCount(const CmdId cmdId, const int count)
{
  CUnitCommand* command = FindCommandById(mCommandDB, cmdId);
  if (command && OkayToMessWith(command)) {
    command->DecreaseCount(count);
  }
}

// 0x00749740
void Sim::SetCommandTarget(const CmdId cmdId, const SSTITarget& target)
{
  CUnitCommand* command = FindCommandById(mCommandDB, cmdId);
  if (!command || !OkayToMessWith(command)) {
    return;
  }

  command->mVarDat.mTarget1 = target;

  CAiTarget aiTarget{};
  aiTarget.targetType = target.mType;
  aiTarget.position = target.mPos;
  aiTarget.targetPoint = -1;
  aiTarget.targetIsMobile = false;
  command->SetTarget(aiTarget);
}

// 0x00749800
void Sim::SetCommandType(const CmdId cmdId, const EUnitCommandType commandType)
{
  CUnitCommand* command = FindCommandById(mCommandDB, cmdId);
  if (!command || !OkayToMessWith(command)) {
    return;
  }

  command->mVarDat.mCmdType = commandType;
  command->mNeedsUpdate = true;
}

// 0x00749860
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
  std::memcpy(&aiTarget.position, &targetPosition, sizeof(aiTarget.position));
  aiTarget.targetPoint = -1;
  aiTarget.targetIsMobile = false;
  command->SetTarget(aiTarget);
}

// 0x00749970
void Sim::RemoveCommandFromUnitQueue(const CmdId cmdId, const EntId unitId)
{
  CUnitCommand* command = FindCommandById(mCommandDB, cmdId);
  if (!command || !OkayToMessWith(command)) {
    return;
  }

  Entity* matchedEntity = nullptr;
  for (CScriptObject** it = command->mUnitSet.mVec.begin(); it != command->mUnitSet.mVec.end(); ++it) {
    CScriptObject* scriptObject = *it;
    if (!SCommandUnitSet::IsUsableEntry(scriptObject)) {
      continue;
    }

    Entity* entity = static_cast<Entity*>(scriptObject);
    if (entity->id_ == unitId) {
      matchedEntity = entity;
      break;
    }
  }

  if (!matchedEntity || !OkayToMessWith(matchedEntity)) {
    return;
  }

  Unit* unit = matchedEntity->IsUnit();
  if (!unit || unit->IsDead()) {
    return;
  }

  CUnitCommandQueue* commandQueue = unit->CommandQueue;
  if (commandQueue && commandQueue->FindCommandIndex(command->mConstDat.cmd) != -1) {
    commandQueue->RemoveCommandFromQueue(command);
    return;
  }

  CAiTransportCommandOps* transport = unit->AiTransport;
  if (!transport) {
    return;
  }

  if (transport->TransportAssignSlot(command)) {
    transport->TransportDetachUnit(command);
  }
}

// 0x00749A70
void Sim::ExecuteLuaInSim(const char* functionName, const LuaPlus::LuaObject& args)
{
  if (!CheatsEnabled() || !functionName || !mLuaState || !mLuaState->m_state) {
    return;
  }

  lua_State* state = mLuaState->m_state;
  const int oldTop = lua_gettop(state);

  lua_getglobal(state, functionName);
  if (!lua_isfunction(state, -1)) {
    lua_settop(state, oldTop);
    return;
  }

  try {
    LuaPlus::LuaPush(state, args);
  } catch (const std::exception&) {
    lua_pushnil(state);
  }

  if (lua_pcall(state, 1, 0, 0) != 0) {
    const char* err = lua_tostring(state, -1);
    gpg::Warnf("Sim::ExecuteLuaInSim('%s') failed: %s", functionName, err ? err : "<unknown>");
  }

  lua_settop(state, oldTop);
}

// 0x00749B60
void Sim::LuaSimCallback(
  const char* callbackName, const LuaPlus::LuaObject& args, const BVSet<EntId, EntIdUniverse>& entities
)
{
  if (!callbackName || !mLuaState || !mLuaState->m_state) {
    return;
  }

  lua_State* state = mLuaState->m_state;
  const int oldTop = lua_gettop(state);

  lua_getglobal(state, "DoCallback");
  if (!lua_isfunction(state, -1)) {
    lua_settop(state, oldTop);
    return;
  }

  lua_pushstring(state, callbackName);

  try {
    LuaPlus::LuaPush(state, args);
  } catch (const std::exception&) {
    lua_pushnil(state);
  }

  lua_newtable(state);
  int luaIndex = 1;

  auto appendUnitLuaObject = [this, state, &luaIndex](const EntId entId) {
    Entity* entity = FindEntityById(mEntityDB, entId);
    if (!entity) {
      return;
    }

    Unit* unit = entity->IsUnit();
    if (!unit) {
      return;
    }

    LuaPlus::LuaObject unitObject = unit->GetLuaObject();
    lua_pushnumber(state, static_cast<lua_Number>(luaIndex++));
    LuaPlus::LuaPush(state, unitObject);
    lua_settable(state, -3);
  };

  entities.ForEachValue([&appendUnitLuaObject](const unsigned int value) {
    appendUnitLuaObject(static_cast<EntId>(value));
  });

  if (lua_pcall(state, 3, 0, 0) != 0) {
    const char* err = lua_tostring(state, -1);
    gpg::Warnf("Sim::LuaSimCallback('%s') failed: %s", callbackName, err ? err : "<unknown>");
  }

  lua_settop(state, oldTop);
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
  SimDebugEntitySet selectedUnits{};
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

    AppendUniqueEntity(selectedUnits, static_cast<Entity*>(unit));
  };

  entities.ForEachValue([&appendSelectedUnit](const unsigned int value) {
    appendSelectedUnit(static_cast<EntId>(value));
  });

  CArmyImpl* focusArmyPtr = nullptr;
  if (focusArmy < mArmiesList.size()) {
    focusArmyPtr = mArmiesList[focusArmy];
  }

  // Parser body 0x00734870 is now wired; command table recovery remains in progress.
  TryParseSimCommand(this, command, worldPos, focusArmyPtr, selectedUnits);
  DestroySimDebugEntitySet(selectedUnits);
}

// 0x00749F40
void Sim::AdvanceBeat(const int amt)
{
  (void)amt; // Binary implementation does not consume this parameter at 0x00749F40.

  Logf("********** beat %u **********\n", mCurBeat);
  RulesUpdateLuaState(mRules, mLuaState);

  if (IsDebugWindowEnabled() && mLuaState && mLuaState->m_state) {
    lua_sethook(mLuaState->m_state, GetDebugLuaHook(), 4, 0);
  }

  if (!mGameOver && (mPausedByCommandSource == -1 || mSingleStep)) {
    ++mCurTick;
    Logf("  tick number %u\n", mCurTick);

    if (ReadSimConVarBool(this, PathBackgroundUpdateConVar(), false)) {
      const int pathBudget = ReadSimConVarInt(this, PathBackgroundBudgetConVar(), 0);
      UpdatePaths(mPathTables, pathBudget);
    }

    ForEachAllArmyUnit(mEntityDB, [](Unit* unit) {
      if (!unit || unit->IsDead()) {
        return;
      }

      unit->ClearBeatResourceAccumulators();
    });

    for (CArmyImpl* army : mArmiesList) {
      if (army) {
        army->OnTick();
      }
    }

    TickTaskStage(&mTaskStageA);
    TickTaskStage(&mDiskWatcherTaskStage);
    TickTaskStage(&mTaskStageB);
    RefreshBlips();

    if (!mArmiesList.empty()) {
      const std::size_t armyCount = mArmiesList.size();
      const std::size_t reconTickIndex = static_cast<std::size_t>(mCurTick) % armyCount;
      for (std::size_t i = 0; i < armyCount; ++i) {
        CArmyImpl* army = mArmiesList[i];
        if (!army) {
          continue;
        }

        CAiReconDBImpl* reconDb = army->GetReconDB();
        if (!reconDb) {
          continue;
        }

        if (i == reconTickIndex) {
          reconDb->ReconTick(static_cast<int>(armyCount));
        } else {
          reconDb->ReconRefresh();
        }
      }
    }

    TickEffectManager(mEffectManager);
    UpdateFormationDb(mFormationDB);

    ForEachAllArmyUnit(mEntityDB, [](Unit* unit) {
      if (unit->NeedsKillCleanup()) {
        unit->KillCleanup();
      }
    });

    // Binary 0x00749F40 still has an additional sync-filter packing pass here
    // (EntityDB lookup + serialization vector push helpers).
    for (auto* entity : mCoordEntities.owners_member<Entity, &Entity::mCoordNode>()) {
      AdvanceCoords(entity);
    }

    mDebugCanvas2 = mDebugCanvas1;
    mDebugCanvas1.reset();

    mAdvancedThisTick = true;
    mSingleStep = false;
  }

  while (!mDeletionQueue.empty()) {
    void* queuedObject = mDeletionQueue.front();
    mDeletionQueue.pop_front();
    RunQueuedDestroy(queuedObject);
  }

  PurgeDestroyedEffects(mEffectManager);
  CleanupDecals(mDecalBuffer);

  const int checksumPeriod = ReadSimConVarInt(this, ChecksumPeriodConVar(), 1);
  if (checksumPeriod > 0 && (mCurBeat % static_cast<uint32_t>(checksumPeriod)) == 0u) {
    UpdateChecksum();
  }

  for (auto* node = mDebugOverlays.mPrev; node != &mDebugOverlays; node = node->mPrev) {
    auto* overlay = static_cast<RDebugOverlay*>(node);
    TickDebugOverlay(overlay, this);
  }

  if (mLuaState && mLuaState->m_state && (mCurTick % 70u) == 0u) {
    lua_setgcthreshold(mLuaState->m_state, 0);
  }

  // +0x08FC latch: set here in AdvanceBeat, cleared in Sim::Sync.
  mDidProcess = true;
}

// 0x0074B100
void Sim::EndGame()
{
  mGameEnded = true;
}

/**
 * Address: 0x0074CFB0 (FUN_0074CFB0, sub_74CFB0)
 */
void SimSerializer::RegisterSerializeFunctions()
{
  // 0x0074CF80 / 0x00744F90 initialize these callback slots in static init.
  if (mSerLoadFunc == nullptr) {
    mSerLoadFunc = &SimSerializerLoadThunk;
  }
  if (mSerSaveFunc == nullptr) {
    mSerSaveFunc = &SimSerializerSaveThunk;
  }

  gpg::RType* type = gpg::LookupRType(typeid(Sim));
  GPG_ASSERT(type->serLoadFunc_ == nullptr);
  type->serLoadFunc_ = mSerLoadFunc;
  GPG_ASSERT(type->serSaveFunc_ == nullptr);
  type->serSaveFunc_ = mSerSaveFunc;
}

/**
 * Address: 0x007432C0 (FUN_007432C0, sub_7432C0)
 */
SimTypeInfo::~SimTypeInfo() = default;

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
