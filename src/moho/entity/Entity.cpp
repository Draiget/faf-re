#include "moho/lua/ScrLuaUserData.h"
#include "moho/entity/EntityPrivate.h"

namespace moho
{
  /// Engine addition: see CScriptModuleExistenceCache below. Same answers either way.
  bool sim_CacheScriptModuleLookups = true;

  TConVar<bool> gTConVar_sim_CacheScriptModuleLookups(
    "sim_CacheScriptModuleLookups",
    "Remember which blueprint script modules exist instead of asking the file system for every new entity.",
    &sim_CacheScriptModuleLookups
  );
}

namespace
{
  constexpr std::uint32_t kEntityAttributeRangeMask = 0x7FFFFFFFu;
  constexpr std::uint32_t kEntityAttributeEnabledMask = 0x80000000u;

  [[nodiscard]] constexpr std::uint32_t EncodeIntelRangeLane(const std::uint32_t range) noexcept
  {
    return (range != 0u) ? (range | kEntityAttributeEnabledMask) : 0u;
  }

  /**
   * Address: 0x0067B6F0 (FUN_0067B6F0)
   *
   * What it does:
   * Appends one create-entity payload to the sync queue, growing the backing
   * vector as needed and returning a pointer to the stored record. The binary
   * takes the vector itself in `eax` and strides by 12 (`imul 2AAAAAABh`, the
   * divide-by-`sizeof(SCreateEntityParams)` reciprocal); the member it is
   * handed comes from the caller, which is `Entity::CreateInterface`
   * (0x0067A220) doing `add eax, 128h` - that is `mNewEntities`.
   *
   * This used to reach into `SSyncData` through a hand-written view struct
   * that placed `mNewEntities` at +0x138. +0x138 is `mNewUnits`, so every
   * plain entity was appended to the unit queue instead, and through a view
   * whose element stride was 0x0C against a container of 0x1C-byte
   * `SCreateUnitParams`. `CWldSession::DoBeat` then built a `UserUnit` for
   * each one and read `mConstDat` out of a record that never contained it,
   * which faulted in `boost::sp_counted_base::add_ref_copy` copying a
   * `shared_ptr<Stats<StatItem>>` whose control block was whatever followed
   * the shorter record. Use the real typed member instead.
   */
  [[nodiscard]] moho::SCreateEntityParams* QueueCreateEntityParams(
    moho::SSyncData* const syncData,
    const moho::SCreateEntityParams& params
  )
  {
    syncData->mNewEntities.push_back(params);
    return &syncData->mNewEntities.back();
  }

  /**
   * Address: 0x005BD420 (FUN_005BD420)
   *
   * What it does:
   * Pushes one byte-backed boolean lane to Lua stack storage.
   */
  [[maybe_unused]] void PushLuaBooleanByte(lua_State* const rawState, const std::uint8_t value) noexcept
  {
    lua_pushboolean(rawState, value != 0u ? 1 : 0);
  }

  /**
   * Address: 0x005BD430 (FUN_005BD430)
   *
   * What it does:
   * Pushes one unsigned 32-bit lane to Lua number stack storage while
   * preserving unsigned conversion semantics for values above `INT32_MAX`.
   */
  [[maybe_unused]] void PushLuaUnsignedInt(lua_State* const rawState, const std::uint32_t value) noexcept
  {
    const std::int32_t signedBits = static_cast<std::int32_t>(value);
    float lane = static_cast<float>(signedBits);
    if (signedBits < 0) {
      lane += 4294967296.0f;
    }
    lua_pushnumber(rawState, lane);
  }

  void ApplyWorldImpulseToBody(
    moho::SPhysBody& body,
    const Wm3::Vector3f& impulse,
    const Wm3::Vector3f& applicationPoint
  ) noexcept
  {
    const float mass = body.mMass;
    float impulseXOverMass = std::numeric_limits<float>::max();
    float impulseYOverMass = std::numeric_limits<float>::max();
    float impulseZOverMass = std::numeric_limits<float>::max();
    if (mass != 0.0f) {
      const float invMass = 1.0f / mass;
      impulseXOverMass = impulse.x * invMass;
      impulseYOverMass = impulse.y * invMass;
      impulseZOverMass = impulse.z * invMass;
    }

    body.mVelocity.x += impulseXOverMass;
    body.mVelocity.y += impulseYOverMass;
    body.mVelocity.z += impulseZOverMass;

    const float deltaX = applicationPoint.x - body.mPos.x;
    const float deltaY = applicationPoint.y - body.mPos.y;
    const float deltaZ = applicationPoint.z - body.mPos.z;

    body.mWorldImpulse.x += (deltaY * impulse.z) - (deltaZ * impulse.y);
    body.mWorldImpulse.y += (deltaZ * impulse.x) - (deltaX * impulse.z);
    body.mWorldImpulse.z += (deltaX * impulse.y) - (deltaY * impulse.x);
  }

  enum class BlueprintKind : std::uint8_t
  {
    Unknown = 0,
    Unit,
    Projectile,
    Prop
  };

  [[nodiscard]] BlueprintKind GuessBlueprintKind(const moho::REntityBlueprint* blueprint)
  {
    if (!blueprint) {
      return BlueprintKind::Unknown;
    }

    // 0x00677360 asks the *reflection* system, not C++ RTTI: it builds one
    // `RRef` off the blueprint (`gpg::RRef_REntityBlueprint` at 0x0067741D,
    // which upgrades the ref to the dynamic derived type) and then upcasts that
    // same ref against each concrete blueprint descriptor in turn, taking the
    // first that comes back non-null. `dynamic_cast` answers a similar question
    // over a different hierarchy; this asks the one the engine actually indexes
    // its script factories by.
    //
    // The name-sniffing below is a fallback for blueprints whose concrete type
    // is not one of the three - it used to be the *only* test, which meant a
    // unit whose blueprint named neither "unit" nor its script class exactly
    // "Unit" fell through to "can't tell the type of blueprint id '<x>'. No
    // scripts for you", and then every GetWeaponClass on it returned nil.
    gpg::RRef blueprintRef{};
    // The RRef builder takes a mutable pointer because an RRef models a mutable
    // reflected reference; nothing here writes through it.
    blueprintRef = gpg::MakeRRef<moho::REntityBlueprint>(const_cast<moho::REntityBlueprint*>(blueprint));

    // Unit: 0x006773C7-0x006773EC, against RUnitBlueprint's own descriptor
    // cache (0x010C6E0C, i.e. `StaticGetClass`) - not the base's.
    if (gpg::REF_UpcastPtr(blueprintRef, moho::RUnitBlueprint::StaticGetClass()).mObj != nullptr) {
      return BlueprintKind::Unit;
    }

    // Projectile: 0x0067742E-0x00677463, lazy-resolving the descriptor inline
    // exactly as the binary does rather than through a helper.
    gpg::RType* projectileType = moho::RProjectileBlueprint::sType;
    if (!projectileType) {
      projectileType = gpg::LookupRType(typeid(moho::RProjectileBlueprint));
      moho::RProjectileBlueprint::sType = projectileType;
    }
    if (gpg::REF_UpcastPtr(blueprintRef, projectileType).mObj != nullptr) {
      return BlueprintKind::Projectile;
    }

    // Prop: the one arm the binary keeps out of line, called at 0x006774AB.
    if (func_CastRPropBlueprint(blueprintRef) != nullptr) {
      return BlueprintKind::Prop;
    }

    const std::string scriptModule = blueprint->mScriptModule.to_std();
    if (gpg::STR_ContainsNoCase(scriptModule.c_str(), "projectile")) {
      return BlueprintKind::Projectile;
    }
    if (gpg::STR_ContainsNoCase(scriptModule.c_str(), "unit")) {
      return BlueprintKind::Unit;
    }
    if (gpg::STR_ContainsNoCase(scriptModule.c_str(), "prop")) {
      return BlueprintKind::Prop;
    }

    const std::string scriptClass = blueprint->mScriptClass.to_std();
    if (gpg::STR_EqualsNoCase(scriptClass.c_str(), "Projectile")) {
      return BlueprintKind::Projectile;
    }
    if (gpg::STR_EqualsNoCase(scriptClass.c_str(), "Unit")) {
      return BlueprintKind::Unit;
    }
    if (gpg::STR_EqualsNoCase(scriptClass.c_str(), "Prop")) {
      return BlueprintKind::Prop;
    }

    const std::string id = blueprint->mBlueprintId.to_std();
    if (gpg::STR_ContainsNoCase(id.c_str(), "/projectiles/")) {
      return BlueprintKind::Projectile;
    }
    if (gpg::STR_ContainsNoCase(id.c_str(), "/units/")) {
      return BlueprintKind::Unit;
    }
    if (gpg::STR_ContainsNoCase(id.c_str(), "/props/")) {
      return BlueprintKind::Prop;
    }

    return BlueprintKind::Unknown;
  }

  struct ScriptFallbackSpec
  {
    const char* module;
    const char* className;
  };

  [[nodiscard]] ScriptFallbackSpec GetScriptFallbackSpec(const BlueprintKind kind)
  {
    switch (kind) {
    case BlueprintKind::Unit:
      return {"/lua/sim/unit.lua", "Unit"};
    case BlueprintKind::Projectile:
      return {"/lua/sim/projectile.lua", "Projectile"};
    case BlueprintKind::Prop:
      return {"/lua/sim/prop.lua", "Prop"};
    default:
      return {nullptr, nullptr};
    }
  }

  /**
   * Address: 0x00677360 lines 106-120 (part of `FUN_00677360`,
   * `func_FindBlueprintScriptModule` / `ResolveBlueprintScriptFactory`)
   *
   * What it does:
   * Ground truth reads `blueprint->mSource` (the un-normalized full VFS path
   * the blueprint's Lua script set via `GetSource()`/`SetShortId`, e.g.
   * "/units/uel0001/uel0001_unit.bp" — NOT `mBlueprintId`, which by that point
   * already holds the short id "uel0001" with no path or underscore left in
   * it) and finds the LAST '_' via `func_StringSearchFromEnd`, not the first.
   * The earlier revision of this helper read `mBlueprintId` and searched from
   * the start, which can never match a short id like "uel0001" (zero
   * underscores) and silently produced an always-empty result.
   */
  [[nodiscard]] std::string BuildBlueprintScriptModuleFromId(const moho::REntityBlueprint* blueprint)
  {
    if (!blueprint) {
      return {};
    }

    std::string id = blueprint->mSource.to_std();
    if (id.empty()) {
      return {};
    }

    gpg::STR_NormalizeFilenameLowerSlash(id);

    std::size_t start = 0;
    if (!id.empty() && id.front() == '/') {
      start = 1;
    }
    const std::size_t underscorePos = id.rfind('_');
    if (underscorePos == std::string::npos || underscorePos <= start) {
      return {};
    }

    return "/" + id.substr(start, underscorePos - start) + "_script.lua";
  }

  /**
   * Address: 0x0067F160 (FUN_0067F160)
   *
   * What it does:
   * Returns cached `Entity` metatable object from Lua object-factory storage.
   */
  [[nodiscard]] LuaPlus::LuaObject GetEntityFactory(LuaPlus::LuaState* const state)
  {
    return moho::CScrLuaMetatableFactory<moho::Entity>::Instance().Get(state);
  }

  /**
   * Engine addition (`sim_CacheScriptModuleLookups`): whether each blueprint script module exists,
   * so the VFS stat below (a `GetFileAttributesExW` on loose mounts) runs once per module rather
   * than once per entity created - every projectile asked again.
   *
   * The answer is the VFS's, kept until it can change: any Lua file event the disk watch reports
   * (hot reload, a mod edited on disk) or a new `Sim` (new mounts) clears it. Only the sim thread
   * creates entities; the disk watch reports on the main thread, so it only bumps a counter.
   */
  class CScriptModuleExistenceCache final : public moho::CDiskWatchListener
  {
  public:
    CScriptModuleExistenceCache()
      : CDiskWatchListener("*.lua")
    {}

    void OnDiskWatchEvent(const moho::SDiskWatchEvent& /*event*/) override
    {
      mChanges.fetch_add(1u, std::memory_order_relaxed);
    }

    [[nodiscard]] bool Exists(const moho::Sim* const sim, moho::CVirtualFileSystem& vfs, const char* const path)
    {
      const std::uint64_t changes = mChanges.load(std::memory_order_relaxed);
      if (sim != mSim || changes != mSeenChanges) {
        mSim = sim;
        mSeenChanges = changes;
        mExists.clear();
      }
      const auto [it, inserted] = mExists.try_emplace(path, false);
      if (inserted) {
        it->second = vfs.GetFileInfo(path, nullptr);
      }
      return it->second;
    }

  private:
    std::atomic<std::uint64_t> mChanges{0u};
    std::uint64_t mSeenChanges = ~std::uint64_t{0};
    const moho::Sim* mSim = nullptr;
    std::unordered_map<std::string, bool> mExists;
  };

  /// Never destroyed: the disk watch it registers with may already be gone at exit.
  [[nodiscard]] CScriptModuleExistenceCache& ScriptModuleExistence()
  {
    static CScriptModuleExistenceCache* const sCache = new CScriptModuleExistenceCache();
    return *sCache;
  }

  /**
   * Address: 0x00677360 (FUN_00677360, func_FindBlueprintScriptModule)
   *
   * What it does:
   * Resolves blueprint script factory tables by trying blueprint-specific module/class
   * first, then falling back to type-default `unit/projectile/prop` script modules.
   */
  [[nodiscard]] LuaPlus::LuaObject
  ResolveBlueprintScriptFactory(moho::Sim* sim, const moho::REntityBlueprint* blueprint)
  {
    if (!sim || !sim->mLuaState) {
      return {};
    }

    const BlueprintKind kind = GuessBlueprintKind(blueprint);
    const ScriptFallbackSpec fallback = GetScriptFallbackSpec(kind);
    if (!fallback.module || !fallback.className) {
      const char* id = (blueprint && !blueprint->mBlueprintId.empty()) ? blueprint->mBlueprintId.c_str() : "<unknown>";
      gpg::Warnf("Can't tell the type of blueprint id '%s'.  No scripts for you -- one year.", id);
      return GetEntityFactory(sim->mLuaState);
    }

    LuaPlus::LuaObject defaultFactory{};
    switch (kind) {
    case BlueprintKind::Unit:
      (void)moho::func_GetUnitFactory(&defaultFactory, sim->mLuaState);
      break;
    case BlueprintKind::Projectile:
      (void)moho::func_GetProjectileFactory(&defaultFactory, sim->mLuaState);
      break;
    case BlueprintKind::Prop:
      (void)moho::func_GetPropFactory(&defaultFactory, sim->mLuaState);
      break;
    default:
      break;
    }

    const char* requestedClass = "TypeClass";
    if (blueprint && !blueprint->mScriptClass.empty()) {
      requestedClass = blueprint->mScriptClass.c_str();
    }

    std::string requestedModuleStorage;
    const char* requestedModule = nullptr;
    if (blueprint && !blueprint->mScriptModule.empty()) {
      requestedModule = blueprint->mScriptModule.c_str();
    } else {
      requestedModuleStorage = BuildBlueprintScriptModuleFromId(blueprint);
      if (!requestedModuleStorage.empty()) {
        requestedModule = requestedModuleStorage.c_str();
      }
    }

    // 0x006774F1: the binary asks the VFS whether the module file exists
    // before importing it -- `boost::call_once(func_EnsureFileCWaitHandleSet,
    // ...)` then `sPFWaitHandleSet->mHandle->GetFileInfo(path, 0)` -- and skips
    // straight to the fallback when it does not.
    //
    // That guard was missing here, and its absence is expensive rather than
    // cosmetic. `mScriptModule` is empty for every stock blueprint, so every
    // entity falls into the synthesised `<id>_script.lua` path above; for props
    // that file genuinely does not exist. Lua's `import` does not cache a
    // failed module (`modules[name] = nil` in LoadModule's error arm), so each
    // of the 5182 props on SCMP_009 re-ran the whole failure: a WARN, a
    // `LuaState::Error`, and a C++ throw unwound back through `Prop::Prop`'s
    // `RunScript`. dbgrun counted 3000 first-chance throws inside `Sim::Setup`.
    // Retail, with this check, emits none of it.
    const moho::FWaitHandleSet* const waitHandleSet = moho::FILE_GetWaitHandleSet();
    const bool moduleFileExists = requestedModule != nullptr && *requestedModule != '\0'
      && waitHandleSet != nullptr && waitHandleSet->mHandle != nullptr
      && (moho::sim_CacheScriptModuleLookups
            ? ScriptModuleExistence().Exists(sim, *waitHandleSet->mHandle, requestedModule)
            : waitHandleSet->mHandle->GetFileInfo(requestedModule, nullptr));

    // Both modules load through SCR_Import (0x004D3250, called at 0x006776DE
    // and 0x0067783E): its `catch (const std::runtime_error&)` turns a script
    // error into an "Error importing" warning and a nil module, so a broken
    // module degrades to the fallback rather than unwinding into the entity
    // constructor. The module must be a table (`IsTable`, 0x006776F2) and the
    // class a raw non-nil field of it (`GetByName` + `IsNil`); every outcome
    // is reported with Logf, not Warnf (0x00937CB0).
    if (moduleFileExists) {
      const LuaPlus::LuaObject requestedModuleObj = moho::SCR_Import(sim->mLuaState, requestedModule);
      if (requestedModuleObj.IsTable()) {
        LuaPlus::LuaObject factoryObj = requestedModuleObj.GetByName(requestedClass);
        if (!factoryObj.IsNil()) {
          return factoryObj;
        }

        gpg::Logf(
          "Script module '%s' exists but doesn't define '%s'.\nFalling back to '%s' in module '%s'.",
          requestedModule,
          requestedClass,
          fallback.className,
          fallback.module
        );
      } else {
        gpg::Logf(
          "Problems loading module '%s'.  Falling back to '%s' in '%s'.",
          requestedModule,
          fallback.className,
          fallback.module
        );
      }
    }

    // 0x006777FD: the fallback module gets the same VFS existence check before
    // it is imported.
    const bool fallbackFileExists = waitHandleSet != nullptr && waitHandleSet->mHandle != nullptr
      && waitHandleSet->mHandle->GetFileInfo(fallback.module, nullptr);
    if (!fallbackFileExists) {
      gpg::Logf("Can't find module '%s'.  No scripts for you -- one year.", fallback.module);
      return defaultFactory;
    }

    const LuaPlus::LuaObject fallbackModuleObj = moho::SCR_Import(sim->mLuaState, fallback.module);
    if (fallbackModuleObj.IsTable()) {
      LuaPlus::LuaObject fallbackFactory = fallbackModuleObj.GetByName(fallback.className);
      if (!fallbackFactory.IsNil()) {
        return fallbackFactory;
      }

      gpg::Logf(
        "Script module '%s' exists but doesn't define '%s'.\nNo scripts for you -- one year.",
        fallback.module,
        fallback.className
      );
    } else {
      gpg::Logf("Problems loading module '%s'.  No scripts for you -- one year.", fallback.module);
    }

    return defaultFactory;
  }

  [[nodiscard]] moho::CArmyImpl* ResolveEntityArmyFromEntityId(moho::Sim* sim, const moho::EntId entityId) noexcept
  {
    if (!sim) {
      return nullptr;
    }

    const std::uint8_t sourceIndex = moho::ExtractEntityIdSourceIndex(static_cast<std::uint32_t>(entityId));
    if (sourceIndex == moho::kEntityIdSourceIndexInvalid) {
      return nullptr;
    }

    if (sourceIndex >= sim->mArmiesList.size()) {
      return nullptr;
    }

    return sim->mArmiesList[sourceIndex];
  }

  [[nodiscard]] moho::EntityOccupationManager* ResolveEntityCollisionGrid(moho::Sim* sim) noexcept
  {
    if (!sim || !sim->mOGrid) {
      return nullptr;
    }

    // 0x004FD420 (`CollisionShapeBase::Add`) reads width/mask/shift straight
    // off `COGrid::mEntityOccupationManager`; the old `+ 0x04` view here put
    // the chunk vector's capacity word on `COGrid::terrainOccupation.ptr`.
    return &sim->mOGrid->mEntityOccupationManager;
  }

  [[nodiscard]] Wm3::Vector3f RotateVectorByQuaternion(const Wm3::Quatf& quaternion, const Wm3::Vector3f& v) noexcept
  {
    Wm3::Vector3f out{};
    // Ground truth (FUN_00679CE0.c) rotates via
    // Moho::MultQuadVec(&v13, &v12, &this->mVarDat.mCurTransform.orient), not
    // the generic Wm3::MultiplyQuaternionVector -- same quaternion-convention
    // mismatch as the other orient_-consuming sites (`quaternion` above is a
    // byte-exact repack of the entity's own VTransform::orient_, which is
    // always in VMatrix4::Set's convention).
    moho::MultQuadVec(&out, &v, &quaternion);
    return out;
  }

  [[nodiscard]] std::uint8_t LayerToOccupancyBit(const moho::ELayer layer) noexcept
  {
    switch (layer) {
    case moho::LAYER_Land:
      return static_cast<std::uint8_t>(moho::EOccupancyCaps::OC_LAND);
    case moho::LAYER_Seabed:
      return static_cast<std::uint8_t>(moho::EOccupancyCaps::OC_SEABED);
    case moho::LAYER_Sub:
      return static_cast<std::uint8_t>(moho::EOccupancyCaps::OC_SUB);
    case moho::LAYER_Water:
      return static_cast<std::uint8_t>(moho::EOccupancyCaps::OC_WATER);
    case moho::LAYER_Air:
      return static_cast<std::uint8_t>(moho::EOccupancyCaps::OC_AIR);
    case moho::LAYER_Orbit:
      return static_cast<std::uint8_t>(moho::EOccupancyCaps::OC_ORBIT);
    default:
      return 0u;
    }
  }

  [[nodiscard]] bool HasOccupancyBit(const moho::EOccupancyCaps caps, const std::uint8_t bit) noexcept
  {
    return (static_cast<std::uint8_t>(caps) & bit) != 0u;
  }

  void RefreshCollisionBoundsSnapshot(moho::Entity& entity)
  {
    entity.UpdateAABox();
  }

  /**
   * Address: 0x0067AE00 (shared body used by FUN_0067AC40/FUN_0067AD30/FUN_0067AE00)
   *
   * What it does:
   * Replaces collision primitive pointer, relinks span as needed, and keeps
   * cached collision bounds in sync.
   */
  void InstallCollisionPrimitiveAndRefresh(moho::Entity& entity, moho::CColPrimitiveBase* replacement)
  {
    moho::CColPrimitiveBase* const old = entity.CollisionExtents;
    entity.CollisionExtents = replacement;
    ::operator delete(old);

    if (!entity.CollisionExtents) {
      entity.UpdateRect(static_cast<const moho::CColPrimitiveBase*>(nullptr));
      return;
    }

    entity.CollisionExtents->SetTransform(entity.mVarDat.mCurTransform);
    entity.UpdateRect(entity.CollisionExtents);
    RefreshCollisionBoundsSnapshot(entity);
  }

  [[nodiscard]] Wm3::Box3f BuildBlueprintCollisionBox(const moho::REntityBlueprint& blueprint)
  {
    Wm3::Box3f localBox{};
    localBox.Center[0] = blueprint.mCollisionOffsetX;
    localBox.Center[1] = blueprint.mCollisionOffsetY + blueprint.mSizeY * 0.5f;
    localBox.Center[2] = blueprint.mCollisionOffsetZ;

    localBox.Axis[0][0] = 1.0f;
    localBox.Axis[0][1] = 0.0f;
    localBox.Axis[0][2] = 0.0f;
    localBox.Axis[1][0] = 0.0f;
    localBox.Axis[1][1] = 1.0f;
    localBox.Axis[1][2] = 0.0f;
    localBox.Axis[2][0] = 0.0f;
    localBox.Axis[2][1] = 0.0f;
    localBox.Axis[2][2] = 1.0f;

    localBox.Extent[0] = blueprint.mSizeX * 0.5f;
    localBox.Extent[1] = blueprint.mSizeY * 0.5f;
    localBox.Extent[2] = blueprint.mSizeZ * 0.5f;
    return localBox;
  }

  [[nodiscard]] std::uint32_t ReadBlueprintCategoryBitIndex(const moho::REntityBlueprint* blueprint) noexcept
  {
    return blueprint ? blueprint->mCategoryBitIndex : 0u;
  }

  /**
   * Address: 0x00679680 (FUN_00679680)
   *
   * What it does:
   * Applies attach-link/local transform from `src` into `dst`, including
   * intrusive weak-chain rewire when attach owner changes.
   */
  void ApplyAttachInfo(moho::SEntAttachInfo& dst, const moho::SEntAttachInfo& src)
  {
    moho::WeakPtr<moho::Entity>& dstWeak = dst.TargetWeakLink();
    const moho::WeakPtr<moho::Entity>& srcWeak = src.TargetWeakLink();

    // `WeakPtr::operator=`: nothing when both already name one chain.
    dstWeak = srcWeak;

    dst.mParentBoneIndex = src.mParentBoneIndex;
    dst.mChildBoneIndex = src.mChildBoneIndex;
    dst.mRelativeTransform = src.mRelativeTransform;
  }

  /**
   * Address: 0x00676850 (FUN_00676850, sub_676850)
   *
   * What it does:
   * Solves owner-world transform from child-bone local transform and already
   * composed parent-bone world transform.
   *
   * Ground truth (`FUN_00676850.c`) keeps the child's lane 0 unnegated and
   * negates lanes 1..3 - the conjugate under the binary's scalar-first
   * layout, which `Wm3::Quaternionf` spells "keep `.w`, negate `.x/.y/.z`".
   * The product then reduces exactly to `parent * conj(child)`, i.e. the
   * child-local transform undone from the composed parent world transform,
   * which is what the name says and an independent check on the lane
   * assignment. The identity it starts from is `{1, 0, 0, 0}`, matching the
   * `1.0` the binary stores to `[edi+00]`.
   *
   * The position rotate uses `Moho::MultQuadVec(&v21, &v20, &a2->orient)`,
   * not `Wm3::MultiplyQuaternionVector`.
   */
  [[nodiscard]] moho::VTransform SolveAttachedWorldTransformFromChildLocal(
    const moho::VTransform& childLocalTransform,
    const moho::VTransform& parentComposedTransform
  ) noexcept
  {
    moho::VTransform out{};
    out.orient_.w = 1.0f;
    out.orient_.x = 0.0f;
    out.orient_.y = 0.0f;
    out.orient_.z = 0.0f;
    out.pos_.x = 0.0f;
    out.pos_.y = 0.0f;
    out.pos_.z = 0.0f;

    const float parentW = parentComposedTransform.orient_.w;
    const float parentX = parentComposedTransform.orient_.x;
    const float parentY = parentComposedTransform.orient_.y;
    const float parentZ = parentComposedTransform.orient_.z;

    const float childW = childLocalTransform.orient_.w;
    const float childX = childLocalTransform.orient_.x;
    const float childY = childLocalTransform.orient_.y;
    const float childZ = childLocalTransform.orient_.z;

    // parent * conj(child), accumulated in the binary's order
    // (0x006768B2..0x006769B9): the conjugate lanes are formed as `-0.0 - c`
    // and each lane starts from the two negated products. Float addition does
    // not associate; a near-cancelling lane (a factory-held unit's yaw/tilt
    // residual) otherwise lands on a different tiny value.
    const float negChildX = -childX;
    const float negChildY = -childY;
    const float negChildZ = -childZ;
    const float outW = (((parentW * childW) + (parentX * childX)) + (parentY * childY)) + (parentZ * childZ);
    const float outX = (((parentY * negChildZ) + (parentW * negChildX)) + (parentX * childW)) + (parentZ * childY);
    const float outY = (((parentZ * negChildX) + (parentW * negChildY)) + (parentY * childW)) + (parentX * childZ);
    const float outZ = (((parentX * negChildY) + (parentW * negChildZ)) + (parentZ * childW)) + (parentY * childX);

    out.orient_.w = outW;
    out.orient_.x = outX;
    out.orient_.y = outY;
    out.orient_.z = outZ;

    const Wm3::Vector3f negChildPos{
      -childLocalTransform.pos_.x,
      -childLocalTransform.pos_.y,
      -childLocalTransform.pos_.z,
    };

    Wm3::Vector3f rotatedNegChildPos{};
    moho::MultQuadVec(&rotatedNegChildPos, &negChildPos, &out.orient_);
    out.pos_.x = rotatedNegChildPos.x + parentComposedTransform.pos_.x;
    out.pos_.y = rotatedNegChildPos.y + parentComposedTransform.pos_.y;
    out.pos_.z = rotatedNegChildPos.z + parentComposedTransform.pos_.z;
    return out;
  }
}

namespace moho
{

  /**
   * Address: 0x005BD530 (FUN_005BD530, Moho::EntityAttributes::GetRange)
   *
   * What it does:
   * Returns the masked range magnitude for intel-bearing lanes and zero for
   * the non-range field lanes.
   */
  std::uint32_t EntityAttributes::GetRange(const EEntityAttribute attribute) const noexcept
  {
    switch (attribute) {
    case ENTATTR_Vision:
      return vision & kEntityAttributeRangeMask;
    case ENTATTR_WaterVision:
      return waterVision & kEntityAttributeRangeMask;
    case ENTATTR_Radar:
      return radar & kEntityAttributeRangeMask;
    case ENTATTR_Sonar:
      return sonar & kEntityAttributeRangeMask;
    case ENTATTR_Omni:
      return omni & kEntityAttributeRangeMask;
    case ENTATTR_RadarStealthField:
    case ENTATTR_SonarStealthField:
    case ENTATTR_CloakField:
    case ENTATTR_Jammer:
    case ENTATTR_Spoof:
      return 0u;
    case ENTATTR_Cloak:
      return cloak & kEntityAttributeRangeMask;
    case ENTATTR_RadarStealth:
      return radarStealth & kEntityAttributeRangeMask;
    case ENTATTR_SonarStealth:
      return sonarStealth & kEntityAttributeRangeMask;
    }
    return 0u;
  }

  /**
   * Address: 0x008B8330 (FUN_008B8330, Moho::EntityAttributes::IsEnabled)
   *
   * What it does:
   * Returns the high-bit enable flag for range-bearing intel lanes and false
   * for field/jammer/spoof lanes.
   */
  bool EntityAttributes::IsEnabled(const EEntityAttribute attribute) const noexcept
  {
    switch (attribute) {
    case ENTATTR_Vision:
      return (vision >> 31u) != 0u;
    case ENTATTR_WaterVision:
      return (waterVision >> 31u) != 0u;
    case ENTATTR_Radar:
      return (radar >> 31u) != 0u;
    case ENTATTR_Sonar:
      return (sonar >> 31u) != 0u;
    case ENTATTR_Omni:
      return (omni >> 31u) != 0u;
    case ENTATTR_RadarStealthField:
    case ENTATTR_SonarStealthField:
    case ENTATTR_CloakField:
    case ENTATTR_Jammer:
    case ENTATTR_Spoof:
      return false;
    case ENTATTR_Cloak:
      return (cloak >> 31u) != 0u;
    case ENTATTR_RadarStealth:
      return (radarStealth >> 31u) != 0u;
    case ENTATTR_SonarStealth:
      return (sonarStealth >> 31u) != 0u;
    }
    return false;
  }

  /**
   * Address: 0x00689DC0 (FUN_00689DC0, Moho::EntityAttributes::SetEnabled)
   *
   * What it does:
   * Writes one high-bit enable flag into the selected range-bearing intel lane
   * while preserving its lower 31-bit radius payload.
   */
  void EntityAttributes::SetEnabled(const EEntityAttribute attribute, const bool enabled) noexcept
  {
    const std::uint32_t enabledBit = enabled ? kEntityAttributeEnabledMask : 0u;

    switch (attribute) {
    case ENTATTR_Vision:
      vision = (vision & kEntityAttributeRangeMask) | enabledBit;
      return;
    case ENTATTR_WaterVision:
      waterVision = (waterVision & kEntityAttributeRangeMask) | enabledBit;
      return;
    case ENTATTR_Radar:
      radar = (radar & kEntityAttributeRangeMask) | enabledBit;
      return;
    case ENTATTR_Sonar:
      sonar = (sonar & kEntityAttributeRangeMask) | enabledBit;
      return;
    case ENTATTR_Omni:
      omni = (omni & kEntityAttributeRangeMask) | enabledBit;
      return;
    case ENTATTR_RadarStealthField:
    case ENTATTR_SonarStealthField:
    case ENTATTR_CloakField:
    case ENTATTR_Jammer:
    case ENTATTR_Spoof:
      return;
    case ENTATTR_Cloak:
      cloak = (cloak & kEntityAttributeRangeMask) | enabledBit;
      return;
    case ENTATTR_RadarStealth:
      radarStealth = (radarStealth & kEntityAttributeRangeMask) | enabledBit;
      return;
    case ENTATTR_SonarStealth:
      sonarStealth = (sonarStealth & kEntityAttributeRangeMask) | enabledBit;
      return;
    }
  }

  /**
   * Address: 0x005BD470 (FUN_005BD470, Moho::EntityAttributes::SetIntelRadius)
   *
   * IDA signature:
   * void __usercall Moho::EntityAttributes::SetIntelRadius(
   *   Moho::EntityAttributes *result@<eax>,
   *   Moho::EEntityAttribute type@<edx>,
   *   int rad@<ecx>);
   *
   * What it does:
   * Writes one new intel radius magnitude into the matching payload lane while
   * preserving the lane's sign bit. The non-radius field lanes are left alone.
   */
  void EntityAttributes::SetIntelRadius(const EEntityAttribute attribute, const int radius) noexcept
  {
    const std::uint32_t newRadius = static_cast<std::uint32_t>(radius);

    switch (attribute) {
    case ENTATTR_Vision:
      vision = newRadius | (vision & kEntityAttributeEnabledMask);
      return;
    case ENTATTR_WaterVision:
      waterVision = newRadius | (waterVision & kEntityAttributeEnabledMask);
      return;
    case ENTATTR_Radar:
      radar = newRadius | (radar & kEntityAttributeEnabledMask);
      return;
    case ENTATTR_Sonar:
      sonar = newRadius | (sonar & kEntityAttributeEnabledMask);
      return;
    case ENTATTR_Omni:
      omni = newRadius | (omni & kEntityAttributeEnabledMask);
      return;
    case ENTATTR_RadarStealthField:
    case ENTATTR_SonarStealthField:
    case ENTATTR_CloakField:
    case ENTATTR_Jammer:
    case ENTATTR_Spoof:
      return;
    case ENTATTR_Cloak:
      cloak = newRadius | (cloak & kEntityAttributeEnabledMask);
      return;
    case ENTATTR_RadarStealth:
      radarStealth = newRadius | (radarStealth & kEntityAttributeEnabledMask);
      return;
    case ENTATTR_SonarStealth:
      sonarStealth = newRadius | (sonarStealth & kEntityAttributeEnabledMask);
      return;
    }
  }

  /**
   * Address: 0x00559350 (FUN_00559350, Moho::EntityAttributes::MemberDeserialize)
   *
   * What it does:
   * Loads all eight intel payload lanes from archive storage in field order.
   */
  void EntityAttributes::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    archive->ReadUInt(&vision);
    archive->ReadUInt(&waterVision);
    archive->ReadUInt(&radar);
    archive->ReadUInt(&sonar);
    archive->ReadUInt(&omni);
    archive->ReadUInt(&radarStealth);
    archive->ReadUInt(&sonarStealth);
    archive->ReadUInt(&cloak);
  }

  /**
   * Address: 0x005593D0 (FUN_005593D0, Moho::EntityAttributes::MemberSerialize)
   *
   * What it does:
   * Stores all eight intel payload lanes to archive storage in field order.
   */
  void EntityAttributes::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    archive->WriteUInt(vision);
    archive->WriteUInt(waterVision);
    archive->WriteUInt(radar);
    archive->WriteUInt(sonar);
    archive->WriteUInt(omni);
    archive->WriteUInt(radarStealth);
    archive->WriteUInt(sonarStealth);
    archive->WriteUInt(cloak);
  }

  /**
   * Address: 0x006A46A0 (FUN_006A46A0, Moho::EntityAttributes::Initialize)
   *
   * What it does:
   * Seeds intel lanes from unit-blueprint intel radii, setting the enable
   * sign bit for non-zero ranges.
   */
  void EntityAttributes::Initialize(const RUnitBlueprint* const blueprint)
  {
    vision = EncodeIntelRangeLane(blueprint->Intel.VisionRadius);
    waterVision = EncodeIntelRangeLane(blueprint->Intel.WaterVisionRadius);
    radar = EncodeIntelRangeLane(blueprint->Intel.RadarRadius);
    sonar = EncodeIntelRangeLane(blueprint->Intel.SonarRadius);
    omni = EncodeIntelRangeLane(blueprint->Intel.OmniRadius);
    radarStealth = EncodeIntelRangeLane(blueprint->Intel.RadarStealthFieldRadius);
    sonarStealth = EncodeIntelRangeLane(blueprint->Intel.SonarStealthFieldRadius);
    cloak = EncodeIntelRangeLane(blueprint->Intel.CloakFieldRadius);
  }

  /**
   * Address: 0x00676C40 (FUN_00676C40)
   *
   * What it does:
   * Returns cached reflection descriptor for Entity.
   */
  gpg::RType* Entity::GetClass() const
  {
    static gpg::RType* sEntityType = nullptr;
    if (!sEntityType) {
      sEntityType = gpg::LookupRType(typeid(Entity));
    }
    return sEntityType;
  }
namespace
{

}


  /**
   * Address: 0x00681220 (FUN_00681220, sub_681220)
   *
   * IDA signature:
   * void __usercall sub_681220(gpg::ReadArchive* archive@<eax>, Entity* this@<esi>);
   *
   * What it does:
   * Reflection LOAD serializer, the exact mirror of `MemberSerialize`: reads
   * every persisted lane back in the same order, restoring each tracked
   * pointer's OWNED/UNOWNED state. Without this the base of every entity could
   * be written to a save but never read back.
   */
  void Entity::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    GPG_ASSERT(archive != nullptr);
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef owner{};

    // Through a real block: Entity's flat lanes need not have its spacing (see MemberSerialize).
    SSTIEntityConstantData constantData{};
    archive->Read(gpg::RTypeOf<SSTIEntityConstantData>(), &constantData, owner);
    id_ = static_cast<EntId>(constantData.mEntityId);
    BluePrint = constantData.mBlueprint;
    mTickCreated = constantData.mTickCreated;
    archive->Read(gpg::RTypeOf<CScriptObject>(), static_cast<CScriptObject*>(this), owner);
    archive->Read(gpg::CachedLookup<CTask>(CTask::sType), static_cast<CTask*>(this), owner);
    archive->Read(gpg::RTypeOf<SSTIEntityVariableData>(), &mVarDat.mScmResource, owner);

    // Owning army (UNOWNED).
    auto* army = static_cast<SimArmy*>(ArmyRef);
    (void)archive->ReadPointer(&army, &owner);
    ArmyRef = static_cast<CArmyImpl*>(army);

    archive->Read(gpg::RTypeOf<VTransform>(), &mPendingTransform, owner);

    (void)archive->ReadPointerOwned(&mPositionHistory, &owner);

    archive->ReadFloat(&mPendingVelocityScale);

    int lastTickProcessed = 0;
    archive->ReadInt(&lastTickProcessed);
    mLastTickProcessed = static_cast<std::uint32_t>(lastTickProcessed);

    (void)archive->ReadPointerOwned(&CollisionExtents, &owner);

    archive->Read(gpg::RTypeOf<fa::vector<Entity*>>(), &mAttachedEntities, owner);
    archive->Read(gpg::RTypeOf<SEntAttachInfo>(), &mAttachInfo, owner);

    bool queueRelinkBlocked = false;
    bool destroyQueued = false;
    bool onDestroyDispatched = false;
    archive->ReadBool(&queueRelinkBlocked);
    archive->ReadBool(&destroyQueued);
    archive->ReadBool(&onDestroyDispatched);
    mQueueRelinkBlocked = queueRelinkBlocked ? 1u : 0u;
    DestroyQueuedFlag = destroyQueued ? 1u : 0u;
    mOnDestroyDispatched = onDestroyDispatched ? 1u : 0u;

    archive->Read(gpg::RTypeOf<RResId>(), &mResId, owner);

    (void)archive->ReadPointerOwned(&mIntelManager, &owner);

    gpg::RType* const visibilityType = gpg::RTypeOf<EVisibilityMode>();
    archive->Read(visibilityType, &mVizToFocusPlayer, owner);
    archive->Read(visibilityType, &mVizToAllies, owner);
    archive->Read(visibilityType, &mVizToEnemies, owner);
    archive->Read(visibilityType, &mVizToNeutrals, owner);

    (void)archive->ReadPointerOwned(&mScroller, &owner);
    (void)archive->ReadPointerOwned(&mPhysBody, &owner);

    bool realtimeStatsEnabled = false;
    archive->ReadBool(&realtimeStatsEnabled);
    RealtimeStatsEnabled = realtimeStatsEnabled ? 1u : 0u;

    archive->ReadString(&mUniqueName);

    archive->Read(gpg::RTypeOf<EntitySetTemplate<Entity>>(), &mShooters, owner);

    (void)archive->ReadPointerOwned(&mMotor, &owner);

    archive->Read(gpg::RTypeOf<Wm3::AxisAlignedBox3f>(), &mAABox, owner);

    // Engine addition (replay keyframes): Entity:GetPosition() returns this one table and updates it
    // in place, so Lua holding it keeps seeing the entity move.
    if (gSimExactArchive.load(std::memory_order_relaxed)) {
      archive->Read(gpg::LookupRType(typeid(LuaPlus::LuaObject)), &mLuaPositionCache, owner);
    }

    // 0x0068170C: `call 0x4FD4F0`. The grid buckets are not saved; this puts the entity back in them.
    UpdateRect(CollisionExtents);
  }

  /**
   * Address: 0x00681720 (FUN_00681720, Moho::Entity::MemberSerialize)
   * Mangled: ?MemberSerialize@Entity@Moho@@QBEXPAVWriteArchive@gpg@@@Z
   *
   * IDA signature:
   * void __usercall Moho::Entity::MemberSerialize(Entity *this@<eax>, gpg::WriteArchive *archive@<esi>);
   *
   * What it does:
   * Reflection SAVE serializer. Writes every persisted `Entity` lane to the
   * archive in exact binary field order, preserving each tracked pointer's
   * original OWNED/UNOWNED state:
   *   1. Constant-data sub-object (+0x68), `CScriptObject` base (+0x00),
   *      `CTask` base (+0x34), variable-data sub-object (+0x78).
   *   2. Owning army (UNOWNED), pending transform (+0x150), position history
   *      (OWNED), interpolation float, last-tick int, collision primitive
   *      (OWNED), attached-entity vector, attach info, three teardown flags.
   *   3. Resource id (+0x1BC), intel manager (OWNED), four visibility lanes,
   *      texture scroller (OWNED), physics body (OWNED), realtime-stats bool,
   *      unique name string, shooter set, motor (OWNED), collision AABB.
   */
  void Entity::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    const gpg::RRef owner{};

    // Constant-data sub-object (+0x68). The three lanes (id/blueprint/tick) are
    // modeled flat because they are referenced across the engine. They go through
    // a real block because only the binary's layout gives the lanes its spacing:
    // the Linux ABI can seat `id_` in a base's tail padding, 4 bytes before `BluePrint`.
    const SSTIEntityConstantData constantData{static_cast<std::int32_t>(id_), BluePrint, mTickCreated};
    archive->Write(gpg::RTypeOf<SSTIEntityConstantData>(), &constantData, owner);

    // CScriptObject base subobject (+0x00).
    archive->Write(gpg::RTypeOf<CScriptObject>(), static_cast<const CScriptObject*>(this), owner);

    // CTask base subobject (+0x34).
    archive->Write(gpg::CachedLookup<CTask>(CTask::sType), static_cast<const CTask*>(this), owner);

    // Variable-data sub-object (+0x78); modeled flat, first field is mMeshRef.
    archive->Write(gpg::RTypeOf<SSTIEntityVariableData>(), &mVarDat.mScmResource, owner);

    // Owning army pointer (UNOWNED). CArmyImpl derives from SimArmy.
    archive->WritePointer<moho::SimArmy>(static_cast<SimArmy*>(ArmyRef), gpg::TrackedPointerState::Unowned, owner);

    // Pending world transform (+0x150), logically a VTransform payload.
    archive->Write(gpg::RTypeOf<VTransform>(), &mPendingTransform, owner);

    // Position-history pointer (OWNED).
    archive->WritePointer<moho::PositionHistory>(mPositionHistory, gpg::TrackedPointerState::Owned, owner);

    archive->WriteFloat(mPendingVelocityScale);
    archive->WriteInt(static_cast<int>(mLastTickProcessed));

    // Collision-primitive pointer (OWNED).
    archive->WritePointer<moho::CColPrimitiveBase>(CollisionExtents, gpg::TrackedPointerState::Owned, owner);

    // Attached-entity vector (+0x17C).
    archive->Write(gpg::RTypeOf<fa::vector<Entity*>>(), &mAttachedEntities, owner);

    // Attach-info payload (+0x18C).
    archive->Write(gpg::RTypeOf<SEntAttachInfo>(), &mAttachInfo, owner);

    archive->WriteBool(mQueueRelinkBlocked != 0u);
    archive->WriteBool(DestroyQueuedFlag != 0u);
    archive->WriteBool(mOnDestroyDispatched != 0u);

    // Resource id (+0x1BC).
    archive->Write(gpg::RTypeOf<RResId>(), &mResId, owner);

    // Intel-manager pointer (OWNED).
    archive->WritePointer<moho::CIntel>(mIntelManager, gpg::TrackedPointerState::Owned, owner);

    // Four visibility-mode lanes (+0x1DC..+0x1E8).
    gpg::RType* const visibilityType = gpg::RTypeOf<EVisibilityMode>();
    archive->Write(visibilityType, &mVizToFocusPlayer, owner);
    archive->Write(visibilityType, &mVizToAllies, owner);
    archive->Write(visibilityType, &mVizToEnemies, owner);
    archive->Write(visibilityType, &mVizToNeutrals, owner);

    // Texture-scroller pointer (OWNED).
    archive->WritePointer<moho::CTextureScroller>(mScroller, gpg::TrackedPointerState::Owned, owner);

    // Physics-body pointer (OWNED).
    archive->WritePointer<moho::SPhysBody>(mPhysBody, gpg::TrackedPointerState::Owned, owner);

    archive->WriteBool(RealtimeStatsEnabled != 0u);
    archive->WriteString(const_cast<fa::string*>(&mUniqueName));

    // Shooter set (+0x218): EntitySetBase IS-A EntitySetTemplate<Entity>.
    archive->Write(gpg::RTypeOf<EntitySetTemplate<Entity>>(), &mShooters, owner);

    // Motor pointer (OWNED).
    archive->WritePointer<moho::Motor>(mMotor, gpg::TrackedPointerState::Owned, owner);

    // Collision AABB (+0x240): min/max modeled split, first field is min.
    archive->Write(gpg::RTypeOf<Wm3::AxisAlignedBox3f>(), &mAABox, owner);

    // Engine addition (replay keyframes): see MemberDeserialize.
    if (gSimExactArchive.load(std::memory_order_relaxed)) {
      archive->Write(gpg::LookupRType(typeid(LuaPlus::LuaObject)), &mLuaPositionCache, owner);
    }
  }
namespace
{
    /**
     * Address: 0x0067E410 (FUN_0067E410)
     * Address: 0x00BFC900 (FUN_00BFC900, atexit destructor of the static `RPointerType<Entity>` descriptor)
     *
     * What it does:
     * Constructs the static `RPointerType<Entity>` descriptor that the binary
     * exposes as `Moho::Entity::PointerType` and pre-registers it under the
     * `Entity*` type-info key, so subsequent `LookupRType` queries from the
     * lazy `GetPointerType` lane resolve to this descriptor. The binary holds
     * the descriptor as a function-local static of `GetPointerType`; it lives
     * here because the preregister phase has to construct it before any
     * consumer looks up `Entity*`.
     */
    gpg::RType* PreregisterEntityPointerType()
    {
      static gpg::RPointerType<moho::Entity> sDescriptor;
      gpg::PreRegisterRType(typeid(moho::Entity*), &sDescriptor);
      return &sDescriptor;
    }
}


  /**
   * Address: 0x0067CFA0 (FUN_0067CFA0, Moho::Entity::GetPointerType)
   *
   * What it does:
   * On first call, pre-registers the static `RPointerType<Entity>`
   * descriptor. After that, lazily caches the
   * `LookupRType(typeid(Entity*))` result in `sPointerType` and returns it.
   */
  gpg::RType* Entity::GetPointerType()
  {
    static const bool sOnceInit = (PreregisterEntityPointerType(), true);
    (void)sOnceInit;

    if (!sPointerType) {
      sPointerType = gpg::LookupRType(typeid(Entity*));
    }
    return sPointerType;
  }

  /**
   * Address: 0x00676C60 (FUN_00676C60)
   *
   * What it does:
   * Packs {this, GetClass()} as a reflection reference handle.
   */
  gpg::RRef Entity::GetDerivedObjectRef()
  {
    return gpg::MakeSelfRef(this);
  }

  /**
   * Address: 0x0067B470 (FUN_0067B470,
   * ?MemberSaveConstructArgs@Entity@Moho@@AAEXAAVWriteArchive@gpg@@HABVRRef@4@AAVSerSaveConstructArgsResult@4@@Z)
   *
   * What it does:
   * Saves construct payload (`Sim*`) as an unowned tracked-pointer lane.
   */
  void Entity::MemberSaveConstructArgs(
    gpg::WriteArchive& archive,
    const int,
    const gpg::RRef&,
    gpg::SerSaveConstructArgsResult& result
  )
  {
    archive.WritePointer(SimulationRef, gpg::TrackedPointerState::Unowned, gpg::RRef{});
    result.SetUnowned(0u);
  }

  /**
   * Address: 0x0067B570 (FUN_0067B570,
   * ?MemberConstruct@Entity@Moho@@CAXAAVReadArchive@gpg@@HABVRRef@4@AAVSerConstructResult@4@@Z)
   *
   * What it does:
   * Reads construct payload (`Sim*`) and allocates one `Entity` with
   * default entity collision-bucket flags (`0x800`).
   */
  void Entity::MemberConstruct(gpg::ReadArchive& archive, const int, const gpg::RRef&, gpg::SerConstructResult& result)
  {
    Sim* sim = nullptr;
    const gpg::RRef owner{};
    archive.ReadPointer(&sim, &owner);
    result.SetUnowned(gpg::MakeRRef(new Entity(sim, 0x800u)), 0u);
  }

  /**
   * Address: 0x006785D0 (FUN_006785D0, ??1Entity@Moho@@MAE@XZ)
   * Address: 0x00677C60 (FUN_00677C60, the compiler-generated scalar deleting
   * destructor thunk for the destructor above)
   *
   * What it does:
   * Releases entity id ownership, tears down runtime-owned collision/intel/
   * attach helper lanes, and unlinks local intrusive nodes before base/member
   * destructor lanes run.
   */
  Entity::~Entity()
  {
#if FAF_SERVER_MODE
    faf::remote::ForgetUnderlayPath(static_cast<std::uint32_t>(id_));
#endif
    if (SimulationRef != nullptr && SimulationRef->mEntityDB != nullptr) {
      (void)SimulationRef->mEntityDB->ReleaseId(static_cast<std::uint32_t>(id_));
    }

    delete mMotor;
    mMotor = nullptr;

    // Binary lane explicitly tears down the cached Lua position object before
    // remaining runtime-owned members.
    mLuaPositionCache = LuaPlus::LuaObject{};

    mShooters.Clear();
    mUniqueName = fa::string{};

    delete mPhysBody;
    mPhysBody = nullptr;

    delete mScroller;
    mScroller = nullptr;

    delete mIntelManager;
    mIntelManager = nullptr;

    if (Entity* const parent = mAttachInfo.GetAttachTargetEntity(); parent != nullptr) {
      fa::vector<Entity*>& siblings = parent->GetAttachedEntities();
      for (Entity** it = siblings.begin(); it != siblings.end(); ++it) {
        if (*it == this) {
          siblings.erase(it);
          break;
        }
      }
    }

    mAttachInfo.TargetWeakLink().UnlinkFromOwnerChain();
    mAttachInfo = SEntAttachInfo();
    mAttachedEntities.clear();

    ::operator delete(CollisionExtents);
    CollisionExtents = nullptr;

    delete mPositionHistory;
    mPositionHistory = nullptr;

    // mVarDat's member destructor releases the attachment vector and shared
    // resources (0x0067879A), before the base destructors below.

    // Leaving Sim::mCoordEntities (binary FUN_006785D0 lines 75-78: the splice
    // and self-reset at +0x60/+0x64) is the dirty-list base's own
    // `~TDatListItem`, after InstanceCounter<Entity>'s -1 and ~CTask, where
    // the binary runs it. `mShooters` leaves the entity DB's set ring the same
    // way, as a member (0x0067866A: its inline vector reset, then its unlink).

    // The collision shape leaves the grid in ~CollisionShapeBase, which runs
    // after this body and ~CTask -- binary FUN_006785D0 line 79 calls
    // CollisionShapeBase::Remove (FUN_004FD490) at the same point.
  }

  /**
   * Address: 0x006779E0 (FUN_006779E0)
   *
   * What it does:
   * Initializes Entity storage for serializer-owned construction paths and
   * links the entity node into `Sim::mCoordEntities`.
   */
  Entity::Entity(Sim* sim, const std::uint32_t collisionBucketFlags)
    : CollisionShape<Entity>(ResolveEntityCollisionGrid(sim), collisionBucketFlags)
    , CTask(nullptr, false)
  {
    std::memset(pad_01BB, 0, sizeof(pad_01BB));
    std::memset(pad_01ED, 0, sizeof(pad_01ED));
    RealtimeStatsEnabled = 0u;
    std::memset(pad_01F9_01FB, 0, sizeof(pad_01F9_01FB));

    id_ = static_cast<EntId>(moho::ToRaw(moho::EEntityIdSentinel::Invalid));
    BluePrint = nullptr;
    mTickCreated = 0u;
    mReserved74 = 0u;

    // +0x78 is `mVarDat`, and its own constructor (0x00558760) writes every
    // default this body used to write by hand -- the unit scale, the 1.0f
    // interpolation and fraction-complete lanes, the invalid attachment-parent
    // sentinel, the inline auxiliary-id vector, `MapPlayableRect` and the
    // zeroed intel lanes. The binary calls it from here too; MSVC emits the
    // call from the member list, so there is no source line for it.

    SimulationRef = sim;
    ArmyRef = nullptr;

    mPositionHistory = nullptr;
    mPendingVelocityScale = 0.0f;
    mLastTickProcessed = 0u;
    CollisionExtents = nullptr;

    mAttachedEntities.clear();

    mQueueRelinkBlocked = 0u;
    DestroyQueuedFlag = 0u;
    mOnDestroyDispatched = 0u;
    mIntelManager = nullptr;
    mVizToFocusPlayer = 2;
    mVizToAllies = 2;
    mVizToEnemies = 2;
    mVizToNeutrals = 2;
    mInterfaceCreated = 0u;
    mScroller = nullptr;
    mPhysBody = nullptr;
    mAABox.Min = {0.0f, 0.0f, 0.0f};
    mAABox.Max = {0.0f, 0.0f, 0.0f};
    mMotor = nullptr;

    if (sim != nullptr) {
      ListLinkBefore(&sim->mCoordEntities);
    }
  }

  /**
   * Address: 0x00678160 (FUN_00678160, ??0Entity@Moho@@IAE@PAVSim@1@VEntId@1@H@Z)
   *
   * What it does:
   * Initializes Entity base state for derived runtime lanes, applies caller
   * collision bucket flags, and finalizes ownership through `StandardInit`.
   */
  /**
   * @warning The null thread here is correct -- do not "fix" it. `Entity` really
   * does derive from `CTask` (RTTI puts the base at mdisp=52, with its own
   * vftable at 0xE27590), and `CTask`'s ctor pushes onto a thread only when it
   * is given one. Both Entity ctors in the binary inline that ctor and store the
   * vftable straight into `[this+0x34]` (0x006779E0 and 0x00677F40) without ever
   * touching a thread's task stack, so entities are *not* scheduled at
   * construction.
   *
   * That matters because nothing currently ticks any unit at all -- see the
   * warning on `Unit::MotionTick`, which measured zero calls over twenty minutes
   * of game time. The missing link is whatever pushes the entity onto a
   * `CTaskThread` later, not this constructor.
   */
  Entity::Entity(Sim* sim, const EntId entityId, const std::uint32_t collisionBucketFlags)
    : CollisionShape<Entity>(ResolveEntityCollisionGrid(sim), collisionBucketFlags)
    , CTask(nullptr, false)
  {
    std::memset(pad_01BB, 0, sizeof(pad_01BB));
    std::memset(pad_01ED, 0, sizeof(pad_01ED));
    RealtimeStatsEnabled = 0u;
    std::memset(pad_01F9_01FB, 0, sizeof(pad_01F9_01FB));

    id_ = static_cast<EntId>(moho::ToRaw(moho::EEntityIdSentinel::Invalid));
    BluePrint = nullptr;
    mTickCreated = 0u;
    mReserved74 = 0u;

    // +0x78 is `mVarDat`, and its own constructor (0x00558760) writes every
    // default this body used to write by hand -- the unit scale, the 1.0f
    // interpolation and fraction-complete lanes, the invalid attachment-parent
    // sentinel, the inline auxiliary-id vector, `MapPlayableRect` and the
    // zeroed intel lanes. The binary calls it from here too; MSVC emits the
    // call from the member list, so there is no source line for it.

    SimulationRef = nullptr;
    ArmyRef = nullptr;

    mPositionHistory = nullptr;
    mPendingVelocityScale = 1.0f;
    mLastTickProcessed = 0u;
    CollisionExtents = nullptr;

    mQueueRelinkBlocked = 0u;
    DestroyQueuedFlag = 0u;
    mOnDestroyDispatched = 0u;
    mIntelManager = nullptr;
    mVizToFocusPlayer = 2;
    mVizToAllies = 2;
    mVizToEnemies = 4;
    mVizToNeutrals = 2;
    mInterfaceCreated = 0u;
    mScroller = nullptr;
    mPhysBody = nullptr;
    mAABox.Min = {0.0f, 0.0f, 0.0f};
    mAABox.Max = {0.0f, 0.0f, 0.0f};
    mMotor = nullptr;

    StandardInit(sim, entityId);
  }

  /**
   * Address: 0x00677C90 (FUN_00677C90)
   *
   * What it does:
   * Initializes Entity base state blocks, binds script object from blueprint module,
   * seeds collision/grid metadata, and dispatches `StandardInit`.
   */
  Entity::Entity(REntityBlueprint* blueprint, Sim* sim, const EntId entityId, const std::uint32_t collisionBucketFlags)
    : CollisionShape<Entity>(ResolveEntityCollisionGrid(sim), collisionBucketFlags)
    , CTask(nullptr, false)
  {
    std::memset(pad_01BB, 0, sizeof(pad_01BB));
    std::memset(pad_01ED, 0, sizeof(pad_01ED));
    RealtimeStatsEnabled = 0u;
    std::memset(pad_01F9_01FB, 0, sizeof(pad_01F9_01FB));

    LuaPlus::LuaObject arg1{};
    LuaPlus::LuaObject arg2{};
    LuaPlus::LuaObject arg3{};
    LuaPlus::LuaObject scriptFactory = ResolveBlueprintScriptFactory(sim, blueprint);
    CreateLuaObject(scriptFactory, arg1, arg2, arg3);

    id_ = static_cast<EntId>(moho::ToRaw(moho::EEntityIdSentinel::Invalid));
    BluePrint = nullptr;
    mTickCreated = 0u;
    mReserved74 = 0u;

    // +0x78 is `mVarDat`, and its own constructor (0x00558760) writes every
    // default this body used to write by hand -- the unit scale, the 1.0f
    // interpolation and fraction-complete lanes, the invalid attachment-parent
    // sentinel, the inline auxiliary-id vector, `MapPlayableRect` and the
    // zeroed intel lanes. The binary calls it from here too; MSVC emits the
    // call from the member list, so there is no source line for it.

    SimulationRef = nullptr;
    ArmyRef = nullptr;

    mPositionHistory = nullptr;
    mPendingVelocityScale = 1.0f;
    mLastTickProcessed = 0u;
    CollisionExtents = nullptr;

    mQueueRelinkBlocked = 0u;
    DestroyQueuedFlag = 0u;
    mOnDestroyDispatched = 0u;
    mIntelManager = nullptr;
    mVizToFocusPlayer = 2;
    mVizToAllies = 2;
    mVizToEnemies = 4;
    mVizToNeutrals = 2;
    mInterfaceCreated = 0u;
    mScroller = nullptr;
    mPhysBody = nullptr;
    mAABox.Min = {0.0f, 0.0f, 0.0f};
    mAABox.Max = {0.0f, 0.0f, 0.0f};
    mMotor = nullptr;

    BluePrint = blueprint;
    StandardInit(sim, entityId);
  }

  /**
   * Address: 0x00677F40 (FUN_00677F40, ??0Entity@Moho@@QAE@ABVLuaObject@LuaPlus@@PAVSim@1@VEntId@1@H@Z)
   *
   * LuaPlus::LuaObject const &,Moho::Sim *,Moho::EntId
   *
   * IDA signature:
   * LuaPlus::LuaObject *__userpurge Moho::Entity::Entity@<eax>(Moho::Sim *a1@<edi>, LuaPlus::LuaObject *result, LuaPlus::LuaObject *a2, unsigned int a4);
   *
   * What it does:
   * Initializes Entity base state for Lua-side spawned entities, applies the
   * default collision bucket mask `0x800`, then binds the provided Lua object.
   */
  Entity::Entity(const LuaPlus::LuaObject& luaObject, Sim* sim, const EntId entityId)
    : CollisionShape<Entity>(ResolveEntityCollisionGrid(sim), 0x800u)
    , CTask(nullptr, false)
  {
    std::memset(pad_01BB, 0, sizeof(pad_01BB));
    std::memset(pad_01ED, 0, sizeof(pad_01ED));
    RealtimeStatsEnabled = 0u;
    std::memset(pad_01F9_01FB, 0, sizeof(pad_01F9_01FB));

    id_ = static_cast<EntId>(moho::ToRaw(moho::EEntityIdSentinel::Invalid));
    BluePrint = nullptr;
    mTickCreated = 0u;
    mReserved74 = 0u;

    // +0x78 is `mVarDat`, and its own constructor (0x00558760) writes every
    // default this body used to write by hand -- the unit scale, the 1.0f
    // interpolation and fraction-complete lanes, the invalid attachment-parent
    // sentinel, the inline auxiliary-id vector, `MapPlayableRect` and the
    // zeroed intel lanes. The binary calls it from here too; MSVC emits the
    // call from the member list, so there is no source line for it.

    SimulationRef = nullptr;
    ArmyRef = nullptr;

    mPositionHistory = nullptr;
    mPendingVelocityScale = 1.0f;
    mLastTickProcessed = 0u;
    CollisionExtents = nullptr;

    mQueueRelinkBlocked = 0u;
    DestroyQueuedFlag = 0u;
    mOnDestroyDispatched = 0u;
    mIntelManager = nullptr;
    mVizToFocusPlayer = 2;
    mVizToAllies = 2;
    mVizToEnemies = 4;
    mVizToNeutrals = 2;
    mInterfaceCreated = 0u;
    mScroller = nullptr;
    mPhysBody = nullptr;
    mAABox.Min = {0.0f, 0.0f, 0.0f};
    mAABox.Max = {0.0f, 0.0f, 0.0f};
    mMotor = nullptr;

    StandardInit(sim, entityId);
    SetLuaObject(luaObject);
  }

  /**
   * Address: 0x00678370 (FUN_00678370)
   *
   * What it does:
   * Applies runtime identity ownership (sim/army/id), initializes interface/visibility
   * defaults, registers entity in sim db/lists, and initializes collision shape.
   */
  void Entity::StandardInit(Sim* sim, const EntId entityId)
  {
    SimulationRef = sim;
    ArmyRef = ResolveEntityArmyFromEntityId(sim, entityId);
    id_ = entityId;
    mTickCreated = sim ? sim->mCurTick : 0u;
    mReserved74 = 0u;

    mVarDat.mIsDead = 0u;
    mVarDat.mLayerMask = LAYER_None;
    mPendingVelocityScale = 1.0f;
    mLastTickProcessed = 0u;
    mQueueRelinkBlocked = 0u;
    DestroyQueuedFlag = 0u;
    mOnDestroyDispatched = 0u;
    mScroller = nullptr;
    mPhysBody = nullptr;
    mInterfaceCreated = 0u;

    mVizToFocusPlayer = 2;
    mVizToAllies = 2;
    mVizToEnemies = 4;
    mVizToNeutrals = 2;

    // 0x00678370: `std::map_EntId_Entity::find(&node, sim->mEntityDB, &id); node->second = this;`
    // -- the id node was inserted (null payload) by `EntityDB::DoReserveId`.
    sim->mEntityDB->mAllUnits.find(entityId)->second = this;

    // 0x00678477: this is what makes an entity run at all. The binary pushes
    // the CTask subobject (`lea esi, [ebp+34h]`, matching RTTI's mdisp=52) onto
    // a fresh thread on `[this+0x148] + 0x930` -- `SimulationRef->mTaskStageA`,
    // pinned by `mCurCommandSource` ending at 0x092C -- with `own = false`
    // (`push 0`), between the entity-DB registration above and the collision
    // revert below. Without it nothing ever calls Entity::Execute, so
    // TaskTick/MotionTick never run and no unit is simulated.
    if (sim != nullptr) {
      (void)CTask::CreateTaskThread(static_cast<CTask*>(this), &sim->mTaskStageA, false);
    }

    // 0x0067847E: `call ?RevertCollisionShape@Entity@Moho@@QAEXXZ` -- the
    // blueprint rebuild, which is what gives a freshly-created entity its
    // collision primitive in the first place.
    RevertCollisionShape();

    if (SimulationRef) {
      ListLinkBefore(&SimulationRef->mCoordEntities);
    }

    // 0x006784B5-0x00678570: unique name = blueprint id, then "(%s)" of the
    // blueprint label (+0x24) when it is non-empty, then "-%d" of the entity
    // id's low 16 bits (`movzx ecx, word ptr [id]`). No blueprint -> "".
    if (BluePrint != nullptr) {
      const char* const blueprintId = BluePrint->mBlueprintId.c_str();
      mUniqueName.assign(blueprintId, std::strlen(blueprintId));
      if (!BluePrint->mBlueprintLabel.empty()) {
        mUniqueName += gpg::STR_Printf("(%s)", BluePrint->mBlueprintLabel.c_str());
      }
      mUniqueName += gpg::STR_Printf("-%d", static_cast<int>(static_cast<std::uint16_t>(static_cast<std::uint32_t>(entityId))));
    } else {
      mUniqueName.assign("", 0);
    }
  }

  /**
   * Address: 0x0062AD30 (FUN_0062AD30) / 0x00678880 (FUN_0062AD30/FUN_00678880)
   *
   * What it does:
   * Chooses initial simulation layer from footprint occupancy, category hints,
   * map water elevation and terrain elevation at spawn coordinates.
   */
  ELayer Entity::GetStartingLayer(const Wm3::Vec3f& worldPos, const ELayer desiredLayer) const
  {
    const SFootprint& footprint = GetFootprint();

    // 0x0062AD56-0x0062ADCA: origin cell = fistp-rounded
    // `(pos.x - SizeX*0.5, pos.z - SizeZ*0.5)` (the `SFootprint::ToCellPos`
    // computation, inlined), then `OCCUPY_FootprintFits(*sim->mOGrid, cell,
    // footprint, -1)` -- the live occupancy test against the terrain/water
    // bit arrays, not the footprint's static caps.
    const SOCellPos originCell = footprint.ToCellPos(worldPos);
    const std::uint8_t occupancyMask = static_cast<std::uint8_t>(
      OCCUPY_FootprintFits(*SimulationRef->mOGrid, originCell, footprint, EOccupancyCaps::OC_ANY)
    );

    const bool isExperimental = IsInCategory("EXPERIMENTAL");
    const bool isBeacon = IsInCategory("FERRYBEACON");

    const std::uint8_t desiredMaskBit = LayerToOccupancyBit(desiredLayer);
    if ((occupancyMask & desiredMaskBit) != 0u) {
      return desiredLayer;
    }

    if ((occupancyMask & static_cast<std::uint8_t>(EOccupancyCaps::OC_AIR)) != 0u) {
      return isExperimental ? LAYER_Land : LAYER_Air;
    }

    const STIMap* const mapData = SimulationRef->mMapData;
    const float waterElevation = mapData->IsWaterEnabled() ? mapData->GetWaterElevation() : -10000.0f;
    // 0x0062AEE8: `CHeightField::GetElevation(x, z)` (0x0044FB90) on the map's
    // height field.
    const float terrainElevation = mapData->GetHeightField()->GetElevation(worldPos.x, worldPos.z);

    // 0x0062AEF1: `fcompi` + `jbe` -- unordered also takes the Land exit.
    if (!(waterElevation > terrainElevation)) {
      return LAYER_Land;
    }

    if (HasOccupancyBit(footprint.mOccupancyCaps, static_cast<std::uint8_t>(EOccupancyCaps::OC_SUB)) &&
        !isExperimental) {
      return LAYER_Sub;
    }

    if (HasOccupancyBit(footprint.mOccupancyCaps, static_cast<std::uint8_t>(EOccupancyCaps::OC_WATER)) || isBeacon) {
      return LAYER_Water;
    }

    return LAYER_Seabed;
  }

  /**
   * Address: 0x00678D40 (FUN_00678D40)
   *
   * What it does:
   * Names this entity in script-error warnings as `Entity <blueprintId> at
   * <address>` (format at 0x00E27324, `%08x` of `this`); a blueprint-less
   * entity prints an empty id. This is the `where` of every
   * `Error running %s script in %s: %s` line raised for entities, units,
   * props and projectiles.
   */
  fa::string Entity::GetErrorDescription()
  {
    return gpg::STR_Printf("Entity %s at %08x", GetBlueprintId(), reinterpret_cast<std::uintptr_t>(this));
  }

  /**
   * Address: 0x005BDB10 (FUN_005BDB10)
   */
  Unit* Entity::IsUnit()
  {
    return nullptr;
  }

  /**
   * Address: 0x005BDB20 (FUN_005BDB20)
   */
  Prop* Entity::IsProp()
  {
    return nullptr;
  }

  /**
   * Address: 0x005BDB30 (FUN_005BDB30)
   */
  Projectile* Entity::IsProjectile()
  {
    return nullptr;
  }

  /**
   * Address: 0x00672BB0 (FUN_00672BB0)
   */
  ReconBlip* Entity::IsReconBlip()
  {
    return nullptr;
  }

  /**
   * Address: 0x005BDB40 (FUN_005BDB40)
   */
  CollisionBeamEntity* Entity::IsCollisionBeam()
  {
    return nullptr;
  }

  /**
   * Address: 0x005BDB50 (FUN_005BDB50)
   */
  Shield* Entity::IsShield()
  {
    return nullptr;
  }

  /**
   * Address: 0x00678BB0 (FUN_00678BB0, ?GetBoneCount@Entity@Moho@@UBEHXZ)
   *
   * IDA signature:
   * int __thiscall Moho::Entity::GetBoneCount(Moho::Entity *this);
   *
   * What it does:
   * Resolves the mesh resource's skeleton and returns its bone count, or 0
   * when either is absent. The bone vector belongs to `CAniSkel`, reached
   * through `RScmResource::GetSkeleton` - it is not a span hanging off the
   * resource itself, which is what this used to read and why every unit
   * reported zero bones.
   */
  int Entity::GetBoneCount() const
  {
    auto* const scmResource = mVarDat.mScmResource.get();
    if (scmResource == nullptr) {
      return 0;
    }

    const boost::shared_ptr<const CAniSkel> skeleton = scmResource->GetSkeleton();
    const CAniSkel* const skel = skeleton.get();
    if (skel == nullptr) {
      return 0;
    }

    return static_cast<int>(skel->mBones.size());
  }

  /**
   * Address: 0x00678C30 (FUN_00678C30, ?GetBoneName@Entity@Moho@@QBEPBDH@Z)
   *
   * What it does:
   * Resolves one bone index through the current mesh skeleton and returns the
   * bone-name pointer, or null when the mesh/skeleton lane is unavailable.
   */
  const char* Entity::GetBoneName(const std::uint32_t boneIndex) const
  {
    auto* const scmResource = mVarDat.mScmResource.get();
    if (scmResource == nullptr) {
      return nullptr;
    }

    const boost::shared_ptr<const CAniSkel> skeleton = scmResource->GetSkeleton();
    const CAniSkel* const skel = skeleton.get();
    if (skel == nullptr) {
      return nullptr;
    }

    const SAniSkelBone* const bone = skel->GetBone(boneIndex);
    return (bone != nullptr) ? bone->mBoneName : nullptr;
  }

  /**
   * Address: 0x005BDB90 (FUN_005BDB90, Moho::Entity::GetMesh)
   *
   * What it does:
   * Returns this entity's mesh resource.
   */
  boost::shared_ptr<RScmResource> Entity::GetMesh() const
  {
    return mVarDat.mScmResource;
  }

  /**
   * Address: 0x0062CB60 (FUN_0062CB60, Moho::Entity::IsInBounds)
   *
   * What it does:
   * Tests this entity's current transform position against simulation map
   * bounds with caller-selected whole-map border semantics.
   */
  bool Entity::IsInBounds(const bool wholeMap, const float border) const
  {
    return SimulationRef->mMapData->IsWithin(mVarDat.mCurTransform.pos_, border, wholeMap);
  }

  /**
   * Address: 0x00678B90 (FUN_00678B90, Moho::Entity::GetArmyIndex)
   *
   * What it does:
   * Returns the owning army id when present, otherwise `-1`.
   */
  int Entity::GetArmyIndex() const
  {
    return (ArmyRef != nullptr) ? ArmyRef->mConstDat.mArmyIndex : -1;
  }

  /**
   * Address: 0x00678CC0 (FUN_00678CC0, Moho::Entity::ResolveBoneIndex)
   *
   * What it does:
   * Resolves one bone-name token through the current SCM skeleton, returning
   * `-1` when the mesh/skeleton lane is missing.
   */
  int Entity::ResolveBoneIndex(const char* const boneName) const
  {
    auto* const scmResource = mVarDat.mScmResource.get();
    if (scmResource == nullptr) {
      return -1;
    }

    const boost::shared_ptr<const CAniSkel> skeleton = scmResource->GetSkeleton();
    const CAniSkel* const skel = skeleton.get();
    if (skel == nullptr) {
      return -1;
    }

    return skel->FindBoneIndex(boneName);
  }

  /**
   * Address: 0x005BDB60 (FUN_005BDB60)
   */
  bool Entity::IsBeingBuilt() const
  {
    return mVarDat.mIsBeingBuilt != 0u;
  }

  /**
   * Address: 0x0067A0A0 (FUN_0067A0A0)
   *
   * What it does:
   * Updates visibility + interface sync state and clears dirty-sync marker.
   */
  void Entity::Sync(SSyncData* syncData)
  {
    UpdateVisibility();

    if (mOnDestroyDispatched != 0u || mVarDat.mVisibilityHidden == 0u) {
      if (mInterfaceCreated != 0u) {
        DestroyInterface(syncData);
      }
    } else {
      if (mInterfaceCreated == 0u) {
        CreateInterface(syncData);
      }
      SyncInterface(syncData);
    }

    mVarDat.mRequestRefreshUI = 0u;

    if (mQueueRelinkBlocked == 0u) {
      ListUnlink();
    }
  }

  /**
   * Address: 0x0067A720 (FUN_0067A720, Moho::Entity::SetMesh)
   * Mangled: ?SetMesh@Entity@Moho@@UAEXABVRResId@2@PAVRMeshBlueprint@2@_N@Z
   *
   * What it does:
   * Resolves mesh resource id (or explicit placeholder) and updates mesh
   * binding. When `meshResId.name` is empty, releases the existing mesh
   * shared-resource lane and clears the mesh blueprint slot. Otherwise
   * looks up the mesh blueprint, invokes
   * `RMeshBlueprint::GetMesh` (FUN_0067A5B0) to retrieve the LOD-resolved
   * `boost::shared_ptr<RScmResource>`, and copies it into the entity's
   * borrowed shared-resource lane (`mMeshRef` aliased as
   * `boost::SharedPtrRaw<RScmResource>`). On success, stores the chosen
   * blueprint pointer in `mMeshTypeClassId` (aliased blueprint slot). On
   * failure, falls back to the `explicitPlaceholder` blueprint and runs
   * the same retrieval through `AssignSharedPtrRScmResourceWeak`
   * (FUN_0055AA60). The `allowExplicitPlaceholder` parameter is part of
   * the ABI signature but the shipped binary never branches on it.
   */
  void
  Entity::SetMesh(const RResId& meshResId, RMeshBlueprint* const explicitPlaceholder, const bool allowExplicitPlaceholder)
  {
    static_cast<void>(allowExplicitPlaceholder);

    if (meshResId.name.empty()) {
      boost::ReleaseSharedResource(mVarDat.mScmResource);
      mVarDat.mMeshBlueprint = nullptr;
      return;
    }

    RMeshBlueprint* const meshBlueprint =
      SimulationRef->mRules->GetMeshBlueprint(meshResId);
    if (meshBlueprint == nullptr) {
      return;
    }

    boost::AssignSharedResource(mVarDat.mScmResource, meshBlueprint->GetMesh());

    if (boost::HasSharedResource(mVarDat.mScmResource)) {
      mVarDat.mMeshBlueprint = meshBlueprint;
      return;
    }

    if (explicitPlaceholder != nullptr) {
      boost::AssignSharedResource(mVarDat.mScmResource, explicitPlaceholder->GetMesh());

      if (boost::HasSharedResource(mVarDat.mScmResource)) {
        mVarDat.mMeshBlueprint = explicitPlaceholder;
        return;
      }

      gpg::Warnf(
        "Failed to load ExplicitPlaceholder %s",
        explicitPlaceholder->mBlueprintId.raw_data_unsafe()
      );
      return;
    }

    gpg::Warnf("Failed to load mesh for blueprint %s", meshResId.name.raw_data_unsafe());
  }

  /**
   * Address: 0x0067A8B0 (FUN_0067A8B0, ?ChangeScroller@Entity@Moho@@QAEXABUSScroller@2@@Z)
   *
   * What it does:
   * Creates the entity's texture scroller on first use, then installs
   * `definition` on it. Every `Entity:Add*Scroller` / `RemoveScroller` Lua
   * binding inlines this whole body (e.g. 0x006911F7..0x0069123D in
   * `AddManualScroller`), after reading its arguments.
   */
  void Entity::ChangeScroller(const SScroller& definition)
  {
    if (mScroller == nullptr) {
      // The binary stores the new scroller before deleting the old pointer
      // (0x0067A8C9..0x0067A8E3) -- a reset whose delete is dead here, since
      // the slot was just tested null.
      delete std::exchange(mScroller, new CTextureScroller(this));
    }

    mScroller->SetScroller(definition);
  }

  /**
   * Address: 0x0067A900 (FUN_0067A900, ?UpdateScrollPos@Entity@Moho@@QAEXQAM@Z)
   *
   * What it does:
   * Seeds both texture-scroll lanes from one incoming UV coordinate pair.
   */
  void Entity::UpdateScrollPos(const Wm3::Vec2f& scrollPosition)
  {
    mVarDat.mScrollBeatStart = scrollPosition;
    mVarDat.mScrollBeatEnd = scrollPosition;
  }

  /**
   * Address: 0x0067A930 (FUN_0067A930, ?UpdateScroll@Entity@Moho@@QAEXQAM@Z)
   *
   * What it does:
   * Copies current scroll lane to previous and advances current lane by one
   * delta vector.
   */
  void Entity::UpdateScroll(const Wm3::Vec2f& scrollDelta)
  {
    const Wm3::Vec2f beatEnd = mVarDat.mScrollBeatEnd;
    mVarDat.mScrollBeatStart = beatEnd;
    mVarDat.mScrollBeatEnd.x = beatEnd.x + scrollDelta.x;
    mVarDat.mScrollBeatEnd.y = beatEnd.y + scrollDelta.y;
  }

  /**
   * Address: 0x0067A980 (FUN_0067A980, ?StopScroll@Entity@Moho@@QAEXXZ)
   *
   * What it does:
   * Collapses scroll motion by snapping current lane to previous lane.
   */
  void Entity::StopScroll()
  {
    mVarDat.mScrollBeatEnd = mVarDat.mScrollBeatStart;
  }

  /**
   * Address: 0x00678D80 (FUN_00678D80, ?SetAnimScoll@Entity@Moho@@QAEXMM@Z)
   *
   * What it does:
   * Shifts the current texture-scroll lane into the previous lane and stores
   * one new animation scroll lane pair.
   */
  void Entity::SetAnimScroll(const float scrollX, const float scrollY)
  {
    mVarDat.mScrollBeatStart = mVarDat.mScrollBeatEnd;
    mVarDat.mScrollBeatEnd.x = scrollX;
    mVarDat.mScrollBeatEnd.y = scrollY;
  }

  /**
   * Address: 0x0067A9A0 (FUN_0067A9A0, ?SetAmbientSound@Entity@Moho@@QAEXPAVCSndParams@2@0@Z)
   *
   * What it does:
   * Stores ambient detail and rumble sound parameter lanes.
   */
  void Entity::SetAmbientSound(CSndParams* const detailSound, CSndParams* const rumbleSound)
  {
    mVarDat.mAmbientSound = detailSound;
    mVarDat.mRumbleSound = rumbleSound;
  }

  /**
   * Address: 0x005BDBD0 (FUN_005BDBD0)
   */
  float Entity::GetUniformScale() const
  {
    return 1.0f;
  }

  /**
   * Address: 0x00678DC0 (FUN_00678DC0)
   *
   * What it does:
   * Returns frame velocity from current/previous positions scaled by mVelocityScale.
   */
  Wm3::Vec3f Entity::GetVelocity() const
  {
    Wm3::Vec3f velocity{};
    velocity.x = (mVarDat.mCurTransform.pos_.x - mVarDat.mLastTransform.pos_.x) * mVarDat.mCurImpactValue;
    velocity.y = (mVarDat.mCurTransform.pos_.y - mVarDat.mLastTransform.pos_.y) * mVarDat.mCurImpactValue;
    velocity.z = (mVarDat.mCurTransform.pos_.z - mVarDat.mLastTransform.pos_.z) * mVarDat.mCurImpactValue;
    return velocity;
  }

  /**
   * Address: 0x005BDBF0 (FUN_005BDBF0)
   */
  bool Entity::IsMobile() const
  {
    return true;
  }

  /**
   * What it does:
   * CTask execution entry point for FUN_00679C40. The original secondary
   * vtable invokes TaskTick directly through the CTask subobject.
   */
  int Entity::Execute()
  {
    return TaskTick();
  }

  /**
   * Address: 0x00679C40 (FUN_00679C40, ?TaskTick@Entity@Moho@@EAE?AW4ETaskStatus@2@XZ)
   *
   * What it does:
   * Ticks texture-scroller runtime, advances attach-follow pending transform,
   * updates last-processed tick, prunes invalid shooters, then executes motion.
   */
  int Entity::TaskTick()
  {
    if (CTextureScroller* const scroller = mScroller; scroller != nullptr) {
      scroller->Tick();
    }

    if (Entity* const attachTarget = mAttachInfo.GetAttachTargetEntity(); attachTarget != nullptr) {
      if (attachTarget->mLastTickProcessed == mLastTickProcessed) {
        return -4;
      }

      const VTransform attachedTransform = CalculateAttachedTransform();
      SetPendingTransform(attachedTransform, 1.0f);
    }

    mLastTickProcessed = SimulationRef->mCurTick;
    ProcessEntitiesShootingAtMe();
    return MotionTick();
  }

  /**
   * Address: 0x00679CE0 (FUN_00679CE0)
   * Mangled: ?GetBoneWorldTransform@Entity@Moho@@UBE?AVVTransform@2@H@Z
   *
   * VFTable SLOT: 18. Entity, Prop, Projectile, ReconBlip and Shield all keep
   * this body; Unit (0x006AA5C0) and CollisionBeamEntity (0x006730B0)
   * override it.
   *
   * What it does:
   * Returns one bone's world transform:
   *  - `boneIndex >= 0` (0x00679CEF..0x00679D16): the bone's entity-space
   *    transform from the virtual `GetBoneLocalTransform` (vtable +0x4C,
   *    slot 19), placed under the current transform by
   *    `VTransform::Compose(local, mCurTransform)` (0x00549C20: `eax` = the
   *    slot-19 result, stack = `&mVarDat.mCurTransform`).
   *  - `boneIndex == -1` with a blueprint (0x00679D19..0x00679DC9): the
   *    collision-centre anchor `(CollisionOffsetX, CollisionOffsetY +
   *    SizeY * 0.5, CollisionOffsetZ)`, rotated by the current orientation
   *    through `MultQuadVec` (0x00452D40) and added to the current position.
   *    The orientation is the current one, unchanged.
   *  - any other negative index (the `-2` weapon callers pass, or `-1`
   *    without a blueprint) (0x00679DCC..0x00679E13): the current transform.
   */
  VTransform Entity::GetBoneWorldTransform(const int boneIndex) const
  {
    const VTransform& curTransform = mVarDat.mCurTransform;
    if (boneIndex >= 0) {
      return VTransform::Compose(GetBoneLocalTransform(boneIndex), curTransform);
    }

    if (boneIndex == -1 && BluePrint != nullptr) {
      const Wm3::Vector3f localAnchor{
        BluePrint->mCollisionOffsetX,
        BluePrint->mCollisionOffsetY + BluePrint->mSizeY * 0.5f,
        BluePrint->mCollisionOffsetZ,
      };
      const Wm3::Vector3f rotatedAnchor = RotateVectorByQuaternion(curTransform.orient_, localAnchor);

      VTransform anchorTransform = curTransform;
      anchorTransform.pos_.x += rotatedAnchor.x;
      anchorTransform.pos_.y += rotatedAnchor.y;
      anchorTransform.pos_.z += rotatedAnchor.z;
      return anchorTransform;
    }

    return curTransform;
  }

  /**
   * Address: 0x00679E20 (FUN_00679E20)
   * Mangled: ?GetBoneLocalTransform@Entity@Moho@@UBE?AVVTransform@2@H@Z
   *
   * VFTable SLOT: 19. Kept by the same classes as slot 18, so it is what
   * `GetBoneWorldTransform`'s `boneIndex >= 0` dispatch reaches for Entity,
   * Prop, Projectile, ReconBlip and Shield. Unit (0x006AA440) and
   * CollisionBeamEntity (0x006731A0) override it.
   *
   * What it does:
   * Returns one bone's transform in this entity's local space:
   *  - `boneIndex >= 0` with a mesh (0x00679E2F..0x00679EC3): looks up the bone
   *    in the mesh skeleton (`RScmResource::GetSkeleton` 0x00538DB0,
   *    `CAniSkel::GetBone` 0x00549E20) and inverts its `mBoneTransform`
   *    (`VTransform::Inverse` 0x0046FBF0). It multiplies the translation
   *    lane by lane by `mVarDat.mScale` (0x00679E72..0x00679E99), then
   *    copy-constructs the result (0x0046FC90). The skeleton handle is a
   *    temporary that is released (0x00538320) before its pointer is
   *    null-tested; the entity's mesh resource keeps the skeleton alive.
   *  - `boneIndex == -1` with a blueprint (0x00679EC6..0x00679F30): identity
   *    orientation at the collision-centre anchor `(CollisionOffsetX,
   *    CollisionOffsetY + SizeY * 0.5, CollisionOffsetZ)`.
   *  - otherwise, including a missing mesh, skeleton or bone
   *    (0x00679F33..0x00679F69): the identity transform.
   */
  VTransform Entity::GetBoneLocalTransform(const int boneIndex) const
  {
    if (boneIndex >= 0) {
      if (RScmResource* const scmResource = mVarDat.mScmResource.get(); scmResource != nullptr) {
        const CAniSkel* const skeleton = scmResource->GetSkeleton().get();
        if (skeleton != nullptr) {
          const SAniSkelBone* const bone = skeleton->GetBone(static_cast<std::uint32_t>(boneIndex));
          if (bone != nullptr) {
            VTransform boneTransform = bone->mBoneTransform.Inverse();
            boneTransform.pos_.x *= mVarDat.mScale.x;
            boneTransform.pos_.y *= mVarDat.mScale.y;
            boneTransform.pos_.z *= mVarDat.mScale.z;
            return boneTransform;
          }
        }
      }
    }

    VTransform result{};
    if (boneIndex == -1 && BluePrint != nullptr) {
      result.pos_.x = BluePrint->mCollisionOffsetX;
      result.pos_.y = BluePrint->mCollisionOffsetY + BluePrint->mSizeY * 0.5f;
      result.pos_.z = BluePrint->mCollisionOffsetZ;
    }

    return result;
  }

  /**
   * Address: 0x0067A020 (FUN_0067A020, ?CalculateAttachedTransform@Entity@Moho@@QAE?AVVTransform@2@XZ)
   *
   * What it does:
   * Calculates entity world transform that satisfies current attach-relative
   * payload against parent/child bone transforms.
   */
  VTransform Entity::CalculateAttachedTransform()
  {
    const VTransform childLocalTransform = GetBoneLocalTransform(mAttachInfo.mChildBoneIndex);
    Entity* const parentEntity = mAttachInfo.GetAttachTargetEntity();
    if (parentEntity == nullptr) {
      return {};
    }

    const VTransform parentBoneTransform = parentEntity->GetBoneWorldTransform(mAttachInfo.mParentBoneIndex);
    const VTransform parentComposedTransform = VTransform::Compose(mAttachInfo.mRelativeTransform, parentBoneTransform);
    VTransform attachedTransform = SolveAttachedWorldTransformFromChildLocal(childLocalTransform, parentComposedTransform);
    NormalizeQuatInPlace(&attachedTransform.orient_);
    return attachedTransform;
  }

  /**
   * Address: 0x0067A130 (FUN_0067A130, ?AddShooter@Entity@Moho@@QAEXPAV12@@Z)
   *
   * What it does:
   * Inserts one shooter entry into this entity's shooter ownership set when
   * the shooter pointer is non-null.
   */
  void Entity::AddShooter(Entity* const shooter)
  {
    if (shooter == nullptr) {
      return;
    }

    (void)mShooters.Add(shooter);
  }

  /**
   * Address: 0x0067A160 (FUN_0067A160, ?RemoveShooter@Entity@Moho@@QAEXPAV12@@Z)
   * Mangled: ?RemoveShooter@Entity@Moho@@QAEXPAV12@@Z
   *
   * What it does:
   * Removes `shooter` from this entity's shooter set -- the mirror of
   * `AddShooter`.
   *
   * 0x0067A160..0x0067A16E: `test eax,eax` (the shooter), then
   * `edi = ecx + 0x218` (this->mShooters) and `push eax; call 0x67BCE0`. The
   * set that shrinks is `this`'s. The previous body removed `this` from the
   * argument's set instead, so `UnitWeapon::SetTarget` (whose inlined copy at
   * 0x006D5FB6 removes the unit from the *old target's* set) left every
   * retargeting unit listed as a shooter of its old target forever. Projectiles
   * then reached `mDesiredShooterCap` early and `CAiAttackerImpl::TrackToTarget`
   * (0x005D8253 `cmp shooters, cap; jge skip`) rejected them.
   */
  void Entity::RemoveShooter(Entity* const shooter)
  {
    if (shooter == nullptr) {
      return;
    }

    (void)mShooters.Remove(shooter);
  }

  /**
   * Address: 0x0067A180 (FUN_0067A180, Moho::Entity::GetNumShooters)
   *
   * What it does:
   * Returns the shooter set size from the contiguous pointer lane.
   */
  int Entity::GetNumShooters() const
  {
    return static_cast<int>(mShooters.mVec.end() - mShooters.mVec.begin());
  }

  /**
   * Address: 0x0067A190 (FUN_0067A190, ?ProcessEntitiesShootingAtMe@Entity@Moho@@QAEXXZ)
   *
   * What it does:
   * Removes null/destroyed/dead shooter entries from the shooter container.
   */
  void Entity::ProcessEntitiesShootingAtMe()
  {
    auto& shooters = mShooters.mVec;
    for (Entity** it = shooters.begin(); it != shooters.end();) {
      Entity* const shooter = *it;
      if (shooter == nullptr || shooter->DestroyQueuedFlag != 0u || shooter->mVarDat.mIsDead != 0u) {
        it = shooters.erase(it, it + 1);
      } else {
        ++it;
      }
    }
  }

  /**
   * Address: 0x00679120 (FUN_00679120, Moho::Entity::UpdateIntel)
   *
   * What it does:
   * Pushes current world position (with +1 Y probe offset) into intel manager
   * update path for the current simulation tick.
   */
  void Entity::UpdateIntel()
  {
    if (!mIntelManager || !SimulationRef) {
      return;
    }

    const Wm3::Vec3f probePosition{
      mVarDat.mCurTransform.pos_.x,
      mVarDat.mCurTransform.pos_.y + 1.0f,
      mVarDat.mCurTransform.pos_.z,
    };
    mIntelManager->Update(probePosition, static_cast<std::int32_t>(SimulationRef->mCurTick));
  }

  /**
   * Address: 0x00679290 (FUN_00679290, ?GetPhysBody@Entity@Moho@@QAEPAUSPhysBody@2@_N@Z)
   * Mangled: ?GetPhysBody@Entity@Moho@@QAEPAUSPhysBody@2@_N@Z
   *
   * What it does:
   * Returns cached physics body, lazily constructing it from blueprint-derived
   * mass/inertia/collision-offset lanes and current entity transform when absent.
   */
  SPhysBody* Entity::GetPhysBody(const bool unusedFlag)
  {
    (void)unusedFlag;

    SPhysBody*& cachedBody = mPhysBody;
    if (cachedBody != nullptr) {
      return cachedBody;
    }

    SPhysBodyParams physicsParams{
      1.0f,
      Wm3::Vector3f{1.0f, 1.0f, 1.0f},
      Wm3::Vector3f{0.0f, 0.0f, 0.0f},
    };
    if (BluePrint != nullptr) {
      physicsParams.collisionOffset.x = BluePrint->mCollisionOffsetX;
      physicsParams.collisionOffset.y = (BluePrint->mSizeY * 0.5f) + BluePrint->mCollisionOffsetY;
      physicsParams.collisionOffset.z = BluePrint->mCollisionOffsetZ;
      physicsParams.mass = (BluePrint->mAverageDensity * BluePrint->mSizeZ) * BluePrint->mSizeX * BluePrint->mSizeY;
      physicsParams.inertiaTensor.x = BluePrint->mInertiaTensorX;
      physicsParams.inertiaTensor.y = BluePrint->mInertiaTensorY;
      physicsParams.inertiaTensor.z = BluePrint->mInertiaTensorZ;
    }

    SPhysConstants* const constants = SimulationRef ? SimulationRef->mPhysConstants : nullptr;
    SPhysBody* const newBody = new (std::nothrow) SPhysBody(constants, physicsParams);

    SPhysBody* const oldBody = cachedBody;
    cachedBody = newBody;
    delete oldBody;

    if (cachedBody != nullptr) {
      cachedBody->SetTransform(mVarDat.mCurTransform);
    }

    return cachedBody;
  }

  /**
   * Address: 0x006793D0 (FUN_006793D0, ?AddWorldImpulse@Entity@Moho@@QAEXABV?$Vector3@M@Wm3@@0@Z)
   * Mangled: ?AddWorldImpulse@Entity@Moho@@QAEXABV?$Vector3@M@Wm3@@0@Z
   *
   * What it does:
   * Applies one world-space impulse at one world-space application point into
   * this entity's cached physics-body lane when present.
   */
  void Entity::AddWorldImpulse(const Wm3::Vec3f& impulse, const Wm3::Vec3f& worldPoint)
  {
    SPhysBody* const body = mPhysBody;
    if (body == nullptr) {
      return;
    }

    ApplyWorldImpulseToBody(*body, impulse, worldPoint);
  }

  /**
   * Address: 0x006794D0 (FUN_006794D0, ?AddLocalImpulse@Entity@Moho@@QAEXABV?$Vector3@M@Wm3@@0@Z)
   * Mangled: ?AddLocalImpulse@Entity@Moho@@QAEXABV?$Vector3@M@Wm3@@0@Z
   *
   * What it does:
   * Forwards one local impulse + local-point payload into the cached physics
   * body lane when present.
   */
  void Entity::AddLocalImpulse(const Wm3::Vec3f& localImpulse, const Wm3::Vec3f& localPoint)
  {
    SPhysBody* const body = mPhysBody;
    if (body == nullptr) {
      return;
    }

    body->AddLocalImpulse(localImpulse, localPoint);
  }

  /**
   * Address: 0x00679210 (FUN_00679210)
   *
   * What it does:
   * Writes pending transform, advances twice, then updates entity intel manager.
   */
  void Entity::Warp(const VTransform& transform)
  {
    SetPendingTransform(transform, 1.0f);
    AdvanceCoords();
    AdvanceCoords();

    if (mIntelManager && SimulationRef) {
      const Wm3::Vec3f& position = mVarDat.mCurTransform.pos_;
      const Wm3::Vec3f probePosition{
        position.x,
        position.y + 1.0f,
        position.z,
      };
      mIntelManager->Update(probePosition, static_cast<std::int32_t>(SimulationRef->mCurTick));
    }
  }

  /**
   * Address: 0x00678E90 (FUN_00678E90, ?SetPendingTransform@Entity@Moho@@QAEXABVVTransform@2@M@Z)
   *
   * What it does:
   * Stores pending transform/scalar and links the coord-node into Sim list
   * when it is currently detached.
   */
  void Entity::SetPendingTransform(const VTransform& transform, const float pendingVelocityScale)
  {
    mPendingTransform = transform;
    mPendingVelocityScale = pendingVelocityScale;

    if (SimulationRef && ListIsSingleton()) {
      ListLinkBefore(&SimulationRef->mCoordEntities);
    }
  }

  /**
   * Address: 0x00679F70 (FUN_00679F70)
   *
   * What it does:
   * Advances the active motor when not attached; returns engine task status code.
   */
  int Entity::MotionTick()
  {
    if (!mAttachInfo.HasAttachTarget()) {
      if (!mMotor) {
        return -2;
      }

      mMotor->Update(this);
    }

    return 1;
  }

  /**
   * Address: 0x00679FA0 (FUN_00679FA0)
   *
   * What it does:
   * Replaces entity motor from auto_ptr handoff storage, then wakes the task
   * thread so the new motor actually gets ticked.
   */
  void Entity::SetMotor(fa::auto_ptr<Motor>& motor)
  {
    Motor* const newMotor = motor.release();
    Motor* oldMotor = mMotor;
    mMotor = newMotor;

    if (oldMotor) {
      delete oldMotor;
    }

    if (mMotor) {
      mMotor->BindEntity(this);
    }

    // 0x00679FD5-0x0067A00E is `TaskResume(false, 0)` inlined: read
    // `mOwnerThread` from the CTask subobject (`[esi+40h]` = Entity+0x34+0x0C),
    // zero its pending-frame counter, and - when `mStaged` (`[thread+0x18]`) is
    // set - unlink the thread from the staged list and relink it before the
    // stage's active-thread sentinel, clearing the flag.
    //
    // Without it an entity that gains a motor after creation never runs it.
    // `Entity::MotionTick` returns -2 while `mMotor` is null (0x00679F99), and
    // -2 makes the scheduler stage the thread (0x004092DC), so every prop parks
    // itself on its first beat. `Entity:FallDown()` then installed a
    // `MotorFallDown` onto a thread nothing would step again: trees took their
    // hit and stayed bolt upright, and wreckage never sank.
    TaskResume(false, 0);
  }

  /**
   * Address: 0x005BDC10 (FUN_005BDC10)
   */
  fa::vector<Entity*>& Entity::GetAttachedEntities()
  {
    return mAttachedEntities;
  }

  /**
   * Address: 0x0067A220 (FUN_0067A220, ?CreateInterface@Entity@Moho@@MAEXPAUSSyncData@2@@Z)
   *
   * What it does:
   * Packs the entity identity snapshot into the sync payload's create queue
   * and marks the interface lane created.
   */
  void Entity::CreateInterface(SSyncData* const syncData)
  {
    SCreateEntityParams createParams{};
    createParams.mEntityId = id_;
    createParams.mBlueprint = BluePrint;
    createParams.mTickCreated = static_cast<std::uint32_t>(mTickCreated);
    (void)QueueCreateEntityParams(syncData, createParams);
    mInterfaceCreated = 1u;
  }

  /**
   * Address: 0x0067A260 (FUN_0067A260, ?DestroyInterface@Entity@Moho@@MAEXPAUSSyncData@2@@Z)
   *
   * IDA signature:
   * void __thiscall Moho::Entity::DestroyInterface(Moho::Entity *this, Moho::SSyncData *a2);
   *
   * What it does:
   * Queues this entity's id (`id_`, +0x68) onto the sync packet's delete-id lane
   * (`SSyncData::mDeleteIds`, +0x168) -- `fa::vector<EntId>::push_back`
   * emitted out of line as FUN_0067B810 (`call sub_67B810` at 0x0067A27A),
   * cited on Vector.h's `push_back` -- then clears the interface-created
   * flag (`mInterfaceCreated`, +0x1EC).
   */
  void Entity::DestroyInterface(SSyncData* const syncData)
  {
    syncData->mDeleteIds.push_back(id_);
    mInterfaceCreated = 0u;
  }

  /**
   * Address: 0x0067A290 (FUN_0067A290, ?SyncInterface@Entity@Moho@@MAEXPAUSSyncData@2@@Z)
   *
   * IDA signature:
   * Moho::SSTIEntityVariableData* __thiscall
   * Moho::Entity::SyncInterface(Moho::Entity* this, Moho::SSyncData* arg0);
   *
   * What it does:
   * Snapshots this entity's replicated attachment state into its variable-data
   * block, then queues a `{ id_, mVarDat }` record onto the sync packet's
   * entity-update lane (`SSyncData::mEntityUpdates`, +0x148).
   *   1. Resolves the weak attach parent; writes its id into
   *      `mVarDat.mAttachmentParentRef` (+0x64), or the 0xF0000000 sentinel when
   *      detached / tombstoned.
   *   2. Resizes `mVarDat.mAuxValueVector` (+0x68) to `mAttachedEntities.size()`,
   *      filling each slot with the child entity id (or 0xF0000000 for a null
   *      child).
   *   3. Pushes a default entity-update record and copies `id_` + `mVarDat` into
   *      it via `QueueEntityVariableUpdate`.
   * The IDA return of the stored `SSTIEntityVariableData*` is discarded at every
   * call site, so the override keeps its `void` signature.
   */
  void Entity::SyncInterface(SSyncData* const syncData)
  {
    constexpr std::uint32_t kInvalidEntityId = ToRaw(EEntityIdSentinel::Invalid);

    Entity* const parent = mAttachInfo.GetAttachTargetEntity();
    mVarDat.mAttachmentParentRef = parent ? parent->id_ : kInvalidEntityId;

    mVarDat.mAuxValueVector.resize(
      mAttachedEntities.size(), SSTIEntityAttachInfo{std::bit_cast<std::int32_t>(kInvalidEntityId)}
    );
    for (std::size_t i = 0; i < mAttachedEntities.size(); ++i) {
      Entity* const child = mAttachedEntities[i];
      mVarDat.mAuxValueVector[i].mAttachedEntityId =
        std::bit_cast<std::int32_t>(child ? child->id_ : kInvalidEntityId);
    }
    // The whole block goes to the client verbatim. It is a plain member now, so
    // this is an ordinary argument rather than the `(char*)this + 0x78` cast the
    // flattened spelling forced.
    // sim_ParallelEntitySync finishes the copy on workers after the walk; otherwise the serial queue.
    if (QueueEntityVariableUpdateDeferred(syncData, id_, mVarDat) == nullptr) {
      (void)QueueEntityVariableUpdate(syncData, id_, mVarDat);
    }
  }

  /**
   * Address: 0x00679550 (FUN_00679550, Moho::Entity::AttachTo)
   * Mangled: ?AttachTo@Entity@Moho@@UAE_NABUSEntAttachInfo@2@@Z
   *
   * What it does:
   * Validates parent attach chain, appends this entity to parent attached-list,
   * repairs queued runtime-link state, then applies attach payload into `mAttachInfo`.
   * MSVC inlines the `parentChildren.push_back(this)` fast path here and calls
   * `fa::vector<Entity*>::_Insert_n` (0x0067DB40) directly at 0x0067961C for
   * the capacity-full arm, so no out-of-line `push_back` exists for this element.
   */
  bool Entity::AttachTo(const SEntAttachInfo& attachInfo)
  {
    if (mAttachInfo.HasAttachTarget()) {
      return false;
    }

    Entity* const parent = attachInfo.GetAttachTargetEntity();
    if (!parent) {
      return false;
    }

    for (Entity* ancestor = parent; ancestor != nullptr; ancestor = ancestor->mAttachInfo.GetAttachTargetEntity()) {
      if (ancestor == this) {
        return false;
      }
      if (!ancestor->mAttachInfo.HasAttachTarget()) {
        break;
      }
    }

    fa::vector<Entity*>& parentChildren = parent->GetAttachedEntities();
    if (std::find(parentChildren.begin(), parentChildren.end(), this) != parentChildren.end()) {
      return false;
    }

    parentChildren.push_back(this);

    // 0x00679621-0x00679660. `[edi+40h]` is the CTask subobject's
    // `mOwnerThread` (Entity+0x34 + CTask+0x0C), the same field `SetMotor`
    // wakes, and what follows the hoisted `mStaged` test is
    // `CTask::TaskResume(false, 0)` inlined - null check, pending-frame
    // counter zeroed, unlink from the staged list, relink before the stage's
    // active sentinel, flag cleared.
    //
    // It matters because an entity with no motor stages itself on its first
    // beat (`Entity::MotionTick` returns -2 while `mMotor` is null), and
    // `TaskTick`'s attach-follow arm is what keeps an attached entity glued to
    // its parent's transform every beat. On a thread nobody resumes, that arm
    // never runs again.
    //
    // This was previously modelled as a list-repair pass over a
    // `{next, prev, owner, pendingValue, queuedFlag}` node read out of
    // `mSubtask` (CTask+0x10). That read the wrong field and did the wrong
    // thing; the offsets only lined up because a task thread and the invented
    // node happened to share a shape.
    if (mOwnerThread != nullptr && mOwnerThread->mStaged) {
      TaskResume(false, 0);
    }

    ApplyAttachInfo(mAttachInfo, attachInfo);
    return true;
  }

  /**
   * Address: 0x006796F0 (FUN_006796F0)
   *
   * What it does:
   * Removes this entity from parent attached-list and applies detached defaults
   * to the local attach-info block.
   */
  bool Entity::DetachFrom(Entity* parent, bool)
  {
    if (!parent) {
      return false;
    }

    fa::vector<Entity*>& parentChildren = parent->GetAttachedEntities();
    for (Entity** it = parentChildren.begin(); it != parentChildren.end(); ++it) {
      if (*it != this) {
        continue;
      }

      parentChildren.erase(it);

      SEntAttachInfo detached;
      ApplyAttachInfo(mAttachInfo, detached);

      return true;
    }

    return false;
  }

  /**
   * Address: 0x006797E0 (FUN_006797E0)
   */
  void Entity::AttachedEntityDestroyed(Entity* const attached)
  {
    // 0x006797E0: `lea eax, [esp+4]; push eax` -- the entity rides along as the
    // script's argument (RunScript_Ent, 0x0067F180).
    RunScriptEntity("OnAttachedDestroyed", attached);
  }

  /**
   * Address: 0x00679800 (FUN_00679800)
   */
  void Entity::AttachedEntityKilled(Entity* const attached)
  {
    // 0x00679800: `lea eax, [esp+4]; push eax` -- the entity rides along as the
    // script's argument (RunScript_Ent, 0x0067F180).
    RunScriptEntity("OnAttachedKilled", attached);
  }

  /**
   * Address: 0x00679820 (FUN_00679820)
   */
  void Entity::ParentEntityDestroyed(Entity* const parent)
  {
    // 0x00679820: `lea eax, [esp+4]; push eax` -- the entity rides along as the
    // script's argument (RunScript_Ent, 0x0067F180).
    RunScriptEntity("OnParentDestroyed", parent);
  }

  /**
   * Address: 0x00679840 (FUN_00679840)
   */
  void Entity::ParentEntityKilled(Entity* const parent)
  {
    // 0x00679840: `lea eax, [esp+4]; push eax` -- the entity rides along as the
    // script's argument (RunScript_Ent, 0x0067F180).
    RunScriptEntity("OnParentKilled", parent);
  }

  /**
   * Address: 0x005BDC20 (FUN_005BDC20)
   */
  float Entity::Materialize(float)
  {
    return 0.0f;
  }

  /**
   * Address: 0x005BDC60 (FUN_005BDC60)
   *
   * What it does:
   * Returns the cached intel manager pointer lane.
   */
  CIntel* Entity::GetIntelManager() const noexcept
  {
    return mIntelManager;
  }

  /**
   * Address: 0x00678E20 (FUN_00678E20, ?UpdateFractionComplete@Entity@Moho@@QAEMM@Z)
   *
   * What it does:
   * Accumulates completion fraction by `delta`, enforces binary clamp rules
   * and health-derived floor, then returns the applied fraction delta.
   */
  float Entity::UpdateFractionComplete(const float delta)
  {
    if (delta == 0.0f) {
      return 0.0f;
    }

    const float previousFraction = mVarDat.mFractionComplete;
    float nextFraction = previousFraction + delta;
    float healthFloor = 0.0f;

    // 0x00678E3B `comiss delta, 0` / `jbe`: an unordered delta takes the
    // non-positive branch. Both max clamps (0x00678E48, 0x00678E6A) are
    // `comiss 1.0, next` / `ja` -- keep `next` only when strictly below 1.0.
    if (!(delta > 0.0f)) {
      if (!(1.0f > nextFraction)) {
        nextFraction = 1.0f;
      }
    } else {
      if (!(1.0f > nextFraction)) {
        nextFraction = 1.0f;
      }
      if (nextFraction < 0.0f) {
        nextFraction = 0.0f;
      }
      healthFloor = mVarDat.mHealth / mVarDat.mMaxHealth;
    }

    if (healthFloor > nextFraction) {
      nextFraction = healthFloor;
    }

    mVarDat.mFractionComplete = nextFraction;
    return nextFraction - previousFraction;
  }

  /**
   * Address: 0x00679940 (FUN_00679940, Moho::Entity::SetHealth)
   * Mangled: ?SetHealth@Entity@Moho@@QAEXPAV12@M@Z
   *
   * What it does:
   * Sets absolute health, logs the change, fires the "OnHealthChanged" script
   * callback with the new and previous quantized (0.25-step) health fractions
   * when the bucket changes, then re-queues this entity at the front of the Sim
   * coord-dirty list.
   */
  void Entity::SetHealth(const float newHealth)
  {
    // The binary divides by MaxHealth unconditionally -- there is no MaxHealth<=0
    // guard in the original; callers guarantee a positive MaxHealth for a live
    // entity. The two health fractions are quantized to 0.25 steps via floor().
    const float invMaxHealth = 1.0f / mVarDat.mMaxHealth;
    const float nextBucket = std::floor(invMaxHealth * newHealth * 4.0f) * 0.25f;
    const float prevBucket = std::floor(invMaxHealth * mVarDat.mHealth * 4.0f) * 0.25f;

    mVarDat.mHealth = newHealth;

    SimulationRef->Logf(
      "Entity[0x%08x]->SetHealth(%.1f [0x%08x])\n",
      static_cast<std::uint32_t>(id_),
      newHealth,
      std::bit_cast<std::uint32_t>(newHealth));

    if (nextBucket != prevBucket) {
      RunScriptNum2("OnHealthChanged", nextBucket, prevBucket);
    }

    // Unlink from the current list and re-insert immediately after the Sim
    // coord-dirty list sentinel (front). The binary does this unconditionally,
    // regardless of whether the node was already linked.
    ListLinkBefore(&SimulationRef->mCoordEntities);
  }

  /**
   * Address: 0x00679860 (FUN_00679860, Moho::Entity::AdjustHealth)
   * Mangled: ?AdjustHealth@Entity@Moho@@UAEXPAV12@M@Z
   *
   * What it does:
   * Logs the requested delta, then applies it clamped to [0, MaxHealth] unless
   * the "NoDamage" sim cheat blocks a negative delta or the entity is dead and
   * the delta would heal it. The (unused) first parameter is the instigator.
   */
  void Entity::AdjustHealth(Entity*, const float delta)
  {
    SimulationRef->Logf(
      "Entity[0x%08x]->AdjustHealth(%.5f)\n",
      static_cast<std::uint32_t>(id_),
      delta);

    // Only an exact-zero delta short-circuits (0x00679893, `ucomiss`/`jnp`); a
    // NaN delta passes. It does not reach SetHealth as NaN, though: the max
    // clamp below (0x006798F4 `comiss max, next` / `ja`) treats an unordered
    // compare as "not below max" and writes MaxHealth.
    if (delta == 0.0f) {
      return;
    }

    // The "NoDamage" sim convar blocks all damage (negative deltas); a dead
    // entity cannot be healed (positive delta). Combined skip guard matches the
    // binary at 0x006798A4-0x006798DB.
    CSimConVarInstanceBase* const noDamageVar = SimulationRef->GetSimVar(&moho::gSimConVar_NoDamage);
    const bool noDamage = *static_cast<const std::uint8_t*>(noDamageVar->GetValueStorage()) != 0;
    if ((noDamage && delta < 0.0f) || (mVarDat.mIsDead && delta > 0.0f)) {
      return;
    }

    float next = mVarDat.mHealth + delta;
    // 0x006798F4: keep `next` only when strictly below max (NaN -> max).
    if (!(mVarDat.mMaxHealth > next)) {
      next = mVarDat.mMaxHealth;
    }
    if (next < 0.0f) {
      next = 0.0f;
    }
    if (next != mVarDat.mHealth) {
      SetHealth(next);
    }
  }

  /**
   * Address: 0x00679A80 (FUN_00679A80)
   *
   * What it does:
   * Dispatches attached/parent killed notifications and marks entity dead/dirty.
   */
  void Entity::Kill(Entity*, gpg::StrArg, float)
  {
    Entity* const parent = mAttachInfo.GetAttachTargetEntity();
    if (parent) {
      parent->AttachedEntityKilled(this);
    }

    // 0x00679AAC..0x00679AD3. The cursor (`edi`) is loaded once from
    // `_Myfirst`, but `_Mylast` is re-read out of `[esi+184h]` on every
    // iteration - for the entry test at 0x00679AB2 and again for the loop-back
    // test at 0x00679ACD. That reload is load bearing, not a missed
    // optimisation: `ParentEntityKilled` runs the `OnParentKilled` script, and
    // a script that detaches or destroys a sibling reaches
    // `Entity::DetachFrom`, which erases from this very vector. A cached `end()`
    // then walks one slot past the live range and dereferences the stale copy
    // the erase left behind - which is a freed `Entity` whenever the sibling was
    // being destroyed. Re-reading `end()` stops at the shortened range, exactly
    // as the shipped loop does.
    for (Entity** child = mAttachedEntities.begin(); child != mAttachedEntities.end(); ++child) {
      if (*child) {
        (*child)->ParentEntityKilled(this);
      }
    }

    mVarDat.mRequestRefreshUI = 1;
    mVarDat.mIsDead = 1;
  }

  /**
   * Address: 0x00679B80 (FUN_00679B80, ?OnDestroy@Entity@Moho@@...)
   *
   * What it does:
   * Marks destroy dispatch, appends this entity to the entity DB's
   * pending-destroy list (`SimulationRef->mEntityDB->mEntList`, no null
   * checks), emits the script callback, detaches from the parent, and
   * notifies attached children.
   */
  void Entity::OnDestroy()
  {
    mOnDestroyDispatched = 1;
    SimulationRef->mEntityDB->mEntList.push_back(this);
    CallbackStr("OnDestroy");

    Entity* const parent = mAttachInfo.GetAttachTargetEntity();
    if (parent) {
      parent->AttachedEntityDestroyed(this);
      (void)DetachFrom(parent, false);
    }

    // 0x00679C15..0x00679C36, the same reload-`_Mylast`-every-iteration shape as
    // `Kill` above, and load bearing for the same reason: `ParentEntityDestroyed`
    // runs the `OnParentDestroyed` script, whose own `Destroy` calls re-enter
    // this function on a sibling and erase it from this vector.
    for (Entity** child = mAttachedEntities.begin(); child != mAttachedEntities.end(); ++child) {
      if (*child) {
        (*child)->ParentEntityDestroyed(this);
      }
    }
  }

  /**
   * Address: 0x00679AF0 (FUN_00679AF0, ?Destroy@Entity@Moho@@QAEXXZ)
   *
   * What it does:
   * Marks this entity as destroy-queued once, enqueues it into `Sim::mDeletionQueue`,
   * logs the queue event, and re-inserts the coord node at the front of the sim
   * coord list (unlink + ListLinkAfter the sentinel, matching the binary).
   */
  void Entity::Destroy()
  {
    if (DestroyQueuedFlag != 0u) {
      return;
    }

    DestroyQueuedFlag = 1u;
    SimulationRef->mDeletionQueue.push_back(this);
    SimulationRef->Logf("Entity 0x%08x queued for delete.\n", static_cast<unsigned int>(id_));

    ListLinkBefore(&SimulationRef->mCoordEntities);
  }

  /**
   * Address: 0x00679180 (FUN_00679180, ?UpdateAABox@Entity@Moho@@QAEXXZ)
   *
   * What it does:
   * Reads one world-space AABB from the active collision primitive into
   * `mAABox` (+0x240).
   */
  void Entity::UpdateAABox()
  {
    if (CollisionExtents == nullptr) {
      return;
    }

    mAABox = CollisionExtents->GetBoundingBox();
  }

  /**
   * Address: 0x006791D0 (FUN_006791D0)
   *
   * What it does:
   * Pushes current transform to collision primitive, relinks collision-cell
   * bucket membership, and refreshes cached world-space bounds at +0x240.
   */
  void Entity::UpdateCollision()
  {
    if (!CollisionExtents) {
      return;
    }

    auto* collision = CollisionExtents;
    collision->SetTransform(mVarDat.mCurTransform);
    UpdateRect(collision);
    UpdateAABox();
  }

  /**
   * Address: 0x0067A9B0 (FUN_0067A9B0, ?Intersects@Entity@Moho@@QAE_NABV?$Sphere3@M@Wm3@@PAUCollisionResult@2@@Z)
   *
   * What it does:
   * Tests one world sphere against this entity's active collision primitive.
   * On hit, stamps this entity as the collision source lane in `outResult`.
   */
  bool Entity::Intersects(const Wm3::Sphere3f& sphere, CollisionResult* const outResult)
  {
    CColPrimitiveBase* const collision = CollisionExtents;
    if (collision == nullptr || !collision->CollideSphere(&sphere, outResult)) {
      return false;
    }

    outResult->sourceEntity = this;
    return true;
  }

  /**
   * Address: 0x0067A9D0 (FUN_0067A9D0, ?Intersects@Entity@Moho@@QAE_NABV?$Box3@M@Wm3@@PAUCollisionResult@2@@Z)
   *
   * What it does:
   * Tests one world-space box against this entity's active collision primitive.
   * On hit, stamps this entity as the collision source lane in `outResult`.
   */
  bool Entity::Intersects(const Wm3::Box3f& box, CollisionResult* const outResult)
  {
    CColPrimitiveBase* const collision = CollisionExtents;
    if (collision == nullptr || !collision->CollideBox(&box, outResult)) {
      return false;
    }

    outResult->sourceEntity = this;
    return true;
  }

  /**
   * Address: 0x0067A9F0 (FUN_0067A9F0, ?Intersects@Entity@Moho@@QAE_NABV?$Vector3@M@Wm3@@0PAUCollisionSegmentResult@2@@Z)
   *
   * What it does:
   * Tests one world line segment against this entity's active collision
   * primitive. On hit, stamps this entity as the collision source lane in
   * `outResult`.
   */
  bool Entity::Intersects(
    const Wm3::Vec3f& lineStart,
    const Wm3::Vec3f& lineEnd,
    CollisionSegmentResult* const outResult
  )
  {
    CColPrimitiveBase* const collision = CollisionExtents;
    if (collision == nullptr || !collision->CollideLine(&lineStart, &lineEnd, outResult)) {
      return false;
    }

    outResult->sourceEntity = this;
    return true;
  }

  /**
   * Address: 0x0067AA50 (FUN_0067AA50, ?GetTerrainCollisionGeom@Entity@Moho@@QBEXAAV?$fastvector@V?$Sphere3@M@Wm3@@@gpg@@@Z)
   *
   * What it does:
   * Emits one terrain-collision proxy sphere list from the active collision
   * primitive: eight corner points for box primitives, or one center/radius
   * sphere for sphere primitives.
   *
   * 0x0067AA57 loads `CollisionExtents` and calls through its vtable with no
   * null test, so an entity whose script ran `SetCollisionShape('None')` must
   * never get here. Its only caller, `CUnitMotion::HandleGroundCollision`, is
   * unreachable in FAF's build (patched out of `CalcMoveAir` at 0x006C018B).
   */
  void Entity::GetTerrainCollisionGeom(gpg::fastvector<Wm3::Sphere3f>& outSpheres) const
  {
    Wm3::Vec3f center{};
    CollisionExtents->GetCenter(&center);

    if (const Wm3::Box3f* const box = CollisionExtents->GetBox(); box != nullptr) {
      const float minX = center.x - box->Extent[0];
      const float maxX = center.x + box->Extent[0];
      const float minY = center.y - box->Extent[1];
      const float maxY = center.y + box->Extent[1];
      const float minZ = center.z - box->Extent[2];
      const float maxZ = center.z + box->Extent[2];

      outSpheres.resize(8u, Wm3::Sphere3f{});
      outSpheres[0].Center = Wm3::Vec3f(minX, minY, minZ);
      outSpheres[0].Radius = 0.0f;
      outSpheres[1].Center = Wm3::Vec3f(maxX, minY, minZ);
      outSpheres[1].Radius = 0.0f;
      outSpheres[2].Center = Wm3::Vec3f(minX, maxY, minZ);
      outSpheres[2].Radius = 0.0f;
      outSpheres[3].Center = Wm3::Vec3f(maxX, maxY, minZ);
      outSpheres[3].Radius = 0.0f;
      outSpheres[4].Center = Wm3::Vec3f(minX, minY, maxZ);
      outSpheres[4].Radius = 0.0f;
      outSpheres[5].Center = Wm3::Vec3f(maxX, minY, maxZ);
      outSpheres[5].Radius = 0.0f;
      outSpheres[6].Center = Wm3::Vec3f(minX, maxY, maxZ);
      outSpheres[6].Radius = 0.0f;
      outSpheres[7].Center = Wm3::Vec3f(maxX, maxY, maxZ);
      outSpheres[7].Radius = 0.0f;
      return;
    }

    if (const Wm3::Sphere3f* const sphere = CollisionExtents->GetSphere(); sphere != nullptr) {
      outSpheres.resize(1u, Wm3::Sphere3f{});
      outSpheres[0].Center = center;
      outSpheres[0].Radius = sphere->Radius;
    }
  }

  /**
    * Alias of FUN_0067AC40 (non-canonical helper lane).
   *
   * What it does:
   * Builds a box collision primitive from supplied local box and installs it.
   */
  void Entity::SetCollisionBoxShape(const Wm3::Box3f& localBox)
  {
    InstallCollisionPrimitiveAndRefresh(*this, new CColPrimitive<Wm3::Box3f>(localBox));
  }

  /**
    * Alias of FUN_0067AD30 (non-canonical helper lane).
   *
   * What it does:
   * Builds a sphere collision primitive from local center/radius and installs it.
   */
  void Entity::SetCollisionSphereShape(const Wm3::Vec3f& localCenter, const float radius)
  {
    InstallCollisionPrimitiveAndRefresh(*this, new CColPrimitive<Wm3::Sphere3f>(localCenter, radius));
  }

  /**
   * Address: 0x0067AE00 (FUN_0067AE00, ?SetCollisionShapeNone@Entity@Moho@@QAEXXZ)
   *
   * What it does:
   * Clears active collision primitive and resets collision-cell span to zero.
   */
  void Entity::SetCollisionShapeNone()
  {
    InstallCollisionPrimitiveAndRefresh(*this, nullptr);
  }

  /**
   * Address: 0x0067AE70 (FUN_0067AE70, ?RevertCollisionShape@Entity@Moho@@QAEXXZ)
   *
   * What it does:
   * Recreates the collision primitive from the blueprint shape descriptor.
   *
   * 0x0067AE7D: a null blueprint tail-jumps to `SetCollisionShapeNone`
   * (0x0067AFE8), and `mCollisionShape` (blueprint +0xA8) then selects between
   * that same clear (0), the box builder (1) and the sphere builder (2); any
   * other value returns having touched nothing (0x0067AE9A -> 0x0067AEE9).
   */
  void Entity::RevertCollisionShape()
  {
    if (!BluePrint) {
      SetCollisionShapeNone();
      return;
    }

    switch (BluePrint->mCollisionShape) {
    case COLSHAPE_None:
      SetCollisionShapeNone();
      break;
    case COLSHAPE_Box:
      SetCollisionBoxShape(BuildBlueprintCollisionBox(*BluePrint));
      break;
    case COLSHAPE_Sphere: {
      // 0x0067AE9C-0x0067AEC4: the sphere's radius is `mSizeX * 0.5`, and it is
      // that same radius -- not `mSizeY * 0.5` -- that is added to
      // `mCollisionOffsetY` to lift the centre off the ground.
      const float radius = BluePrint->mSizeX * 0.5f;
      const Wm3::Vec3f localCenter{
        BluePrint->mCollisionOffsetX,
        BluePrint->mCollisionOffsetY + radius,
        BluePrint->mCollisionOffsetZ,
      };
      SetCollisionSphereShape(localCenter, radius);
      break;
    }
    default:
      break;
    }
  }

  void Entity::MarkNeedsSyncGameData() noexcept
  {
    mVarDat.mRequestRefreshUI = 1;
  }

  /**
   * Address: 0x00689F60 (FUN_00689F60)
   *
   * What it does:
   * Copies this entity's draw-scale triple `(x,y,z)` into caller storage.
   */
  Wm3::Vector3f* CopyEntityDrawScaleToVector(
    Wm3::Vector3f* const outScale,
    const Entity* const entity
  ) noexcept
  {
    outScale->x = entity->mVarDat.mScale.x;
    outScale->y = entity->mVarDat.mScale.y;
    outScale->z = entity->mVarDat.mScale.z;
    return outScale;
  }

  /**
   * Address: 0x00689F80 (FUN_00689F80)
   *
   * What it does:
   * Stores one draw-scale triple and relinks this entity's coord node before
   * the simulation coord-entities head.
   */
  TDatListItem<Entity, EntityDirtyList>* SetEntityDrawScaleAndRelinkCoordNode(
    Entity* const entity,
    const Wm3::Vector3f* const drawScale
  ) noexcept
  {
    entity->mVarDat.mScale.x = drawScale->x;
    entity->mVarDat.mScale.y = drawScale->y;
    entity->mVarDat.mScale.z = drawScale->z;

    entity->ListLinkBefore(&entity->SimulationRef->mCoordEntities);
    return entity;
  }

  /**
   * Address: 0x00689F20 (FUN_00689F20, Moho::Entity::GetUniqueName)
   *
   * What it does:
   * Returns the entity's unique runtime name string.
   */
  fa::string Entity::GetUniqueName() const
  {
    return fa::string(mUniqueName.data(), mUniqueName.size());
  }

  /**
   * Address: 0x00689F50 (FUN_00689F50)
   *
   * What it does:
   * Returns whether per-entity realtime-stats accounting is currently enabled
   * for this entity (gates the shots-fired / hit-miss / fire-range stat lanes).
   */
  bool Entity::IsRealtimeStatsEnabled() const noexcept
  {
    return RealtimeStatsEnabled != 0u;
  }

  /**
   * Address: 0x00678B70 (FUN_00678B70, ?GetBlueprintId@Entity@Moho@@QBEPBDXZ)
   *
   * What it does:
   * Returns the bound blueprint id text lane, or process-static empty string
   * when this entity has no blueprint.
   */
  const char* Entity::GetBlueprintId() const noexcept
  {
    return ResolveEntityBlueprintId(this);
  }

  /**
   * Address: 0x00678880 (FUN_00678880, ?GetFootprint@Entity@Moho@@QBEABUSFootprint@2@XZ)
   *
   * What it does:
   * Returns active footprint (default or alt footprint).
   * Throws when blueprint pointer is missing.
   */
  const SFootprint& Entity::GetFootprint() const
  {
    if (!BluePrint) {
      throw std::runtime_error("Attempt to get footprint on nameless entity");
    }

    // FAF hot-patch: 0x006788A5 jumps to 0x0128E836 in .exxt, which adds the
    // +0x11D byte (mUsingAltFootprintSecondary) as a second alt-footprint test.
    const bool useAlt = (mVarDat.mUsingAltFootprint != 0u) || (mVarDat.mUsingAltFootprintSecondary != 0u);
    return useAlt ? BluePrint->mAltFootprint : BluePrint->mFootprint;
  }

  /**
   * Address: 0x0067AFF0 (FUN_0067AFF0, ?SetCurrentLayer@Entity@Moho@@QAEXW4ELayer@2@@Z)
   *
   * What it does:
   * Updates current layer and issues `OnLayerChange(new, old)` callback.
   */
  void Entity::SetCurrentLayer(const ELayer newLayer)
  {
    const ELayer oldLayer = mVarDat.mLayerMask;
    mVarDat.mLayerMask = newLayer;
    if (newLayer == oldLayer) {
      return;
    }

    const char* oldName = LayerToString(oldLayer);
    const char* newName = LayerToString(newLayer);
    const char* newNameArg = newName;
    const char* oldNameArg = oldName;
    CallbackStr("OnLayerChange", &newNameArg, &oldNameArg);
  }

  /**
   * Address: 0x0067B050 (FUN_0067B050)
   *
   * What it does:
   * Resolves category text through Sim rules and tests the blueprint category bit.
   */
  bool Entity::IsInCategory(const char* categoryName) const noexcept
  {
    if (!categoryName || !BluePrint || !SimulationRef || !SimulationRef->mRules) {
      return false;
    }

    const EntityCategorySet* const range = SimulationRef->mRules->GetEntityCategory(categoryName);
    if (!range) {
      return false;
    }

    const std::uint32_t bitIndex = ReadBlueprintCategoryBitIndex(BluePrint);
    const auto wordIt = range->FindWord(bitIndex >> 5u);
    if (wordIt == range->WordEnd()) {
      return false;
    }

    return (((*wordIt) >> (bitIndex & 0x1Fu)) & 1u) != 0u;
  }

  /**
   * Address: 0x0067B0C0 (FUN_0067B0C0, ?SetStrategicUnderlay@Entity@Moho@@QAEXABVRResId@2@@Z)
   *
   * What it does:
   * Resolves one strategic underlay icon id into
   * `/textures/ui/common/game/strategicicons/<icon>_rest.dds`,
   * updates the underlay texture pointer, and relinks this entity in the
   * coord-entities update list.
   */
  void Entity::SetStrategicUnderlay(const RResId& underlayId)
  {
    if (underlayId.name.empty()) {
      mVarDat.mUnderlayTexture.reset();
#if FAF_SERVER_MODE
      faf::remote::SetUnderlayPath(static_cast<std::uint32_t>(id_), std::string());
#endif
      return;
    }

    const char* const underlayName = underlayId.name.c_str();
    if (FILE_IsAbsolute(underlayName)) {
      return;
    }

    std::string underlayPath("/textures/ui/common/game/strategicicons/");
    underlayPath.append(underlayName, std::strlen(underlayName));
    underlayPath.append("_rest.dds", 9u);

    // Engine addition (plan WPL.4): the texture is the client's
    // (CD3DBatchTexture.h sBatchTextureFromFile); without a client there is none.
    mVarDat.mUnderlayTexture =
      sBatchTextureFromFile != nullptr ? sBatchTextureFromFile(underlayPath.c_str(), 0u) : boost::shared_ptr<CD3DBatchTexture>{};
#if FAF_SERVER_MODE
    // Engine addition, server mode: the path, for the frames (remote/UnderlayPaths.h).
    faf::remote::SetUnderlayPath(static_cast<std::uint32_t>(id_), underlayPath);
#endif

    ListLinkBefore(&SimulationRef->mCoordEntities);
  }

  /**
   * Address: 0x005BDC70 (FUN_005BDC70, ?SetStrategicUnderlay@Entity@Moho@@QAEXV?$shared_ptr@VCD3DBatchTexture@Moho@@@boost@@@Z)
   * Mangled: ?SetStrategicUnderlay@Entity@Moho@@QAEXV?$shared_ptr@VCD3DBatchTexture@Moho@@@boost@@@Z
   *
   * What it does:
   * Updates strategic-underlay texture pointer/control lanes from one by-value
   * shared handle when the incoming raw texture pointer differs.
   */
  void Entity::SetStrategicUnderlay(boost::shared_ptr<CD3DBatchTexture> underlayTexture)
  {
    if (mVarDat.mUnderlayTexture.get() == underlayTexture.get()) {
      return;
    }

    mVarDat.mUnderlayTexture = underlayTexture;
  }

  /**
   * Address: 0x005BDD20 (FUN_005BDD20, ?GetStrategicUnderlay@Entity@Moho@@QBE?AV?$shared_ptr@VCD3DBatchTexture@Moho@@@boost@@XZ)
   * Mangled: ?GetStrategicUnderlay@Entity@Moho@@QBE?AV?$shared_ptr@VCD3DBatchTexture@Moho@@@boost@@XZ
   *
   * What it does:
   * Returns one retained shared strategic-underlay texture handle.
   */
  boost::shared_ptr<CD3DBatchTexture> Entity::GetStrategicUnderlay() const
  {
    return mVarDat.mUnderlayTexture;
  }

  Wm3::Vec3f const& Entity::GetPositionWm3() const noexcept
  {
    return mVarDat.mCurTransform.pos_;
  }

  VTransform const& Entity::GetTransformWm3() const noexcept
  {
    return mVarDat.mCurTransform;
  }

  /**
   * Address: 0x00678800 (FUN_00678800, ?InitPositionHistory@Entity@Moho@@QAEXXZ)
   *
   * What it does:
   * Rebuilds the rolling position-history ring with identity/default samples.
   */
  void Entity::InitPositionHistory()
  {
    PositionHistory* const rebuiltHistory = new (std::nothrow) PositionHistory;

    delete mPositionHistory;
    mPositionHistory = rebuiltHistory;
  }

  /**
   * Address: 0x006794F0 (FUN_006794F0, ?GetPositionHistory@Entity@Moho@@QBEABVVTransform@2@H@Z)
   *
   * What it does:
   * Maps one requested tick to the rolling 25-entry position-history ring and
   * returns the selected sample as a `VTransform` view.
   */
  VTransform const& Entity::GetPositionHistory(const int tick) const
  {
    const PositionHistory* const positionHistory = mPositionHistory;
    const std::int32_t delta = positionHistory->cursor - tick;
    const std::int32_t historyIndex = (delta < 0)
      ? (((delta + 1) % PositionHistory::kSampleCount) + (PositionHistory::kSampleCount - 1))
      : (delta % PositionHistory::kSampleCount);
    return positionHistory->samples[static_cast<std::size_t>(historyIndex)];
  }

  /**
   * Address: 0x00678F10 (FUN_00678F10, ?AdvanceCoords@Entity@Moho@@QAEXXZ)
   *
   * What it does:
   * Commits pending transform to current, archives previous/current snapshots,
   * updates collision when movement changed, runs intel force-update pass,
   * then relinks coord node into Sim's coord-entities list when needed.
   */
  void Entity::AdvanceCoords()
  {

    mVarDat.mLastTransform = mVarDat.mCurTransform;
    mVarDat.mCurTransform = mPendingTransform;
    mVarDat.mCurImpactValue = mPendingVelocityScale;

    if (mPositionHistory) {
      mPositionHistory->samples[mPositionHistory->cursor] = mVarDat.mLastTransform;
      mPositionHistory->cursor = (mPositionHistory->cursor + 1) % PositionHistory::kSampleCount;
      mPositionHistory->samples[mPositionHistory->cursor] = mVarDat.mCurTransform;
    }

    if (CollisionExtents &&
        (mVarDat.mLastTransform.pos_ != mVarDat.mCurTransform.pos_ ||
         mVarDat.mLastTransform.orient_ != mVarDat.mCurTransform.orient_)) {
      UpdateCollision();
    }

    if (mIntelManager && SimulationRef) {
      const Wm3::Vec3f& position = mVarDat.mCurTransform.pos_;
      const Wm3::Vec3f probePosition{
        position.x,
        position.y + 1.0f,
        position.z,
      };
      mIntelManager->ForceUpdate(probePosition, static_cast<std::int32_t>(SimulationRef->mCurTick));
    }

    if (SimulationRef && ListIsSingleton()) {
      ListLinkBefore(&SimulationRef->mCoordEntities);
    }
  }

  void Entity::AdvanceCoordsOwn(CollisionShapeBase::DeferredRelink& relink)
  {
    mVarDat.mLastTransform = mVarDat.mCurTransform;
    mVarDat.mCurTransform = mPendingTransform;
    mVarDat.mCurImpactValue = mPendingVelocityScale;

    if (mPositionHistory) {
      mPositionHistory->samples[mPositionHistory->cursor] = mVarDat.mLastTransform;
      mPositionHistory->cursor = (mPositionHistory->cursor + 1) % PositionHistory::kSampleCount;
      mPositionHistory->samples[mPositionHistory->cursor] = mVarDat.mCurTransform;
    }

    relink = CollisionShapeBase::DeferredRelink{};
    if (CollisionExtents &&
        (mVarDat.mLastTransform.pos_ != mVarDat.mCurTransform.pos_ ||
         mVarDat.mLastTransform.orient_ != mVarDat.mCurTransform.orient_)) {
      CollisionShapeBase::SetDeferredRelinkSlot(&relink);
      UpdateCollision();
      CollisionShapeBase::SetDeferredRelinkSlot(nullptr);
    }
  }

  void Entity::AdvanceCoordsShared(const CollisionShapeBase::DeferredRelink& relink)
  {
    CollisionShapeBase::ApplyDeferredRelink(relink);

    if (mIntelManager && SimulationRef) {
      const Wm3::Vec3f& position = mVarDat.mCurTransform.pos_;
      const Wm3::Vec3f probePosition{
        position.x,
        position.y + 1.0f,
        position.z,
      };
      mIntelManager->ForceUpdate(probePosition, static_cast<std::int32_t>(SimulationRef->mCurTick));
    }

    if (SimulationRef && ListIsSingleton()) {
      ListLinkBefore(&SimulationRef->mCoordEntities);
    }
  }

  /**
   * Address: 0x00678A70 (FUN_00678A70, Moho::Entity::UpdateVisibility)
   * Mangled: ?UpdateVisibility@Entity@Moho@@MAEXXZ
   *
   * What it does:
   * Resolves this entity's current visibility mode (mFootprintLayer @0x114) and
   * its not-hidden flag (mVisibilityState @0x110) for the active sync focus army.
   * With no owning army the entity uses its neutral channel and is flagged
   * not-visible. Otherwise: if the focus army is this entity's own army (or
   * there is no focus, index -1) the focus-player channel is used; else the
   * channel is chosen from the alliance relation between this entity's army and
   * the focus army (neutral/ally/enemy). The not-hidden flag is set for every
   * channel except VIZMODE_Never.
   */
  void Entity::UpdateVisibility()
  {
    // No owning army: resolve to the neutral channel and flag it VISIBLE.
    // 0x00678A73 reads `[edi+14Ch]` (ArmyRef) and branches on it; the no-army
    // arm copies `[edi+1E8h]` (mVizToNeutrals) into `[edi+114h]`
    // (mFootprintLayer) and then does `mov byte ptr [edi+110h], 1` at
    // 0x00678A89 -- mVisibilityState = 1, unconditionally, with no VIZMODE_Never
    // test. Unowned entities are always published; only the army-relative arms
    // below can suppress one.
    //
    // This comment used to say "flagged not-visible" while the code beside it
    // set 1. The code was right.
    if (ArmyRef == nullptr) {
      mVarDat.mVisibilityMode = static_cast<EUserEntityVisibilityMode>(mVizToNeutrals);
      mVarDat.mVisibilityHidden = 1;
      return;
    }

    const std::int32_t focusArmy = SimulationRef->mSyncFilter.focusArmy;

    std::int32_t viz;
    if (focusArmy == GetArmyIndex() || focusArmy == -1) {
      // The sync focus is this entity's own army (or unfocused): use the
      // focus-player channel directly. (0x00678AA4-0x00678AB0)
      viz = mVizToFocusPlayer;
    } else {
      // Otherwise pick the channel by the alliance relation between this
      // entity's army and the focus army. (0x00678AB5-0x00678AF2)
      CArmyImpl* focusArmyImpl = nullptr;
      const fa::vector<CArmyImpl*>& armies = SimulationRef->mArmiesList;
      if (static_cast<std::uint32_t>(focusArmy) < armies.size()) {
        focusArmyImpl = armies[static_cast<std::size_t>(focusArmy)];
      }

      switch (ArmyRef->GetAllianceWith(focusArmyImpl)) {
        case ALLIANCE_Neutral:
          mVarDat.mVisibilityMode = static_cast<EUserEntityVisibilityMode>(mVizToNeutrals);
          mVarDat.mVisibilityHidden = static_cast<std::uint8_t>(mVizToNeutrals != VIZMODE_Never);
          return;
        case ALLIANCE_Ally:
          mVarDat.mVisibilityMode = static_cast<EUserEntityVisibilityMode>(mVizToAllies);
          mVarDat.mVisibilityHidden = static_cast<std::uint8_t>(mVizToAllies != VIZMODE_Never);
          return;
        case ALLIANCE_Enemy:
          viz = mVizToEnemies;
          break;
        default:
          gpg::HandleAssertFailure(
            "Reached the supposably unreachable.", 354,
            "c:\\work\\rts\\main\\code\\src\\sim\\Entity.cpp");
          viz = mVizToEnemies;
          break;
      }
    }

    mVarDat.mVisibilityMode = static_cast<EUserEntityVisibilityMode>(viz);
    mVarDat.mVisibilityHidden = static_cast<std::uint8_t>(viz != VIZMODE_Never);
  }

  /**
   * Address: 0x00678930 (FUN_00678930, Moho::Entity::SetVizToFocusPlayer)
   *
   * What it does:
   * Updates focus-player visibility mode, refreshes derived visibility state,
   * and queues this entity in Sim coord-visibility refresh list when needed.
   */
  void Entity::SetVizToFocusPlayer(const EVisibilityMode mode)
  {
    mVizToFocusPlayer = static_cast<std::int32_t>(mode);
    UpdateVisibility();
    if (SimulationRef != nullptr && ListIsSingleton()) {
      ListLinkBefore(&SimulationRef->mCoordEntities);
    }
  }

  /**
   * Address: 0x00678980 (FUN_00678980, Moho::Entity::SetVizToEnemies)
   *
   * What it does:
   * Updates enemy visibility mode, refreshes derived visibility state,
   * and queues this entity in Sim coord-visibility refresh list when needed.
   */
  void Entity::SetVizToEnemies(const EVisibilityMode mode)
  {
    mVizToEnemies = static_cast<std::int32_t>(mode);
    UpdateVisibility();
    if (SimulationRef != nullptr && ListIsSingleton()) {
      ListLinkBefore(&SimulationRef->mCoordEntities);
    }
  }

  /**
   * Address: 0x006789D0 (FUN_006789D0, Moho::Entity::SetVizToAllies)
   *
   * What it does:
   * Updates allied visibility mode, refreshes derived visibility state,
   * and queues this entity in Sim coord-visibility refresh list when needed.
   */
  void Entity::SetVizToAllies(const EVisibilityMode mode)
  {
    mVizToAllies = static_cast<std::int32_t>(mode);
    UpdateVisibility();
    if (SimulationRef != nullptr && ListIsSingleton()) {
      ListLinkBefore(&SimulationRef->mCoordEntities);
    }
  }

  /**
   * Address: 0x00678A20 (FUN_00678A20, Moho::Entity::SetVizToNeutrals)
   *
   * What it does:
   * Updates neutral visibility mode, refreshes derived visibility state,
   * and queues this entity in Sim coord-visibility refresh list when needed.
   */
  void Entity::SetVizToNeutrals(const EVisibilityMode mode)
  {
    mVizToNeutrals = static_cast<std::int32_t>(mode);
    UpdateVisibility();
    if (SimulationRef != nullptr && ListIsSingleton()) {
      ListLinkBefore(&SimulationRef->mCoordEntities);
    }
  }


  /**
   * Address: 0x00692580 (FUN_00692580, Moho::ENTSCR_ResolveBoneIndex)
   *
   * What it does:
   * Resolves one Lua bone identifier (integer index, string name, or optional
   * nil lane) into one validated entity bone index.
   */
  int ENTSCR_ResolveBoneIndex(
    Entity* const entity,
    LuaPlus::LuaStackObject& boneIdentifier,
    const bool allowNilAndSpecialIndices
  )
  {
    if (!entity || !boneIdentifier.m_state || !boneIdentifier.m_state->m_state) {
      return -1;
    }

    LuaPlus::LuaState* const state = boneIdentifier.m_state;
    lua_State* const rawState = state->m_state;
    const int stackIndex = boneIdentifier.m_stackIndex;

    if (lua_type(rawState, stackIndex) == LUA_TNUMBER) {
      if (lua_type(rawState, stackIndex) != LUA_TNUMBER) {
        boneIdentifier.TypeError("integer");
      }

      const int boneIndex = static_cast<int>(lua_tonumber(rawState, stackIndex));
      const int minBoneIndex = allowNilAndSpecialIndices ? -2 : 0;
      const int boneCount = entity->GetBoneCount();
      if (boneIndex < minBoneIndex || boneIndex >= boneCount) {
        LuaPlus::LuaState::Error(
          state,
          "Invalid bone index of %d; must be bettern %d (inclusive) and %d (exclusive)",
          boneIndex,
          minBoneIndex,
          boneCount
        );
      }
      return boneIndex;
    }

    if (lua_isstring(rawState, stackIndex) != 0) {
      const char* boneName = lua_tostring(rawState, stackIndex);
      if (!boneName) {
        boneIdentifier.TypeError("string");
        boneName = "";
      }

      const int boneIndex = entity->ResolveBoneIndex(boneName);
      if (boneIndex < 0) {
        LuaPlus::LuaState::Error(state, "Invalid bone name \"%s\".", boneIdentifier.GetString());
      }
      return boneIndex;
    }

    if (allowNilAndSpecialIndices) {
      if (lua_type(rawState, stackIndex) == LUA_TNIL) {
        return -1;
      }

      LuaPlus::LuaState::Error(state, "Invalid bone identifier; must be a string or integer");
      return -1;
    }

    LuaPlus::LuaState::Error(state, "Invalid bone identifier; must be a string, integer, or nil");
    return -1;
  }

  /**
   * Address: 0x006926C0 (FUN_006926C0, Moho::ENTSCR_GetBonePosition)
   * Mangled: ?ENTSCR_GetBonePosition@Moho@@YA?AV?$Vector3@M@Wm3@@PAVEntity@1@AAVLuaStackObject@LuaPlus@@_N@Z
   *
   * What it does:
   * Resolves one bone index and returns the corresponding world-space position lane.
   */
  Wm3::Vector3f ENTSCR_GetBonePosition(
    Entity* const entity,
    LuaPlus::LuaStackObject& boneIdentifier,
    [[maybe_unused]] const bool allowNilAndSpecialIndices
  )
  {
    // Binary hard-codes AL=1 for the resolve call in this helper.
    const int boneIndex = ENTSCR_ResolveBoneIndex(entity, boneIdentifier, true);
    const VTransform boneWorldTransform = entity->GetBoneWorldTransform(boneIndex);
    return boneWorldTransform.pos_;
  }

  /**
   * Address: 0x0050B300 (FUN_0050B300, ?COORDS_Orient@Moho@@YA?AV?$Quaternion@M@Wm3@@MMM@Z)
   *
   * What it does:
   * Builds a heading/pitch orientation quaternion from half-angle sine/cosine
   * products, preserving the original lane order used by camera/weapon code.
   *
   * The binary composes a pitch-then-heading quaternion product with an
   * identity third factor (roll = 0, folded away at compile time - the
   * `* cos(0.0)` / `* sin(0.0)` terms throughout FUN_0050B300.c are exactly
   * `*1.0` / `*0.0`), and stores the four terms to consecutive offsets:
   *   [eax+00] = cosHeading*cosPitch
   *   [eax+04] = sinPitch*cosHeading
   *   [eax+08] = sinHeading*cosPitch
   *   [eax+0C] = -(sinHeading*sinPitch)
   *
   * Offset 0 therefore carries the scalar, which is what `Wm3::Quaternionf`
   * spells `.w` (`m_afTuple[0]`). IDA's own struct for the type names offset
   * 0 `x`, so the decompile's `dest->x = ...` line is lane 0, not `.x` - and
   * reading that literally is how this body came to sit one lane out of
   * step, scalar in `.x`, with `COORDS_Orient(0, 0)` returning a 180-degree
   * rotation instead of the identity.
   *
   * The corrected assignment is exactly the Hamilton product
   * qHeading (cH, 0, sH, 0) * qPitch (cP, sP, 0, 0):
   *   w = cH*cP,  v = cH*(sP,0,0) + cP*(0,sH,0) + (0,sH,0)x(sP,0,0)
   *             = (cH*sP, cP*sH, -sH*sP)
   * which is an independent confirmation of the lane order above.
   */
  Wm3::Quaternionf COORDS_Orient(const float heading, const float pitch) noexcept
  {
    const float halfHeading = heading * 0.5f;
    const float halfPitch = pitch * 0.5f;

    const float cosHeading = fa::cos(halfHeading);
    const float sinHeading = fa::sin(halfHeading);
    const float cosPitch = fa::cos(halfPitch);
    const float sinPitch = fa::sin(halfPitch);

    Wm3::Quaternionf orientation{};
    orientation.w = cosHeading * cosPitch;
    orientation.x = sinPitch * cosHeading;
    orientation.y = sinHeading * cosPitch;
    orientation.z = -(sinHeading * sinPitch);
    return orientation;
  }

  /**
   * Address: 0x0050B480 (FUN_0050B480, ?COORDS_Orient@Moho@@YA?AV?$Quaternion@M@Wm3@@ABV?$Vector3@M@3@@Z)
   *
   * What it does:
   * Builds an orientation quaternion whose forward axis follows `direction`,
   * with fixed fallback quaternions for zero-length and vertical vectors.
   */
  Wm3::Quaternionf COORDS_Orient(const Wm3::Vector3f& direction) noexcept
  {
    Wm3::Vector3f forward = direction;
    if (Wm3::Vector3f::Normalize(&forward) == 0.0f) {
      return Wm3::Quaternionf::Identity();
    }

    Wm3::Vector3f right{forward.z, 0.0f, -forward.x};
    if (Wm3::Vector3f::Normalize(&right) == 0.0f) {
      // Straight up / straight down: a quarter turn about X, whose sign
      // follows the vertical direction. Memory lanes are
      // {kHalfSqrtTwo, +-kHalfSqrtTwo, 0, 0} - scalar first, matching
      // COORDS_Orient(heading, pitch) above and the binary's `QuatToMatrix`.
      // The previous form put the scalar in lane 1, which reads back as a
      // 180-degree turn about (1, +-1, 0) and sends forward to -forward
      // instead of up/down.
      constexpr float kHalfSqrtTwo = 0.70710677f;
      const float pitchLane = direction.y > 0.0f ? -kHalfSqrtTwo : kHalfSqrtTwo;
      return Wm3::Quaternionf{kHalfSqrtTwo, pitchLane, 0.0f, 0.0f};
    }

    const Wm3::Vector3f up{
      (forward.y * right.z) - (forward.z * right.y),
      (forward.z * right.x) - (right.z * forward.x),
      (right.y * forward.x) - (forward.y * right.x),
    };

    // 0x0050B480 hands the three rows (right, up, forward) to func_MatrixToQuat
    // (0x004EB3F0), whose lane order is the engine's rows-as-axes convention
    // (x = m12 - m21, y = m20 - m02, z = m01 - m10). The previous inline
    // trace conversion used the column-vector signs and produced the conjugate,
    // so every unit faced the mirror of its path heading while walking.
    const Wm3::Vector3f rows[3] = {right, up, forward};
    Wm3::Quaternionf orientation{};
    (void)MatrixToQuat(rows, &orientation);
    return orientation;
  }

  /**
   * Address: 0x0050B620 (FUN_0050B620, ?COORDS_ForwardVector@Moho@@YA?AV?$Vector3@M@Wm3@@MM@Z)
   *
   * What it does:
   * Converts heading/pitch radians into one forward vector using the engine's
   * original trigonometric sign convention.
   */
  Wm3::Vector3f COORDS_ForwardVector(const float heading, const float pitch) noexcept
  {
    const float cosPitch = fa::cos(pitch);

    Wm3::Vector3f result{};
    result.x = fa::sin(heading) * cosPitch;
    result.y = -fa::sin(pitch);
    result.z = cosPitch * fa::cos(heading);
    return result;
  }

  /**
   * Address: 0x0050B710 (FUN_0050B710, ?COORDS_Pitch@Moho@@YAMABV?$Vector3@M@Wm3@@@Z)
   *
   * What it does:
   * Computes the negative fast-asin pitch approximation used by the engine's
   * aim and sound lanes from a 3D velocity vector.
   */
  [[nodiscard]] float COORDS_Pitch(const Wm3::Vector3f& velocity) noexcept
  {
    const float length = std::sqrt((velocity.x * velocity.x) + (velocity.y * velocity.y) + (velocity.z * velocity.z));
    const float normalizedY = velocity.y / length;
    const float rootTerm = std::sqrt(1.0f - normalizedY);
    const float polynomial =
      normalizedY * (((normalizedY * -0.018729299f) + 0.074261002f) * normalizedY - 0.21211439f) + 1.5707288f;
    return (rootTerm * polynomial) - kHalfPi;
  }

  /**
   * Address: 0x0050B790 (FUN_0050B790, ?COORDS_Pitch@Moho@@YAMABV?$Quaternion@M@Wm3@@@Z)
   *
   * What it does:
   * Computes pitch from quaternion orientation lanes using the binary's
   * clamped fast-asin polynomial path.
   */
  [[nodiscard]] float COORDS_Pitch(const Wm3::Quaternionf& orientation) noexcept
  {
    float clamped =
      ((orientation.w * orientation.z) - (orientation.y * orientation.x)) * -2.0f;
    if (clamped > 1.0f) {
      clamped = 1.0f;
    }
    if (clamped < -1.0f) {
      clamped = -1.0f;
    }

    const float rootTerm = std::sqrt(1.0f - clamped);
    const float polynomial =
      clamped * (((clamped * -0.018729299f) + 0.074261002f) * clamped - 0.21211439f) + 1.5707288f;
    return kHalfPi - (rootTerm * polynomial);
  }

  /**
   * Address: 0x0050B820 (FUN_0050B820, ?COORDS_Tilt@Moho@@YAXPAV?$Quaternion@M@Wm3@@V?$Vector3@M@3@@Z)
   *
   * What it does:
   * Tilts one orientation so its local up-axis aligns to `surfaceNormal`,
   * preserving heading by pre-multiplying one shortest-arc delta quaternion.
   *
   * Ground truth (`FUN_0050B820.c`) re-derived term-by-term: the final
   * compose is `*orientation = tiltDelta * oldOrientation` (delta left/
   * first, existing orientation right/second) using `tiltDelta.w` as the
   * delta's scalar lane -- matching `BuildTiltShortestArcDelta`'s corrected
   * labelling, not the generic `Wm3::Quaternionf::Multiply` (`.w`-scalar on
   * both operands). Same pattern as `cfunc_EntityPushOverL`, which shares
   * this helper.
   */
  void COORDS_Tilt(Wm3::Quaternionf* const orientation, Wm3::Vector3f surfaceNormal) noexcept
  {
    if (orientation == nullptr) {
      return;
    }

    // 0x0050B829: Wm3 `Vector3::Normalize` (0x00452AF0); 0x0050B836 `jbe`
    // exits on `len <= 0` AND on an unordered (NaN) length.
    if (!(Wm3::Vector3f::Normalize(&surfaceNormal) > 0.0f)) {
      return;
    }

    const Wm3::Quaternionf oldOrientation = *orientation;
    const Wm3::Vector3f currentUp{
      ((oldOrientation.y * oldOrientation.x) - (oldOrientation.w * oldOrientation.z)) * 2.0f,
      1.0f - (((oldOrientation.z * oldOrientation.z) + (oldOrientation.x * oldOrientation.x)) * 2.0f),
      ((oldOrientation.z * oldOrientation.y) + (oldOrientation.w * oldOrientation.x)) * 2.0f,
    };

    Wm3::Quaternionf tiltDelta{};
    (void)BuildTiltShortestArcDelta(surfaceNormal, &tiltDelta, currentUp);

    // 0x0050B8DA..0x0050B9C4 inlines `tiltDelta * oldOrientation` with its own
    // accumulation order, which differs from `MultiplyQuat`'s
    // (CAniPoseBone::Rotate's emission) in the x and z lanes. Float addition
    // does not associate, so the grouping is kept exactly.
    const Wm3::Quaternionf& d = tiltDelta;
    const Wm3::Quaternionf& q = oldOrientation;
    Wm3::Quaternionf tilted{};
    tilted.w = ((q.w * d.w - q.x * d.x) - q.y * d.y) - q.z * d.z;
    tilted.x = ((q.z * d.y + q.x * d.w) + q.w * d.x) - q.y * d.z;
    tilted.y = ((q.w * d.y + q.x * d.z) + q.y * d.w) - q.z * d.x;
    tilted.z = ((q.w * d.z + q.z * d.w) + q.y * d.x) - q.x * d.y;
    *orientation = tilted;
  }

  /**
   * Address: 0x0050AE10 (FUN_0050AE10, ?COORDS_StringToLayer@Moho@@YA?AW4ELayer@1@PBD@Z)
   *
   * What it does:
   * Maps canonical layer text names to enum lanes and returns `LAYER_None`
   * when no supported name matches.
   */
  ELayer COORDS_StringToLayer(const char* const layerName) noexcept
  {
    if (_stricmp(layerName, "Land") == 0) {
      return LAYER_Land;
    }
    if (_stricmp(layerName, "Seabed") == 0) {
      return LAYER_Seabed;
    }
    if (_stricmp(layerName, "Sub") == 0) {
      return LAYER_Sub;
    }
    if (_stricmp(layerName, "Water") == 0) {
      return LAYER_Water;
    }
    if (_stricmp(layerName, "Air") == 0) {
      return LAYER_Air;
    }
    return _stricmp(layerName, "Orbit") == 0 ? LAYER_Orbit : LAYER_None;
  }

  /**
   * Address: 0x0050AF80 (FUN_0050AF80, ?COORDS_ToRect@Moho@@YA?AV?$Rect2@H@gpg@@ABUSOCellPos@1@ABUSFootprint@1@@Z)
   *
   * What it does:
   * Converts one footprint-origin cell position and footprint dimensions into
   * one half-open cell rectangle.
   */
  gpg::Rect2i COORDS_ToRect(const SOCellPos& cellPos, const SFootprint& footprint) noexcept
  {
    gpg::Rect2i result{};
    result.x0 = static_cast<int>(cellPos.x);
    result.z0 = static_cast<int>(cellPos.z);
    result.x1 = result.x0 + static_cast<int>(footprint.mSizeX);
    result.z1 = result.z0 + static_cast<int>(footprint.mSizeZ);
    return result;
  }

  /**
   * Address: 0x0050AFA0 (FUN_0050AFA0, Moho::COORDS_ToGridRect)
   *
   * IDA signature:
   * _DWORD *__usercall Moho::COORDS_ToGridRect@<eax>(
   *   _DWORD *result@<eax>, float *centerXZ@<ecx>, int sizeX@<edi>, int sizeZ@<esi>);
   *
   * What it does:
   * Computes the axis-aligned integer grid rectangle that a footprint of
   * dimensions `sizeX × sizeZ` occupies when centered at world coordinates
   * `centerXZ`. The corners are rounded to nearest by `fistp`
   * (0x0050AFC6/0x0050AFE6), then narrowed to `int16` (the binary's `WORD`
   * cast).
   */
  gpg::Rect2i* COORDS_ToGridRect(gpg::Rect2i* const result, const SCoordsVec2& centerXZ, const int sizeX, const int sizeZ)
  {
    const std::int16_t halfSizeX =
      static_cast<std::int16_t>(fa::RoundToInt(centerXZ.x - (static_cast<float>(sizeX) * 0.5f)));
    const std::int16_t halfSizeZ =
      static_cast<std::int16_t>(fa::RoundToInt(centerXZ.z - (static_cast<float>(sizeZ) * 0.5f)));
    result->x0 = halfSizeX;
    result->z0 = halfSizeZ;
    result->x1 = sizeX + halfSizeX;
    result->z1 = sizeZ + halfSizeZ;
    return result;
  }

  /**
   * Address: 0x0050B010 (FUN_0050B010, Moho::COORDS_ToGridRect)
   *
   * IDA signature:
   * gpg::Rect2i *callcnv_F3 Moho::COORDS_ToGridRect@<eax>(
   *   gpg::Rect2i *result@<eax>, Moho::SCoordsVec2 *centerXZ@<edx>, Moho::SFootprint *footprint@<ecx>);
   *
   * What it does:
   * Footprint-typed overload of `COORDS_ToGridRect`: delegates to the raw
   * integer-dimensions overload using the footprint's `mSizeX`/`mSizeZ`.
   */
  gpg::Rect2i* COORDS_ToGridRect(gpg::Rect2i* const result, const SCoordsVec2& centerXZ, const SFootprint& footprint)
  {
    return COORDS_ToGridRect(
      result, centerXZ, static_cast<int>(footprint.mSizeX), static_cast<int>(footprint.mSizeZ)
    );
  }

  /**
   * Address: 0x0050B090 (FUN_0050B090, ?COORDS_Elevation@Moho@@YAMPBVSTIMap@1@MME@Z)
   *
   * What it does:
   * Samples terrain elevation and optionally clamps it to water elevation when
   * the requested layer is not seabed-capable.
   */
  float COORDS_Elevation(const STIMap* const map, const float x, const float z, const ELayer layer) noexcept
  {
    const float terrainElevation = map->mHeightField->GetElevation(x, z);
    if ((static_cast<std::uint8_t>(layer) & static_cast<std::uint8_t>(LAYER_Seabed)) != 0u) {
      return terrainElevation;
    }

    if (map->mWaterEnabled == 0u) {
      return terrainElevation;
    }

    return (map->mWaterElevation > terrainElevation) ? map->mWaterElevation : terrainElevation;
  }

  /**
   * Address: 0x0050B0F0 (FUN_0050B0F0, ?COORDS_ToWorldPos@Moho@@YA?AV?$Vector3@M@Wm3@@PBVSTIMap@1@ABUSOCellPos@1@EHH@Z)
   *
   * What it does:
   * Converts one footprint-origin cell position into world center position and
   * samples terrain/water elevation by requested layer.
   */
  Wm3::Vector3f
  COORDS_ToWorldPos(const STIMap* const map, const SOCellPos& cellPos, const ELayer layer, const int sizeX, const int sizeZ) noexcept
  {
    Wm3::Vector3f outPos{};
    const float worldX = static_cast<float>(cellPos.x) + (static_cast<float>(sizeX) * 0.5f);
    const float worldZ = static_cast<float>(cellPos.z) + (static_cast<float>(sizeZ) * 0.5f);
    outPos.x = worldX;
    outPos.z = worldZ;

    const CHeightField* const field = map->mHeightField.get();
    const float terrainElevation = field->GetElevation(worldX, worldZ);
    if ((static_cast<std::int32_t>(layer) & static_cast<std::int32_t>(LAYER_Seabed)) != 0 || map->mWaterEnabled == 0u) {
      outPos.y = terrainElevation;
    } else {
      outPos.y = (map->mWaterElevation > terrainElevation) ? map->mWaterElevation : terrainElevation;
    }

    return outPos;
  }

  /**
   * Address: 0x0050B1A0 (FUN_0050B1A0, ?COORDS_ToWorldPos@Moho@@YA?AV?$Vector3@M@Wm3@@PBVSTIMap@1@ABUSOCellPos@1@ABUSFootprint@1@@Z)
   *
   * What it does:
   * Convenience overload that converts one cell position using a footprint's
   * layer and dimensions.
   */
  Wm3::Vector3f COORDS_ToWorldPos(const STIMap* const map, const SOCellPos& cellPos, const SFootprint& footprint) noexcept
  {
    return COORDS_ToWorldPos(
      map,
      cellPos,
      static_cast<ELayer>(static_cast<std::uint8_t>(footprint.mOccupancyCaps)),
      static_cast<int>(footprint.mSizeX),
      static_cast<int>(footprint.mSizeZ)
    );
  }

  /**
   * Address: 0x0050B1D0 (FUN_0050B1D0, ?COORDS_ToWorldPos@Moho@@YA?AV?$Vector3@M@Wm3@@PBVSTIMap@1@ABUSCoordsVec2@1@ABUSFootprint@1@@Z)
   *
   * What it does:
   * Builds one world-space vector from raw XZ coordinates and samples
   * elevation using footprint occupancy and water rules.
   */
  Wm3::Vector3f COORDS_ToWorldPos(const STIMap* const map, const SCoordsVec2& worldPos, const SFootprint& footprint) noexcept
  {
    Wm3::Vector3f outPos{};
    outPos.x = worldPos.x;
    outPos.z = worldPos.z;

    const CHeightField* const field = map->mHeightField.get();
    const float terrainElevation = field->GetElevation(worldPos.x, worldPos.z);
    const bool seabedOnly =
      (static_cast<std::uint8_t>(footprint.mOccupancyCaps) & static_cast<std::uint8_t>(LAYER_Seabed)) != 0u;
    if (seabedOnly || map->mWaterEnabled == 0u || map->mWaterElevation <= terrainElevation) {
      outPos.y = terrainElevation;
    } else {
      outPos.y = map->mWaterElevation;
    }

    return outPos;
  }

  /**
   * Address: 0x0050B260 (FUN_0050B260, ?COORDS_GridSnap@Moho@@YA?AV?$Vector3@M@Wm3@@PBVSTIMap@1@ABUSCoordsVec2@1@ABUSFootprint@1@W4ELayer@1@@Z)
   *
   * What it does:
   * Snaps one world XZ center to footprint-origin cell coordinates and returns
   * the corresponding world-aligned snapped position.
   */
  Wm3::Vector3f
  COORDS_GridSnap(const STIMap* const map, const SCoordsVec2& worldPos, const SFootprint& footprint, ELayer layer) noexcept
  {
    if (layer == LAYER_None) {
      layer = static_cast<ELayer>(static_cast<std::uint8_t>(footprint.mOccupancyCaps));
    }

    SOCellPos cellPos{};
    cellPos.x = static_cast<std::int16_t>(static_cast<int>(std::lrintf(worldPos.x - (static_cast<float>(footprint.mSizeX) * 0.5f))));
    cellPos.z = static_cast<std::int16_t>(static_cast<int>(std::lrintf(worldPos.z - (static_cast<float>(footprint.mSizeZ) * 0.5f))));
    return COORDS_ToWorldPos(
      map,
      cellPos,
      layer,
      static_cast<int>(footprint.mSizeX),
      static_cast<int>(footprint.mSizeZ)
    );
  }

  /**
   * Address: 0x0050AD80 (FUN_0050AD80, ?COORDS_LayerToString@Moho@@YAPBDW4ELayer@1@@Z)
   *
   * What it does:
   * Maps canonical single-layer enum values to their text names and returns an
   * empty string for mixed-bit layer masks.
   */
  const char* Entity::LayerToString(const ELayer layer) noexcept
  {
    switch (layer) {
    case LAYER_None:
      return "None";
    case LAYER_Land:
      return "Land";
    case LAYER_Seabed:
      return "Seabed";
    case LAYER_Sub:
      return "Sub";
    case LAYER_Water:
      return "Water";
    case LAYER_Air:
      return "Air";
    case LAYER_Orbit:
      return "Orbit";
    default:
      return "";
    }
  }
}


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(PreregisterEntityPointerType_26ac7a, moho::PreregisterEntityPointerType)

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
  struct EntityLuaFuncDefBootstrap
  {
    EntityLuaFuncDefBootstrap()
    {
      (void)::moho::func_EntityCreateProjectile_LuaFuncDef();
      (void)::moho::func_EntityCreateProjectileAtBone_LuaFuncDef();
      (void)::moho::func_EntityShakeCamera_LuaFuncDef();
      (void)::moho::func_GetBlueprintSim_LuaFuncDef();
      (void)::moho::func__c_CreateEntity_LuaFuncDef();
      (void)::moho::func_EntityGetAIBrain_LuaFuncDef();
      (void)::moho::func_EntityGetBlueprint_LuaFuncDef();
      (void)::moho::func_EntityGetArmy_LuaFuncDef();
      (void)::moho::func_EntityGetBoneDirection_LuaFuncDef();
      (void)::moho::func_EntityIsValidBone_LuaFuncDef();
      (void)::moho::func_EntityGetBoneCount_LuaFuncDef();
      (void)::moho::func_EntityGetBoneName_LuaFuncDef();
      (void)::moho::func_EntityRequestRefreshUI_LuaFuncDef();
      (void)::moho::func_EntityAttachBoneTo_LuaFuncDef();
      (void)::moho::func_EntitySetParentOffset_LuaFuncDef();
      (void)::moho::func_EntityDetachFrom_LuaFuncDef();
      (void)::moho::func_EntityGetParent_LuaFuncDef();
      (void)::moho::func_EntityGetCollisionExtents_LuaFuncDef();
      (void)::moho::func_EntityPlaySound_LuaFuncDef();
      (void)::moho::func_EntitySetAmbientSound_LuaFuncDef();
      (void)::moho::func_EntityGetFractionComplete_LuaFuncDef();
      (void)::moho::func_EntityAdjustHealth_LuaFuncDef();
      (void)::moho::func_EntityGetHealth_LuaFuncDef();
      (void)::moho::func_EntityGetMaxHealth_LuaFuncDef();
      (void)::moho::func_EntitySetHealth_LuaFuncDef();
      (void)::moho::func_EntitySetMaxHealth_LuaFuncDef();
      (void)::moho::func_EntitySetVizToFocusPlayer_LuaFuncDef();
      (void)::moho::func_EntitySetVizToEnemies_LuaFuncDef();
      (void)::moho::func_EntitySetVizToAllies_LuaFuncDef();
      (void)::moho::func_EntitySetVizToNeutrals_LuaFuncDef();
      (void)::moho::func_EntityGetEntityId_LuaFuncDef();
      (void)::moho::func_EntityDetachAll_LuaFuncDef();
      (void)::moho::func_EntitySetCollisionShape_LuaFuncDef();
      (void)::moho::func_EntityReachedMaxShooters_LuaFuncDef();
      (void)::moho::func_EntityGetOrientation_LuaFuncDef();
      (void)::moho::func_EntityGetHeading_LuaFuncDef();
      (void)::moho::func_EntityGetScale_LuaFuncDef();
      (void)::moho::func_EntityAddLocalImpulse_LuaFuncDef();
      (void)::moho::func_EntityAddWorldImpulse_LuaFuncDef();
      (void)::moho::func_EntitySetMesh_LuaFuncDef();
      (void)::moho::func_EntitySetScale_LuaFuncDef();
      (void)::moho::func_EntityAddManualScroller_LuaFuncDef();
      (void)::moho::func_EntityAddThreadScroller_LuaFuncDef();
      (void)::moho::func_EntityAddPingPongScroller_LuaFuncDef();
      (void)::moho::func_EntityRemoveScroller_LuaFuncDef();
      (void)::moho::func_EntityDestroy_LuaFuncDef();
      (void)::moho::func_EntityBeenDestroyed_LuaFuncDef();
      (void)::moho::func_EntityKill_LuaFuncDef();
      (void)::moho::func_EntitySetDrawScale_LuaFuncDef();
      (void)::moho::func_EntityFallDown_LuaFuncDef();
      (void)::moho::func_EntitySinkAway_LuaFuncDef();
      (void)::moho::func_EntityPushOver_LuaFuncDef();
    }
  };

  const EntityLuaFuncDefBootstrap gEntityLuaFuncDefBootstrap{};
} // namespace
namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<Entity>`, vtable 0x00E276F4.
   *
   * Address: 0x00BD5050 (FUN_00BD5050 -- constructs the global and registers its destructor.)
   * Address: 0x00BFC870 (FUN_00BFC870 -- the global's destructor.)
   * Address: 0x0067F640 (FUN_0067F640 -- an unreferenced copy of `Serialize`.)
   * Address: 0x006807A0 (FUN_006807A0 -- an unreferenced copy of `Serialize`.)
   * Address: 0x0067C600 (FUN_0067C600 -- `Init`.)
   * Address: 0x0067B630 (FUN_0067B630 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x0067B640 (FUN_0067B640 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct EntitySerializer : gpg::SerSaveLoadHelper<Entity>
  {};
}

namespace
{
  // Address: 0x010B43E4 -- process-global `EntitySerializer` singleton.
  moho::EntitySerializer gEntitySerializer;
}

