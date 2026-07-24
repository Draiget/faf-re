#include "Prop.h"

#include <cmath>
#include <cstdint>
#include <new>
#include <string>
#include <typeinfo>

#include "gpg/core/containers/Rect2.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Global.h"
#include "moho/entity/EntityDb.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/misc/InstanceCounter.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/Stats.h"
#include "moho/path/PathTables.h"
#include "moho/resource/blueprints/RPropBlueprint.h"
#include "moho/sim/COGrid.h"
#include "moho/sim/Sim.h"
#include "moho/sim/SimDebugCommandRegistrations.h"
#include "moho/sim/SimDriver.h"
#include "moho/animation/CAniSkel.h"
#include "moho/resource/RScmResource.h"
#include "moho/sim/RRuleGameRules.h"
#include "moho/math/QuaternionMath.h"
#include "gpg/core/containers/String.h"

namespace moho
{
  // Defined in QuaternionMath.cpp (no shared header); rotate a vector by a quaternion.
  Wm3::Vector3f* MultQuadVec(Wm3::Vector3f* dest, const Wm3::Vector3f* vec, const Wm3::Quaternionf* quat);
}

namespace
{
  constexpr const char* kPropLuaClassName = "Prop";
  constexpr const char* kPropAddBoundedPropName = "AddBoundedProp";
  constexpr const char* kPropAddBoundedPropHelpText = "Prop:AddBoundedProp(priority)";
  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";
  constexpr const char* kSplitPropName = "SplitProp";
  constexpr const char* kSplitPropHelpText =
    "SplitProp(original, blueprint_name) -- split a prop into multiple child props, one per bone; "
    "returns all the created props";
  constexpr const char* kCreatePropHPRName = "CreatePropHPR";
  constexpr const char* kCreatePropHPRHelpText = "CreatePropHPR(blueprint, x, y, z, heading, pitch, roll)";
  constexpr float kDegreesToRadians = 0.017453292f;

  constexpr std::uint8_t kPropEntityIdSourceIndex = moho::kEntityIdSourceIndexInvalid;
  constexpr std::uint32_t kPropEntityIdFamilySourceBits =
    moho::MakeEntityIdFamilySourceBits(moho::EEntityIdFamily::Prop, kPropEntityIdSourceIndex);
  constexpr std::uint32_t kPropEntityIdFallback =
    moho::MakeEntityId(moho::EEntityIdFamily::Prop, kPropEntityIdSourceIndex, 1u);
  constexpr std::uint32_t kPropCollisionBucketFlags = 0x200u;

  gpg::RType* gEntitySerializationType = nullptr;

  template <typename T>
  [[nodiscard]] gpg::RType* ResolveSerializedType(gpg::RType*& cache)
  {
    if (cache == nullptr) {
      cache = gpg::LookupRType(typeid(T));
    }
    GPG_ASSERT(cache != nullptr);
    return cache;
  }

  struct DestroyQueueNodeView
  {
    DestroyQueueNodeView* next;
    DestroyQueueNodeView* prev;
    moho::Entity* entity;
  };

  struct CommandDbDestroyQueueView
  {
    std::uint8_t pad_00[0x20];
    std::int32_t count;         // +0x20
    DestroyQueueNodeView* head; // +0x24
  };

  void QueueEntityForDestroyNoCallback(moho::Entity* entity)
  {
    if (!entity || !entity->SimulationRef || !entity->SimulationRef->mCommandDB) {
      return;
    }

    auto* const queue = reinterpret_cast<CommandDbDestroyQueueView*>(entity->SimulationRef->mCommandDB);
    DestroyQueueNodeView* const head = queue->head;
    if (!head) {
      return;
    }

    auto* const node = static_cast<DestroyQueueNodeView*>(::operator new(sizeof(DestroyQueueNodeView)));
    node->next = head;
    node->prev = head->prev;
    node->entity = entity;

    ++queue->count;
    head->prev = node;
    node->prev->next = node;
  }

  void QueuePropReclaimDelete(moho::Prop& prop)
  {
    if (prop.DestroyQueuedFlag != 0u) {
      return;
    }

    prop.DestroyQueuedFlag = 1u;
    QueueEntityForDestroyNoCallback(&prop);

    if (prop.SimulationRef) {
      prop.mCoordNode.ListLinkAfter(&prop.SimulationRef->mCoordEntities);
    }
  }

  /**
   * Address: 0x00721A90 (FUN_00721A90)
   *
   * What it does:
   * Marks terrain/water occupancy masks for the reclaim area rectangle.
   */
  void LoadOccupancy(const std::uint8_t occupancyCaps, moho::COGrid* grid, const gpg::Rect2i& rect)
  {
    if (!grid) {
      return;
    }

    const int width = rect.x1 - rect.x0;
    const int height = rect.z1 - rect.z0;
    if (width <= 0 || height <= 0) {
      return;
    }

    if ((occupancyCaps & 0x07u) != 0u) {
      grid->terrainOccupation.FillRect(rect.x0, rect.z0, width, height, true);
    }
    if ((occupancyCaps & 0x08u) != 0u) {
      grid->waterOccupation.FillRect(rect.x0, rect.z0, width, height, true);
    }

    if (grid->sim && grid->sim->mPathTables) {
      grid->sim->mPathTables->DirtyClusters(rect);
    }
  }

  struct OccupancyFootprintRuntimeView
  {
    std::uint8_t widthCells = 0;         // +0x00
    std::uint8_t heightCells = 0;        // +0x01
    std::uint8_t occupancyCapsBits = 0;  // +0x02
  };
  static_assert(sizeof(OccupancyFootprintRuntimeView) == 0x03, "OccupancyFootprintRuntimeView size must be 0x03");

  /**
   * Address: 0x00721AF0 (FUN_00721AF0)
   *
   * What it does:
   * Converts one footprint lane (`width/height/caps`) and top-left occupancy
   * cell origin into a `Rect2i`, then forwards to `COGrid::ExecuteOccupy`.
   */
  [[maybe_unused]] void LoadOccupancyFromFootprintCellRuntime(
    const OccupancyFootprintRuntimeView& footprint,
    const std::int16_t originX,
    const std::int16_t originZ,
    moho::COGrid* const grid
  )
  {
    if (grid == nullptr) {
      return;
    }

    gpg::Rect2i rect{};
    rect.x0 = static_cast<int>(originX);
    rect.z0 = static_cast<int>(originZ);
    rect.x1 = rect.x0 + static_cast<int>(footprint.widthCells);
    rect.z1 = rect.z0 + static_cast<int>(footprint.heightCells);
    grid->ExecuteOccupy(static_cast<moho::EOccupancyCaps>(footprint.occupancyCapsBits), rect);
  }

  /**
   * Increments or decrements one StatItem's primary counter atomically.
   *
   * Binary lane: `Prop::Prop` and `Prop::~Prop` both emit
   * `_InterlockedExchangeAdd(&statItem->mCounter, +/-1)` against the per-type
   * instance-counter stat item.
   */
  void AddInstanceCounterDelta(moho::StatItem* const statItem, const long delta) noexcept
  {
    if (statItem == nullptr) {
      return;
    }

    (void)InterlockedExchangeAdd(reinterpret_cast<volatile long*>(&statItem->mPrimaryValueBits), delta);
  }

  [[nodiscard]] moho::CScrLuaInitFormSet& SimLuaInitSet()
  {
    static moho::CScrLuaInitFormSet sSet("sim");
    return sSet;
  }

} // namespace

namespace moho
{
  gpg::RType* SPropPriorityInfo::sType = nullptr;
  gpg::RType* Prop::sType = nullptr;
  CScrLuaMetatableFactory<Prop> CScrLuaMetatableFactory<Prop>::sInstance{};
  int cfunc_PropAddBoundedProp(lua_State* luaContext);
  int cfunc_PropAddBoundedPropL(LuaPlus::LuaState* state);
  int cfunc_SplitProp(lua_State* luaContext);
  int cfunc_SplitPropL(LuaPlus::LuaState* state);
  void SplitPropIntoBoneChildren(
    Entity* original, const RPropBlueprint* childBlueprint, gpg::fastvector_n<Prop*, 20>* out
  );
  int cfunc_CreatePropHPR(lua_State* luaContext);
  int cfunc_CreatePropHPRL(LuaPlus::LuaState* state);

  /**
   * Address: 0x006FAAD0 (FUN_006FAAD0, Moho::InstanceCounter<Moho::Prop>::GetStatItem)
   *
   * What it does:
   * Lazily resolves and caches the engine stat slot used for Prop instance
   * counting (`Instance Counts_<type-name-without-underscores>`).
   */
  template <>
  moho::StatItem* moho::InstanceCounter<moho::Prop>::GetStatItem()
  {
    static moho::StatItem* sStatItem = nullptr;
    if (sStatItem) {
      return sStatItem;
    }

    const std::string statPath = moho::BuildInstanceCounterStatPath(typeid(moho::Prop).name());
    moho::EngineStats* const engineStats = moho::GetEngineStats();
    sStatItem = engineStats->GetItem(statPath.c_str(), true);
    return sStatItem;
  }

  CScrLuaMetatableFactory<Prop>& CScrLuaMetatableFactory<Prop>::Instance()
  {
    return sInstance;
  }

  /**
   * Address: 0x00680010 (FUN_00680010, Moho::CScrLuaMetatableFactory<Moho::Prop>::Create)
   */
  LuaPlus::LuaObject CScrLuaMetatableFactory<Prop>::Create(LuaPlus::LuaState* const state)
  {
    return SCR_CreateSimpleMetatable(state);
  }

  /**
   * Address: 0x0067F140 (FUN_0067F140, func_GetPropFactory)
   *
   * What it does:
   * Returns cached `Prop` metatable object from Lua object-factory storage.
   */
  LuaPlus::LuaObject* func_GetPropFactory(LuaPlus::LuaObject* const object, LuaPlus::LuaState* const state)
  {
    if (object == nullptr) {
      return nullptr;
    }

    *object = CScrLuaMetatableFactory<Prop>::Instance().Get(state);
    return object;
  }

  /**
   * Address: 0x00BD50F0 (FUN_00BD50F0, register_CScrLuaMetatableFactory_Prop_Index)
   *
   * What it does:
   * Allocates one factory-object index and assigns it to prop metatable factory singleton.
   */
  int register_CScrLuaMetatableFactory_Prop_Index()
  {
    const int index = CScrLuaObjectFactory::AllocateFactoryObjectIndex();
    CScrLuaMetatableFactory<Prop>::Instance().SetFactoryObjectIndexForRecovery(index);
    return index;
  }

  /**
   * Address: 0x006FCF60 (FUN_006FCF60, func_PropAddBoundedProp_LuaFuncDef)
   *
   * What it does:
   * Publishes the `Prop:AddBoundedProp(priority)` Lua binder form.
   */
  CScrLuaInitForm* func_PropAddBoundedProp_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kPropAddBoundedPropName,
      &cfunc_PropAddBoundedProp,
      &CScrLuaMetatableFactory<Prop>::Instance(),
      kPropLuaClassName,
      kPropAddBoundedPropHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006FCF40 (FUN_006FCF40, cfunc_PropAddBoundedProp)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_PropAddBoundedPropL`.
   */
  int cfunc_PropAddBoundedProp(lua_State* const luaContext)
  {
    return cfunc_PropAddBoundedPropL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006FCFC0 (FUN_006FCFC0, cfunc_PropAddBoundedPropL)
   *
   * What it does:
   * Resolves `(prop, priority)`, writes bounded-priority/tick lanes on the
   * prop, and inserts it into `EntityDB::AddBoundedProp`.
   */
  int cfunc_PropAddBoundedPropL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kPropAddBoundedPropHelpText, 2, argumentCount);
    }

    const LuaPlus::LuaObject propObject(LuaPlus::LuaStackObject(state, 1));
    Prop* const prop = SCR_FromLua_Prop(propObject, state);

    LuaPlus::LuaStackObject priorityObject(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      priorityObject.TypeError("number");
    }

    const float priorityValue = static_cast<float>(lua_tonumber(rawState, 2));
    prop->mPriorityInfo.mPriority = static_cast<std::int32_t>(std::ceil(priorityValue));

    Sim* const sim = prop->SimulationRef;
    prop->mPriorityInfo.mBoundedTick = static_cast<std::int32_t>(sim->mCurTick);
    prop->mHandleIndex = sim->mEntityDB->AddBoundedProp(prop);
    return 0;
  }

  /**
   * Address: 0x006FC850 (FUN_006FC850, func_SplitProp_LuaFuncDef)
   *
   * What it does:
   * Publishes the global `SplitProp(original, blueprint_name)` Lua binder.
   */
  CScrLuaInitForm* func_SplitProp_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kSplitPropName,
      &cfunc_SplitProp,
      nullptr,
      "<global>",
      kSplitPropHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006FC830 (FUN_006FC830, cfunc_SplitProp)
   *
   * What it does:
   * Unwraps the raw Lua callback context and forwards to `cfunc_SplitPropL`.
   */
  int cfunc_SplitProp(lua_State* const luaContext)
  {
    return cfunc_SplitPropL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006FC8B0 (FUN_006FC8B0, cfunc_SplitPropL)
   *
   * What it does:
   * Reads `(original, blueprint_name)`, resolves the source prop and the child
   * prop blueprint, splits the source into per-bone child props via
   * `SplitPropIntoBoneChildren`, pushes each created child's Lua userdata, and
   * returns the child count.
   */
  int cfunc_SplitPropL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 2) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kSplitPropHelpText, 2, argumentCount);
    }

    const LuaPlus::LuaObject propObject(LuaPlus::LuaStackObject(state, 1));
    Prop* const prop = SCR_FromLua_Prop(propObject, state);

    LuaPlus::LuaStackObject blueprintArg(state, 2);
    const char* const blueprintName = lua_tostring(rawState, 2);
    if (blueprintName == nullptr) {
      blueprintArg.TypeError("string");
    }

    msvc8::string blueprintFilename;
    (void)gpg::STR_InitFilename(&blueprintFilename, blueprintName);
    const RPropBlueprint* const childBlueprint = prop->SimulationRef->mRules->GetPropBlueprint(blueprintFilename);

    gpg::fastvector_n<Prop*, 20> spawnedChildren;
    if (childBlueprint != nullptr) {
      SplitPropIntoBoneChildren(prop, childBlueprint, &spawnedChildren);
    }

    lua_settop(rawState, 0);
    const int childCount = static_cast<int>(spawnedChildren.end() - spawnedChildren.begin());
    lua_checkstack(rawState, childCount);
    for (Prop* const child : spawnedChildren) {
      child->mLuaObj.PushStack(state);
    }
    return childCount;
  }

  /**
   * Address: 0x006FBFB0 (FUN_006FBFB0, func_CreatePropHPR_LuaFuncDef)
   *
   * What it does:
   * Publishes the global `CreatePropHPR(blueprint, x, y, z, heading, pitch, roll)`
   * Lua binder.
   */
  CScrLuaInitForm* func_CreatePropHPR_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      SimLuaInitSet(),
      kCreatePropHPRName,
      &cfunc_CreatePropHPR,
      nullptr,
      "<global>",
      kCreatePropHPRHelpText
    );
    return &binder;
  }

  /**
   * Address: 0x006FBF90 (FUN_006FBF90, cfunc_CreatePropHPR)
   *
   * What it does:
   * Unwraps the raw Lua callback context and forwards to `cfunc_CreatePropHPRL`.
   */
  int cfunc_CreatePropHPR(lua_State* const luaContext)
  {
    return cfunc_CreatePropHPRL(moho::SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006FC010 (FUN_006FC010, cfunc_CreatePropHPRL)
   *
   * IDA signature:
   * int __usercall cfunc_CreatePropHPRL@<eax>(LuaPlus::LuaState *this@<ebx>);
   *
   * What it does:
   * Reads `(blueprint, x, y, z, heading, pitch, roll)`, builds a heading/pitch/roll
   * rotation quaternion, spawns the prop at `{position, orientation}`, and pushes
   * the created prop's Lua userdata.
   */
  int cfunc_CreatePropHPRL(LuaPlus::LuaState* const state)
  {
    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 7) {
      LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kCreatePropHPRHelpText, 7, argumentCount);
    }

    Sim* const sim = lua_getglobaluserdata(rawState);

    LuaPlus::LuaStackObject blueprintArg(state, 1);
    const char* const blueprintName = lua_tostring(rawState, 1);
    if (blueprintName == nullptr) {
      blueprintArg.TypeError("string");
    }
    const msvc8::string blueprintId(blueprintName, std::strlen(blueprintName));

    // Position (args 2,3,4) and Euler angles (args 5,6,7); validated in the
    // binary's order (4, 3, 2, then 5, 6, 7).
    LuaPlus::LuaStackObject zArg(state, 4);
    if (lua_type(rawState, 4) != LUA_TNUMBER) {
      zArg.TypeError("number");
    }
    const float posZ = static_cast<float>(lua_tonumber(rawState, 4));

    LuaPlus::LuaStackObject yArg(state, 3);
    if (lua_type(rawState, 3) != LUA_TNUMBER) {
      yArg.TypeError("number");
    }
    const float posY = static_cast<float>(lua_tonumber(rawState, 3));

    LuaPlus::LuaStackObject xArg(state, 2);
    if (lua_type(rawState, 2) != LUA_TNUMBER) {
      xArg.TypeError("number");
    }
    const float posX = static_cast<float>(lua_tonumber(rawState, 2));

    LuaPlus::LuaStackObject headingArg(state, 5);
    if (lua_type(rawState, 5) != LUA_TNUMBER) {
      headingArg.TypeError("number");
    }
    const float heading = static_cast<float>(lua_tonumber(rawState, 5)) * kDegreesToRadians;

    LuaPlus::LuaStackObject pitchArg(state, 6);
    if (lua_type(rawState, 6) != LUA_TNUMBER) {
      pitchArg.TypeError("number");
    }
    const float pitch = static_cast<float>(lua_tonumber(rawState, 6)) * kDegreesToRadians;

    LuaPlus::LuaStackObject rollArg(state, 7);
    if (lua_type(rawState, 7) != LUA_TNUMBER) {
      rollArg.TypeError("number");
    }
    const float roll = static_cast<float>(lua_tonumber(rawState, 7)) * kDegreesToRadians;

    Wm3::Vector3f rotationMatrix[3];
    (void)BuildRotationMatrixFromEulerHPR(rotationMatrix, heading, pitch, roll);

    VTransform transform{};
    transform.pos_.x = posX;
    transform.pos_.y = posY;
    transform.pos_.z = posZ;
    (void)MatrixToQuat(rotationMatrix, &transform.orient_);

    Prop* const prop = PROP_Create(sim, transform, blueprintId.c_str());
    if (prop == nullptr) {
      LuaPlus::LuaState::Error(state, "Unable to create prop '%s'", blueprintId.c_str());
    }

    prop->mLuaObj.PushStack(state);
    return 1;
  }

  /**
   * Address: 0x006F9CD0 (FUN_006F9CD0)
   *
   * What it does:
   * Initializes Prop for serializer construction lanes by using Entity's
   * non-blueprint constructor and applying Prop reclaim defaults.
   */
  Prop::Prop(Sim* sim)
    : Entity(sim, kPropCollisionBucketFlags)
    , mReclaimMass(0.0f)
    , mReclaimEnergy(0.0f)
    , mTracksReclaimArea(false)
    , mReclaimTerminated(false)
    , pad_027A{0u, 0u}
    , mPriorityInfo{0, 0}
    , mHandleIndex(-1)
  {
    // Increment the Prop instance-count stat (binary FUN_006F9CD0). The recovery
    // wired the matching -1 into ~Prop but dropped both ctors' +1, so the stat
    // decremented without ever incrementing. Independent standalone ctor.
    AddInstanceCounterDelta(InstanceCounter<Prop>::GetStatItem(), 1L);
  }

  /**
   * Address: 0x006F9D90 (FUN_006F9D90)
   *
   * What it does:
   * Constructs Prop from blueprint/transform, initializes layer+mesh+reclaim
   * state, and registers reclaim occupancy area when needed.
   */
  Prop::Prop(Sim* sim, const RPropBlueprint* blueprint, const VTransform& transform)
    : Entity(
        static_cast<REntityBlueprint*>(const_cast<RPropBlueprint*>(blueprint)),
        sim,
        static_cast<EntId>(
          sim && sim->mEntityDB ? sim->mEntityDB->DoReserveId(kPropEntityIdFamilySourceBits) : kPropEntityIdFallback
        ),
        kPropCollisionBucketFlags
      )
    , mReclaimMass(0.0f)
    , mReclaimEnergy(0.0f)
    , mTracksReclaimArea(false)
    , mReclaimTerminated(false)
    , pad_027A{0u, 0u}
    , mPriorityInfo{0, 0}
    , mHandleIndex(-1)
  {
    // Increment the Prop instance-count stat (binary FUN_006F9D90), before the
    // early-out so every construction is counted. Independent standalone ctor.
    AddInstanceCounterDelta(InstanceCounter<Prop>::GetStatItem(), 1L);

    if (!blueprint) {
      return;
    }

    const float uniformScale = blueprint->Display.UniformScale;
    mDrawScaleX = uniformScale;
    mDrawScaleY = uniformScale;
    mDrawScaleZ = uniformScale;

    // Entity orientation lanes are stored as (w,x,y,z) in Vector4f::x/y/z/w slots.
    PendingOrientation.x = transform.orient_.w;
    PendingOrientation.y = transform.orient_.x;
    PendingOrientation.z = transform.orient_.y;
    PendingOrientation.w = transform.orient_.z;
    PendingPosition.x = transform.pos_.x;
    PendingPosition.y = transform.pos_.y;
    PendingPosition.z = transform.pos_.z;

    const ELayer startingLayer = GetStartingLayer(transform.pos_, LAYER_Land);
    SetCurrentLayer(startingLayer);
    AdvanceCoords();
    AdvanceCoords();

    MaxHealth = blueprint->Defense.Health;
    mReclaimMass = blueprint->Economy.ReclaimMassMax;
    mReclaimEnergy = blueprint->Economy.ReclaimEnergyMax;

    mVizToNeutrals = 2;
    mFootprintLayer = static_cast<int>(LAYER_Seabed);
    mVisibilityState = 1u;

    SetMesh(blueprint->Display.MeshBlueprint, nullptr, true);
    RunScript("OnCreate");

    if (mReclaimMass > 0.0f || mReclaimEnergy > 0.0f) {
      mTracksReclaimArea = true;

      if (sim && sim->mOGrid) {
        const int originX = static_cast<int>(transform.pos_.x - static_cast<float>(blueprint->mFootprint.mSizeX) * 0.5f);
        const int originZ = static_cast<int>(transform.pos_.z - static_cast<float>(blueprint->mFootprint.mSizeZ) * 0.5f);

        const OccupancyFootprintRuntimeView footprint{
          static_cast<std::uint8_t>(blueprint->mFootprint.mSizeX),
          static_cast<std::uint8_t>(blueprint->mFootprint.mSizeZ),
          static_cast<std::uint8_t>(blueprint->mFootprint.mOccupancyCaps)
        };
        LoadOccupancyFromFootprintCellRuntime(
          footprint,
          static_cast<std::int16_t>(originX),
          static_cast<std::int16_t>(originZ),
          sim->mOGrid
        );
      }
    }
  }

  /**
   * Address: 0x006FA000 (FUN_006FA000, ??1Prop@Moho@@QAE@@Z)
   * Deleting thunk: 0x006F9D70 (FUN_006F9D70, Moho::Prop::dtr) - vtable slot 2.
   *
   * IDA signature:
   * void __cdecl Moho::Prop::~Prop(Moho::Prop *this);
   *
   * What it does:
   * Auto-unregisters this Prop from the EntityDB bounded-reclaim priority
   * queue when registered (`mHandleIndex != -1`), releases the reclaim-area
   * occupancy footprint on the COGrid when `mTracksReclaimArea` is set,
   * decrements the per-type instance counter, and falls through to
   * `Entity::~Entity` for base teardown.
   */
  Prop::~Prop()
  {
    // Binary path: unconditionally dereferences mSim->mEntityDB; the ctor
    // invariant guarantees both are valid whenever a Prop reaches the dtor.
    if (mHandleIndex != -1) {
      SimulationRef->mEntityDB->RemoveBoundedProp(mHandleIndex);
    }

    if (mTracksReclaimArea) {
      // Binary path: unconditionally dereferences BluePrint and mOGrid; the
      // ctor sets mTracksReclaimArea=true only after both were resolved.
      const auto* const blueprint = static_cast<const RPropBlueprint*>(BluePrint);
      const SFootprint& footprint = blueprint->mFootprint;

      const int originX = static_cast<int>(Position.x - static_cast<float>(footprint.mSizeX) * 0.5f);
      const int originZ = static_cast<int>(Position.z - static_cast<float>(footprint.mSizeZ) * 0.5f);

      gpg::Rect2i rect{};
      rect.x0 = originX;
      rect.z0 = originZ;
      rect.x1 = originX + static_cast<int>(footprint.mSizeX);
      rect.z1 = originZ + static_cast<int>(footprint.mSizeZ);

      SimulationRef->mOGrid->ReleaseOccupy(footprint.mOccupancyCaps, rect);
    }

    AddInstanceCounterDelta(InstanceCounter<Prop>::GetStatItem(), -1L);

    // Base `Entity::~Entity` runs implicitly as part of the C++ destructor chain.
  }

  /**
   * Address: 0x006FB3B0 (FUN_006FB3B0)
   *
   * IDA signature:
   * Moho::Prop * __cdecl Moho::PROP_Create(Moho::Sim *, Moho::VTransform const &, Moho::RPropBlueprint const *);
   *
   * What it does:
   * Allocates Prop and dispatches to Prop ctor path.
   */
  Prop* Prop::CreateFromBlueprintResolved(Sim* sim, const RPropBlueprint* blueprint, const VTransform& transform)
  {
    if (!sim || !blueprint) {
      return nullptr;
    }

    return new (std::nothrow) Prop(sim, blueprint, transform);
  }

  /**
   * Address: 0x006FB620 (FUN_006FB620, sub_6FB620)
   *
   * IDA signature:
   * void __cdecl sub_6FB620(Moho::Entity *original, Moho::RPropBlueprint *childBlueprint,
   *                         gpg::fastvector_n<Prop*,20> *out);
   *
   * What it does:
   * Splits one source prop into per-bone child props. For every bone of the source
   * mesh skeleton it inverts the bone local transform, scales the translation by
   * the source draw-scale, applies a fixed 90-degree quaternion rotation, composes
   * with the source world transform, and spawns a child Prop of `childBlueprint`
   * there. When the spawned child has its own mesh, it rescales the child by the
   * source-bone-bounds / child-mesh-box ratio, warps the child so its root bone
   * sits at the composed pose, stores that scale, and relinks the child coord node
   * into `Sim::mCoordEntities`. Every spawned child pointer is appended to `out`.
   * Finally the source prop is destroyed. Sole caller: cfunc_SplitPropL.
   */
  void SplitPropIntoBoneChildren(
    Entity* const original,
    const RPropBlueprint* const childBlueprint,
    gpg::fastvector_n<Prop*, 20>* const out
  )
  {
    constexpr float kQ = 0.70710677f; // sqrt(2)/2; fixed 90-degree rotation lane.

    boost::SharedPtrRaw<RScmResource> meshResource = original->GetMesh();
    if (meshResource.px == nullptr) {
      meshResource.release();
      return;
    }

    const CAniSkel* sourceSkeleton = nullptr;
    {
      // Binary grabs the raw skeleton pointer then drops the shared owner; the
      // mesh resource keeps the skeleton alive for the loop.
      const boost::shared_ptr<const CAniSkel> handle = meshResource.px->GetSkeleton();
      sourceSkeleton = handle.get();
    }
    if (sourceSkeleton == nullptr) {
      meshResource.release();
      return;
    }

    const SAniSkelBone* const bonesBegin = sourceSkeleton->mBones.begin();
    const std::size_t boneCount = static_cast<std::size_t>(sourceSkeleton->mBones.end() - bonesBegin);
    for (std::size_t i = 0; i < boneCount; ++i) {
      const SAniSkelBone& bone = bonesBegin[i];

      VTransform invTransform = bone.mBoneTransform.Inverse();
      const float scaleX = original->mDrawScaleX;
      const float scaleY = original->mDrawScaleY;
      const float scaleZ = original->mDrawScaleZ;
      invTransform.pos_.x *= scaleX;
      invTransform.pos_.y *= scaleY;
      invTransform.pos_.z *= scaleZ;

      // Fixed 90-degree quaternion multiply (q' = q * qFixed), from the original
      // lanes before any are overwritten. 1:1 with FUN_006FB620.
      const float qx = invTransform.orient_.x;
      const float qy = invTransform.orient_.y;
      const float qz = invTransform.orient_.z;
      const float qw = invTransform.orient_.w;
      const float newY = (((qz * 0.0f) + (qy * kQ)) + (qx * kQ)) - (qw * 0.0f);
      const float newZ = (((qz * kQ) + (qx * 0.0f)) + (qw * kQ)) - (qy * 0.0f);
      const float newW = (((qy * 0.0f) + (qx * 0.0f)) + (qw * kQ)) - (qz * kQ);
      const float newX = (((qx * kQ) - (qy * kQ)) - (qz * 0.0f)) - (qw * 0.0f);
      invTransform.orient_.x = newX;
      invTransform.orient_.y = newY;
      invTransform.orient_.z = newZ;
      invTransform.orient_.w = newW;

      const VTransform composed = VTransform::Compose(invTransform, original->GetTransformWm3());
      Prop* const child = Prop::CreateFromBlueprintResolved(original->SimulationRef, childBlueprint, composed);

      boost::SharedPtrRaw<RScmResource> childMeshResource = child->GetMesh();
      if (childMeshResource.px != nullptr) {
        const RScmResource* const childMesh = childMeshResource.px;

        // Per-axis child scale = source-bone-bounds extent / child-mesh-box extent.
        Wm3::Vector3f childScale{};
        childScale.x = ((bone.mBoundsMaxX - bone.mBoundsMinX) * scaleX) /
          (childMesh->mBounds.Max.x - childMesh->mBounds.Min.x);
        childScale.y = (scaleY * (bone.mBoundsMaxY - bone.mBoundsMinY)) /
          (childMesh->mBounds.Max.y - childMesh->mBounds.Min.y);
        childScale.z = (scaleZ * (bone.mBoundsMaxZ - bone.mBoundsMinZ)) /
          (childMesh->mBounds.Max.z - childMesh->mBounds.Min.z);

        {
          const boost::shared_ptr<const CAniSkel> childHandle = childMeshResource.px->GetSkeleton();
          const CAniSkel* const childSkeleton = childHandle.get();
          if (childSkeleton != nullptr && childSkeleton->mBones.begin() != childSkeleton->mBones.end()) {
            const SAniSkelBone* const rootBone = childSkeleton->GetBone(0);
            // Root-bone local translation ("dir" == mBoneTransform.pos_), y negated,
            // scaled per-axis, rotated by the composed orientation.
            Wm3::Vector3f localOffset{};
            localOffset.x = childScale.x * rootBone->mBoneTransform.pos_.x;
            localOffset.y = childScale.y * rootBone->mBoneTransform.pos_.z;
            localOffset.z = childScale.z * (-0.0f - rootBone->mBoneTransform.pos_.y);

            Wm3::Vector3f rotatedOffset{};
            MultQuadVec(&rotatedOffset, &localOffset, &composed.orient_);

            VTransform warpTransform{};
            warpTransform.orient_ = composed.orient_;
            warpTransform.pos_.x = composed.pos_.x + rotatedOffset.x;
            warpTransform.pos_.y = composed.pos_.y + rotatedOffset.y;
            warpTransform.pos_.z = composed.pos_.z + rotatedOffset.z;
            child->Warp(warpTransform);
          }
        }

        // Store the child's draw-scale and relink its coord node at the tail of
        // sim->mCoordEntities (inlined; matches SetEntityDrawScaleAndRelinkCoordNode).
        child->mDrawScaleX = childScale.x;
        child->mDrawScaleY = childScale.y;
        child->mDrawScaleZ = childScale.z;
        TDatListItem<Entity, void>* const node = &child->mCoordNode;
        TDatListItem<Entity, void>* const head = &child->SimulationRef->mCoordEntities;
        node->ListUnlink();
        node->mPrev = head->mPrev;
        node->mNext = head;
        head->mPrev = node;
        node->mPrev->mNext = node;
      }
      childMeshResource.release();

      out->push_back(child);
    }

    original->Destroy();
    meshResource.release();
  }

  /**
   * Address: 0x006F9A30 (FUN_006F9A30, Moho::Prop::GetClass)
   */
  gpg::RType* Prop::GetClass() const
  {
    gpg::RType* type = sType;
    if (!type) {
      type = gpg::LookupRType(typeid(Prop));
      sType = type;
    }
    return type;
  }

  /**
   * Address: 0x006F9A50 (FUN_006F9A50, Moho::Prop::GetDerivedObjectRef)
   */
  gpg::RRef Prop::GetDerivedObjectRef()
  {
    gpg::RRef ref{};
    ref.mObj = this;
    ref.mType = GetClass();
    return ref;
  }

  /**
   * Address: 0x006F9A70 (FUN_006F9A70)
   */
  Prop* Prop::IsProp()
  {
    return this;
  }

  /**
   * Address: 0x006FA2A0 (FUN_006FA2A0)
   *
   * IDA signature:
   * void __thiscall Moho::Prop::Sync(Moho::Prop *this, Moho::SSyncData *a2);
   *
   * What it does:
   * Overrides Entity::Sync for props. When the prop has dispatched its
   * on-destroy pass (`mOnDestroyDispatched`) and still has a live interface
   * lane (`mInterfaceCreated`), it queues this prop's id_ onto one of two sync
   * lanes selected by the terminal reclaim/kill flag (`mReclaimTerminated`,
   * +0x279): set -> `SSyncData::mEraseIds` (immediate erase, 0x006FA2D6), clear
   * -> `SSyncData::mDeleteIds` (deferred delete, 0x006FA2F1), then clears the
   * interface-created flag. Otherwise it lazily creates the interface and syncs
   * it. Finally, when the current transform equals the previous transform, it
   * unlinks the coord-list node.
   */
  void Prop::Sync(SSyncData* syncData)
  {
    if (mOnDestroyDispatched != 0u) {
      if (mInterfaceCreated != 0u) {
        // 1:1 dual-branch push (asm 0x006FA2B8 selector on +0x279): a
        // terminated (reclaimed/killed) prop is erased immediately, otherwise
        // it is queued for deferred deletion.
        if (mReclaimTerminated) {
          PushBackDeleteEntId(syncData->mEraseIds, id_);
        } else {
          PushBackDeleteEntId(syncData->mDeleteIds, id_);
        }
        mInterfaceCreated = 0u;
      }
    } else {
      if (mInterfaceCreated == 0u) {
        CreateInterface(syncData);
      }
      SyncInterface(syncData);
    }

    const bool samePosition =
      Position.x == PrevPosition.x && Position.y == PrevPosition.y && Position.z == PrevPosition.z;
    const bool sameOrientation = Orientation.x == PrevOrientation.x && Orientation.y == PrevOrientation.y &&
      Orientation.z == PrevOrientation.z && Orientation.w == PrevOrientation.w;
    if (samePosition && sameOrientation) {
      mCoordNode.ListUnlink();
    }
  }

  /**
   * Address: 0x006F9A80 (FUN_006F9A80)
   */
  float Prop::GetUniformScale() const
  {
    if (!BluePrint) {
      return 1.0f;
    }

    const auto* const blueprint = reinterpret_cast<const RPropBlueprint*>(BluePrint);
    return blueprint->Display.UniformScale;
  }

  /**
   * Address: 0x006F9A90 (FUN_006F9A90)
   */
  bool Prop::IsMobile() const
  {
    return false;
  }

  /**
   * Address: 0x006FA180 (FUN_006FA180)
   */
  float Prop::Materialize(const float reclaimDelta)
  {
    if (reclaimDelta == 0.0f) {
      return 0.0f;
    }

    if (SimulationRef && mCoordNode.ListIsSingleton()) {
      mCoordNode.ListLinkAfter(&SimulationRef->mCoordEntities);
    }

    const float previous = FractionCompleted;
    if (reclaimDelta <= 0.0f) {
      float next = previous + reclaimDelta;
      if (next > 1.0f) {
        next = 1.0f;
      }
      if (next < 0.0f) {
        next = 0.0f;
      }
      FractionCompleted = next;
    } else {
      float next = previous + reclaimDelta;
      if (next > 1.0f) {
        next = 1.0f;
      }
      if (next < 0.0f) {
        next = 0.0f;
      }

      if (MaxHealth > 0.0f) {
        const float minFractionFromHealth = Health / MaxHealth;
        if (next < minFractionFromHealth) {
          next = minFractionFromHealth;
        }
      }
      FractionCompleted = next;
    }

    const float applied = FractionCompleted - previous;
    CallbackStr("BeingReclaimed");

    if (FractionCompleted == 0.0f && reclaimDelta < 0.0f) {
      CallbackStr("OnReclaimed");
      mReclaimTerminated = true;
      QueuePropReclaimDelete(*this);
    }

    return applied;
  }

  /**
   * Address: 0x006FA150 (FUN_006FA150)
   */
  void Prop::Kill(Entity* killer, gpg::StrArg reason, const float overkillRatio)
  {
    Entity::Kill(killer, reason, overkillRatio);
    mReclaimTerminated = true;
  }

  /**
   * Address: 0x006FB0F0 (FUN_006FB0F0, Moho::Prop::MemberDeserialize)
   *
   * What it does:
   * Loads Prop reclaim and priority state after deserializing Entity base lanes.
   */
  void Prop::MemberDeserialize(gpg::ReadArchive* const archive, const int version)
  {
    if (archive == nullptr) {
      return;
    }

    gpg::RRef ownerRef{};
    const gpg::RType* const entityType = ResolveSerializedType<Entity>(gEntitySerializationType);
    archive->Read(entityType, this, ownerRef);

    archive->ReadFloat(&mReclaimMass);
    archive->ReadFloat(&mReclaimEnergy);
    archive->ReadBool(&mTracksReclaimArea);
    archive->ReadBool(&mReclaimTerminated);

    if (version >= 1) {
      ownerRef = {};
      const gpg::RType* const priorityType = ResolveSerializedType<SPropPriorityInfo>(SPropPriorityInfo::sType);
      archive->Read(priorityType, &mPriorityInfo, ownerRef);
      archive->ReadInt(&mHandleIndex);
    }
  }

  /**
   * Address: 0x006FB1D0 (FUN_006FB1D0, Moho::Prop::MemberSerialize)
   *
   * What it does:
   * Saves Prop reclaim and priority state after serializing Entity base lanes.
   */
  void Prop::MemberSerialize(gpg::WriteArchive* const archive, const int version) const
  {
    if (archive == nullptr) {
      return;
    }

    gpg::RRef ownerRef{};
    const gpg::RType* const entityType = ResolveSerializedType<Entity>(gEntitySerializationType);
    archive->Write(entityType, this, ownerRef);

    archive->WriteFloat(mReclaimMass);
    archive->WriteFloat(mReclaimEnergy);
    archive->WriteBool(mTracksReclaimArea);
    archive->WriteBool(mReclaimTerminated);

    if (version >= 1) {
      ownerRef = {};
      const gpg::RType* const priorityType = ResolveSerializedType<SPropPriorityInfo>(SPropPriorityInfo::sType);
      archive->Write(priorityType, &mPriorityInfo, ownerRef);
      archive->WriteInt(mHandleIndex);
    }
  }
} // namespace moho

namespace
{
  struct PropLuaFactoryBootstrap
  {
    PropLuaFactoryBootstrap()
    {
      (void)moho::register_CScrLuaMetatableFactory_Prop_Index();
    }
  };

  [[maybe_unused]] PropLuaFactoryBootstrap gPropLuaFactoryBootstrap;
} // namespace
