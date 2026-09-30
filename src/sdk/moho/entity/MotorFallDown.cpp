#include "moho/entity/MotorFallDown.h"
#include "legacy/math/X87Math.h"

#include <cmath>
#include <cstdint>
#include <new>
#include <string>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/entity/Entity.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/math/QuaternionMath.h"
#include "moho/script/CScriptEvent.h"
#include "lua/LuaObject.h"
#include "lua/LuaRuntimeTypes.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/Stats.h"
#include "moho/sim/CSimConVarBase.h"
#include "moho/sim/Sim.h"
#include "moho/sim/SimStartupRegistrations.h"
#include "moho/sim/STIMap.h"

#include "gpg/core/reflection/StaticInitPhase.h"
#include "gpg/core/containers/ArchiveSerialization.h"

namespace
{
  constexpr float kPi = 3.1415927f;
  constexpr float kHalfPi = 1.5707964f;
  constexpr float kQuarterPi = 0.78539819f;
  constexpr float kFourOverPi = 1.2732395f;
  constexpr float kTwoPi = 6.2831855f;
  constexpr float kQuatUpdateThreshold = 0.0001f;

  std::int32_t gRecoveredCScrLuaMetatableFactoryMotorFallDownIndex = 0;

  /**
   * Address: 0x00694B70 (FUN_00694B70)
   *
   * What it does:
   * Resolves and caches RTTI for one `MotorFallDown` lane.
   */
  [[nodiscard]] gpg::RType* CachedMotorFallDownType()
  {
    if (!moho::MotorFallDown::sType) {
      moho::MotorFallDown::sType = gpg::LookupRType(typeid(moho::MotorFallDown));
    }

    GPG_ASSERT(moho::MotorFallDown::sType != nullptr);
    return moho::MotorFallDown::sType;
  }

  /**
   * Address: 0x006959F0 (FUN_006959F0)
   *
   * What it does:
   * Secondary duplicated RTTI-resolve lane for `MotorFallDown`.
   */
  [[maybe_unused]] [[nodiscard]] gpg::RType* CachedMotorFallDownTypeVariantB()
  {
    return CachedMotorFallDownType();
  }

  [[nodiscard]] gpg::RType* CachedMotorType()
  {
    if (!moho::Motor::sType) {
      moho::Motor::sType = gpg::LookupRType(typeid(moho::Motor));
    }

    GPG_ASSERT(moho::Motor::sType != nullptr);
    return moho::Motor::sType;
  }

  [[nodiscard]] gpg::RType* CachedCScriptObjectType()
  {
    if (!moho::CScriptObject::sType) {
      moho::CScriptObject::sType = gpg::LookupRType(typeid(moho::CScriptObject));
    }

    GPG_ASSERT(moho::CScriptObject::sType != nullptr);
    return moho::CScriptObject::sType;
  }

  [[nodiscard]] float
  ReadSimConVarFloat(moho::Sim* const sim, moho::CSimConVarBase* const conVar, const float fallback)
  {
    if (!sim || !conVar) {
      return fallback;
    }

    moho::CSimConVarInstanceBase* const instance = sim->GetSimVar(conVar);
    if (!instance) {
      return fallback;
    }

    void* const valueStorage = instance->GetValueStorage();
    if (!valueStorage) {
      return fallback;
    }

    return *static_cast<float*>(valueStorage);
  }

  [[nodiscard]] float NormalizeAnglePositive(const float angleRadians) noexcept
  {
    float normalized = angleRadians;
    while (normalized < 0.0f) {
      normalized += kTwoPi;
    }
    while (normalized >= kTwoPi) {
      normalized -= kTwoPi;
    }
    return normalized;
  }

  [[nodiscard]] Wm3::Vec3f BuildCurrentFallAxis(const Wm3::Quatf& orientation) noexcept
  {
    return Wm3::Vec3f{
      // Column 1 - the local up axis - scalar-first:
      // (2(xy-wz), 1-2(x*x+z*z), 2(yz+wx)). The previous spelling carried a
      // `w*w` diagonal term, which no matrix expansion in this binary computes.
      ((orientation.y * orientation.x) - (orientation.w * orientation.z)) * 2.0f,
      1.0f - ((orientation.z * orientation.z + orientation.x * orientation.x) * 2.0f),
      ((orientation.z * orientation.y) + (orientation.w * orientation.x)) * 2.0f,
    };
  }

  [[nodiscard]] Wm3::Quatf BuildRotationDeltaFromAxes(const Wm3::Vec3f& targetAxisRaw, const Wm3::Vec3f& currentAxisRaw)
  {
    Wm3::Vec3f targetAxis = targetAxisRaw;
    Wm3::Vec3f currentAxis = currentAxisRaw;

    if (Wm3::Vec3f::Normalize(&targetAxis) <= 1.0e-6f || Wm3::Vec3f::Normalize(&currentAxis) <= 1.0e-6f) {
      return Wm3::Quatf::Identity();
    }

    const float dot = Wm3::Vec3f::Dot(currentAxis, targetAxis);
    if (dot < -0.9999f) {
      Wm3::Vec3f fallbackAxis = Wm3::Vec3f::Cross(currentAxis, Wm3::Vec3f{1.0f, 0.0f, 0.0f});
      if (Wm3::Vec3f::LengthSq(fallbackAxis) <= 1.0e-6f) {
        fallbackAxis = Wm3::Vec3f::Cross(currentAxis, Wm3::Vec3f{0.0f, 0.0f, 1.0f});
      }
      Wm3::Vec3f::Normalize(&fallbackAxis);
      return Wm3::Quatf(0.0f, fallbackAxis.x, fallbackAxis.y, fallbackAxis.z);
    }

    const Wm3::Vec3f cross = Wm3::Vec3f::Cross(currentAxis, targetAxis);
    Wm3::Quatf delta{1.0f + dot, cross.x, cross.y, cross.z};
    delta.Normalize();
    return delta;
  }

  /**
   * Address: 0x00695CA0 (FUN_00695CA0, Lua factory lookup thunk)
   */
  [[nodiscard]] LuaPlus::LuaObject GetMotorFallDownLuaFactoryObject(LuaPlus::LuaState* const state)
  {
    return moho::CScrLuaMetatableFactory<moho::MotorFallDown>::Instance().Get(state);
  }

  /**
   * Address: 0x00695F00 (FUN_00695F00, gpg::RRef_MotorFallDown)
   */
  [[nodiscard]] gpg::RRef MakeMotorFallDownRef(moho::MotorFallDown* const object)
  {
    gpg::RRef ref{};
    ref.mObj = object;
    ref.mType = CachedMotorFallDownType();
    return ref;
  }

  /**
   * Address: 0x006960D0 (FUN_006960D0)
   *
   * What it does:
   * Upcasts one reflected reference lane to `MotorFallDown` object storage
   * using the cached motor-fall-down RTTI descriptor.
   */
  [[maybe_unused]] [[nodiscard]] void* TryUpcastMotorFallDownRefObject(gpg::RRef* const sourceRef)
  {
    if (!sourceRef) {
      return nullptr;
    }

    const gpg::RRef upcast = gpg::REF_UpcastPtr(*sourceRef, CachedMotorFallDownType());
    return upcast.mObj;
  }

  /**
   * Address: 0x00695ED0 (FUN_00695ED0, metatable index bootstrap lane)
   */
  int InitializeMotorFallDownLuaFactoryIndex()
  {
    const int index = moho::CScrLuaObjectFactory::AllocateFactoryObjectIndex();
    moho::CScrLuaMetatableFactory<moho::MotorFallDown>::Instance().SetFactoryObjectIndexForRecovery(index);
    gRecoveredCScrLuaMetatableFactoryMotorFallDownIndex = index;
    return index;
  }

} // namespace

namespace moho
{
  gpg::RType* MotorFallDown::sType = nullptr;
  CScrLuaMetatableFactory<MotorFallDown> CScrLuaMetatableFactory<MotorFallDown>::sInstance{};

  CScrLuaMetatableFactory<MotorFallDown>& CScrLuaMetatableFactory<MotorFallDown>::Instance()
  {
    return sInstance;
  }

  /**
   * Address: 0x00695B90 (FUN_00695B90, Moho::CScrLuaMetatableFactory<Moho::MotorFallDown>::Create)
   */
  LuaPlus::LuaObject CScrLuaMetatableFactory<MotorFallDown>::Create(LuaPlus::LuaState* const state)
  {
    return SCR_CreateSimpleMetatable(state);
  }

  /**
   * Address: 0x00694CF0 (FUN_00694CF0, default ctor lane)
   */
  MotorFallDown::MotorFallDown()
    : Motor()
    , CScriptObject()
    , mFallDirectionRadians(0.0f)
    , mFallAngleRadians(0.0f)
    , mFallDepth(0.0f)
    , mBreakOnWhack(false)
  {
  }

  /**
   * Address: 0x00694BD0 (FUN_00694BD0, Lua ctor lane)
   */
  MotorFallDown::MotorFallDown(LuaPlus::LuaState* const state)
    : Motor()
    , CScriptObject(
        GetMotorFallDownLuaFactoryObject(state), LuaPlus::LuaObject{}, LuaPlus::LuaObject{}, LuaPlus::LuaObject{}
      )
    , mFallDirectionRadians(0.0f)
    , mFallAngleRadians(0.0f)
    , mFallDepth(0.0f)
    , mBreakOnWhack(false)
  {
  }

  /**
   * Address: 0x00694D70 (FUN_00694D70, deleting-thunk chain)
   * Address: 0x00694DA0 (FUN_00694DA0, non-deleting body)
   */
  MotorFallDown::~MotorFallDown()
  {
  }

  /**
   * Address: 0x00694B90 (FUN_00694B90, Moho::MotorFallDown::GetClass)
   */
  gpg::RType* MotorFallDown::GetClass() const
  {
    return CachedMotorFallDownType();
  }

  /**
   * Address: 0x00694BB0 (FUN_00694BB0, Moho::MotorFallDown::GetDerivedObjectRef)
   */
  gpg::RRef MotorFallDown::GetDerivedObjectRef()
  {
    gpg::RRef ref{};
    ref.mObj = this;
    ref.mType = GetClass();
    return ref;
  }

  /**
   * Address: 0x00695180 (FUN_00695180, update lane)
   *
   * Ground truth (`FUN_00695180.c`) confirms `delta` (whose own scalar lane
   * is `.w`, per `BuildRotationDeltaFromAxes`'s `Quaternion(1+dot, cross.x,
   * cross.y, cross.z)` construction) is composed onto the existing `.x`-
   * scalar `pendingTransform.orient_` via the same mixed-convention product
   * as `Entity.cpp`'s tilt-delta sites (`ComposeWScalarDeltaOntoOrientation`),
   * not the generic `Wm3::Quatf::Multiply` (`.w`-scalar on both operands).
   */
  void MotorFallDown::Update(Entity* const entity)
  {
    if (!entity || !entity->SimulationRef) {
      return;
    }

    Sim* const sim = entity->SimulationRef;
    if (mBreakOnWhack) {
      const float accelFactor = ReadSimConVarFloat(sim, &moho::gSimConVar_tree_AccelFactor, 0.1f);
      const float previousAngle = mFallAngleRadians;
      const float nextDepth = (accelFactor * previousAngle) + mFallDepth;
      mFallDepth = nextDepth;
      mFallAngleRadians = nextDepth + previousAngle;
    } else {
      const float springFactor = ReadSimConVarFloat(sim, &moho::gSimConVar_tree_SpringFactor, 0.5f);
      const float previousAngle = mFallAngleRadians;
      const float nextDepth = mFallDepth - (previousAngle * springFactor);
      mFallDepth = nextDepth;
      mFallAngleRadians = nextDepth + previousAngle;

      const float dampFactor = ReadSimConVarFloat(sim, &moho::gSimConVar_tree_DampFactor, 0.5f);
      mFallDepth = (1.0f - dampFactor) * mFallDepth;
    }

    if (mFallAngleRadians < 0.0f) {
      mFallAngleRadians *= -1.0f;
      mFallDepth *= -1.0f;
      mFallDirectionRadians = NormalizeAnglePositive(mFallDirectionRadians + kPi);
    }

    if (mFallAngleRadians > kHalfPi) {
      mFallAngleRadians = kHalfPi;
      mFallDepth = 0.0f;
    }

    const float elevationAngle = mFallAngleRadians - kHalfPi;
    const float sinTilt = msvc8::cos(elevationAngle);
    const Wm3::Vec3f targetAxis{
      msvc8::sin(mFallDirectionRadians) * sinTilt,
      -msvc8::sin(elevationAngle),
      msvc8::cos(mFallDirectionRadians) * sinTilt,
    };

    VTransform pendingTransform = entity->mVarDat.mCurTransform;

    const Wm3::Vec3f currentAxis = BuildCurrentFallAxis(pendingTransform.orient_);
    Wm3::Quatf delta = BuildRotationDeltaFromAxes(targetAxis, currentAxis);

    const float quatDeltaMagnitude = std::fabs(std::fabs(delta.w) - 1.0f);
    if (quatDeltaMagnitude <= kQuatUpdateThreshold) {
      return;
    }

    if (mBreakOnWhack && mFallAngleRadians > kQuarterPi) {
      const STIMap* const mapData = sim->mMapData;
      const CHeightField* const heightField = mapData ? mapData->mHeightField.get() : nullptr;
      if (heightField) {
        const float groundElevation = heightField->GetElevation(pendingTransform.pos_.x, pendingTransform.pos_.z);
        const float uprootFactor = ReadSimConVarFloat(sim, &moho::gSimConVar_tree_UprootFactor, 0.1f);
        const float sizeLane = entity->BluePrint ? entity->BluePrint->mSizeX : 0.0f;
        const float uprootTargetY = groundElevation + (sizeLane * uprootFactor);
        pendingTransform.pos_.y +=
          (uprootTargetY - pendingTransform.pos_.y) * (mFallAngleRadians - kQuarterPi) * kFourOverPi;
      }
    }

    pendingTransform.orient_ = MultiplyQuat(delta, pendingTransform.orient_);
    pendingTransform.orient_.Normalize();
    entity->SetPendingTransform(pendingTransform, 1.0f);
  }

  /**
   * Address: 0x00694E00 (FUN_00694E00, Moho::MotorFallDownTypeInfo::MotorFallDownTypeInfo)
   */
  MotorFallDownTypeInfo::MotorFallDownTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(MotorFallDown), this);
  }

  /**
   * Address: 0x00694F00 (FUN_00694F00, MotorFallDownTypeInfo non-deleting cleanup body)
   *
   * What it does:
   * Clears reflected base/field vector lanes for one `MotorFallDownTypeInfo`
   * instance while preserving outer storage ownership.
   */
  void DestroyMotorFallDownTypeInfoBody(MotorFallDownTypeInfo* const typeInfo) noexcept
  {
    if (typeInfo == nullptr) {
      return;
    }

    typeInfo->fields_ = {};
    typeInfo->bases_ = {};
  }

  /**
   * Address: 0x00694EA0 (FUN_00694EA0, Moho::MotorFallDownTypeInfo::dtr)
   */
  MotorFallDownTypeInfo::~MotorFallDownTypeInfo()
  {
    DestroyMotorFallDownTypeInfoBody(this);
  }

  /**
   * Address: 0x00694E90 (FUN_00694E90, Moho::MotorFallDownTypeInfo::GetName)
   */
  const char* MotorFallDownTypeInfo::GetName() const
  {
    return "MotorFallDown";
  }

  /**
   * Address: 0x00695CC0 (FUN_00695CC0, Moho::MotorFallDownTypeInfo::AddBase_CScriptObject)
   */
  void MotorFallDownTypeInfo::AddBase_CScriptObject(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = CachedCScriptObjectType();
    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = gpg::RType::BaseSubobjectOffset<MotorFallDown, CScriptObject>();
    baseField.mFlags = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x00695D20 (FUN_00695D20, Moho::MotorFallDownTypeInfo::AddBase_Motor)
   * Address: 0x00694F40 (FUN_00694F40, add-base thunk lane)
   */
  void MotorFallDownTypeInfo::AddBase_Motor(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = CachedMotorType();
    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.mFlags = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x00694E60 (FUN_00694E60, Moho::MotorFallDownTypeInfo::Init)
   */
  void MotorFallDownTypeInfo::Init()
  {
    size_ = sizeof(MotorFallDown);
    AddBase_CScriptObject(this);
    gpg::RType::Init();
    AddBase_Motor(this);
    Finish();
  }

  /**
   * Address: 0x00BD5BE0 (FUN_00BD5BE0, register_MotorFallDownTypeInfo)
   * Address: 0x00BFD130 (FUN_00BFD130, atexit destructor of the MotorFallDownTypeInfo object)
   */
  void register_MotorFallDownTypeInfo()
  {
    static MotorFallDownTypeInfo sInstance;
    (void)sInstance;
  }

  /**
   * Address: 0x00BD5CC0 (FUN_00BD5CC0, register_CScrLuaMetatableFactory_MotorFallDown_Index)
   */
  int register_CScrLuaMetatableFactory_MotorFallDown_Index()
  {
    return InitializeMotorFallDownLuaFactoryIndex();
  }

  namespace
  {
    constexpr const char* kMotorFallDownLuaClassName = "MotorFallDown";
    constexpr const char* kMotorFallDownWhackName = "Whack";
    constexpr const char* kMotorFallDownWhackHelpText = "MotorFallDown:Whack(nx,ny,nz,f,dobreak)";

    [[nodiscard]] CScrLuaInitFormSet& MotorFallDownSimLuaInitSet()
    {
      if (CScrLuaInitFormSet* const set = SCR_FindLuaInitFormSet("Sim"); set != nullptr) {
        return *set;
      }

      static CScrLuaInitFormSet fallbackSet("Sim");
      return fallbackSet;
    }

    [[nodiscard]] float ReadLuaNumberArg(LuaPlus::LuaState* const state, const int stackIndex)
    {
      LuaPlus::LuaStackObject arg(state, stackIndex);
      if (lua_type(state->m_state, stackIndex) != LUA_TNUMBER) {
        LuaPlus::LuaStackObject::TypeError(&arg, "number");
      }
      return static_cast<float>(lua_tonumber(state->m_state, stackIndex));
    }

    /**
     * Address: 0x00695140 (FUN_00695140)
     *
     * What it does:
     * Applies one whack impulse lane to `MotorFallDown`: initializes
     * `mFallDirectionRadians`/`mBreakOnWhack` from the first XZ normal pair and
     * accumulates force into `mFallDepth`.
     */
    bool ApplyMotorFallDownWhackImpulse(
      const float* const normalXYZ,
      MotorFallDown* const motor,
      const float force,
      const bool doBreak
    )
    {
      if (!motor->mBreakOnWhack) {
        motor->mFallDirectionRadians = msvc8::atan2(normalXYZ[0], normalXYZ[2]);
        motor->mBreakOnWhack = doBreak;
      }

      motor->mFallDepth += force;
      return doBreak;
    }
  } // namespace

  /**
   * Address: 0x00695720 (FUN_00695720, cfunc_MotorFallDownWhack)
   *
   * What it does:
   * Unwraps the raw `lua_State` callback context and forwards to
   * `cfunc_MotorFallDownWhackL`.
   */
  int cfunc_MotorFallDownWhack(lua_State* const luaContext)
  {
    return cfunc_MotorFallDownWhackL(SCR_ResolveBindingState(luaContext));
  }

  /**
   * Address: 0x006957A0 (FUN_006957A0, cfunc_MotorFallDownWhackL)
   *
   * What it does:
   * Parses `MotorFallDown:Whack(nx, ny, nz, force, dobreak)`. On the first
   * whack the motor captures the XZ-plane fall direction from
   * `atan2(nx, nz)` and latches the `dobreak` flag into `mBreakOnWhack`,
   * which switches the update loop from the spring-return path to the
   * gravity-accelerated fall path. Every call adds `force` to the motor's
   * angular-velocity accumulator (`mFallDepth`). The `ny` argument
   * (vertical component of the hit normal) is intentionally ignored —
   * only the horizontal XZ direction drives the fall orientation.
   */
  int cfunc_MotorFallDownWhackL(LuaPlus::LuaState* const state)
  {
    if (!state || !state->m_state) {
      return 0;
    }

    lua_State* const rawState = state->m_state;
    const int argumentCount = lua_gettop(rawState);
    if (argumentCount != 6) {
      LuaPlus::LuaState::Error(
        state, "%s\n  expected %d args, but got %d", kMotorFallDownWhackHelpText, 6, argumentCount
      );
    }

    const LuaPlus::LuaObject selfObject(LuaPlus::LuaStackObject(state, 1));
    MotorFallDown* const motor = SCR_FromLua_MotorFallDown(selfObject, state);
    if (!motor) {
      return 0;
    }

    const float normalX = ReadLuaNumberArg(state, 2);
    (void)ReadLuaNumberArg(state, 3); // ny: hit-normal vertical — unused for XZ fall direction.
    const float normalZ = ReadLuaNumberArg(state, 4);
    const float force = ReadLuaNumberArg(state, 5);

    LuaPlus::LuaStackObject dobreakArg(state, 6);
    const bool dobreak = LuaPlus::LuaStackObject::GetBoolean(&dobreakArg);

    const float hitNormal[3]{normalX, 0.0f, normalZ};
    (void)ApplyMotorFallDownWhackImpulse(hitNormal, motor, force, dobreak);

    lua_settop(rawState, 1);
    return 1;
  }

  /**
    * Alias of FUN_00695740 (non-canonical helper lane).
   *
   * What it does:
   * Publishes `MotorFallDown:Whack()` into the sim Lua init set.
   */
  CScrLuaInitForm* func_MotorFallDownWhack_LuaFuncDef()
  {
    static CScrLuaBinder binder(
      MotorFallDownSimLuaInitSet(),
      kMotorFallDownWhackName,
      &cfunc_MotorFallDownWhack,
      &CScrLuaMetatableFactory<MotorFallDown>::Instance(),
      kMotorFallDownLuaClassName,
      kMotorFallDownWhackHelpText
    );
    return &binder;
  }
} // namespace moho

namespace
{
  struct MotorFallDownBootstrap
  {
    MotorFallDownBootstrap()
    {
      moho::register_MotorFallDownTypeInfo();
      (void)moho::register_CScrLuaMetatableFactory_MotorFallDown_Index();
    }
  };

  [[maybe_unused]] MotorFallDownBootstrap gMotorFallDownBootstrap;
} // namespace

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_MotorFallDownTypeInfo_920782, moho::register_MotorFallDownTypeInfo)

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
  struct MotorFallDownLuaFuncDefBootstrap
  {
    MotorFallDownLuaFuncDefBootstrap()
    {
      (void)::moho::func_MotorFallDownWhack_LuaFuncDef();
    }
  };

  const MotorFallDownLuaFuncDefBootstrap gMotorFallDownLuaFuncDefBootstrap{};
} // namespace

namespace moho
{
  /**
   * Address: 0x00696110 (FUN_00696110)
   */
  void MotorFallDown::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    const gpg::RRef owner{};
    archive->Read(CachedMotorType(), static_cast<Motor*>(this), owner);
    archive->Read(CachedCScriptObjectType(), static_cast<CScriptObject*>(this), owner);
    archive->ReadFloat(&mFallDirectionRadians);
    archive->ReadFloat(&mFallAngleRadians);
    archive->ReadFloat(&mFallDepth);
    archive->ReadBool(&mBreakOnWhack);
  }

  /**
   * Address: 0x006961D0 (FUN_006961D0)
   */
  void MotorFallDown::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    const gpg::RRef owner{};
    archive->Write(CachedMotorType(), static_cast<const Motor*>(this), owner);
    archive->Write(CachedCScriptObjectType(), static_cast<const CScriptObject*>(this), owner);
    archive->WriteFloat(mFallDirectionRadians);
    archive->WriteFloat(mFallAngleRadians);
    archive->WriteFloat(mFallDepth);
    archive->WriteBool(mBreakOnWhack);
  }
} // namespace moho

namespace moho
{
  /**
   * Address: 0x00694FF0 (FUN_00694FF0)
   */
  void MotorFallDown::MemberConstruct(gpg::ReadArchive&, const int, const gpg::RRef&, gpg::SerConstructResult& result)
  {
    result.SetUnowned(gpg::MakeRRef(new MotorFallDown()), 0u);
  }

  /**
   * `gpg::SerConstructHelper<MotorFallDown>`, vtable 0x00E291E4.
   *
   * Address: 0x00BD5C00 (FUN_00BD5C00 -- constructs the global and registers its destructor.)
   * Address: 0x00BFD190 (FUN_00BFD190 -- the global's destructor.)
   * Address: 0x00694F50 (FUN_00694F50 -- an unreferenced out-of-line copy of the constructor.)
   * Address: 0x00695A40 (FUN_00695A40 -- `Init`.)
   * Address: 0x00694FE0 (FUN_00694FE0 -- `Construct`, a forward to `MemberConstruct`.)
   * Address: 0x00695D80 (FUN_00695D80 -- `Delete`.)
   */
  struct MotorFallDownConstruct : gpg::SerConstructHelper<MotorFallDown>
  {};

  /**
   * `gpg::SerSaveLoadHelper<MotorFallDown>`, vtable 0x00E291F4.
   *
   * Address: 0x00BD5C40 (FUN_00BD5C40 -- constructs the global and registers its destructor.)
   * Address: 0x00BFD1C0 (FUN_00BFD1C0 -- the global's destructor.)
   * Address: 0x006950B0 (FUN_006950B0 -- an unreferenced out-of-line copy of the constructor.)
   * Address: 0x00695AC0 (FUN_00695AC0 -- `Init`.)
   * Address: 0x00695080 (FUN_00695080 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x00695090 (FUN_00695090 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct MotorFallDownSerializer : gpg::SerSaveLoadHelper<MotorFallDown>
  {};
} // namespace moho

namespace
{
  // Address: 0x010B5080 -- process-global `MotorFallDownConstruct` singleton.
  moho::MotorFallDownConstruct gMotorFallDownConstruct;

  // Address: 0x010B50A8 -- process-global `MotorFallDownSerializer` singleton.
  moho::MotorFallDownSerializer gMotorFallDownSerializer;
} // namespace
