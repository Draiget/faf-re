#include "moho/entity/MotorFallDown.h"

#include <cmath>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <string>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/entity/Entity.h"
#include "moho/entity/EntityTransformPayload.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/misc/StatItem.h"
#include "moho/misc/Stats.h"
#include "moho/sim/CSimConVarBase.h"
#include "moho/sim/Sim.h"
#include "moho/sim/SimStartupRegistrations.h"
#include "moho/sim/STIMap.h"

#pragma init_seg(lib)

namespace gpg
{
  class SerConstructResult
  {
  public:
    void SetUnowned(const RRef& ref, unsigned int flags);
  };
} // namespace gpg

namespace
{
  constexpr float kPi = 3.1415927f;
  constexpr float kHalfPi = 1.5707964f;
  constexpr float kQuarterPi = 0.78539819f;
  constexpr float kFourOverPi = 1.2732395f;
  constexpr float kTwoPi = 6.2831855f;
  constexpr float kQuatUpdateThreshold = 0.0001f;

  alignas(moho::MotorFallDownTypeInfo)
    unsigned char gMotorFallDownTypeInfoStorage[sizeof(moho::MotorFallDownTypeInfo)];
  bool gMotorFallDownTypeInfoConstructed = false;
  moho::MotorFallDownSerializer gMotorFallDownSerializer{};
  moho::MotorFallDownConstruct gMotorFallDownConstruct{};
  std::int32_t gRecoveredCScrLuaMetatableFactoryMotorFallDownIndex = 0;

  [[nodiscard]] moho::MotorFallDownTypeInfo& MotorFallDownTypeInfoStorageRef() noexcept
  {
    return *reinterpret_cast<moho::MotorFallDownTypeInfo*>(gMotorFallDownTypeInfoStorage);
  }

  [[nodiscard]] gpg::RType* CachedMotorFallDownType()
  {
    if (!moho::MotorFallDown::sType) {
      moho::MotorFallDown::sType = gpg::LookupRType(typeid(moho::MotorFallDown));
    }

    GPG_ASSERT(moho::MotorFallDown::sType != nullptr);
    return moho::MotorFallDown::sType;
  }

  [[nodiscard]] gpg::RType* CachedMotorType()
  {
    if (!moho::EntityMotor::sType) {
      moho::EntityMotor::sType = gpg::LookupRType(typeid(moho::EntityMotor));
    }

    GPG_ASSERT(moho::EntityMotor::sType != nullptr);
    return moho::EntityMotor::sType;
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

  void AddInstanceCounterDelta(moho::StatItem* const statItem, const long delta) noexcept
  {
    if (!statItem) {
      return;
    }

#if defined(_WIN32)
    InterlockedExchangeAdd(reinterpret_cast<volatile long*>(&statItem->mPrimaryValueBits), delta);
#else
    statItem->mPrimaryValueBits += static_cast<std::int32_t>(delta);
#endif
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
      ((orientation.z * orientation.y) - (orientation.w * orientation.x)) * 2.0f,
      1.0f - ((orientation.w * orientation.w + orientation.y * orientation.y) * 2.0f),
      ((orientation.w * orientation.z) + (orientation.y * orientation.x)) * 2.0f,
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

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* HelperSelfNode(THelper& helper) noexcept
  {
    return &helper.mHelperLinks;
  }

  template <typename THelper>
  void InitializeHelperNode(THelper& helper) noexcept
  {
    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperLinks.mNext = self;
    helper.mHelperLinks.mPrev = self;
  }

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* UnlinkHelperNode(THelper& helper) noexcept
  {
    if (helper.mHelperLinks.mNext != nullptr && helper.mHelperLinks.mPrev != nullptr) {
      helper.mHelperLinks.mNext->mPrev = helper.mHelperLinks.mPrev;
      helper.mHelperLinks.mPrev->mNext = helper.mHelperLinks.mNext;
    }

    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperLinks.mPrev = self;
    helper.mHelperLinks.mNext = self;
    return self;
  }

  /**
   * Address: 0x00694FF0 (FUN_00694FF0, construct helper body)
   */
  void ConstructMotorFallDownObject(gpg::SerConstructResult* const result)
  {
    moho::MotorFallDown* const object = new (std::nothrow) moho::MotorFallDown();
    if (!result) {
      return;
    }

    const gpg::RRef objectRef = MakeMotorFallDownRef(object);
    result->SetUnowned(objectRef, 0u);
  }

  /**
   * Address: 0x00694FE0 (FUN_00694FE0, construct callback thunk)
   */
  void ConstructMotorFallDownCallback(gpg::ReadArchive*, const int, const int, gpg::SerConstructResult* const result)
  {
    ConstructMotorFallDownObject(result);
  }

  /**
   * Address: 0x00695D80 (FUN_00695D80, delete callback thunk)
   */
  void DeleteConstructedMotorFallDown(void* const objectPtr)
  {
    delete static_cast<moho::MotorFallDown*>(objectPtr);
  }

  /**
   * Address: 0x00696110 (FUN_00696110, serializer load body)
   */
  void DeserializeMotorFallDownBody(moho::MotorFallDown* const object, gpg::ReadArchive* const archive)
  {
    if (!object || !archive) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->Read(CachedMotorType(), static_cast<moho::EntityMotor*>(object), nullOwner);
    archive->Read(CachedCScriptObjectType(), static_cast<moho::CScriptObject*>(object), nullOwner);
    archive->ReadFloat(&object->mFallDirectionRadians);
    archive->ReadFloat(&object->mFallAngleRadians);
    archive->ReadFloat(&object->mFallDepth);
    archive->ReadBool(&object->mBreakOnWhack);
  }

  /**
   * Address: 0x006961D0 (FUN_006961D0, serializer save body)
   */
  void SerializeMotorFallDownBody(const moho::MotorFallDown* const object, gpg::WriteArchive* const archive)
  {
    if (!object || !archive) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->Write(CachedMotorType(), static_cast<const moho::EntityMotor*>(object), nullOwner);
    archive->Write(CachedCScriptObjectType(), static_cast<const moho::CScriptObject*>(object), nullOwner);
    archive->WriteFloat(object->mFallDirectionRadians);
    archive->WriteFloat(object->mFallAngleRadians);
    archive->WriteFloat(object->mFallDepth);
    archive->WriteBool(object->mBreakOnWhack);
  }

  /**
   * Address: 0x00695DE0 (FUN_00695DE0, serializer load thunk alias)
   *
   * What it does:
   * Tail-forwards the MotorFallDown deserialize thunk alias to the recovered
   * serializer load body.
   */
  void DeserializeMotorFallDownThunkVariantA(moho::MotorFallDown* const object, gpg::ReadArchive* const archive)
  {
    DeserializeMotorFallDownBody(object, archive);
  }

  /**
   * Address: 0x00695DF0 (FUN_00695DF0, serializer save thunk alias)
   *
   * What it does:
   * Tail-forwards the MotorFallDown serialize thunk alias to the recovered
   * serializer save body.
   */
  void SerializeMotorFallDownThunkVariantA(const moho::MotorFallDown* const object, gpg::WriteArchive* const archive)
  {
    SerializeMotorFallDownBody(object, archive);
  }

  /**
   * Address: 0x006960B0 (FUN_006960B0, serializer load thunk alias)
   *
   * What it does:
   * Tail-forwards the second MotorFallDown deserialize thunk alias to the
   * recovered serializer load body.
   */
  void DeserializeMotorFallDownThunkVariantB(moho::MotorFallDown* const object, gpg::ReadArchive* const archive)
  {
    DeserializeMotorFallDownBody(object, archive);
  }

  /**
   * Address: 0x006960C0 (FUN_006960C0, serializer save thunk alias)
   *
   * What it does:
   * Tail-forwards the second MotorFallDown serialize thunk alias to the
   * recovered serializer save body.
   */
  void SerializeMotorFallDownThunkVariantB(const moho::MotorFallDown* const object, gpg::WriteArchive* const archive)
  {
    SerializeMotorFallDownBody(object, archive);
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

  void cleanup_MotorFallDownConstruct_atexit()
  {
    (void)moho::cleanup_MotorFallDownConstruct();
  }

  void cleanup_MotorFallDownSerializer_atexit()
  {
    (void)moho::cleanup_MotorFallDownSerializer();
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
    : EntityMotor()
    , CScriptObject()
    , mFallDirectionRadians(0.0f)
    , mFallAngleRadians(0.0f)
    , mFallDepth(0.0f)
    , mBreakOnWhack(false)
  {
    AddInstanceCounterDelta(InstanceCounter<MotorFallDown>::GetStatItem(), 1);
  }

  /**
   * Address: 0x00694BD0 (FUN_00694BD0, Lua ctor lane)
   */
  MotorFallDown::MotorFallDown(LuaPlus::LuaState* const state)
    : EntityMotor()
    , CScriptObject(
        GetMotorFallDownLuaFactoryObject(state), LuaPlus::LuaObject{}, LuaPlus::LuaObject{}, LuaPlus::LuaObject{}
      )
    , mFallDirectionRadians(0.0f)
    , mFallAngleRadians(0.0f)
    , mFallDepth(0.0f)
    , mBreakOnWhack(false)
  {
    AddInstanceCounterDelta(InstanceCounter<MotorFallDown>::GetStatItem(), 1);
  }

  /**
   * Address: 0x00694D70 (FUN_00694D70, deleting-thunk chain)
   * Address: 0x00694DA0 (FUN_00694DA0, non-deleting body)
   */
  MotorFallDown::~MotorFallDown()
  {
    AddInstanceCounterDelta(InstanceCounter<MotorFallDown>::GetStatItem(), -1);
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
   */
  void MotorFallDown::Update(Entity* const entity)
  {
    if (!entity || !entity->SimulationRef) {
      return;
    }

    Sim* const sim = entity->SimulationRef;
    if (mBreakOnWhack) {
      const float accelFactor = ReadSimConVarFloat(sim, GetTreeAccelFactorSimConVarDef(), 0.1f);
      const float previousAngle = mFallAngleRadians;
      const float nextDepth = (accelFactor * previousAngle) + mFallDepth;
      mFallDepth = nextDepth;
      mFallAngleRadians = nextDepth + previousAngle;
    } else {
      const float springFactor = ReadSimConVarFloat(sim, GetTreeSpringFactorSimConVarDef(), 0.5f);
      const float previousAngle = mFallAngleRadians;
      const float nextDepth = mFallDepth - (previousAngle * springFactor);
      mFallDepth = nextDepth;
      mFallAngleRadians = nextDepth + previousAngle;

      const float dampFactor = ReadSimConVarFloat(sim, GetTreeDampFactorSimConVarDef(), 0.5f);
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
    const float sinTilt = std::cos(elevationAngle);
    const Wm3::Vec3f targetAxis{
      std::sin(mFallDirectionRadians) * sinTilt,
      -std::sin(elevationAngle),
      std::cos(mFallDirectionRadians) * sinTilt,
    };

    const EntityTransformPayload currentPayload = ReadEntityTransformPayload(entity->Orientation, entity->Position);
    VTransform pendingTransform = BuildVTransformFromEntityTransformPayload(currentPayload);

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
        const float uprootFactor = ReadSimConVarFloat(sim, GetTreeUprootFactorSimConVarDef(), 0.1f);
        const float sizeLane = entity->BluePrint ? entity->BluePrint->mSizeX : 0.0f;
        const float uprootTargetY = groundElevation + (sizeLane * uprootFactor);
        pendingTransform.pos_.y +=
          (uprootTargetY - pendingTransform.pos_.y) * (mFallAngleRadians - kQuarterPi) * kFourOverPi;
      }
    }

    pendingTransform.orient_ = Wm3::Quatf::Multiply(delta, pendingTransform.orient_);
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
   * Address: 0x00694EA0 (FUN_00694EA0, Moho::MotorFallDownTypeInfo::dtr)
   */
  MotorFallDownTypeInfo::~MotorFallDownTypeInfo()
  {
    fields_ = {};
    bases_ = {};
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
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x00695D20 (FUN_00695D20, Moho::MotorFallDownTypeInfo::AddBase_Motor)
   */
  void MotorFallDownTypeInfo::AddBase_Motor(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = CachedMotorType();
    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = 0;
    baseField.v4 = 0;
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
   * Address: 0x00695080 (FUN_00695080, serializer load thunk)
   */
  void MotorFallDownSerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    DeserializeMotorFallDownBody(reinterpret_cast<MotorFallDown*>(objectPtr), archive);
  }

  /**
   * Address: 0x00695090 (FUN_00695090, serializer save thunk)
   */
  void MotorFallDownSerializer::Serialize(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    SerializeMotorFallDownBody(reinterpret_cast<const MotorFallDown*>(objectPtr), archive);
  }

  /**
   * Address: 0x006950B0 (FUN_006950B0, serializer registration lane)
   */
  void MotorFallDownSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CachedMotorFallDownType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mDeserialize);
    GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSerialize);
    type->serLoadFunc_ = mDeserialize;
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00694F50 (FUN_00694F50, construct registration lane)
   */
  void MotorFallDownConstruct::RegisterConstructFunction()
  {
    gpg::RType* const type = CachedMotorFallDownType();
    GPG_ASSERT(type->serConstructFunc_ == nullptr || type->serConstructFunc_ == mConstructCallback);
    GPG_ASSERT(type->deleteFunc_ == nullptr || type->deleteFunc_ == mDeleteCallback);
    type->serConstructFunc_ = mConstructCallback;
    type->deleteFunc_ = mDeleteCallback;
  }

  /**
   * Address: 0x00BFD130 (FUN_00BFD130, cleanup_MotorFallDownTypeInfo)
   */
  void cleanup_MotorFallDownTypeInfo()
  {
    if (!gMotorFallDownTypeInfoConstructed) {
      return;
    }

    MotorFallDownTypeInfoStorageRef().~MotorFallDownTypeInfo();
    gMotorFallDownTypeInfoConstructed = false;
    MotorFallDown::sType = nullptr;
  }

  /**
   * Address: 0x00BFD190 (FUN_00BFD190, cleanup_MotorFallDownConstruct)
   */
  gpg::SerHelperBase* cleanup_MotorFallDownConstruct()
  {
    return UnlinkHelperNode(gMotorFallDownConstruct);
  }

  /**
   * Address: 0x00BFD1C0 (FUN_00BFD1C0, cleanup_MotorFallDownSerializer)
   */
  gpg::SerHelperBase* cleanup_MotorFallDownSerializer()
  {
    return UnlinkHelperNode(gMotorFallDownSerializer);
  }

  /**
   * Address: 0x00BD5BE0 (FUN_00BD5BE0, register_MotorFallDownTypeInfo)
   */
  void register_MotorFallDownTypeInfo()
  {
    if (!gMotorFallDownTypeInfoConstructed) {
      new (gMotorFallDownTypeInfoStorage) MotorFallDownTypeInfo();
      gMotorFallDownTypeInfoConstructed = true;
    }

    (void)std::atexit(&cleanup_MotorFallDownTypeInfo);
  }

  /**
   * Address: 0x00BD5C00 (FUN_00BD5C00, register_MotorFallDownConstruct)
   */
  int register_MotorFallDownConstruct()
  {
    InitializeHelperNode(gMotorFallDownConstruct);
    gMotorFallDownConstruct.mConstructCallback =
      reinterpret_cast<gpg::RType::construct_func_t>(&ConstructMotorFallDownCallback);
    gMotorFallDownConstruct.mDeleteCallback = &DeleteConstructedMotorFallDown;
    gMotorFallDownConstruct.RegisterConstructFunction();
    return std::atexit(&cleanup_MotorFallDownConstruct_atexit);
  }

  /**
   * Address: 0x00BD5C40 (FUN_00BD5C40, register_MotorFallDownSerializer)
   */
  int register_MotorFallDownSerializer()
  {
    InitializeHelperNode(gMotorFallDownSerializer);
    gMotorFallDownSerializer.mDeserialize = &MotorFallDownSerializer::Deserialize;
    gMotorFallDownSerializer.mSerialize = &MotorFallDownSerializer::Serialize;
    gMotorFallDownSerializer.RegisterSerializeFunctions();
    return std::atexit(&cleanup_MotorFallDownSerializer_atexit);
  }

  /**
   * Address: 0x00BD5CC0 (FUN_00BD5CC0, register_CScrLuaMetatableFactory_MotorFallDown_Index)
   */
  int register_CScrLuaMetatableFactory_MotorFallDown_Index()
  {
    return InitializeMotorFallDownLuaFactoryIndex();
  }
} // namespace moho

/**
 * Address: 0x00695BC0 (FUN_00695BC0, Moho::InstanceCounter<Moho::MotorFallDown>::GetStatItem)
 */
template <>
moho::StatItem* moho::InstanceCounter<moho::MotorFallDown>::GetStatItem()
{
  static moho::StatItem* sStatItem = nullptr;
  if (sStatItem) {
    return sStatItem;
  }

  moho::EngineStats* const engineStats = moho::GetEngineStats();
  if (!engineStats) {
    return nullptr;
  }

  std::string statPath("Instance Counts_");
  const char* const rawTypeName = typeid(moho::MotorFallDown).name();
  for (const char* it = rawTypeName; it && *it != '\0'; ++it) {
    if (*it != '_') {
      statPath.push_back(*it);
    }
  }

  sStatItem = engineStats->GetItem(statPath.c_str(), true);
  return sStatItem;
}

namespace
{
  struct MotorFallDownBootstrap
  {
    MotorFallDownBootstrap()
    {
      moho::register_MotorFallDownTypeInfo();
      (void)moho::register_MotorFallDownConstruct();
      (void)moho::register_MotorFallDownSerializer();
      (void)moho::register_CScrLuaMetatableFactory_MotorFallDown_Index();
    }
  };

  [[maybe_unused]] MotorFallDownBootstrap gMotorFallDownBootstrap;
} // namespace
