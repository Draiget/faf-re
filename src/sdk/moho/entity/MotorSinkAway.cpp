#include "moho/entity/MotorSinkAway.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/lua/CScrLuaObjectFactory.h"

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
  alignas(moho::MotorSinkAwayTypeInfo)
    unsigned char gMotorSinkAwayTypeInfoStorage[sizeof(moho::MotorSinkAwayTypeInfo)];
  bool gMotorSinkAwayTypeInfoConstructed = false;
  moho::MotorSinkAwaySerializer gMotorSinkAwaySerializer{};
  moho::MotorSinkAwayConstruct gMotorSinkAwayConstruct{};
  std::int32_t gRecoveredCScrLuaMetatableFactoryMotorSinkAwayIndex = 0;

  [[nodiscard]] moho::MotorSinkAwayTypeInfo& MotorSinkAwayTypeInfoStorageRef() noexcept
  {
    return *reinterpret_cast<moho::MotorSinkAwayTypeInfo*>(gMotorSinkAwayTypeInfoStorage);
  }

  [[nodiscard]] gpg::RType* CachedMotorSinkAwayType()
  {
    if (!moho::MotorSinkAway::sType) {
      moho::MotorSinkAway::sType = gpg::LookupRType(typeid(moho::MotorSinkAway));
    }

    GPG_ASSERT(moho::MotorSinkAway::sType != nullptr);
    return moho::MotorSinkAway::sType;
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

  [[nodiscard]] gpg::RRef MakeMotorSinkAwayRef(moho::MotorSinkAway* const object)
  {
    gpg::RRef ref{};
    ref.mObj = object;
    ref.mType = CachedMotorSinkAwayType();
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
   * Address: 0x006967F0 (FUN_006967F0, construct helper body)
   */
  void Construct_MotorSinkAway_Object(gpg::SerConstructResult* const result)
  {
    moho::MotorSinkAway* const object = new (std::nothrow) moho::MotorSinkAway();
    if (!result) {
      return;
    }

    const gpg::RRef ref = MakeMotorSinkAwayRef(object);
    result->SetUnowned(ref, 0u);
  }

  /**
   * Address: 0x006967E0 (FUN_006967E0, construct callback thunk)
   */
  void Construct_MotorSinkAway_Callback(
    gpg::ReadArchive*, const int, const int, gpg::SerConstructResult* const result
  )
  {
    Construct_MotorSinkAway_Object(result);
  }

  /**
   * Address: 0x00696F50 (FUN_00696F50, delete callback thunk)
   */
  void DeleteConstructedMotorSinkAway(void* const objectPtr)
  {
    delete static_cast<moho::MotorSinkAway*>(objectPtr);
  }

  /**
   * Address: 0x00697200 (FUN_00697200, serializer load body)
   */
  void DeserializeMotorSinkAwayBody(moho::MotorSinkAway* const object, gpg::ReadArchive* const archive)
  {
    if (!object || !archive) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->Read(CachedMotorType(), static_cast<moho::EntityMotor*>(object), nullOwner);
    archive->Read(CachedCScriptObjectType(), static_cast<moho::CScriptObject*>(object), nullOwner);
    archive->ReadFloat(&object->mSinkDeltaY);
  }

  /**
   * Address: 0x00697290 (FUN_00697290, serializer save body)
   */
  void SerializeMotorSinkAwayBody(const moho::MotorSinkAway* const object, gpg::WriteArchive* const archive)
  {
    if (!object || !archive) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->Write(CachedMotorType(), static_cast<const moho::EntityMotor*>(object), nullOwner);
    archive->Write(CachedCScriptObjectType(), static_cast<const moho::CScriptObject*>(object), nullOwner);
    archive->WriteFloat(object->mSinkDeltaY);
  }

  void cleanup_MotorSinkAwayConstruct_atexit()
  {
    (void)moho::cleanup_MotorSinkAwayConstruct();
  }

  void cleanup_MotorSinkAwaySerializer_atexit()
  {
    (void)moho::cleanup_MotorSinkAwaySerializer();
  }
} // namespace

namespace moho
{
  gpg::RType* MotorSinkAway::sType = nullptr;

  /**
   * Address: 0x00696500 (FUN_00696500, default ctor)
   */
  MotorSinkAway::MotorSinkAway()
    : EntityMotor()
    , CScriptObject()
    , mSinkDeltaY(0.0f)
  {}

  /**
   * Address: 0x00696580 (FUN_00696580, deleting-thunk chain)
   */
  MotorSinkAway::~MotorSinkAway() = default;

  /**
   * Address: 0x006965A0 (FUN_006965A0, Moho::MotorSinkAway::GetClass)
   */
  gpg::RType* MotorSinkAway::GetClass() const
  {
    return CachedMotorSinkAwayType();
  }

  /**
   * Address: 0x00696700 (FUN_00696700, Moho::MotorSinkAway::GetDerivedObjectRef)
   */
  gpg::RRef MotorSinkAway::GetDerivedObjectRef()
  {
    gpg::RRef ref{};
    ref.mObj = this;
    ref.mType = GetClass();
    return ref;
  }

  /**
   * Address: 0x00696750 (FUN_00696750, update lane)
   */
  void MotorSinkAway::Update(Entity* const)
  {}

  /**
   * Address: 0x00696600 (FUN_00696600, Moho::MotorSinkAwayTypeInfo::MotorSinkAwayTypeInfo)
   */
  MotorSinkAwayTypeInfo::MotorSinkAwayTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(MotorSinkAway), this);
  }

  /**
   * Address: 0x006966A0 (FUN_006966A0, Moho::MotorSinkAwayTypeInfo::dtr)
   */
  MotorSinkAwayTypeInfo::~MotorSinkAwayTypeInfo()
  {
    fields_ = {};
    bases_ = {};
  }

  /**
   * Address: 0x00696690 (FUN_00696690, Moho::MotorSinkAwayTypeInfo::GetName)
   */
  const char* MotorSinkAwayTypeInfo::GetName() const
  {
    return "MotorSinkAway";
  }

  /**
   * Address: 0x00696E90 (FUN_00696E90, Moho::MotorSinkAwayTypeInfo::AddBase_CScriptObject)
   */
  void MotorSinkAwayTypeInfo::AddBase_CScriptObject(gpg::RType* const typeInfo)
  {
    gpg::RType* const baseType = CachedCScriptObjectType();
    gpg::RField baseField{};
    baseField.mName = baseType->GetName();
    baseField.mType = baseType;
    baseField.mOffset = gpg::RType::BaseSubobjectOffset<MotorSinkAway, CScriptObject>();
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  /**
   * Address: 0x00696EF0 (FUN_00696EF0, Moho::MotorSinkAwayTypeInfo::AddBase_Motor)
   */
  void MotorSinkAwayTypeInfo::AddBase_Motor(gpg::RType* const typeInfo)
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
   * Address: 0x00696660 (FUN_00696660, Moho::MotorSinkAwayTypeInfo::Init)
   */
  void MotorSinkAwayTypeInfo::Init()
  {
    size_ = sizeof(MotorSinkAway);
    AddBase_CScriptObject(this);
    gpg::RType::Init();
    AddBase_Motor(this);
    Finish();
  }

  /**
   * Address: 0x00696880 (FUN_00696880, serializer load thunk)
   */
  void MotorSinkAwaySerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    DeserializeMotorSinkAwayBody(reinterpret_cast<MotorSinkAway*>(objectPtr), archive);
  }

  /**
   * Address: 0x00696890 (FUN_00696890, serializer save thunk)
   */
  void MotorSinkAwaySerializer::Serialize(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    SerializeMotorSinkAwayBody(reinterpret_cast<const MotorSinkAway*>(objectPtr), archive);
  }

  /**
   * Address: 0x006968B0 (FUN_006968B0, serializer registration lane)
   */
  void MotorSinkAwaySerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CachedMotorSinkAwayType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mDeserialize);
    GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSerialize);
    type->serLoadFunc_ = mDeserialize;
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x006967E0 (FUN_006967E0, construct registration lane)
   */
  void MotorSinkAwayConstruct::RegisterConstructFunction()
  {
    gpg::RType* const type = CachedMotorSinkAwayType();
    GPG_ASSERT(type->serConstructFunc_ == nullptr || type->serConstructFunc_ == mConstructCallback);
    GPG_ASSERT(type->deleteFunc_ == nullptr || type->deleteFunc_ == mDeleteCallback);
    type->serConstructFunc_ = mConstructCallback;
    type->deleteFunc_ = mDeleteCallback;
  }

  /**
   * Address: 0x00BFD210 (FUN_00BFD210, cleanup_MotorSinkAwayTypeInfo)
   */
  void cleanup_MotorSinkAwayTypeInfo()
  {
    if (!gMotorSinkAwayTypeInfoConstructed) {
      return;
    }

    MotorSinkAwayTypeInfoStorageRef().~MotorSinkAwayTypeInfo();
    gMotorSinkAwayTypeInfoConstructed = false;
    MotorSinkAway::sType = nullptr;
  }

  /**
   * Address: 0x00BFD270 (FUN_00BFD270, cleanup_MotorSinkAwayConstruct)
   */
  gpg::SerHelperBase* cleanup_MotorSinkAwayConstruct()
  {
    return UnlinkHelperNode(gMotorSinkAwayConstruct);
  }

  /**
   * Address: 0x00BFD2A0 (FUN_00BFD2A0, cleanup_MotorSinkAwaySerializer)
   */
  gpg::SerHelperBase* cleanup_MotorSinkAwaySerializer()
  {
    return UnlinkHelperNode(gMotorSinkAwaySerializer);
  }

  /**
   * Address: 0x00BD5D50 (FUN_00BD5D50, register_MotorSinkAwayTypeInfo)
   */
  void register_MotorSinkAwayTypeInfo()
  {
    if (!gMotorSinkAwayTypeInfoConstructed) {
      new (gMotorSinkAwayTypeInfoStorage) MotorSinkAwayTypeInfo();
      gMotorSinkAwayTypeInfoConstructed = true;
    }

    (void)std::atexit(&cleanup_MotorSinkAwayTypeInfo);
  }

  /**
   * Address: 0x00BD5D70 (FUN_00BD5D70, register_MotorSinkAwayConstruct)
   */
  int register_MotorSinkAwayConstruct()
  {
    InitializeHelperNode(gMotorSinkAwayConstruct);
    gMotorSinkAwayConstruct.mConstructCallback =
      reinterpret_cast<gpg::RType::construct_func_t>(&Construct_MotorSinkAway_Callback);
    gMotorSinkAwayConstruct.mDeleteCallback = &DeleteConstructedMotorSinkAway;
    gMotorSinkAwayConstruct.RegisterConstructFunction();
    return std::atexit(&cleanup_MotorSinkAwayConstruct_atexit);
  }

  /**
   * Address: 0x00BD5DB0 (FUN_00BD5DB0, register_MotorSinkAwaySerializer)
   */
  int register_MotorSinkAwaySerializer()
  {
    InitializeHelperNode(gMotorSinkAwaySerializer);
    gMotorSinkAwaySerializer.mDeserialize = &MotorSinkAwaySerializer::Deserialize;
    gMotorSinkAwaySerializer.mSerialize = &MotorSinkAwaySerializer::Serialize;
    gMotorSinkAwaySerializer.RegisterSerializeFunctions();
    return std::atexit(&cleanup_MotorSinkAwaySerializer_atexit);
  }

  /**
   * Address: 0x00BD5E00 (FUN_00BD5E00, register_CScrLuaMetatableFactory_MotorSinkAway_Index)
   */
  int register_CScrLuaMetatableFactory_MotorSinkAway_Index()
  {
    const int index = CScrLuaObjectFactory::AllocateFactoryObjectIndex();
    gRecoveredCScrLuaMetatableFactoryMotorSinkAwayIndex = index;
    return index;
  }
} // namespace moho

namespace
{
  struct MotorSinkAwayBootstrap
  {
    MotorSinkAwayBootstrap()
    {
      moho::register_MotorSinkAwayTypeInfo();
      (void)moho::register_MotorSinkAwayConstruct();
      (void)moho::register_MotorSinkAwaySerializer();
      (void)moho::register_CScrLuaMetatableFactory_MotorSinkAway_Index();
    }
  };

  [[maybe_unused]] MotorSinkAwayBootstrap gMotorSinkAwayBootstrap;
} // namespace

