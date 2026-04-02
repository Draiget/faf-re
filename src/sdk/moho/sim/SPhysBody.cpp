#include "moho/sim/SPhysBody.h"

#include <cstdint>
#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"

#pragma init_seg(lib)

namespace gpg
{
  class SerConstructResult
  {
  public:
    void SetUnowned(const RRef& ref, unsigned int flags);
  };

  class SerSaveConstructArgsResult
  {
  public:
    void SetUnowned(unsigned int value);
  };
} // namespace gpg

namespace
{
  alignas(moho::SPhysBodyTypeInfo) unsigned char gSPhysBodyTypeInfoStorage[sizeof(moho::SPhysBodyTypeInfo)];
  bool gSPhysBodyTypeInfoConstructed = false;
  moho::SPhysBodySaveConstruct gSPhysBodySaveConstruct{};
  moho::SPhysBodyConstruct gSPhysBodyConstruct{};
  moho::SPhysBodySerializer gSPhysBodySerializer{};

  [[nodiscard]] moho::SPhysBodyTypeInfo& SPhysBodyTypeInfoStorageRef() noexcept
  {
    return *reinterpret_cast<moho::SPhysBodyTypeInfo*>(gSPhysBodyTypeInfoStorage);
  }

  [[nodiscard]] gpg::RType* CachedSPhysBodyType()
  {
    if (!moho::SPhysBody::sType) {
      moho::SPhysBody::sType = gpg::LookupRType(typeid(moho::SPhysBody));
    }

    GPG_ASSERT(moho::SPhysBody::sType != nullptr);
    return moho::SPhysBody::sType;
  }

  [[nodiscard]] gpg::RType* CachedSPhysConstantsType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::SPhysConstants));
    }

    GPG_ASSERT(cached != nullptr);
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedVector3fType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(Wm3::Vec3f));
    }

    GPG_ASSERT(cached != nullptr);
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedQuaternionfType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(Wm3::Quaternionf));
    }

    GPG_ASSERT(cached != nullptr);
    return cached;
  }

  [[nodiscard]] gpg::RRef MakeSPhysBodyRef(moho::SPhysBody* const object)
  {
    gpg::RRef ref{};
    ref.mObj = object;
    ref.mType = CachedSPhysBodyType();
    return ref;
  }

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* HelperSelfNode(THelper& helper) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&helper.mHelperNext);
  }

  template <typename THelper>
  void InitializeHelperNode(THelper& helper) noexcept
  {
    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperNext = self;
    helper.mHelperPrev = self;
  }

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* UnlinkHelperNode(THelper& helper) noexcept
  {
    if (helper.mHelperNext != nullptr && helper.mHelperPrev != nullptr) {
      helper.mHelperNext->mPrev = helper.mHelperPrev;
      helper.mHelperPrev->mNext = helper.mHelperNext;
    }

    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperPrev = self;
    helper.mHelperNext = self;
    return self;
  }

  [[nodiscard]] moho::SPhysConstants* ReadSPhysConstantsPointer(gpg::ReadArchive* const archive)
  {
    if (!archive) {
      return nullptr;
    }

    const gpg::TrackedPointerInfo& tracked = gpg::ReadRawPointer(archive, gpg::RRef{});
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;

    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedSPhysConstantsType());
    return static_cast<moho::SPhysConstants*>(upcast.mObj);
  }

  /**
   * Address: 0x006980D0 (FUN_006980D0, save-construct args body)
   */
  void SaveConstructArgs_SPhysBodyVariant2(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    const auto* const object = reinterpret_cast<const moho::SPhysBody*>(objectPtr);
    if (!archive || !object) {
      return;
    }

    gpg::RRef constantsRef{};
    constantsRef.mObj = object->mConstants;
    constantsRef.mType = object->mConstants ? CachedSPhysConstantsType() : nullptr;
    gpg::WriteRawPointer(archive, constantsRef, gpg::TrackedPointerState::Unowned, gpg::RRef{});

    if (result) {
      result->SetUnowned(0u);
    }
  }

  /**
   * Address: 0x006981B0 (FUN_006981B0, construct callback body)
   */
  void ConstructSPhysBody(
    gpg::ReadArchive* const archive,
    const int,
    const int,
    gpg::SerConstructResult* const result
  )
  {
    moho::SPhysConstants* const constants = ReadSPhysConstantsPointer(archive);
    moho::SPhysBody* const object = new (std::nothrow) moho::SPhysBody{};
    if (object) {
      object->mConstants = constants;
      object->mMass = 1.0f;
      object->mInvInertiaTensor.x = 1.0f;
      object->mInvInertiaTensor.y = 1.0f;
      object->mInvInertiaTensor.z = 1.0f;
      object->mCollisionOffset.x = 0.0f;
      object->mCollisionOffset.y = 0.0f;
      object->mCollisionOffset.z = 0.0f;
      object->mPos.x = 0.0f;
      object->mPos.y = 0.0f;
      object->mPos.z = 0.0f;
      object->mOrientation.x = 1.0f;
      object->mOrientation.y = 0.0f;
      object->mOrientation.z = 0.0f;
      object->mOrientation.w = 0.0f;
      object->mVelocity.x = 0.0f;
      object->mVelocity.y = 0.0f;
      object->mVelocity.z = 0.0f;
      object->mWorldImpulse.x = 0.0f;
      object->mWorldImpulse.y = 0.0f;
      object->mWorldImpulse.z = 0.0f;
    }

    if (!result) {
      return;
    }

    const gpg::RRef ref = MakeSPhysBodyRef(object);
    result->SetUnowned(ref, 0u);
  }

  /**
   * Address: 0x006981A0 (delete callback lane, inferred)
   */
  void DeleteConstructedSPhysBodyVariant1(void* const objectPtr)
  {
    delete static_cast<moho::SPhysBody*>(objectPtr);
  }

  /**
   * Address: 0x00698A60 (FUN_00698A60, serializer load body)
   */
  void DeserializeSPhysBodyBody(moho::SPhysBody* const object, gpg::ReadArchive* const archive)
  {
    if (!object || !archive) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->ReadFloat(&object->mMass);
    archive->Read(CachedVector3fType(), &object->mInvInertiaTensor, nullOwner);
    archive->Read(CachedVector3fType(), &object->mCollisionOffset, nullOwner);
    archive->Read(CachedVector3fType(), &object->mPos, nullOwner);
    archive->Read(CachedQuaternionfType(), &object->mOrientation, nullOwner);
    archive->Read(CachedVector3fType(), &object->mVelocity, nullOwner);
    archive->Read(CachedVector3fType(), &object->mWorldImpulse, nullOwner);
  }

  /**
   * Address: 0x00698BC0 (FUN_00698BC0, serializer save body)
   */
  void SerializeSPhysBodyBody(const moho::SPhysBody* const object, gpg::WriteArchive* const archive)
  {
    if (!object || !archive) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->WriteFloat(object->mMass);
    archive->Write(CachedVector3fType(), &object->mInvInertiaTensor, nullOwner);
    archive->Write(CachedVector3fType(), &object->mCollisionOffset, nullOwner);
    archive->Write(CachedVector3fType(), &object->mPos, nullOwner);
    archive->Write(CachedQuaternionfType(), &object->mOrientation, nullOwner);
    archive->Write(CachedVector3fType(), &object->mVelocity, nullOwner);
    archive->Write(CachedVector3fType(), &object->mWorldImpulse, nullOwner);
  }

  void cleanup_SPhysBodySaveConstruct_atexit()
  {
    (void)moho::cleanup_SPhysBodySaveConstruct();
  }

  void cleanup_SPhysBodyConstruct_atexit()
  {
    (void)moho::cleanup_SPhysBodyConstruct();
  }

  void cleanup_SPhysBodySerializer_atexit()
  {
    moho::cleanup_SPhysBodySerializer();
  }
} // namespace

namespace moho
{
  gpg::RType* SPhysBody::sType = nullptr;

  /**
   * Address: 0x006973F0 (FUN_006973F0, Moho::SPhysBodyTypeInfo::SPhysBodyTypeInfo)
   */
  SPhysBodyTypeInfo::SPhysBodyTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(SPhysBody), this);
  }

  /**
   * Address: 0x00697480 (FUN_00697480, Moho::SPhysBodyTypeInfo::dtr)
   */
  SPhysBodyTypeInfo::~SPhysBodyTypeInfo()
  {
    fields_ = {};
    bases_ = {};
  }

  /**
   * Address: 0x00697470 (FUN_00697470, Moho::SPhysBodyTypeInfo::GetName)
   */
  const char* SPhysBodyTypeInfo::GetName() const
  {
    return "SPhysBody";
  }

  /**
   * Address: 0x00697450 (FUN_00697450, Moho::SPhysBodyTypeInfo::Init)
   */
  void SPhysBodyTypeInfo::Init()
  {
    size_ = sizeof(SPhysBody);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00698040 (FUN_00698040, save-construct registration lane)
   */
  void SPhysBodySaveConstruct::RegisterSaveConstructArgsFunction()
  {
    gpg::RType* const type = CachedSPhysBodyType();
    GPG_ASSERT(type->serSaveConstructArgsFunc_ == nullptr || type->serSaveConstructArgsFunc_ == mSaveConstructArgsCallback);
    type->serSaveConstructArgsFunc_ = mSaveConstructArgsCallback;
  }

  /**
   * Address: 0x006981B0 (FUN_006981B0, construct registration lane)
   */
  void SPhysBodyConstruct::RegisterConstructFunction()
  {
    gpg::RType* const type = CachedSPhysBodyType();
    GPG_ASSERT(type->serConstructFunc_ == nullptr || type->serConstructFunc_ == mConstructCallback);
    GPG_ASSERT(type->deleteFunc_ == nullptr || type->deleteFunc_ == mDeleteCallback);
    type->serConstructFunc_ = mConstructCallback;
    type->deleteFunc_ = mDeleteCallback;
  }

  /**
   * Address: 0x006982A0 (FUN_006982A0, Moho::SPhysBodySerializer::Deserialize)
   */
  void SPhysBodySerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    DeserializeSPhysBodyBody(reinterpret_cast<SPhysBody*>(objectPtr), archive);
  }

  /**
   * Address: 0x006982B0 (FUN_006982B0, Moho::SPhysBodySerializer::Serialize)
   */
  void SPhysBodySerializer::Serialize(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    SerializeSPhysBodyBody(reinterpret_cast<const SPhysBody*>(objectPtr), archive);
  }

  /**
   * Address: 0x006982C0 (FUN_006982C0, serializer registration lane)
   */
  void SPhysBodySerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CachedSPhysBodyType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mDeserialize);
    GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSerialize);
    type->serLoadFunc_ = mDeserialize;
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BFD2D0 (FUN_00BFD2D0, cleanup_SPhysBodyTypeInfo)
   */
  void cleanup_SPhysBodyTypeInfo()
  {
    if (!gSPhysBodyTypeInfoConstructed) {
      return;
    }

    SPhysBodyTypeInfoStorageRef().~SPhysBodyTypeInfo();
    gSPhysBodyTypeInfoConstructed = false;
    SPhysBody::sType = nullptr;
  }

  /**
   * Address: 0x00BFD330 (FUN_00BFD330, cleanup_SPhysBodySaveConstruct)
   */
  gpg::SerHelperBase* cleanup_SPhysBodySaveConstruct()
  {
    return UnlinkHelperNode(gSPhysBodySaveConstruct);
  }

  /**
   * Address: 0x00BFD360 (FUN_00BFD360, cleanup_SPhysBodyConstruct)
   */
  gpg::SerHelperBase* cleanup_SPhysBodyConstruct()
  {
    return UnlinkHelperNode(gSPhysBodyConstruct);
  }

  /**
   * Address: 0x00BFD390 (FUN_00BFD390, cleanup_SPhysBodySerializer)
   */
  void cleanup_SPhysBodySerializer()
  {
    (void)UnlinkHelperNode(gSPhysBodySerializer);
  }

  /**
   * Address: 0x00BD5E80 (FUN_00BD5E80, register_SPhysBodyTypeInfo)
   */
  void register_SPhysBodyTypeInfo()
  {
    if (!gSPhysBodyTypeInfoConstructed) {
      new (gSPhysBodyTypeInfoStorage) SPhysBodyTypeInfo();
      gSPhysBodyTypeInfoConstructed = true;
    }

    (void)std::atexit(&cleanup_SPhysBodyTypeInfo);
  }

  /**
   * Address: 0x00BD5EA0 (FUN_00BD5EA0, register_SPhysBodySaveConstruct)
   */
  int register_SPhysBodySaveConstruct()
  {
    InitializeHelperNode(gSPhysBodySaveConstruct);
    gSPhysBodySaveConstruct.mSaveConstructArgsCallback =
      reinterpret_cast<gpg::RType::save_construct_args_func_t>(&SaveConstructArgs_SPhysBodyVariant2);
    gSPhysBodySaveConstruct.RegisterSaveConstructArgsFunction();
    return std::atexit(&cleanup_SPhysBodySaveConstruct_atexit);
  }

  /**
   * Address: 0x00BD5ED0 (FUN_00BD5ED0, register_SPhysBodyConstruct)
   */
  int register_SPhysBodyConstruct()
  {
    InitializeHelperNode(gSPhysBodyConstruct);
    gSPhysBodyConstruct.mConstructCallback =
      reinterpret_cast<gpg::RType::construct_func_t>(&ConstructSPhysBody);
    gSPhysBodyConstruct.mDeleteCallback = &DeleteConstructedSPhysBodyVariant1;
    gSPhysBodyConstruct.RegisterConstructFunction();
    return std::atexit(&cleanup_SPhysBodyConstruct_atexit);
  }

  /**
   * Address: 0x00BD5F10 (FUN_00BD5F10, register_SPhysBodySerializer)
   */
  void register_SPhysBodySerializer()
  {
    InitializeHelperNode(gSPhysBodySerializer);
    gSPhysBodySerializer.mDeserialize = &SPhysBodySerializer::Deserialize;
    gSPhysBodySerializer.mSerialize = &SPhysBodySerializer::Serialize;
    gSPhysBodySerializer.RegisterSerializeFunctions();
    (void)std::atexit(&cleanup_SPhysBodySerializer_atexit);
  }
} // namespace moho

namespace
{
  struct SPhysBodyBootstrap
  {
    SPhysBodyBootstrap()
    {
      moho::register_SPhysBodyTypeInfo();
      (void)moho::register_SPhysBodySaveConstruct();
      (void)moho::register_SPhysBodyConstruct();
      moho::register_SPhysBodySerializer();
    }
  };

  [[maybe_unused]] SPhysBodyBootstrap gSPhysBodyBootstrap;
} // namespace
