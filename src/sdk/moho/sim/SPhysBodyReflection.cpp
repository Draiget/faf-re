#include "moho/sim/SPhysBodyReflection.h"

#include <cstdlib>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/utils/Global.h"
#include "moho/sim/SPhysConstants.h"

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
  using TypeInfo = moho::SPhysBodyTypeInfo;
  using SaveConstruct = moho::SPhysBodySaveConstruct;
  using Construct = moho::SPhysBodyConstruct;
  using Serializer = moho::SPhysBodySerializer;

  alignas(TypeInfo) unsigned char gSPhysBodyTypeInfoStorage[sizeof(TypeInfo)];
  bool gSPhysBodyTypeInfoConstructed = false;

  SaveConstruct gSPhysBodySaveConstruct{};
  Construct gSPhysBodyConstruct{};
  Serializer gSPhysBodySerializer{};

  template <class TObject>
  [[nodiscard]] gpg::RType* ResolveCachedType(gpg::RType*& slot)
  {
    if (!slot) {
      slot = gpg::LookupRType(typeid(TObject));
    }
    return slot;
  }

  [[nodiscard]] TypeInfo& GetSPhysBodyTypeInfo() noexcept
  {
    if (!gSPhysBodyTypeInfoConstructed) {
      new (gSPhysBodyTypeInfoStorage) TypeInfo();
      gSPhysBodyTypeInfoConstructed = true;
    }

    return *reinterpret_cast<TypeInfo*>(gSPhysBodyTypeInfoStorage);
  }

  [[nodiscard]] gpg::RType* CachedSPhysBodyType()
  {
    return ResolveCachedType<moho::SPhysBody>(moho::SPhysBody::sType);
  }

  [[nodiscard]] gpg::RType* CachedSPhysConstantsType()
  {
    static gpg::RType* cached = nullptr;
    return ResolveCachedType<moho::SPhysConstants>(cached);
  }

  [[nodiscard]] gpg::RType* CachedVector3fType()
  {
    static gpg::RType* cached = nullptr;
    return ResolveCachedType<Wm3::Vector3f>(cached);
  }

  [[nodiscard]] gpg::RType* CachedQuaternionfType()
  {
    static gpg::RType* cached = nullptr;
    return ResolveCachedType<Wm3::Quaternionf>(cached);
  }

  [[nodiscard]] gpg::RRef MakeSPhysBodyRef(moho::SPhysBody* object)
  {
    gpg::RRef ref{};
    ref.mObj = object;
    ref.mType = CachedSPhysBodyType();
    return ref;
  }

  [[nodiscard]] gpg::RRef MakeSPhysConstantsRef(moho::SPhysConstants* object)
  {
    gpg::RRef ref{};
    ref.mObj = object;
    ref.mType = CachedSPhysConstantsType();
    return ref;
  }

  [[nodiscard]] moho::SPhysConstants* ReadPointerSPhysConstants(gpg::ReadArchive* archive, const gpg::RRef& ownerRef)
  {
    const gpg::TrackedPointerInfo& tracked = gpg::ReadRawPointer(archive, ownerRef);
    if (!tracked.object) {
      return nullptr;
    }

    gpg::RRef source{};
    source.mObj = tracked.object;
    source.mType = tracked.type;
    const gpg::RRef upcast = gpg::REF_UpcastPtr(source, CachedSPhysConstantsType());
    GPG_ASSERT(upcast.mObj != nullptr);
    return static_cast<moho::SPhysConstants*>(upcast.mObj);
  }

  void InitializeBodyDefaults(moho::SPhysBody& body)
  {
    body.mConstants = nullptr;
    body.mMass = 1.0f;
    body.mInvInertiaTensor = {1.0f, 1.0f, 1.0f};
    body.mCollisionOffset = {0.0f, 0.0f, 0.0f};
    body.mPos = {0.0f, 0.0f, 0.0f};
    body.mOrientation = {1.0f, 0.0f, 0.0f, 0.0f};
    body.mVelocity = {0.0f, 0.0f, 0.0f};
    body.mWorldImpulse = {0.0f, 0.0f, 0.0f};
  }

  template <class THelper>
  [[nodiscard]] gpg::SerHelperBase* HelperSelfNode(THelper& helper) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&helper.mHelperNext);
  }

  template <class THelper>
  void InitializeHelperNode(THelper& helper) noexcept
  {
    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperNext = self;
    helper.mHelperPrev = self;
  }

  template <class THelper>
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

  /**
   * Address: 0x006980D0 (FUN_006980D0)
   *
   * What it does:
   * Writes unowned `SPhysConstants*` save-construct argument and marks result as unowned.
   */
  void SaveConstructArgs_SPhysBodyVariant2(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    auto** const constantsSlot = reinterpret_cast<moho::SPhysConstants**>(objectPtr);
    const gpg::RRef constantsRef = MakeSPhysConstantsRef(constantsSlot ? *constantsSlot : nullptr);
    gpg::WriteRawPointer(archive, constantsRef, gpg::TrackedPointerState::Unowned, gpg::RRef{});

    if (result) {
      result->SetUnowned(0u);
    }
  }

  /**
   * Address: 0x00698040 (FUN_00698040)
   *
   * What it does:
   * Save-construct-args thunk forwarding into `SaveConstructArgs_SPhysBodyVariant2`.
   */
  void SaveConstructArgs_SPhysBodyVariant1(
    gpg::WriteArchive* const archive,
    const int objectPtr,
    const int version,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    SaveConstructArgs_SPhysBodyVariant2(archive, objectPtr, version, result);
  }

  /**
   * Address: 0x006981B0 (FUN_006981B0)
   *
   * What it does:
   * Constructs one `SPhysBody` with defaults seeded from referenced `SPhysConstants`
   * gravity and returns it as unowned reflection construct result.
   */
  void ConstructSPhysBody(gpg::ReadArchive* archive, int, int, gpg::SerConstructResult* result)
  {
    gpg::RRef ownerRef{};
    const moho::SPhysConstants* const constants = ReadPointerSPhysConstants(archive, ownerRef);

    moho::SPhysBody* object = new (std::nothrow) moho::SPhysBody{};
    if (object) {
      InitializeBodyDefaults(*object);
      object->mConstants = const_cast<moho::SPhysConstants*>(constants);
    }

    if (result) {
      result->SetUnowned(MakeSPhysBodyRef(object), 0u);
    }
  }

  /**
   * Address: 0x006982A0 (FUN_006982A0 helper body at 0x00698A60)
   */
  void DeserializeSPhysBody(moho::SPhysBody& object, gpg::ReadArchive& archive)
  {
    const gpg::RRef nullOwner{};

    archive.ReadFloat(&object.mMass);
    archive.Read(CachedVector3fType(), &object.mInvInertiaTensor, nullOwner);
    archive.Read(CachedVector3fType(), &object.mCollisionOffset, nullOwner);
    archive.Read(CachedVector3fType(), &object.mPos, nullOwner);
    archive.Read(CachedQuaternionfType(), &object.mOrientation, nullOwner);
    archive.Read(CachedVector3fType(), &object.mVelocity, nullOwner);
    archive.Read(CachedVector3fType(), &object.mWorldImpulse, nullOwner);
  }

  /**
   * Address: 0x006982B0 (FUN_006982B0 helper body at 0x00698BC0)
   */
  void SerializeSPhysBody(const moho::SPhysBody& object, gpg::WriteArchive& archive)
  {
    const gpg::RRef nullOwner{};

    archive.WriteFloat(object.mMass);
    archive.Write(CachedVector3fType(), &object.mInvInertiaTensor, nullOwner);
    archive.Write(CachedVector3fType(), &object.mCollisionOffset, nullOwner);
    archive.Write(CachedVector3fType(), &object.mPos, nullOwner);
    archive.Write(CachedQuaternionfType(), &object.mOrientation, nullOwner);
    archive.Write(CachedVector3fType(), &object.mVelocity, nullOwner);
    archive.Write(CachedVector3fType(), &object.mWorldImpulse, nullOwner);
  }

  /**
   * Address: 0x00698880 (FUN_00698880, serializer load thunk alias)
   *
   * What it does:
   * Tail-forwards the first SPhysBody deserialize thunk alias into the
   * recovered deserialize helper body.
   */
  void DeserializeSPhysBodyThunkVariantA(moho::SPhysBody* const object, gpg::ReadArchive* const archive)
  {
    if (!object || !archive) {
      return;
    }

    DeserializeSPhysBody(*object, *archive);
  }

  /**
   * Address: 0x00698890 (FUN_00698890, serializer save thunk alias)
   *
   * What it does:
   * Tail-forwards the first SPhysBody serialize thunk alias into the recovered
   * serialize helper body.
   */
  void SerializeSPhysBodyThunkVariantA(const moho::SPhysBody* const object, gpg::WriteArchive* const archive)
  {
    if (!object || !archive) {
      return;
    }

    SerializeSPhysBody(*object, *archive);
  }

  /**
   * Address: 0x006988E0 (FUN_006988E0, serializer load thunk alias)
   *
   * What it does:
   * Tail-forwards the second SPhysBody deserialize thunk alias into the
   * recovered deserialize helper body.
   */
  void DeserializeSPhysBodyThunkVariantB(moho::SPhysBody* const object, gpg::ReadArchive* const archive)
  {
    if (!object || !archive) {
      return;
    }

    DeserializeSPhysBody(*object, *archive);
  }

  /**
   * Address: 0x006988F0 (FUN_006988F0, serializer save thunk alias)
   *
   * What it does:
   * Tail-forwards the second SPhysBody serialize thunk alias into the recovered
   * serialize helper body.
   */
  void SerializeSPhysBodyThunkVariantB(const moho::SPhysBody* const object, gpg::WriteArchive* const archive)
  {
    if (!object || !archive) {
      return;
    }

    SerializeSPhysBody(*object, *archive);
  }

  /**
   * Address: 0x00698630 (FUN_00698630 decomp helper lane)
   *
   * What it does:
   * Deletes one constructed `SPhysBody`.
   */
  void DeleteConstructedSPhysBodyVariant2(void* objectPtr)
  {
    delete static_cast<moho::SPhysBody*>(objectPtr);
  }

  void cleanup_SPhysBodyTypeInfo_atexit()
  {
    moho::cleanup_SPhysBodyTypeInfo();
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
    (void)moho::cleanup_SPhysBodySerializer();
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
   * Address: 0x00698660 (FUN_00698660)
   */
  void SPhysBodySaveConstruct::RegisterSaveConstructArgsFunction()
  {
    gpg::RType* const type = CachedSPhysBodyType();
    GPG_ASSERT(type->serSaveConstructArgsFunc_ == nullptr || type->serSaveConstructArgsFunc_ == mSaveConstructArgsCallback);
    type->serSaveConstructArgsFunc_ = mSaveConstructArgsCallback;
  }

  /**
   * Address: 0x006986E0 (FUN_006986E0)
   */
  void SPhysBodyConstruct::RegisterConstructFunction()
  {
    gpg::RType* const type = CachedSPhysBodyType();
    GPG_ASSERT(type->serConstructFunc_ == nullptr || type->serConstructFunc_ == mConstructCallback);
    type->serConstructFunc_ = mConstructCallback;
    type->deleteFunc_ = mDeleteCallback;
  }

  /**
   * Address: 0x006982A0 (FUN_006982A0, Moho::SPhysBodySerializer::Deserialize)
   */
  void SPhysBodySerializer::Deserialize(gpg::ReadArchive* archive, int objectPtr, int, gpg::RRef*)
  {
    auto* const object = reinterpret_cast<SPhysBody*>(objectPtr);
    if (!archive || !object) {
      return;
    }

    DeserializeSPhysBody(*object, *archive);
  }

  /**
   * Address: 0x006982B0 (FUN_006982B0, Moho::SPhysBodySerializer::Serialize)
   */
  void SPhysBodySerializer::Serialize(gpg::WriteArchive* archive, int objectPtr, int, gpg::RRef*)
  {
    const auto* const object = reinterpret_cast<const SPhysBody*>(objectPtr);
    if (!archive || !object) {
      return;
    }

    SerializeSPhysBody(*object, *archive);
  }

  /**
   * Address: 0x00698760 (FUN_00698760)
   */
  void SPhysBodySerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CachedSPhysBodyType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mDeserialize);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSerialize);
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BFD2D0 (FUN_00BFD2D0)
   */
  void cleanup_SPhysBodyTypeInfo()
  {
    if (!gSPhysBodyTypeInfoConstructed) {
      return;
    }

    GetSPhysBodyTypeInfo().~SPhysBodyTypeInfo();
    gSPhysBodyTypeInfoConstructed = false;
  }

  /**
   * Address: 0x00BFD330 (FUN_00BFD330)
   */
  gpg::SerHelperBase* cleanup_SPhysBodySaveConstruct()
  {
    return UnlinkHelperNode(gSPhysBodySaveConstruct);
  }

  /**
   * Address: 0x00BFD360 (FUN_00BFD360)
   */
  gpg::SerHelperBase* cleanup_SPhysBodyConstruct()
  {
    return UnlinkHelperNode(gSPhysBodyConstruct);
  }

  /**
   * Address: 0x00BFD390 (FUN_00BFD390, Moho::SPhysBodySerializer::dtr)
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
    (void)GetSPhysBodyTypeInfo();
    (void)std::atexit(&cleanup_SPhysBodyTypeInfo_atexit);
  }

  /**
   * Address: 0x00BD5EA0 (FUN_00BD5EA0)
   */
  int register_SPhysBodySaveConstruct()
  {
    InitializeHelperNode(gSPhysBodySaveConstruct);
    gSPhysBodySaveConstruct.mSaveConstructArgsCallback =
      reinterpret_cast<gpg::RType::save_construct_args_func_t>(&SaveConstructArgs_SPhysBodyVariant1);
    gSPhysBodySaveConstruct.RegisterSaveConstructArgsFunction();
    return std::atexit(&cleanup_SPhysBodySaveConstruct_atexit);
  }

  /**
   * Address: 0x00BD5ED0 (FUN_00BD5ED0)
   */
  int register_SPhysBodyConstruct()
  {
    InitializeHelperNode(gSPhysBodyConstruct);
    gSPhysBodyConstruct.mConstructCallback = reinterpret_cast<gpg::RType::construct_func_t>(&ConstructSPhysBody);
    gSPhysBodyConstruct.mDeleteCallback = &DeleteConstructedSPhysBodyVariant2;
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
  struct SPhysBodyReflectionBootstrap
  {
    SPhysBodyReflectionBootstrap()
    {
      moho::register_SPhysBodyTypeInfo();
      (void)moho::register_SPhysBodySaveConstruct();
      (void)moho::register_SPhysBodyConstruct();
      moho::register_SPhysBodySerializer();
    }
  };

  [[maybe_unused]] SPhysBodyReflectionBootstrap gSPhysBodyReflectionBootstrap;
} // namespace
