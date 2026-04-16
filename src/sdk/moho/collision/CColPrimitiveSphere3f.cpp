#include "moho/collision/CColPrimitiveSphere3f.h"

#include <cstdlib>
#include <limits>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"

#pragma init_seg(lib)

namespace
{
  constexpr const char* kSerializationSourcePath =
    "c:\\work\\rts\\main\\code\\src\\libs\\gpgcore/reflection/serialization.h";
  constexpr int kSerializationLoadLine = 84;
  constexpr int kSerializationSaveLine = 87;
  constexpr int kSaveConstructArgsLine = 189;
  constexpr int kConstructLine = 231;

  [[nodiscard]] gpg::RType* CachedVector3fType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(Wm3::Vector3<float>));
    }
    GPG_ASSERT(cached != nullptr);
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedSphere3fType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(Wm3::Sphere3<float>));
    }
    GPG_ASSERT(cached != nullptr);
    return cached;
  }

  [[nodiscard]] gpg::SerHelperBase* Sphere3fSerializerSelfNode(moho::Sphere3fSerializer& serializer)
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&serializer.mHelperNext);
  }

  moho::Sphere3fSerializer gSphere3fSerializer;

  [[nodiscard]] gpg::SerHelperBase* ResetSphere3fSerializerLinks()
  {
    if (gSphere3fSerializer.mHelperNext != nullptr && gSphere3fSerializer.mHelperPrev != nullptr) {
      gSphere3fSerializer.mHelperNext->mPrev = gSphere3fSerializer.mHelperPrev;
      gSphere3fSerializer.mHelperPrev->mNext = gSphere3fSerializer.mHelperNext;
    }

    gpg::SerHelperBase* const self = Sphere3fSerializerSelfNode(gSphere3fSerializer);
    gSphere3fSerializer.mHelperPrev = self;
    gSphere3fSerializer.mHelperNext = self;
    return self;
  }

  void CleanupSphere3fSerializer()
  {
    (void)ResetSphere3fSerializerLinks();
  }

  struct Sphere3fSerializerBootstrap
  {
    Sphere3fSerializerBootstrap()
    {
      moho::register_Sphere3fSerializer();
    }
  };

  Sphere3fSerializerBootstrap gSphere3fSerializerBootstrap;
} // namespace

namespace Wm3
{
  /**
   * Address: 0x00474260 (FUN_00474260, Wm3::Sphere3f::MemberDeserialize)
   */
  template <>
  void Sphere3<float>::MemberDeserialize(gpg::ReadArchive* archive)
  {
    gpg::RType* const vector3Type = CachedVector3fType();
    gpg::RRef ownerRef{};
    archive->Read(vector3Type, &Center, ownerRef);
    archive->ReadFloat(&Radius);
  }

  /**
   * Address: 0x004742B0 (FUN_004742B0, Wm3::Sphere3f::MemberSerialize)
   */
  template <>
  void Sphere3<float>::MemberSerialize(gpg::WriteArchive* archive) const
  {
    gpg::RType* const vector3Type = CachedVector3fType();
    gpg::RRef ownerRef{};
    archive->Write(vector3Type, &Center, ownerRef);
    archive->WriteFloat(Radius);
  }
} // namespace Wm3

namespace moho
{
  /**
   * Address: 0x004730E0 (FUN_004730E0, Moho::Sphere3fSerializer::Deserialize)
   */
  void Sphere3fSerializer::Deserialize(gpg::ReadArchive* archive, int objectStorage, int, gpg::RRef*)
  {
    auto* const object = reinterpret_cast<Wm3::Sphere3f*>(objectStorage);
    object->MemberDeserialize(archive);
  }

  /**
   * Address: 0x004730F0 (FUN_004730F0, Moho::Sphere3fSerializer::Serialize)
   */
  void Sphere3fSerializer::Serialize(gpg::WriteArchive* archive, int objectStorage, int, gpg::RRef*)
  {
    auto* const object = reinterpret_cast<const Wm3::Sphere3f*>(objectStorage);
    object->MemberSerialize(archive);
  }

  /**
   * Address: 0x00473FF0 (FUN_00473FF0, gpg::SerSaveLoadHelper<Wm3::Sphere3<float>>::Init)
   */
  void Sphere3fSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CachedSphere3fType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }

  /**
   * Address: 0x00BC4970 (FUN_00BC4970, register_Sphere3fSerializer)
   *
   * What it does:
   * Installs startup serializer callbacks for Sphere3f and registers shutdown
   * unlink/teardown.
   */
  void register_Sphere3fSerializer()
  {
    gpg::SerHelperBase* const self = Sphere3fSerializerSelfNode(gSphere3fSerializer);
    gSphere3fSerializer.mHelperNext = self;
    gSphere3fSerializer.mHelperPrev = self;
    gSphere3fSerializer.mLoadCallback = &Sphere3fSerializer::Deserialize;
    gSphere3fSerializer.mSaveCallback = &Sphere3fSerializer::Serialize;
    (void)std::atexit(&CleanupSphere3fSerializer);
  }

  /**
   * Address: 0x00473050 (FUN_00473050, Moho::Invalid<Wm3::Sphere3<float>>)
   */
  template <>
  const Wm3::Sphere3f& Invalid<Wm3::Sphere3f>()
  {
    static bool initialized = false;
    static Wm3::Sphere3f invalid{};

    if (!initialized) {
      const float nanValue = std::numeric_limits<float>::quiet_NaN();
      invalid.Center = Wm3::Vector3<float>{nanValue, nanValue, nanValue};
      invalid.Radius = nanValue;
      initialized = true;
    }

    return invalid;
  }
} // namespace moho

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
  alignas(moho::DColPrimSphereTypeInfo) unsigned char
    gDColPrimSphereTypeInfoStorage[sizeof(moho::DColPrimSphereTypeInfo)];
  bool gDColPrimSphereTypeInfoConstructed = false;

  moho::DColPrimSphereSerializer gDColPrimSphereSerializer{};
  moho::DColPrimSphereConstruct gDColPrimSphereConstruct{};
  moho::DColPrimSphereSaveConstruct gDColPrimSphereSaveConstruct{};

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

  /**
   * Address: 0x004FEF90 (FUN_004FEF90, DColPrimSphereSerializer helper unlink/reset)
   *
   * What it does:
   * Unlinks the global `DColPrimSphereSerializer` helper node from its current
   * intrusive lane, rewires it to a self-linked singleton node, and returns
   * that self node.
   */
  [[nodiscard]] gpg::SerHelperBase* UnlinkDColPrimSphereSerializerHelperPrimary() noexcept
  {
    gDColPrimSphereSerializer.mHelperNext->mPrev = gDColPrimSphereSerializer.mHelperPrev;
    gDColPrimSphereSerializer.mHelperPrev->mNext = gDColPrimSphereSerializer.mHelperNext;

    gpg::SerHelperBase* const self = HelperSelfNode(gDColPrimSphereSerializer);
    gDColPrimSphereSerializer.mHelperPrev = self;
    gDColPrimSphereSerializer.mHelperNext = self;
    return self;
  }

  /**
   * Address: 0x004FEFC0 (FUN_004FEFC0, DColPrimSphereSerializer helper unlink/reset variant)
   *
   * What it does:
   * Executes the duplicate serializer-helper unlink/reset lane and returns the
   * self-linked helper node.
   */
  [[maybe_unused]] [[nodiscard]] gpg::SerHelperBase* UnlinkDColPrimSphereSerializerHelperSecondary() noexcept
  {
    gDColPrimSphereSerializer.mHelperNext->mPrev = gDColPrimSphereSerializer.mHelperPrev;
    gDColPrimSphereSerializer.mHelperPrev->mNext = gDColPrimSphereSerializer.mHelperNext;

    gpg::SerHelperBase* const self = HelperSelfNode(gDColPrimSphereSerializer);
    gDColPrimSphereSerializer.mHelperPrev = self;
    gDColPrimSphereSerializer.mHelperNext = self;
    return self;
  }

  [[nodiscard]] gpg::RType* CachedDColPrimSpherePrimitiveType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CColPrimitive<Wm3::Sphere3f>));
    }
    GPG_ASSERT(cached != nullptr);
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedDColPrimSphereShapeType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(Wm3::Sphere3f));
    }
    GPG_ASSERT(cached != nullptr);
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedDColPrimSphereVector3fType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(Wm3::Vector3f));
    }
    GPG_ASSERT(cached != nullptr);
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedCColPrimitiveBaseType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CColPrimitiveBase));
    }
    GPG_ASSERT(cached != nullptr);
    return cached;
  }

  [[nodiscard]] gpg::RRef MakeDColPrimSphereRef(moho::SphereCollisionPrimitive* object)
  {
    gpg::RRef ref{};
    ref.mObj = object;
    ref.mType = CachedDColPrimSpherePrimitiveType();
    return ref;
  }

  void AddBase_CColPrimitiveBase(gpg::RType* const typeInfo)
  {
    GPG_ASSERT(typeInfo != nullptr);
    GPG_ASSERT(!typeInfo->initFinished_);

    gpg::RField baseField{};
    baseField.mName = CachedCColPrimitiveBaseType()->GetName();
    baseField.mType = CachedCColPrimitiveBaseType();
    baseField.mOffset = 0;
    baseField.v4 = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
  }

  void CleanupDColPrimSphereTypeInfoAtExit()
  {
    if (!gDColPrimSphereTypeInfoConstructed) {
      return;
    }

    reinterpret_cast<moho::DColPrimSphereTypeInfo*>(gDColPrimSphereTypeInfoStorage)->~DColPrimSphereTypeInfo();
    gDColPrimSphereTypeInfoConstructed = false;
  }

  void CleanupDColPrimSphereSerializerAtExit()
  {
    (void)UnlinkDColPrimSphereSerializerHelperPrimary();
  }

  void CleanupDColPrimSphereConstructAtExit()
  {
    (void)UnlinkHelperNode(gDColPrimSphereConstruct);
  }

  void CleanupDColPrimSphereSaveConstructAtExit()
  {
    (void)UnlinkHelperNode(gDColPrimSphereSaveConstruct);
  }

  /**
   * Address: 0x004FEE20 (FUN_004FEE20)
   *
   * What it does:
   * Reconstructs one sphere collision primitive from archived sphere/vector
   * payloads and returns it as an unowned construct result.
   */
  void ConstructDColPrimSphere(
    gpg::ReadArchive* const archive, const int, const int, gpg::SerConstructResult* const result
  )
  {
    Wm3::Sphere3f shape{};
    Wm3::Vec3f localCenter{};
    const gpg::RRef ownerRef{};

    archive->Read(CachedDColPrimSphereShapeType(), &shape, ownerRef);
    archive->Read(CachedDColPrimSphereVector3fType(), &localCenter, ownerRef);

    auto* object = new (std::nothrow) moho::SphereCollisionPrimitive(localCenter, shape.Radius);
    if (object != nullptr) {
      object->mShape.Center = shape.Center;
      object->mShape.Radius = shape.Radius;
      object->mLocalCenter = localCenter;
    }

    result->SetUnowned(MakeDColPrimSphereRef(object), 0u);
  }

  /**
   * Address: 0x004FECF0 (FUN_004FECF0)
   *
   * What it does:
   * Serializes one sphere primitive's shape payload and local-center payload
   * through the primitive virtual accessors used by save-construct lanes.
   */
  void SaveSpherePrimitiveConstructArgs(
    moho::SphereCollisionPrimitive* const primitive,
    gpg::WriteArchive* const archive,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    Wm3::Vec3f center{};
    gpg::RRef shapeOwnerRef{};
    archive->Write(CachedDColPrimSphereShapeType(), primitive->GetSphere(), shapeOwnerRef);

    gpg::RRef centerOwnerRef{};
    archive->Write(CachedDColPrimSphereVector3fType(), primitive->GetCenter(&center), centerOwnerRef);
    result->SetUnowned(0u);
  }

  /**
   * Address: 0x004FEC50 (FUN_004FEC50)
   *
   * What it does:
   * Tail-forwards save-construct-args dispatch into the shared sphere
   * primitive serialization helper.
   */
  void SaveConstructArgsDColPrimSphere(
    gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::SerSaveConstructArgsResult* const result
  )
  {
    auto* const primitive = reinterpret_cast<moho::SphereCollisionPrimitive*>(objectPtr);
    SaveSpherePrimitiveConstructArgs(primitive, archive, result);
  }

  /**
   * Deletes one constructed sphere collision primitive.
   */
  void DeleteDColPrimSphere(void* const objectPtr)
  {
    delete static_cast<moho::SphereCollisionPrimitive*>(objectPtr);
  }

  /**
   * Address: 0x00BF1A40 (FUN_00BF1A40)
   *
   * What it does:
   * Unlinks the global `DColPrimSphereTypeInfo` storage at process exit.
   */
  void cleanup_DColPrimSphereTypeInfo_atexit()
  {
    CleanupDColPrimSphereTypeInfoAtExit();
  }

  void cleanup_DColPrimSphereSerializer_atexit()
  {
    (void)CleanupDColPrimSphereSerializerAtExit();
  }

  void cleanup_DColPrimSphereConstruct_atexit()
  {
    (void)CleanupDColPrimSphereConstructAtExit();
  }

  void cleanup_DColPrimSphereSaveConstruct_atexit()
  {
    (void)CleanupDColPrimSphereSaveConstructAtExit();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x004FE6D0 (FUN_004FE6D0, Moho::DColPrimSphereTypeInfo::dtr)
   */
  DColPrimSphereTypeInfo::~DColPrimSphereTypeInfo() = default;

  /**
   * Address: 0x004FE6C0 (FUN_004FE6C0, Moho::DColPrimSphereTypeInfo::GetName)
   */
  const char* DColPrimSphereTypeInfo::GetName() const
  {
    return "DColPrimSphere";
  }

  /**
   * Address: 0x004FE6A0 (FUN_004FE6A0, Moho::DColPrimSphereTypeInfo::Init)
   */
  void DColPrimSphereTypeInfo::Init()
  {
    size_ = sizeof(CColPrimitive<Wm3::Sphere3f>);
    gpg::RType::Init();
    AddBase_CColPrimitiveBase(this);
    Finish();
  }

  /**
   * Address: 0x004FEF40 (FUN_004FEF40, Moho::DColPrimSphereSerializer::Deserialize)
   */
  void DColPrimSphereSerializer::Deserialize(gpg::ReadArchive* const, const int, const int, gpg::RRef*)
  {}

  /**
   * Address: 0x004FEF50 (FUN_004FEF50, Moho::DColPrimSphereSerializer::Serialize)
   */
  void DColPrimSphereSerializer::Serialize(gpg::WriteArchive* const, const int, const int, gpg::RRef*)
  {}

  /**
   * Address: 0x004FFB40 (FUN_004FFB40, Moho::DColPrimSphereSerializer::RegisterSerializeFunctions)
   */
  void DColPrimSphereSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CachedDColPrimSpherePrimitiveType();
    if (type->serLoadFunc_ != nullptr) {
      gpg::HandleAssertFailure("!type->mSerLoadFunc", kSerializationLoadLine, kSerializationSourcePath);
    }
    if (type->serSaveFunc_ != nullptr) {
      gpg::HandleAssertFailure("!type->mSerSaveFunc", kSerializationSaveLine, kSerializationSourcePath);
    }
    type->serLoadFunc_ = mDeserialize;
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x004FFAC0 (FUN_004FFAC0, Moho::DColPrimSphereConstruct::RegisterConstructFunction)
   */
  void DColPrimSphereConstruct::RegisterConstructFunction()
  {
    gpg::RType* const type = CachedDColPrimSpherePrimitiveType();
    if (type->serConstructFunc_ != nullptr) {
      gpg::HandleAssertFailure("!type->mSerConstructFunc", kConstructLine, kSerializationSourcePath);
    }
    type->serConstructFunc_ = mConstructCallback;
    type->deleteFunc_ = mDeleteCallback;
  }

  /**
   * Address: 0x004FFA40 (FUN_004FFA40, Moho::DColPrimSphereSaveConstruct::RegisterSaveConstructArgsFunction)
   */
  void DColPrimSphereSaveConstruct::RegisterSaveConstructArgsFunction()
  {
    gpg::RType* const type = CachedDColPrimSpherePrimitiveType();
    if (type->serSaveConstructArgsFunc_ != nullptr) {
      gpg::HandleAssertFailure("!type->mSerSaveConstructArgsFunc", kSaveConstructArgsLine, kSerializationSourcePath);
    }
    type->serSaveConstructArgsFunc_ = mSaveConstructArgsCallback;
  }

  /**
   * Address: 0x004FE640 (FUN_004FE640, preregister_DColPrimSphereTypeInfo)
   *
   * What it does:
   * Constructs/preregisters the startup-owned `DColPrimSphereTypeInfo`
   * instance for `typeid(CColPrimitive<Wm3::Sphere3f>)`.
   */
  [[nodiscard]] gpg::RType* preregister_DColPrimSphereTypeInfo()
  {
    if (!gDColPrimSphereTypeInfoConstructed) {
      new (gDColPrimSphereTypeInfoStorage) DColPrimSphereTypeInfo();
      gDColPrimSphereTypeInfoConstructed = true;
    }

    auto* const type = reinterpret_cast<gpg::RType*>(gDColPrimSphereTypeInfoStorage);
    gpg::PreRegisterRType(typeid(CColPrimitive<Wm3::Sphere3f>), type);
    return type;
  }

  /**
   * Address: 0x00BC7550 (FUN_00BC7550, register_DColPrimSphereTypeInfo)
   *
   * What it does:
   * Installs the startup-owned `DColPrimSphereTypeInfo` instance and its
   * process-exit cleanup hook.
   */
  int register_DColPrimSphereTypeInfo()
  {
    (void)preregister_DColPrimSphereTypeInfo();
    return std::atexit(&cleanup_DColPrimSphereTypeInfo_atexit);
  }

  /**
   * Address: 0x00BC75E0 (FUN_00BC75E0, register_DColPrimSphereSerializer)
   *
   * What it does:
   * Installs serializer callbacks for `DColPrimSphere` and registers shutdown
   * unlink/destruction.
   */
  void register_DColPrimSphereSerializer()
  {
    InitializeHelperNode(gDColPrimSphereSerializer);
    gDColPrimSphereSerializer.mDeserialize = reinterpret_cast<gpg::RType::load_func_t>(&DColPrimSphereSerializer::Deserialize);
    gDColPrimSphereSerializer.mSerialize = reinterpret_cast<gpg::RType::save_func_t>(&DColPrimSphereSerializer::Serialize);
    (void)std::atexit(&cleanup_DColPrimSphereSerializer_atexit);
  }

  /**
   * Address: 0x00BC75A0 (FUN_00BC75A0, register_DColPrimSphereConstruct)
   *
   * What it does:
   * Installs construct/delete callbacks for `DColPrimSphere` and registers
   * shutdown unlink/destruction.
   */
  int register_DColPrimSphereConstruct()
  {
    InitializeHelperNode(gDColPrimSphereConstruct);
    gDColPrimSphereConstruct.mConstructCallback =
      reinterpret_cast<gpg::RType::construct_func_t>(&ConstructDColPrimSphere);
    gDColPrimSphereConstruct.mDeleteCallback = &DeleteDColPrimSphere;
    return std::atexit(&cleanup_DColPrimSphereConstruct_atexit);
  }

  /**
   * Address: 0x00BC7570 (FUN_00BC7570, register_DColPrimSphereSaveConstruct)
   *
   * What it does:
   * Installs save-construct-args callbacks for `DColPrimSphere` and registers
   * shutdown unlink/destruction.
   */
  int register_DColPrimSphereSaveConstruct()
  {
    InitializeHelperNode(gDColPrimSphereSaveConstruct);
    gDColPrimSphereSaveConstruct.mSaveConstructArgsCallback =
      reinterpret_cast<gpg::RType::save_construct_args_func_t>(&SaveConstructArgsDColPrimSphere);
    return std::atexit(&cleanup_DColPrimSphereSaveConstruct_atexit);
  }
} // namespace moho

namespace
{
  struct DColPrimSphereBootstrap
  {
    DColPrimSphereBootstrap()
    {
      (void)moho::register_DColPrimSphereTypeInfo();
      (void)moho::register_DColPrimSphereSaveConstruct();
      (void)moho::register_DColPrimSphereConstruct();
      moho::register_DColPrimSphereSerializer();
    }
  };

  [[maybe_unused]] DColPrimSphereBootstrap gDColPrimSphereBootstrap;
} // namespace


