#include "moho/collision/CColPrimitiveBox3f.h"

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

  [[nodiscard]] gpg::RType* CachedBox3fType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(Wm3::Box3<float>));
    }
    GPG_ASSERT(cached != nullptr);
    return cached;
  }

  [[nodiscard]] gpg::SerHelperBase* Box3fSerializerSelfNode(moho::Box3fSerializer& serializer)
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&serializer.mHelperNext);
  }

  moho::Box3fTypeInfo gBox3fTypeInfo;
  moho::Box3fSerializer gBox3fSerializer;

  /**
   * Address: 0x004747D0 (FUN_004747D0)
   *
   * What it does:
   * Unlinks global Box3f serializer helper node from its intrusive list and
   * rewires it to a self-linked singleton node.
   */
  gpg::SerHelperBase* ResetBox3fSerializerLinksPrimary()
  {
    gBox3fSerializer.mHelperNext->mPrev = gBox3fSerializer.mHelperPrev;
    gBox3fSerializer.mHelperPrev->mNext = gBox3fSerializer.mHelperNext;

    gpg::SerHelperBase* const self = Box3fSerializerSelfNode(gBox3fSerializer);
    gBox3fSerializer.mHelperPrev = self;
    gBox3fSerializer.mHelperNext = self;
    return self;
  }

  /**
   * Address: 0x00474800 (FUN_00474800)
   *
   * What it does:
   * Duplicate emitted helper lane that performs the same serializer-list reset
   * as `FUN_004747D0`.
   */
  gpg::SerHelperBase* ResetBox3fSerializerLinksSecondary()
  {
    return ResetBox3fSerializerLinksPrimary();
  }

  void CleanupBox3fSerializer()
  {
    (void)ResetBox3fSerializerLinksPrimary();
  }

  struct Box3fSerializerBootstrap
  {
    Box3fSerializerBootstrap()
    {
      moho::register_Box3fTypeInfo();
      moho::register_Box3fSerializer();
      (void)&ResetBox3fSerializerLinksSecondary;
    }
  };

  Box3fSerializerBootstrap gBox3fSerializerBootstrap;
} // namespace

namespace Wm3
{
  /**
   * Address: 0x00475800 (FUN_00475800, Wm3::Box3f::MemberDeserialize)
   */
  template <>
  void Box3<float>::MemberDeserialize(gpg::ReadArchive* archive)
  {
    gpg::RType* const vector3Type = CachedVector3fType();

    gpg::RRef ownerRef{};
    archive->Read(vector3Type, &Center, ownerRef);

    gpg::RRef axis0OwnerRef{};
    archive->Read(vector3Type, &Axis[0], axis0OwnerRef);

    gpg::RRef axis1OwnerRef{};
    archive->Read(vector3Type, &Axis[1], axis1OwnerRef);

    gpg::RRef axis2OwnerRef{};
    archive->Read(vector3Type, &Axis[2], axis2OwnerRef);

    archive->ReadFloat(&Extent[0]);
    archive->ReadFloat(&Extent[1]);
    archive->ReadFloat(&Extent[2]);
  }

  /**
   * Address: 0x00475910 (FUN_00475910, Wm3::Box3f::MemberSerialize)
   */
  template <>
  void Box3<float>::MemberSerialize(gpg::WriteArchive* archive) const
  {
    gpg::RType* const vector3Type = CachedVector3fType();

    gpg::RRef ownerRef{};
    archive->Write(vector3Type, &Center, ownerRef);

    gpg::RRef axis0OwnerRef{};
    archive->Write(vector3Type, &Axis[0], axis0OwnerRef);

    gpg::RRef axis1OwnerRef{};
    archive->Write(vector3Type, &Axis[1], axis1OwnerRef);

    gpg::RRef axis2OwnerRef{};
    archive->Write(vector3Type, &Axis[2], axis2OwnerRef);

    archive->WriteFloat(Extent[0]);
    archive->WriteFloat(Extent[1]);
    archive->WriteFloat(Extent[2]);
  }
} // namespace Wm3

namespace moho
{
  /**
   * Address: 0x00474410 (FUN_00474410, Moho::Box3fTypeInfo::Box3fTypeInfo)
   */
  Box3fTypeInfo::Box3fTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(Wm3::Box3<float>), this);
  }

  /**
   * Address: 0x004744A0 (FUN_004744A0, Moho::Box3fTypeInfo::dtr)
   */
  Box3fTypeInfo::~Box3fTypeInfo() = default;

  /**
   * Address: 0x00474490 (FUN_00474490, Moho::Box3fTypeInfo::GetName)
   */
  const char* Box3fTypeInfo::GetName() const
  {
    return "Box3f";
  }

  /**
   * Address: 0x00474470 (FUN_00474470, Moho::Box3fTypeInfo::Init)
   */
  void Box3fTypeInfo::Init()
  {
    size_ = sizeof(Wm3::Box3f);
    gpg::RType::Init();
    Finish();
  }

  /**
   * Address: 0x00474770 (FUN_00474770, Moho::Box3fSerializer::Deserialize)
   */
  void Box3fSerializer::Deserialize(gpg::ReadArchive* archive, int objectStorage, int, gpg::RRef*)
  {
    auto* const object = reinterpret_cast<Wm3::Box3f*>(objectStorage);
    object->MemberDeserialize(archive);
  }

  /**
   * Address: 0x00474780 (FUN_00474780, Moho::Box3fSerializer::Serialize)
   */
  void Box3fSerializer::Serialize(gpg::WriteArchive* archive, int objectStorage, int, gpg::RRef*)
  {
    auto* const object = reinterpret_cast<const Wm3::Box3f*>(objectStorage);
    object->MemberSerialize(archive);
  }

  /**
   * Address: 0x004756D0 (FUN_004756D0, gpg::SerSaveLoadHelper<Wm3::Box3<float>>::Init)
   */
  void Box3fSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CachedBox3fType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }

  /**
   * Address: 0x00BC4A40 (FUN_00BC4A40, register_Box3fSerializer)
   *
   * What it does:
   * Installs startup serializer callbacks for Box3f and registers shutdown
   * unlink/teardown.
   */
  void register_Box3fSerializer()
  {
    gpg::SerHelperBase* const self = Box3fSerializerSelfNode(gBox3fSerializer);
    gBox3fSerializer.mHelperNext = self;
    gBox3fSerializer.mHelperPrev = self;
    gBox3fSerializer.mLoadCallback = &Box3fSerializer::Deserialize;
    gBox3fSerializer.mSaveCallback = &Box3fSerializer::Serialize;
    gBox3fSerializer.RegisterSerializeFunctions();
    (void)std::atexit(&CleanupBox3fSerializer);
  }

  /**
   * Address: 0x00BC4A20 (FUN_00BC4A20, register_Box3fTypeInfo)
   *
   * What it does:
   * Touches startup-owned Box3f typeinfo storage so process-lifetime static
   * teardown is retained by CRT registration.
   */
  void register_Box3fTypeInfo()
  {
    (void)gBox3fTypeInfo;
  }

  /**
   * Address: 0x00474600 (FUN_00474600, Moho::Invalid<Wm3::Box3<float>>)
   */
  template <>
  const Wm3::Box3f& Invalid<Wm3::Box3f>()
  {
    static bool initialized = false;
    static Wm3::Box3f invalid{};

    if (!initialized) {
      const float nanValue = std::numeric_limits<float>::quiet_NaN();
      const Wm3::Vector3<float> invalidVector{nanValue, nanValue, nanValue};
      invalid = Wm3::Box3f(invalidVector, invalidVector, invalidVector, invalidVector, nanValue, nanValue, nanValue);
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
  alignas(moho::DColPrimBoxTypeInfo) unsigned char gDColPrimBoxTypeInfoStorage[sizeof(moho::DColPrimBoxTypeInfo)];
  bool gDColPrimBoxTypeInfoConstructed = false;

  moho::DColPrimBoxSerializer gDColPrimBoxSerializer{};
  moho::DColPrimBoxConstruct gDColPrimBoxConstruct{};
  moho::DColPrimBoxSaveConstruct gDColPrimBoxSaveConstruct{};

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* HelperSelfNode(THelper& helper) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&helper.mHelperNext);
  }

  template <typename THelper>
  void InitializeHelperNode(THelper& helper) noexcept
  {
    new (HelperSelfNode(helper)) gpg::SerHelperBase();
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

  [[nodiscard]] gpg::RType* CachedDColPrimBoxPrimitiveType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::CColPrimitive<Wm3::Box3f>));
    }
    GPG_ASSERT(cached != nullptr);
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedDColPrimBoxShapeType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(Wm3::Box3f));
    }
    GPG_ASSERT(cached != nullptr);
    return cached;
  }

  [[nodiscard]] gpg::RType* CachedDColPrimBoxVector3fType()
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

  [[nodiscard]] gpg::RRef MakeDColPrimBoxRef(moho::BoxCollisionPrimitive* object)
  {
    gpg::RRef ref{};
    ref.mObj = object;
    ref.mType = CachedDColPrimBoxPrimitiveType();
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

  void CleanupDColPrimBoxTypeInfoAtExit()
  {
    if (!gDColPrimBoxTypeInfoConstructed) {
      return;
    }

    reinterpret_cast<moho::DColPrimBoxTypeInfo*>(gDColPrimBoxTypeInfoStorage)->~DColPrimBoxTypeInfo();
    gDColPrimBoxTypeInfoConstructed = false;
  }

  void CleanupDColPrimBoxSerializerAtExit()
  {
    (void)UnlinkHelperNode(gDColPrimBoxSerializer);
  }

  void CleanupDColPrimBoxConstructAtExit()
  {
    (void)UnlinkHelperNode(gDColPrimBoxConstruct);
  }

  void CleanupDColPrimBoxSaveConstructAtExit()
  {
    (void)UnlinkHelperNode(gDColPrimBoxSaveConstruct);
  }

  /**
   * Address: 0x004FF750 (FUN_004FF750)
   *
   * What it does:
   * Reconstructs one box collision primitive from archived box/vector payloads
   * and returns it as an unowned construct result.
   */
  void ConstructDColPrimBox(gpg::ReadArchive* const archive, const int, const int, gpg::SerConstructResult* const result)
  {
    Wm3::Box3f shape{};
    Wm3::Vec3f localCenter{};
    const gpg::RRef ownerRef{};

    archive->Read(CachedDColPrimBoxShapeType(), &shape, ownerRef);
    archive->Read(CachedDColPrimBoxVector3fType(), &localCenter, ownerRef);

    auto* object = new (std::nothrow) moho::BoxCollisionPrimitive(shape);
    if (object != nullptr) {
      object->mLocalCenter = localCenter;
    }

    result->SetUnowned(MakeDColPrimBoxRef(object), 0u);
  }

  /**
   * Address: 0x004FF570 (FUN_004FF570)
   *
   * What it does:
   * Saves one box collision primitive's shape and local-center construct
   * arguments in binary archive order.
   */
  void SaveConstructArgsDColPrimBox(
    gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::SerSaveConstructArgsResult* const result
  )
  {
    auto* const primitive = reinterpret_cast<moho::BoxCollisionPrimitive*>(objectPtr);
    Wm3::Vec3f center{};
    const gpg::RRef ownerRef{};

    archive->Write(CachedDColPrimBoxShapeType(), primitive->GetBox(), ownerRef);
    archive->Write(CachedDColPrimBoxVector3fType(), primitive->GetCenter(&center), ownerRef);
    result->SetUnowned(0u);
  }

  /**
   * Deletes one constructed box collision primitive.
   */
  void DeleteDColPrimBox(void* const objectPtr)
  {
    delete static_cast<moho::BoxCollisionPrimitive*>(objectPtr);
  }

  void cleanup_DColPrimBoxTypeInfo_atexit()
  {
    CleanupDColPrimBoxTypeInfoAtExit();
  }

  void cleanup_DColPrimBoxSerializer_atexit()
  {
    (void)CleanupDColPrimBoxSerializerAtExit();
  }

  void cleanup_DColPrimBoxConstruct_atexit()
  {
    (void)CleanupDColPrimBoxConstructAtExit();
  }

  void cleanup_DColPrimBoxSaveConstruct_atexit()
  {
    (void)CleanupDColPrimBoxSaveConstructAtExit();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x004FEFF0 (FUN_004FEFF0, Moho::DColPrimBoxTypeInfo::DColPrimBoxTypeInfo)
   */
  DColPrimBoxTypeInfo::DColPrimBoxTypeInfo()
    : gpg::RType()
  {
    gpg::PreRegisterRType(typeid(CColPrimitive<Wm3::Box3f>), this);
  }

  /**
   * Address: 0x004FF080 (FUN_004FF080, Moho::DColPrimBoxTypeInfo::dtr)
   */
  DColPrimBoxTypeInfo::~DColPrimBoxTypeInfo() = default;

  /**
   * Address: 0x004FF070 (FUN_004FF070, Moho::DColPrimBoxTypeInfo::GetName)
   */
  const char* DColPrimBoxTypeInfo::GetName() const
  {
    return "DColPrimBox";
  }

  /**
   * Address: 0x004FF050 (FUN_004FF050, Moho::DColPrimBoxTypeInfo::Init)
   */
  void DColPrimBoxTypeInfo::Init()
  {
    size_ = sizeof(CColPrimitive<Wm3::Box3f>);
    gpg::RType::Init();
    AddBase_CColPrimitiveBase(this);
    Finish();
  }

  /**
   * Address: 0x004FF880 (FUN_004FF880, Moho::DColPrimBoxSerializer::Deserialize)
   */
  void DColPrimBoxSerializer::Deserialize(gpg::ReadArchive* const, const int, const int, gpg::RRef*)
  {}

  /**
   * Address: 0x004FF890 (FUN_004FF890, Moho::DColPrimBoxSerializer::Serialize)
   */
  void DColPrimBoxSerializer::Serialize(gpg::WriteArchive* const, const int, const int, gpg::RRef*)
  {}

  /**
   * Address: 0x004FFD70 (FUN_004FFD70, Moho::DColPrimBoxSerializer::RegisterSerializeFunctions)
   */
  void DColPrimBoxSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CachedDColPrimBoxPrimitiveType();
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
   * Address: 0x004FFCF0 (FUN_004FFCF0, Moho::DColPrimBoxConstruct::RegisterConstructFunction)
   */
  void DColPrimBoxConstruct::RegisterConstructFunction()
  {
    gpg::RType* const type = CachedDColPrimBoxPrimitiveType();
    if (type->serConstructFunc_ != nullptr) {
      gpg::HandleAssertFailure("!type->mSerConstructFunc", kConstructLine, kSerializationSourcePath);
    }
    type->serConstructFunc_ = mConstructCallback;
    type->deleteFunc_ = mDeleteCallback;
  }

  /**
   * Address: 0x004FFC70 (FUN_004FFC70, Moho::DColPrimBoxSaveConstruct::RegisterSaveConstructArgsFunction)
   */
  void DColPrimBoxSaveConstruct::RegisterSaveConstructArgsFunction()
  {
    gpg::RType* const type = CachedDColPrimBoxPrimitiveType();
    if (type->serSaveConstructArgsFunc_ != nullptr) {
      gpg::HandleAssertFailure("!type->mSerSaveConstructArgsFunc", kSaveConstructArgsLine, kSerializationSourcePath);
    }
    type->serSaveConstructArgsFunc_ = mSaveConstructArgsCallback;
  }

  /**
   * Address: 0x00BC7620 (FUN_00BC7620, register_DColPrimBoxTypeInfo)
   *
   * What it does:
   * Installs the startup-owned `DColPrimBoxTypeInfo` instance and its process-
   * exit cleanup hook.
   */
  void register_DColPrimBoxTypeInfo()
  {
    if (!gDColPrimBoxTypeInfoConstructed) {
      new (gDColPrimBoxTypeInfoStorage) DColPrimBoxTypeInfo();
      gDColPrimBoxTypeInfoConstructed = true;
    }

    (void)std::atexit(&cleanup_DColPrimBoxTypeInfo_atexit);
  }

  /**
   * Address: 0x00BC76B0 (FUN_00BC76B0, register_DColPrimBoxSerializer)
   *
   * What it does:
   * Installs serializer callbacks for `DColPrimBox` and registers shutdown
   * unlink/destruction.
   */
  void register_DColPrimBoxSerializer()
  {
    InitializeHelperNode(gDColPrimBoxSerializer);
    gDColPrimBoxSerializer.mDeserialize = reinterpret_cast<gpg::RType::load_func_t>(&DColPrimBoxSerializer::Deserialize);
    gDColPrimBoxSerializer.mSerialize = reinterpret_cast<gpg::RType::save_func_t>(&DColPrimBoxSerializer::Serialize);
    (void)std::atexit(&cleanup_DColPrimBoxSerializer_atexit);
  }

  /**
   * Address: 0x00BC7670 (FUN_00BC7670, register_DColPrimBoxConstruct)
   *
   * What it does:
   * Installs construct/delete callbacks for `DColPrimBox` and registers
   * shutdown unlink/destruction.
   */
  int register_DColPrimBoxConstruct()
  {
    InitializeHelperNode(gDColPrimBoxConstruct);
    gDColPrimBoxConstruct.mConstructCallback = reinterpret_cast<gpg::RType::construct_func_t>(&ConstructDColPrimBox);
    gDColPrimBoxConstruct.mDeleteCallback = &DeleteDColPrimBox;
    return std::atexit(&cleanup_DColPrimBoxConstruct_atexit);
  }

  /**
   * Address: 0x00BC7640 (FUN_00BC7640, register_DColPrimBoxSaveConstruct)
   *
   * What it does:
   * Installs save-construct-args callbacks for `DColPrimBox` and registers
   * shutdown unlink/destruction.
   */
  int register_DColPrimBoxSaveConstruct()
  {
    InitializeHelperNode(gDColPrimBoxSaveConstruct);
    gDColPrimBoxSaveConstruct.mSaveConstructArgsCallback =
      reinterpret_cast<gpg::RType::save_construct_args_func_t>(&SaveConstructArgsDColPrimBox);
    return std::atexit(&cleanup_DColPrimBoxSaveConstruct_atexit);
  }
} // namespace moho

namespace
{
  struct DColPrimBoxBootstrap
  {
    DColPrimBoxBootstrap()
    {
      (void)moho::register_DColPrimBoxTypeInfo();
      (void)moho::register_DColPrimBoxSaveConstruct();
      (void)moho::register_DColPrimBoxConstruct();
      moho::register_DColPrimBoxSerializer();
    }
  };

  [[maybe_unused]] DColPrimBoxBootstrap gDColPrimBoxBootstrap;
} // namespace


