#include "moho/collision/CColPrimitiveBox3f.h"

#include <cstdlib>
#include <limits>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/reflection/StaticInitPhase.h"

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

  moho::Box3fTypeInfo gBox3fTypeInfo;

  struct Box3fTypeInfoBootstrap
  {
    Box3fTypeInfoBootstrap()
    {
      moho::register_Box3fTypeInfo();
    }
  };

  Box3fTypeInfoBootstrap gBox3fTypeInfoBootstrap;

  // Address: 0x010A7CBC -- process-global `Box3fSerializer` singleton.
  moho::Box3fSerializer gBox3fSerializer;
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
   * Address: 0x004756D0 (FUN_004756D0, gpg::SerSaveLoadHelper<Wm3::Box3<float>>::Init lane)
   */
  void Box3fSerializer::Init()
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
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields.
   */
  Box3fSerializer::Box3fSerializer()
    : mLoadCallback(&Box3fSerializer::Deserialize)
    , mSaveCallback(&Box3fSerializer::Serialize)
  {}

  Box3fSerializer::~Box3fSerializer()
  {
    ResetLinks();
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


  void CleanupDColPrimBoxTypeInfoAtExit()
  {
    if (!gDColPrimBoxTypeInfoConstructed) {
      return;
    }

    reinterpret_cast<moho::DColPrimBoxTypeInfo*>(gDColPrimBoxTypeInfoStorage)->~DColPrimBoxTypeInfo();
    gDColPrimBoxTypeInfoConstructed = false;
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
   * Address: 0x004FF620 (FUN_004FF620)
   *
   * What it does:
   * Serializes one box primitive's shape payload and local-center payload
   * through the primitive virtual accessors used by save-construct lanes.
   */
  void SaveBoxPrimitiveConstructArgs(
    moho::BoxCollisionPrimitive* const primitive,
    gpg::WriteArchive* const archive,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    Wm3::Vec3f center{};
    gpg::RRef shapeOwnerRef{};
    archive->Write(CachedDColPrimBoxShapeType(), primitive->GetBox(), shapeOwnerRef);

    gpg::RRef centerOwnerRef{};
    archive->Write(CachedDColPrimBoxVector3fType(), primitive->GetCenter(&center), centerOwnerRef);
    result->SetUnowned(0u);
  }

  /**
   * Address: 0x004FF570 (FUN_004FF570)
   *
   * What it does:
   * Tail-forwards save-construct-args dispatch into the shared box primitive
   * serialization helper.
   */
  void SaveConstructArgsDColPrimBox(
    gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::SerSaveConstructArgsResult* const result
  )
  {
    auto* const primitive = reinterpret_cast<moho::BoxCollisionPrimitive*>(objectPtr);
    SaveBoxPrimitiveConstructArgs(primitive, archive, result);
  }

  /**
   * Address: 0x00500570 (FUN_00500570, j_j_func_tent_Destroy_4 -> ??3@YAXPAX@Z)
   *
   * What it does:
   * Frees one constructed box collision primitive's raw storage. Confirmed
   * from raw disassembly: the real delete-callback field is a direct jump
   * thunk to the global `operator delete(void*)`, NOT a per-type wrapper
   * that runs `~BoxCollisionPrimitive()` first -- `BoxCollisionPrimitive`
   * is deleted through this path with no destructor call.
   */
  void DeleteDColPrimBox(void* const objectPtr)
  {
    ::operator delete(objectPtr);
  }

  void cleanup_DColPrimBoxTypeInfo_atexit()
  {
    CleanupDColPrimBoxTypeInfoAtExit();
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
 * Address: 0x005004D0 (FUN_005004D0, Moho::DColPrimBoxTypeInfo::AddBase_CColPrimitiveBase)
 *
 * What it does:
 * Registers `CColPrimitiveBase` as this type's reflected base at offset 0 -
 * the primitive derives from it singly.
 */
void DColPrimBoxTypeInfo::AddBase_CColPrimitiveBase(gpg::RType* const typeInfo)
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
  void DColPrimBoxSerializer::Init()
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
   * Address: 0x00BC76B0 (FUN_00BC76B0, register_DColPrimBoxSerializer)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields.
   */
  DColPrimBoxSerializer::DColPrimBoxSerializer()
    : mDeserialize(reinterpret_cast<gpg::RType::load_func_t>(&DColPrimBoxSerializer::Deserialize))
    , mSerialize(reinterpret_cast<gpg::RType::save_func_t>(&DColPrimBoxSerializer::Serialize))
  {}

  DColPrimBoxSerializer::~DColPrimBoxSerializer()
  {
    ResetLinks();
  }

  /**
   * Address: 0x004FFCF0 (FUN_004FFCF0, Moho::DColPrimBoxConstruct::RegisterConstructFunction)
   */
  void DColPrimBoxConstruct::Init()
  {
    gpg::RType* const type = CachedDColPrimBoxPrimitiveType();
    if (type->serConstructFunc_ != nullptr) {
      gpg::HandleAssertFailure("!type->mSerConstructFunc", kConstructLine, kSerializationSourcePath);
    }
    type->serConstructFunc_ = mConstructCallback;
    type->deleteFunc_ = mDeleteCallback;
  }

  /**
   * Address: 0x00BC7670 (FUN_00BC7670, register_DColPrimBoxConstruct)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * construct/delete callback fields.
   */
  DColPrimBoxConstruct::DColPrimBoxConstruct()
    : mConstructCallback(reinterpret_cast<gpg::RType::construct_func_t>(&ConstructDColPrimBox))
    , mDeleteCallback(&DeleteDColPrimBox)
  {}

  DColPrimBoxConstruct::~DColPrimBoxConstruct()
  {
    ResetLinks();
  }

  /**
   * Address: 0x004FFC70 (FUN_004FFC70, Moho::DColPrimBoxSaveConstruct::RegisterSaveConstructArgsFunction)
   */
  void DColPrimBoxSaveConstruct::Init()
  {
    gpg::RType* const type = CachedDColPrimBoxPrimitiveType();
    if (type->serSaveConstructArgsFunc_ != nullptr) {
      gpg::HandleAssertFailure("!type->mSerSaveConstructArgsFunc", kSaveConstructArgsLine, kSerializationSourcePath);
    }
    type->serSaveConstructArgsFunc_ = mSaveConstructArgsCallback;
  }

  /**
   * Address: 0x00BC7640 (FUN_00BC7640, register_DColPrimBoxSaveConstruct)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * save-construct-args callback field.
   */
  DColPrimBoxSaveConstruct::DColPrimBoxSaveConstruct()
    : mSaveConstructArgsCallback(
        reinterpret_cast<gpg::RType::save_construct_args_func_t>(&SaveConstructArgsDColPrimBox)
      )
  {}

  DColPrimBoxSaveConstruct::~DColPrimBoxSaveConstruct()
  {
    ResetLinks();
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
} // namespace moho

namespace
{
  struct DColPrimBoxTypeInfoBootstrap
  {
    DColPrimBoxTypeInfoBootstrap()
    {
      (void)moho::register_DColPrimBoxTypeInfo();
    }
  };

  [[maybe_unused]] DColPrimBoxTypeInfoBootstrap gDColPrimBoxTypeInfoBootstrap;

  // Address: 0x010A9C0C -- process-global `DColPrimBoxSerializer` singleton.
  moho::DColPrimBoxSerializer gDColPrimBoxSerializer;

  // Address: 0x010A9E14 -- process-global `DColPrimBoxConstruct` singleton.
  moho::DColPrimBoxConstruct gDColPrimBoxConstruct;

  // Address: 0x010A9C84 -- process-global `DColPrimBoxSaveConstruct` singleton.
  moho::DColPrimBoxSaveConstruct gDColPrimBoxSaveConstruct;
} // namespace


// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_Box3fTypeInfo_88284f, moho::register_Box3fTypeInfo)
GPG_PREREGISTER_INIT(register_DColPrimBoxTypeInfo_88284f, moho::register_DColPrimBoxTypeInfo)
