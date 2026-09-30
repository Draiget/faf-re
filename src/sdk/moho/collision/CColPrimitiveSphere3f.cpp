#include "moho/collision/CColPrimitiveSphere3f.h"

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

  [[nodiscard]] gpg::RType* CachedSphere3fType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(Wm3::Sphere3<float>));
    }
    GPG_ASSERT(cached != nullptr);
    return cached;
  }
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
  void Sphere3fSerializer::Init()
  {
    gpg::RType* const type = CachedSphere3fType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }

  /**
   * Address: 0x00BC4970 (FUN_00BC4970, dynamic initializer for the global
   * `Sphere3fSerializer` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields.
   */
  Sphere3fSerializer::Sphere3fSerializer()
    : mLoadCallback(&Sphere3fSerializer::Deserialize)
    , mSaveCallback(&Sphere3fSerializer::Serialize)
  {}

  /**
   * Address: 0x00BEF780 (FUN_00BEF780, Moho::Sphere3fSerializer::~Sphere3fSerializer)
   */
  Sphere3fSerializer::~Sphere3fSerializer() = default;

  /**
   * Address: 0x00473050 (FUN_00473050, Moho::Invalid<Wm3::Sphere3<float>>)
   */
  template <>
  const Wm3::Sphere3f& Invalid<Wm3::Sphere3f>()
  {
    static bool initialized = false;
    static Wm3::Sphere3f invalid{};

    if (!initialized) {
      const float nanValue = gpg::NaN;
      invalid.Center = Wm3::Vector3<float>{nanValue, nanValue, nanValue};
      invalid.Radius = nanValue;
      initialized = true;
    }

    return invalid;
  }
} // namespace moho

namespace
{
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

  [[nodiscard]] gpg::RRef MakeDColPrimSphereRef(moho::CColPrimitive<Wm3::Sphere3f>* object)
  {
    gpg::RRef ref{};
    ref.mObj = object;
    ref.mType = CachedDColPrimSpherePrimitiveType();
    return ref;
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
   * Address: 0x00500390 (FUN_00500390, Moho::DColPrimSphereTypeInfo::AddBase_CColPrimitiveBase)
   *
   * What it does:
   * Registers `CColPrimitiveBase` as this type's reflected base at offset 0 -
   * the primitive derives from it singly.
   */
  void DColPrimSphereTypeInfo::AddBase_CColPrimitiveBase(gpg::RType* const typeInfo)
  {
    GPG_ASSERT(typeInfo != nullptr);
    GPG_ASSERT(!typeInfo->initFinished_);

    gpg::RField baseField{};
    baseField.mName = CachedCColPrimitiveBaseType()->GetName();
    baseField.mType = CachedCColPrimitiveBaseType();
    baseField.mOffset = 0;
    baseField.mFlags = 0;
    baseField.mDesc = nullptr;
    typeInfo->AddBase(baseField);
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
   * Address: 0x004FFB40 (FUN_004FFB40, Moho::DColPrimSphereSerializer::Init)
   */
  void DColPrimSphereSerializer::Init()
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
   * Address: 0x00BC75E0 (FUN_00BC75E0, dynamic initializer for the global
   * `DColPrimSphereSerializer` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields.
   */
  DColPrimSphereSerializer::DColPrimSphereSerializer()
    : mDeserialize(reinterpret_cast<gpg::RType::load_func_t>(&DColPrimSphereSerializer::Deserialize))
    , mSerialize(reinterpret_cast<gpg::RType::save_func_t>(&DColPrimSphereSerializer::Serialize))
  {}

  DColPrimSphereSerializer::~DColPrimSphereSerializer() = default;

  /**
   * Address: 0x004FE640 (FUN_004FE640, preregister_DColPrimSphereTypeInfo)
   * Address: 0x00BF1A40 (FUN_00BF1A40, atexit destructor of the DColPrimSphereTypeInfo object)
   *
   * What it does:
   * Constructs/preregisters the startup-owned `DColPrimSphereTypeInfo`
   * instance for `typeid(CColPrimitive<Wm3::Sphere3f>)`.
   */
  [[nodiscard]] gpg::RType* preregister_DColPrimSphereTypeInfo()
  {
    static DColPrimSphereTypeInfo sInstance;
    gpg::PreRegisterRType(typeid(CColPrimitive<Wm3::Sphere3f>), &sInstance);
    return &sInstance;
  }

  /**
   * Address: 0x00BC7550 (FUN_00BC7550, register_DColPrimSphereTypeInfo)
   *
   * What it does:
   * Installs the startup-owned `DColPrimSphereTypeInfo` instance.
   */
  void register_DColPrimSphereTypeInfo()
  {
    (void)preregister_DColPrimSphereTypeInfo();
  }
} // namespace moho

namespace
{
  struct DColPrimSphereTypeInfoBootstrap
  {
    DColPrimSphereTypeInfoBootstrap()
    {
      (void)moho::register_DColPrimSphereTypeInfo();
    }
  };

  [[maybe_unused]] DColPrimSphereTypeInfoBootstrap gDColPrimSphereTypeInfoBootstrap;

  // Address: 0x010A7C34 -- process-global `Sphere3fSerializer` singleton.
  moho::Sphere3fSerializer gSphere3fSerializer;

  // Address: 0x010A9D84 -- process-global `DColPrimSphereSerializer` singleton.
  moho::DColPrimSphereSerializer gDColPrimSphereSerializer;

} // namespace

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_DColPrimSphereTypeInfo_2459d0, moho::register_DColPrimSphereTypeInfo)
GPG_PREREGISTER_INIT(preregister_DColPrimSphereTypeInfo_2459d0, moho::preregister_DColPrimSphereTypeInfo)

namespace moho
{
  void CColPrimitive<Wm3::Sphere3f>::MemberConstruct(gpg::ReadArchive& archive, const int, const gpg::RRef&, gpg::SerConstructResult& result)
  {
    Wm3::Sphere3f shape{};
    Wm3::Vec3f localCenter{};
    const gpg::RRef ownerRef{};

    archive.Read(CachedDColPrimSphereShapeType(), &shape, ownerRef);
    archive.Read(CachedDColPrimSphereVector3fType(), &localCenter, ownerRef);

    auto* object = new CColPrimitive<Wm3::Sphere3f>(localCenter, shape.Radius);
    if (object != nullptr) {
      object->mShape.Center = shape.Center;
      object->mShape.Radius = shape.Radius;
      object->mLocalCenter = localCenter;
    }

    result.SetUnowned(MakeDColPrimSphereRef(object), 0u);
  }

  /**
   * Address: 0x004FECF0 (FUN_004FECF0)
   */
  void CColPrimitive<Wm3::Sphere3f>::MemberSaveConstructArgs(
    gpg::WriteArchive& archive, const int, const gpg::RRef&, gpg::SerSaveConstructArgsResult& result
  )
  {
    Wm3::Vec3f center{};
    gpg::RRef shapeOwnerRef{};
    archive.Write(CachedDColPrimSphereShapeType(), GetSphere(), shapeOwnerRef);

    gpg::RRef centerOwnerRef{};
    archive.Write(CachedDColPrimSphereVector3fType(), GetCenter(&center), centerOwnerRef);
    result.SetUnowned(0u);
  }

  /**
   * `gpg::SerSaveConstructHelper<CColPrimitive<Wm3::Sphere3f>>`, vtable 0x00E0D4DC.
   *
   * Address: 0x00BC7570 (FUN_00BC7570 -- constructs the global and registers its destructor.)
   * Address: 0x00BF1AA0 (FUN_00BF1AA0 -- the global's destructor.)
   * Address: 0x004FFA40 (FUN_004FFA40 -- `Init`.)
   * Address: 0x004FEC50 (FUN_004FEC50 -- `SaveConstructArgs`, a forward to `MemberSaveConstructArgs`.)
   */
  struct DColPrimSphereSaveConstruct : gpg::SerSaveConstructHelper<CColPrimitive<Wm3::Sphere3f>>
  {};

  /**
   * `gpg::SerConstructHelper<CColPrimitive<Wm3::Sphere3f>>`, vtable 0x00E0D4EC.
   *
   * Address: 0x00BC75A0 (FUN_00BC75A0 -- constructs the global and registers its destructor.)
   * Address: 0x00BF1AD0 (FUN_00BF1AD0 -- the global's destructor.)
   * Address: 0x004FFAC0 (FUN_004FFAC0 -- `Init`.)
   * Address: 0x004FEE20 (FUN_004FEE20 -- `Construct`, `MemberConstruct` inlined.)
   * Address: 0x00500430 (FUN_00500430 -- `Delete`.)
   */
  struct DColPrimSphereConstruct : gpg::SerConstructHelper<CColPrimitive<Wm3::Sphere3f>>
  {};
} // namespace moho

namespace
{
  // Address: 0x010A9C94 -- process-global `DColPrimSphereSaveConstruct` singleton.
  moho::DColPrimSphereSaveConstruct gDColPrimSphereSaveConstruct;

  // Address: 0x010A9CA4 -- process-global `DColPrimSphereConstruct` singleton.
  moho::DColPrimSphereConstruct gDColPrimSphereConstruct;
} // namespace
