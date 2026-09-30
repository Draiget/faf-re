#include "moho/collision/CColPrimitiveBox3f.h"

#include <cstdlib>
#include <limits>
#include <new>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "gpg/core/reflection/StaticInitPhase.h"
#include "gpg/core/reflection/Reflection.h"

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
      const float nanValue = gpg::NaN;
      const Wm3::Vector3<float> invalidVector{nanValue, nanValue, nanValue};
      invalid = Wm3::Box3f(invalidVector, invalidVector, invalidVector, invalidVector, nanValue, nanValue, nanValue);
      initialized = true;
    }

    return invalid;
  }
} // namespace moho

namespace
{
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

  [[nodiscard]] gpg::RRef MakeDColPrimBoxRef(moho::CColPrimitive<Wm3::Box3f>* object)
  {
    gpg::RRef ref{};
    ref.mObj = object;
    ref.mType = CachedDColPrimBoxPrimitiveType();
    return ref;
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
  baseField.mFlags = 0;
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
   * Address: 0x00BC7620 (FUN_00BC7620, register_DColPrimBoxTypeInfo)
   * Address: 0x00BF1B30 (FUN_00BF1B30, atexit destructor of the DColPrimBoxTypeInfo object)
   *
   * What it does:
   * Installs the startup-owned `DColPrimBoxTypeInfo` instance.
   */
  void register_DColPrimBoxTypeInfo()
  {
    static DColPrimBoxTypeInfo sInstance;
    (void)sInstance;
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

} // namespace

// Phase-1 pre-registration: run these descriptor registrations ahead of
// every consumer that calls gpg::LookupRType. See StaticInitPhase.h.
GPG_PREREGISTER_INIT(register_Box3fTypeInfo_88284f, moho::register_Box3fTypeInfo)
GPG_PREREGISTER_INIT(register_DColPrimBoxTypeInfo_88284f, moho::register_DColPrimBoxTypeInfo)

namespace moho
{
  void CColPrimitive<Wm3::Box3f>::MemberConstruct(gpg::ReadArchive& archive, const int, const gpg::RRef&, gpg::SerConstructResult& result)
  {
    Wm3::Box3f shape{};
    Wm3::Vec3f localCenter{};
    const gpg::RRef ownerRef{};

    archive.Read(CachedDColPrimBoxShapeType(), &shape, ownerRef);
    archive.Read(CachedDColPrimBoxVector3fType(), &localCenter, ownerRef);

    auto* object = new CColPrimitive<Wm3::Box3f>(shape);
    if (object != nullptr) {
      object->mLocalCenter = localCenter;
    }

    result.SetUnowned(MakeDColPrimBoxRef(object), 0u);
  }

  /**
   * Address: 0x004FF620 (FUN_004FF620)
   */
  void CColPrimitive<Wm3::Box3f>::MemberSaveConstructArgs(
    gpg::WriteArchive& archive, const int, const gpg::RRef&, gpg::SerSaveConstructArgsResult& result
  )
  {
    Wm3::Vec3f center{};
    gpg::RRef shapeOwnerRef{};
    archive.Write(CachedDColPrimBoxShapeType(), GetBox(), shapeOwnerRef);

    gpg::RRef centerOwnerRef{};
    archive.Write(CachedDColPrimBoxVector3fType(), GetCenter(&center), centerOwnerRef);
    result.SetUnowned(0u);
  }

  /**
   * `gpg::SerSaveConstructHelper<CColPrimitive<Wm3::Box3f>>`, vtable 0x00E0D568.
   *
   * Address: 0x00BC7640 (FUN_00BC7640 -- constructs the global and registers its destructor.)
   * Address: 0x00BF1B90 (FUN_00BF1B90 -- the global's destructor.)
   * Address: 0x004FFC70 (FUN_004FFC70 -- `Init`.)
   * Address: 0x004FF570 (FUN_004FF570 -- `SaveConstructArgs`, a forward to `MemberSaveConstructArgs`.)
   */
  struct DColPrimBoxSaveConstruct : gpg::SerSaveConstructHelper<CColPrimitive<Wm3::Box3f>>
  {};

  /**
   * `gpg::SerConstructHelper<CColPrimitive<Wm3::Box3f>>`, vtable 0x00E0D578.
   *
   * Address: 0x00BC7670 (FUN_00BC7670 -- constructs the global and registers its destructor.)
   * Address: 0x00BF1BC0 (FUN_00BF1BC0 -- the global's destructor.)
   * Address: 0x004FFCF0 (FUN_004FFCF0 -- `Init`.)
   * Address: 0x004FF750 (FUN_004FF750 -- `Construct`, `MemberConstruct` inlined.)
   * Address: 0x00500570 (FUN_00500570 -- `Delete`.)
   */
  struct DColPrimBoxConstruct : gpg::SerConstructHelper<CColPrimitive<Wm3::Box3f>>
  {};
} // namespace moho

namespace
{
  // Address: 0x010A9C84 -- process-global `DColPrimBoxSaveConstruct` singleton.
  moho::DColPrimBoxSaveConstruct gDColPrimBoxSaveConstruct;

  // Address: 0x010A9E14 -- process-global `DColPrimBoxConstruct` singleton.
  moho::DColPrimBoxConstruct gDColPrimBoxConstruct;
} // namespace

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<Wm3::Box3f>`, vtable 0x00E03944.
   *
   * Address: 0x00BC4A40 (FUN_00BC4A40 -- constructs the global and registers its destructor.)
   * Address: 0x00BEF830 (FUN_00BEF830 -- the global's destructor.)
   * Address: 0x004756D0 (FUN_004756D0 -- `Init`.)
   * Address: 0x00474770 (FUN_00474770 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x00474780 (FUN_00474780 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct Box3fSerializer : gpg::SerSaveLoadHelper<Wm3::Box3f>
  {};
} // namespace moho

namespace
{
  // Address: 0x010A7CBC -- process-global `Box3fSerializer` singleton.
  moho::Box3fSerializer gBox3fSerializer;
} // namespace

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<CColPrimitive<Wm3::Box3f>>`, vtable 0x00E0D588.
   *
   * Address: 0x00BC76B0 (FUN_00BC76B0 -- constructs the global and registers its destructor.)
   * Address: 0x00BF1BF0 (FUN_00BF1BF0 -- the global's destructor.)
   * Address: 0x004FFD70 (FUN_004FFD70 -- `Init`.)
   * Address: 0x004FF880 (FUN_004FF880 -- `Deserialize`, `MemberDeserialize` inlined.)
   * Address: 0x004FF890 (FUN_004FF890 -- `Serialize`, `MemberSerialize` inlined.)
   */
  struct DColPrimBoxSerializer : gpg::SerSaveLoadHelper<CColPrimitive<Wm3::Box3f>>
  {};
} // namespace moho

namespace
{
  // Address: 0x010A9C0C -- process-global `DColPrimBoxSerializer` singleton.
  moho::DColPrimBoxSerializer gDColPrimBoxSerializer;
} // namespace
