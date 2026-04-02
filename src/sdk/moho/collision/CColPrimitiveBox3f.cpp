#include "moho/collision/CColPrimitiveBox3f.h"

#include <cstdlib>
#include <limits>
#include <typeinfo>

#include "gpg/core/utils/Global.h"

#pragma init_seg(lib)

namespace
{
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
      gpg::SerHelperBase* const self = Box3fSerializerSelfNode(gBox3fSerializer);
      gBox3fSerializer.mHelperNext = self;
      gBox3fSerializer.mHelperPrev = self;
      gBox3fSerializer.mLoadCallback = &moho::Box3fSerializer::Deserialize;
      gBox3fSerializer.mSaveCallback = &moho::Box3fSerializer::Serialize;
      gBox3fSerializer.RegisterSerializeFunctions();
      (void)std::atexit(&CleanupBox3fSerializer);
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
    archive->Read(vector3Type, reinterpret_cast<Wm3::Vector3<float>*>(&Center[0]), ownerRef);

    gpg::RRef axis0OwnerRef{};
    archive->Read(vector3Type, reinterpret_cast<Wm3::Vector3<float>*>(&Axis[0][0]), axis0OwnerRef);

    gpg::RRef axis1OwnerRef{};
    archive->Read(vector3Type, reinterpret_cast<Wm3::Vector3<float>*>(&Axis[1][0]), axis1OwnerRef);

    gpg::RRef axis2OwnerRef{};
    archive->Read(vector3Type, reinterpret_cast<Wm3::Vector3<float>*>(&Axis[2][0]), axis2OwnerRef);

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
    archive->Write(vector3Type, reinterpret_cast<const Wm3::Vector3<float>*>(&Center[0]), ownerRef);

    gpg::RRef axis0OwnerRef{};
    archive->Write(vector3Type, reinterpret_cast<const Wm3::Vector3<float>*>(&Axis[0][0]), axis0OwnerRef);

    gpg::RRef axis1OwnerRef{};
    archive->Write(vector3Type, reinterpret_cast<const Wm3::Vector3<float>*>(&Axis[1][0]), axis1OwnerRef);

    gpg::RRef axis2OwnerRef{};
    archive->Write(vector3Type, reinterpret_cast<const Wm3::Vector3<float>*>(&Axis[2][0]), axis2OwnerRef);

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


