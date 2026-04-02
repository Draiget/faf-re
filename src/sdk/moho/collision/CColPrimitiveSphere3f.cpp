#include "moho/collision/CColPrimitiveSphere3f.h"

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

  struct Sphere3fSerializerBootstrap
  {
    Sphere3fSerializerBootstrap()
    {
      gpg::SerHelperBase* const self = Sphere3fSerializerSelfNode(gSphere3fSerializer);
      gSphere3fSerializer.mHelperNext = self;
      gSphere3fSerializer.mHelperPrev = self;
      gSphere3fSerializer.mLoadCallback = &moho::Sphere3fSerializer::Deserialize;
      gSphere3fSerializer.mSaveCallback = &moho::Sphere3fSerializer::Serialize;
      gSphere3fSerializer.RegisterSerializeFunctions();
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


