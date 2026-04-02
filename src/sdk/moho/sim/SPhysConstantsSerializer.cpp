#include "moho/sim/SPhysConstantsSerializer.h"

#include <cstdlib>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/sim/SPhysConstants.h"
#include "moho/sim/SPhysConstantsTypeInfo.h"

#pragma init_seg(lib)

namespace
{
  using Serializer = moho::SPhysConstantsSerializer;

  [[nodiscard]] Serializer& GetSPhysConstantsSerializer() noexcept
  {
    static Serializer serializer{};
    return serializer;
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

  [[nodiscard]] gpg::RType* CachedSPhysConstantsType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(moho::SPhysConstants));
    }

    GPG_ASSERT(cached != nullptr);
    return cached;
  }

  [[nodiscard]] gpg::SerHelperBase* SerializerSelfNode(Serializer& serializer) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&serializer.mHelperNext);
  }

  void InitializeSerializerNode(Serializer& serializer) noexcept
  {
    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperNext = self;
    serializer.mHelperPrev = self;
  }

  void cleanup_SPhysConstantsSerializer_atexit()
  {
    (void)moho::cleanup_SPhysConstantsSerializer();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00699C10 (FUN_00699C10, Moho::SPhysConstantsSerializer::Deserialize)
   */
  void SPhysConstantsSerializer::Deserialize(
    gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const /*ownerRef*/
  )
  {
    auto* const object = reinterpret_cast<SPhysConstants*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(object != nullptr);
    if (!archive || !object) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->Read(CachedVector3fType(), &object->mGravity, nullOwner);
  }

  /**
   * Address: 0x00699C50 (FUN_00699C50, Moho::SPhysConstantsSerializer::Serialize)
   */
  void SPhysConstantsSerializer::Serialize(
    gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const /*ownerRef*/
  )
  {
    const auto* const object = reinterpret_cast<const SPhysConstants*>(objectPtr);
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(object != nullptr);
    if (!archive || !object) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->Write(CachedVector3fType(), &object->mGravity, nullOwner);
  }

  /**
   * What it does:
   * Binds `SPhysConstants` RTTI load/save callbacks.
   */
  void SPhysConstantsSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = CachedSPhysConstantsType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BFD460 (FUN_00BFD460, cleanup_SPhysConstantsSerializer)
   */
  gpg::SerHelperBase* cleanup_SPhysConstantsSerializer()
  {
    Serializer& serializer = GetSPhysConstantsSerializer();
    gpg::SerHelperBase* const self = SerializerSelfNode(serializer);
    serializer.mHelperNext->mPrev = serializer.mHelperPrev;
    serializer.mHelperPrev->mNext = serializer.mHelperNext;
    serializer.mHelperPrev = self;
    serializer.mHelperNext = self;
    return self;
  }

  /**
   * Address: 0x00BD6050 (FUN_00BD6050, register_SPhysConstantsSerializer)
   */
  int register_SPhysConstantsSerializer()
  {
    Serializer& serializer = GetSPhysConstantsSerializer();
    InitializeSerializerNode(serializer);
    serializer.mDeserialize = &SPhysConstantsSerializer::Deserialize;
    serializer.mSerialize = &SPhysConstantsSerializer::Serialize;
    serializer.RegisterSerializeFunctions();
    return std::atexit(&cleanup_SPhysConstantsSerializer_atexit);
  }
} // namespace moho

namespace
{
  struct SPhysConstantsSerializerBootstrap
  {
    SPhysConstantsSerializerBootstrap()
    {
      (void)moho::register_SPhysConstantsSerializer();
    }
  };

  [[maybe_unused]] SPhysConstantsSerializerBootstrap gSPhysConstantsSerializerBootstrap;
} // namespace
