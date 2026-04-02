#include "moho/serialization/WeakUnitSetSerializer.h"

#include <cstdlib>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/entity/Entity.h"

namespace
{
  using Serializer = moho::WeakUnitSetSerializer;

  Serializer gWeakUnitSetSerializer{};

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

  [[nodiscard]] gpg::RType* ResolveUnitSetType()
  {
    gpg::RType* type = moho::EntitySetTemplate<moho::Unit>::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::EntitySetTemplate<moho::Unit>));
      moho::EntitySetTemplate<moho::Unit>::sType = type;
    }

    GPG_ASSERT(type != nullptr);
    return type;
  }

  [[nodiscard]] gpg::RType* ResolveWeakUnitSetType()
  {
    gpg::RType* type = moho::WeakEntitySetTemplate<moho::Unit>::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::WeakEntitySetTemplate<moho::Unit>));
      moho::WeakEntitySetTemplate<moho::Unit>::sType = type;
    }

    GPG_ASSERT(type != nullptr);
    return type;
  }

  /**
   * Address: 0x006D2CD0 (FUN_006D2CD0, sub_6D2CD0)
   *
   * What it does:
   * Initializes global `WeakUnitSetSerializer` links and callback pointers.
   */
  Serializer& construct_WeakUnitSetSerializerVariant1()
  {
    InitializeSerializerNode(gWeakUnitSetSerializer);
    gWeakUnitSetSerializer.mDeserialize = &moho::WeakUnitSetSerializer::Deserialize;
    gWeakUnitSetSerializer.mSerialize = &moho::WeakUnitSetSerializer::Serialize;
    return gWeakUnitSetSerializer;
  }

  /**
   * Address: 0x006D2E00 (FUN_006D2E00, sub_6D2E00)
   *
   * What it does:
   * `SerSaveLoadHelper<WeakEntitySetTemplate<Unit>>` thunk lane that reuses
   * weak unit-set serializer initialization.
   */
  Serializer& construct_WeakUnitSetSerializerVariant2()
  {
    return construct_WeakUnitSetSerializerVariant1();
  }

  void cleanup_WeakUnitSetSerializer_00BFE4E0_atexit()
  {
    (void)moho::cleanup_WeakUnitSetSerializer();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x006D2C50 (FUN_006D2C50, sub_6D2C50)
   */
  void
  WeakUnitSetSerializer::Deserialize(gpg::ReadArchive* archive, int objectPtr, int /*version*/, gpg::RRef* /*ownerRef*/)
  {
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(objectPtr != 0);
    if (!archive || objectPtr == 0) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->Read(ResolveUnitSetType(), reinterpret_cast<void*>(objectPtr), nullOwner);
  }

  /**
   * Address: 0x006D2C90 (FUN_006D2C90, sub_6D2C90)
   */
  void
  WeakUnitSetSerializer::Serialize(gpg::WriteArchive* archive, int objectPtr, int /*version*/, gpg::RRef* /*ownerRef*/)
  {
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(objectPtr != 0);
    if (!archive || objectPtr == 0) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->Write(ResolveUnitSetType(), reinterpret_cast<void*>(objectPtr), nullOwner);
  }

  /**
   * Address: 0x006D2E30 (FUN_006D2E30, sub_6D2E30)
   */
  void WeakUnitSetSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = ResolveWeakUnitSetType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BFE4E0 (FUN_00BFE4E0, sub_BFE4E0)
   */
  gpg::SerHelperBase* cleanup_WeakUnitSetSerializer()
  {
    gpg::SerHelperBase* const self = SerializerSelfNode(gWeakUnitSetSerializer);
    if (!gWeakUnitSetSerializer.mHelperNext || !gWeakUnitSetSerializer.mHelperPrev) {
      gWeakUnitSetSerializer.mHelperNext = self;
      gWeakUnitSetSerializer.mHelperPrev = self;
      return self;
    }

    gWeakUnitSetSerializer.mHelperNext->mPrev = gWeakUnitSetSerializer.mHelperPrev;
    gWeakUnitSetSerializer.mHelperPrev->mNext = gWeakUnitSetSerializer.mHelperNext;
    gWeakUnitSetSerializer.mHelperPrev = self;
    gWeakUnitSetSerializer.mHelperNext = self;
    return self;
  }

  /**
   * Address: 0x00BD84E0 (FUN_00BD84E0, sub_BD84E0)
   */
  int register_WeakUnitSetSerializer()
  {
    (void)construct_WeakUnitSetSerializerVariant1();
    (void)construct_WeakUnitSetSerializerVariant2();
    gWeakUnitSetSerializer.RegisterSerializeFunctions();
    return std::atexit(&cleanup_WeakUnitSetSerializer_00BFE4E0_atexit);
  }
} // namespace moho

namespace
{
  struct WeakUnitSetSerializerBootstrap
  {
    WeakUnitSetSerializerBootstrap()
    {
      (void)moho::register_WeakUnitSetSerializer();
    }
  };

  WeakUnitSetSerializerBootstrap gWeakUnitSetSerializerBootstrap;
} // namespace
