#include "moho/unit/core/UnitSetSerializer.h"

#include <cstdlib>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/entity/Entity.h"

namespace
{
  using Serializer = moho::UnitSetSerializer;

  Serializer gUnitSetSerializer{};

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

  [[nodiscard]] gpg::RType* ResolveEntitySetBaseType()
  {
    gpg::RType* type = moho::EntitySetBase::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::EntitySetBase));
      moho::EntitySetBase::sType = type;
    }

    GPG_ASSERT(type != nullptr);
    return type;
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

  /**
   * Address: 0x006D2A80 (FUN_006D2A80, sub_6D2A80)
   *
   * What it does:
   * Initializes global `UnitSetSerializer` links and callback pointers.
   */
  Serializer& construct_UnitSetSerializerVariant1()
  {
    InitializeSerializerNode(gUnitSetSerializer);
    gUnitSetSerializer.mDeserialize = &moho::UnitSetSerializer::Deserialize;
    gUnitSetSerializer.mSerialize = &moho::UnitSetSerializer::Serialize;
    return gUnitSetSerializer;
  }

  /**
   * Address: 0x006D2D60 (FUN_006D2D60, sub_6D2D60)
   *
   * What it does:
   * `SerSaveLoadHelper<EntitySetTemplate<Unit>>` thunk lane that reuses
   * `UnitSetSerializer` callback/link initialization.
   */
  Serializer& construct_UnitSetSerializerVariant2()
  {
    return construct_UnitSetSerializerVariant1();
  }

  void cleanup_UnitSetSerializer_00BFE450_atexit()
  {
    (void)moho::cleanup_UnitSetSerializer();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x006D2A00 (FUN_006D2A00, sub_6D2A00)
   */
  void UnitSetSerializer::Deserialize(gpg::ReadArchive* archive, int objectPtr, int /*version*/, gpg::RRef* /*ownerRef*/)
  {
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(objectPtr != 0);
    if (!archive || objectPtr == 0) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->Read(ResolveEntitySetBaseType(), reinterpret_cast<void*>(objectPtr), nullOwner);
  }

  /**
   * Address: 0x006D2A40 (FUN_006D2A40, sub_6D2A40)
   */
  void UnitSetSerializer::Serialize(gpg::WriteArchive* archive, int objectPtr, int /*version*/, gpg::RRef* /*ownerRef*/)
  {
    GPG_ASSERT(archive != nullptr);
    GPG_ASSERT(objectPtr != 0);
    if (!archive || objectPtr == 0) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->Write(ResolveEntitySetBaseType(), reinterpret_cast<void*>(objectPtr), nullOwner);
  }

  /**
   * Address: 0x006D2D90 (FUN_006D2D90, sub_6D2D90)
   */
  void UnitSetSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = ResolveUnitSetType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BFE450 (FUN_00BFE450, sub_BFE450)
   */
  gpg::SerHelperBase* cleanup_UnitSetSerializer()
  {
    gpg::SerHelperBase* const self = SerializerSelfNode(gUnitSetSerializer);
    if (!gUnitSetSerializer.mHelperNext || !gUnitSetSerializer.mHelperPrev) {
      gUnitSetSerializer.mHelperNext = self;
      gUnitSetSerializer.mHelperPrev = self;
      return self;
    }

    gUnitSetSerializer.mHelperNext->mPrev = gUnitSetSerializer.mHelperPrev;
    gUnitSetSerializer.mHelperPrev->mNext = gUnitSetSerializer.mHelperNext;
    gUnitSetSerializer.mHelperPrev = self;
    gUnitSetSerializer.mHelperNext = self;
    return self;
  }

  /**
   * Address: 0x00BD8480 (FUN_00BD8480, sub_BD8480)
   */
  int register_UnitSetSerializer()
  {
    (void)construct_UnitSetSerializerVariant1();
    (void)construct_UnitSetSerializerVariant2();
    gUnitSetSerializer.RegisterSerializeFunctions();
    return std::atexit(&cleanup_UnitSetSerializer_00BFE450_atexit);
  }
} // namespace moho

namespace
{
  struct UnitSetSerializerBootstrap
  {
    UnitSetSerializerBootstrap()
    {
      (void)moho::register_UnitSetSerializer();
    }
  };

  UnitSetSerializerBootstrap gUnitSetSerializerBootstrap;
} // namespace
