#include "moho/serialization/WeakUnitSetSerializer.h"

#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/entity/Entity.h"

namespace
{
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
   * Address: 0x006D2EA0 (FUN_006D2EA0)
   *
   * What it does:
   * Resolves and caches RTTI for one `WeakEntitySetTemplate<Unit>` lane.
   */
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
} // namespace

namespace moho
{
  /**
   * Address: 0x00BD84E0 (FUN_00BD84E0, dynamic initializer for the global
   * `WeakUnitSetSerializer` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields.
   */
  WeakUnitSetSerializer::WeakUnitSetSerializer()
    : mDeserialize(&WeakUnitSetSerializer::Deserialize)
    , mSerialize(&WeakUnitSetSerializer::Serialize)
  {}

  WeakUnitSetSerializer::~WeakUnitSetSerializer()
  {
    ResetLinks();
  }

  /**
   * Address: 0x006D2C50 (FUN_006D2C50, sub_6D2C50)
   */
  void WeakUnitSetSerializer::Deserialize(
    gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef*
  )
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
  void WeakUnitSetSerializer::Serialize(
    gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef*
  )
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
  void WeakUnitSetSerializer::Init()
  {
    gpg::RType* const type = ResolveWeakUnitSetType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }
} // namespace moho

namespace
{
  // Address: 0x010B76B8 -- process-global `WeakUnitSetSerializer` singleton.
  moho::WeakUnitSetSerializer gWeakUnitSetSerializer;
} // namespace
