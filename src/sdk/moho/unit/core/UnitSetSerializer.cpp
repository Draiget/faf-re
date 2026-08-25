#include "moho/unit/core/UnitSetSerializer.h"

#include <cstdlib>
#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/entity/Entity.h"

namespace
{
  void cleanup_UnitSetSerializer();

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
   * Address: 0x006D2F20 (FUN_006D2F20)
   *
   * What it does:
   * Deserializes one `EntitySetBase` object lane using one local null-owner
   * reference.
   */
  void ReadEntitySetBaseArchiveObjectWithNullOwner_UnitSet(gpg::ReadArchive* const archive, void* const object)
  {
    gpg::RRef ownerRef{};
    archive->Read(ResolveEntitySetBaseType(), object, ownerRef);
  }

  /**
   * Address: 0x006D2F60 (FUN_006D2F60)
   *
   * What it does:
   * Serializes one `EntitySetBase` object lane using one local null-owner
   * reference.
   */
  void WriteEntitySetBaseArchiveObjectWithNullOwner_UnitSet(gpg::WriteArchive* const archive, void** const objectSlot)
  {
    const gpg::RRef ownerRef{};
    archive->Write(ResolveEntitySetBaseType(), objectSlot, ownerRef);
  }

  /**
   * Address: 0x006D3000 (FUN_006D3000)
   *
   * What it does:
   * Deserializes one `EntitySetTemplate<Unit>` object lane using one local
   * null-owner reference.
   */
  void ReadUnitSetArchiveObjectWithNullOwner(gpg::ReadArchive* const archive, void* const object)
  {
    gpg::RRef ownerRef{};
    archive->Read(ResolveUnitSetType(), object, ownerRef);
  }

  /**
   * Address: 0x006D3040 (FUN_006D3040)
   *
   * What it does:
   * Serializes one `EntitySetTemplate<Unit>` object lane using one local
   * null-owner reference.
   */
  void WriteUnitSetArchiveObjectWithNullOwner(gpg::WriteArchive* const archive, void** const objectSlot)
  {
    const gpg::RRef ownerRef{};
    archive->Write(ResolveUnitSetType(), objectSlot, ownerRef);
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
  void UnitSetSerializer::Init()
  {
    gpg::RType* const type = ResolveUnitSetType();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mDeserialize;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BD8480 (FUN_00BD8480, dynamic initializer for the global
   * `UnitSetSerializer` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields.
   */
  UnitSetSerializer::UnitSetSerializer()
    : mDeserialize(&UnitSetSerializer::Deserialize)
    , mSerialize(&UnitSetSerializer::Serialize)
  {
    (void)std::atexit(&cleanup_UnitSetSerializer);
  }
} // namespace moho

namespace
{
  // Address: 0x010B75D4 -- process-global `UnitSetSerializer` singleton.
  moho::UnitSetSerializer gUnitSetSerializer;

  /**
   * Address: 0x00BFE450 (FUN_00BFE450, cleanup_UnitSetSerializer)
   *
   * What it does:
   * Unlinks `UnitSetSerializer` helper-node links and rewires self-links.
   * The real ctor registers this plain free function (not a mangled
   * destructor) as its explicit atexit target.
   */
  void cleanup_UnitSetSerializer()
  {
    gUnitSetSerializer.ResetLinks();
  }
} // namespace
