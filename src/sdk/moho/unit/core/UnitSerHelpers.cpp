#include "moho/unit/core/UnitSerHelpers.h"

#include <cstdint>
#include <cstdlib>
#include <typeinfo>

#include "gpg/core/utils/Global.h"

namespace gpg
{
  class SerConstructResult
  {
  public:
    void SetUnowned(const RRef& ref, unsigned int flags);
  };
} // namespace gpg

namespace
{
  /**
   * Address: 0x00BD6B20 (FUN_00BD6B20, dynamic initializer for the global
   * `UnitConstruct` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * construct/delete callback fields (vtable slot 0 `Init()` dispatched
   * later by `gpg::SerHelperBase::InitNewHelpers`). Confirmed via raw asm:
   * base-ctor call -> field-set -> vtable-install -> atexit, with no eager
   * `RegisterConstructFunction()` dispatch (the prior recovery fabricated
   * that eager call from `register_UnitConstruct`).
   */
  moho::UnitConstruct gUnitConstruct{};

  /**
   * Address: 0x00BD6B60 (FUN_00BD6B60, dynamic initializer for the global
   * `UnitSerializer` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields. Independent `__xc_a` static initializer,
   * separate from `UnitConstruct`'s own initializer above.
   */
  moho::UnitSerializer gUnitSerializer{};
} // namespace

namespace moho
{
  /**
   * Address: 0x006AD3A0 (FUN_006AD3A0, Moho::UnitConstruct::Construct)
   *
   * What it does:
   * Forwards construct callback flow into `Unit::MemberConstruct`.
   */
  void UnitConstruct::Construct(
    gpg::ReadArchive* const archive,
    const int,
    const int version,
    gpg::SerConstructResult* const result
  )
  {
    if (!archive || !result) {
      return;
    }

    gpg::RRef ownerRef{};
    Unit::MemberConstruct(*archive, version, ownerRef, *result);
  }

  /**
   * Address: 0x006B1010 (FUN_006B1010, Moho::UnitConstruct::Deconstruct)
   *
   * What it does:
   * Runs deleting-dtor teardown for one constructed `Unit`.
   */
  void UnitConstruct::Deconstruct(void* const objectPtr)
  {
    if (!objectPtr) {
      return;
    }

    auto* const entitySubobject = reinterpret_cast<Entity*>(reinterpret_cast<std::uint8_t*>(objectPtr) + 0x08);
    delete entitySubobject;
  }

  /**
   * Address: 0x006AD470 (FUN_006AD470, Moho::UnitSerializer::Deserialize)
   *
   * What it does:
   * Forwards archive-load callback into `Unit::MemberDeserialize`.
   */
  void UnitSerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, const int version, gpg::RRef*)
  {
    auto* const unit = reinterpret_cast<Unit*>(objectPtr);
    if (!archive || !unit) {
      return;
    }

    Unit::MemberDeserialize(archive, unit, version);
  }

  /**
   * Address: 0x006AD490 (FUN_006AD490, Moho::UnitSerializer::Serialize)
   *
   * What it does:
   * Forwards archive-save callback into `Unit::MemberSerialize`.
   */
  void UnitSerializer::Serialize(gpg::WriteArchive* const archive, const int objectPtr, const int version, gpg::RRef*)
  {
    auto* const unit = reinterpret_cast<Unit*>(objectPtr);
    if (!archive || !unit) {
      return;
    }

    Unit::MemberSerialize(archive, unit, version);
  }

  /**
   * Address: 0x00BD6B20 (FUN_00BD6B20, register_UnitConstruct)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * construct/delete callback fields.
   */
  UnitConstruct::UnitConstruct()
    : mConstructCallback(reinterpret_cast<gpg::RType::construct_func_t>(&UnitConstruct::Construct))
    , mDeconstructCallback(&UnitConstruct::Deconstruct)
  {}

  /**
   * Address: 0x00BFDA00 (FUN_00BFDA00, Moho::UnitConstruct::~UnitConstruct)
   */
  UnitConstruct::~UnitConstruct()
  {
    ResetLinks();
  }

  /**
   * Address: 0x006AE9A0 (FUN_006AE9A0, Moho::UnitConstruct::RegisterConstructFunction)
   *
   * What it does:
   * Binds construct/delete callbacks into reflected RTTI for `Unit`. Real
   * body caches on `Unit::sType` directly; reached here through the
   * already-established `Unit::StaticGetClass()` accessor rather than the
   * prior recovery's disconnected local `gUnitType` cache.
   */
  void UnitConstruct::Init()
  {
    gpg::RType* const type = Unit::StaticGetClass();

    GPG_ASSERT(type != nullptr);
    GPG_ASSERT(type->serConstructFunc_ == nullptr);
    type->serConstructFunc_ = mConstructCallback;
    type->deleteFunc_ = mDeconstructCallback;
  }

  /**
   * Address: 0x00BD6B60 (FUN_00BD6B60, register_UnitSerializer)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields.
   */
  UnitSerializer::UnitSerializer()
    : mDeserialize(reinterpret_cast<gpg::RType::load_func_t>(&UnitSerializer::Deserialize))
    , mSerialize(reinterpret_cast<gpg::RType::save_func_t>(&UnitSerializer::Serialize))
  {}

  /**
   * Address: 0x00BFDA30 (FUN_00BFDA30, Moho::UnitSerializer::~UnitSerializer)
   */
  UnitSerializer::~UnitSerializer()
  {
    ResetLinks();
  }

  /**
   * Address: 0x006AEA20 (FUN_006AEA20, gpg::SerSaveLoadHelper<Moho::Unit>::Init lane)
   *
   * What it does:
   * Binds load/save callbacks into reflected RTTI for `Unit`.
   */
  void UnitSerializer::Init()
  {
    gpg::RType* const type = Unit::StaticGetClass();
    GPG_ASSERT(type != nullptr);
    GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mDeserialize);
    GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSerialize);
    type->serLoadFunc_ = mDeserialize;
    type->serSaveFunc_ = mSerialize;
  }
} // namespace moho
