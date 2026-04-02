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

#pragma init_seg(lib)

namespace
{
  gpg::RType* gUnitType = nullptr;
  moho::UnitConstruct gUnitConstruct{};
  moho::UnitSerializer gUnitSerializer{};

  template <typename TObject>
  [[nodiscard]] gpg::RType* ResolveCachedType(gpg::RType*& slot)
  {
    if (!slot) {
      slot = gpg::LookupRType(typeid(TObject));
    }
    return slot;
  }

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* HelperSelfNode(THelper& helper) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&helper.mHelperNext);
  }

  template <typename THelper>
  void InitializeHelperNode(THelper& helper) noexcept
  {
    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperNext = self;
    helper.mHelperPrev = self;
  }

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* UnlinkHelperNode(THelper& helper) noexcept
  {
    if (helper.mHelperNext != nullptr && helper.mHelperPrev != nullptr) {
      helper.mHelperNext->mPrev = helper.mHelperPrev;
      helper.mHelperPrev->mNext = helper.mHelperNext;
    }

    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperPrev = self;
    helper.mHelperNext = self;
    return self;
  }

  void CleanupUnitConstructAtexit()
  {
    (void)moho::cleanup_UnitConstruct();
  }

  void CleanupUnitSerializerAtexit()
  {
    (void)moho::cleanup_UnitSerializer();
  }
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
   * What it does:
   * Binds construct/delete callbacks into reflected RTTI for `Unit`.
   */
  void UnitConstruct::RegisterConstructFunction()
  {
    gpg::RType* const type = ResolveCachedType<Unit>(gUnitType);
    GPG_ASSERT(type != nullptr);
    GPG_ASSERT(type->serConstructFunc_ == nullptr || type->serConstructFunc_ == mConstructCallback);
    GPG_ASSERT(type->deleteFunc_ == nullptr || type->deleteFunc_ == mDeconstructCallback);
    type->serConstructFunc_ = mConstructCallback;
    type->deleteFunc_ = mDeconstructCallback;
  }

  /**
   * What it does:
   * Binds load/save callbacks into reflected RTTI for `Unit`.
   */
  void UnitSerializer::RegisterSerializeFunctions()
  {
    gpg::RType* const type = ResolveCachedType<Unit>(gUnitType);
    GPG_ASSERT(type != nullptr);
    GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mDeserialize);
    GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSerialize);
    type->serLoadFunc_ = mDeserialize;
    type->serSaveFunc_ = mSerialize;
  }

  /**
   * Address: 0x00BFDA00 (FUN_00BFDA00, cleanup_UnitConstruct)
   *
   * What it does:
   * Unlinks `UnitConstruct` helper links and rewires self-links.
   */
  gpg::SerHelperBase* cleanup_UnitConstruct()
  {
    return UnlinkHelperNode(gUnitConstruct);
  }

  /**
   * Address: 0x00BFDA30 (FUN_00BFDA30, cleanup_UnitSerializer)
   *
   * What it does:
   * Unlinks `UnitSerializer` helper links and rewires self-links.
   */
  gpg::SerHelperBase* cleanup_UnitSerializer()
  {
    return UnlinkHelperNode(gUnitSerializer);
  }

  /**
   * Address: 0x00BD6B20 (FUN_00BD6B20, register_UnitConstruct)
   *
   * What it does:
   * Initializes and registers `UnitConstruct` startup helper.
   */
  void register_UnitConstruct()
  {
    InitializeHelperNode(gUnitConstruct);
    gUnitConstruct.mConstructCallback = reinterpret_cast<gpg::RType::construct_func_t>(&UnitConstruct::Construct);
    gUnitConstruct.mDeconstructCallback = &UnitConstruct::Deconstruct;
    gUnitConstruct.RegisterConstructFunction();
    (void)std::atexit(&CleanupUnitConstructAtexit);
  }

  /**
   * Address: 0x00BD6B60 (FUN_00BD6B60, register_UnitSerializer)
   *
   * What it does:
   * Initializes and registers `UnitSerializer` startup helper.
   */
  void register_UnitSerializer()
  {
    InitializeHelperNode(gUnitSerializer);
    gUnitSerializer.mDeserialize = reinterpret_cast<gpg::RType::load_func_t>(&UnitSerializer::Deserialize);
    gUnitSerializer.mSerialize = reinterpret_cast<gpg::RType::save_func_t>(&UnitSerializer::Serialize);
    gUnitSerializer.RegisterSerializeFunctions();
    (void)std::atexit(&CleanupUnitSerializerAtexit);
  }
} // namespace moho

namespace
{
  struct UnitSerHelpersBootstrap
  {
    UnitSerHelpersBootstrap()
    {
      moho::register_UnitConstruct();
      moho::register_UnitSerializer();
    }
  };

  UnitSerHelpersBootstrap gUnitSerHelpersBootstrap;
} // namespace
