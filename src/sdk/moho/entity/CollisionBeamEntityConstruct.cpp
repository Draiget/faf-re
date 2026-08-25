#include "moho/entity/CollisionBeamEntityConstruct.h"

#include <cstdint>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "moho/entity/CollisionBeamEntity.h"

namespace
{
  template <typename TObject>
  [[nodiscard]] gpg::RType* ResolveCachedType(gpg::RType*& slot)
  {
    if (!slot) {
      slot = gpg::LookupRType(typeid(TObject));
    }
    return slot;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00675590 (FUN_00675590, construct callback adapter)
   *
   * What it does:
   * Adapts construct-callback calling convention lanes into
   * `CollisionBeamEntity::MemberConstruct`.
   */
  void ForwardCollisionBeamEntityMemberConstruct(
    gpg::ReadArchive& archive,
    const int version,
    const gpg::RRef& ownerRef,
    gpg::SerConstructResult& result
  )
  {
    CollisionBeamEntity::MemberConstruct(archive, version, ownerRef, result);
  }

  /**
   * Address: 0x00673A30 (FUN_00673A30, Moho::CollisionBeamEntityConstruct::Construct)
   */
  void CollisionBeamEntityConstruct::Construct(
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
    ForwardCollisionBeamEntityMemberConstruct(*archive, version, ownerRef, *result);
  }

  /**
   * Address: 0x00675570 (FUN_00675570, Moho::CollisionBeamEntityConstruct::Deconstruct)
   */
  void CollisionBeamEntityConstruct::Deconstruct(void* const objectPtr)
  {
    delete static_cast<CollisionBeamEntity*>(objectPtr);
  }

  /**
   * Address: 0x00BD4C90 (FUN_00BD4C90, dynamic initializer for the global
   * `CollisionBeamEntityConstruct` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * construct/delete callback fields.
   */
  CollisionBeamEntityConstruct::CollisionBeamEntityConstruct()
    : mConstructCallback(reinterpret_cast<gpg::RType::construct_func_t>(&CollisionBeamEntityConstruct::Construct))
    , mDeleteCallback(&CollisionBeamEntityConstruct::Deconstruct)
  {}

  CollisionBeamEntityConstruct::~CollisionBeamEntityConstruct()
  {
    ResetLinks();
  }

  /**
   * Address: 0x00674F60 (FUN_00674F60, gpg::SerConstructHelper_CollisionBeamEntity::Init)
   *
   * What it does:
   * Resolves `CollisionBeamEntity` RTTI (caching into its own `sType`
   * static, matching the binary) and installs construct/delete callback
   * lanes. Raw asm at 0x00674F60 asserts only `serConstructFunc_ ==
   * nullptr` before overwriting both fields unconditionally -- it does not
   * also assert on `deleteFunc_` the way the sibling Serializer::Init
   * (0x00674FE0) asserts both of its callback lanes.
   */
  void CollisionBeamEntityConstruct::Init()
  {
    gpg::RType* const type = ResolveCachedType<CollisionBeamEntity>(CollisionBeamEntity::sType);
    GPG_ASSERT(type->serConstructFunc_ == nullptr);
    type->serConstructFunc_ = mConstructCallback;
    type->deleteFunc_ = mDeleteCallback;
  }
} // namespace moho

namespace
{
  moho::CollisionBeamEntityConstruct gCollisionBeamEntityConstruct{};
} // namespace
