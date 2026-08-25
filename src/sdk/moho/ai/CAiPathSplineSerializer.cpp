#include "moho/ai/CAiPathSplineSerializer.h"

#include <cstdint>

#include "moho/ai/CAiPathSpline.h"

using namespace moho;

namespace
{
  /**
   * Address: 0x005B56F0 (FUN_005B56F0, j_Moho::CAiPathSpline::MemberDeserialize)
   *
   * What it does:
   * Thin forwarding thunk to `CAiPathSpline::MemberDeserialize`.
   */
  [[maybe_unused]] void CAiPathSplineMemberDeserializeThunk(
    moho::CAiPathSpline* const pathSpline, gpg::ReadArchive* const archive
  )
  {
    if (!pathSpline || !archive) {
      return;
    }

    pathSpline->MemberDeserialize(archive);
  }

  /**
   * Address: 0x005B5700 (FUN_005B5700, j_Moho::CAiPathSpline::MemberSerialize)
   *
   * What it does:
   * Thin forwarding thunk to `CAiPathSpline::MemberSerialize`.
   */
  [[maybe_unused]] void CAiPathSplineMemberSerializeThunk(
    moho::CAiPathSpline* const pathSpline, gpg::WriteArchive* const archive
  )
  {
    if (!pathSpline || !archive) {
      return;
    }

    pathSpline->MemberSerialize(archive);
  }

  /**
   * Address: 0x005B5A70 (FUN_005B5A70, j_Moho::CAiPathSpline::MemberDeserialize_0)
   *
   * What it does:
   * Secondary forwarding thunk to `CAiPathSpline::MemberDeserialize`.
   */
  [[maybe_unused]] void CAiPathSplineMemberDeserializeThunkSecondary(
    moho::CAiPathSpline* const pathSpline, gpg::ReadArchive* const archive
  )
  {
    if (!pathSpline || !archive) {
      return;
    }

    pathSpline->MemberDeserialize(archive);
  }

  /**
   * Address: 0x005B5A80 (FUN_005B5A80, j_Moho::CAiPathSpline::MemberSerialize_0)
   *
   * What it does:
   * Secondary forwarding thunk to `CAiPathSpline::MemberSerialize`.
   */
  [[maybe_unused]] void CAiPathSplineMemberSerializeThunkSecondary(
    moho::CAiPathSpline* const pathSpline, gpg::WriteArchive* const archive
  )
  {
    if (!pathSpline || !archive) {
      return;
    }

    pathSpline->MemberSerialize(archive);
  }

  [[nodiscard]] gpg::RType* CachedCAiPathSplineType()
  {
    gpg::RType* type = CAiPathSpline::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(CAiPathSpline));
      CAiPathSpline::sType = type;
    }
    return type;
  }

  // Address: 0x010AF098 -- process-global `CAiPathSplineSerializer`
  // singleton. Constructing it runs CAiPathSplineSerializer::
  // CAiPathSplineSerializer() (0x00BCD350), which splices this helper into
  // gpg::SerHelperBase::sNewHelpers; gpg::SerHelperBase::InitNewHelpers()
  // later dispatches Init() on it from within the first ReadArchive/
  // WriteArchive construction. Its destructor (~CAiPathSplineSerializer,
  // 0x00BF7540) runs at normal static-duration teardown, matching the real
  // binary's atexit registration.
  moho::CAiPathSplineSerializer gCAiPathSplineSerializer;
} // namespace

/**
 * Address: 0x005B24A0 (FUN_005B24A0, Moho::CAiPathSplineSerializer::Deserialize)
 */
void CAiPathSplineSerializer::Deserialize(
  gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef* const ownerRef
)
{
  auto* const pathSpline = reinterpret_cast<CAiPathSpline*>(static_cast<std::uintptr_t>(objectPtr));
  if (!archive || !pathSpline) {
    return;
  }

  if (ownerRef != nullptr) {
    pathSpline->MemberDeserialize(archive);
    return;
  }

  CAiPathSplineMemberDeserializeThunk(pathSpline, archive);
}

/**
 * Address: 0x005B24B0 (FUN_005B24B0, Moho::CAiPathSplineSerializer::Serialize)
 */
void CAiPathSplineSerializer::Serialize(
  gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef* const ownerRef
)
{
  auto* const pathSpline = reinterpret_cast<CAiPathSpline*>(static_cast<std::uintptr_t>(objectPtr));
  if (!archive || !pathSpline) {
    return;
  }

  if (ownerRef != nullptr) {
    pathSpline->MemberSerialize(archive);
    return;
  }

  CAiPathSplineMemberSerializeThunk(pathSpline, archive);
}

/**
 * Address: 0x00BCD350 (FUN_00BCD350, dynamic initializer for the global
 * `CAiPathSplineSerializer` singleton)
 *
 * What it does:
 * Default-constructs the `gpg::SerHelperBase` base (self-links and splices
 * into `sNewHelpers`) and binds the load/save callback fields.
 */
CAiPathSplineSerializer::CAiPathSplineSerializer()
  : mLoadCallback(&CAiPathSplineSerializer::Deserialize)
  , mSaveCallback(&CAiPathSplineSerializer::Serialize)
{}

/**
 * Address: 0x00BF7540 (FUN_00BF7540, Moho::CAiPathSplineSerializer::~CAiPathSplineSerializer)
 *
 * What it does:
 * Unlinks this helper node from whatever intrusive list it currently sits
 * in and restores a self-linked sentinel state.
 */
CAiPathSplineSerializer::~CAiPathSplineSerializer()
{
  ResetLinks();
}

/**
 * Address: 0x005B48E0 (FUN_005B48E0)
 */
void CAiPathSplineSerializer::Init()
{
  gpg::RType* const type = CachedCAiPathSplineType();

  GPG_ASSERT(type->serLoadFunc_ == nullptr || type->serLoadFunc_ == mLoadCallback);
  type->serLoadFunc_ = mLoadCallback;
  GPG_ASSERT(type->serSaveFunc_ == nullptr || type->serSaveFunc_ == mSaveCallback);
  type->serSaveFunc_ = mSaveCallback;
}
