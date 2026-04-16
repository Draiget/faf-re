#pragma once

#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/BoostWrappers.h"

namespace moho
{
  class CAniPose;
}

namespace gpg
{
  template <class T>
  class RSharedPointerType;

  /**
   * What it is:
   * Reflection helper specialization for `boost::shared_ptr<moho::CAniPose>`.
   */
  template <>
  class RSharedPointerType<moho::CAniPose> final : public gpg::RType, public gpg::RIndexed
  {
  public:
    /**
     * Address: 0x0055CE20 (FUN_0055CE20, gpg::RSharedPointerType_CAniPose::GetName)
     *
     * What it does:
     * Builds/caches lexical type name `"boost::shared_ptr<%s>"` from CAniPose RTTI.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0055CED0 (FUN_0055CED0, gpg::RSharedPointerType_CAniPose::GetLexical)
     *
     * What it does:
     * Returns `"NULL"` for empty shared pointers, otherwise wraps pointee lexical with brackets.
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;

    /**
     * Address: 0x0055D050 (FUN_0055D050, gpg::RSharedPointerType_CAniPose::IsIndexed)
     */
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;

    /**
     * Address: 0x0055D060 (FUN_0055D060, gpg::RSharedPointerType_CAniPose::IsPointer)
     */
    [[nodiscard]] const gpg::RIndexed* IsPointer() const override;

    /**
     * Address: 0x0055CEC0 (FUN_0055CEC0, gpg::RSharedPointerType_CAniPose::Init)
     *
     * What it does:
     * Registers one shared-pointer payload size lane (`sizeof(boost::SharedPtrRaw<CAniPose>)`).
     */
    void Init() override;

    /**
     * Address: 0x0055D080 (FUN_0055D080, gpg::RSharedPointerType_CAniPose::SubscriptIndex)
     *
     * What it does:
     * Returns element 0 as `RRef<CAniPose>` (asserts on any other index).
     */
    [[nodiscard]] gpg::RRef SubscriptIndex(void* obj, int ind) const override;

    /**
     * Address: 0x0055D070 (FUN_0055D070, gpg::RSharedPointerType_CAniPose::GetCount)
     *
     * What it does:
     * Returns 1 when shared pointer has a non-null pointee, otherwise 0.
     */
    [[nodiscard]] size_t GetCount(void* obj) const override;
  };

  using RSharedPointerType_CAniPose = RSharedPointerType<moho::CAniPose>;

  static_assert(
    sizeof(RSharedPointerType<moho::CAniPose>) == 0x68,
    "RSharedPointerType<moho::CAniPose> size must be 0x68"
  );

  /**
   * Address: 0x0055EA20 (FUN_0055EA20, preregister_SharedPtrCAniPoseTypeStartup)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for
   * `boost::shared_ptr<moho::CAniPose>`.
   */
  [[nodiscard]] gpg::RType* preregister_SharedPtrCAniPoseTypeStartup();
} // namespace gpg
