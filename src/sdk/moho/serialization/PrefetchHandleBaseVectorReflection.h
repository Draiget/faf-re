#pragma once

#include "gpg/core/reflection/Reflection.h"
#include "legacy/containers/Vector.h"
#include "moho/serialization/PrefetchHandleBase.h"

namespace gpg
{
  template <class T>
  class RVectorType;

  /**
   * VFTABLE: 0x00E072E0
   * COL: 0x00E61DE8
   *
   * What it is:
   * Reflection/indexing adapter for `msvc8::vector<moho::PrefetchHandleBase>`.
   */
  template <>
  class RVectorType<moho::PrefetchHandleBase> final : public gpg::RType, public gpg::RIndexed
  {
  public:
    /**
     * Address: 0x004A8330 (FUN_004A8330)
     */
    ~RVectorType() override;

    /**
     * Address: 0x004A5D10 (FUN_004A5D10, gpg::RVectorType_PrefetchHandleBase::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x004A5DD0 (FUN_004A5DD0)
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;

    /**
     * Address: 0x004A5E60 (FUN_004A5E60)
     */
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;

    /**
     * Address: 0x004A5DB0 (FUN_004A5DB0)
     */
    void Init() override;

    /**
     * Address: 0x004A5EC0 (FUN_004A5EC0)
     */
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;

    /**
     * Address: 0x004A5E70 (FUN_004A5E70)
     */
    size_t GetCount(void* obj) const override;

    /**
     * Address: 0x004A5E90 (FUN_004A5E90)
     */
    void SetCount(void* obj, int count) const override;
  };

  static_assert(
    sizeof(RVectorType<moho::PrefetchHandleBase>) == 0x68,
    "RVectorType<PrefetchHandleBase> size must be 0x68"
  );

  /**
   * Address: 0x004A8700 (FUN_004A8700, gpg::RRef_PrefetchHandleBase)
   */
  RRef* RRef_PrefetchHandleBase(RRef* outRef, moho::PrefetchHandleBase* value);

  [[nodiscard]] RType* ResolvePrefetchHandleBaseVectorType();
} // namespace gpg
