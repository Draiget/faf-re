#pragma once

#include "gpg/core/containers/FastVector.h"
#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  template <class T>
  class RFastVectorType;

  /**
   * VFTABLE: 0x00DFFEE0
   * COL: 0x00E5C5C8
   *
   * What it is:
   * Reflection/indexing adapter for `gpg::fastvector<unsigned int>`.
   */
  template <>
  class RFastVectorType<unsigned int> final : public gpg::RType, public gpg::RIndexed
  {
  public:
    /**
     * Address: 0x00402E30 (FUN_00402E30, gpg::RFastVectorType_uint::RFastVectorType_uint)
     *
     * What it does:
     * Constructs and preregisters the reflection descriptor for
     * `gpg::fastvector<unsigned int>`.
     */
    RFastVectorType();

    /**
     * Address: 0x00402EA0 (FUN_00402EA0, gpg::RFastVectorType_uint::dtr)
     * Slot: 2
     */
    ~RFastVectorType() override;

    /**
     * Address: 0x00402420 (FUN_00402420, gpg::RFastVectorType_uint::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x004024E0 (FUN_004024E0)
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;

    /**
     * Address: 0x00402570 (FUN_00402570)
     */
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;

    /**
     * Address: 0x004024C0 (FUN_004024C0)
     */
    void Init() override;

    /**
     * Address: 0x004025B0 (FUN_004025B0)
     */
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;

    /**
     * Address: 0x00402580 (FUN_00402580)
     */
    size_t GetCount(void* obj) const override;

    /**
     * Address: 0x00402590 (FUN_00402590)
     */
    void SetCount(void* obj, int count) const override;
  };

  static_assert(sizeof(RFastVectorType<unsigned int>) == 0x68, "RFastVectorType<unsigned int> size must be 0x68");

  [[nodiscard]] RType* ResolveFastVectorUIntType();
} // namespace gpg
