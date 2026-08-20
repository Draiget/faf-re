#pragma once

#include "gpg/core/containers/FastVector.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/unit/core/IUnit.h"

namespace gpg
{
  template <class T>
  class RFastVectorType;

  /**
   * VFTABLE: 0x00E17A84
   * VFTABLE (RIndexed subobject): 0x00E17AB4
   *
   * What it is:
   * Reflection/indexing adapter for `gpg::fastvector<Moho::EntId>`.
   *
   * The binary keys this descriptor's RTTI registration on
   * `??_R0?AVEntId@Moho@@@8` -- a distinct *class* `Moho::EntId` type
   * descriptor, not `int`'s (see `moho::preregister_EntIdTypeInfo`,
   * SSTITarget.h/.cpp). Every element access this adapter performs, though,
   * treats storage as a flat array of 4-byte words -- the exact layout
   * `RFastVectorType<unsigned int>` uses. That is why the linker folds this
   * class's `SetCount` and `SerLoad` resize call into the very same compiled
   * body as `gpg::FastVectorUIntResize` (0x00553480 == 0x004022D0).
   */
  template <>
  class RFastVectorType<moho::EntId> final : public gpg::RType, public gpg::RIndexed
  {
  public:
    /**
     * Address: 0x00553F50 (FUN_00553F50, gpg::RFastVectorType_EntId::RFastVectorType_EntId)
     *
     * What it does:
     * Constructs and preregisters the reflection descriptor for
     * `gpg::fastvector<Moho::EntId>`.
     */
    RFastVectorType();

    /**
     * Address: 0x005540F0 (FUN_005540F0, gpg::RFastVectorType_EntId::dtr)
     * Slot: 2
     */
    ~RFastVectorType() override;

    /**
     * Address: 0x00552E70 (FUN_00552E70, gpg::RFastVectorType_EntId::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00552F30 (FUN_00552F30, gpg::RFastVectorType_EntId::GetLexical)
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;

    /**
     * Address: 0x00552FC0 (FUN_00552FC0, gpg::RFastVectorType_EntId::IsIndexed)
     */
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;

    /**
     * Address: 0x00552F10 (FUN_00552F10, gpg::RFastVectorType_EntId::Init)
     */
    void Init() override;

    /**
     * Address: 0x00553010 (FUN_00553010, gpg::RFastVectorType_EntId::SubscriptIndex)
     */
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;

    /**
     * Address: 0x00552FD0 (FUN_00552FD0, gpg::RFastVectorType_EntId::GetCount)
     */
    size_t GetCount(void* obj) const override;

    /**
     * Address: 0x00552FE0 (FUN_00552FE0, gpg::RFastVectorType_EntId::SetCount)
     */
    void SetCount(void* obj, int count) const override;
  };

  static_assert(sizeof(RFastVectorType<moho::EntId>) == 0x68, "RFastVectorType<Moho::EntId> size must be 0x68");

  /**
   * Address: 0x00BC9D40 (FUN_00BC9D40, register_RFastVectorType_EntId)
   *
   * What it does:
   * Materializes startup reflection storage for `fastvector<Moho::EntId>` and
   * registers process-exit teardown.
   */
  void register_RFastVectorType_EntId();
} // namespace gpg
