#pragma once

#include "gpg/core/containers/FastVector.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/sim/SOCellPos.h"

namespace gpg
{
  template <class T>
  class RFastVectorType;

  /**
   * VFTABLE: 0x00E17AC8
   * VFTABLE (RIndexed subobject): 0x00E17AF8
   *
   * What it is:
   * Reflection/indexing adapter for `gpg::fastvector<Moho::SOCellPos>`.
   * Unlike the `EntId` sibling, `moho::SOCellPos` is a real recovered
   * struct (moho/sim/SOCellPos.h) with its own `static gpg::RType* sType`
   * cache slot, so this adapter's GetName/SerLoad/SerSave read/write that
   * member directly -- exactly matching `Moho::SOCellPos::sType` in the
   * disassembly, no name-keyed workaround needed.
   */
  template <>
  class RFastVectorType<moho::SOCellPos> final : public gpg::RType, public gpg::RIndexed
  {
  public:
    /**
     * Address: 0x00553FC0 (FUN_00553FC0, gpg::RFastVectorType_SOCellPos::RFastVectorType_SOCellPos)
     *
     * What it does:
     * Constructs and preregisters the reflection descriptor for
     * `gpg::fastvector<Moho::SOCellPos>`.
     */
    RFastVectorType();

    /**
     * Address: 0x00554150 (FUN_00554150, gpg::RFastVectorType_SOCellPos::dtr)
     * Slot: 2
     */
    ~RFastVectorType() override;

    /**
     * Address: 0x00553050 (FUN_00553050, gpg::RFastVectorType_SOCellPos::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00553110 (FUN_00553110, gpg::RFastVectorType_SOCellPos::GetLexical)
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;

    /**
     * Address: 0x005531A0 (FUN_005531A0, gpg::RFastVectorType_SOCellPos::IsIndexed)
     */
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;

    /**
     * Address: 0x005530F0 (FUN_005530F0, gpg::RFastVectorType_SOCellPos::Init)
     */
    void Init() override;

    /**
     * Address: 0x005531F0 (FUN_005531F0, gpg::RFastVectorType_SOCellPos::SubscriptIndex)
     */
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;

    /**
     * Address: 0x005531B0 (FUN_005531B0, gpg::RFastVectorType_SOCellPos::GetCount)
     */
    size_t GetCount(void* obj) const override;

    /**
     * Address: 0x005531C0 (FUN_005531C0, gpg::RFastVectorType_SOCellPos::SetCount)
     */
    void SetCount(void* obj, int count) const override;
  };

  static_assert(sizeof(RFastVectorType<moho::SOCellPos>) == 0x68, "RFastVectorType<Moho::SOCellPos> size must be 0x68");

  /**
   * Address: 0x00BC9D60 (FUN_00BC9D60, register_RFastVectorType_SOCellPos)
   *
   * What it does:
   * Materializes startup reflection storage for `fastvector<Moho::SOCellPos>`
   * and registers process-exit teardown.
   */
  void register_RFastVectorType_SOCellPos();
} // namespace gpg
