#pragma once

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  struct ResourceDeposit;
}

namespace gpg
{
  /**
   * VFTABLE: 0x00E1713C
   * COL: 0x00E6B614
   */
  class RVectorType_ResourceDeposit final : public RType, public RIndexed
  {
  public:
    /**
     * Address: 0x005474C0 (FUN_005474C0, gpg::RVectorType_ResourceDeposit::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00547580 (FUN_00547580, gpg::RVectorType_ResourceDeposit::GetLexical)
     */
    [[nodiscard]] msvc8::string GetLexical(const RRef& ref) const override;

    /**
     * Address: 0x00547610 (FUN_00547610, gpg::RVectorType_ResourceDeposit::IsIndexed)
     */
    [[nodiscard]] const RIndexed* IsIndexed() const override;

    /**
     * Address: 0x00547560 (FUN_00547560, gpg::RVectorType_ResourceDeposit::Init)
     */
    void Init() override;

    /**
     * Address: 0x00547950 (FUN_00547950, gpg::RVectorType_ResourceDeposit::SerLoad)
     */
    static void SerLoad(ReadArchive* archive, int objectPtr, int version, RRef* ownerRef);

    /**
     * Address: 0x00547A50 (FUN_00547A50, gpg::RVectorType_ResourceDeposit::SerSave)
     */
    static void SerSave(WriteArchive* archive, int objectPtr, int version, RRef* ownerRef);

    /**
     * Address: 0x00547690 (FUN_00547690, gpg::RVectorType_ResourceDeposit::SubscriptIndex)
     */
    [[nodiscard]] RRef SubscriptIndex(void* obj, int ind) const override;

    /**
     * Address: 0x00547620 (FUN_00547620, gpg::RVectorType_ResourceDeposit::GetCount)
     */
    [[nodiscard]] size_t GetCount(void* obj) const override;

    /**
     * Address: 0x00547650 (FUN_00547650, gpg::RVectorType_ResourceDeposit::SetCount)
     */
    void SetCount(void* obj, int count) const override;
  };

  static_assert(sizeof(RVectorType_ResourceDeposit) == 0x68, "RVectorType_ResourceDeposit size must be 0x68");
} // namespace gpg

namespace moho
{
  /**
   * Address: 0x00548C70 (FUN_00548C70, preregister_VectorResourceDepositType)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for
   * `msvc8::vector<moho::ResourceDeposit>`.
   */
  [[nodiscard]] gpg::RType* preregister_VectorResourceDepositType();
  int register_VectorResourceDepositTypeAtexit();
} // namespace moho

