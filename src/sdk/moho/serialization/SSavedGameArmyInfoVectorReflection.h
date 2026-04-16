#pragma once

#include "gpg/core/reflection/Reflection.h"
#include "legacy/containers/Vector.h"
#include "moho/serialization/SSavedGameArmyInfo.h"

namespace gpg
{
  /**
   * Address family:
   * - 0x00882100 / 0x008821C0 / 0x00882250 / 0x008821A0
   * - 0x00882260 / 0x00882290 / 0x008822C0
   * - 0x008826C0 / 0x008827F0
   *
   * What it is:
   * Reflection/indexing adapter for `msvc8::vector<moho::SSavedGameArmyInfo>`.
   */
  class RVectorType_SSavedGameArmyInfo final : public gpg::RType, public gpg::RIndexed
  {
  public:
    /**
     * Address: 0x00882100 (FUN_00882100)
     */
    const char* GetName() const override;

    /**
     * Address: 0x008821C0 (FUN_008821C0)
     */
    msvc8::string GetLexical(const gpg::RRef& ref) const override;

    /**
     * Address: 0x00882250 (FUN_00882250)
     */
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;

    /**
     * Address: 0x008821A0 (FUN_008821A0)
     */
    void Init() override;

    /**
     * Address: 0x008822C0 (FUN_008822C0)
     */
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;

    /**
     * Address: 0x00882260 (FUN_00882260)
     */
    size_t GetCount(void* obj) const override;

    /**
     * Address: 0x00882290 (FUN_00882290)
     */
    void SetCount(void* obj, int count) const override;
  };

  static_assert(sizeof(RVectorType_SSavedGameArmyInfo) == 0x68, "RVectorType_SSavedGameArmyInfo size must be 0x68");

  /**
   * Address: 0x00884040 (FUN_00884040)
   */
  RRef* RRef_SSavedGameArmyInfo(RRef* outRef, moho::SSavedGameArmyInfo* value);

  /**
   * Address: 0x00883960 (FUN_00883960, preregister_SSavedGameArmyInfoVectorTypeStartup)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for
   * `msvc8::vector<moho::SSavedGameArmyInfo>`.
   */
  [[nodiscard]] RType* preregister_SSavedGameArmyInfoVectorTypeStartup();

  /**
   * Lazily ensures preregistration and returns RTTI for
   * `msvc8::vector<moho::SSavedGameArmyInfo>`.
   */
  [[nodiscard]] RType* ResolveSavedGameArmyInfoVectorType();
} // namespace gpg
