#pragma once

#include "gpg/core/reflection/Reflection.h"
#include "legacy/containers/Vector.h"
#include "moho/serialization/SBlackListInfo.h"

namespace gpg
{
  template <class T>
  class RVectorType;

  /**
   * Address family:
   * - 0x006DDF70 / 0x00BFE860 / 0x00BD8BB0
   * - 0x006DB5D0 / 0x006DB670 / 0x006DB690 / 0x006DB720
   * - 0x006DB730 / 0x006DB760 / 0x006DB790
   *
   * What it is:
   * Reflection/indexing adapter for `msvc8::vector<moho::SBlackListInfo>`.
   */
  template <>
  class RVectorType<moho::SBlackListInfo> final : public gpg::RType, public gpg::RIndexed
  {
  public:
    /**
     * Address: 0x006DB5D0 (FUN_006DB5D0, gpg::RVectorType_SBlackListInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x006DB690 (FUN_006DB690, gpg::RVectorType_SBlackListInfo::GetLexical)
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;

    /**
     * Address: 0x006DB720 (FUN_006DB720, gpg::RVectorType_SBlackListInfo::IsIndexed)
     */
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;

    /**
     * Address: 0x006DB670 (FUN_006DB670, gpg::RVectorType_SBlackListInfo::Init)
     */
    void Init() override;

    /**
     * Address: 0x006DB790 (FUN_006DB790, gpg::RVectorType_SBlackListInfo::SubscriptIndex)
     */
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;

    /**
     * Address: 0x006DB730 (FUN_006DB730, gpg::RVectorType_SBlackListInfo::GetCount)
     */
    size_t GetCount(void* obj) const override;

    /**
     * Address: 0x006DB760 (FUN_006DB760, gpg::RVectorType_SBlackListInfo::SetCount)
     */
    void SetCount(void* obj, int count) const override;
  };

  static_assert(sizeof(RVectorType<moho::SBlackListInfo>) == 0x68, "RVectorType<SBlackListInfo> size must be 0x68");
  static_assert(sizeof(msvc8::vector<moho::SBlackListInfo>) == 0x10, "msvc8::vector<SBlackListInfo> size must be 0x10");

  /**
   * Address: 0x006DE830 (FUN_006DE830, gpg::RRef_SBlackListInfo)
   *
   * What it does:
   * Creates a typed `RRef` lane for one `SBlackListInfo` object pointer.
   */
  gpg::RRef* RRef_SBlackListInfo(gpg::RRef* outRef, moho::SBlackListInfo* value);

  /**
   * Address: 0x006DDA30 (FUN_006DDA30)
   *
   * What it does:
   * Packs one `RRef_SBlackListInfo` lane into caller-owned output storage.
   */
  gpg::RRef* PackRRef_SBlackListInfo(gpg::RRef* outRef, moho::SBlackListInfo* value);
} // namespace gpg

namespace moho
{
  /**
   * Address: 0x006DDF70 (FUN_006DDF70, sub_6DDF70)
   *
   * What it does:
   * Constructs/preregisters RTTI for `vector<SBlackListInfo>`.
   */
  [[nodiscard]] gpg::RType* register_SBlackListInfoVectorType_00();

  /**
   * Address: 0x00BD8BB0 (FUN_00BD8BB0, sub_BD8BB0)
   *
   * What it does:
   * Registers `vector<SBlackListInfo>` reflection and installs process-exit
   * teardown via `atexit`.
   */
  int register_SBlackListInfoVectorType_AtExit();
} // namespace moho
