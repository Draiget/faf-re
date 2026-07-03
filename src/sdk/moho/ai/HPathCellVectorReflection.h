#pragma once

#include "gpg/core/reflection/Reflection.h"
#include "legacy/containers/Vector.h"
#include "moho/ai/CAiPathFinder.h"

namespace gpg
{
  template <class T>
  class RVectorType;

  /**
   * Address family:
   * - 0x00763EE0 (register_00) / 0x00BDC6D0 (register + atexit)
   * - 0x00C018F0 (type teardown) / 0x00C01800 (name teardown)
   * - 0x007633E0 (GetName) / 0x00763480 (Init) / 0x007634A0 (GetLexical)
   * - 0x00763530 (IsIndexed) / 0x00763540 (GetCount) / 0x00763560 (SetCount)
   * - 0x00763580 (SubscriptIndex) / 0x00763760 (load) / 0x00763850 (save)
   * - 0x00763AC0 (resize) / 0x00764010 (scalar-deleting dtor)
   *
   * What it is:
   * Reflection/indexing adapter for `msvc8::vector<moho::HPathCell>` — the
   * value-element sibling of `RVectorType<moho::SimArmy*>`. `HPathCell` is a
   * 4-byte packed path-grid cell, so the element (de)serialize lanes read/write
   * cell *values* through `moho::HPathCell::sType`.
   */
  template <>
  class RVectorType<moho::HPathCell> final : public gpg::RType, public gpg::RIndexed
  {
  public:
    /**
     * Address: 0x007633E0 (FUN_007633E0, gpg::RVectorType_HPathCell::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x007634A0 (FUN_007634A0, gpg::RVectorType_HPathCell::GetLexical)
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;

    /**
     * Address: 0x00763530 (FUN_00763530, gpg::RVectorType_HPathCell::IsIndexed)
     */
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;

    /**
     * Address: 0x00763480 (FUN_00763480, gpg::RVectorType_HPathCell::Init)
     */
    void Init() override;

    /**
     * Address: 0x00763580 (FUN_00763580, gpg::RVectorType_HPathCell::SubscriptIndex)
     */
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;

    /**
     * Address: 0x00763540 (FUN_00763540, gpg::RVectorType_HPathCell::GetCount)
     */
    size_t GetCount(void* obj) const override;

    /**
     * Address: 0x00763560 (FUN_00763560, gpg::RVectorType_HPathCell::SetCount)
     */
    void SetCount(void* obj, int count) const override;
  };

  static_assert(sizeof(RVectorType<moho::HPathCell>) == 0x68, "RVectorType<HPathCell> size must be 0x68");
  static_assert(sizeof(msvc8::vector<moho::HPathCell>) == 0x10, "msvc8::vector<HPathCell> size must be 0x10");
} // namespace gpg

namespace moho
{
  /**
   * Address: 0x00763EE0 (FUN_00763EE0, sub_763EE0)
   *
   * What it does:
   * Constructs/preregisters the startup-owned reflection descriptor for
   * `std::vector<moho::HPathCell>` under `typeid(std::vector<HPathCell>)`.
   */
  [[nodiscard]] gpg::RType* register_HPathCellVectorType_00();

  /**
   * Address: 0x00BDC6D0 (FUN_00BDC6D0, sub_BDC6D0)
   *
   * What it does:
   * Registers `vector<HPathCell>` reflection and installs process-exit teardown
   * via `atexit`.
   */
  int register_HPathCellVectorType_AtExit();
} // namespace moho
