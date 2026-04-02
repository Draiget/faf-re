#pragma once

#include "gpg/core/reflection/Reflection.h"
#include "legacy/containers/Vector.h"
#include "moho/sim/ArmyUnitSet.h"

namespace gpg
{
  template <class T>
  class RVectorType;

  /**
   * Address family:
   * - 0x00704B90 / 0x00BFF470 / 0x00BD9C60
   *
   * What it is:
   * Reflection/indexing adapter for `msvc8::vector<moho::SEntitySetTemplateUnit>`.
   */
  template <>
  class RVectorType<moho::SEntitySetTemplateUnit> final : public gpg::RType, public gpg::RIndexed
  {
  public:
    [[nodiscard]] const char* GetName() const override;
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;
    void Init() override;

    gpg::RRef SubscriptIndex(void* obj, int ind) const override;
    size_t GetCount(void* obj) const override;
    void SetCount(void* obj, int count) const override;
  };

  static_assert(
    sizeof(RVectorType<moho::SEntitySetTemplateUnit>) == 0x68,
    "RVectorType<SEntitySetTemplateUnit> size must be 0x68"
  );

  gpg::RRef* RRef_SEntitySetTemplateUnit(gpg::RRef* outRef, moho::SEntitySetTemplateUnit* value);

  [[nodiscard]] gpg::RType* ResolveEntitySetTemplateUnitVectorType();
} // namespace gpg

namespace moho
{
  /**
   * Address: 0x00704B90 (FUN_00704B90, sub_704B90)
   *
   * What it does:
   * Constructs/preregisters RTTI for `vector<EntitySetTemplate<Unit>>`.
   */
  [[nodiscard]] gpg::RType* register_EntitySetTemplateUnitVectorType();

  /**
   * Address: 0x00BD9C60 (FUN_00BD9C60, sub_BD9C60)
   *
   * What it does:
   * Registers `vector<EntitySetTemplate<Unit>>` reflection and installs
   * process-exit teardown via `atexit`.
   */
  int register_EntitySetTemplateUnitVectorType_AtExit();
} // namespace moho
