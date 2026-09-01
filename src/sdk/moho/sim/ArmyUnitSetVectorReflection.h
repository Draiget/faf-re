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
    /**
     * Address: 0x00704C60 (FUN_00704C60, gpg::RVectorType<Moho::SEntitySetTemplateUnit>::dtr)
     *
     * What it does:
     * Tears down one `RVectorType<SEntitySetTemplateUnit>` descriptor and
     * releases inherited `gpg::RType` reflection storage lanes.
     */
    ~RVectorType() override;

    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00701740 (FUN_00701740, gpg::RVectorType<Moho::SEntitySetTemplateUnit>::GetLexical)
     *
     * What it does:
     * Appends the element count to the base `RType::GetLexical` text,
     * matching the binary's `"%s, size=%d"` formatting of the inherited
     * lexical form.
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;
    void Init() override;

    /**
     * Address: 0x00701850 (FUN_00701850, gpg::RVectorType<Moho::SEntitySetTemplateUnit>::SubscriptIndex)
     * VFTABLE: `??_7?$RVectorType@V?$EntitySetTemplate@VUnit@Moho@@@Moho@@@gpg@@6BRIndexed@gpg@@@`
     * (`gpg::RIndexed` sub-vtable), confirmed via data xref.
     *
     * What it does:
     * Builds one reflected reference for the `ind`-th element of the
     * `msvc8::vector<SEntitySetTemplateUnit>` storage at `obj`
     * (`&(*storage)[ind]`, matching the binary's own `base + 0x28*ind`
     * stride), via `gpg::RRef_EntitySetTemplate_Unit`.
     */
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;

    /**
     * Address: 0x007017E0 (FUN_007017E0, gpg::RVectorType<Moho::SEntitySetTemplateUnit>::GetCount)
     */
    size_t GetCount(void* obj) const override;

    /**
     * Address: 0x00701810 (FUN_00701810, gpg::RVectorType<Moho::SEntitySetTemplateUnit>::SetCount)
     * VFTABLE: `??_7?$RVectorType@V?$EntitySetTemplate@VUnit@Moho@@@Moho@@@gpg@@6BRIndexed@gpg@@@`
     * +0x8 (`gpg::RIndexed` sub-vtable), confirmed via data xref.
     */
    void SetCount(void* obj, int count) const override;
  };

  static_assert(
    sizeof(RVectorType<moho::SEntitySetTemplateUnit>) == 0x68,
    "RVectorType<SEntitySetTemplateUnit> size must be 0x68"
  );

  gpg::RRef* RRef_SEntitySetTemplateUnit(gpg::RRef* outRef, moho::SEntitySetTemplateUnit* value);

  /**
   * Address: 0x00705320 (FUN_00705320, gpg::RRef_EntitySetTemplate_Unit)
   *
   * What it does:
   * Builds one reflected, dynamically-typed reference for
   * `EntitySetTemplate<Unit>`, adjusting for multiple inheritance via
   * `IsDerivedFrom` when the dynamic type differs from the base. Called
   * per-element by `RVectorType<SEntitySetTemplateUnit>::SubscriptIndex`.
   */
  gpg::RRef* RRef_EntitySetTemplate_Unit(gpg::RRef* outRef, moho::SEntitySetTemplateUnit* value);

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
