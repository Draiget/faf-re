#pragma once

#include "gpg/core/containers/FastVector.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/IFormationInstance.h"

namespace gpg
{
  template <class T>
  class RFastVectorType;

  /**
   * VFTABLE: 0x00E1B578
   * VFTABLE (RIndexed subobject): 0x00E1B5A8
   *
   * What it is:
   * Reflection/indexing adapter for `gpg::fastvector<Moho::IFormationInstance*>`.
   * Both vtable heads are confirmed constructed: `FUN_0059DED0` (this class's
   * constructor) writes `??_7?$RFastVectorType@PAVIFormationInstance@Moho@@@gpg@@6B@`
   * into the primary lane and
   * `??_7?$RFastVectorType@PAVIFormationInstance@Moho@@@gpg@@6BRIndexed@gpg@@@`
   * into the `RIndexed` subobject lane at offset 0x64 (`VTABLE_CONFIRMED`).
   */
  template <>
  class RFastVectorType<moho::IFormationInstance*> final : public gpg::RType, public gpg::RIndexed
  {
  public:
    /**
     * Address: 0x0059DED0 (FUN_0059DED0, gpg::RFastVectorType_IFormationInstance_P::RFastVectorType_IFormationInstance_P)
     *
     * What it does:
     * Constructs and preregisters the reflection descriptor for
     * `gpg::fastvector<Moho::IFormationInstance*>`.
     */
    RFastVectorType();

    /**
     * Address: 0x0059DFA0 (FUN_0059DFA0, gpg::RFastVectorType_IFormationInstance_P::dtr)
     */
    ~RFastVectorType() override;

    /**
     * Address: 0x0059C9A0 (FUN_0059C9A0, gpg::RFastVectorType_IFormationInstance_P::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x0059CA40 (FUN_0059CA40, gpg::RFastVectorType_IFormationInstance_P::GetLexical)
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;

    /**
     * Address: 0x0059CAD0 (FUN_0059CAD0, gpg::RFastVectorType_IFormationInstance_P::IsIndexed)
     */
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;

    /**
     * Address: 0x0059CA20 (FUN_0059CA20, gpg::RFastVectorType_IFormationInstance_P::Init)
     */
    void Init() override;

    /**
     * Address: 0x0059CB10 (FUN_0059CB10, gpg::RFastVectorType_IFormationInstance_P::SubscriptIndex)
     */
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;

    /**
     * Address: 0x0059CAE0 (FUN_0059CAE0, gpg::RFastVectorType_IFormationInstance_P::GetCount)
     */
    size_t GetCount(void* obj) const override;

    /**
     * Address: 0x0059CAF0 (FUN_0059CAF0, gpg::RFastVectorType_IFormationInstance_P::SetCount)
     */
    void SetCount(void* obj, int count) const override;
  };

  static_assert(
    sizeof(RFastVectorType<moho::IFormationInstance*>) == 0x68,
    "RFastVectorType<Moho::IFormationInstance*> size must be 0x68"
  );

  /**
   * Address: 0x00BCC210 (FUN_00BCC210, register_RFastVectorType_IFormationInstance)
   *
   * What it does:
   * Materializes startup reflection storage for `fastvector<Moho::IFormationInstance*>`
   * and registers process-exit teardown.
   */
  void register_RFastVectorType_IFormationInstance();
} // namespace gpg
