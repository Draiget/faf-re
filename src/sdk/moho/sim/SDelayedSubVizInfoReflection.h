#pragma once

#include "gpg/core/reflection/Reflection.h"
#include "legacy/containers/Vector.h"
#include "moho/sim/CIntelGrid.h"

namespace gpg
{
  template <class T>
  class RVectorType;

  /**
   * Address family:
   * - 0x00507AA0 / 0x00507B40 / 0x00507B60 / 0x00507BF0
   * - 0x00507C00 / 0x00507C30 / 0x00507C50
   * - 0x005080C0 / 0x005081B0
   *
   * What it is:
   * Reflection/indexing adapter for `msvc8::vector<moho::SDelayedSubVizInfo>`.
   */
  template <>
  class RVectorType<moho::SDelayedSubVizInfo> final : public gpg::RType, public gpg::RIndexed
  {
  public:
    /**
     * Address: 0x00507AA0 (FUN_00507AA0, gpg::RVectorType_SDelayedSubVizInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00507B60 (FUN_00507B60, gpg::RVectorType_SDelayedSubVizInfo::GetLexical)
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;

    /**
     * Address: 0x00507BF0 (FUN_00507BF0, gpg::RVectorType_SDelayedSubVizInfo::IsIndexed)
     */
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;

    /**
     * Address: 0x00507B40 (FUN_00507B40, gpg::RVectorType_SDelayedSubVizInfo::Init)
     */
    void Init() override;

    /**
     * Address: 0x00507C50 (FUN_00507C50, gpg::RVectorType_SDelayedSubVizInfo::SubscriptIndex)
     */
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;

    /**
     * Address: 0x00507C00 (FUN_00507C00, gpg::RVectorType_SDelayedSubVizInfo::GetCount)
     */
    size_t GetCount(void* obj) const override;

    /**
     * Address: 0x00507C30 (FUN_00507C30, gpg::RVectorType_SDelayedSubVizInfo::SetCount)
     */
    void SetCount(void* obj, int count) const override;
  };

  static_assert(sizeof(RVectorType<moho::SDelayedSubVizInfo>) == 0x68, "RVectorType<SDelayedSubVizInfo> size must be 0x68");
  static_assert(
    sizeof(msvc8::vector<moho::SDelayedSubVizInfo>) == 0x10,
    "msvc8::vector<SDelayedSubVizInfo> size must be 0x10"
  );

  /**
   * Address: 0x00509410 (FUN_00509410, gpg::RRef_SDelayedSubVizInfo)
   *
   * What it does:
   * Creates a typed `RRef` lane for one `SDelayedSubVizInfo` object pointer.
   */
  gpg::RRef* RRef_SDelayedSubVizInfo(gpg::RRef* outRef, moho::SDelayedSubVizInfo* value);
} // namespace gpg

namespace moho
{
  /**
   * VFTABLE: 0x00E0D774
   * COL: 0x00E67028
   *
   * Demangled: gpg::SerSaveLoadHelper<class Moho::SDelayedSubVizInfo>
   *
   * Per-instantiation addresses (one compiler-emitted body per `T`; see the
   * template's class-level comment in Reflection.h for the general shape):
   *  - ctor / compiler dynamic-initializer (`register_SDelayedSubVizInfoSerializer`):
   *    0x00BC78E0 (dead zero-xref COMDAT duplicate: 0x00507C90)
   *  - dtor: 0x00BF1D60 (`??1SDelayedSubVizInfoSerializer@Moho@@QAE@@Z`)
   *  - Init(): 0x00507CC0
   *  - Deserialize(): 0x00507010
   *  - Serialize(): 0x00507020
   */
  using SDelayedSubVizInfoSerializer = gpg::SerSaveLoadHelper<SDelayedSubVizInfo>;

  /**
   * Address: 0x00BC78E0 (FUN_00BC78E0, register_SDelayedSubVizInfoSerializer)
   *
   * What it does:
   * Forces this translation unit's global `SDelayedSubVizInfoSerializer`
   * instance to link into the reflection bootstrap sequence. The ctor/
   * vtable-install/atexit-dtor-registration sequence this address decompiles
   * to is MSVC's own compiler-generated dynamic initializer for that global,
   * not hand-written source -- see `gpg::SerSaveLoadHelper<T>` in
   * Reflection.h.
   */
  void register_SDelayedSubVizInfoSerializer();

  /**
   * Address: 0x00506ED0 (FUN_00506ED0, preregister_SDelayedSubVizInfoTypeInfo)
   *
   * What it does:
   * Constructs/preregisters reflection metadata for `SDelayedSubVizInfo`.
   */
  [[nodiscard]] gpg::RType* preregister_SDelayedSubVizInfoTypeInfo();

  [[nodiscard]] gpg::RType* register_SDelayedSubVizInfoVectorType();

  /**
   * Address: 0x00BC79F0 (FUN_00BC79F0, register_SDelayedSubVizInfoVectorType_AtExit)
   *
   * What it does:
   * Registers the delayed-sub-viz vector RTTI lane and installs process-exit
   * cleanup.
   */
  int register_SDelayedSubVizInfoVectorType_AtExit();
} // namespace moho
