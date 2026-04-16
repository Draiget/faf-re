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
   */
  class SDelayedSubVizInfoSerializer
  {
  public:
    /**
     * Address: 0x00507CC0 (FUN_00507CC0, gpg::SerSaveLoadHelper<Moho::SDelayedSubVizInfo>::Init)
     *
     * What it does:
     * Binds serializer load/save callbacks into `SDelayedSubVizInfo` RTTI.
     */
    virtual void RegisterSerializeFunctions();

    /**
     * Address: 0x00507010 (FUN_00507010, Moho::SDelayedSubVizInfoSerializer::Deserialize)
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectStorage, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00507020 (FUN_00507020, Moho::SDelayedSubVizInfoSerializer::Serialize)
     */
    static void Serialize(gpg::WriteArchive* archive, int objectStorage, int version, gpg::RRef* ownerRef);

  public:
    gpg::SerHelperBase* mHelperNext;     // +0x04
    gpg::SerHelperBase* mHelperPrev;     // +0x08
    gpg::RType::load_func_t mDeserialize; // +0x0C
    gpg::RType::save_func_t mSerialize;   // +0x10
  };

  static_assert(offsetof(SDelayedSubVizInfoSerializer, mHelperNext) == 0x04, "SDelayedSubVizInfoSerializer::mHelperNext offset must be 0x04");
  static_assert(offsetof(SDelayedSubVizInfoSerializer, mHelperPrev) == 0x08, "SDelayedSubVizInfoSerializer::mHelperPrev offset must be 0x08");
  static_assert(offsetof(SDelayedSubVizInfoSerializer, mDeserialize) == 0x0C, "SDelayedSubVizInfoSerializer::mDeserialize offset must be 0x0C");
  static_assert(offsetof(SDelayedSubVizInfoSerializer, mSerialize) == 0x10, "SDelayedSubVizInfoSerializer::mSerialize offset must be 0x10");
  static_assert(sizeof(SDelayedSubVizInfoSerializer) == 0x14, "SDelayedSubVizInfoSerializer size must be 0x14");

  /**
   * Address: 0x00507040 (FUN_00507040, init_SDelayedSubVizInfoSerializer)
   *
   * What it does:
   * Initializes global delayed-sub-viz serializer helper lanes.
   */
  SDelayedSubVizInfoSerializer* initialize_SDelayedSubVizInfoSerializer();

  /**
   * Address: 0x00507070 (FUN_00507070, cleanup_SDelayedSubVizInfoSerializer)
   *
   * What it does:
   * Unlinks serializer helper node from intrusive list and self-links it.
   */
  gpg::SerHelperBase* cleanup_SDelayedSubVizInfoSerializerVariant1();

  /**
   * Address: 0x005070A0 (FUN_005070A0, cleanup_SDelayedSubVizInfoSerializer duplicate lane)
   *
   * What it does:
   * Duplicate cleanup lane with same list-unlink semantics as `FUN_00507070`.
   */
  gpg::SerHelperBase* cleanup_SDelayedSubVizInfoSerializerVariant2();

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
