#pragma once

#include "gpg/core/reflection/Reflection.h"
#include "legacy/containers/Vector.h"
#include "moho/entity/EntityCategorySetTypeInfo.h"

namespace gpg
{
  template <class T>
  class RVectorType;

  /**
   * Address family:
   * - 0x006DDF00 / 0x00BFE8C0 / 0x00BD8B90
   * - 0x006DB280 / 0x006DB320 / 0x006DB340 / 0x006DB3D0 / 0x006DB3E0 /
   *   0x006DB410 / 0x006DB450
   *
   * What it is:
   * Reflection/indexing adapter for `msvc8::vector<moho::EntityCategorySet>`.
   */
  template <>
  class RVectorType<moho::EntityCategorySet> final : public gpg::RType, public gpg::RIndexed
  {
  public:
    /**
     * Address: 0x006DB280 (FUN_006DB280, gpg::RVectorType_BVSet_PRBlueprint::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x006DB340 (FUN_006DB340, gpg::RVectorType_BVSet_PRBlueprint::GetLexical)
     */
    [[nodiscard]] msvc8::string GetLexical(const gpg::RRef& ref) const override;

    /**
     * Address: 0x006DB3D0 (FUN_006DB3D0, gpg::RVectorType_BVSet_PRBlueprint::IsIndexed)
     */
    [[nodiscard]] const gpg::RIndexed* IsIndexed() const override;

    /**
     * Address: 0x006DB320 (FUN_006DB320, gpg::RVectorType_BVSet_PRBlueprint::Init)
     */
    void Init() override;

    /**
     * Address: 0x006DB450 (FUN_006DB450, gpg::RVectorType_BVSet_PRBlueprint::SubscriptIndex)
     */
    gpg::RRef SubscriptIndex(void* obj, int ind) const override;

    /**
     * Address: 0x006DB3E0 (FUN_006DB3E0, gpg::RVectorType_BVSet_PRBlueprint::GetCount)
     */
    size_t GetCount(void* obj) const override;

    /**
     * Address: 0x006DB410 (FUN_006DB410, gpg::RVectorType_BVSet_PRBlueprint::SetCount)
     */
    void SetCount(void* obj, int count) const override;
  };

  static_assert(
    sizeof(RVectorType<moho::EntityCategorySet>) == 0x68,
    "RVectorType<EntityCategorySet> size must be 0x68"
  );

  static_assert(
    sizeof(msvc8::vector<moho::EntityCategorySet>) == 0x10,
    "msvc8::vector<moho::EntityCategorySet> size must be 0x10"
  );
} // namespace gpg

namespace moho
{
  /**
   * Address: 0x006DDF00 (FUN_006DDF00, sub_6DDF00)
   *
   * What it does:
   * Constructs and preregisters RTTI for `vector<EntityCategorySet>`.
   */
  [[nodiscard]] gpg::RType* register_EntityCategorySetVectorType();

  /**
   * Address: 0x00BD8B90 (FUN_00BD8B90, sub_BD8B90)
   *
   * What it does:
   * Registers `vector<EntityCategorySet>` reflection and installs
   * process-exit teardown via `atexit`.
   */
  int register_EntityCategorySetVectorType_AtExit();
} // namespace moho
