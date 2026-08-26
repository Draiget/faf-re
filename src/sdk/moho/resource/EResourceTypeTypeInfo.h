#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  enum EResourceType : std::int32_t
  {
    RESTYPE_None = 0,
    RESTYPE_Mass = 1,
    RESTYPE_Hydrocarbon = 2,
    RESTYPE_Max = 3,
  };

  static_assert(sizeof(EResourceType) == 0x4, "EResourceType size must be 0x4");

  class EResourceTypeTypeInfo final : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x00545A50 (FUN_00545A50, Moho::EResourceTypeTypeInfo::EResourceTypeTypeInfo)
     *
     * What it does:
     * Preregisters this type descriptor under `typeid(EResourceType)` so
     * `gpg::LookupRType` can find it later.
     */
    EResourceTypeTypeInfo();

    /**
     * Address: 0x00BF4190 (FUN_00BF4190, Moho::EResourceTypeTypeInfo::~EResourceTypeTypeInfo)
     */
    ~EResourceTypeTypeInfo() override;

    /**
     * Address: 0x00545AD0 (FUN_00545AD0, Moho::EResourceTypeTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x00545AB0 (FUN_00545AB0, Moho::EResourceTypeTypeInfo::Init)
     */
    void Init() override;

  private:
    /**
     * Address: 0x00545B10 (FUN_00545B10, Moho::EResourceTypeTypeInfo::AddEnums)
     */
    void AddEnums();
  };

  static_assert(sizeof(EResourceTypeTypeInfo) == 0x78, "EResourceTypeTypeInfo size must be 0x78");

  /**
   * Demangled: gpg::PrimitiveSerHelper<enum Moho::EResourceType,int>
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='?$PrimitiveSerHelper@W4EResourceType@Moho@@H@gpg'`):
   * `FUN_00BC9610` (real, `__xc_a`-reachable) vs. a dead zero-xref duplicate
   * at `FUN_00547380` in the same instantiation family. `FUN_00BC9610` was
   * wrongly tagged `external_dependency` in progress tracking before this
   * recovery -- it is the same SerHelperBase-ctor/field-set/vtable-install/
   * atexit shape as every other confirmed instantiation, not an OS/CRT/
   * library import.
   *
   * Previously modeled in this file as a hand-rolled `{ void* mVtable;
   * SerHelperBase* mHelperNext, mHelperPrev; ... }` POD. Worse than the
   * sibling conversions in this same pass: its only wiring function,
   * `InitializeEResourceTypePrimitiveSerializerStartupThunk` (citing the
   * dead `FUN_00547380` address, not the real one), was `[[maybe_unused]]`
   * and genuinely never called from anywhere -- not even from an eager
   * bootstrap struct like the others had -- so `EResourceType`'s
   * serialize/deserialize callbacks were never installed under any code
   * path at all. `SerHelperBase`'s own ctor now performs the real
   * self-registration onto the pending-helper list.
   *
   * `~PrimitiveSerHelper()`'s compiler-emitted static-destructor
   * registration for this instantiation is `FUN_00BF41A0` (atexit target
   * pushed by the real ctor at 0x00BC9610); `FUN_00545B70`/`FUN_00545BA0`
   * are dead, zero-xref duplicate-emission twins of that exact body
   * (function_sha256-confirmed), formerly modeled in
   * `moho/containers/LegacyContainerFillLanes.cpp` as
   * `gGlobalIntrusiveSentinelLaneC` and its two reset thunks; removed in
   * favor of this citation. See `gpg::PrimitiveSerHelper<T,IntType>`'s
   * per-instantiation address list in `Reflection.h`.
   */
  using EResourceTypePrimitiveSerializer = gpg::PrimitiveSerHelper<EResourceType, int>;

  /**
   * Address: 0x00BC95F0 (FUN_00BC95F0, register_EResourceTypeTypeInfo)
   *
   * What it does:
   * Constructs the global `EResourceTypeTypeInfo` descriptor and schedules
   * its teardown at process exit.
   */
  void register_EResourceTypeTypeInfo();
} // namespace moho
