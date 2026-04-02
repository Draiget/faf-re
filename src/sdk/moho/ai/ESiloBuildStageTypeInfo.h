#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/CAiSiloBuildImpl.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1DD24
   * COL:  0x00E74BD0
   */
  class ESiloBuildStageTypeInfo : public gpg::REnumType
  {
  public:
    /**
     * Address: 0x005CEA80 (FUN_005CEA80, scalar deleting thunk)
     */
    ~ESiloBuildStageTypeInfo() override;

    /**
     * Address: 0x005CEA70 (FUN_005CEA70, ?GetName@ESiloBuildStageTypeInfo@Moho@@UBEPBDXZ)
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x005CEA50 (FUN_005CEA50, ?Init@ESiloBuildStageTypeInfo@Moho@@UAEXXZ)
     */
    void Init() override;
  };

  /**
   * Address: 0x00BCE050 (FUN_00BCE050, register_ESiloBuildStagePrimitiveSerializer)
   *
   * What it does:
   * Binds primitive enum load/save callbacks onto reflected
   * `ESiloBuildStage`.
   */
  class ESiloBuildStagePrimitiveSerializer
  {
  public:
    /**
     * Address: 0x005CFFB0 (FUN_005CFFB0, sub_5CFFB0)
     *
     * What it does:
     * Deserializes one `ESiloBuildStage` enum value from archive storage.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005CFFD0 (FUN_005CFFD0, sub_5CFFD0)
     *
     * What it does:
     * Serializes one `ESiloBuildStage` enum value to archive storage.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005CFAC0 (FUN_005CFAC0, sub_5CFAC0)
     *
     * What it does:
     * Binds load/save callbacks into `ESiloBuildStage` reflected metadata.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(ESiloBuildStagePrimitiveSerializer, mHelperNext) == 0x04,
    "ESiloBuildStagePrimitiveSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(ESiloBuildStagePrimitiveSerializer, mHelperPrev) == 0x08,
    "ESiloBuildStagePrimitiveSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(ESiloBuildStagePrimitiveSerializer, mLoadCallback) == 0x0C,
    "ESiloBuildStagePrimitiveSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(ESiloBuildStagePrimitiveSerializer, mSaveCallback) == 0x10,
    "ESiloBuildStagePrimitiveSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(
    sizeof(ESiloBuildStagePrimitiveSerializer) == 0x14,
    "ESiloBuildStagePrimitiveSerializer size must be 0x14"
  );

  /**
   * Address: 0x00BCE030 (FUN_00BCE030, register_ESiloBuildStageTypeInfo)
   *
   * What it does:
   * Registers `ESiloBuildStage` enum type-info and installs process-exit
   * cleanup.
   */
  int register_ESiloBuildStageTypeInfo();

  /**
   * Address: 0x00BCE050 (FUN_00BCE050, register_ESiloBuildStagePrimitiveSerializer)
   *
   * What it does:
   * Registers primitive serializer callbacks for `ESiloBuildStage` and
   * installs process-exit cleanup.
   */
  int register_ESiloBuildStagePrimitiveSerializer();

  static_assert(sizeof(ESiloBuildStageTypeInfo) == 0x78, "ESiloBuildStageTypeInfo size must be 0x78");
} // namespace moho
