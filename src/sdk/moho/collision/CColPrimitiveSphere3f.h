#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "moho/collision/CColPrimitiveBase.h"
#include "wm3/Sphere3.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E038FC
   * COL: 0x00E60048
   */
  class Sphere3fSerializer
  {
  public:
    /**
     * Address: 0x00473FF0 (FUN_00473FF0, gpg::SerSaveLoadHelper<Wm3::Sphere3<float>>::Init)
     *
     * What it does:
     * Resolves Sphere3f RTTI and installs load/save callbacks for this helper.
     */
    virtual void RegisterSerializeFunctions();

    /**
     * Address: 0x004730E0 (FUN_004730E0, Moho::Sphere3fSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive load flow into `Wm3::Sphere3f::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectStorage, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x004730F0 (FUN_004730F0, Moho::Sphere3fSerializer::Serialize)
     *
     * What it does:
     * Forwards archive save flow into `Wm3::Sphere3f::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectStorage, int version, gpg::RRef* ownerRef);

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(
    offsetof(Sphere3fSerializer, mHelperNext) == 0x04, "Sphere3fSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(Sphere3fSerializer, mHelperPrev) == 0x08, "Sphere3fSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(Sphere3fSerializer, mLoadCallback) == 0x0C, "Sphere3fSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(Sphere3fSerializer, mSaveCallback) == 0x10, "Sphere3fSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(Sphere3fSerializer) == 0x14, "Sphere3fSerializer size must be 0x14");

  /**
   * Address: 0x00BC4970 (FUN_00BC4970, register_Sphere3fSerializer)
   *
   * What it does:
   * Installs startup serializer callbacks for Sphere3f and registers shutdown
   * unlink/teardown.
   */
  void register_Sphere3fSerializer();

  /**
   * Owns reflected metadata for `CColPrimitive<Wm3::Sphere3<float>>`.
   */
  class DColPrimSphereTypeInfo final : public gpg::RType
  {
  public:
    /**
     * Address: 0x004FE6D0 (FUN_004FE6D0, Moho::DColPrimSphereTypeInfo::dtr)
     * Slot: 2
     */
    ~DColPrimSphereTypeInfo() override;

    /**
     * Address: 0x004FE6C0 (FUN_004FE6C0, Moho::DColPrimSphereTypeInfo::GetName)
     * Slot: 3
     *
     * What it does:
     * Returns the reflection type-name literal for `DColPrimSphere`.
     */
    [[nodiscard]]
    const char* GetName() const override;

    /**
     * Address: 0x004FE6A0 (FUN_004FE6A0, Moho::DColPrimSphereTypeInfo::Init)
     * Slot: 9
     *
     * What it does:
     * Initializes reflection metadata for `CColPrimitive<Wm3::Sphere3<float>>`
     * (`sizeof = 0x20`) and adds the `CColPrimitiveBase` base lane.
     */
    void Init() override;
  };

  static_assert(sizeof(DColPrimSphereTypeInfo) == 0x64, "DColPrimSphereTypeInfo size must be 0x64");

  /**
   * Serializer helper for `CColPrimitive<Wm3::Sphere3<float>>` archive lanes.
   */
  class DColPrimSphereSerializer
  {
  public:
    /**
     * Address: 0x004FEF40 (FUN_004FEF40, Moho::DColPrimSphereSerializer::Deserialize)
     *
     * What it does:
     * No-op serializer lane placeholder bound into the primitive reflection
     * helper table.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectStorage, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x004FEF50 (FUN_004FEF50, Moho::DColPrimSphereSerializer::Serialize)
     *
     * What it does:
     * No-op serializer lane placeholder bound into the primitive reflection
     * helper table.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectStorage, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x004FFB40 (FUN_004FFB40, Moho::DColPrimSphereSerializer::RegisterSerializeFunctions)
     *
     * What it does:
     * Binds load/save callbacks into `CColPrimitive<Wm3::Sphere3<float>>` RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(
    offsetof(DColPrimSphereSerializer, mHelperNext) == 0x04, "DColPrimSphereSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(DColPrimSphereSerializer, mHelperPrev) == 0x08, "DColPrimSphereSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(DColPrimSphereSerializer, mDeserialize) == 0x0C, "DColPrimSphereSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(DColPrimSphereSerializer, mSerialize) == 0x10, "DColPrimSphereSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(DColPrimSphereSerializer) == 0x14, "DColPrimSphereSerializer size must be 0x14");

  /**
   * Construct helper for `CColPrimitive<Wm3::Sphere3<float>>`.
   */
  class DColPrimSphereConstruct
  {
  public:
    /**
     * Address: 0x004FFAC0 (FUN_004FFAC0, Moho::DColPrimSphereConstruct::RegisterConstructFunction)
     *
     * What it does:
     * Binds construct/delete callbacks into `CColPrimitive<Wm3::Sphere3<float>>` RTTI.
     */
    virtual void RegisterConstructFunction();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };

  static_assert(
    offsetof(DColPrimSphereConstruct, mHelperNext) == 0x04, "DColPrimSphereConstruct::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(DColPrimSphereConstruct, mHelperPrev) == 0x08, "DColPrimSphereConstruct::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(DColPrimSphereConstruct, mConstructCallback) == 0x0C,
    "DColPrimSphereConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(DColPrimSphereConstruct, mDeleteCallback) == 0x10,
    "DColPrimSphereConstruct::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(DColPrimSphereConstruct) == 0x14, "DColPrimSphereConstruct size must be 0x14");

  /**
   * Save-construct helper for `CColPrimitive<Wm3::Sphere3<float>>`.
   */
  class DColPrimSphereSaveConstruct
  {
  public:
    /**
     * Address: 0x004FFA40 (FUN_004FFA40, Moho::DColPrimSphereSaveConstruct::RegisterSaveConstructArgsFunction)
     *
     * What it does:
     * Binds save-construct-args callback into `CColPrimitive<Wm3::Sphere3<float>>` RTTI.
     */
    virtual void RegisterSaveConstructArgsFunction();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::save_construct_args_func_t mSaveConstructArgsCallback;
  };

  static_assert(
    offsetof(DColPrimSphereSaveConstruct, mHelperNext) == 0x04,
    "DColPrimSphereSaveConstruct::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(DColPrimSphereSaveConstruct, mHelperPrev) == 0x08,
    "DColPrimSphereSaveConstruct::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(DColPrimSphereSaveConstruct, mSaveConstructArgsCallback) == 0x0C,
    "DColPrimSphereSaveConstruct::mSaveConstructArgsCallback offset must be 0x0C"
  );
  static_assert(sizeof(DColPrimSphereSaveConstruct) == 0x10, "DColPrimSphereSaveConstruct size must be 0x10");

  /**
   * Address: 0x00BC7550 (FUN_00BC7550, register_DColPrimSphereTypeInfo)
   *
   * What it does:
   * Installs the startup-owned `DColPrimSphereTypeInfo` instance and its
   * process-exit cleanup hook.
   */
  int register_DColPrimSphereTypeInfo();

  /**
   * Address: 0x00BC75E0 (FUN_00BC75E0, register_DColPrimSphereSerializer)
   *
   * What it does:
   * Installs serializer callbacks for `DColPrimSphere` and registers shutdown
   * unlink/destruction.
   */
  void register_DColPrimSphereSerializer();

  /**
   * Address: 0x00BC75A0 (FUN_00BC75A0, register_DColPrimSphereConstruct)
   *
   * What it does:
   * Installs construct/delete callbacks for `DColPrimSphere` and registers
   * shutdown unlink/destruction.
   */
  int register_DColPrimSphereConstruct();

  /**
   * Address: 0x00BC7570 (FUN_00BC7570, register_DColPrimSphereSaveConstruct)
   *
   * What it does:
   * Installs save-construct-args callbacks for `DColPrimSphere` and registers
   * shutdown unlink/destruction.
   */
  int register_DColPrimSphereSaveConstruct();

  template <class T>
  [[nodiscard]] const T& Invalid();

  /**
   * Address: 0x00473050 (FUN_00473050, Moho::Invalid<Wm3::Sphere3<float>>)
   *
   * What it does:
   * Returns process-lifetime singleton invalid Sphere3f (center/radius set to NaN).
   */
  template <>
  [[nodiscard]] const Wm3::Sphere3f& Invalid<Wm3::Sphere3f>();
} // namespace moho
