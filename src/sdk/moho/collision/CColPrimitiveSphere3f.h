#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "moho/collision/CColPrimitiveBase.h"
#include "Wm3Sphere3.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E038FC
   * COL: 0x00E60048
   */
  class Sphere3fSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC4970 (FUN_00BC4970, dynamic initializer for the global
     * `Sphere3fSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields.
     */
    Sphere3fSerializer();

    /**
     * Address: 0x00BEF780 (FUN_00BEF780, Moho::Sphere3fSerializer::~Sphere3fSerializer)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~Sphere3fSerializer();

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

    /**
     * Address: 0x00473FF0 (FUN_00473FF0, gpg::SerSaveLoadHelper<Wm3::Sphere3<float>>::Init lane)
     *
     * What it does:
     * Resolves Sphere3f RTTI and installs load/save callbacks for this helper.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(Sphere3fSerializer, mLoadCallback) == 0x0C, "Sphere3fSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(Sphere3fSerializer, mSaveCallback) == 0x10, "Sphere3fSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(Sphere3fSerializer) == 0x14, "Sphere3fSerializer size must be 0x14");

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

    /**
     * Address: 0x00500390 (FUN_00500390, Moho::DColPrimSphereTypeInfo::AddBase_CColPrimitiveBase)
     *
     * What it does:
     * Registers `CColPrimitiveBase` as this type's reflected base at offset 0.
     */
    static void AddBase_CColPrimitiveBase(gpg::RType* typeInfo);
  };

  static_assert(sizeof(DColPrimSphereTypeInfo) == 0x64, "DColPrimSphereTypeInfo size must be 0x64");

  /**
   * Serializer helper for `CColPrimitive<Wm3::Sphere3<float>>` archive lanes.
   */
  class DColPrimSphereSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC75E0 (FUN_00BC75E0, dynamic initializer for the global
     * `DColPrimSphereSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields.
     */
    DColPrimSphereSerializer();

    /**
     * Address: 0x00BF1B00 (FUN_00BF1B00, Moho::DColPrimSphereSerializer::~DColPrimSphereSerializer)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~DColPrimSphereSerializer();

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
     * Address: 0x004FFB40 (FUN_004FFB40, Moho::DColPrimSphereSerializer::Init)
     *
     * What it does:
     * Binds load/save callbacks into `CColPrimitive<Wm3::Sphere3<float>>` RTTI.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mDeserialize; // +0x0C
    gpg::RType::save_func_t mSerialize;   // +0x10
  };

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
  class DColPrimSphereConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC75A0 (FUN_00BC75A0, dynamic initializer for the global
     * `DColPrimSphereConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * construct/delete callback fields. Confirmed from raw disassembly:
     * `mDeleteCallback` is the real global `operator delete(void*)`
     * directly (a `jmp ??3@YAXPAX@Z` thunk via `j_j_func_tent_Destroy_3`
     * at 0x00500430, not a per-type wrapper that runs
     * `~SphereCollisionPrimitive()` first) -- the ctor's own atexit
     * target is a plain unlink thunk, so it is modeled as the compiler's
     * implicit static-destructor registration rather than an explicit
     * call.
     */
    DColPrimSphereConstruct();

    /**
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~DColPrimSphereConstruct();

    /**
     * Address: 0x004FFAC0 (FUN_004FFAC0, Moho::DColPrimSphereConstruct::Init)
     *
     * What it does:
     * Binds construct/delete callbacks into `CColPrimitive<Wm3::Sphere3<float>>` RTTI.
     */
    void Init() override;

  public:
    gpg::RType::construct_func_t mConstructCallback; // +0x0C
    gpg::RType::delete_func_t mDeleteCallback;         // +0x10
  };

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
  class DColPrimSphereSaveConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC7570 (FUN_00BC7570, dynamic initializer for the global
     * `DColPrimSphereSaveConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * save-construct-args callback field. Plain unlink atexit target,
     * modeled as the compiler's implicit static-destructor registration.
     */
    DColPrimSphereSaveConstruct();

    /**
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~DColPrimSphereSaveConstruct();

    /**
     * Address: 0x004FFA40 (FUN_004FFA40, Moho::DColPrimSphereSaveConstruct::Init)
     *
     * What it does:
     * Binds save-construct-args callback into `CColPrimitive<Wm3::Sphere3<float>>` RTTI.
     */
    void Init() override;

  public:
    gpg::RType::save_construct_args_func_t mSaveConstructArgsCallback; // +0x0C
  };

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
