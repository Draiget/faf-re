#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1DA74
   * COL:  0x00E73E34
   */
  class SReconKeyTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x005BFE20 (FUN_005BFE20, Moho::SReconKeyTypeInfo::dtr)
     *
     * What it does:
     * Releases reflected base/field vectors and runs scalar-delete thunk lane.
     */
    ~SReconKeyTypeInfo() override;

    /**
     * Address: 0x005BFE10 (FUN_005BFE10, Moho::SReconKeyTypeInfo::GetName)
     *
     * What it does:
     * Returns reflection type name for `SReconKey`.
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x005BFDF0 (FUN_005BFDF0, Moho::SReconKeyTypeInfo::Init)
     *
     * What it does:
     * Sets reflection payload size and finalizes `gpg::RType` init path.
     */
    void Init() override;
  };

  static_assert(sizeof(SReconKeyTypeInfo) == 0x64, "SReconKeyTypeInfo size must be 0x64");

  /**
   * Address: 0x00BCDD20 (FUN_00BCDD20, register_SReconKeyTypeInfo)
   *
   * What it does:
   * Preregisters `SReconKey` RTTI and installs process-exit cleanup.
   */
  int register_SReconKeyTypeInfo();

  /**
   * VFTABLE: 0x00E1DAA4
   * COL:  0x00E73D9C
   */
  class SReconKeySerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BCDD40 (FUN_00BCDD40, dynamic initializer for the global
     * `SReconKeySerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links and
     * splices into `sNewHelpers`) and binds the load/save callback fields.
     * Confirmed from raw disassembly: calls
     * `gpg::SerHelperBase::SerHelperBase()` directly, then installs
     * `??_7SReconKeySerializer@Moho@@6B@` -- no eager `Init()` call exists
     * here.
     */
    SReconKeySerializer();

    /**
     * Address: 0x00BF79C0 (FUN_00BF79C0, Moho::SReconKeySerializer::~SReconKeySerializer)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~SReconKeySerializer();

    /**
     * Address: 0x005BFED0 (FUN_005BFED0, Moho::SReconKeySerializer::Deserialize)
     *
     * What it does:
     * Forwards archive loading into `SReconKey::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005BFEE0 (FUN_005BFEE0, Moho::SReconKeySerializer::Serialize)
     *
     * What it does:
     * Forwards archive saving into `SReconKey::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005C4450 (FUN_005C4450, Moho::SReconKeySerializer::Init)
     *
     * What it does:
     * Binds load/save serializer callbacks into `SReconKey` RTTI
     * (`serLoadFunc_`, `serSaveFunc_`). Dispatched by
     * `gpg::SerHelperBase::InitNewHelpers` when this helper is drained from
     * the pending list (vtable slot 0).
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mSerLoadFunc;
    gpg::RType::save_func_t mSerSaveFunc;
  };

  static_assert(
    offsetof(SReconKeySerializer, mSerLoadFunc) == 0x0C, "SReconKeySerializer::mSerLoadFunc offset must be 0x0C"
  );
  static_assert(
    offsetof(SReconKeySerializer, mSerSaveFunc) == 0x10, "SReconKeySerializer::mSerSaveFunc offset must be 0x10"
  );
  static_assert(sizeof(SReconKeySerializer) == 0x14, "SReconKeySerializer size must be 0x14");

  /**
   * VFTABLE: 0x00E1DB44
   * COL:  0x00E73C00
   */
  class CAiReconDBImplSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BCDDC0 (FUN_00BCDDC0, dynamic initializer for the global
     * `CAiReconDBImplSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links and
     * splices into `sNewHelpers`) and binds the load/save callback fields.
     * Confirmed from raw disassembly: calls
     * `gpg::SerHelperBase::SerHelperBase()` directly, then installs
     * `??_7CAiReconDBImplSerializer@Moho@@6B@` -- no eager `Init()` call
     * exists here.
     */
    CAiReconDBImplSerializer();

    /**
     * Address: 0x00BF7AB0 (FUN_00BF7AB0, Moho::CAiReconDBImplSerializer::~CAiReconDBImplSerializer)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~CAiReconDBImplSerializer();

    /**
     * Address: 0x005C2910 (FUN_005C2910, Moho::CAiReconDBImplSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive loading into recovered CAiReconDBImpl member deserialize lane.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005C2920 (FUN_005C2920, Moho::CAiReconDBImplSerializer::Serialize)
     *
     * What it does:
     * Forwards archive saving into recovered CAiReconDBImpl member serialize lane.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005C4EE0 (FUN_005C4EE0, Moho::CAiReconDBImplSerializer::Init)
     *
     * What it does:
     * Binds load/save callbacks into CAiReconDBImpl RTTI
     * (`serLoadFunc_`, `serSaveFunc_`). Dispatched by
     * `gpg::SerHelperBase::InitNewHelpers` when this helper is drained from
     * the pending list (vtable slot 0).
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mSerLoadFunc;
    gpg::RType::save_func_t mSerSaveFunc;
  };

  static_assert(
    offsetof(CAiReconDBImplSerializer, mSerLoadFunc) == 0x0C,
    "CAiReconDBImplSerializer::mSerLoadFunc offset must be 0x0C"
  );
  static_assert(
    offsetof(CAiReconDBImplSerializer, mSerSaveFunc) == 0x10,
    "CAiReconDBImplSerializer::mSerSaveFunc offset must be 0x10"
  );
  static_assert(sizeof(CAiReconDBImplSerializer) == 0x14, "CAiReconDBImplSerializer size must be 0x14");
} // namespace moho
