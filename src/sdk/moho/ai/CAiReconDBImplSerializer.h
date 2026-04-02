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
  class SReconKeySerializer
  {
  public:
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
     * Address: 0x005C4450 (FUN_005C4450, Moho::SReconKeySerializer::RegisterSerializeFunctions)
     *
     * What it does:
     * Binds load/save serializer callbacks into `SReconKey` RTTI
     * (`serLoadFunc_`, `serSaveFunc_`).
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mNext;
    gpg::SerHelperBase* mPrev;
    gpg::RType::load_func_t mSerLoadFunc;
    gpg::RType::save_func_t mSerSaveFunc;
  };

  static_assert(offsetof(SReconKeySerializer, mNext) == 0x04, "SReconKeySerializer::mNext offset must be 0x04");
  static_assert(offsetof(SReconKeySerializer, mPrev) == 0x08, "SReconKeySerializer::mPrev offset must be 0x08");
  static_assert(
    offsetof(SReconKeySerializer, mSerLoadFunc) == 0x0C, "SReconKeySerializer::mSerLoadFunc offset must be 0x0C"
  );
  static_assert(
    offsetof(SReconKeySerializer, mSerSaveFunc) == 0x10, "SReconKeySerializer::mSerSaveFunc offset must be 0x10"
  );
  static_assert(sizeof(SReconKeySerializer) == 0x14, "SReconKeySerializer size must be 0x14");

  /**
   * Address: 0x00BCDD40 (FUN_00BCDD40, register_SReconKeySerializer)
   *
   * What it does:
   * Constructs the startup serializer helper and binds `SReconKey` archive callbacks.
   */
  void register_SReconKeySerializer();

  /**
   * VFTABLE: 0x00E1DB44
   * COL:  0x00E73C00
   */
  class CAiReconDBImplSerializer
  {
  public:
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
     * Address: 0x005C4EE0 (FUN_005C4EE0)
     *
     * What it does:
     * Binds load/save callbacks into CAiReconDBImpl RTTI
     * (`serLoadFunc_`, `serSaveFunc_`).
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mNext;
    gpg::SerHelperBase* mPrev;
    gpg::RType::load_func_t mSerLoadFunc;
    gpg::RType::save_func_t mSerSaveFunc;
  };

  static_assert(offsetof(CAiReconDBImplSerializer, mNext) == 0x04, "CAiReconDBImplSerializer::mNext offset must be 0x04");
  static_assert(offsetof(CAiReconDBImplSerializer, mPrev) == 0x08, "CAiReconDBImplSerializer::mPrev offset must be 0x08");
  static_assert(
    offsetof(CAiReconDBImplSerializer, mSerLoadFunc) == 0x0C,
    "CAiReconDBImplSerializer::mSerLoadFunc offset must be 0x0C"
  );
  static_assert(
    offsetof(CAiReconDBImplSerializer, mSerSaveFunc) == 0x10,
    "CAiReconDBImplSerializer::mSerSaveFunc offset must be 0x10"
  );
  static_assert(sizeof(CAiReconDBImplSerializer) == 0x14, "CAiReconDBImplSerializer size must be 0x14");

  /**
   * Address: 0x00BCDDC0 (FUN_00BCDDC0, register_CAiReconDBImplSerializer)
   *
   * What it does:
   * Constructs startup serializer helper storage for CAiReconDBImpl and binds
   * archive load/save callbacks.
   */
  void register_CAiReconDBImplSerializer();
} // namespace moho
