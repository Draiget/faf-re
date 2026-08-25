#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  class SerConstructResult;
  class SerSaveConstructArgsResult;
} // namespace gpg

namespace moho
{
  class CUnitCommandQueueTypeInfo : public gpg::RType
  {
  public:
    /**
     * Address: 0x006EDAA0 (FUN_006EDAA0, ??0CUnitCommandQueueTypeInfo@Moho@@QAE@@Z)
     */
    CUnitCommandQueueTypeInfo();

    /**
     * Address: 0x006EDB30 (FUN_006EDB30, Moho::CUnitCommandQueueTypeInfo::dtr)
     */
    ~CUnitCommandQueueTypeInfo() override;

    /**
     * Address: 0x006EDB20 (FUN_006EDB20, Moho::CUnitCommandQueueTypeInfo::GetName)
     */
    [[nodiscard]] const char* GetName() const override;

    /**
     * Address: 0x006EDB00 (FUN_006EDB00, Moho::CUnitCommandQueueTypeInfo::Init)
     */
    void Init() override;

  private:
    /**
     * Address: 0x006F8C50 (FUN_006F8C50, Moho::CUnitCommandQueueTypeInfo::AddBase_Broadcaster_EUnitCommandQueueStatus)
     */
    static void AddBase_Broadcaster_EUnitCommandQueueStatus(gpg::RType* typeInfo);
  };

  static_assert(sizeof(CUnitCommandQueueTypeInfo) == 0x64, "CUnitCommandQueueTypeInfo size must be 0x64");

  class CUnitCommandQueueSaveConstruct final : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BD92A0 (FUN_00BD92A0, register_CUnitCommandQueueSaveConstruct)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * save-construct-args callback field.
     */
    CUnitCommandQueueSaveConstruct();

    /**
     * Address: 0x00BFEF10 (FUN_00BFEF10, sub_BFEF10)
     *
     * What it does:
     * Unlinks the `CUnitCommandQueueSaveConstruct` helper node from the
     * intrusive helper list.
     */
    ~CUnitCommandQueueSaveConstruct();

    /**
     * Address: 0x006EE9C0 (FUN_006EE9C0, save-construct callback thunk)
     */
    static void SaveConstructArgs(
      gpg::WriteArchive* archive, int objectPtr, int version, gpg::SerSaveConstructArgsResult* result
    );

    /**
     * Address: 0x006F8420 (FUN_006F8420, Moho::CUnitCommandQueueSaveConstruct::RegisterSaveConstructArgsFunction)
     */
    void Init() override;

  public:
    gpg::RType::save_construct_args_func_t mSaveConstructArgsCallback; // +0x0C
  };

  static_assert(
    offsetof(CUnitCommandQueueSaveConstruct, mSaveConstructArgsCallback) == 0x0C,
    "CUnitCommandQueueSaveConstruct::mSaveConstructArgsCallback offset must be 0x0C"
  );
  static_assert(sizeof(CUnitCommandQueueSaveConstruct) == 0x10, "CUnitCommandQueueSaveConstruct size must be 0x10");

  class CUnitCommandQueueConstruct final : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BD92D0 (FUN_00BD92D0, register_CUnitCommandQueueConstruct)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * construct/delete callback fields.
     */
    CUnitCommandQueueConstruct();

    /**
     * Address: 0x00BFEF40 (FUN_00BFEF40, Moho::CUnitCommandQueueConstruct::~CUnitCommandQueueConstruct)
     */
    ~CUnitCommandQueueConstruct();

    /**
     * Address: 0x006EEAA0 (FUN_006EEAA0, Moho::CUnitCommandQueueConstruct::Construct)
     */
    static void Construct(gpg::ReadArchive* archive, int objectPtr, int version, gpg::SerConstructResult* result);

    /**
     * Address: 0x006F8D00 (FUN_006F8D00, Moho::CUnitCommandQueueConstruct::Deconstruct)
     */
    static void Deconstruct(void* objectPtr);

    /**
     * Address: 0x006F84A0 (FUN_006F84A0, Moho::CUnitCommandQueueConstruct::RegisterConstructFunction)
     */
    void Init() override;

  public:
    gpg::RType::construct_func_t mConstructCallback; // +0x0C
    gpg::RType::delete_func_t mDeconstructCallback;  // +0x10
  };

  static_assert(
    offsetof(CUnitCommandQueueConstruct, mConstructCallback) == 0x0C,
    "CUnitCommandQueueConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CUnitCommandQueueConstruct, mDeconstructCallback) == 0x10,
    "CUnitCommandQueueConstruct::mDeconstructCallback offset must be 0x10"
  );
  static_assert(sizeof(CUnitCommandQueueConstruct) == 0x14, "CUnitCommandQueueConstruct size must be 0x14");

  class CUnitCommandQueueSerializer final : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BD9310 (FUN_00BD9310, register_CUnitCommandQueueSerializer)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields.
     */
    CUnitCommandQueueSerializer();

    /**
     * Address: 0x00BFEF70 (FUN_00BFEF70, sub_BFEF70)
     *
     * What it does:
     * Unlinks the `CUnitCommandQueueSerializer` helper node from the
     * intrusive helper list.
     */
    ~CUnitCommandQueueSerializer();

    /**
     * Address: 0x006EEB70 (FUN_006EEB70, Moho::CUnitCommandQueueSerializer::Deserialize)
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006EEB90 (FUN_006EEB90, Moho::CUnitCommandQueueSerializer::Serialize)
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006F8520 (FUN_006F8520, gpg::SerSaveLoadHelper<Moho::CUnitCommandQueue>::Init)
     *
     * What it does:
     * Binds `CUnitCommandQueue` load/save callbacks onto its reflected type
     * metadata; asserts neither slot is already claimed before installing them.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mDeserialize; // +0x0C
    gpg::RType::save_func_t mSerialize;   // +0x10
  };

  static_assert(
    offsetof(CUnitCommandQueueSerializer, mDeserialize) == 0x0C,
    "CUnitCommandQueueSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(CUnitCommandQueueSerializer, mSerialize) == 0x10,
    "CUnitCommandQueueSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(CUnitCommandQueueSerializer) == 0x14, "CUnitCommandQueueSerializer size must be 0x14");

  /**
   * Address: 0x00BD9280 (FUN_00BD9280, register_CUnitCommandQueueTypeInfo)
   */
  void register_CUnitCommandQueueTypeInfo();
} // namespace moho
