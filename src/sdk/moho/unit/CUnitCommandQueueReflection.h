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

  class CUnitCommandQueueSaveConstruct
  {
  public:
    /**
     * Address: 0x006EE9C0 (FUN_006EE9C0, save-construct callback thunk)
     */
    static void SaveConstructArgs(
      gpg::WriteArchive* archive, int objectPtr, int version, gpg::SerSaveConstructArgsResult* result
    );

    /**
     * Address: 0x006EE970 (FUN_006EE970, helper Init)
     */
    virtual void RegisterSaveConstructArgsFunction();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::save_construct_args_func_t mSaveConstructArgsCallback;
  };

  static_assert(
    offsetof(CUnitCommandQueueSaveConstruct, mHelperNext) == 0x04,
    "CUnitCommandQueueSaveConstruct::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CUnitCommandQueueSaveConstruct, mHelperPrev) == 0x08,
    "CUnitCommandQueueSaveConstruct::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CUnitCommandQueueSaveConstruct, mSaveConstructArgsCallback) == 0x0C,
    "CUnitCommandQueueSaveConstruct::mSaveConstructArgsCallback offset must be 0x0C"
  );
  static_assert(sizeof(CUnitCommandQueueSaveConstruct) == 0x10, "CUnitCommandQueueSaveConstruct size must be 0x10");

  class CUnitCommandQueueConstruct
  {
  public:
    /**
     * Address: 0x006EEAA0 (FUN_006EEAA0, Moho::CUnitCommandQueueConstruct::Construct)
     */
    static void Construct(gpg::ReadArchive* archive, int objectPtr, int version, gpg::SerConstructResult* result);

    /**
     * Address: 0x006F8D00 (FUN_006F8D00, Moho::CUnitCommandQueueConstruct::Deconstruct)
     */
    static void Deconstruct(void* objectPtr);

    /**
     * Address: 0x006EEA40 (FUN_006EEA40, helper Init)
     */
    virtual void RegisterConstructFunction();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeconstructCallback;
  };

  static_assert(
    offsetof(CUnitCommandQueueConstruct, mHelperNext) == 0x04,
    "CUnitCommandQueueConstruct::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CUnitCommandQueueConstruct, mHelperPrev) == 0x08,
    "CUnitCommandQueueConstruct::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CUnitCommandQueueConstruct, mConstructCallback) == 0x0C,
    "CUnitCommandQueueConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CUnitCommandQueueConstruct, mDeconstructCallback) == 0x10,
    "CUnitCommandQueueConstruct::mDeconstructCallback offset must be 0x10"
  );
  static_assert(sizeof(CUnitCommandQueueConstruct) == 0x14, "CUnitCommandQueueConstruct size must be 0x14");

  class CUnitCommandQueueSerializer
  {
  public:
    /**
     * Address: 0x006EEB70 (FUN_006EEB70, Moho::CUnitCommandQueueSerializer::Deserialize)
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006EEB90 (FUN_006EEB90, Moho::CUnitCommandQueueSerializer::Serialize)
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006EEBE0 (FUN_006EEBE0, helper Init)
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(
    offsetof(CUnitCommandQueueSerializer, mHelperNext) == 0x04,
    "CUnitCommandQueueSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CUnitCommandQueueSerializer, mHelperPrev) == 0x08,
    "CUnitCommandQueueSerializer::mHelperPrev offset must be 0x08"
  );
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

  /**
   * Address: 0x00BD92A0 (FUN_00BD92A0, sub_BD92A0)
   */
  void register_CUnitCommandQueueSaveConstruct();

  /**
   * Address: 0x00BD92D0 (FUN_00BD92D0, register_CUnitCommandQueueConstruct)
   */
  void register_CUnitCommandQueueConstruct();

  /**
   * Address: 0x00BD9310 (FUN_00BD9310, register_CUnitCommandQueueSerializer)
   */
  void register_CUnitCommandQueueSerializer();
} // namespace moho

