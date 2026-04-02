#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  class ReadArchive;
  class SerConstructResult;
  class SerSaveConstructArgsResult;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  class CCommandDb;

  class CCommandDBSaveConstruct
  {
  public:
    /**
     * Address: 0x006E1040 (FUN_006E1040, sub_6E1040)
     *
     * What it does:
     * Serializes the owning `Sim` pointer for `CCommandDb` as an unowned tracked pointer.
     */
    static void SaveConstructArgs(
      gpg::WriteArchive* archive, int objectPtr, int version, gpg::SerSaveConstructArgsResult* result
    );

    /**
     * Address: 0x006E1B20 (FUN_006E1B20, Moho::CCommandDBSaveConstruct::RegisterSaveConstructArgsFunction)
     *
     * What it does:
     * Binds `CCommandDb` save-construct-args callback into the reflected RTTI slot.
     */
    virtual void RegisterSaveConstructArgsFunction();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::save_construct_args_func_t mSaveConstructArgsCallback;
  };

  static_assert(offsetof(CCommandDBSaveConstruct, mHelperNext) == 0x04, "CCommandDBSaveConstruct::mHelperNext offset must be 0x04");
  static_assert(offsetof(CCommandDBSaveConstruct, mHelperPrev) == 0x08, "CCommandDBSaveConstruct::mHelperPrev offset must be 0x08");
  static_assert(
    offsetof(CCommandDBSaveConstruct, mSaveConstructArgsCallback) == 0x0C,
    "CCommandDBSaveConstruct::mSaveConstructArgsCallback offset must be 0x0C"
  );
  static_assert(sizeof(CCommandDBSaveConstruct) == 0x10, "CCommandDBSaveConstruct size must be 0x10");

  class CCommandDBConstruct
  {
  public:
    /**
     * Address: 0x006E1220 (FUN_006E1220, sub_6E1220)
     *
     * What it does:
     * Reads the owning `Sim` pointer, allocates `CCommandDb`, and returns it as unowned.
     */
    static void Construct(gpg::ReadArchive* archive, int objectPtr, int version, gpg::SerConstructResult* result);

    /**
     * Address: 0x006E1BA0 (FUN_006E1BA0, Moho::CCommandDBConstruct::RegisterConstructFunction)
     *
     * What it does:
     * Binds `CCommandDb` construct/delete callbacks into the reflected RTTI slot.
     */
    virtual void RegisterConstructFunction();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeconstructCallback;
  };

  static_assert(offsetof(CCommandDBConstruct, mHelperNext) == 0x04, "CCommandDBConstruct::mHelperNext offset must be 0x04");
  static_assert(offsetof(CCommandDBConstruct, mHelperPrev) == 0x08, "CCommandDBConstruct::mHelperPrev offset must be 0x08");
  static_assert(offsetof(CCommandDBConstruct, mConstructCallback) == 0x0C, "CCommandDBConstruct::mConstructCallback offset must be 0x0C");
  static_assert(offsetof(CCommandDBConstruct, mDeconstructCallback) == 0x10, "CCommandDBConstruct::mDeconstructCallback offset must be 0x10");
  static_assert(sizeof(CCommandDBConstruct) == 0x14, "CCommandDBConstruct size must be 0x14");

  class CCommandDBSerializer
  {
  public:
    /**
     * Address: 0x006E12E0 (FUN_006E12E0, Moho::CCommandDBSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive load into `CCommandDb::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006E12F0 (FUN_006E12F0, Moho::CCommandDBSerializer::Serialize)
     *
     * What it does:
     * Forwards archive save into `CCommandDb::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006E1C20 (FUN_006E1C20, Moho::CCommandDBSerializer::RegisterSerializeFunctions)
     *
     * What it does:
     * Binds `CCommandDb` load/save callbacks into the reflected RTTI slot.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(offsetof(CCommandDBSerializer, mHelperNext) == 0x04, "CCommandDBSerializer::mHelperNext offset must be 0x04");
  static_assert(offsetof(CCommandDBSerializer, mHelperPrev) == 0x08, "CCommandDBSerializer::mHelperPrev offset must be 0x08");
  static_assert(offsetof(CCommandDBSerializer, mDeserialize) == 0x0C, "CCommandDBSerializer::mDeserialize offset must be 0x0C");
  static_assert(offsetof(CCommandDBSerializer, mSerialize) == 0x10, "CCommandDBSerializer::mSerialize offset must be 0x10");
  static_assert(sizeof(CCommandDBSerializer) == 0x14, "CCommandDBSerializer size must be 0x14");

  /**
   * Address: 0x00BFE9A0 (FUN_00BFE9A0, sub_BFE9A0)
   *
   * What it does:
   * Unlinks the `CCommandDBSaveConstruct` helper node from the intrusive list.
   */
  gpg::SerHelperBase* cleanup_CCommandDBSaveConstruct();

  /**
   * Address: 0x00BFE9D0 (FUN_00BFE9D0, sub_BFE9D0)
   *
   * What it does:
   * Unlinks the `CCommandDBConstruct` helper node from the intrusive list.
   */
  gpg::SerHelperBase* cleanup_CCommandDBConstruct();

  /**
   * Address: 0x00BFEA00 (FUN_00BFEA00, sub_BFEA00)
   *
   * What it does:
   * Unlinks the `CCommandDBSerializer` helper node from the intrusive list.
   */
  gpg::SerHelperBase* cleanup_CCommandDBSerializer();

  /**
   * Address: 0x00BD8C60 (FUN_00BD8C60, sub_BD8C60)
   *
   * What it does:
   * Initializes `CCommandDBSaveConstruct` helper callback slots and registers them.
   */
  void register_CCommandDBSaveConstruct();

  /**
   * Address: 0x00BD8C90 (FUN_00BD8C90, sub_BD8C90)
   *
   * What it does:
   * Initializes `CCommandDBConstruct` helper callback slots and registers them.
   */
  void register_CCommandDBConstruct();

  /**
   * Address: 0x00BD8CD0 (FUN_00BD8CD0, register_CCommandDBSerializer)
   *
   * What it does:
   * Initializes `CCommandDBSerializer` helper callback slots and registers them.
   */
  void register_CCommandDBSerializer();
} // namespace moho
