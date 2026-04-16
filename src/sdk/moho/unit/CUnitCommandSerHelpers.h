#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "moho/unit/CUnitCommand.h"

namespace moho
{
  class CUnitCommandConstruct
  {
  public:
    /**
     * Address: 0x006E91B0 (FUN_006E91B0, Moho::CUnitCommandConstruct::Construct)
     *
     * What it does:
     * Allocates and construct-initializes one `CUnitCommand`, then returns it
     * as an unowned construct result.
     */
    static void Construct(gpg::ReadArchive* archive, int objectPtr, int version, gpg::SerConstructResult* result);

    /**
     * Address: 0x006EB710 (FUN_006EB710, Moho::CUnitCommandConstruct::Deconstruct)
     *
     * What it does:
     * Runs command teardown and frees the backing allocation.
     */
    static void Deconstruct(void* objectPtr);

    /**
     * Address: 0x006EA060 (FUN_006EA060, Moho::CUnitCommandConstruct::RegisterConstructFunction)
     *
     * What it does:
     * Binds `CUnitCommand` construct/delete callbacks into RTTI.
     */
    virtual void RegisterConstructFunction();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeconstructCallback;
  };

  static_assert(offsetof(CUnitCommandConstruct, mHelperNext) == 0x04, "CUnitCommandConstruct::mHelperNext offset must be 0x04");
  static_assert(offsetof(CUnitCommandConstruct, mHelperPrev) == 0x08, "CUnitCommandConstruct::mHelperPrev offset must be 0x08");
  static_assert(offsetof(CUnitCommandConstruct, mConstructCallback) == 0x0C, "CUnitCommandConstruct::mConstructCallback offset must be 0x0C");
  static_assert(offsetof(CUnitCommandConstruct, mDeconstructCallback) == 0x10, "CUnitCommandConstruct::mDeconstructCallback offset must be 0x10");
  static_assert(sizeof(CUnitCommandConstruct) == 0x14, "CUnitCommandConstruct size must be 0x14");

  class CUnitCommandSerializer
  {
  public:
    /**
     * Address: 0x006E9250 (FUN_006E9250, Moho::CUnitCommandSerializer::Deserialize)
     *
     * What it does:
     * Loads the serialized `CUnitCommand` payload lanes.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x006E9270 (FUN_006E9270, Moho::CUnitCommandSerializer::Serialize)
     *
     * What it does:
     * Saves the serialized `CUnitCommand` payload lanes.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
       * Address: 0x00BD8F90 (FUN_00BD8F90)
     *
     * What it does:
     * Binds `CUnitCommand` load/save callbacks into RTTI and schedules helper
     * cleanup at process exit.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(offsetof(CUnitCommandSerializer, mHelperNext) == 0x04, "CUnitCommandSerializer::mHelperNext offset must be 0x04");
  static_assert(offsetof(CUnitCommandSerializer, mHelperPrev) == 0x08, "CUnitCommandSerializer::mHelperPrev offset must be 0x08");
  static_assert(offsetof(CUnitCommandSerializer, mDeserialize) == 0x0C, "CUnitCommandSerializer::mDeserialize offset must be 0x0C");
  static_assert(offsetof(CUnitCommandSerializer, mSerialize) == 0x10, "CUnitCommandSerializer::mSerialize offset must be 0x10");
  static_assert(sizeof(CUnitCommandSerializer) == 0x14, "CUnitCommandSerializer size must be 0x14");

  /**
   * Address: 0x00BFEBE0 (FUN_00BFEBE0, Moho::CUnitCommandConstruct::~CUnitCommandConstruct)
   *
   * What it does:
   * Unlinks the construct helper from the intrusive helper list.
   */
  gpg::SerHelperBase* cleanup_CUnitCommandConstruct();

  /**
   * Address: 0x00BFEC10 (FUN_00BFEC10, Moho::CUnitCommandSerializer::~CUnitCommandSerializer)
   *
   * What it does:
   * Unlinks the serializer helper from the intrusive helper list.
   */
  gpg::SerHelperBase* cleanup_CUnitCommandSerializer();

  /**
    * Alias of FUN_00BD8F50 (non-canonical helper lane).
   *
   * What it does:
   * Initializes and registers the `CUnitCommand` construct helper.
   */
  void register_CUnitCommandConstruct();

  /**
    * Alias of FUN_00BD8F90 (non-canonical helper lane).
   *
   * What it does:
   * Initializes and registers the `CUnitCommand` serializer helper.
   */
  void register_CUnitCommandSerializer();
} // namespace moho

