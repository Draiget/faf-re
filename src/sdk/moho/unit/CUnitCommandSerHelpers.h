#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "moho/unit/CUnitCommand.h"

namespace moho
{
  class CUnitCommandConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BD8F50 (FUN_00BD8F50, register_CUnitCommandConstruct)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * construct/delete callback fields.
     */
    CUnitCommandConstruct();

    /**
     * Address: 0x00BFEBE0 (FUN_00BFEBE0, Moho::CUnitCommandConstruct::~CUnitCommandConstruct)
     *
     * What it does:
     * Unlinks the construct helper from the intrusive helper list.
     */
    ~CUnitCommandConstruct();

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
    void Init() override;

  public:
    gpg::RType::construct_func_t mConstructCallback; // +0x0C
    gpg::RType::delete_func_t mDeconstructCallback;   // +0x10
  };

  static_assert(offsetof(CUnitCommandConstruct, mConstructCallback) == 0x0C, "CUnitCommandConstruct::mConstructCallback offset must be 0x0C");
  static_assert(offsetof(CUnitCommandConstruct, mDeconstructCallback) == 0x10, "CUnitCommandConstruct::mDeconstructCallback offset must be 0x10");
  static_assert(sizeof(CUnitCommandConstruct) == 0x14, "CUnitCommandConstruct size must be 0x14");

  class CUnitCommandSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BD8F90 (FUN_00BD8F90, register_CUnitCommandSerializer)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields.
     */
    CUnitCommandSerializer();

    /**
     * Address: 0x00BFEC10 (FUN_00BFEC10, Moho::CUnitCommandSerializer::~CUnitCommandSerializer)
     *
     * What it does:
     * Unlinks the serializer helper from the intrusive helper list.
     */
    ~CUnitCommandSerializer();

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
     * Address: 0x006EA0E0 (FUN_006EA0E0, gpg::SerSaveLoadHelper<Moho::CUnitCommand>::Init)
     *
     * What it does:
     * Binds `CUnitCommand` load/save callbacks onto its reflected type
     * metadata; asserts neither slot is already claimed before installing them.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mDeserialize; // +0x0C
    gpg::RType::save_func_t mSerialize;   // +0x10
  };

  static_assert(offsetof(CUnitCommandSerializer, mDeserialize) == 0x0C, "CUnitCommandSerializer::mDeserialize offset must be 0x0C");
  static_assert(offsetof(CUnitCommandSerializer, mSerialize) == 0x10, "CUnitCommandSerializer::mSerialize offset must be 0x10");
  static_assert(sizeof(CUnitCommandSerializer) == 0x14, "CUnitCommandSerializer size must be 0x14");
} // namespace moho

