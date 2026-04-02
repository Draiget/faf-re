#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
} // namespace gpg

namespace moho
{
  class CSimResources;

  /**
   * Address: 0x00BC96D0 (FUN_00BC96D0, register_CSimResourcesSerializer)
   *
   * What it does:
   * Initializes startup serializer helper links/callbacks for `CSimResources`
   * and schedules process-exit cleanup.
   */
  void register_CSimResourcesSerializer();

  /**
   * Address: 0x00BF42C0 (FUN_00BF42C0, cleanup_CSimResourcesSerializer)
   *
   * What it does:
   * Restores the serializer helper node to a self-linked singleton lane on
   * process exit.
   */
  void cleanup_CSimResourcesSerializer();

  /**
   * VFTABLE: 0x00E171E4
   * COL: 0x00E6B64C
   */
  class CSimResourcesSerializer
  {
  public:
    /**
     * Address: 0x00546B80 (FUN_00546B80, Moho::CSimResourcesSerializer::Deserialize)
     *
     * What it does:
     * Deserializes the `CSimResources::deposits_` vector from archive state.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00546BD0 (FUN_00546BD0, Moho::CSimResourcesSerializer::Serialize)
     *
     * What it does:
     * Serializes the `CSimResources::deposits_` vector to archive state.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00547870 (FUN_00547870, gpg::SerSaveLoadHelper_CSimResources::Init)
     *
     * What it does:
     * Binds `CSimResources` load/save serializer callbacks into RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mDeserialize;
    gpg::RType::save_func_t mSerialize;
  };

  static_assert(
    offsetof(CSimResourcesSerializer, mHelperNext) == 0x04,
    "CSimResourcesSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CSimResourcesSerializer, mHelperPrev) == 0x08,
    "CSimResourcesSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CSimResourcesSerializer, mDeserialize) == 0x0C,
    "CSimResourcesSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(CSimResourcesSerializer, mSerialize) == 0x10,
    "CSimResourcesSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(CSimResourcesSerializer) == 0x14, "CSimResourcesSerializer size must be 0x14");
} // namespace moho
