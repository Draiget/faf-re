#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E175B4
   * COL:  0x00E6C470
   */
  class IArmySerializer
  {
  public:
    /**
     * Address: 0x00550C00 (FUN_00550C00, Moho::IArmySerializer::Deserialize)
     *
     * What it does:
     * Archive callback thunk that forwards to `IArmy::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00550C10 (FUN_00550C10, Moho::IArmySerializer::Serialize)
     *
     * What it does:
     * Archive callback thunk that forwards to `IArmy::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00550E30 (FUN_00550E30, gpg::SerSaveLoadHelper_IArmy::Init)
     *
     * What it does:
     * Binds load/save callback lanes to reflected `IArmy` RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;       // +0x04
    gpg::SerHelperBase* mHelperPrev;       // +0x08
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(offsetof(IArmySerializer, mHelperNext) == 0x04, "IArmySerializer::mHelperNext offset must be 0x04");
  static_assert(offsetof(IArmySerializer, mHelperPrev) == 0x08, "IArmySerializer::mHelperPrev offset must be 0x08");
  static_assert(
    offsetof(IArmySerializer, mLoadCallback) == 0x0C, "IArmySerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(IArmySerializer, mSaveCallback) == 0x10, "IArmySerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(IArmySerializer) == 0x14, "IArmySerializer size must be 0x14");

  /**
   * Address: 0x005506B0 (FUN_005506B0, preregister_SSTIArmyConstantDataTypeInfo)
   *
   * What it does:
   * Constructs/preregisters RTTI metadata for `SSTIArmyConstantData`.
   */
  [[nodiscard]] gpg::RType* preregister_SSTIArmyConstantDataTypeInfo();

  /**
   * Address: 0x00BC9B70 (FUN_00BC9B70, register_IArmySerializer)
   *
   * What it does:
   * Initializes startup serializer helper links/callbacks for `IArmy` and
   * installs process-exit cleanup.
   */
  void register_IArmySerializer();
} // namespace moho
