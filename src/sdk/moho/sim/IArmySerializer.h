#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E175B4
   * COL:  0x00E6C470
   */
  class IArmySerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC9B70 (FUN_00BC9B70, dynamic initializer for the global
     * `IArmySerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields.
     */
    IArmySerializer();

    /**
     * Address: 0x00BF4900 (FUN_00BF4900, ??1IArmySerializer@Moho@@QAE@@Z)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~IArmySerializer();

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
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

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
   * Constructs/preregisters RTTI metadata for `SSTIArmyConstantData`. This is
   * orthogonal to IArmySerializer above: SSTIArmyConstantDataTypeInfo derives
   * from gpg::RType directly (not gpg::SerHelperBase) and this preregister
   * function is independently reachable through GPG_PREREGISTER_INIT: the
   * real IArmySerializer ctor's disassembly does not call it.
   */
  [[nodiscard]] gpg::RType* preregister_SSTIArmyConstantDataTypeInfo();
} // namespace moho
