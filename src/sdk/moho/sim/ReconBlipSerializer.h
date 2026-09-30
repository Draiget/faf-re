#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1DA64
   * COL:  0x00E73E98
   */
  class ReconBlipSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BCDCE0 (FUN_00BCDCE0, register_ReconBlipSerializer)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields; the compiler registers the destructor with
     * `atexit`.
     */
    ReconBlipSerializer();

    /**
     * Address: 0x00BF7930 (FUN_00BF7930, dynamic atexit destructor for `gReconBlipSerializer`)
     *
     * What it does:
     * Unlinks this helper node from the serializer-helper list (the
     * `TDatListItem` base destructor). `FUN_005BFCE0` and `FUN_005BFD10` are
     * unreferenced out-of-line copies of the same body.
     */
    ~ReconBlipSerializer();

    /**
     * Address: 0x005BFC90 (FUN_005BFC90, Moho::ReconBlipSerializer::Deserialize)
     *
     * What it does:
     * Reflection load callback that deserializes `ReconBlip` fields.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005BFCA0 (FUN_005BFCA0, Moho::ReconBlipSerializer::Serialize)
     *
     * What it does:
     * Reflection save callback that serializes `ReconBlip` fields.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005C43B0 (FUN_005C43B0, gpg::SerSaveLoadHelper_ReconBlip::Init)
     *
     * What it does:
     * Binds load/save serializer callbacks into ReconBlip RTTI.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(ReconBlipSerializer, mLoadCallback) == 0x0C, "ReconBlipSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(ReconBlipSerializer, mSaveCallback) == 0x10, "ReconBlipSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(ReconBlipSerializer) == 0x14, "ReconBlipSerializer size must be 0x14");
} // namespace moho
