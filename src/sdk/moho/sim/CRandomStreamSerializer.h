#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E005C4
   */
  class CRandomStreamSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC3380 (FUN_00BC3380, dynamic initializer for the global
     * `CRandomStreamSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields.
     */
    CRandomStreamSerializer();

    /**
     * Address: 0x00BEE780 (FUN_00BEE780, ??1CRandomStreamSerializer@Moho@@QAE@@Z)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~CRandomStreamSerializer();

    /**
     * Address: 0x0040F1D0 (FUN_0040F1D0, Moho::CRandomStreamSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive loading to `CRandomStream::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0040F1E0 (FUN_0040F1E0, Moho::CRandomStreamSerializer::Serialize)
     *
     * What it does:
     * Forwards archive saving to `CRandomStream::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0040F380 (FUN_0040F380, gpg::SerSaveLoadHelper<class Moho::CRandomStream>::Init)
     *
     * What it does:
     * Binds CRandomStream load/save callbacks into reflected RTTI.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(CRandomStreamSerializer, mLoadCallback) == 0x0C,
    "CRandomStreamSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CRandomStreamSerializer, mSaveCallback) == 0x10,
    "CRandomStreamSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CRandomStreamSerializer) == 0x14, "CRandomStreamSerializer size must be 0x14");

  /**
   * Address: 0x00BC3360 (FUN_00BC3360, register_CRandomStreamTypeInfo)
   *
   * What it does:
   * Startup thunk that materializes CRandomStream type-info storage and
   * registers its process-exit destructor.
   */
  void register_CRandomStreamTypeInfo();
} // namespace moho
