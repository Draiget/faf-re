#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "moho/audio/SAudioRequest.h"

namespace moho
{
  class SAudioRequestSerializer
  {
  public:
    /**
     * Address: 0x004E1EB0 (FUN_004E1EB0, gpg::SerSaveLoadHelper<Moho::SAudioRequest>::Init)
     *
     * What it does:
     * Binds `SAudioRequest` load/save callbacks into reflected type metadata.
     */
    virtual void RegisterSerializeFunctions();

    /**
     * Address: 0x004E1040 (FUN_004E1040, Moho::SAudioRequestSerializer::Deserialize)
     */
    static void Deserialize(gpg::ReadArchive* archive, SAudioRequest* request);

    /**
     * Address: 0x004E1050 (FUN_004E1050, Moho::SAudioRequestSerializer::Serialize)
     */
    static void Serialize(gpg::WriteArchive* archive, SAudioRequest* request);

    /**
     * Address: 0x004E10C0 (FUN_004E10C0, Moho::SAudioRequestSerializer::dtr)
     */
    virtual ~SAudioRequestSerializer() noexcept;

  public:
    gpg::SerHelperBase* mHelperNext;       // +0x04
    gpg::SerHelperBase* mHelperPrev;       // +0x08
    gpg::RType::load_func_t mDeserialize;  // +0x0C
    gpg::RType::save_func_t mSerialize;    // +0x10
  };

  /**
   * Address: 0x00BC6A50 (FUN_00BC6A50, register_SAudioRequestSerializer)
   */
  void register_SAudioRequestSerializer();

  static_assert(
    offsetof(SAudioRequestSerializer, mHelperNext) == 0x04, "SAudioRequestSerializer::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(SAudioRequestSerializer, mHelperPrev) == 0x08, "SAudioRequestSerializer::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(SAudioRequestSerializer, mDeserialize) == 0x0C, "SAudioRequestSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(SAudioRequestSerializer, mSerialize) == 0x10, "SAudioRequestSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(SAudioRequestSerializer) == 0x14, "SAudioRequestSerializer size must be 0x14");
} // namespace moho
