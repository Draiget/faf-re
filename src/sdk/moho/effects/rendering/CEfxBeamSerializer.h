#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  class CEfxBeamSerializer
  {
  public:
    /**
     * Address: 0x00657B80 (FUN_00657B80, gpg::SerSaveLoadHelper_CEfxBeam::Init)
     *
     * What it does:
     * Binds load/save serializer callbacks into `CEfxBeam` RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    /**
     * Address: 0x00655F60 (FUN_00655F60, Moho::CEfxBeamSerializer::Deserialize)
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00655F70 (FUN_00655F70, Moho::CEfxBeamSerializer::Serialize)
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(offsetof(CEfxBeamSerializer, mHelperNext) == 0x04, "CEfxBeamSerializer::mHelperNext offset must be 0x04");
  static_assert(offsetof(CEfxBeamSerializer, mHelperPrev) == 0x08, "CEfxBeamSerializer::mHelperPrev offset must be 0x08");
  static_assert(
    offsetof(CEfxBeamSerializer, mLoadCallback) == 0x0C, "CEfxBeamSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CEfxBeamSerializer, mSaveCallback) == 0x10, "CEfxBeamSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(CEfxBeamSerializer) == 0x14, "CEfxBeamSerializer size must be 0x14");

  /**
   * Address: 0x00BFB910 (FUN_00BFB910, cleanup_CEfxBeamSerializer)
   *
   * What it does:
   * Unlinks startup CEfxBeam serializer helper node and restores self-links.
   */
  void cleanup_CEfxBeamSerializer();

  /**
   * Address: 0x00BD3F50 (FUN_00BD3F50, register_CEfxBeamSerializer)
   *
   * What it does:
   * Initializes startup CEfxBeam serializer helper callbacks and installs
   * process-exit cleanup.
   */
  void register_CEfxBeamSerializer();
} // namespace moho
