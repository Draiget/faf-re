#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  struct SerHelperBase;
} // namespace gpg

namespace moho
{
  class SThreatSerializer
  {
  public:
    /**
     * Address: 0x00717AF0 (FUN_00717AF0, Moho::SThreatSerializer::Deserialize)
     *
     * What it does:
     * Reads 14 contiguous `float` threat lanes from archive into one `SThreat`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00717B00 (FUN_00717B00, Moho::SThreatSerializer::Serialize)
     *
     * What it does:
     * Writes 14 contiguous `float` threat lanes from one `SThreat` to archive.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00719370 (FUN_00719370, gpg::SerSaveLoadHelper_SThreat::Init)
     *
     * What it does:
     * Binds load/save serializer callbacks into SThreat RTTI.
     */
    virtual void RegisterSerializeFunctions();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(offsetof(SThreatSerializer, mHelperNext) == 0x04, "SThreatSerializer::mHelperNext offset must be 0x04");
  static_assert(offsetof(SThreatSerializer, mHelperPrev) == 0x08, "SThreatSerializer::mHelperPrev offset must be 0x08");
  static_assert(
    offsetof(SThreatSerializer, mLoadCallback) == 0x0C, "SThreatSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(SThreatSerializer, mSaveCallback) == 0x10, "SThreatSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(SThreatSerializer) == 0x14, "SThreatSerializer size must be 0x14");
} // namespace moho
