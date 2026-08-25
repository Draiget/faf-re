#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E318D4
   */
  class SThreatSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BDA780 (FUN_00BDA780, dynamic initializer for the global
     * `SThreatSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields. The ctor's atexit target is a plain
     * unlink thunk, not a mangled destructor, so it is modeled as the
     * compiler's implicit static-destructor registration rather than an
     * explicit call.
     */
    SThreatSerializer();

    /**
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~SThreatSerializer();

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
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback; // +0x0C
    gpg::RType::save_func_t mSaveCallback; // +0x10
  };

  static_assert(
    offsetof(SThreatSerializer, mLoadCallback) == 0x0C, "SThreatSerializer::mLoadCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(SThreatSerializer, mSaveCallback) == 0x10, "SThreatSerializer::mSaveCallback offset must be 0x10"
  );
  static_assert(sizeof(SThreatSerializer) == 0x14, "SThreatSerializer size must be 0x14");
} // namespace moho
