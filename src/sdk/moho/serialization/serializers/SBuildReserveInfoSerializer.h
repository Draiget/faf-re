#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  struct SBuildReserveInfo;

  /**
   * Serializer helper for reflected `SBuildReserveInfo` archive callbacks.
   */
  class SBuildReserveInfoSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BCB390 (FUN_00BCB390, register_SBuildReserveInfoSerializer)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * load/save callback fields. Confirmed from raw disassembly: calls
     * `gpg::SerHelperBase::SerHelperBase()` directly, then installs
     * `??_7SBuildReserveInfoSerializer@Moho@@6B@` -- no eager
     * `RegisterSerializeFunctions`-style call exists here. The
     * `push offset ~SBuildReserveInfoSerializer; call _atexit` sequence
     * visible in the real ctor's tail is the compiler's own implicit
     * static-destructor registration for a global with a non-trivial
     * destructor (it is not a call the 2007 source wrote), so it is not
     * reproduced explicitly here -- declaring a real destructor below is
     * sufficient for the compiler to emit the same registration.
     */
    SBuildReserveInfoSerializer();

    /**
     * Address: 0x00BF6230 (FUN_00BF6230, Moho::SBuildReserveInfoSerializer::~SBuildReserveInfoSerializer)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~SBuildReserveInfoSerializer();

    /**
     * Address: 0x00579A70 (FUN_00579A70, Moho::SBuildReserveInfoSerializer::Deserialize)
     *
     * What it does:
     * Forwards archive load flow into `SBuildReserveInfo::MemberDeserialize`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00579A80 (FUN_00579A80, Moho::SBuildReserveInfoSerializer::Serialize)
     *
     * What it does:
     * Forwards archive save flow into `SBuildReserveInfo::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x0057E1D0 (FUN_0057E1D0, gpg::SerSaveLoadHelper<Moho::SBuildReserveInfo>::Init lane)
     *
     * What it does:
     * Binds this serializer helper's load/save callbacks into
     * `SBuildReserveInfo` RTTI.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mDeserialize; // +0x0C
    gpg::RType::save_func_t mSerialize;   // +0x10
  };

  static_assert(
    offsetof(SBuildReserveInfoSerializer, mDeserialize) == 0x0C,
    "SBuildReserveInfoSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(SBuildReserveInfoSerializer, mSerialize) == 0x10,
    "SBuildReserveInfoSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(SBuildReserveInfoSerializer) == 0x14, "SBuildReserveInfoSerializer size must be 0x14");
} // namespace moho
