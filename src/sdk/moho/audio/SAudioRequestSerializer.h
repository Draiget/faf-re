#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"
#include "moho/audio/SAudioRequest.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E0BAD8
   */
  class SAudioRequestSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC6A50 (FUN_00BC6A50, register_SAudioRequestSerializer)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this`
     * and splices it into the process-global `sNewHelpers` pending list) and
     * binds the load/save callback fields. Confirmed from raw disassembly:
     * calls `gpg::SerHelperBase::SerHelperBase()` directly, then installs
     * `??_7SAudioRequestSerializer@Moho@@6B@` -- no eager `Init()` call
     * exists here. The `push offset ~SAudioRequestSerializer; call _atexit`
     * sequence visible in the real ctor's tail is the compiler's own
     * implicit static-destructor registration for a global with a
     * non-trivial destructor (it pushes the mangled
     * `??1SAudioRequestSerializer@Moho@@QAE@@Z` symbol directly, not a call
     * the 2007 source wrote), so it is not reproduced explicitly here --
     * declaring a real destructor below is sufficient for the compiler to
     * emit the same registration.
     */
    SAudioRequestSerializer();

    /**
     * Address: 0x00BF1080 (FUN_00BF1080, Moho::SAudioRequestSerializer::~SAudioRequestSerializer)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~SAudioRequestSerializer() noexcept;

    /**
     * Address: 0x004E1040 (FUN_004E1040, Moho::SAudioRequestSerializer::Deserialize)
     *
     * What it does:
     * Reflection load-callback facade for `SAudioRequest`. Forwards the
     * reflected object pointer to `SAudioRequest::MemberDeserialize`; the
     * `version`/owner-ref lanes are unused by the member (IDA's decompile
     * only shows the two leading params it actually reads).
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x004E1050 (FUN_004E1050, Moho::SAudioRequestSerializer::Serialize)
     *
     * What it does:
     * Reflection save-callback facade for `SAudioRequest`. Forwards the
     * reflected object pointer to `SAudioRequest::MemberSerialize`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x004E1EB0 (FUN_004E1EB0, gpg::SerSaveLoadHelper<Moho::SAudioRequest>::Init)
     *
     * What it does:
     * Binds `SAudioRequest` load/save callbacks into reflected type metadata.
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mDeserialize; // +0x0C
    gpg::RType::save_func_t mSerialize;   // +0x10
  };

  static_assert(
    offsetof(SAudioRequestSerializer, mDeserialize) == 0x0C,
    "SAudioRequestSerializer::mDeserialize offset must be 0x0C"
  );
  static_assert(
    offsetof(SAudioRequestSerializer, mSerialize) == 0x10, "SAudioRequestSerializer::mSerialize offset must be 0x10"
  );
  static_assert(sizeof(SAudioRequestSerializer) == 0x14, "SAudioRequestSerializer size must be 0x14");
} // namespace moho
