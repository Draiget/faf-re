#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1EAC4
   * COL: 0x00E75904
   */
  class LAiAttackerImplSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x005D61A0 (FUN_005D61A0, Moho::LAiAttackerImplSerializer::Deserialize)
     *
     * What it does:
     * Loads the `CAiAttackerImpl` link stored by `LAiAttackerImpl`.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005D61D0 (FUN_005D61D0, Moho::LAiAttackerImplSerializer::Serialize)
     *
     * What it does:
     * Saves the `CAiAttackerImpl` link stored by `LAiAttackerImpl`.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x00BCE850 (FUN_00BCE850, dynamic initializer for the global
     * `LAiAttackerImplSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this` and
     * splices it into the process-global `sNewHelpers` pending list), then
     * binds the load/save callback fields. Confirmed from raw disassembly:
     * calls `gpg::SerHelperBase::SerHelperBase()` directly, then installs
     * `??_7LAiAttackerImplSerializer@Moho@@6B@` -- no eager `Init()` call
     * exists here, and this class has no user-declared destructor (the real
     * binary explicitly registers `atexit(&sub_BF83D0)` instead).
     */
    LAiAttackerImplSerializer();

    /**
     * Address: 0x005DBF80 (FUN_005DBF80)
     *
     * What it does:
     * Lazily resolves `LAiAttackerImpl` RTTI and installs load/save callbacks
     * from this helper object into the type descriptor. Dispatched by
     * `gpg::SerHelperBase::InitNewHelpers` when this helper is drained from
     * the pending list (vtable slot 0).
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(offsetof(LAiAttackerImplSerializer, mLoadCallback) == 0x0C, "LAiAttackerImplSerializer::mLoadCallback offset must be 0x0C");
  static_assert(offsetof(LAiAttackerImplSerializer, mSaveCallback) == 0x10, "LAiAttackerImplSerializer::mSaveCallback offset must be 0x10");
  static_assert(sizeof(LAiAttackerImplSerializer) == 0x14, "LAiAttackerImplSerializer size must be 0x14");

  /**
   * Address: 0x00BCE850 caller lane (`CAiAttackerImplTypeInfo.cpp`'s
   * reflection bootstrap sequence)
   *
   * What it does:
   * Historically forced construction of the (then lazily-constructed)
   * `LAiAttackerImplSerializer` singleton from an explicit registration
   * sequence. `gLAiAttackerImplSerializer` is now a genuine namespace-scope
   * global, so its constructor already runs unconditionally at static-init
   * time; this call is kept only so `CAiAttackerImplTypeInfo.cpp`'s existing
   * bootstrap sequence does not need editing.
   */
  void register_LAiAttackerImplSerializer();
} // namespace moho
