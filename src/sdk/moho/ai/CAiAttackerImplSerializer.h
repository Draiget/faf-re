#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace moho
{
  /**
   * VFTABLE: 0x00E1EAE4
   * COL: 0x00E757AC
   */
  class CAiAttackerImplSerializer : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BCE8D0 (FUN_00BCE8D0, dynamic initializer for the global
     * `CAiAttackerImplSerializer` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base (self-links `this` and
     * splices it into the process-global `sNewHelpers` pending list), then
     * binds the load/save callback fields. Confirmed from raw disassembly:
     * calls `gpg::SerHelperBase::SerHelperBase()` directly, then installs
     * `??_7CAiAttackerImplSerializer@Moho@@6B@` -- no eager `Init()` call
     * exists here.
     */
    CAiAttackerImplSerializer();

    /**
     * Address: 0x00BF8430 (FUN_00BF8430, Moho::CAiAttackerImplSerializer::~CAiAttackerImplSerializer)
     * Address: 0x005D8480 (FUN_005D8480), Address: 0x005D84B0 (FUN_005D84B0)
     * -- duplicate emissions of the same unlink/self-link sequence hardcoded
     * to the identical global; zero callers and zero incoming xrefs in the
     * callgraph index.
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently sits
     * in and restores a self-linked sentinel state. Registered by the real
     * dynamic initializer (0x00BCE8D0) as the global's `atexit` teardown.
     */
    ~CAiAttackerImplSerializer();

    /**
     * Address: 0x005D8430 (FUN_005D8430, Moho::CAiAttackerImplSerializer::Deserialize)
     *
     * What it does:
     * Loads the recovered `CAiAttackerImpl` state payload from the archive.
     */
    static void Deserialize(gpg::ReadArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005D8440 (FUN_005D8440, Moho::CAiAttackerImplSerializer::Serialize)
     *
     * What it does:
     * Saves the recovered `CAiAttackerImpl` state payload to the archive.
     */
    static void Serialize(gpg::WriteArchive* archive, int objectPtr, int version, gpg::RRef* ownerRef);

    /**
     * Address: 0x005DC0D0 (FUN_005DC0D0)
     *
     * What it does:
     * Binds load/save serializer callbacks into `CAiAttackerImpl` RTTI.
     * Dispatched by `gpg::SerHelperBase::InitNewHelpers` when this helper is
     * drained from the pending list (vtable slot 0).
     */
    void Init() override;

  public:
    gpg::RType::load_func_t mLoadCallback;
    gpg::RType::save_func_t mSaveCallback;
  };

  static_assert(offsetof(CAiAttackerImplSerializer, mLoadCallback) == 0x0C, "CAiAttackerImplSerializer::mLoadCallback offset must be 0x0C");
  static_assert(offsetof(CAiAttackerImplSerializer, mSaveCallback) == 0x10, "CAiAttackerImplSerializer::mSaveCallback offset must be 0x10");
  static_assert(sizeof(CAiAttackerImplSerializer) == 0x14, "CAiAttackerImplSerializer size must be 0x14");

  /**
   * Compatibility no-op: `CAiAttackerImplTypeInfo.cpp`'s reflection bootstrap
   * sequence still calls this by name. See the definition in
   * CAiAttackerImplSerializer.cpp for why it no longer needs to do anything.
   */
  void register_CAiAttackerImplSerializer();
} // namespace moho
