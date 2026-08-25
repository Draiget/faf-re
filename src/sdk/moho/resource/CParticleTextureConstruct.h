#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  class ReadArchive;
  class SerConstructResult;
  struct SerHelperBase;
} // namespace gpg

namespace moho
{
  /**
   * VFTABLE: 0x00E06270
   * COL: 0x00E6143C
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='CParticleTextureConstruct@Moho'`): `FUN_00BC52A0` (real,
   * sole writer, `__xc_a`-reachable). Confirmed via raw asm:
   * default-constructs `gpg::SerHelperBase`, binds `mConstructCallback`/
   * `mDeleteCallback` to `FUN_0048F140`/`FUN_0048FFB0`, installs the
   * `CParticleTextureConstruct` vtable, and pushes the real mangled
   * destructor `??1CParticleTextureConstruct@Moho@@QAE@@Z` (`FUN_00BEFE00`,
   * confirmed unlink-then-self-link shape matching `SerHelperBase::
   * ResetLinks()`) as its `atexit` target -- no eager `RegisterConstructFunction`/
   * `Init()` call exists in the real ctor; that call was fabricated in the
   * previous recovery's `register_CParticleTextureConstruct()` free
   * function, invoked from this file's own bootstrap struct. Removed;
   * `Init()` is now dispatched the normal way, by `SerHelperBase::
   * InitNewHelpers()` draining the pending-helper list.
   */
  class CParticleTextureConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC52A0 (FUN_00BC52A0, dynamic initializer for the global
     * `CParticleTextureConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * construct/delete callback fields.
     */
    CParticleTextureConstruct();

    /**
     * Address: 0x00BEFE00 (FUN_00BEFE00, Moho::CParticleTextureConstruct::~CParticleTextureConstruct)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~CParticleTextureConstruct();

    /**
     * Address: 0x0048F140 (FUN_0048F140, Moho::CParticleTextureConstruct::Construct)
     *
     * What it does:
     * Reads archive construct args, allocates one `CParticleTexture`, and
     * returns it through `SerConstructResult` as unowned payload.
     */
    static void Construct(gpg::ReadArchive* archive, int objectStorage, int version, gpg::SerConstructResult* result);

    /**
     * Address: 0x0048FFB0 (FUN_0048FFB0, Moho::CParticleTextureConstruct::Deconstruct)
     *
     * What it does:
     * Executes deleting-dtor teardown for one constructed `CParticleTexture`.
     */
    static void Deconstruct(void* objectPtr);

    /**
     * Address: 0x0048FA30 (FUN_0048FA30, gpg::SerConstructHelper_CParticleTexture::Init)
     *
     * What it does:
     * Binds construct/delete callbacks into `CParticleTexture` RTTI.
     */
    void Init() override;

  public:
    gpg::RType::construct_func_t mConstructCallback; // +0x0C
    gpg::RType::delete_func_t mDeleteCallback;        // +0x10
  };

  static_assert(
    offsetof(CParticleTextureConstruct, mConstructCallback) == 0x0C,
    "CParticleTextureConstruct::mConstructCallback offset must be 0x0C"
  );
  static_assert(
    offsetof(CParticleTextureConstruct, mDeleteCallback) == 0x10,
    "CParticleTextureConstruct::mDeleteCallback offset must be 0x10"
  );
  static_assert(sizeof(CParticleTextureConstruct) == 0x14, "CParticleTextureConstruct size must be 0x14");
} // namespace moho
