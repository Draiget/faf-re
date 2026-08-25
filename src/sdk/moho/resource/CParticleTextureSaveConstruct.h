#pragma once

#include <cstddef>

#include "gpg/core/reflection/Reflection.h"

namespace gpg
{
  class RRef;
  struct SerHelperBase;
  class SerSaveConstructArgsResult;
  class WriteArchive;
} // namespace gpg

namespace moho
{
  class CParticleTexture;

  /**
   * VFTABLE: 0x00E06260
   * COL: 0x00E614E8
   *
   * Real ctor confirmed via the callgraph index's `vtable_writers` table
   * (`class_name='CParticleTextureSaveConstruct@Moho'`): `FUN_00BC5270`
   * (real, sole writer, `__xc_a`-reachable). Confirmed via raw asm:
   * default-constructs `gpg::SerHelperBase`, binds
   * `mSerSaveConstructArgsFunc` to `FUN_0048F010`, installs the
   * `CParticleTextureSaveConstruct` vtable, and pushes the real mangled
   * destructor `??1CParticleTextureSaveConstruct@Moho@@QAE@@Z`
   * (`FUN_00BEFDD0`, confirmed unlink-then-self-link shape matching
   * `SerHelperBase::ResetLinks()`) as its `atexit` target -- no eager
   * `RegisterSaveConstructArgsFunction`/`Init()` call exists in the real
   * ctor; that call was fabricated in the previous recovery's
   * `register_CParticleTextureSaveConstruct()` free function, invoked from
   * this file's own bootstrap struct. Removed.
   */
  class CParticleTextureSaveConstruct : public gpg::SerHelperBase
  {
  public:
    /**
     * Address: 0x00BC5270 (FUN_00BC5270, dynamic initializer for the global
     * `CParticleTextureSaveConstruct` singleton)
     *
     * What it does:
     * Default-constructs the `gpg::SerHelperBase` base and binds the
     * save-construct-args callback field.
     */
    CParticleTextureSaveConstruct();

    /**
     * Address: 0x00BEFDD0 (FUN_00BEFDD0, Moho::CParticleTextureSaveConstruct::~CParticleTextureSaveConstruct)
     *
     * What it does:
     * Unlinks this helper node from whatever intrusive list it currently
     * sits in and restores a self-linked sentinel state.
     */
    ~CParticleTextureSaveConstruct();

    /**
     * Address: 0x0048F010 (FUN_0048F010, Moho::CParticleTextureSaveConstruct::Construct)
     *
     * What it does:
     * Writes `CParticleTexture` save-construct args (`mTexturePath`) into the
     * archive and marks result payload as unowned.
     */
    static void Construct(
      gpg::WriteArchive* archive,
      CParticleTexture* texture,
      int version,
      gpg::RRef* ownerRef,
      gpg::SerSaveConstructArgsResult* result
    );

    /**
     * Address: 0x0048F9B0 (FUN_0048F9B0, gpg::SerSaveConstructHelper_CParticleTexture::Init)
     *
     * What it does:
     * Binds save-construct-args callback into `CParticleTexture` RTTI.
     */
    void Init() override;

  public:
    gpg::RType::save_construct_args_func_t mSerSaveConstructArgsFunc; // +0x0C
  };

  static_assert(
    offsetof(CParticleTextureSaveConstruct, mSerSaveConstructArgsFunc) == 0x0C,
    "CParticleTextureSaveConstruct::mSerSaveConstructArgsFunc offset must be 0x0C"
  );
  static_assert(sizeof(CParticleTextureSaveConstruct) == 0x10, "CParticleTextureSaveConstruct size must be 0x10");
} // namespace moho
