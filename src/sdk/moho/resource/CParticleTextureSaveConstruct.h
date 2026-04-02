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
   */
  class CParticleTextureSaveConstruct
  {
  public:
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
    virtual void RegisterSaveConstructArgsFunction();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::save_construct_args_func_t mSerSaveConstructArgsFunc;
  };

  /**
   * Address: 0x00BEFDD0 (FUN_00BEFDD0, Moho::CParticleTextureSaveConstruct::~CParticleTextureSaveConstruct)
   *
   * What it does:
   * Unlinks the save-construct helper node from the intrusive helper list.
   */
  gpg::SerHelperBase* cleanup_CParticleTextureSaveConstruct();

  /**
   * Address: 0x00BC5270 (FUN_00BC5270, register_CParticleTextureSaveConstruct)
   *
   * What it does:
   * Initializes callback slots for the global save-construct helper and
   * schedules teardown.
   */
  void register_CParticleTextureSaveConstruct();

  static_assert(
    offsetof(CParticleTextureSaveConstruct, mHelperNext) == 0x04,
    "CParticleTextureSaveConstruct::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CParticleTextureSaveConstruct, mHelperPrev) == 0x08,
    "CParticleTextureSaveConstruct::mHelperPrev offset must be 0x08"
  );
  static_assert(
    offsetof(CParticleTextureSaveConstruct, mSerSaveConstructArgsFunc) == 0x0C,
    "CParticleTextureSaveConstruct::mSerSaveConstructArgsFunc offset must be 0x0C"
  );
  static_assert(sizeof(CParticleTextureSaveConstruct) == 0x10, "CParticleTextureSaveConstruct size must be 0x10");
} // namespace moho
