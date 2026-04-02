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
   */
  class CParticleTextureConstruct
  {
  public:
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
    virtual void RegisterConstructFunction();

  public:
    gpg::SerHelperBase* mHelperNext;
    gpg::SerHelperBase* mHelperPrev;
    gpg::RType::construct_func_t mConstructCallback;
    gpg::RType::delete_func_t mDeleteCallback;
  };

  /**
   * Address: 0x00BEFE00 (FUN_00BEFE00, Moho::CParticleTextureConstruct::~CParticleTextureConstruct)
   *
   * What it does:
   * Unlinks the construct helper node from the intrusive helper list.
   */
  gpg::SerHelperBase* cleanup_CParticleTextureConstruct();

  /**
   * Address: 0x00BC52A0 (FUN_00BC52A0, register_CParticleTextureConstruct)
   *
   * What it does:
   * Initializes callback slots for the global construct helper and schedules
   * teardown.
   */
  void register_CParticleTextureConstruct();

  static_assert(
    offsetof(CParticleTextureConstruct, mHelperNext) == 0x04,
    "CParticleTextureConstruct::mHelperNext offset must be 0x04"
  );
  static_assert(
    offsetof(CParticleTextureConstruct, mHelperPrev) == 0x08,
    "CParticleTextureConstruct::mHelperPrev offset must be 0x08"
  );
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
