#include "moho/resource/CParticleTextureSaveConstruct.h"

#include <cstdlib>

#include "moho/resource/CParticleTexture.h"
#include "moho/resource/ResourceReflectionHelpers.h"

namespace gpg
{
  class SerSaveConstructArgsResult
  {
  public:
    void SetUnowned(unsigned int value);
  };
} // namespace gpg

namespace
{
  // Address: 0x010A7F88 -- process-global `CParticleTextureSaveConstruct`
  // singleton (constructed by FUN_00BC5270, self-registering via `__xc_a`;
  // see CParticleTextureSaveConstruct.h for the real-ctor/atexit-target
  // evidence).
  moho::CParticleTextureSaveConstruct gCParticleTextureSaveConstruct;
} // namespace

namespace moho
{
  /**
   * Address: 0x0048F010 (FUN_0048F010, Moho::CParticleTextureSaveConstruct::Construct)
   *
   * What it does:
   * Writes `CParticleTexture` save-construct args (`mTexturePath`) into the
   * archive and marks result payload as unowned.
   */
  void CParticleTextureSaveConstruct::Construct(
    gpg::WriteArchive* const archive,
    CParticleTexture* const texture,
    const int,
    gpg::RRef* const,
    gpg::SerSaveConstructArgsResult* const result
  )
  {
    archive->WriteString(&texture->mTexturePath);
    result->SetUnowned(1u);
  }

  /**
   * Address: 0x0048F9B0 (FUN_0048F9B0, gpg::SerSaveConstructHelper_CParticleTexture::Init)
   *
   * What it does:
   * Resolves `CParticleTexture` RTTI and installs save-construct-args callback.
   */
  void CParticleTextureSaveConstruct::Init()
  {
    gpg::RType* const typeInfo = resource_reflection::ResolveCParticleTextureType();
    resource_reflection::RegisterSaveConstructArgsCallback(typeInfo, mSerSaveConstructArgsFunc);
  }

  /**
   * Address: 0x00BC5270 (FUN_00BC5270, dynamic initializer for the global
   * `CParticleTextureSaveConstruct` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * save-construct-args callback field.
   */
  CParticleTextureSaveConstruct::CParticleTextureSaveConstruct()
    : mSerSaveConstructArgsFunc(reinterpret_cast<gpg::RType::save_construct_args_func_t>(&CParticleTextureSaveConstruct::Construct))
  {}

  CParticleTextureSaveConstruct::~CParticleTextureSaveConstruct()
  {
    ResetLinks();
  }
} // namespace moho
