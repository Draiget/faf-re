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
  moho::CParticleTextureSaveConstruct gCParticleTextureSaveConstruct;

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* HelperSelfNode(THelper& helper) noexcept
  {
    return reinterpret_cast<gpg::SerHelperBase*>(&helper.mHelperNext);
  }

  template <typename THelper>
  void InitializeHelperNode(THelper& helper) noexcept
  {
    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperNext = self;
    helper.mHelperPrev = self;
  }

  template <typename THelper>
  [[nodiscard]] gpg::SerHelperBase* UnlinkHelperNode(THelper& helper) noexcept
  {
    if (helper.mHelperNext != nullptr && helper.mHelperPrev != nullptr) {
      helper.mHelperNext->mPrev = helper.mHelperPrev;
      helper.mHelperPrev->mNext = helper.mHelperNext;
    }

    gpg::SerHelperBase* const self = HelperSelfNode(helper);
    helper.mHelperPrev = self;
    helper.mHelperNext = self;
    return self;
  }

  void CleanupCParticleTextureSaveConstructAtexit()
  {
    (void)moho::cleanup_CParticleTextureSaveConstruct();
  }
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
  void CParticleTextureSaveConstruct::RegisterSaveConstructArgsFunction()
  {
    gpg::RType* const typeInfo = resource_reflection::ResolveCParticleTextureType();
    resource_reflection::RegisterSaveConstructArgsCallback(typeInfo, mSerSaveConstructArgsFunc);
  }

  /**
   * Address: 0x00BEFDD0 (FUN_00BEFDD0, Moho::CParticleTextureSaveConstruct::~CParticleTextureSaveConstruct)
   *
   * What it does:
   * Unlinks the save-construct helper node from the intrusive helper list.
   */
  gpg::SerHelperBase* cleanup_CParticleTextureSaveConstruct()
  {
    return UnlinkHelperNode(gCParticleTextureSaveConstruct);
  }

  /**
   * Address: 0x00BC5270 (FUN_00BC5270, register_CParticleTextureSaveConstruct)
   *
   * What it does:
   * Initializes callback slots for the global save-construct helper and
   * schedules teardown.
   */
  void register_CParticleTextureSaveConstruct()
  {
    InitializeHelperNode(gCParticleTextureSaveConstruct);
    gCParticleTextureSaveConstruct.mSerSaveConstructArgsFunc =
      reinterpret_cast<gpg::RType::save_construct_args_func_t>(&CParticleTextureSaveConstruct::Construct);
    gCParticleTextureSaveConstruct.RegisterSaveConstructArgsFunction();
    (void)std::atexit(&CleanupCParticleTextureSaveConstructAtexit);
  }
} // namespace moho

namespace
{
  struct CParticleTextureSaveConstructBootstrap
  {
    CParticleTextureSaveConstructBootstrap()
    {
      moho::register_CParticleTextureSaveConstruct();
    }
  };

  CParticleTextureSaveConstructBootstrap gCParticleTextureSaveConstructBootstrap;
} // namespace
