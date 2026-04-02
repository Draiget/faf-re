#include "moho/resource/CParticleTextureConstruct.h"

#include <cstdlib>
#include <new>

#include "moho/resource/CParticleTexture.h"
#include "moho/resource/CParticleTextureReflection.h"
#include "moho/resource/ResourceReflectionHelpers.h"

namespace gpg
{
  class SerConstructResult
  {
  public:
    void SetUnowned(const RRef& ref, unsigned int flags);
  };
} // namespace gpg

namespace
{
  moho::CParticleTextureConstruct gCParticleTextureConstruct;

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

  [[nodiscard]] gpg::RRef MakeCParticleTextureRef(moho::CParticleTexture* const object)
  {
    gpg::RRef ref{};
    gpg::RRef_CParticleTexture(&ref, object);
    return ref;
  }

  void CleanupCParticleTextureConstructAtexit()
  {
    (void)moho::cleanup_CParticleTextureConstruct();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x0048F140 (FUN_0048F140, Moho::CParticleTextureConstruct::Construct)
   *
   * What it does:
   * Reads archive construct args, allocates one `CParticleTexture`, and
   * returns it through `SerConstructResult` as unowned payload.
   */
  void CParticleTextureConstruct::Construct(
    gpg::ReadArchive* const archive, const int, const int, gpg::SerConstructResult* const result
  )
  {
    msvc8::string texturePath{};
    archive->ReadString(&texturePath);

    CParticleTexture* const object = new (std::nothrow) CParticleTexture(texturePath.c_str());
    const gpg::RRef objectRef = MakeCParticleTextureRef(object);
    result->SetUnowned(objectRef, 1u);

    texturePath.tidy(true, 0u);
  }

  /**
   * Address: 0x0048FFB0 (FUN_0048FFB0, Moho::CParticleTextureConstruct::Deconstruct)
   *
   * What it does:
   * Executes deleting-dtor teardown for one constructed `CParticleTexture`.
   */
  void CParticleTextureConstruct::Deconstruct(void* const objectPtr)
  {
    auto* const object = static_cast<CParticleTexture*>(objectPtr);
    if (object != nullptr) {
      delete object;
    }
  }

  /**
   * Address: 0x0048FA30 (FUN_0048FA30, gpg::SerConstructHelper_CParticleTexture::Init)
   *
   * What it does:
   * Resolves `CParticleTexture` RTTI and installs construct/delete callbacks.
   */
  void CParticleTextureConstruct::RegisterConstructFunction()
  {
    gpg::RType* const typeInfo = resource_reflection::ResolveCParticleTextureType();
    resource_reflection::RegisterConstructCallbacks(typeInfo, mConstructCallback, mDeleteCallback);
  }

  /**
   * Address: 0x00BEFE00 (FUN_00BEFE00, Moho::CParticleTextureConstruct::~CParticleTextureConstruct)
   *
   * What it does:
   * Unlinks the construct helper node from the intrusive helper list.
   */
  gpg::SerHelperBase* cleanup_CParticleTextureConstruct()
  {
    return UnlinkHelperNode(gCParticleTextureConstruct);
  }

  /**
   * Address: 0x00BC52A0 (FUN_00BC52A0, register_CParticleTextureConstruct)
   *
   * What it does:
   * Initializes callback slots for the global construct helper and schedules
   * teardown.
   */
  void register_CParticleTextureConstruct()
  {
    InitializeHelperNode(gCParticleTextureConstruct);
    gCParticleTextureConstruct.mConstructCallback =
      reinterpret_cast<gpg::RType::construct_func_t>(&CParticleTextureConstruct::Construct);
    gCParticleTextureConstruct.mDeleteCallback = &CParticleTextureConstruct::Deconstruct;
    gCParticleTextureConstruct.RegisterConstructFunction();
    (void)std::atexit(&CleanupCParticleTextureConstructAtexit);
  }
} // namespace moho

namespace
{
  struct CParticleTextureConstructBootstrap
  {
    CParticleTextureConstructBootstrap()
    {
      moho::register_CParticleTextureConstruct();
    }
  };

  CParticleTextureConstructBootstrap gCParticleTextureConstructBootstrap;
} // namespace
