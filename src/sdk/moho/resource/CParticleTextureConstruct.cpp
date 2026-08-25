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
  [[nodiscard]] gpg::RRef MakeCParticleTextureRef(moho::CParticleTexture* const object)
  {
    gpg::RRef ref{};
    gpg::RRef_CParticleTexture(&ref, object);
    return ref;
  }

  // Address: 0x010A8024 -- process-global `CParticleTextureConstruct`
  // singleton (constructed by FUN_00BC52A0, self-registering via `__xc_a`;
  // see CParticleTextureConstruct.h for the real-ctor/atexit-target evidence).
  moho::CParticleTextureConstruct gCParticleTextureConstruct;
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
  void CParticleTextureConstruct::Init()
  {
    gpg::RType* const typeInfo = resource_reflection::ResolveCParticleTextureType();
    resource_reflection::RegisterConstructCallbacks(typeInfo, mConstructCallback, mDeleteCallback);
  }

  /**
   * Address: 0x00BC52A0 (FUN_00BC52A0, dynamic initializer for the global
   * `CParticleTextureConstruct` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * construct/delete callback fields.
   */
  CParticleTextureConstruct::CParticleTextureConstruct()
    : mConstructCallback(reinterpret_cast<gpg::RType::construct_func_t>(&CParticleTextureConstruct::Construct))
    , mDeleteCallback(&CParticleTextureConstruct::Deconstruct)
  {}

  CParticleTextureConstruct::~CParticleTextureConstruct()
  {
    ResetLinks();
  }
} // namespace moho
