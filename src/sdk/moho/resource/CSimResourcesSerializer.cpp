#include "moho/resource/CSimResourcesSerializer.h"

#include <cstdlib>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "legacy/containers/Vector.h"
#include "moho/resource/CSimResources.h"
#include "moho/resource/ResourceDeposit.h"
#include "moho/resource/ResourceReflectionHelpers.h"

namespace
{
  [[nodiscard]] const gpg::RRef& NullOwnerRef() noexcept
  {
    static const gpg::RRef kNullOwner{nullptr, nullptr};
    return kNullOwner;
  }

  [[nodiscard]] gpg::RType* ResolveResourceDepositVectorType()
  {
    static gpg::RType* sType = nullptr;
    if (sType == nullptr) {
      sType = gpg::LookupRType(typeid(msvc8::vector<moho::ResourceDeposit>));
    }
    return sType;
  }

  // Address: 0x010ABFDC -- process-global `CSimResourcesSerializer` singleton
  // (constructed by FUN_00BC96D0, self-registering via `__xc_a`; see
  // CSimResourcesSerializer.h for the real-ctor/atexit-target/dead-duplicate
  // evidence).
  moho::CSimResourcesSerializer gCSimResourcesSerializer;
} // namespace

namespace moho
{
  /**
   * Address: 0x00546B80 (FUN_00546B80, Moho::CSimResourcesSerializer::Deserialize)
   */
  void CSimResourcesSerializer::Deserialize(gpg::ReadArchive* const archive, int objectPtr, int, gpg::RRef*)
  {
    CSimResources* const object = reinterpret_cast<CSimResources*>(objectPtr);
    gpg::RType* const vectorType = ResolveResourceDepositVectorType();
    GPG_ASSERT(vectorType != nullptr);
    archive->Read(vectorType, &object->deposits_, NullOwnerRef());
  }

  /**
   * Address: 0x00546BD0 (FUN_00546BD0, Moho::CSimResourcesSerializer::Serialize)
   */
  void CSimResourcesSerializer::Serialize(gpg::WriteArchive* const archive, int objectPtr, int, gpg::RRef*)
  {
    CSimResources* const object = reinterpret_cast<CSimResources*>(objectPtr);
    gpg::RType* const vectorType = ResolveResourceDepositVectorType();
    GPG_ASSERT(vectorType != nullptr);
    archive->Write(vectorType, &object->deposits_, NullOwnerRef());
  }

  /**
   * Address: 0x00547870 (FUN_00547870, gpg::SerSaveLoadHelper_CSimResources::Init)
   */
  void CSimResourcesSerializer::Init()
  {
    gpg::RType* const typeInfo = resource_reflection::ResolveCSimResourcesType();
    resource_reflection::RegisterSerializeCallbacks(typeInfo, mDeserialize, mSerialize);
  }

  /**
   * Address: 0x00BC96D0 (FUN_00BC96D0, dynamic initializer for the global
   * `CSimResourcesSerializer` singleton)
   */
  CSimResourcesSerializer::CSimResourcesSerializer()
    : mDeserialize(&CSimResourcesSerializer::Deserialize)
    , mSerialize(&CSimResourcesSerializer::Serialize)
  {}

  CSimResourcesSerializer::~CSimResourcesSerializer()
  {
    ResetLinks();
  }
} // namespace moho
