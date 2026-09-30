
#include <cstddef>
#include <cstdlib>
#include <typeinfo>

#include "gpg/core/utils/Global.h"
#include "legacy/containers/Vector.h"
#include "moho/resource/CSimResources.h"
#include "moho/resource/ResourceDeposit.h"
#include "moho/resource/ResourceReflectionHelpers.h"
#include "gpg/core/reflection/Reflection.h"

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

} // namespace

namespace moho
{
  /**
   * Inlined into `gpg::SerSaveLoadHelper<CSimResources>::Deserialize` 0x00546B80.
   */
  void CSimResources::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    gpg::RType* const vectorType = ResolveResourceDepositVectorType();
    GPG_ASSERT(vectorType != nullptr);
    archive->Read(vectorType, &deposits_, NullOwnerRef());
  }

  /**
   * Inlined into `gpg::SerSaveLoadHelper<CSimResources>::Serialize` 0x00546BD0.
   */
  void CSimResources::MemberSerialize(gpg::WriteArchive* const archive)
  {
    gpg::RType* const vectorType = ResolveResourceDepositVectorType();
    GPG_ASSERT(vectorType != nullptr);
    archive->Write(vectorType, &deposits_, NullOwnerRef());
  }
} // namespace moho

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<CSimResources>`, vtable 0x00E171E4.
   *
   * Address: 0x00BC96D0 (FUN_00BC96D0 -- constructs the global and registers its destructor.)
   * Address: 0x00BF42C0 (FUN_00BF42C0 -- the global's destructor.)
   * Address: 0x00546C20 (FUN_00546C20 -- an unreferenced out-of-line copy of the constructor.)
   * Address: 0x00547870 (FUN_00547870 -- `Init`.)
   * Address: 0x00546B80 (FUN_00546B80 -- `Deserialize`, `MemberDeserialize` inlined.)
   * Address: 0x00546BD0 (FUN_00546BD0 -- `Serialize`, `MemberSerialize` inlined.)
   */
  struct CSimResourcesSerializer : gpg::SerSaveLoadHelper<CSimResources>
  {};
} // namespace moho

namespace
{
  // Address: 0x010ABFDC -- process-global `CSimResourcesSerializer` singleton.
  moho::CSimResourcesSerializer gCSimResourcesSerializer;
} // namespace
