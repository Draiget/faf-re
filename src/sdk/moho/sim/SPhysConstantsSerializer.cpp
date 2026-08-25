#include "moho/sim/SPhysConstantsSerializer.h"

#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/utils/Global.h"
#include "moho/sim/SPhysConstants.h"
#include "moho/sim/SPhysConstantsTypeInfo.h"

namespace
{
  [[nodiscard]] gpg::RType* CachedVector3fType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(Wm3::Vec3f));
    }

    GPG_ASSERT(cached != nullptr);
    return cached;
  }
} // namespace

namespace moho
{
  gpg::RType* SPhysConstants::sType = nullptr;

  /**
   * Address: 0x00699C10 (FUN_00699C10, Moho::SPhysConstants::MemberDeserialize)
   */
  void SPhysConstants::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->Read(CachedVector3fType(), &mGravity, nullOwner);
  }

  /**
   * Address: 0x00699C50 (FUN_00699C50, Moho::SPhysConstants::MemberSerialize)
   */
  void SPhysConstants::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    GPG_ASSERT(archive != nullptr);
    if (!archive) {
      return;
    }

    const gpg::RRef nullOwner{};
    archive->Write(CachedVector3fType(), &mGravity, nullOwner);
  }
} // namespace moho

namespace
{
  // Address: 0x00BD6050 (FUN_00BD6050, dynamic initializer for the global
  // `SPhysConstantsSerializer` singleton, __xc_a-reachable) -- MSVC's own
  // compiler-generated dynamic initializer for this global runs the real
  // `gpg::SerSaveLoadHelper<SPhysConstants>` ctor (self-links into
  // `sNewHelpers`, binds `mLoadCallback`/`mSaveCallback` to the template's
  // `Deserialize`/`Serialize`, installs the vtable) and registers the real
  // destructor (0x00BFD460, no recovered mangled name; body confirmed via
  // raw asm to just call `ResetLinks()`) via `atexit`. Dead zero-xref COMDAT
  // duplicate ctor: 0x00699EA0.
  moho::SPhysConstantsSerializer gSPhysConstantsSerializer;
} // namespace
