
#include <cstdint>
#include <cstdlib>
#include <typeinfo>

#include "moho/ai/CAiTransportImpl.h"
#include "gpg/core/reflection/Reflection.h"

using namespace moho;

namespace
{
  [[nodiscard]] gpg::RType* CachedVector3fType()
  {
    static gpg::RType* cached = nullptr;
    if (!cached) {
      cached = gpg::LookupRType(typeid(Wm3::Vector3<float>));
    }
    return cached;
  }

} // namespace

namespace moho
{
  /**
   * Address: 0x005EB980 (FUN_005EB980)
   *
   * What it does:
   * Deserializes one `SAttachPoint` payload lane (`index`, `localPos`,
   * `distSq`) from the archive.
   */
  void SAttachPoint::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    archive->ReadUInt(&index);

    const gpg::RRef ownerRef{};
    gpg::RType* const vectorType = CachedVector3fType();
    GPG_ASSERT(vectorType != nullptr);
    archive->Read(vectorType, &localPos, ownerRef);

    archive->ReadFloat(&distSq);
  }

  /**
   * Address: 0x005EB9E0 (FUN_005EB9E0)
   *
   * What it does:
   * Serializes one `SAttachPoint` payload lane (`index`, `localPos`,
   * `distSq`) into the archive.
   */
  void SAttachPoint::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    archive->WriteUInt(index);

    const gpg::RRef ownerRef{};
    gpg::RType* const vectorType = CachedVector3fType();
    GPG_ASSERT(vectorType != nullptr);
    archive->Write(vectorType, &localPos, ownerRef);

    archive->WriteFloat(distSq);
  }
} // namespace moho

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<SAttachPoint>`, vtable 0x00E1F2F4.
   *
   * Address: 0x00BCEDF0 (FUN_00BCEDF0 -- constructs the global and registers its destructor.)
   * Address: 0x00BF8A90 (FUN_00BF8A90 -- the global's destructor.)
   * Address: 0x005E91E0 (FUN_005E91E0 -- `Init`.)
   * Address: 0x005E42E0 (FUN_005E42E0 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x005E42F0 (FUN_005E42F0 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct SAttachPointSerializer : gpg::SerSaveLoadHelper<SAttachPoint>
  {};
} // namespace moho

namespace
{
  // Address: 0x010B07C4 -- process-global `SAttachPointSerializer` singleton.
  moho::SAttachPointSerializer gSAttachPointSerializer;
} // namespace
