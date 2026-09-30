#include "moho/sim/SMassInfo.h"

#include <typeinfo>

#include "gpg/core/containers/ReadArchive.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "moho/containers/SCoordsVec2.h"

namespace
{
  [[nodiscard]] gpg::RType* CachedSCoordsVec2Type()
  {
    gpg::RType* type = moho::SCoordsVec2::sType;
    if (!type) {
      type = gpg::LookupRType(typeid(moho::SCoordsVec2));
      moho::SCoordsVec2::sType = type;
    }
    return type;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00593030 (FUN_00593030, Moho::SMassInfo::MemberDeserialize)
   *
   * What it does:
   * Reads the embedded `SCoordsVec2 mPosition` (`+0x00`, 8 bytes) via
   * reflection-driven `gpg::ReadArchive::Read` against the cached
   * `SCoordsVec2` RType, then reads the trailing `float mVal` (`+0x08`).
   *
   * Caller chain (from CRT static-init root):
   *   - `gSMassInfoSerializer` file-scope global
   *     (`SMassInfoSerializer.cpp`) default-constructs, binding
   *     `&SMassInfoSerializer::Deserialize` into `mLoadCallback`.
   *   - `SMassInfoSerializer::Init()` installs that callback as the
   *     typed `gpg::RType::serLoadFunc_` for `SMassInfo`.
   *   - At deserialization time `gpg::ReadArchive::Read` resolves the
   *     load callback by type and dispatches into
   *     `SMassInfoSerializer::Deserialize`, which forwards to this
   *     `SMassInfo::MemberDeserialize`.
   */
  void SMassInfo::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (archive == nullptr) {
      return;
    }

    gpg::RType* const coordsType = CachedSCoordsVec2Type();
    gpg::RRef ownerRef{};
    archive->Read(coordsType, &mPosition, ownerRef);
    archive->ReadFloat(&mVal);
  }

  /**
   * Address: 0x00593080 (FUN_00593080, Moho::SMassInfo::MemberSerialize)
   *
   * What it does:
   * Mirror of `MemberDeserialize`: writes the `SCoordsVec2 mPosition`
   * payload via reflection, then writes the trailing `float mVal`.
   *
   * Caller chain (from CRT static-init root):
   *   - Same `gSMassInfoSerializer` global as the deserialize path;
   *     `SMassInfoSerializer::Init()` installs
   *     `&SMassInfoSerializer::Serialize` as `gpg::RType::serSaveFunc_`.
   *   - At save time `gpg::WriteArchive::Write` resolves the save
   *     callback by type and dispatches into
   *     `SMassInfoSerializer::Serialize`, which forwards to this
   *     `SMassInfo::MemberSerialize`.
   */
  void SMassInfo::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (archive == nullptr) {
      return;
    }

    gpg::RType* const coordsType = CachedSCoordsVec2Type();
    gpg::RRef ownerRef{};
    archive->Write(coordsType, &mPosition, ownerRef);
    archive->WriteFloat(mVal);
  }
} // namespace moho

namespace moho
{
  /**
   * `gpg::SerSaveLoadHelper<SMassInfo>`, vtable 0x00E1AF4C.
   *
   * Address: 0x00BCB700 (FUN_00BCB700 -- constructs the global and registers its destructor.)
   * Address: 0x00BF64C0 (FUN_00BF64C0 -- the global's destructor.)
   * Address: 0x00591B90 (FUN_00591B90 -- `Init`.)
   * Address: 0x00585E10 (FUN_00585E10 -- `Deserialize`, a forward to `MemberDeserialize`.)
   * Address: 0x00585E20 (FUN_00585E20 -- `Serialize`, a forward to `MemberSerialize`.)
   */
  struct SMassInfoSerializer : gpg::SerSaveLoadHelper<SMassInfo>
  {};
} // namespace moho

namespace
{
  // Address: 0x010AE004 -- process-global `SMassInfoSerializer` singleton.
  moho::SMassInfoSerializer gSMassInfoSerializer;
} // namespace
