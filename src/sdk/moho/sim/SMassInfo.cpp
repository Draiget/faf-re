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
   *   - `gSMassInfoSerializerBootstrap` file-scope static
   *     (`SMassInfoSerializer.cpp:180`).
   *   - `register_SMassInfoSerializer()` installs
   *     `&SMassInfoSerializer::Deserialize` as the typed
   *     `gpg::RType::serLoadFunc_` for `SMassInfo`.
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
   *   - Same `gSMassInfoSerializerBootstrap` lane as the deserialize
   *     path; `register_SMassInfoSerializer()` installs
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
