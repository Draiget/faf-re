#include "moho/sim/SThreatSerializer.h"

#include <cstddef>
#include <cstdint>

#include "moho/sim/CInfluenceMap.h"

namespace moho
{
  /**
   * Address: 0x00717AF0 (FUN_00717AF0, Moho::SThreat::MemberDeserialize)
   *
   * What it does:
   * Reads one 14-float `SThreat` record from archive.
   */
  void SThreat::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (archive == nullptr) {
      return;
    }

    float* const lanes = reinterpret_cast<float*>(this);
    for (std::size_t i = 0; i < 14u; ++i) {
      archive->ReadFloat(&lanes[i]);
    }
  }

  /**
   * Address: 0x00717B00 (FUN_00717B00, Moho::SThreat::MemberSerialize)
   *
   * What it does:
   * Writes one 14-float `SThreat` record to archive.
   */
  void SThreat::MemberSerialize(gpg::WriteArchive* const archive) const
  {
    if (archive == nullptr) {
      return;
    }

    const float* const lanes = reinterpret_cast<const float*>(this);
    for (std::size_t i = 0; i < 14u; ++i) {
      archive->WriteFloat(lanes[i]);
    }
  }
} // namespace moho

namespace
{
  // Address: 0x00BDA780 (FUN_00BDA780, register_SThreatSerializer) -- MSVC's
  // own compiler-generated dynamic initializer for this global runs the real
  // `gpg::SerSaveLoadHelper<SThreat>` ctor (self-links into `sNewHelpers`,
  // binds `mLoadCallback`/`mSaveCallback` to the template's `Deserialize`/
  // `Serialize`, installs the vtable) and registers the real destructor
  // (0x00C00060, no recovered mangled name; body confirmed via raw asm to
  // just call `ResetLinks()`) via `atexit`. Dead zero-xref COMDAT duplicate
  // ctor: 0x00719340.
  moho::SThreatSerializer gSThreatSerializer;
} // namespace
