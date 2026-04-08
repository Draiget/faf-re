#pragma once

#include <cstdint>

namespace moho
{
  /**
   * Address family:
   * - 0x0084ACA0 (FUN_0084ACA0, gpg::RRef_ESpecialFileType)
   * - 0x00844120/0x008445C0/0x00844F90/0x008455C0 special-file Lua binders
   *
   * What it does:
   * Enumerates profile-scoped special file buckets used by save/replay/screenshot
   * helper APIs.
   */
  enum ESpecialFileType : std::int32_t
  {
    SaveGame = 0,
    Replay = 1,
    Screenshot = 2,
    CampaignSave = 3,
  };

  static_assert(sizeof(ESpecialFileType) == 0x4, "ESpecialFileType size must be 0x4");
} // namespace moho
