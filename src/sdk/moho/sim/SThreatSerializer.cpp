#include "moho/sim/SThreatSerializer.h"

#include <cstddef>
#include <cstdint>

#include "moho/sim/CInfluenceMap.h"

namespace moho
{
  /**
   * Address: 0x00BDA780 (FUN_00BDA780, dynamic initializer for the global
   * `SThreatSerializer` singleton)
   *
   * What it does:
   * Default-constructs the `gpg::SerHelperBase` base and binds the
   * load/save callback fields.
   */
  SThreatSerializer::SThreatSerializer()
    : mLoadCallback(&SThreatSerializer::Deserialize)
    , mSaveCallback(&SThreatSerializer::Serialize)
  {}

  SThreatSerializer::~SThreatSerializer()
  {
    ResetLinks();
  }

  /**
   * Address: 0x00717AF0 (FUN_00717AF0, Moho::SThreatSerializer::Deserialize)
   *
   * What it does:
   * Reads one 14-float `SThreat` record from archive.
   */
  void SThreatSerializer::Deserialize(gpg::ReadArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    auto* const threat = reinterpret_cast<SThreat*>(static_cast<std::uintptr_t>(objectPtr));
    if (archive == nullptr || threat == nullptr) {
      return;
    }

    float* const lanes = reinterpret_cast<float*>(threat);
    for (std::size_t i = 0; i < 14u; ++i) {
      archive->ReadFloat(&lanes[i]);
    }
  }

  /**
   * Address: 0x00717B00 (FUN_00717B00, Moho::SThreatSerializer::Serialize)
   *
   * What it does:
   * Writes one 14-float `SThreat` record to archive.
   */
  void SThreatSerializer::Serialize(gpg::WriteArchive* const archive, const int objectPtr, const int, gpg::RRef*)
  {
    const auto* const threat = reinterpret_cast<const SThreat*>(static_cast<std::uintptr_t>(objectPtr));
    if (archive == nullptr || threat == nullptr) {
      return;
    }

    const float* const lanes = reinterpret_cast<const float*>(threat);
    for (std::size_t i = 0; i < 14u; ++i) {
      archive->WriteFloat(lanes[i]);
    }
  }

  /**
   * Address: 0x00719370 (FUN_00719370, gpg::SerSaveLoadHelper_SThreat::Init)
   *
   * IDA signature:
   * void (__cdecl *__thiscall sub_719370(void (__cdecl **this)(...)))(...);
   */
  void SThreatSerializer::Init()
  {
    gpg::RType* const type = SThreat::StaticGetClass();
    GPG_ASSERT(type->serLoadFunc_ == nullptr);
    type->serLoadFunc_ = mLoadCallback;
    GPG_ASSERT(type->serSaveFunc_ == nullptr);
    type->serSaveFunc_ = mSaveCallback;
  }
} // namespace moho

namespace
{
  // Address: 0x010B945C -- process-global `SThreatSerializer` singleton.
  moho::SThreatSerializer gSThreatSerializer;
} // namespace
