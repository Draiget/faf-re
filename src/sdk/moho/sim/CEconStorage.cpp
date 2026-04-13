#include "moho/sim/CEconStorage.h"

#include <typeinfo>

#include "gpg/core/containers/ArchiveSerialization.h"
#include "gpg/core/containers/WriteArchive.h"
#include "gpg/core/reflection/Reflection.h"
#include "gpg/core/utils/Global.h"
#include "moho/sim/CEconomy.h"

namespace
{
  [[nodiscard]] gpg::RType* CachedSEconValueType()
  {
    if (moho::SEconValue::sType == nullptr) {
      moho::SEconValue::sType = gpg::LookupRType(typeid(moho::SEconValue));
    }
    return moho::SEconValue::sType;
  }

  /**
   * Address: 0x00774B80 (FUN_00774B80)
   *
   * What it does:
   * Serializes one `CEconomy*` slot as an unowned tracked pointer and returns
   * the archive for callback chaining.
   */
  [[nodiscard]] gpg::WriteArchive*
  SerializeUnownedCEconomyPointer(moho::CEconomy** const economySlot, gpg::WriteArchive* const archive)
  {
    if (archive == nullptr || economySlot == nullptr) {
      return archive;
    }

    gpg::RRef economyRef{};
    economyRef.mObj = *economySlot;
    economyRef.mType = gpg::LookupRType(typeid(moho::CEconomy));
    GPG_ASSERT(economyRef.mType != nullptr);
    gpg::WriteRawPointer(archive, economyRef, gpg::TrackedPointerState::Unowned, gpg::RRef{});
    return archive;
  }

  /**
   * Address: 0x00774BC0 (FUN_00774BC0)
   *
   * What it does:
   * Binary-write callback variant of unowned `CEconomy*` slot serialization.
   */
  [[maybe_unused]] void
  SerializeUnownedCEconomyPointerBinary(moho::CEconomy** const economySlot, gpg::WriteArchive* const archive)
  {
    (void)SerializeUnownedCEconomyPointer(economySlot, archive);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00774990 (FUN_00774990, Moho::CEconStorage::MemberDeserialize)
   *
   * What it does:
   * Deserializes referenced economy owner pointer, then reads one reflected
   * `SEconValue` payload lane.
   */
  void CEconStorage::MemberDeserialize(gpg::ReadArchive* const archive)
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef nullOwner{};

    (void)archive->ReadPointer_CEconomy(&mEconomy, &nullOwner);

    gpg::RType* const econValueType = CachedSEconValueType();
    GPG_ASSERT(econValueType != nullptr);
    archive->Read(econValueType, &mAmt, nullOwner);
  }

  /**
   * Address: 0x007749F0 (FUN_007749F0, Moho::CEconStorage::MemberSerialize)
   *
   * What it does:
   * Serializes referenced economy owner as an unowned pointer, then writes
   * one reflected `SEconValue` payload lane.
   */
  void CEconStorage::MemberSerialize(gpg::WriteArchive* const archive)
  {
    if (archive == nullptr) {
      return;
    }

    const gpg::RRef nullOwner{};

    (void)SerializeUnownedCEconomyPointer(&mEconomy, archive);

    gpg::RType* const econValueType = CachedSEconValueType();
    GPG_ASSERT(econValueType != nullptr);
    archive->Write(econValueType, &mAmt, nullOwner);
  }
} // namespace moho
