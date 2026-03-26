#include "moho/ai/IAiFormationDB.h"

#include "moho/misc/WeakPtr.h"

namespace
{
  constexpr std::uint32_t kEmptyFormationWeakRefWord = 0u;
  constexpr std::uint32_t kUnitOwnerLinkOffsetWord = static_cast<std::uint32_t>(moho::WeakPtr<moho::Unit>::kOwnerLinkOffset);
  constexpr std::uint32_t kEmptyFormationWeakRefNextWord = kUnitOwnerLinkOffsetWord + sizeof(std::uint32_t);

  static_assert(kUnitOwnerLinkOffsetWord == 0x04, "Formation weak-ref slot encoding expects Unit owner-link offset 0x04");
}

using namespace moho;

SFormationUnitWeakRef SFormationUnitWeakRef::FromUnit(Unit* const unit) noexcept
{
  SFormationUnitWeakRef ref{};
  ref.ownerLinkSlotWord = static_cast<std::uint32_t>(
    reinterpret_cast<std::uintptr_t>(WeakPtr<Unit>::EncodeOwnerLinkSlot(unit))
  );
  return ref;
}

std::uint32_t* SFormationUnitWeakRef::DecodeOwnerChainHead() const noexcept
{
  // FUN_0059C120 treats {0, 8} as empty words; `4` also decodes to null via the subtract path.
  if (ownerLinkSlotWord == kEmptyFormationWeakRefWord || ownerLinkSlotWord == kEmptyFormationWeakRefNextWord) {
    return nullptr;
  }

  return reinterpret_cast<std::uint32_t*>(static_cast<std::uintptr_t>(ownerLinkSlotWord - kUnitOwnerLinkOffsetWord));
}

/**
 * Address: 0x0059A3D0 (FUN_0059A3D0)
 */
IAiFormationDB::~IAiFormationDB() = default;
