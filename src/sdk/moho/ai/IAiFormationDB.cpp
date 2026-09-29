#include "moho/ai/IAiFormationDB.h"

#include <new>

#include "moho/misc/WeakPtr.h"
#include "moho/unit/core/Unit.h"

namespace
{
  /// The set words are `Entity*` (the `EntitySetTemplate<Unit>` shape the
  /// serializer at Unit.cpp uses for `GuardedByList`): `Unit`'s `Entity`
  /// base sits at +0x08 and its `IUnit` weak-link head at +0x04, which is why
  /// `CAiFormationDBImpl::NewFormation` (0x0059C120, 0x0059C176-0x0059C184)
  /// rebases each word by `-8 + 4` and treats both 0 and 8 (a null unit's
  /// `Entity` subobject) as empty.
  constexpr std::uint32_t kEmptyFormationWeakRefWord = 0u;

  // `Unit`'s `Entity` base offset (0x08 on x86): the word a null unit encodes to.
  [[nodiscard]] std::uint32_t NullUnitEntityWord() noexcept
  {
    return static_cast<std::uint32_t>(gpg::BaseSubobjectOffset<moho::Unit, moho::Entity>());
  }
}

using namespace moho;

/**
 * What it does:
 * Encodes one unit as the `Entity*` word the formation sets carry -- the
 * `Unit`'s `Entity` base subobject, `unit + 0x08` (the `Unit::GuardedByList`
 * writers in Unit.cpp produce the same word). A null unit stays null.
 */
SFormationUnitWeakRef SFormationUnitWeakRef::FromUnit(Unit* const unit) noexcept
{
  SFormationUnitWeakRef ref{};
  Entity* const entity = unit != nullptr ? static_cast<Entity*>(unit) : nullptr;
  ref.ownerLinkSlotWord = static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(entity));
  return ref;
}

std::uint32_t* SFormationUnitWeakRef::DecodeOwnerChainHead() const noexcept
{
  // FUN_0059C120 treats {0, 8} as empty words: null, and a null unit's Entity.
  if (ownerLinkSlotWord == kEmptyFormationWeakRefWord || ownerLinkSlotWord == NullUnitEntityWord()) {
    return nullptr;
  }

  // Rebase the Entity word to its Unit (`-8` on x86), then to the IUnit
  // weak-link head (`+4`).
  auto* const entity = reinterpret_cast<Entity*>(static_cast<std::uintptr_t>(ownerLinkSlotWord));
  IUnit* const unit = static_cast<Unit*>(entity);
  return reinterpret_cast<std::uint32_t*>(reinterpret_cast<std::uintptr_t>(unit) + WeakPtr<IUnit>::kOwnerLinkOffset);
}

/**
 * Address: 0x0059C360 (FUN_0059C360)
 */
IAiFormationDB::IAiFormationDB() = default;

/**
 * Address: 0x0059A3C0 (FUN_0059A3C0)
 *
 * What it does:
 * Alternate in-place constructor adapter for one IAiFormationDB interface
 * subobject lane.
 */
[[maybe_unused]] IAiFormationDB* InitializeIAiFormationDBInterfaceLane(
  IAiFormationDB* const objectStorage
) noexcept
{
  if (objectStorage == nullptr) {
    return nullptr;
  }

  return objectStorage;
}

/**
 * Address: 0x0059A3D0 (FUN_0059A3D0)
 */
IAiFormationDB::~IAiFormationDB() = default;
