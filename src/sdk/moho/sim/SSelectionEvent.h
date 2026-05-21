#pragma once

namespace moho
{
  struct SSelectionSetUserEntity;

  /**
   * SSelectionEvent
   *
   * Layout evidence:
   * - Vftable name `??_7SelectionListener@Moho@@6B?$Listener@USSelectionEvent@Moho@@@Moho@@@`
   *   establishes the Listener template specialization for `Moho::SSelectionEvent`.
   * - Selection-event broadcast site (FUN_008986F0 in CWldSession.cpp) passes the
   *   event payload as 4 word-sized lanes after the listener `this`, which the
   *   MSVC8 ABI emits as a 16-byte by-value struct argument.
   * - The four lanes correspond to (previous selection, current selection,
   *   added selection, removed selection) — confirmed by `CWldSession::SetSelection`
   *   where the lanes are built from `&mSelection`, `incomingSelection`,
   *   `&addedEntities`, `&removedEntities` in this order.
   *
   * The event is passed by value: each lane is a pointer to a
   * `SSelectionSetUserEntity` (a.k.a. `WeakSet<UserEntity>`) that the listener
   * reads but does not own.
   */
  struct SSelectionEvent
  {
    SSelectionSetUserEntity* mPreviousSelection; // +0x00
    SSelectionSetUserEntity* mCurrentSelection;  // +0x04
    SSelectionSetUserEntity* mAddedEntities;     // +0x08
    SSelectionSetUserEntity* mRemovedEntities;   // +0x0C
  };

  static_assert(sizeof(SSelectionEvent) == 0x10, "SSelectionEvent size must be 0x10");
} // namespace moho
