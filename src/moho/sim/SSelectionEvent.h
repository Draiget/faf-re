#pragma once

namespace moho
{
  class UserEntity;
  template <class T>
  class WeakSet;

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
   * The event is passed by value: each lane points at a `WeakSet<UserEntity>`
   * the listener reads but does not own.
   */
  struct SSelectionEvent
  {
    const WeakSet<UserEntity>* mPreviousSelection; // +0x00
    const WeakSet<UserEntity>* mCurrentSelection;  // +0x04
    const WeakSet<UserEntity>* mAddedEntities;     // +0x08
    const WeakSet<UserEntity>* mRemovedEntities;   // +0x0C
  };

  static_assert(sizeof(SSelectionEvent) == 0x10, "SSelectionEvent size must be 0x10");
} // namespace moho
