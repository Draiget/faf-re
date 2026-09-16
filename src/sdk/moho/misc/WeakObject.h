#pragma once
#include <cstdint>

namespace moho
{
  class WeakObject
  {
  public:
    using WeakLinkSlot = void**;

    struct WeakLinkNodeView
    {
      WeakLinkSlot ownerLinkSlot;
      WeakLinkNodeView* nextInOwner;
    };

    class ScopedWeakLinkGuard final
    {
    public:
      explicit ScopedWeakLinkGuard(WeakObject* owner) noexcept
      {
        m_ownerLinkSlot = owner ? owner->WeakLinkHeadSlot() : nullptr;
        if (!m_ownerLinkSlot) {
          return;
        }

        m_prev = *m_ownerLinkSlot;
        *m_ownerLinkSlot = MarkerSlot();
      }

      ~ScopedWeakLinkGuard()
      {
        Restore();
      }

      ScopedWeakLinkGuard(const ScopedWeakLinkGuard&) = delete;
      ScopedWeakLinkGuard& operator=(const ScopedWeakLinkGuard&) = delete;

      [[nodiscard]]
      const WeakLinkSlot* OwnerLinkSlotAddress() const noexcept
      {
        return m_ownerLinkSlot;
      }

    private:
      [[nodiscard]] WeakLinkSlot MarkerSlot() const noexcept
      {
        return reinterpret_cast<WeakLinkSlot>(const_cast<WeakLinkSlot**>(&m_ownerLinkSlot));
      }

      [[nodiscard]] WeakLinkNodeView* MarkerNode() const noexcept
      {
        return reinterpret_cast<WeakLinkNodeView*>(MarkerSlot());
      }

      void Restore() noexcept
      {
        if (!m_ownerLinkSlot) {
          return;
        }

        auto** cursor = reinterpret_cast<WeakLinkNodeView**>(m_ownerLinkSlot);
        while (*cursor != MarkerNode()) {
          cursor = &((*cursor)->nextInOwner);
        }

        *cursor = reinterpret_cast<WeakLinkNodeView*>(m_prev);
        m_ownerLinkSlot = nullptr;
        m_prev = nullptr;
      }

    private:
      WeakLinkSlot* m_ownerLinkSlot = nullptr;
      WeakLinkSlot m_prev = nullptr;
    };

    [[nodiscard]] WeakLinkSlot* WeakLinkHeadSlot() noexcept
    {
      return reinterpret_cast<WeakLinkSlot*>(&weakLinkHead_);
    }

    [[nodiscard]] const WeakLinkSlot* WeakLinkHeadSlot() const noexcept
    {
      return reinterpret_cast<const WeakLinkSlot*>(&weakLinkHead_);
    }

  public:
    /**
     * Drops every weak reference still aimed at this object, blanking each
     * node's owner slot and forward link as it leaves the chain.
     *
     * Owners run this when they are torn down, so that a weak holder outliving
     * the owner observes a detached node rather than a dangling owner slot.
     * The walk is destructive and leaves the head slot empty.
     *
     * The compiler inlines this into every owner destructor rather than
     * emitting a callable body, which is why it has no address of its own.
     * `~CScriptObject` (0x004C7340) carries the canonical emission, and it
     * fixes the layout too -- the head is read at `[esi+4]`, i.e. `WeakObject`
     * sits immediately after `CScriptObject`'s vptr:
     *
     *     0x004C73BF  8B 46 04           mov  eax, [esi+4]     ; head
     *     0x004C73C2  85 C0 / 74 24      test eax,eax / jz end
     *   loop:
     *     0x004C73D0  8B 50 04           mov  edx, [eax+4]     ; node->nextInOwner
     *     0x004C73D3  89 56 04           mov  [esi+4], edx     ; head = next
     *     0x004C73D6  C7 00 00 00 00 00  mov  dword [eax], 0   ; ownerLinkSlot = 0
     *     0x004C73DC  C7 40 04 00 ...    mov  dword [eax+4], 0 ; nextInOwner  = 0
     *     0x004C73E3  8B 46 04           mov  eax, [esi+4]     ; reload head
     *     0x004C73E6  85 C0 / 75 E6      test eax,eax / jnz loop
     *
     * Note it re-reads the head each iteration instead of following `edx`, so
     * a node that relinks itself while being blanked is still handled. Three
     * hand-written `ClearWeakObjectChain` copies of this loop (in
     * CScriptObject.cpp, Unit.cpp and CAcquireTargetTask.cpp) were folded back
     * into this member on 2026-09-16; the programmer wrote one method and the
     * compiler inlined it, which is what the single `[esi+4]` shape above says.
     */
    void DetachAllWeakReferences() noexcept
    {
      auto** cursor = reinterpret_cast<WeakLinkNodeView**>(WeakLinkHeadSlot());
      while (*cursor != nullptr) {
        WeakLinkNodeView* const node = *cursor;
        *cursor = node->nextInOwner;
        node->ownerLinkSlot = nullptr;
        node->nextInOwner = nullptr;
      }
    }

    // Head link slot for intrusive weak-guard / weak-pointer chains.
    // WeakPtr<T>::ownerLinkSlot points to this slot in owner objects.
    uint32_t weakLinkHead_;
  };

  static_assert(sizeof(WeakObject) == 4, "WeakObject must be 4 bytes");
} // namespace moho
