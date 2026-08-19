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
