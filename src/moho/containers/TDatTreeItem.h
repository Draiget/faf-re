#pragma once
#include <cstdint>

namespace moho
{
  /**
   * Intrusive tree base: each item sits in its parent's circular child list and
   * heads its own. `T` is the most-derived type; the base follows its vptr, so
   * the offsets below are the derived object's.
   */
  template <class T>
  struct TDatTreeItem
  {
    /** One link of a circular list: an item's place among its siblings, or a list head. */
    struct Link
    {
      Link* mPrev;
      Link* mNext;
    };

    /** An item's own link, with its parent and the item itself. */
    struct Node : Link
    {
      T* mParent;
      T* mOwner;
    };

    /** The item a sibling link belongs to (every link but a list head is a `Node`). */
    [[nodiscard]] static T* OwnerOf(
      Link* const link
    ) noexcept
    {
      return static_cast<Node*>(link)->mOwner;
    }

    Node mSiblings; // +0x04 prev, +0x08 next, +0x0C parent, +0x10 owner
    Link mChildren; // +0x14 head of the child list
    T* mChildOwner; // +0x1C
  };
} // namespace moho
