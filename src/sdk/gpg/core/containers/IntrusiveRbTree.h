#pragma once
#include <cstdint>
#include <iterator>
#include <type_traits>

namespace gpg::core
{
    /**
	 * Intrusive RB-tree view compatible with MSVC8-style sentinel head.
	 *
	 * Layout assumptions (parametrized):
	 * - Container stores a sentinel "head" node at (container_base + kHeadNodeOffset).
	 * - Each node has pointers: left @ kLeftOff, parent @ kParentOff, right @ kRightOff (DWORD each).
	 * - The intrusive node is embedded inside the owner object at offset kNodeEmbedOff
	 *   so that:  node_addr == (owner_addr + kNodeEmbedOff)
	 *             owner_addr == (node_addr - kNodeEmbedOff)
	 *
	 * We don't need the color bit for in-order iteration, so it's omitted.
	 */
    template<
        typename OwnerT,
        std::size_t kNodeEmbedOff,            // offset of embedded rb-node inside OwnerT
        std::size_t kHeadNodeOffset = 8,      // where the sentinel "head" lies inside container
        std::size_t kLeftOff = 0,       // left  pointer offset inside node
        std::size_t kParentOff = 4,       // parent pointer offset inside node
        std::size_t kRightOff = 8        // right pointer offset inside node
    >
    class IntrusiveRbTree {
        static_assert(std::is_trivial<OwnerT>::value || std::is_standard_layout<OwnerT>::value,
            "OwnerT must be trivially addressable");

        struct NodeView {
            std::uint8_t* p;
            NodeView left()  const { return NodeView{ *reinterpret_cast<std::uint8_t**>(p + kLeftOff) }; }
            NodeView right() const { return NodeView{ *reinterpret_cast<std::uint8_t**>(p + kRightOff) }; }
            NodeView parent()const { return NodeView{ *reinterpret_cast<std::uint8_t**>(p + kParentOff) }; }
            [[nodiscard]] bool      null()  const { return p == nullptr; }
        };

    public:
        /**
         * Lightweight in-order iterator over OwnerT.
         * End iterator is represented by {head_}.
         */
        class iterator {
        public:
            using iterator_category = std::forward_iterator_tag;
            using value_type = OwnerT;
            using difference_type = std::ptrdiff_t;
            using pointer = OwnerT*;
            using reference = OwnerT&;

            iterator() : cur_{ nullptr }, head_{ nullptr } {}
            iterator(NodeView cur, NodeView head) : cur_{ cur }, head_{ head } {}

            reference operator*()  const { return *owner_from_node(cur_); }
            pointer operator->() const { return  owner_from_node(cur_); }

            bool operator==(const iterator& o) const { return cur_.p == o.cur_.p && head_.p == o.head_.p; }
            bool operator!=(const iterator& o) const { return !(*this == o); }

            /** ++it: in-order successor */
            iterator& operator++() {
                // If right subtree exists, go to its leftmost
                NodeView n = cur_;
                if (n.right().p != head_.p && !n.right().null()) {
                    n = n.right();
                    while (n.left().p != head_.p && !n.left().null())
                        n = n.left();
                    cur_ = n;
                    return *this;
                }
                // Else climb up until we come from a left child
                NodeView parent = n.parent();
                while (parent.p != nullptr && parent.p != head_.p && n.p == parent.right().p) {
                    n = parent;
                    parent = parent.parent();
                }
                cur_ = parent.p ? parent : head_; // if reached head or null => end()
                return *this;
            }

            /** it++ */
            iterator operator++(int) { iterator tmp = *this; ++(*this); return tmp; }

        private:
            static pointer owner_from_node(NodeView n) {
                return reinterpret_cast<pointer>(n.p - kNodeEmbedOff);
            }
            NodeView cur_{};
            NodeView head_{};
        };

        IntrusiveRbTree() = default;

        /**
         * Construct a view given the container base address (CArmyImpl + offset_of_tree_container).
         * By default, the sentinel head node lives at (base + kHeadNodeOffset).
         */
        explicit IntrusiveRbTree(void* container_base)
            : base_(static_cast<std::uint8_t*>(container_base))
            , head_{ static_cast<std::uint8_t*>(container_base) + kHeadNodeOffset }
        {
        }

        /** Begin (leftmost) and end (sentinel head) iterators. */
        iterator begin() const {
            NodeView left = head_left();
            return iterator(left.p ? left : head_, head_);
        }
        iterator end() const {
            return iterator(head_, head_);
        }

        /** Access raw head and root nodes if needed for diagnostics. */
        [[nodiscard]] void* head_node() const { return head_.p; }
        [[nodiscard]] void* root_node() const { return head_parent().p; }

    private:
        NodeView head_left()   const { return NodeView{ *reinterpret_cast<std::uint8_t**>(head_.p + kLeftOff) }; }
        NodeView head_right()  const { return NodeView{ *reinterpret_cast<std::uint8_t**>(head_.p + kRightOff) }; }
        NodeView head_parent() const { return NodeView{ *reinterpret_cast<std::uint8_t**>(head_.p + kParentOff) }; }

        std::uint8_t* base_{ nullptr };
        NodeView     head_{ nullptr };
    };
}
