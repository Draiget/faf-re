#pragma once

#include <cstddef>
#include <cstdint>

namespace msvc8
{
    namespace tree
	{

        /**
         * Minimal RB-tree node base used only for navigation.
         * Matches MSVC-era header layout: first three pointers are {parent,left,right}.
         */
        struct NodeBase
    	{
            NodeBase* parent; // +0
            NodeBase* left;   // +4
            NodeBase* right;  // +8
            // Note: color/flags and value payload are not modeled here.
        };

        /**
         * Sentinel "head" node used by MSVC's _Tree:
         * - head->parent = root
         * - head->left   = leftmost
         * - head->right  = rightmost
         * The end() iterator equals head itself.
         */
        using Head = NodeBase;

        /** Return root pointer. */
        inline NodeBase* root(Head* head) noexcept { return head->parent; }
        /** Return leftmost node. */
        inline NodeBase* leftmost(Head* head) noexcept { return head->left; }
        /** Return rightmost node. */
        inline NodeBase* rightmost(Head* head) noexcept { return head->right; }
        /** Return end() sentinel (same as head). */
        inline NodeBase* end(Head* head) noexcept { return head; }

        /**
         * Inorder successor (like std::_Tree::_Next).
         */
        inline NodeBase* next(NodeBase* x, Head* head) noexcept {
            if (x->right) {
                x = x->right;
                while (x->left) x = x->left;
                return x;
            }
            NodeBase* y = x->parent;
            while (x == y->right) {
                x = y;
                y = y->parent;
            }
            return (x->right != y) ? y : head; // reach end() == head
        }

        /**
         * Reset head to empty state.
         */
        inline void reset_empty(Head* head) noexcept {
            head->parent = head;
            head->left = head;
            head->right = head;
        }

        /**
         * Erase a half-open range [first,last) by linear succ traversal.
         *
         * destroy_node: callback that must deallocate the physical node block.
         * It is called once per erased node; value destruction is caller's duty if needed.
         */
        template <class Destroy>
        void erase_range(Head* head, NodeBase* first, NodeBase* last, Destroy destroyNode) {
            for (NodeBase* n = first; n != last; ) {
                NodeBase* nxt = next(n, head); // compute successor before destroying
                destroyNode(n);
                n = nxt;
            }
        }

        /**
         * Clear the entire tree: erase [leftmost(), end()) and reset head.
         *
         * destroy_node: see erase_range.
         */
        template <class Destroy>
        void clear_all(Head* head, Destroy destroyNode) {
            if (!head) return;
            erase_range(head, leftmost(head), end(head), destroyNode);
            reset_empty(head);
        }

        /**
         * Default deleter for nodes allocated with operator new/delete.
         */
        struct DefaultNodeDeleter {
            void operator()(NodeBase* n) const noexcept { operator delete(n); }
        };

        /**
         * Embedded tree that owns only the sentinel head and deletes all nodes on destruction.
         * Nodes must begin with NodeBase layout.
         */
        template<class NodeDeleter = DefaultNodeDeleter>
        class EmbeddedTree {
        public:
            EmbeddedTree() noexcept { reset_empty(&head_); }
            ~EmbeddedTree() { clear(); }

            /**
             * Clear the whole tree by linear successor traversal, then reset head.
             */
            void clear() noexcept {
                // Erase [leftmost, end)
                for (NodeBase* n = leftmost(&head_); n != end(&head_); ) {
                    NodeBase* nxt = next(n, &head_);
                    deleter_(n);
                    n = nxt;
                }
                reset_empty(&head_);
            }

            /** Access to the sentinel head (for advanced ops). */
            Head* head() noexcept { return &head_; }
            const Head* head() const noexcept { return &head_; }

        private:
            Head         head_{};
            NodeDeleter  deleter_{};
        };

    } // namespace tree
}
