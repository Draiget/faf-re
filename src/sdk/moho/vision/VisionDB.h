// Auto-generated from IDA VFTABLE/RTTI scan.
// This header is a skeleton for reverse-engineering; adjust as needed.
#pragma once
#include "moho/misc/TDatList.h"

namespace moho
{
    /**
     * VFTABLE: 0x00E422AC
     * COL:     0x00E98CA0
     */
    class VisionDB
    {
    public:
        /**
         * VFTABLE: 0x00E422B4
         * COL:     0x00E98C58
         */
        class Pool
        {
        public:
            /**
             * Allocates two heap-allocated sentinels and self-links them.
             */
            Pool();

            /**
             * Address: 0x0081AD00
             * Slot: 0
             * Demangled: Moho::VisionDB::Pool::dtr
             */
            virtual ~Pool();

            /**
             * Address: 0x0081AD20
             * Demangled: Moho::VisionDB::Pool::Clear
             */
            void Clear();

            /**
             * Node that owns a dynamic array of 40-byte items (trivial destructors).
             */
            struct ZoneNode : TDatListItem<ZoneNode, void>
            {
                char* items40{ nullptr };
            };

            /**
             *
             * Node without payload, used for handle bookkeeping.
             */
            struct HandleNode : TDatListItem<HandleNode, void>
            {
                // empty
            };

        private:
            // +0x08 (field #2): pointer to heap-allocated sentinel for Zones list
            ZoneNode* zones_{ nullptr };

            // +0x0C (field #3): count for mZones (reset to 0 in Clear)
            std::uint32_t zoneCount_{ 0 };

            // +0x10 (field #4): неизвестно (в дизасме не трогается)
            std::uint32_t pad0_{ 0 };

            // +0x14 (field #5): pointer to heap-allocated sentinel for HandleNodes list
            HandleNode* handlesHead_{ nullptr };

            // +0x18 (field #6): count for mHandleNodes (reset to 0 in Clear)
            std::uint32_t handleCount_{ 0 };

            /**
             * Make head point to itself (sentinel state).
             */
            template<class Node>
            static void ResetCircle(Node* head)
            {
                if (!head) return;
                head->mPrev = head;
                head->mNext = head;
            }

            /**
             * Delete all nodes in the circular list, but not the head itself.
             */
            template<class Node>
            static void DeleteRange(Node* head)
            {
                if (!head) return;
                for (Node* it = static_cast<Node*>(head->mNext); it != head; ) {
                    Node* next = static_cast<Node*>(it->mNext);
                    ::operator delete(it);
                    it = next;
                }
            }

            /**
             * For each ZoneNode: delete[] items40 (40-byte trivial elements), set pointer to null.
             */
            static void FreeZoneArraysOnly(ZoneNode* head);
        };

        /**
         * VFTABLE: 0x00E422BC
         * COL:     0x00E98C0C
         */
        class Handle
        {
        public:
            /**
             * Address: 0x0081AE20
             * Slot: 0
             * Demangled: Moho::VisionDB::Handle::dtr
             */
            virtual ~Handle();

            /**
             * Init from raw pointers: linkPtr -> mLinkPtr, ownerPtr -> mOwnerPtr.
             *
             * Address: 0x0081AE10
             */
            static Handle* Init(Handle* self, std::uintptr_t linkPtr, std::uintptr_t ownerPtr);

        private:
            /**
             * Erase node from an intrusive doubly-linked list using prev/next links.
             */
            static void EraseNode(void* node);

            /**
             * Unbind node from owner-linked structure; ownerPlus4 semantics unknown, best-effort.
             */
            static void UnbindFromOwner(std::uintptr_t ownerPlus4, void* node);

        private:
            // layout from asm:
            // [0] vptr
            // [4] mOwnerPtr  (v1)  - used as (v1 + 4) in dtor
            // [8] mLinkPtr   (v2)  - pointer to an intrusive node
            std::uintptr_t ownerPtr_{ 0 };
            std::uintptr_t linkPtr_{ 0 };
        };

        /**
         * Build Pool and zero unknown pointer.
         *
         * Address: 0x081AE90
         */
        VisionDB();

        /**
         * Address: 0x0081AEB0
         * Slot: 0
         * Demangled: Moho::VisionDB::Dtr
         */
        virtual ~VisionDB();

    private:
        // +0x04: Pool
        Pool pool_;

        // +0x20 (a1[8]): unknown pointer cleared in ctor
        void* unknown_{ nullptr };
    };
}
