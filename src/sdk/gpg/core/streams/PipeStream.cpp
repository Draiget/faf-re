#include "PipeStream.h"
#include <cstddef>
#include <cstdint>
#include <cstring>

using namespace gpg;

namespace
{
using PipeBufferNode = DListItem<PipeStreamBuffer, void>;

struct PipeBufferNodeCursorRuntime
{
    PipeBufferNode* node = nullptr;
};
static_assert(sizeof(PipeBufferNodeCursorRuntime) == 0x04, "PipeBufferNodeCursorRuntime size must be 0x04");

struct PipeBufferNodeSlotRuntime
{
    PipeBufferNode* node = nullptr;
};
static_assert(sizeof(PipeBufferNodeSlotRuntime) == 0x04, "PipeBufferNodeSlotRuntime size must be 0x04");

/**
 * Address: 0x009563A0 (FUN_009563A0)
 *
 * What it does:
 * Returns one-past-end byte pointer for a 4KB pipe buffer payload.
 */
[[maybe_unused]] [[nodiscard]] char* PipeStreamBufferEndPointerRuntime(PipeStreamBuffer* const buffer) noexcept
{
    return buffer->mData + PipeStreamBuffer::kSize;
}

/**
 * Address: 0x009563B0 (FUN_009563B0)
 *
 * What it does:
 * Returns the first payload byte pointer for a pipe buffer.
 */
[[maybe_unused]] [[nodiscard]] char* PipeStreamBufferBeginPointerRuntime(PipeStreamBuffer* const buffer) noexcept
{
    return buffer->mData;
}

/**
 * Address: 0x009563D0 (FUN_009563D0)
 *
 * What it does:
 * Initializes one intrusive node as a self-linked singleton.
 */
[[maybe_unused]] PipeBufferNode* InitializePipeBufferNodeSelfLinked_A(PipeBufferNode* const node) noexcept
{
    node->mNext = node;
    node->mPrev = node;
    return node;
}

/**
 * Address: 0x009563E0 (FUN_009563E0)
 *
 * What it does:
 * Advances one intrusive-node cursor to its next node.
 */
[[maybe_unused]] PipeBufferNodeCursorRuntime* AdvancePipeBufferNodeCursor(
    PipeBufferNodeCursorRuntime* const cursor
) noexcept
{
    cursor->node = cursor->node->mNext;
    return cursor;
}

/**
 * Address: 0x009563F0 (FUN_009563F0)
 *
 * What it does:
 * Rewinds one intrusive-node cursor to its previous node.
 */
[[maybe_unused]] PipeBufferNodeCursorRuntime* RewindPipeBufferNodeCursor(
    PipeBufferNodeCursorRuntime* const cursor
) noexcept
{
    cursor->node = cursor->node->mPrev;
    return cursor;
}

/**
 * Address: 0x00956430 (FUN_00956430)
 *
 * What it does:
 * Unlinks one intrusive node from its list and re-self-links it.
 */
[[maybe_unused]] PipeBufferNode* UnlinkPipeBufferNode_A(PipeBufferNode* const node) noexcept
{
    node->mPrev->mNext = node->mNext;
    PipeBufferNode* const next = node->mNext;
    next->mPrev = node->mPrev;
    node->mNext = node;
    node->mPrev = node;
    return next;
}

/**
 * Address: 0x00956450 (FUN_00956450)
 *
 * What it does:
 * Unlinks `node` and inserts it immediately before `anchor`.
 */
[[maybe_unused]] PipeBufferNode* RelinkPipeBufferNodeBeforeAnchor(
    PipeBufferNode* const node,
    PipeBufferNode* const anchor
) noexcept
{
    node->mPrev->mNext = node->mNext;
    node->mNext->mPrev = node->mPrev;
    node->mPrev = anchor->mPrev;
    node->mNext = anchor;
    anchor->mPrev = node;
    node->mPrev->mNext = node;
    return node->mPrev;
}

/**
 * Address: 0x00956480 (FUN_00956480)
 *
 * What it does:
 * Returns whether an intrusive node is self-linked (unlinked).
 */
[[maybe_unused]] [[nodiscard]] bool IsPipeBufferNodeSelfLinked_A(const PipeBufferNode* const node) noexcept
{
    return node->mNext == node;
}

/**
 * Address: 0x00956490 (FUN_00956490)
 *
 * What it does:
 * Copies one node-slot pointer from `source` into `destination`.
 */
[[maybe_unused]] PipeBufferNodeSlotRuntime* CopyPipeBufferNodeSlot_A(
    PipeBufferNodeSlotRuntime* const destination,
    const PipeBufferNodeSlotRuntime* const source
) noexcept
{
    destination->node = source->node;
    return destination;
}

/**
 * Address: 0x009564A0 (FUN_009564A0)
 *
 * What it does:
 * Stores one node pointer into a node-slot lane.
 */
[[maybe_unused]] PipeBufferNodeSlotRuntime* SetPipeBufferNodeSlot_A(
    PipeBufferNodeSlotRuntime* const destination,
    PipeBufferNode* const value
) noexcept
{
    destination->node = value;
    return destination;
}

/**
 * Address: 0x009564B0 (FUN_009564B0)
 *
 * What it does:
 * Alias lane that unlinks one node and re-self-links it.
 */
[[maybe_unused]] PipeBufferNode* UnlinkPipeBufferNode_B(PipeBufferNode* const node) noexcept
{
    return UnlinkPipeBufferNode_A(node);
}

/**
 * Address: 0x009564D0 (FUN_009564D0)
 *
 * What it does:
 * Alias lane that initializes one intrusive node as self-linked.
 */
[[maybe_unused]] PipeBufferNode* InitializePipeBufferNodeSelfLinked_B(PipeBufferNode* const node) noexcept
{
    node->mNext = node;
    node->mPrev = node;
    return node;
}

/**
 * Address: 0x009564E0 (FUN_009564E0)
 *
 * What it does:
 * Alias lane that reports whether one node is self-linked.
 */
[[maybe_unused]] [[nodiscard]] bool IsPipeBufferNodeSelfLinked_B(const PipeBufferNode* const node) noexcept
{
    return node->mNext == node;
}

/**
 * Address: 0x009564F0 (FUN_009564F0)
 *
 * What it does:
 * Unlinks `node` and inserts it immediately before `anchor`.
 */
[[maybe_unused]] PipeBufferNode* InsertPipeBufferNodeBeforeAnchor(
    PipeBufferNode* const anchor,
    PipeBufferNode* const node
) noexcept
{
    node->mPrev->mNext = node->mNext;
    node->mNext->mPrev = node->mPrev;
    node->mPrev = anchor->mPrev;
    node->mNext = anchor;
    anchor->mPrev = node;
    node->mPrev->mNext = node;
    return node;
}

/**
 * Address: 0x00956520 (FUN_00956520)
 *
 * What it does:
 * Returns one node's `next` intrusive-link lane.
 */
[[maybe_unused]] [[nodiscard]] PipeBufferNode* GetPipeBufferNodeNext(const PipeBufferNode* const node) noexcept
{
    return node->mNext;
}

/**
 * Address: 0x00956540 (FUN_00956540)
 *
 * What it does:
 * Alias lane that copies one node-slot pointer.
 */
[[maybe_unused]] PipeBufferNodeSlotRuntime* CopyPipeBufferNodeSlot_B(
    PipeBufferNodeSlotRuntime* const destination,
    const PipeBufferNodeSlotRuntime* const source
) noexcept
{
    destination->node = source->node;
    return destination;
}

/**
 * Address: 0x00956550 (FUN_00956550)
 *
 * What it does:
 * Alias lane that stores one node pointer into a node-slot.
 */
[[maybe_unused]] PipeBufferNodeSlotRuntime* SetPipeBufferNodeSlot_B(
    PipeBufferNodeSlotRuntime* const destination,
    PipeBufferNode* const value
) noexcept
{
    destination->node = value;
    return destination;
}

/**
 * Address: 0x00956580 (FUN_00956580)
 *
 * What it does:
 * Alias lane that initializes one intrusive node as self-linked.
 */
[[maybe_unused]] PipeBufferNode* InitializePipeBufferNodeSelfLinked_C(PipeBufferNode* const node) noexcept
{
    node->mNext = node;
    node->mPrev = node;
    return node;
}

/**
 * Address: 0x00956590 (FUN_00956590)
 *
 * What it does:
 * Alias lane that unlinks one node and re-self-links it.
 */
[[maybe_unused]] PipeBufferNode* UnlinkPipeBufferNode_C(PipeBufferNode* const node) noexcept
{
    return UnlinkPipeBufferNode_A(node);
}

/**
 * Address: 0x009565B0 (FUN_009565B0)
 *
 * What it does:
 * Stores one node's `next` lane in `outNext`.
 */
[[maybe_unused]] PipeBufferNode** StorePipeBufferNodeNext(
    const PipeBufferNode* const node,
    PipeBufferNode** const outNext
) noexcept
{
    *outNext = node->mNext;
    return outNext;
}

/**
 * Address: 0x009565C0 (FUN_009565C0)
 *
 * What it does:
 * Stores one node pointer into `outNode`.
 */
[[maybe_unused]] PipeBufferNode** StorePipeBufferNodeSelf(PipeBufferNode* const node, PipeBufferNode** const outNode) noexcept
{
    *outNode = node;
    return outNode;
}
} // namespace

/**
 * Address: 0x009565D0 (FUN_009565D0)
 *
 * What it does:
 * Initializes lock/condition/list state and allocates the first 4KB stream buffer.
 */
PipeStream::PipeStream()
    : Stream(),
      mLock(),
      mClosed(false),
      mCond(),
      mBuff()
{
    auto* const first = new PipeStreamBuffer{};
    mBuff.push_back(first);

    mReadEnd = first->begin();
    mReadHead = first->begin();
    mReadStart = first->begin();
    mWriteHead = first->begin();
    mWriteStart = first->begin();
    mWriteEnd = first->end();
}

/**
 * Address: 0x009569A0 (FUN_009569A0)
 * Deleting owner: 0x00956A90 (FUN_00956A90)
 *
 * What it does:
 * Performs non-deleting teardown of pipe buffers/synchronization before Stream base teardown.
 */
PipeStream::~PipeStream()
{
    while (!mBuff.empty()) {
        delete mBuff.pop_front();
    }
}

/**
 * Address: 0x00956A50 (FUN_00956A50)
 *
 * What it does:
 * Blocking read wrapper forwarding to DoRead(..., true).
 */
size_t PipeStream::VirtRead(char* dst, const size_t len)
{
    return DoRead(dst, len, /*doWait=*/true);
}

/**
 * Address: 0x00956A70 (FUN_00956A70)
 *
 * What it does:
 * Non-blocking read wrapper forwarding to DoRead(..., false).
 */
size_t PipeStream::VirtReadNonBlocking(char* dst, const size_t len)
{
    return DoRead(dst, len, /*doWait=*/false);
}

/**
 * Address: 0x009568E0 (FUN_009568E0)
 *
 * What it does:
 * Returns true when send side is closed and local read cursor reached current readable end.
 */
bool PipeStream::VirtAtEnd()
{
    boost::mutex::scoped_lock lock(mLock);
    return mClosed && (mReadHead == mReadEnd);
}

/**
 * Address: 0x00956AB0 (FUN_00956AB0)
 *
 * What it does:
 * Appends bytes to chunk buffers, updates committed write boundary, and wakes readers.
 */
void PipeStream::VirtWrite(const char* data, size_t size)
{
    boost::mutex::scoped_lock lock(mLock);

    if (mClosed) {
    	// Matches engine semantics: throw on write-after-close.
        throw std::runtime_error("Can't write to a pipe stream after output has been closed.");
    }

    const size_t available = static_cast<size_t>(mWriteEnd - mWriteHead);
    if (available < size) {
        if (available != 0) {
            std::memcpy(mWriteHead, data, available);
            data += available;
            size -= available;
        }

        while (size >= PipeStreamBuffer::kSize) {
            auto* const chunk = new PipeStreamBuffer{};
            mBuff.push_back(chunk);
            std::memcpy(chunk->begin(), data, PipeStreamBuffer::kSize);
            data += PipeStreamBuffer::kSize;
            size -= PipeStreamBuffer::kSize;
        }

        auto* const tail = new PipeStreamBuffer{};
        mBuff.push_back(tail);
        std::memcpy(tail->begin(), data, size);
        mWriteHead = tail->begin() + size;
        mWriteStart = mWriteHead;
        mWriteEnd = tail->end();
    } else {
        std::memcpy(mWriteHead, data, size);
        mWriteHead += size;
        mWriteStart = mWriteHead;
    }

    mCond.notify_all();
}

/**
 * Address: 0x00956CC0 (FUN_00956CC0)
 *
 * What it does:
 * Publishes pending write bytes and wakes readers; throws on closed write side.
 */
void PipeStream::VirtFlush()
{
    boost::mutex::scoped_lock lock(mLock);

    if (mClosed) {
        throw std::runtime_error("Can't write to a pipe stream after output has been closed.");
    }

    // In our implementation writes are immediately published; still keep parity:
    if (mWriteHead != mWriteStart) {
        mWriteStart = mWriteHead;
        mCond.notify_all();
    }
}

/**
 * Address: 0x00956920 (FUN_00956920)
 *
 * What it does:
 * Closes send lane when requested by mode and wakes blocked readers.
 */
void PipeStream::VirtClose(const Mode mode)
{
    // Keep compatibility: close write-end if requested
    if ((mode & ModeSend) != 0) {
        boost::mutex::scoped_lock lock(mLock);
        if (!mClosed) {
            mClosed = true;
            // Publish whatever is currently written
            mWriteStart = mWriteHead;
            mCond.notify_all();
        }
    }
}

/**
 * Address: 0x00483470 (FUN_00483470)
 *
 * What it does:
 * Returns true when local read window is exhausted and VirtAtEnd confirms stream completion.
 */
bool PipeStream::Empty()
{
    return (mReadHead == mReadEnd) && VirtAtEnd();
}

/**
 * Address: 0x009566C0 (FUN_009566C0)
 *
 * What it does:
 * Computes total committed readable bytes across chunk chain.
 */
size_t PipeStream::GetLength()
{
    boost::mutex::scoped_lock lock(mLock);

    PipeStreamBuffer* const head = mBuff.front();
    PipeStreamBuffer* const tail = mBuff.back();
    if (!head || !tail) {
        // no buffers - shouldn't happen
    	return 0; 
    }

    // Single-buffer fast path
    if (head == tail) {
        return static_cast<size_t>(mWriteStart - mReadHead);
    }

    // Multi-buffer: sum leftover in head, full middles, and partial tail up to writeStart
    size_t total = 0;

    // Head buffer remainder
    total += static_cast<size_t>(mReadEnd - mReadHead); // for head we keep mReadEnd = buffer->end()

    // Middle full buffers
    const auto* tailItem = static_cast<const DListItem<PipeStreamBuffer>*>(tail);
    for (const auto* n = head->mNext; n != tailItem; n = n->mNext) {
        total += PipeStreamBuffer::kSize;
    }

    // Tail partial up to writeStart
    total += static_cast<size_t>(mWriteStart - tail->begin());
    return total;
}

/**
 * Address: 0x00956740 (FUN_00956740)
 *
 * What it does:
 * Internal read loop that drains current buffers and optionally waits for new committed bytes.
 */
size_t PipeStream::DoRead(char* dst, size_t len, const bool doWait)
{
    boost::mutex::scoped_lock lock(mLock);
    size_t available = static_cast<size_t>(mReadEnd - mReadHead);
    size_t copied = 0;

    while (available < len) {
        if (available != 0) {
            std::memcpy(dst, mReadHead, available);
            dst += available;
            copied += available;
            len -= available;
            mReadHead += available;
        }

        PipeStreamBuffer* const head = headNode();
        PipeStreamBuffer* const tail = tailNode();

        if (head == tail) {
            if (mReadEnd != mWriteStart) {
                mReadEnd = mWriteStart;
            } else {
                if (!doWait || mClosed) {
                    return copied;
                }
                mCond.wait(lock);
            }
        } else {
            if (mReadEnd != head->end()) {
                mReadEnd = head->end();
            } else {
                delete mBuff.pop_front();
                PipeStreamBuffer* const next = headNode();
                mReadHead = next->begin();
                mReadStart = next->begin();
                if (next != tailNode()) {
                    mReadEnd = next->end();
                } else {
                    mReadEnd = mWriteStart;
                }
            }
        }

        available = static_cast<size_t>(mReadEnd - mReadHead);
    }

    if (len != 0) {
        std::memcpy(dst, mReadHead, len);
        mReadHead += len;
    }

    return copied + len;
}
