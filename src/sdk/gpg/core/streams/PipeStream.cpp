#include "PipeStream.h"
using namespace gpg;

/**
 * Ensure intrusive list sentinel is initialized self-linked.
 */
static void init_sentinel(DList<PipeStream::Buffer>& list) noexcept {
    list.mNext = &list;
    list.mPrev = &list;
}

static bool is_sentinel(
    const DListItem<PipeStream::Buffer>* n,
    const DList<PipeStream::Buffer>* s) noexcept
{
    return reinterpret_cast<const void*>(n) == reinterpret_cast<const void*>(s);
}

static void link_before(DList<PipeStream::Buffer>& where, PipeStream::Buffer* node) noexcept {
    // Insert node before 'where' (i.e., at tail if where==sentinel)
    node->mPrev = where.mPrev;
    node->mNext = &where;
    where.mPrev->mNext = node;
    where.mPrev = node;
}

static void unlink_and_isolate(PipeStream::Buffer* node) noexcept {
    node->mPrev->mNext = node->mNext;
    node->mNext->mPrev = node->mPrev;
    node->mPrev = node;
    node->mNext = node;
}

void PipeStream::allocateTailBuffer() {
	const auto b = new Buffer(); // DListItem ctor should self-link
    link_before(mBuff, b);    // push_back
    // Update write window to this fresh buffer
    mWriteHead = b->begin();
    mWriteStart = mWriteHead;     // write becomes visible immediately (engine behavior)
    mWriteEnd = b->end();
    // If this is the first buffer in the list, also wire read window.
    if (mReadHead == nullptr) {
        resetStateWithOneBuffer(b);
    }
}

PipeStream::Buffer* PipeStream::tailNode() noexcept {
    return is_sentinel(mBuff.mPrev, &mBuff) ? nullptr
        : static_cast<Buffer*>(mBuff.mPrev);
}

PipeStream::Buffer* PipeStream::headNode() noexcept {
    return is_sentinel(mBuff.mNext, &mBuff) ? nullptr
        : static_cast<Buffer*>(mBuff.mNext);
}

void PipeStream::resetStateWithOneBuffer(Buffer* buf) {
    // Set both read and write windows to this single buffer.
    mReadHead = buf->begin();
    mReadStart = buf->begin();
    mReadEnd = buf->end();      // will be adjusted to mWriteStart if this is also the last buffer
    if (tailNode() == buf) {
        // Single buffer: end of readable range cannot exceed committed start.
        mReadEnd = mWriteStart;
    }
}

PipeStream::PipeStream()
    : Stream()
{
    // Initialize intrusive list sentinel
    init_sentinel(mBuff);

    // Allocate initial buffer and prime pointers
    allocateTailBuffer();
}

PipeStream::~PipeStream()
{
    // No locking: object is tearing down.
    // Walk once from head to sentinel, unlink+delete each node.
    auto* n = mBuff.mNext;
    while (!is_sentinel(n, &mBuff)) {
        // save next before unlink
        auto* next = n->mNext;                    
        auto* buf = static_cast<Buffer*>(n);
        // detach from list
        unlink_and_isolate(buf);
        // free 4KB block
        delete buf;                               
        n = next;
    }

    // Reset sentinel links (not strictly needed in dtor, but keeps invariants tidy)
    mBuff.mNext = &mBuff;
    mBuff.mPrev = &mBuff;

    // Null sliding-window pointers so accidental post-dtor use AVs fast
    mReadHead = mReadStart = mReadEnd = nullptr;
    mWriteHead = mWriteStart = mWriteEnd = nullptr;
}

size_t PipeStream::VirtRead(char* dst, const size_t len)
{
    return DoRead(dst, len, /*doWait=*/true);
}

size_t PipeStream::VirtReadNonBlocking(char* dst, const size_t len)
{
    return DoRead(dst, len, /*doWait=*/false);
}

bool PipeStream::VirtAtEnd()
{
    boost::mutex::scoped_lock lock(mLock);
    return mClosed && (mReadHead == mWriteStart);
}

void PipeStream::VirtWrite(const char* data, size_t size)
{
    if (!data || size == 0) return;

    boost::mutex::scoped_lock lock(mLock);

    if (mClosed) {
    	// Matches engine semantics: throw on write-after-close.
        throw std::runtime_error("Can't write to a pipe stream after output has been closed.");
    }

    while (size > 0) {
        // Ensure there is a tail buffer to write into
        const Buffer* tail = tailNode();
        if (!tail) {
            allocateTailBuffer();
            tail = tailNode();
        }

        // Space left in current tail
        size_t space = static_cast<size_t>(mWriteEnd - mWriteHead);
        if (space == 0) {
            // Need a new tail buffer
            allocateTailBuffer();
            continue;
        }

        // Copy chunk into the current tail
        const size_t chunk = (size < space) ? size : space;
        std::memcpy(mWriteHead, data, chunk);
        mWriteHead += chunk;
        mWriteStart = mWriteHead;   // publish immediately (as in original)
        data += chunk;
        size -= chunk;
    }

    // Wake up any waiting readers
    mCond.notify_all();
}

/**
 * Address: 0x00956CC0 (original)
 */
void PipeStream::VirtFlush()
{
    boost::mutex::scoped_lock lock(mLock);
    // In our implementation writes are immediately published; still keep parity:
    if (mWriteHead != mWriteStart) {
        mWriteStart = mWriteHead;
        mCond.notify_all();
    }
}

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

bool PipeStream::Empty()
{
    boost::mutex::scoped_lock lock(mLock);
    // "Empty" means nothing currently readable
    return (mReadHead == mWriteStart);
}

size_t PipeStream::GetLength()
{
    boost::mutex::scoped_lock lock(mLock);

    if (is_sentinel(mBuff.mNext, &mBuff)) {
        // no buffers - shouldn't happen
    	return 0; 
    }

    // Single-buffer fast path
    if (mBuff.mNext == mBuff.mPrev) {
        return static_cast<size_t>(mWriteStart - mReadHead);
    }

    // Multi-buffer: sum leftover in head, full middles, and partial tail up to writeStart
    size_t total = 0;

    // Head buffer remainder
    total += static_cast<size_t>(mReadEnd - mReadHead); // for head we keep mReadEnd = buffer->end()

    // Middle full buffers
    for (const auto* n = mBuff.mNext->mNext; n != mBuff.mPrev; n = n->mNext) {
        total += Buffer::kSize;
    }

    // Tail partial up to writeStart
    if (auto* tail = tailNode()) {
        total += static_cast<size_t>(mWriteStart - tail->begin());
    }
    return total;
}

/**
 * Address: 0x00956740 (original)
 *
 * Blocking read copies up to 'len' bytes; if 'doWait' is false, returns what is immediately available.
 * Wait wakes when bytes are published (notify_all) or when the stream is closed.
 */
size_t PipeStream::DoRead(char* dst, const size_t len, const bool doWait)
{
    if (!dst || len == 0) {
	    return 0;
    }

    boost::mutex::scoped_lock lock(mLock);
    size_t copied = 0;

    auto recomputeReadWindow = [this] {
        if (is_sentinel(mBuff.mNext, &mBuff)) {
            mReadHead = mReadStart = mReadEnd = nullptr;
            return;
        }

        if (mBuff.mNext == mBuff.mPrev) {
            // Single buffer: readable end is the committed write start
            mReadEnd = mWriteStart;
        } else {
            // Multi-buffer: head reads up to its end
            auto* head = static_cast<Buffer*>(mBuff.mNext);
            if (mReadHead < head->begin() || mReadHead > head->end()) {
                mReadHead = head->begin();
                mReadStart = head->begin();
            }
            mReadEnd = head->end();
        }
    };

    recomputeReadWindow();

    while (copied < len)
    {
        const size_t avail = (mReadHead && mReadEnd)
            ? static_cast<size_t>(mReadEnd - mReadHead)
            : 0;

        if (avail == 0)
        {
            if (mBuff.mNext == mBuff.mPrev)
            {
                // Single buffer with no data: either wait or return what we have
                if (!doWait || mClosed) {
                    break;
                }
                mCond.wait(lock);
                recomputeReadWindow();
                continue;
            }

            // Advance to next buffer
            auto* head = static_cast<Buffer*>(mBuff.mNext);
            auto* next = static_cast<Buffer*>(head->mNext);

            // Unlink and destroy current head
            unlink_and_isolate(head);
            delete head;

            // Setup new read window at 'next'
            mReadHead = next->begin();
            mReadStart = next->begin();
            if (next == static_cast<Buffer*>(mBuff.mPrev)) {
	            // Next is also tail: clamp by published boundary
	            mReadEnd = mWriteStart;
            } else {
	            mReadEnd = next->end();
            }
            continue;
        }

        const size_t take = std::min(len - copied, avail);
        std::memcpy(dst, mReadHead, take);
        dst += take;
        mReadHead += take;
        copied += take;

        // If we exactly consumed the head buffer, next loop iteration will advance/delete it.
    }

    return copied;
}
