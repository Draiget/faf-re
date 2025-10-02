#include "CWaitHandleSet.h"

#include "WinApp.h"
using namespace moho;

// 0x00414A00
HANDLE* CWaitHandle::AppendHandle(HANDLE* pos, const unsigned count, const HANDLE* value) {
    if (count == 0) {
	    return end;
    }

    // Current size / capacity in elements (HANDLE is 4 bytes on x86)
    const unsigned curElems = begin ? static_cast<unsigned>(end - begin) : 0u;
    const unsigned capElems = begin ? static_cast<unsigned>(cap - begin) : 0u;

    // Overflow guard like in 0x00414A00 (0x3FFFFFFF accounts for 4-byte elems)
    constexpr unsigned maxElems = 0x3FFFFFFF;
    if (count > (maxElems - curElems)) {
	    throw std::length_error("CWaitHandle::AppendHandle overflow");
    }

    // Fast path: enough capacity
    if (begin && capElems >= curElems + count) {
        if (pos == end) {
            // Pure append
            for (unsigned i = 0; i < count; ++i) {
	            end[i] = *value;
            }
            end += count;
            return end;
        }

        const unsigned tail = static_cast<unsigned>(end - pos);

        if (tail >= count) {
            // Shift tail up by count
            std::memmove(pos + count, pos, tail * sizeof(HANDLE));
            // Fill the gap
            for (unsigned i = 0; i < count; ++i) {
	            pos[i] = *value;
            }
            end += count;
            return end;
        }

        // Partly beyond old end
        const unsigned beyond = count - tail;

        // 1) Write the beyond-end part
        for (unsigned i = 0; i < beyond; ++i) {
	        end[i] = *value;
        }

        // 2) Move the old tail up
        std::memmove(pos + count, pos, tail * sizeof(HANDLE));

        // 3) Fill the remaining gap
        for (unsigned i = 0; i < tail; ++i) {
	        pos[i] = *value;
        }

        end += count;
        return end;
    }

    // Realloc path: grow ~1.5x, but at least curElems + count
    unsigned newCap = capElems + (capElems >> 1);
    const unsigned need = curElems + count;
    if (newCap < need) {
	    newCap = need;
    }

    // Byte-size overflow check for operator new
    if (newCap && (0xFFFFFFFFu / newCap) < sizeof(HANDLE)) {
	    throw std::bad_alloc();
    }

    const auto newBegin = static_cast<HANDLE*>(operator new(newCap * sizeof(HANDLE)));

    // Copy prefix [begin, pos)
    const unsigned prefix = begin ? static_cast<unsigned>(pos - begin) : 0u;
    if (prefix) {
	    std::memmove(newBegin, begin, prefix * sizeof(HANDLE));
    }

    // Fill middle [prefix, prefix+count)
    for (unsigned i = 0; i < count; ++i) {
	    newBegin[prefix + i] = *value;
    }

    // Copy suffix [pos, end)
    if (const unsigned suffix = curElems - prefix) {
	    std::memmove(newBegin + prefix + count, pos, suffix * sizeof(HANDLE));
    }

    // Release old buffer
    if (begin) {
	    operator delete(begin);
    }

    // Install new pointers
    begin = newBegin;
    end = newBegin + need;
    cap = newBegin + newCap;

    return end;
}

// 0x00414220
CWaitHandleSet::CWaitHandleSet() {
    // Zero the vector header (all four first dwords) + explicit ctr
    handleSet.begin = nullptr;
    handleSet.end = nullptr;
    handleSet.cap = nullptr;
    handleSet.pad0 = 0;
    handleSet.ctr = 0;

    count = 0;

    // Create the internal auto-reset event (gate)
    const HANDLE h = CreateEventW(nullptr, FALSE, FALSE, nullptr);

    // Fast in-place append if capacity is available, else grow via AppendHandle
    if (handleSet.begin &&
        static_cast<unsigned>(handleSet.end - handleSet.begin) <
        static_cast<unsigned>(handleSet.cap - handleSet.begin))
    {
        *handleSet.end = h;
        ++handleSet.end;
    } else {
        handleSet.AppendHandle(handleSet.end, 1u, &h);
    }
}

// 0x004143C0
void CWaitHandleSet::AddHandle(const HANDLE handle) {
    boost::mutex::scoped_lock l(lock);

    // Producer enters
    ++count;

    // While sender side is busy (matches 'while (handleSet.ctr)' in asm)
    while (handleSet.ctr != 0) {
        // First slot stores the internal auto-reset event created in the ctor.
        if (handleSet.begin && *handleSet.begin) {
            ::SetEvent(*handleSet.begin);
        }

        // Wait on sender condition; this releases the mutex and reacquires it upon wake.
        objectSender.wait(l);
    }

    // Fast path: capacity available -> append in place
    if (handleSet.begin &&
        static_cast<unsigned>(handleSet.end - handleSet.begin) <
        static_cast<unsigned>(handleSet.cap - handleSet.begin))
    {
        *handleSet.end = handle;
        ++handleSet.end;
    } else {
        // Slow path: grow and insert
        handleSet.AppendHandle(handleSet.end, 1u, &handle);
    }

    // Producer leaves
    if (--count == 0) {
        // Wake all consumers/waiters on the receiver side
        objectReceiver.notify_all();
    }
    // guard unlocks automatically here
}
