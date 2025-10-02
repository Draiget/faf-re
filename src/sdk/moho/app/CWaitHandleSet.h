#pragma once
#include "boost/condition.h"
#include "boost/mutex.h"

namespace moho
{
	struct CWaitHandle
	{
		HANDLE* begin;  // begin()
		HANDLE* end;    // end()
		HANDLE* cap;    // capacity end
		int32_t pad0;   // unused/ABI padding
		int32_t ctr;   // unused/ABI padding

		void reset() noexcept {
			begin = end = cap = nullptr; pad0 = 0;
		}
		[[nodiscard]] size_t size() const noexcept {
			return begin ? static_cast<size_t>(end - begin) : 0u;
		}
		[[nodiscard]] size_t capacity() const noexcept {
			return begin ? static_cast<size_t>(cap - begin) : 0u;
		}

		/**
		 * Address: 0x00414A00
		 *
		 * Insert `count` copies of *value at position `pos` (vector::insert fill).
		 * Only the first three fields (begin/end/cap) are used here.
		 */
		HANDLE* AppendHandle(HANDLE* pos, unsigned count, const HANDLE* value);
	};
	static_assert(sizeof(CWaitHandle) == 0x14, "CWaitHandle size must be 0x14");

	class CWaitHandleSet
	{
	public:
		/**
		 * Address: 0x00414220
		 */
		CWaitHandleSet();

		/**
		 * Address: 0x004143C0
		 *
		 * @param handle 
		 */
		void AddHandle(HANDLE handle);

	public:
		boost::mutex lock;
		CWaitHandle handleSet;
		boost::condition objectSender;
		int32_t count;
		boost::condition objectReceiver;
	};
}
