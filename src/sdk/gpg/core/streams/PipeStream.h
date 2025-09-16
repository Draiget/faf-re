#pragma once

#include "Stream.h"
#include "boost/condition.h"
#include "boost/Mutex.h"
#include "gpg/core/containers/DList.h"

namespace gpg
{
	/**
	 * Pipe-like in-memory stream with blocking and non-blocking reads.
	 * Layout and behavior follow the original Moho engine, with RAII and small safety fixes.
	 *
	 * VFTABLE: 0x00D495F0 (original)
	 * COL:     0x00E53C4C (original)
	 */
	class PipeStream : public Stream
	{
	public:
		/**
		 * Fixed-size 4KB chunk, chained via intrusive DList.
		 */
		struct Buffer : DListItem<Buffer>
		{
			static constexpr size_t kSize = 4096;
			char mData[kSize];

			char* begin() noexcept {
				return mData;
			}
			char* end() noexcept {
				return mData + kSize;
			}

			[[nodiscard]] const char* begin() const noexcept {
				return mData;
			}
			[[nodiscard]] const char* end() const noexcept {
				return mData + kSize;
			}
		};

		/**
		 * Non-virtual dtor frees all buffers.
		 *
		 * Address: 0x00956A90
		 */
		~PipeStream() override;

		/**
		 * Read with blocking semantics.
		 *
		 * Address: 0x00956A50
		 */
		size_t VirtRead(char* dst, size_t len) override;

		/**
		 * Read with non-blocking semantics.
		 *
		 * Address: 0x00956A70
		 */
		size_t VirtReadNonBlocking(char* dst, size_t len) override;

		/**
		 * End-of-input once writer closed and nothing left to read.
		 *
		 * Address: 0x009568E0
		 */
		bool VirtAtEnd() override;

		/**
		 * Write bytes; publishes them to readers immediately.
		 *
		 * Address: 0x00956AB0
		 */
		void VirtWrite(const char* data, size_t size) override;

		/**
		 * Publish any staged bytes (no-op here; kept for parity).
		 *
		 * Address: 0x00956CC0
		 */
		void VirtFlush() override;

		/**
		 * Close pipe (respects write/read flags from Mode).
		 *
		 * Address: 0x00956920
		 */
		void VirtClose(gpg::Stream::Mode mode) override;

		/**
		 * True if there is nothing to read at the moment.
		 *
		 * Address: 0x00483470
		 */
		bool Empty();

		/**
		 * Total readable bytes currently available.
         * Computes total readable bytes across [readHead..writeStart) spanning the buffer chain.
		 *
		 * Address: 0x009566C0
		 */
		size_t GetLength();

		/**
		 * Internal: the read routine with optional waiting.
		 *
		 * Address: 0x00956740
		 */
		size_t DoRead(char* dst, size_t len, bool doWait);

		/**
		 * Ctor allocates the first buffer and resets pointers.
		 *
		 * Address: 0x00956740
		 */
		PipeStream();

	private:
		boost::mutex mLock{};
		bool mClosed{ false };
		boost::condition mCond{};

		// intrusive sentinel (head)
		DList<Buffer> mBuff;

		// Sliding window pointers (inside the chain)
		// Read window: [mReadHead, mReadEnd)
		char* mReadHead{ nullptr };
		char* mReadStart{ nullptr }; // kept for parity with original
		char* mReadEnd{ nullptr };

		// Write window in the last buffer: committed boundary is mWriteStart
		// Readers can consume only up to mWriteStart.
		char* mWriteHead{ nullptr };
		char* mWriteStart{ nullptr };
		char* mWriteEnd{ nullptr };

	private:
		/**
		 * Allocate a fresh 4KB buffer and link at tail; sets write window to this buffer.
		 */
		void allocateTailBuffer();

		/**
		 * Return pointer to the last (tail) buffer (undefined if list empty).
		 */
		Buffer* tailNode() noexcept;

		/**
		 * Return pointer to the first (head) buffer (undefined if list empty).
		 */
		Buffer* headNode() noexcept;

		/**
		 * Reset to a pristine single-buffer state (assumes lock held).
		 */
		void resetStateWithOneBuffer(Buffer* buf);
	};
}
