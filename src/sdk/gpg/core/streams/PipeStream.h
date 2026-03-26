#pragma once

#include "Stream.h"
#include "boost/condition.h"
#include "boost/Mutex.h"
#include "gpg/core/containers/DList.h"

namespace gpg
{
#pragma pack(push, 4)
	/**
	 * Fixed-size 4KB chunk, chained via intrusive DList.
	 */
	struct PipeStreamBuffer : DListItem<PipeStreamBuffer>
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
	 * Pipe-like in-memory stream with blocking and non-blocking reads.
	 * Layout and behavior follow the original Moho engine, with RAII and small safety fixes.
	 *
	 * VFTABLE: 0x00D495F0 (original)
	 * COL:     0x00E53C4C (original)
	 */
	class PipeStream :
		public Stream
	{
	public:
		/**
		 * Address: 0x009569A0 (FUN_009569A0)
         * Deleting owner: 0x00956A90 (FUN_00956A90)
		 *
		 * What it does:
		 * Performs non-deleting teardown of pipe buffers/synchronization before Stream base teardown.
		 */
		~PipeStream() override;

		/**
		 * Address: 0x00956A50 (FUN_00956A50)
		 *
		 * What it does:
		 * Blocking read wrapper that dispatches to `DoRead(..., true)`.
		 */
		size_t VirtRead(char* dst, size_t len) override;

		/**
		 * Address: 0x00956A70 (FUN_00956A70)
		 *
		 * What it does:
		 * Non-blocking read wrapper that dispatches to `DoRead(..., false)`.
		 */
		size_t VirtReadNonBlocking(char* dst, size_t len) override;

		/**
		 * Address: 0x009568E0 (FUN_009568E0)
		 *
		 * What it does:
		 * Returns true when output is closed and no committed unread bytes remain.
		 */
		bool VirtAtEnd() override;

		/**
		 * Address: 0x00956AB0 (FUN_00956AB0)
		 *
		 * What it does:
		 * Appends bytes into 4KB chunk buffers and publishes written range to readers.
		 */
		void VirtWrite(const char* data, size_t size) override;

		/**
		 * Address: 0x00956CC0 (FUN_00956CC0)
		 *
		 * What it does:
		 * Publishes pending write head to read boundary or throws when closed.
		 */
		void VirtFlush() override;

		/**
		 * Address: 0x00956920 (FUN_00956920)
		 *
		 * What it does:
		 * Closes the send lane when requested by mode and wakes waiting readers.
		 */
		void VirtClose(Mode mode) override;

		/**
		 * Address: 0x00483470 (FUN_00483470)
		 *
		 * What it does:
		 * Returns true only when local read window is exhausted and `VirtAtEnd()` is true.
		 */
		bool Empty();

		/**
		 * Address: 0x009566C0 (FUN_009566C0)
		 *
		 * What it does:
		 * Computes committed readable byte count across head/middle/tail chunk ranges.
		 */
		size_t GetLength();

        /**
         * Address: 0x00956740 (FUN_00956740)
         *
         * What it does:
         * Internal read loop that drains current buffers and optionally waits for new committed bytes.
         */
        size_t DoRead(char* dst, size_t len, bool doWait);

        /**
         * Address: 0x009565D0 (FUN_009565D0)
         *
         * What it does:
         * Initializes lock/condition/list state and allocates the first 4KB stream buffer.
         */
        PipeStream();

	protected:
		boost::mutex mLock{};
		BOOL mClosed{ false };
		boost::condition mCond{};
		DList<PipeStreamBuffer, void> mBuff;

	private:
        PipeStreamBuffer* headNode() noexcept {
            return mBuff.front();
        }

        PipeStreamBuffer* tailNode() noexcept {
            return mBuff.back();
        }
	};
#pragma pack(pop)
	static_assert(sizeof(PipeStream) == 0x48, "PipeStream size must be 0x48");
}
