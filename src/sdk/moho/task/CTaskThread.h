#pragma once
#include "moho/containers/TDatList.h"
#include "moho/misc/InstanceCounter.h"

namespace moho
{
	class CTask;
	class CTaskStage;

	class CTaskThread : public TDatListItem<CTaskThread, void>, InstanceCounter<CTaskThread>
	{
	public:
		// Could be EBO trick of older MSVC8 compiler trying to combine InstanceCounter and
		// TDatListItem<T>, so let's just keep it as padding int, unless we know that it's
		// actually in use by some logic.
		int mCookie{ 0 };
		CTaskStage* mStage;
		CTask* mTask;
		bool mPending;
		int mStaged;

		/**
		 * Address: 0x00409050
		 */
		CTaskThread(CTaskStage* stage);

		/**
		 * Address: 0x00409190
		 */
		CTaskStage* Destroy() noexcept;

		/**
		 * Address: 0x004093E0
		 */
		void Stage();

		/**
		 * NOTE: Inlined
		 * Address: 0x004091C0
		 */
		void Unstage();
	};
	static_assert(sizeof(CTaskThread) == 0x1C, "CTaskThread == 0x1C");

	class CTaskStage
	{
	public:
		TDatList<CTaskThread, void> mThreads;
		TDatList<CTaskThread, void> mStagedThreads;
		bool mActive;

		/**
		 * Address: 0x004099C
		 */
		void Teardown();
	};
}
