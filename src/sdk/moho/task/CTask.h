#pragma once

#include "gpg/core/utils/BoostUtils.h"
#include "moho/app/WinApp.h"
#include "moho/misc/InstanceCounter.h"
#include "platform/Platform.h"

namespace moho
{
	enum ETaskState
	{
		TASKSTATE_Preparing = 0x0,
		TASKSTATE_Waiting = 0x1,
		TASKSTATE_Starting = 0x2,
		TASKSTATE_Processing = 0x3,
		TASKSTATE_Complete = 0x4,
		TASKSTATE_5 = 0x5,
		TASKSTATE_6 = 0x6,
		TASKSTATE_7 = 0x7,
		TASKSTATE_8 = 0x8,
	};

	class CTaskThread;

	class MOHO_EMPTY_BASES CTask :
		public boost::noncopyable_::noncopyable,
		public InstanceCounter<CTask>
	{
	public:
		/**
		 * In binary:
		 *
		 * Address: 0x408C90
		 * VFTable SLOT: 0
		 */
		virtual ~CTask();

		/**
		 * In binary: __purecall
		 *
		 * Address: 0xA82547
		 * VFTable SLOT: 1
		 */
		virtual int Execute() = 0;

		/**
		 * Address: 0x00408C40
		 */
		CTask(CTaskThread* thread, bool owning);

		/**
		 * Address: 0x00408D70
		 */
		void TaskInterruptSubtasks() const;

		/**
		 * Address: 0x00408DB0
		 */
		void TaskResume(int pending, bool interrupt) const;

	public:
		bool* mDestroyed{ nullptr };
		CTaskThread* mTaskThread{ nullptr };
		CTask* mSubtask{ nullptr };
		bool mIsOwning{ false };
	};

	static_assert(sizeof(CTask) == 0x14, "size of CTask must be 0x14");

	template<class T>
	class MOHO_EMPTY_BASES CPushTask :
		public CTask,
		public boost::noncopyable_::noncopyable,
		public InstanceCounter<CTask>
	{
	public:
		CPushTask();

	private:
		int32_t padding0_;
		int32_t padding1_;
	};
	static_assert(sizeof(CPushTask<void>) == 0x1C, "size of CPushTask must be 0x1C");

	template <class T>
	CPushTask<T>::CPushTask() :
		CTask(new CTaskThread(WIN_GetBeforeWaitStage()), false)
	{
	}

	template<class T>
	class MOHO_EMPTY_BASES CPullTask : public CTask
	{
	public:
		CPullTask();

	private:
		int32_t padding0_;
	};
	static_assert(sizeof(CPullTask<void>) == 0x18, "size of CPullTask must be 0x18");

	template <class T>
	CPullTask<T>::CPullTask() :
		CTask(new CTaskThread(WIN_GetBeforeEventsStage()), false)
	{
	}
}
