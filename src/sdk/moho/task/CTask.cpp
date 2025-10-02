#include "CTask.h"

#include "CTaskThread.h"
using namespace moho;

CTask::~CTask() {
    if (mTaskThread) {
        mTaskThread->mPending = 0;
        if (mTaskThread->mStaged) {
            mTaskThread->Unstage();
        }

        TaskInterruptSubtasks();

        CTask** link = &mTaskThread->mTask;
        while (*link != this) {
            link = &(*link)->mSubtask;
        }
        *link = mSubtask;

        mSubtask = nullptr;
        mTaskThread = nullptr;
    }
    if (mDestroyed != nullptr) {
        *mDestroyed = true;
    }
}

CTask::CTask(CTaskThread* thread, const bool owning) {
    if (owning) {
        mIsOwning = true;
        mTaskThread = thread;
        mSubtask = thread->mTask;
        thread->mTask = this;
    }
}

void CTask::TaskInterruptSubtasks() const {
    if (mTaskThread == nullptr) {
	    return;
    }

    while (mTaskThread->mTask != this) {
	    CTask* task = mTaskThread->mTask;
	    if (task != nullptr) {
            mTaskThread->mTask = task->mSubtask;
		    task->mSubtask = nullptr;
		    task->mTaskThread = nullptr;
		    if (!task->mIsOwning) {
			    delete task;
		    }
	    }
    }
}

void CTask::TaskResume(const int pending, const bool interrupt) const {
    if (mTaskThread != nullptr) {
        mTaskThread->mPending = pending;
        mTaskThread->Unstage();
        if (interrupt) {
            TaskInterruptSubtasks();
        }
    }
}
