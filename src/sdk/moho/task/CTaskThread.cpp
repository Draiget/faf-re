#include "CTaskThread.h"

#include "CTask.h"
using namespace moho;

CTaskThread::CTaskThread(CTaskStage* stage) {
    ListLinkBefore(&stage->mThreads);
}

CTaskStage* CTaskThread::Destroy() noexcept {
    // Pop the task stack: mTask is the top, each task points to previous via mSubtask.
    while (mTask) {
        CTask* t = mTask;
        mTask = t->mSubtask;

        const bool owning = (t->mIsOwning != 0);
        t->mSubtask = nullptr;
        t->mTaskThread = nullptr;

        // In asm: call scalar deleting dtor via vtable with flag==1.
        // In C++ this is simply 'delete t;' because ~CTask is virtual.
        if (owning) {
            delete t;
        }
    }

    mPending = 0;

    if (mStaged) {
        ListLinkBefore(&mStage->mThreads);
        mStaged = false;
    }

    return mStage;
}

void CTaskThread::Stage() {
    if (mStaged) {
	    return;
    }

    ListLinkBefore(&mStage->mStagedThreads);
    mStaged = true;
}

void CTaskThread::Unstage() {
    if (!mStaged) {
	    return;
    }
    ListLinkBefore(&mStage->mThreads);
    mStaged = false;
}

void CTaskStage::Teardown() {
    // Mark as inactive first (sub_4099C0: *(BYTE*)(a1+16)=0)
    mActive = false;

    // Drain regular list
    while (!mThreads.ListIsSingleton()) {
        auto* n = static_cast<CTaskThread*>(mThreads.mNext);
        ::operator delete(n);
    }
    // Drain staged list
    while (!mStagedThreads.ListIsSingleton()) {
        auto* n = static_cast<CTaskThread*>(mStagedThreads.mNext);
        ::operator delete(n);
    }
}
