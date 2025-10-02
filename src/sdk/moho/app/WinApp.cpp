#include "WinApp.h"

#include "CWaitHandleSet.h"
using namespace moho;

CTaskStage* moho::WIN_GetBeforeEventsStage() {
    // 0x011043CC
    static CTaskStage sBeforeEventsStage{};
    return &sBeforeEventsStage;
}

CTaskStage* moho::WIN_GetBeforeWaitStage() {
    // 0x011043B4
    static CTaskStage sBeforeWaitStage;
    return &sBeforeWaitStage;
}

CWaitHandleSet* moho::WIN_GetWaitHandleSet() {
    static CWaitHandleSet sWaitHandleSet;
    return &sWaitHandleSet;
}
