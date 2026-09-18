// stackdump - walk every thread of a live 32-bit process and print a
// symbolised call stack for each one.
//
// Why this exists: a crash leaves a record (WinApp's TopLevelExceptionFilter
// logs a fault + callstack before either reporting path runs), but a *hang*
// leaves nothing at all - the log simply stops, every probe goes quiet, and
// attaching a source debugger to a wedged process is often itself unresponsive.
// This attaches read-only, suspends each thread just long enough to walk it,
// and tells you exactly where the process is stuck.
//
// Build (32-bit, to match main.exe):
//   scripts\buildsd.bat
//
// Usage:
//   stackdump <pid>
//   stackdump main.exe          (first process with that image name)
//
// Symbols resolve against main.pdb next to the executable, so run it with the
// staged binary's directory available - by default C:\ProgramData\FAForever\bin.

#include <windows.h>
#include <dbghelp.h>
#include <tlhelp32.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>

namespace {

const char* kDefaultSymbolPath = "C:\\ProgramData\\FAForever\\bin";

DWORD FindProcessByName(const char* imageName)
{
  HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
  if (snap == INVALID_HANDLE_VALUE) {
    return 0;
  }

  PROCESSENTRY32 entry;
  ::memset(&entry, 0, sizeof(entry));
  entry.dwSize = sizeof(entry);

  DWORD found = 0;
  if (::Process32First(snap, &entry)) {
    do {
      if (::_stricmp(entry.szExeFile, imageName) == 0) {
        found = entry.th32ProcessID;
        break;
      }
    } while (::Process32Next(snap, &entry));
  }
  ::CloseHandle(snap);
  return found;
}

void PrintFrame(HANDLE process, DWORD64 address, int index)
{
  // SymFromAddr wants room for the name inline after the struct. MaxNameLen is
  // a count of characters, so the buffer has to carry that many bytes past the
  // fixed part - getting this wrong is how the crash reporter used to corrupt
  // its own stack.
  const size_t kMaxName = 512;
  unsigned char symbolStorage[sizeof(SYMBOL_INFO) + kMaxName];
  ::memset(symbolStorage, 0, sizeof(symbolStorage));

  SYMBOL_INFO* symbol = reinterpret_cast<SYMBOL_INFO*>(symbolStorage);
  symbol->SizeOfStruct = sizeof(SYMBOL_INFO);
  symbol->MaxNameLen = static_cast<ULONG>(kMaxName - 1);

  DWORD64 displacement = 0;
  const bool haveSymbol = ::SymFromAddr(process, address, &displacement, symbol) != FALSE;

  IMAGEHLP_LINE64 line;
  ::memset(&line, 0, sizeof(line));
  line.SizeOfStruct = sizeof(line);
  DWORD lineDisplacement = 0;
  const bool haveLine = ::SymGetLineFromAddr64(process, address, &lineDisplacement, &line) != FALSE;

  std::printf("  [%2d] 0x%08llX", index, static_cast<unsigned long long>(address));
  if (haveSymbol) {
    std::printf("  %s+0x%llX", symbol->Name, static_cast<unsigned long long>(displacement));
  } else {
    std::printf("  <no symbol>");
  }
  if (haveLine) {
    std::printf("  (%s:%lu)", line.FileName, static_cast<unsigned long>(line.LineNumber));
  }
  std::printf("\n");
}

void WalkThread(HANDLE process, DWORD threadId)
{
  HANDLE thread = ::OpenThread(THREAD_GET_CONTEXT | THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION,
                               FALSE, threadId);
  if (thread == NULL) {
    std::printf("thread %lu: OpenThread failed (%lu)\n", threadId, ::GetLastError());
    return;
  }

  // Suspending is what makes the context coherent; it is released below no
  // matter which way this function exits.
  if (::SuspendThread(thread) == static_cast<DWORD>(-1)) {
    std::printf("thread %lu: SuspendThread failed (%lu)\n", threadId, ::GetLastError());
    ::CloseHandle(thread);
    return;
  }

  CONTEXT context;
  ::memset(&context, 0, sizeof(context));
  context.ContextFlags = CONTEXT_FULL;

  if (!::GetThreadContext(thread, &context)) {
    std::printf("thread %lu: GetThreadContext failed (%lu)\n", threadId, ::GetLastError());
    ::ResumeThread(thread);
    ::CloseHandle(thread);
    return;
  }

  STACKFRAME64 frame;
  ::memset(&frame, 0, sizeof(frame));
  frame.AddrPC.Offset = context.Eip;
  frame.AddrPC.Mode = AddrModeFlat;
  frame.AddrFrame.Offset = context.Ebp;
  frame.AddrFrame.Mode = AddrModeFlat;
  frame.AddrStack.Offset = context.Esp;
  frame.AddrStack.Mode = AddrModeFlat;

  std::printf("\n--- thread %lu  eip=0x%08lX esp=0x%08lX ---\n",
              threadId,
              static_cast<unsigned long>(context.Eip),
              static_cast<unsigned long>(context.Esp));

  for (int depth = 0; depth < 128; ++depth) {
    if (!::StackWalk64(IMAGE_FILE_MACHINE_I386, process, thread, &frame, &context,
                       NULL, ::SymFunctionTableAccess64, ::SymGetModuleBase64, NULL)) {
      break;
    }
    if (frame.AddrPC.Offset == 0) {
      break;
    }
    PrintFrame(process, frame.AddrPC.Offset, depth);
  }

  ::ResumeThread(thread);
  ::CloseHandle(thread);
}

} // namespace

int main(int argc, char** argv)
{
  if (argc < 2) {
    std::printf("usage: stackdump <pid | image-name>\n");
    return 2;
  }

  DWORD pid = static_cast<DWORD>(::strtoul(argv[1], NULL, 10));
  if (pid == 0) {
    pid = FindProcessByName(argv[1]);
    if (pid == 0) {
      std::printf("no process named '%s'\n", argv[1]);
      return 1;
    }
  }

  HANDLE process = ::OpenProcess(
    PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
  if (process == NULL) {
    std::printf("OpenProcess(%lu) failed (%lu) - run from an elevated shell if needed\n",
                pid, ::GetLastError());
    return 1;
  }

  ::SymSetOptions(SYMOPT_LOAD_LINES | SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);

  const char* symbolPath = (argc >= 3) ? argv[2] : kDefaultSymbolPath;
  if (!::SymInitialize(process, symbolPath, TRUE)) {
    std::printf("SymInitialize failed (%lu)\n", ::GetLastError());
    ::CloseHandle(process);
    return 1;
  }

  std::printf("stackdump pid=%lu symbols=%s\n", pid, symbolPath);

  HANDLE snap = ::CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
  if (snap == INVALID_HANDLE_VALUE) {
    std::printf("CreateToolhelp32Snapshot failed (%lu)\n", ::GetLastError());
    ::SymCleanup(process);
    ::CloseHandle(process);
    return 1;
  }

  THREADENTRY32 threadEntry;
  ::memset(&threadEntry, 0, sizeof(threadEntry));
  threadEntry.dwSize = sizeof(threadEntry);

  int threadCount = 0;
  if (::Thread32First(snap, &threadEntry)) {
    do {
      if (threadEntry.th32OwnerProcessID == pid) {
        WalkThread(process, threadEntry.th32ThreadID);
        ++threadCount;
      }
    } while (::Thread32Next(snap, &threadEntry));
  }
  ::CloseHandle(snap);

  std::printf("\nwalked %d thread(s)\n", threadCount);

  ::SymCleanup(process);
  ::CloseHandle(process);
  return 0;
}
