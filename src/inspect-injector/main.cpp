#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <cstdio>
#include <filesystem>

#include "vs_attach.h"

namespace fs = std::filesystem;

static std::wstring GetEnvW(const wchar_t* name) {
    wchar_t buf[4096];
    const DWORD n = GetEnvironmentVariableW(name, buf, (DWORD)std::size(buf));
    return (n > 0 && n < std::size(buf)) ? std::wstring(buf, n) : L"";
}

static std::wstring GetSiblingDll(const wchar_t* dllName) {
    wchar_t exe[MAX_PATH];
    GetModuleFileNameW(nullptr, exe, MAX_PATH);
    const fs::path p = fs::path(exe).parent_path() / dllName;
    return p.wstring();
}

static std::wstring ComputeDllName() {
    const auto name = GetEnvW(L"HOOK_NAME").empty() ? L"inspect.dll" : GetEnvW(L"HOOK_NAME");
    return name;
}

static std::wstring ComputeDllPath() {
    // 1) From ENV (provided by VS)
    const auto sol = GetEnvW(L"SOLUTION_DIR");
    const auto plat = GetEnvW(L"PLATFORM");
    const auto cfg = GetEnvW(L"CONFIGURATION");
    const auto proj = GetEnvW(L"HOOK_PROJECT");
    const auto name = ComputeDllName();

    if (!sol.empty() && !plat.empty() && !cfg.empty() && !proj.empty()) {
        fs::path p = fs::path(sol) / L"output" / proj / plat / cfg / name;
        if (fs::exists(p)) return p.wstring();
    }

    // 2) Fallback — sibling DLL next to injector
    return GetSiblingDll(name.empty() ? L"inspect.dll" : name.c_str());
}

static bool EnableDebugPrivilege() {
    HANDLE hToken{};
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken))
        return false;

    TOKEN_PRIVILEGES tp{};
    LUID luid{};
    if (!LookupPrivilegeValue(nullptr, SE_DEBUG_NAME, &luid)) {
        CloseHandle(hToken);
        return false;
    }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;

    const bool ok = AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(tp), nullptr, nullptr) && GetLastError() == ERROR_SUCCESS;
    CloseHandle(hToken);
    return ok;
}

static DWORD FindProcessIdByName(const wchar_t* exeName) {
    // Returns first match PID or 0 if not found
    const HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);

    DWORD pid = 0;
    if (Process32FirstW(snap, &pe)) {
        do {
            if (_wcsicmp(pe.szExeFile, exeName) == 0) { pid = pe.th32ProcessID; break; }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

// Find module base in target by name (case-insensitive)
static HMODULE RemoteGetModuleBase(const DWORD pid, const wchar_t* modName) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
    if (snap == INVALID_HANDLE_VALUE) return nullptr;
    MODULEENTRY32W me{ sizeof(me) };
    HMODULE base = nullptr;
    if (Module32FirstW(snap, &me)) {
        do {
            if (_wcsicmp(me.szModule, modName) == 0) { base = me.hModule; break; }
        } while (Module32NextW(snap, &me));
    }
    CloseHandle(snap);
    return base;
}


// Return HMODULE that actually contains the given function pointer (kernel32 or kernelbase)
static HMODULE LocalModuleFromAddress(const void* p) {
    HMODULE mod = nullptr;
    if (GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS |
        GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
        static_cast<LPCWSTR>(p), &mod)) {
        return mod;
    }
    return nullptr;
}

// Get basename of module (e.g., "KERNELBASE.DLL")
static std::wstring ModuleBaseNameW(const HMODULE mod) {
    wchar_t path[MAX_PATH];
    DWORD n = GetModuleFileNameW(mod, path, MAX_PATH);
    if (!n) return L"";
    const wchar_t* base = wcsrchr(path, L'\\');
    return base ? base + 1 : path;
}

// Resolve remote address of a function by matching module + RVA
static LPTHREAD_START_ROUTINE ResolveRemoteProcByRva(
	const DWORD pid, const char* procName,
    std::wstring* outWhichModule /*optional log*/)
{
    HMODULE k32 = GetModuleHandleW(L"KERNEL32.DLL");
    FARPROC pLocal = GetProcAddress(k32, procName);
    if (!pLocal) return nullptr;

    // Which module actually contains this pointer? (kernel32 or kernelbase)
    HMODULE localOwner = LocalModuleFromAddress((void*)pLocal);
    if (!localOwner) return nullptr;

    // Compute RVA inside that module
    auto rva = reinterpret_cast<uintptr_t>(pLocal) - reinterpret_cast<uintptr_t>(localOwner);

    // Find same-named module in target
    std::wstring ownerName = ModuleBaseNameW(localOwner); // e.g. "KERNELBASE.DLL"
    if (outWhichModule) *outWhichModule = ownerName;

    HMODULE remoteOwner = RemoteGetModuleBase(pid, ownerName.c_str());
    if (!remoteOwner) return nullptr;

    return reinterpret_cast<LPTHREAD_START_ROUTINE>(reinterpret_cast<uintptr_t>(remoteOwner) + rva);
}

// Is our DLL already loaded? (case-insensitive "inspect.dll")
static HMODULE RemoteFindInspectDll(const DWORD pid) {
    return RemoteGetModuleBase(pid, ComputeDllName().c_str());
}

// Map local DLL without running DllMain and fetch export RVA
static bool GetExportRvaByName(const std::wstring& dllPath, const char* exportName, uintptr_t& outRva) {
    outRva = 0;
    HMODULE hLocal = LoadLibraryExW(dllPath.c_str(), nullptr, DONT_RESOLVE_DLL_REFERENCES);
    if (!hLocal) return false;
    FARPROC p = GetProcAddress(hLocal, exportName);
    if (!p) { FreeLibrary(hLocal); return false; }
    outRva = reinterpret_cast<uintptr_t>(p) - reinterpret_cast<uintptr_t>(hLocal);
    FreeLibrary(hLocal);
    return true;
}

// Call exported no-arg function inside target: thread starts at (remoteDll + rva)
static bool RemoteCallExportNoArgs(const HANDLE hProc, HMODULE remoteDllBase, const uintptr_t exportRva) {
	const auto remoteStart = reinterpret_cast<LPTHREAD_START_ROUTINE>(reinterpret_cast<uintptr_t>(remoteDllBase) + exportRva);
    const HANDLE th = CreateRemoteThread(hProc, nullptr, 0, remoteStart, nullptr, 0, nullptr);
    if (!th) return false;
    WaitForSingleObject(th, INFINITE);
    DWORD ec = 0; GetExitCodeThread(th, &ec);
    CloseHandle(th);
    return true; // ec опционально можно проверить
}

// Resolve FreeLibrary in remote (handles kernel32/kernelbase forwarders)
static LPTHREAD_START_ROUTINE ResolveRemoteFreeLibrary(const DWORD pid) {
    std::wstring owner;
    return ResolveRemoteProcByRva(pid, "FreeLibrary", &owner); // твой helper из ранее
}

// Call FreeLibrary(remoteDllBase) once
static bool RemoteFreeLibraryOnce(const HANDLE hProc, const LPTHREAD_START_ROUTINE remoteFreeLibrary, const HMODULE remoteDllBase) {
	const HANDLE th = CreateRemoteThread(hProc, nullptr, 0, remoteFreeLibrary, remoteDllBase, 0, nullptr);
    if (!th) return false;
    WaitForSingleObject(th, INFINITE);
    DWORD ec = 0; GetExitCodeThread(th, &ec); // BOOL
    CloseHandle(th);
    return (ec != 0);
}

// Loop FreeLibrary until module disappears (refcount -> 0)
static bool RemoteFreeLibraryAll(const HANDLE hProc, const DWORD pid, const HMODULE remoteDllBase) {
	const auto freeLib = ResolveRemoteFreeLibrary(pid);
    if (!freeLib) {
        return false;
    }

    int safety = 32;
    while (safety-- > 0) {
        if (!RemoteFreeLibraryOnce(hProc, freeLib, remoteDllBase)) break;
        Sleep(30);
        if (!RemoteFindInspectDll(pid)) return true; // gone
    }
    return (RemoteFindInspectDll(pid) == nullptr);
}

int wmain(int argc, wchar_t** argv) {
	const auto targetName = L"ForgedAlliance.exe";

    // Decide DLL path
    std::wstring dllPath = ComputeDllPath();

    // Sanity
    if (GetFileAttributesW(dllPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::fwprintf(stderr, L"[!] DLL not found: %s\n", dllPath.c_str());
        return 1;
    }

    EnableDebugPrivilege();

    // Find target process
    const DWORD pid = FindProcessIdByName(targetName);
    if (!pid) {
        std::fwprintf(stderr, L"[!] Process not found: %s\n", targetName);
        return 2;
    }
    std::wprintf(L"[*] Target PID: %lu\n", pid);

    // Open process
    HANDLE hProc = OpenProcess(
        PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
        PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ |
        SYNCHRONIZE,
        FALSE, pid);
    if (!hProc) {
        std::fwprintf(stderr, L"[!] OpenProcess failed: %lu\n", GetLastError());
        return 3;
    }

    // Validate x86->x86 (WOW64 check)
    BOOL selfWow64 = FALSE, remoteWow64 = FALSE;
    IsWow64Process(GetCurrentProcess(), &selfWow64);
    IsWow64Process(hProc, &remoteWow64);
    if (!selfWow64 && remoteWow64) {
        // Running 32-bit target on 64-bit OS while injector is 64-bit: not allowed in our setup.
        std::fwprintf(stderr, L"[!] Architecture mismatch. Build injector as Win32 (x86).\n");
        CloseHandle(hProc);
        return 4;
    }

    // --- Replacement: resolve remote address by owner module + RVA ---
    std::wstring ownerMod;
    LPTHREAD_START_ROUTINE remoteLoadLib = ResolveRemoteProcByRva(pid, "LoadLibraryW", &ownerMod);
    if (!remoteLoadLib) {
        std::fwprintf(stderr, L"[!] Failed to resolve LoadLibraryW in remote (owner=%s)\n", ownerMod.c_str());
        CloseHandle(hProc);
        return 7; // same error range is fine
    }
    std::wprintf(L"[*] LoadLibraryW owner in this OS: %s\n", ownerMod.c_str());

    // --- Attach-only if DLL is already loaded ---
    if (HMODULE already = RemoteFindInspectDll(pid)) {
        std::wprintf(L"[*] %s already loaded at 0x%p — attach only.\n",
            ComputeDllName().c_str(), already);

        // Attach the SAME VS instance that is debugging this injector
        if (!VS_AttachSameVSInstanceToPid(pid)) {
            std::fwprintf(stderr, L"[!] Auto-attach failed. Make sure VS is running and elevation matches.\n");
        }

        std::wprintf(L"[*] Waiting for target process to exit...\n");
        WaitForSingleObject(hProc, INFINITE);

        DWORD exitCode = 0;
        GetExitCodeProcess(hProc, &exitCode);
        std::wprintf(L"[*] Target exited with code 0x%08X\n", exitCode);

        CloseHandle(hProc);
        return 0;
    }
    // --- /attach-only ---

    // Allocate path buffer in target
    const SIZE_T bytes = (dllPath.size() + 1) * sizeof(wchar_t);
    void* remoteBuf = VirtualAllocEx(hProc, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteBuf) {
        std::fwprintf(stderr, L"[!] VirtualAllocEx failed: %lu\n", GetLastError());
        CloseHandle(hProc); return 8;
    }

    if (!WriteProcessMemory(hProc, remoteBuf, dllPath.c_str(), bytes, nullptr)) {
        std::fwprintf(stderr, L"[!] WriteProcessMemory failed: %lu\n", GetLastError());
        VirtualFreeEx(hProc, remoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProc); return 9;
    }

    // Attach the SAME VS instance that is debugging this injector:
    if (!VS_AttachSameVSInstanceToPid(pid)) {
        std::fwprintf(stderr, L"[!] Auto-attach failed. "
            L"Ensure the same elevation for VS/injector/game and VS is running.\n");
    }

    // Create remote thread: LoadLibraryW(dllPath)
    const HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, remoteLoadLib, remoteBuf, 0, nullptr);
    if (!hThread) {
        std::fwprintf(stderr, L"[!] CreateRemoteThread failed: %lu\n", GetLastError());
        VirtualFreeEx(hProc, remoteBuf, 0, MEM_RELEASE);
        CloseHandle(hProc); return 10;
    }

    // Wait for completion and get HMODULE
    WaitForSingleObject(hThread, INFINITE);

    DWORD dllBaseRemote = 0;
    GetExitCodeThread(hThread, &dllBaseRemote);

    DWORD procExit = STILL_ACTIVE;
    GetExitCodeProcess(hProc, &procExit);
    std::wprintf(L"[*] LoadLibraryW ret=0x%08lX, target=%s (code=0x%08X)\n",
        dllBaseRemote, (procExit == STILL_ACTIVE ? L"alive" : L"exited"), procExit);

    CloseHandle(hThread);
    VirtualFreeEx(hProc, remoteBuf, 0, MEM_RELEASE);

    if (!dllBaseRemote) {
        std::fwprintf(stderr, L"[!] LoadLibraryW returned NULL. Check DLL path/bitness.\n");
        CloseHandle(hProc); return 11;
    }

    std::wprintf(L"[+] Injected: 0x%08lX\n", dllBaseRemote);

    // Keep injector alive while you debug the game
    std::wprintf(L"[*] Waiting for target process to exit...\n");
    WaitForSingleObject(hProc, INFINITE);

    DWORD exitCode = 0;
    GetExitCodeProcess(hProc, &exitCode);
    std::wprintf(L"[*] Target exited with code 0x%08X\n", exitCode);

    // (Optional) Call exported init explicitly:
    // FARPROC localGetProc = GetProcAddress(localK32, "GetProcAddress");
    // HMODULE remoteK32Again = RemoteGetModuleBase(pid, L"KERNEL32.DLL");
    // auto remoteGetProc = (LPTHREAD_START_ROUTINE)((uintptr_t)remoteK32Again + ((uintptr_t)localGetProc - (uintptr_t)localK32));
    // ... (for simplicity we rely on DllMain thread)

    CloseHandle(hProc);
    return 0;
}
