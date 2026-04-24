#include <windows.h>
#include <tlhelp32.h>
#include <string>
#include <vector>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <format>
#include <algorithm>

#include "vs_attach.h"

namespace fs = std::filesystem;

static std::wstring StripWrappingQuotes(std::wstring value);

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
    if (const auto explicitPath = StripWrappingQuotes(GetEnvW(L"INSPECT_DLL_PATH")); !explicitPath.empty()) {
        return explicitPath;
    }

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
    const fs::path sibling = GetSiblingDll(name.empty() ? L"inspect.dll" : name.c_str());
    if (fs::exists(sibling)) {
        return sibling.wstring();
    }

    // 3) Repo output fallback:
    //    output/inspect-injector/<Platform>/<Config>/inspect-injector.exe
    // -> output/inspect/<Platform>/<Config>/inspect.dll
    wchar_t exePathBuf[MAX_PATH];
    GetModuleFileNameW(nullptr, exePathBuf, MAX_PATH);
    const fs::path exeDir = fs::path(exePathBuf).parent_path();
    if (exeDir.has_parent_path() &&
        exeDir.parent_path().has_parent_path() &&
        exeDir.parent_path().parent_path().has_parent_path())
    {
        const fs::path outputRoot = exeDir.parent_path().parent_path().parent_path();
        const fs::path candidate = outputRoot / L"inspect" / exeDir.parent_path().filename() / exeDir.filename() / name;
        if (fs::exists(candidate)) {
            return candidate.wstring();
        }
    }

    return sibling.wstring();
}

static std::wstring FormatWin32Error(const DWORD error) {
    wchar_t* msg = nullptr;
    const DWORD flags = FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS;
    const DWORD chars = FormatMessageW(flags, nullptr, error, 0, reinterpret_cast<LPWSTR>(&msg), 0, nullptr);
    if (!chars || msg == nullptr) {
        return L"(no message)";
    }
    std::wstring out(msg, chars);
    LocalFree(msg);
    while (!out.empty() && (out.back() == L'\r' || out.back() == L'\n' || out.back() == L' ')) {
        out.pop_back();
    }
    return out;
}

static bool EndsWithI(const std::string& value, const char* suffix) {
    const std::string sfx(suffix);
    if (value.size() < sfx.size()) return false;
    for (size_t i = 0; i < sfx.size(); ++i) {
        char a = value[value.size() - sfx.size() + i];
        char b = sfx[i];
        if (a >= 'A' && a <= 'Z') a = static_cast<char>(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z') b = static_cast<char>(b - 'A' + 'a');
        if (a != b) return false;
    }
    return true;
}

static bool IsDebugRuntimeImport(const std::string& moduleName) {
    return
        EndsWithI(moduleName, "msvcp140d.dll") ||
        EndsWithI(moduleName, "vcruntime140d.dll") ||
        EndsWithI(moduleName, "ucrtbased.dll");
}

static bool IsTruthy(const std::wstring& value) {
    if (value.empty()) return false;
    std::wstring lower = value;
    std::transform(lower.begin(), lower.end(), lower.begin(), [](wchar_t ch) {
        if (ch >= L'A' && ch <= L'Z') return static_cast<wchar_t>(ch - L'A' + L'a');
        return ch;
    });
    return lower == L"1" || lower == L"true" || lower == L"yes" || lower == L"on";
}

static std::wstring TrimWs(std::wstring value) {
    auto is_ws = [](wchar_t ch) {
        return ch == L' ' || ch == L'\t' || ch == L'\r' || ch == L'\n';
    };
    while (!value.empty() && is_ws(value.front())) {
        value.erase(value.begin());
    }
    while (!value.empty() && is_ws(value.back())) {
        value.pop_back();
    }
    return value;
}

static std::wstring StripWrappingQuotes(std::wstring value) {
    value = TrimWs(std::move(value));
    if (value.size() >= 2 && value.front() == L'"' && value.back() == L'"') {
        value = value.substr(1, value.size() - 2);
    } else if (value.size() >= 2 && value.front() == L'\'' && value.back() == L'\'') {
        value = value.substr(1, value.size() - 2);
    }
    return TrimWs(std::move(value));
}

static DWORD RvaToFileOffset(const uint8_t* base, const size_t size, const DWORD rva) {
    if (size < sizeof(IMAGE_DOS_HEADER)) return 0;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return 0;
    if (dos->e_lfanew <= 0 || static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS32) > size) return 0;

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS32*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return 0;

    const auto* sec = IMAGE_FIRST_SECTION(nt);
    for (unsigned i = 0; i < nt->FileHeader.NumberOfSections; ++i) {
        const DWORD va = sec[i].VirtualAddress;
        const DWORD raw = sec[i].PointerToRawData;
        const DWORD vsize = sec[i].Misc.VirtualSize;
        const DWORD rsize = sec[i].SizeOfRawData;
        const DWORD span = (vsize > rsize) ? vsize : rsize;
        if (rva >= va && rva < va + span) {
            const DWORD off = raw + (rva - va);
            if (off < size) return off;
            return 0;
        }
    }
    return 0;
}

static bool ScanPeImportModules(const std::wstring& pePath, std::vector<std::string>& outModules) {
    outModules.clear();

    std::ifstream in(pePath, std::ios::binary | std::ios::ate);
    if (!in.is_open()) return false;

    const auto end = in.tellg();
    if (end <= 0) return false;
    std::vector<uint8_t> bytes(static_cast<size_t>(end));
    in.seekg(0, std::ios::beg);
    in.read(reinterpret_cast<char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
    if (!in) return false;

    if (bytes.size() < sizeof(IMAGE_DOS_HEADER)) return false;
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(bytes.data());
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return false;
    if (dos->e_lfanew <= 0 || static_cast<size_t>(dos->e_lfanew) + sizeof(IMAGE_NT_HEADERS32) > bytes.size()) return false;

    const auto* nt32 = reinterpret_cast<const IMAGE_NT_HEADERS32*>(bytes.data() + dos->e_lfanew);
    if (nt32->Signature != IMAGE_NT_SIGNATURE) return false;

    DWORD importRva = 0;
    if (nt32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC) {
        importRva = nt32->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    } else if (nt32->OptionalHeader.Magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        const auto* nt64 = reinterpret_cast<const IMAGE_NT_HEADERS64*>(nt32);
        importRva = nt64->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress;
    } else {
        return false;
    }

    if (importRva == 0) return true;
    const DWORD impOff = RvaToFileOffset(bytes.data(), bytes.size(), importRva);
    if (impOff == 0 || impOff >= bytes.size()) return false;

    const auto* imp = reinterpret_cast<const IMAGE_IMPORT_DESCRIPTOR*>(bytes.data() + impOff);
    constexpr size_t kMaxImportDescriptors = 4096;
    for (size_t i = 0; i < kMaxImportDescriptors; ++i) {
        const auto& d = imp[i];
        if (d.Name == 0 && d.OriginalFirstThunk == 0 && d.FirstThunk == 0) break;
        if (d.Name == 0) continue;

        const DWORD nameOff = RvaToFileOffset(bytes.data(), bytes.size(), d.Name);
        if (nameOff == 0 || nameOff >= bytes.size()) continue;
        const char* s = reinterpret_cast<const char*>(bytes.data() + nameOff);
        const size_t maxLen = bytes.size() - nameOff;
        size_t len = 0;
        while (len < maxLen && s[len] != '\0') ++len;
        if (len == 0 || len >= maxLen) continue;
        outModules.emplace_back(s, len);
    }
    return true;
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

// Forward declaration for loader warm-up helpers.
static HMODULE RemoteGetModuleBase(const DWORD pid, const wchar_t* modName);

static bool LaunchProcessSuspended(
    const std::wstring& exePath,
    const std::wstring& args,
    PROCESS_INFORMATION& outPi)
{
    outPi = PROCESS_INFORMATION{};
    STARTUPINFOW si{};
    si.cb = sizeof(si);

    std::wstring cmdline = std::format(L"\"{}\"", exePath);
    if (!args.empty()) {
        cmdline += L" ";
        cmdline += args;
    }

    std::vector<wchar_t> mutableCmdline(cmdline.begin(), cmdline.end());
    mutableCmdline.push_back(L'\0');

    const fs::path exeFs(exePath);
    const fs::path workDir = exeFs.has_parent_path() ? exeFs.parent_path() : fs::current_path();

    const BOOL ok = CreateProcessW(
        exePath.c_str(),
        mutableCmdline.data(),
        nullptr,
        nullptr,
        FALSE,
        CREATE_SUSPENDED,
        nullptr,
        workDir.wstring().c_str(),
        &si,
        &outPi);
    return ok != FALSE;
}

static bool WarmupLoaderUntilKernelModules(const DWORD pid, HANDLE hMainThread, const HANDLE hProc, bool& outResumedMainThread) {
    outResumedMainThread = false;
    if (hMainThread == nullptr || hProc == nullptr) {
        return false;
    }

    if (RemoteGetModuleBase(pid, L"KERNEL32.DLL") || RemoteGetModuleBase(pid, L"KERNELBASE.DLL")) {
        return true;
    }

    const DWORD prev = ResumeThread(hMainThread);
    if (prev == static_cast<DWORD>(-1)) {
        return false;
    }
    outResumedMainThread = true;

    const DWORD start = GetTickCount();
    bool loaded = false;
    while ((GetTickCount() - start) < 2500) {
        if (RemoteGetModuleBase(pid, L"KERNEL32.DLL") || RemoteGetModuleBase(pid, L"KERNELBASE.DLL")) {
            loaded = true;
            break;
        }
        DWORD code = STILL_ACTIVE;
        if (GetExitCodeProcess(hProc, &code) && code != STILL_ACTIVE) {
            break;
        }
        Sleep(10);
    }
    return loaded;
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
    const bool noWait = IsTruthy(GetEnvW(L"INSPECT_INJECTOR_NO_WAIT"));
    const bool forceReload = IsTruthy(GetEnvW(L"INSPECT_INJECTOR_FORCE_RELOAD"));
    const bool skipVsAttach = IsTruthy(GetEnvW(L"INSPECT_INJECTOR_SKIP_VS_ATTACH"));
    bool launchMode = IsTruthy(GetEnvW(L"INSPECT_INJECTOR_LAUNCH"));
    std::wstring launchExePath = StripWrappingQuotes(GetEnvW(L"INSPECT_TARGET_EXE"));
    std::wstring launchArgs = StripWrappingQuotes(GetEnvW(L"INSPECT_TARGET_ARGS"));

    for (int i = 1; i < argc; ++i) {
        const std::wstring arg = argv[i] ? std::wstring(argv[i]) : std::wstring{};
        if (arg == L"--launch") {
            launchMode = true;
            if ((i + 1) < argc && argv[i + 1] != nullptr) {
                launchExePath = StripWrappingQuotes(argv[++i]);
            }
            continue;
        }
        if (arg == L"--args" && (i + 1) < argc && argv[i + 1] != nullptr) {
            launchArgs = StripWrappingQuotes(argv[++i]);
            continue;
        }
    }

    // Decide DLL path
    std::wstring dllPath = ComputeDllPath();

    // Sanity
    if (GetFileAttributesW(dllPath.c_str()) == INVALID_FILE_ATTRIBUTES) {
        std::fwprintf(stderr, L"[!] DLL not found: %s\n", dllPath.c_str());
        return 1;
    }
    std::wprintf(L"[*] DLL path: %s\n", dllPath.c_str());

    std::vector<std::string> imports;
    if (ScanPeImportModules(dllPath, imports)) {
        bool importsExe = false;
        bool importsDebugRuntime = false;
        for (const auto& mod : imports) {
            if (EndsWithI(mod, ".exe")) {
                importsExe = true;
                std::fwprintf(stderr, L"[!] DLL imports executable module: %S\n", mod.c_str());
            }
            if (IsDebugRuntimeImport(mod)) {
                importsDebugRuntime = true;
            }
        }
        if (importsExe) {
            std::fwprintf(stderr, L"[!] This DLL cannot be reliably injected into %s while importing an .exe module.\n", targetName);
        }
        if (importsDebugRuntime) {
            std::fwprintf(stderr, L"[!] Debug CRT dependency detected. Prefer Release inspect.dll for game injection.\n");
        }
    }

    EnableDebugPrivilege();

    DWORD pid = 0;
    HANDLE hProc = nullptr;
    HANDLE hMainThread = nullptr;
    bool launchedSuspended = false;
    auto CloseOpenHandles = [&]() {
        if (hMainThread) {
            CloseHandle(hMainThread);
            hMainThread = nullptr;
        }
        if (hProc) {
            CloseHandle(hProc);
            hProc = nullptr;
        }
    };

    if (launchMode) {
        launchExePath = StripWrappingQuotes(launchExePath);
        if (launchExePath.empty()) {
            std::fwprintf(stderr, L"[!] Launch mode requires target exe path. Set INSPECT_TARGET_EXE or pass --launch <path>.\n");
            return 2;
        }
        if (GetFileAttributesW(launchExePath.c_str()) == INVALID_FILE_ATTRIBUTES) {
            std::fwprintf(stderr, L"[!] Launch exe not found: %s\n", launchExePath.c_str());
            return 2;
        }

        PROCESS_INFORMATION pi{};
        if (!LaunchProcessSuspended(launchExePath, launchArgs, pi)) {
            const DWORD err = GetLastError();
            std::fwprintf(stderr, L"[!] CreateProcessW(CREATE_SUSPENDED) failed: %lu (%s)\n", err, FormatWin32Error(err).c_str());
            return 3;
        }

        pid = pi.dwProcessId;
        hProc = pi.hProcess;
        hMainThread = pi.hThread;
        launchedSuspended = true;

        std::wprintf(L"[*] Launch mode enabled.\n");
        std::wprintf(L"[*] Target exe: %s\n", launchExePath.c_str());
        if (!launchArgs.empty()) {
            std::wprintf(L"[*] Target args: %s\n", launchArgs.c_str());
        }
        std::wprintf(L"[*] Created suspended PID: %lu\n", pid);
    } else {
        // Find target process
        pid = FindProcessIdByName(targetName);
        if (!pid) {
            std::fwprintf(stderr, L"[!] Process not found: %s\n", targetName);
            return 2;
        }
        std::wprintf(L"[*] Target PID: %lu\n", pid);

        // Open process
        hProc = OpenProcess(
            PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION |
            PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ |
            SYNCHRONIZE,
            FALSE, pid);
        if (!hProc) {
            std::fwprintf(stderr, L"[!] OpenProcess failed: %lu\n", GetLastError());
            return 3;
        }
    }

    // Validate x86->x86 (WOW64 check)
    BOOL selfWow64 = FALSE, remoteWow64 = FALSE;
    IsWow64Process(GetCurrentProcess(), &selfWow64);
    IsWow64Process(hProc, &remoteWow64);
    if (!selfWow64 && remoteWow64) {
        // Running 32-bit target on 64-bit OS while injector is 64-bit: not allowed in our setup.
        std::fwprintf(stderr, L"[!] Architecture mismatch. Build injector as Win32 (x86).\n");
        CloseOpenHandles();
        return 4;
    }

    // --- Replacement: resolve remote address by owner module + RVA ---
    std::wstring ownerMod;
    LPTHREAD_START_ROUTINE remoteLoadLib = ResolveRemoteProcByRva(pid, "LoadLibraryW", &ownerMod);
    if (!remoteLoadLib && launchedSuspended) {
        bool resumedForWarmup = false;
        std::wprintf(L"[*] LoadLibraryW owner (%s) not mapped yet in suspended target, warming up loader...\n", ownerMod.c_str());
        if (WarmupLoaderUntilKernelModules(pid, hMainThread, hProc, resumedForWarmup)) {
            if (resumedForWarmup) {
                launchedSuspended = false;
                std::wprintf(L"[*] Target resumed for loader warm-up; continuing injection without re-suspend.\n");
            }
            remoteLoadLib = ResolveRemoteProcByRva(pid, "LoadLibraryW", &ownerMod);
            if (remoteLoadLib) {
                std::wprintf(L"[*] Loader warm-up complete; resolved LoadLibraryW owner: %s\n", ownerMod.c_str());
            }
        } else {
            if (resumedForWarmup) {
                launchedSuspended = false;
            }
            std::fwprintf(stderr, L"[!] Loader warm-up failed before resolving LoadLibraryW.\n");
        }
    }
    if (!remoteLoadLib) {
        HMODULE localK32 = GetModuleHandleW(L"KERNEL32.DLL");
        FARPROC localLoad = localK32 ? GetProcAddress(localK32, "LoadLibraryW") : nullptr;
        if (localLoad != nullptr) {
            remoteLoadLib = reinterpret_cast<LPTHREAD_START_ROUTINE>(localLoad);
            std::fwprintf(stderr, L"[!] Falling back to local LoadLibraryW address: %p (ASLR same-base assumption).\n",
                reinterpret_cast<void*>(remoteLoadLib));
        }
    }
    if (!remoteLoadLib) {
        std::fwprintf(stderr, L"[!] Failed to resolve LoadLibraryW in remote (owner=%s)\n", ownerMod.c_str());
        if (launchedSuspended && hMainThread) {
            ResumeThread(hMainThread);
            std::wprintf(L"[*] Resumed suspended target after resolve failure.\n");
        }
        CloseOpenHandles();
        return 7; // same error range is fine
    }
    std::wprintf(L"[*] LoadLibraryW owner in this OS: %s\n", ownerMod.c_str());

    // --- Attach-only if DLL is already loaded ---
    if (HMODULE already = RemoteFindInspectDll(pid)) {
        if (!forceReload) {
            std::wprintf(L"[*] %s already loaded at 0x%p — attach only.\n",
                ComputeDllName().c_str(), already);

            // Attach the SAME VS instance that is debugging this injector
            if (!skipVsAttach && !VS_AttachSameVSInstanceToPid(pid)) {
                std::fwprintf(stderr, L"[!] Auto-attach failed. Make sure VS is running and elevation matches.\n");
            }

            if (!noWait) {
                std::wprintf(L"[*] Waiting for target process to exit...\n");
                WaitForSingleObject(hProc, INFINITE);

                DWORD exitCode = 0;
                GetExitCodeProcess(hProc, &exitCode);
                std::wprintf(L"[*] Target exited with code 0x%08X\n", exitCode);
            } else {
                std::wprintf(L"[*] No-wait mode enabled; exiting injector now.\n");
            }
            CloseOpenHandles();
            return 0;
        }

        std::wprintf(L"[*] %s already loaded at 0x%p — force reload requested.\n",
            ComputeDllName().c_str(), already);

        uintptr_t cleanupRva = 0;
        if (GetExportRvaByName(dllPath, "Inspect_Cleanup", cleanupRva)) {
            RemoteCallExportNoArgs(hProc, already, cleanupRva);
        }

        if (!RemoteFreeLibraryAll(hProc, pid, already)) {
            std::fwprintf(stderr, L"[!] Failed to unload previously loaded %s before reinjection.\n", ComputeDllName().c_str());
            CloseOpenHandles();
            return 12;
        }

        std::wprintf(L"[*] Previous module unloaded, proceeding with fresh injection.\n");
    }
    // --- /attach-only ---

    // Allocate path buffer in target
    const SIZE_T bytes = (dllPath.size() + 1) * sizeof(wchar_t);
    void* remoteBuf = VirtualAllocEx(hProc, nullptr, bytes, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!remoteBuf) {
        std::fwprintf(stderr, L"[!] VirtualAllocEx failed: %lu\n", GetLastError());
        CloseOpenHandles(); return 8;
    }

    if (!WriteProcessMemory(hProc, remoteBuf, dllPath.c_str(), bytes, nullptr)) {
        std::fwprintf(stderr, L"[!] WriteProcessMemory failed: %lu\n", GetLastError());
        VirtualFreeEx(hProc, remoteBuf, 0, MEM_RELEASE);
        CloseOpenHandles(); return 9;
    }

    // Attach the SAME VS instance that is debugging this injector:
    if (!skipVsAttach && !VS_AttachSameVSInstanceToPid(pid)) {
        std::fwprintf(stderr, L"[!] Auto-attach failed. "
            L"Ensure the same elevation for VS/injector/game and VS is running.\n");
    } else if (skipVsAttach) {
        std::wprintf(L"[*] VS auto-attach skipped by INSPECT_INJECTOR_SKIP_VS_ATTACH=1\n");
    }

    // Create remote thread: LoadLibraryW(dllPath)
    const HANDLE hThread = CreateRemoteThread(hProc, nullptr, 0, remoteLoadLib, remoteBuf, 0, nullptr);
    if (!hThread) {
        const DWORD err = GetLastError();
        std::fwprintf(stderr, L"[!] CreateRemoteThread failed: %lu (%s)\n", err, FormatWin32Error(err).c_str());
        VirtualFreeEx(hProc, remoteBuf, 0, MEM_RELEASE);
        CloseOpenHandles(); return 10;
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
        std::fwprintf(stderr, L"[!] LoadLibraryW returned NULL.\n");
        std::fwprintf(stderr, L"    Possible causes:\n");
        std::fwprintf(stderr, L"    - DLL imports unavailable dependency (common: debug CRT or unrelated EXE import)\n");
        std::fwprintf(stderr, L"    - Architecture mismatch between injector/target/DLL\n");
        std::fwprintf(stderr, L"    - Blocked module load policy in target process\n");
        if (launchedSuspended && hMainThread) {
            ResumeThread(hMainThread);
            std::wprintf(L"[*] Resumed suspended target after failed injection.\n");
        }
        CloseOpenHandles(); return 11;
    }

    std::wprintf(L"[+] Injected: 0x%08lX\n", dllBaseRemote);

    if (launchedSuspended && hMainThread) {
        const DWORD prevSuspend = ResumeThread(hMainThread);
        if (prevSuspend == static_cast<DWORD>(-1)) {
            const DWORD err = GetLastError();
            std::fwprintf(stderr, L"[!] ResumeThread failed: %lu (%s)\n", err, FormatWin32Error(err).c_str());
        } else {
            std::wprintf(L"[*] Resumed target main thread (previous suspend count=%lu)\n", prevSuspend);
        }
    }

    // Keep injector alive while you debug the game
    if (!noWait) {
        std::wprintf(L"[*] Waiting for target process to exit...\n");
        WaitForSingleObject(hProc, INFINITE);

        DWORD exitCode = 0;
        GetExitCodeProcess(hProc, &exitCode);
        std::wprintf(L"[*] Target exited with code 0x%08X\n", exitCode);
    } else {
        std::wprintf(L"[*] No-wait mode enabled; exiting injector now.\n");
    }

    // (Optional) Call exported init explicitly:
    // FARPROC localGetProc = GetProcAddress(localK32, "GetProcAddress");
    // HMODULE remoteK32Again = RemoteGetModuleBase(pid, L"KERNEL32.DLL");
    // auto remoteGetProc = (LPTHREAD_START_ROUTINE)((uintptr_t)remoteK32Again + ((uintptr_t)localGetProc - (uintptr_t)localK32));
    // ... (for simplicity we rely on DllMain thread)

    CloseOpenHandles();
    return 0;
}
