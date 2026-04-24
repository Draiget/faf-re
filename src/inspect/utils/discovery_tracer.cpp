#include "discovery_tracer.h"

#include <algorithm>
#include <array>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cwchar>
#include <filesystem>
#include <fstream>
#include <format>
#include <mutex>
#include <optional>
#include <numeric>
#include <random>
#include <sstream>
#include <string>
#include <string_view>
#include <tlhelp32.h>
#include <unordered_map>
#include <unordered_set>
#include <vector>

#include "debug.h"
#include "memory/detours.h"

namespace inspect::discovery {
namespace {

using Clock = std::chrono::steady_clock;

constexpr std::size_t kTokenMaxLen = 24;
constexpr std::uint32_t kDefaultFlushDiscoveryThreshold = 25;
constexpr std::uint32_t kDefaultFlushEdgeThreshold = 200;
constexpr auto kDefaultFlushInterval = std::chrono::seconds(8);
constexpr std::uint32_t kDefaultMaxHooks = 4000;
constexpr std::uint32_t kDefaultRotateRefillScanBudget = 4;

struct HookContext {
    std::uint32_t callee_ea = 0;
    char token[kTokenMaxLen]{};
    void* trampoline = nullptr;
    void* target_entry = nullptr;
    void* owner_runtime = nullptr;
};

struct HookRuntime {
    std::string token;
    std::uint32_t address = 0;
    HookContext context{};
    void* stub = nullptr;
    std::unique_ptr<detours::Detour<void(*)()>> detour;
    std::atomic<bool> armed{ false };

    ~HookRuntime() {
        if (stub != nullptr) {
            VirtualFree(stub, 0, MEM_RELEASE);
            stub = nullptr;
        }
    }
};

struct SnapshotEdge {
    std::uint32_t caller_ret = 0;
    std::uint32_t callee = 0;
    std::uint32_t count = 0;
};

struct Snapshot {
    std::vector<std::string> discovered_tokens;
    std::vector<SnapshotEdge> edges;
    std::uint64_t events_seen = 0;
    std::uint32_t installed_hooks = 0;
    std::uint32_t failed_hooks = 0;
    std::uint32_t blocked_hooks = 0;
    std::uint32_t install_epoch = 0;
    std::uint32_t active_hooks = 0;
    std::uint32_t pending_install_tokens = 0;
    std::uint32_t refill_budget_exhausted_count = 0;
    std::uint32_t sanitized_jump_target_count = 0;
    std::uint32_t blocked_live_ip_hooks = 0;
};

thread_local HookContext* g_tls_current_hook_ctx = nullptr;
thread_local std::uint32_t g_tls_current_caller_ret = 0;
volatile std::uint32_t g_last_stub_jump_target = 0;
volatile std::uint32_t g_last_stub_ctx = 0;

class DiscoveryTracer;
extern DiscoveryTracer* g_instance;

std::string TrimCopy(std::string value) {
    while (!value.empty() && (value.front() == ' ' || value.front() == '\t' || value.front() == '\r' || value.front() == '\n')) {
        value.erase(value.begin());
    }
    while (!value.empty() && (value.back() == ' ' || value.back() == '\t' || value.back() == '\r' || value.back() == '\n')) {
        value.pop_back();
    }
    return value;
}

std::wstring GetEnvW(const wchar_t* name) {
    wchar_t buf[32768];
    const DWORD n = GetEnvironmentVariableW(name, buf, static_cast<DWORD>(std::size(buf)));
    if (n == 0 || n >= std::size(buf)) {
        return L"";
    }
    return std::wstring(buf, n);
}

std::string NarrowAscii(std::wstring_view text) {
    std::string out;
    out.reserve(text.size());
    for (const wchar_t ch : text) {
        if (ch >= 0 && ch <= 0x7F) {
            out.push_back(static_cast<char>(ch));
        } else {
            out.push_back('_');
        }
    }
    return out;
}

std::optional<std::uint32_t> ParseUint32Hex(std::string_view text) {
    std::string s(text);
    s = TrimCopy(s);
    if (s.empty()) {
        return std::nullopt;
    }
    if (s.rfind("0x", 0) == 0 || s.rfind("0X", 0) == 0) {
        s = s.substr(2);
    }
    if (s.empty() || s.size() > 8) {
        return std::nullopt;
    }
    std::uint32_t value = 0;
    for (char ch : s) {
        std::uint32_t nibble = 0;
        if (ch >= '0' && ch <= '9') {
            nibble = static_cast<std::uint32_t>(ch - '0');
        } else if (ch >= 'a' && ch <= 'f') {
            nibble = static_cast<std::uint32_t>(10 + ch - 'a');
        } else if (ch >= 'A' && ch <= 'F') {
            nibble = static_cast<std::uint32_t>(10 + ch - 'A');
        } else {
            return std::nullopt;
        }
        value = (value << 4) | nibble;
    }
    return value;
}

std::optional<std::uint32_t> ParseTokenAddress(std::string_view token) {
    std::string s(token);
    s = TrimCopy(s);
    if (s.empty()) {
        return std::nullopt;
    }
    if (s.rfind("FUN_", 0) == 0 || s.rfind("fun_", 0) == 0) {
        return ParseUint32Hex(s.substr(4));
    }
    return ParseUint32Hex(s);
}

std::string TokenFromAddress(std::uint32_t addr) {
    return std::format("FUN_{:08X}", addr);
}

std::string NormalizeToken(std::string_view token) {
    const auto addr = ParseTokenAddress(token);
    if (!addr.has_value()) {
        return {};
    }
    return TokenFromAddress(*addr);
}

std::string JsonEscape(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (const char ch : s) {
        switch (ch) {
        case '\\': out += "\\\\"; break;
        case '"': out += "\\\""; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            out.push_back(ch);
            break;
        }
    }
    return out;
}

std::string UtcNowIso8601() {
    SYSTEMTIME st{};
    GetSystemTime(&st);
    return std::format(
        "{:04}-{:02}-{:02}T{:02}:{:02}:{:02}.{:03}Z",
        st.wYear,
        st.wMonth,
        st.wDay,
        st.wHour,
        st.wMinute,
        st.wSecond,
        st.wMilliseconds);
}

std::filesystem::path GetModulePath(HMODULE module_handle) {
    std::array<wchar_t, 4096> buf{};
    const DWORD n = GetModuleFileNameW(module_handle, buf.data(), static_cast<DWORD>(buf.size()));
    if (n == 0 || n >= buf.size()) {
        return {};
    }
    return std::filesystem::path(std::wstring(buf.data(), n));
}

std::filesystem::path FindRepoRootNear(std::filesystem::path start_dir) {
    auto cur = std::move(start_dir);
    for (int i = 0; i < 10; ++i) {
        if (std::filesystem::exists(cur / "decomp" / "recovery") && std::filesystem::exists(cur / "src" / "inspect")) {
            return cur;
        }
        if (!cur.has_parent_path()) {
            break;
        }
        auto parent = cur.parent_path();
        if (parent == cur) {
            break;
        }
        cur = std::move(parent);
    }
    return start_dir;
}

std::uint64_t MakeEdgeKey(std::uint32_t caller_ret, std::uint32_t callee) {
    return (static_cast<std::uint64_t>(caller_ret) << 32u) | static_cast<std::uint64_t>(callee);
}

bool IsTruthy(std::wstring_view s) {
    std::wstring lower;
    lower.reserve(s.size());
    for (const wchar_t ch : s) {
        if (ch >= L'A' && ch <= L'Z') {
            lower.push_back(static_cast<wchar_t>(ch - L'A' + L'a'));
        } else {
            lower.push_back(ch);
        }
    }
    return lower == L"1" || lower == L"true" || lower == L"yes" || lower == L"on";
}

std::uint32_t ParseUint32OrDefault(std::wstring_view value, std::uint32_t fallback) {
    if (value.empty()) {
        return fallback;
    }
    wchar_t* end = nullptr;
    const unsigned long parsed = wcstoul(std::wstring(value).c_str(), &end, 10);
    if (end == nullptr || *end != L'\0') {
        return fallback;
    }
    return static_cast<std::uint32_t>(parsed);
}

bool IsExecutableAddress(void* p) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(p, &mbi, sizeof(mbi)) != sizeof(mbi)) {
        return false;
    }
    if ((mbi.State & MEM_COMMIT) == 0) {
        return false;
    }
    const DWORD protect = mbi.Protect & 0xFF;
    return
        protect == PAGE_EXECUTE ||
        protect == PAGE_EXECUTE_READ ||
        protect == PAGE_EXECUTE_READWRITE ||
        protect == PAGE_EXECUTE_WRITECOPY;
}

bool IsLikelyUnsafeHookEntry(const std::uint8_t* p) {
    if (p == nullptr) {
        return true;
    }

    // Direct jumps/calls/rets/int3 at entry are often thunks or tiny wrappers.
    switch (p[0]) {
    case 0xE9: // jmp rel32
    case 0xEB: // jmp rel8
    case 0xE8: // call rel32
    case 0xC2: // ret imm16
    case 0xC3: // ret
    case 0xCC: // int3
        return true;
    default:
        break;
    }

    // FF /2,/3,/4,/5 forms (indirect call/jmp) at entry are typically import thunks.
    if (p[0] == 0xFF) {
        const std::uint8_t reg = static_cast<std::uint8_t>((p[1] >> 3) & 0x07);
        if (reg >= 2 && reg <= 5) {
            return true;
        }
    }

    // push imm; ret thunk patterns.
    if (p[0] == 0x68 && p[5] == 0xC3) {
        return true;
    }
    if (p[0] == 0x6A && p[2] == 0xC3) {
        return true;
    }

    return false;
}

bool IsCrtRiskyRange(const std::uint32_t addr) {
    // Known-crashy CRT lane observed in runtime experiments.
    return addr >= 0x00A84000u && addr < 0x00A85200u;
}

bool ParseProgressEdgeLine(
    std::string_view line,
    std::uint32_t& out_caller_ret,
    std::string& out_callee_token,
    std::uint32_t& out_count)
{
    const std::string s(line);
    const std::string key_a = "\"caller_ret\":\"0x";
    const std::string key_b = "\"callee\":\"";
    const std::string key_c = "\"count\":";

    const auto pa = s.find(key_a);
    if (pa == std::string::npos) {
        return false;
    }
    const auto pa_start = pa + key_a.size();
    const auto pa_end = s.find('"', pa_start);
    if (pa_end == std::string::npos) {
        return false;
    }
    const auto caller = ParseUint32Hex(std::string_view(s).substr(pa_start, pa_end - pa_start));
    if (!caller.has_value()) {
        return false;
    }

    const auto pb = s.find(key_b);
    if (pb == std::string::npos) {
        return false;
    }
    const auto pb_start = pb + key_b.size();
    const auto pb_end = s.find('"', pb_start);
    if (pb_end == std::string::npos) {
        return false;
    }
    const auto callee = NormalizeToken(std::string_view(s).substr(pb_start, pb_end - pb_start));
    if (callee.empty()) {
        return false;
    }

    const auto pc = s.find(key_c);
    if (pc == std::string::npos) {
        return false;
    }
    const auto pc_start = pc + key_c.size();
    auto pc_end = pc_start;
    while (pc_end < s.size() && s[pc_end] >= '0' && s[pc_end] <= '9') {
        ++pc_end;
    }
    if (pc_end == pc_start) {
        return false;
    }

    const auto count_sv = std::string_view(s).substr(pc_start, pc_end - pc_start);
    char* end_ptr = nullptr;
    const unsigned long count = strtoul(std::string(count_sv).c_str(), &end_ptr, 10);
    if (end_ptr == nullptr || *end_ptr != '\0') {
        return false;
    }

    out_caller_ret = *caller;
    out_callee_token = callee;
    out_count = static_cast<std::uint32_t>(count);
    return true;
}

std::optional<std::uint32_t> ParseJsonUint32Field(std::string_view line, std::string_view field_name) {
    const std::string key = std::format("\"{}\"", field_name);
    const std::string s(line);
    const auto pos = s.find(key);
    if (pos == std::string::npos) {
        return std::nullopt;
    }
    const auto colon = s.find(':', pos + key.size());
    if (colon == std::string::npos) {
        return std::nullopt;
    }

    std::size_t start = colon + 1;
    while (start < s.size() && (s[start] == ' ' || s[start] == '\t')) {
        ++start;
    }
    std::size_t end = start;
    while (end < s.size() && s[end] >= '0' && s[end] <= '9') {
        ++end;
    }
    if (end == start) {
        return std::nullopt;
    }

    char* ptr = nullptr;
    const unsigned long value = strtoul(s.substr(start, end - start).c_str(), &ptr, 10);
    if (ptr == nullptr || *ptr != '\0') {
        return std::nullopt;
    }
    return static_cast<std::uint32_t>(value);
}

std::optional<DWORD> FindMainThreadId(const DWORD pid, const DWORD exclude_tid) {
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snapshot == INVALID_HANDLE_VALUE) {
        return std::nullopt;
    }

    THREADENTRY32 te{};
    te.dwSize = sizeof(te);

    DWORD best_tid = 0;
    FILETIME best_creation{};
    bool have_creation = false;

    if (Thread32First(snapshot, &te)) {
        do {
            if (te.th32OwnerProcessID != pid || te.th32ThreadID == exclude_tid) {
                continue;
            }

            if (best_tid == 0) {
                best_tid = te.th32ThreadID;
            }

            HANDLE thread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
            if (!thread) {
                continue;
            }

            FILETIME create_time{};
            FILETIME exit_time{};
            FILETIME kernel_time{};
            FILETIME user_time{};
            if (GetThreadTimes(thread, &create_time, &exit_time, &kernel_time, &user_time)) {
                if (!have_creation || CompareFileTime(&create_time, &best_creation) < 0) {
                    best_creation = create_time;
                    best_tid = te.th32ThreadID;
                    have_creation = true;
                }
            }

            CloseHandle(thread);
        } while (Thread32Next(snapshot, &te));
    }

    CloseHandle(snapshot);
    if (best_tid == 0) {
        return std::nullopt;
    }
    return best_tid;
}

bool CanReadAddress(const void* p) {
    MEMORY_BASIC_INFORMATION mbi{};
    if (VirtualQuery(p, &mbi, sizeof(mbi)) != sizeof(mbi)) {
        return false;
    }
    if ((mbi.State & MEM_COMMIT) == 0) {
        return false;
    }
    const DWORD protect = mbi.Protect & 0xFF;
    if (protect == PAGE_NOACCESS || protect == PAGE_EXECUTE) {
        return false;
    }
    return true;
}

std::string TokenFromHookContextAddress(const std::uint32_t ctx_addr) {
    if (ctx_addr == 0) {
        return {};
    }
    const auto* ctx = reinterpret_cast<const HookContext*>(static_cast<std::uintptr_t>(ctx_addr));
    if (!CanReadAddress(ctx)) {
        return {};
    }
    const auto* end_ptr = reinterpret_cast<const std::uint8_t*>(ctx) + sizeof(HookContext) - 1;
    if (!CanReadAddress(end_ptr)) {
        return {};
    }

    std::size_t n = 0;
    while (n < kTokenMaxLen && ctx->token[n] != '\0') {
        ++n;
    }
    return std::string(ctx->token, n);
}

std::string HexBytes(const std::uint8_t* p, std::size_t n) {
    if (p == nullptr || !CanReadAddress(p)) {
        return "<unreadable>";
    }
    std::ostringstream oss;
    oss << std::hex << std::uppercase;
    for (std::size_t i = 0; i < n; ++i) {
        if (!CanReadAddress(p + i)) {
            oss << " ??";
            continue;
        }
        const auto b = static_cast<unsigned>(p[i]);
        oss << std::format(" {:02X}", b);
    }
    return oss.str();
}

struct ScopedThreadSuspend {
    HANDLE handle = nullptr;
    DWORD tid = 0;
    bool suspended = false;

    ~ScopedThreadSuspend() {
        ResumeAndClose();
    }

    void ResumeAndClose() {
        if (suspended && handle != nullptr) {
            ResumeThread(handle);
            suspended = false;
        }
        if (handle != nullptr) {
            CloseHandle(handle);
            handle = nullptr;
        }
        tid = 0;
    }
};

struct ScopedOtherThreadsSuspend {
    std::vector<HANDLE> handles;

    ~ScopedOtherThreadsSuspend() {
        ResumeAndCloseAll();
    }

    bool SuspendAll(const DWORD pid, const DWORD current_tid) {
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (snapshot == INVALID_HANDLE_VALUE) {
            return false;
        }

        THREADENTRY32 te{};
        te.dwSize = sizeof(te);
        if (Thread32First(snapshot, &te)) {
            do {
                if (te.th32OwnerProcessID != pid || te.th32ThreadID == current_tid) {
                    continue;
                }

                HANDLE thread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                if (thread == nullptr) {
                    continue;
                }

                const DWORD prev = SuspendThread(thread);
                if (prev == static_cast<DWORD>(-1)) {
                    CloseHandle(thread);
                    continue;
                }
                handles.push_back(thread);
            } while (Thread32Next(snapshot, &te));
        }

        CloseHandle(snapshot);
        return true;
    }

    std::size_t Count() const {
        return handles.size();
    }

    const std::vector<HANDLE>& Handles() const {
        return handles;
    }

    void ResumeAndCloseAll() {
        for (auto it = handles.rbegin(); it != handles.rend(); ++it) {
            if (*it != nullptr) {
                ResumeThread(*it);
                CloseHandle(*it);
            }
        }
        handles.clear();
    }
};

class DiscoveryTracer {
public:
    bool Start(HMODULE module_handle) {
#if !defined(_M_IX86)
        (void)module_handle;
        DebugPrintf("[discover] runtime tracer is only enabled for x86 builds.\n");
        return false;
#else
        try {
            std::scoped_lock lock(mu_);
            if (started_.load(std::memory_order_acquire)) {
                return true;
            }

            const auto module_path = GetModulePath(module_handle);
            const auto module_dir = module_path.has_parent_path() ? module_path.parent_path() : std::filesystem::current_path();
            const auto repo_root = FindRepoRootNear(module_dir);
            self_module_handle_ = module_handle;

            namespace_key_ = "fa_full_2026_03_26";
            if (const std::wstring ns_env = GetEnvW(L"INSPECT_DISCOVERY_NAMESPACE"); !ns_env.empty()) {
                namespace_key_ = NarrowAscii(ns_env);
            }

            watchlist_path_ = repo_root / "decomp" / "recovery" / "disasm" / namespace_key_ / "_no_caller_evidence_priority.txt";
            if (const std::wstring watch_env = GetEnvW(L"INSPECT_DISCOVERY_WATCHLIST"); !watch_env.empty()) {
                watchlist_path_ = std::filesystem::path(watch_env);
            }

            const std::filesystem::path default_out_dir = repo_root / "tmp";

            progress_path_ = default_out_dir / "_runtime_discovery_progress.json";
            if (const std::wstring prog_env = GetEnvW(L"INSPECT_DISCOVERY_PROGRESS_JSON"); !prog_env.empty()) {
                progress_path_ = std::filesystem::path(prog_env);
            }

            event_log_path_ = default_out_dir / "_runtime_discovery_events.ndjson";
            if (const std::wstring log_env = GetEnvW(L"INSPECT_DISCOVERY_EVENT_LOG"); !log_env.empty()) {
                event_log_path_ = std::filesystem::path(log_env);
            }

            // Safe default for normal game runs without custom env setup.
            max_hooks_ = ParseUint32OrDefault(GetEnvW(L"INSPECT_DISCOVERY_MAX_HOOKS"), kDefaultMaxHooks);
            if (max_hooks_ == 0) {
                max_hooks_ = kDefaultMaxHooks;
            }
            const std::wstring edge_env = GetEnvW(L"INSPECT_DISCOVERY_RECORD_EDGES_AFTER_DISCOVERED");
            // Default to enabled so call/callee schemes are built without requiring extra setup.
            // Set INSPECT_DISCOVERY_RECORD_EDGES_AFTER_DISCOVERED=0 to only record first-discovery edges.
            record_edges_after_discovered_ = edge_env.empty() ? true : IsTruthy(edge_env);
            const std::wstring one_shot_env = GetEnvW(L"INSPECT_DISCOVERY_ONE_SHOT_HOOKS");
            // One-shot hooks are safer for broad binary coverage because they avoid trampoline execution
            // on first call by restoring original entry and tail-jumping to it.
            one_shot_hooks_ = one_shot_env.empty() ? true : IsTruthy(one_shot_env);
            const std::wstring rotate_env = GetEnvW(L"INSPECT_DISCOVERY_ROTATE_ONESHOT");
            // Keep active slots filled by installing another hook after one-shot hits.
            rotate_one_shot_hooks_ = rotate_env.empty() ? false : IsTruthy(rotate_env);
            rotate_refill_scan_budget_ = ParseUint32OrDefault(
                GetEnvW(L"INSPECT_DISCOVERY_ROTATE_REFILL_SCAN_BUDGET"),
                kDefaultRotateRefillScanBudget);
            if (rotate_refill_scan_budget_ == 0) {
                rotate_refill_scan_budget_ = kDefaultRotateRefillScanBudget;
            }
            const std::wstring spread_env = GetEnvW(L"INSPECT_DISCOVERY_SPREAD_HOOKS");
            // Spread picks a shuffled install order so we do not stay trapped in one
            // contiguous watchlist prefix.
            spread_hooks_ = spread_env.empty() ? true : IsTruthy(spread_env);
            const std::wstring skip_crt_env = GetEnvW(L"INSPECT_DISCOVERY_SKIP_CRT_RANGE");
            // Default-on safety rail: skip a known crash-prone CRT lane.
            skip_crt_risky_range_ = skip_crt_env.empty() ? true : IsTruthy(skip_crt_env);
            const std::wstring strict_entry_env = GetEnvW(L"INSPECT_DISCOVERY_STRICT_ENTRY_FILTER");
            // Default-on: avoid hooking obvious thunk/trampoline-like entries.
            strict_entry_filter_ = strict_entry_env.empty() ? true : IsTruthy(strict_entry_env);
            const std::wstring pause_main_env = GetEnvW(L"INSPECT_DISCOVERY_PAUSE_MAIN_THREAD");
            // Default-on: avoid concurrent execution while we patch entry points.
            pause_main_thread_during_install_ = pause_main_env.empty() ? true : IsTruthy(pause_main_env);
            const std::wstring pause_all_install_env = GetEnvW(L"INSPECT_DISCOVERY_PAUSE_ALL_THREADS_DURING_INSTALL");
            // Default-on: large bulk installs should suspend other threads once,
            // instead of per-hook suspend/resume cycles.
            pause_all_threads_during_install_ = pause_all_install_env.empty() ? true : IsTruthy(pause_all_install_env);
            const std::wstring suspend_disable_env = GetEnvW(L"INSPECT_DISCOVERY_SUSPEND_THREADS_ON_DISABLE");
            // Default-on: one-shot unhook restore must be thread-safe, otherwise
            // another thread can execute partially-restored bytes and crash.
            suspend_threads_on_disable_ = suspend_disable_env.empty() ? true : IsTruthy(suspend_disable_env);
            const std::wstring suspend_enable_env = GetEnvW(L"INSPECT_DISCOVERY_SUSPEND_THREADS_ON_ENABLE");
            // Default-on: entry patching during initial install must be thread-safe
            // for the same reason as one-shot restore.
            suspend_threads_on_enable_ = suspend_enable_env.empty() ? true : IsTruthy(suspend_enable_env);

            if (!LoadWatchlist()) {
                DebugPrintf("[discover] watchlist load failed: {}\n", watchlist_path_.string());
                return false;
            }

            LoadProgressJson();
            FilterDiscoveredToWatchlist();

            if (!OpenEventLog()) {
                DebugPrintf("[discover] event log open failed: {}\n", event_log_path_.string());
                return false;
            }
            crash_log_path_ = event_log_path_.parent_path() / "_runtime_discovery_crashes.log";

            if (veh_handle_ == nullptr) {
                veh_handle_ = AddVectoredExceptionHandler(1, &VectoredExceptionHandler);
                if (veh_handle_ == nullptr) {
                    DebugPrintf("[discover] failed to register vectored exception handler (err={})\n", GetLastError());
                }
            }

            // Persist an initial snapshot immediately so a restart-safe progress file appears
            // even if hook installation is long-running.
            WriteProgressJson(MakeSnapshotLocked());
            AppendEventUnlocked(std::format(
                "{{\"ts_utc\":\"{}\",\"event\":\"session_start\",\"watchlist\":\"{}\",\"watchlist_total\":{},\"restored\":{}}}",
                UtcNowIso8601(),
                JsonEscape(watchlist_path_.string()),
                watchlist_total_,
                discovered_tokens_.size()));

            ScopedThreadSuspend paused_main_thread{};
            ScopedOtherThreadsSuspend paused_other_threads{};
            if (pause_main_thread_during_install_) {
                const DWORD pid = GetCurrentProcessId();
                const DWORD current_tid = GetCurrentThreadId();
                const auto main_tid = FindMainThreadId(pid, current_tid);
                if (main_tid.has_value()) {
                    HANDLE th = OpenThread(THREAD_SUSPEND_RESUME | THREAD_QUERY_INFORMATION, FALSE, *main_tid);
                    if (th != nullptr) {
                        const DWORD prev = SuspendThread(th);
                        if (prev != static_cast<DWORD>(-1)) {
                            paused_main_thread.handle = th;
                            paused_main_thread.tid = *main_tid;
                            paused_main_thread.suspended = true;
                            DebugPrintf("[discover] paused main thread tid={} for hook install\n", *main_tid);
                        } else {
                            CloseHandle(th);
                            DebugPrintf("[discover] failed to suspend main thread tid={} (err={})\n", *main_tid, GetLastError());
                        }
                    } else {
                        DebugPrintf("[discover] failed to open main thread tid={} (err={})\n", *main_tid, GetLastError());
                    }
                } else {
                    DebugPrintf("[discover] main thread not found; hook install continues without pause\n");
                }
            }

            if (pause_all_threads_during_install_) {
                paused_other_threads.SuspendAll(GetCurrentProcessId(), GetCurrentThreadId());
                bulk_install_thread_pause_active_ = true;
                DebugPrintf("[discover] paused {} other threads for hook install\n", paused_other_threads.Count());
            }

            CaptureSuspendedThreadIpsNoLock(
                paused_main_thread.handle,
                paused_main_thread.suspended,
                paused_other_threads.Handles());
            if (!suspended_thread_ips_.empty()) {
                DebugPrintf("[discover] captured {} suspended thread IP(s) for install safety\n", suspended_thread_ips_.size());
            }

            InstallHooks();
            if (bulk_install_thread_pause_active_) {
                bulk_install_thread_pause_active_ = false;
                paused_other_threads.ResumeAndCloseAll();
                DebugPrintf("[discover] resumed paused threads after hook install\n");
            }
            if (paused_main_thread.suspended) {
                paused_main_thread.ResumeAndClose();
                DebugPrintf("[discover] resumed main thread after hook install\n");
            }
            suspended_thread_ips_.clear();
            started_.store(true, std::memory_order_release);

            const double pct = watchlist_total_ == 0
                ? 100.0
                : static_cast<double>(discovered_tokens_.size()) * 100.0 / static_cast<double>(watchlist_total_);
            const std::size_t pending = install_cursor_ < install_order_.size()
                ? (install_order_.size() - install_cursor_)
                : 0;
            DebugPrintf(
                "[discover] watchlist={} total={} restored={} ({:.2f}%) max_hooks={} one_shot={} rotate={} refill_budget={} spread={} skip_crt={} strict_entry={} pause_main={} pause_all_install={} suspend_enable={} suspend_disable={} installed={} failed={} blocked={} blocked_live_ip={} active={} pending={} epoch={} edges={} log={}\n",
                watchlist_path_.string(),
                watchlist_total_,
                discovered_tokens_.size(),
                pct,
                max_hooks_,
                one_shot_hooks_ ? "true" : "false",
                rotate_one_shot_hooks_ ? "true" : "false",
                rotate_refill_scan_budget_,
                spread_hooks_ ? "true" : "false",
                skip_crt_risky_range_ ? "true" : "false",
                strict_entry_filter_ ? "true" : "false",
                pause_main_thread_during_install_ ? "true" : "false",
                pause_all_threads_during_install_ ? "true" : "false",
                suspend_threads_on_enable_ ? "true" : "false",
                suspend_threads_on_disable_ ? "true" : "false",
                installed_hooks_,
                failed_hooks_,
                blocked_hooks_,
                blocked_live_ip_hooks_,
                active_hooks_,
                pending,
                install_epoch_,
                edge_counts_.size(),
                event_log_path_.string());

            WriteProgressJson(MakeSnapshotLocked());
            return true;
        } catch (const std::exception& ex) {
            DebugPrintf("[discover] Start exception: {}\n", ex.what());
            started_.store(false, std::memory_order_release);
            return false;
        } catch (...) {
            DebugPrintf("[discover] Start exception: <unknown>\n");
            started_.store(false, std::memory_order_release);
            return false;
        }
#endif
    }

    void Stop() {
#if defined(_M_IX86)
        Snapshot snapshot;
        {
            std::scoped_lock lock(mu_);
            if (!started_.load(std::memory_order_acquire)) {
                return;
            }
            snapshot = MakeSnapshotLocked();
            started_.store(false, std::memory_order_release);
            hooks_.clear();
            install_order_.clear();
            install_cursor_ = 0;
            active_hooks_ = 0;
            if (veh_handle_ != nullptr) {
                RemoveVectoredExceptionHandler(veh_handle_);
                veh_handle_ = nullptr;
            }
            if (event_log_stream_.is_open()) {
                event_log_stream_.flush();
                event_log_stream_.close();
            }
        }
        WriteProgressJson(snapshot);
#endif
    }

    void OnFunctionEnter(HookContext* ctx, std::uint32_t caller_ret) {
#if defined(_M_IX86)
        if (!ctx) {
            return;
        }
        if (!started_.load(std::memory_order_acquire)) {
            // During hook-install phase we bypass trampoline execution to avoid
            // running relocation-sensitive copied prologues while the process is hot.
            if (ctx->target_entry != nullptr) {
                ctx->trampoline = ctx->target_entry;
            }
            return;
        }

        thread_local bool reentrant = false;
        if (reentrant) {
            // Reentrant calls happen while callback internals execute code that can
            // itself be hooked. Do not mutate hook patch state from this fast path:
            // concurrent live patching here can corrupt instruction streams.
            return;
        }
        reentrant = true;
        g_tls_current_hook_ctx = ctx;
        g_tls_current_caller_ret = caller_ret;

        bool should_log = false;
        bool should_print = false;
        bool should_flush = false;
        std::string event_type;
        std::string token;
        std::string event_json;
        std::size_t discovered_count = 0;
        std::size_t total = 0;
        double pct = 0.0;
        std::uint64_t events_seen = 0;
        Snapshot snapshot;

        {
            std::scoped_lock lock(mu_);
            if (!started_.load(std::memory_order_acquire)) {
                reentrant = false;
                g_tls_current_hook_ctx = nullptr;
                g_tls_current_caller_ret = 0;
                return;
            }

            ++events_seen_;
            events_seen = events_seen_;

            token = std::string(ctx->token);
            const bool new_function = discovered_tokens_.insert(token).second;
            bool new_edge = false;

            if (one_shot_hooks_) {
                const bool disabled = DisableRuntimeHookNoLock(static_cast<HookRuntime*>(ctx->owner_runtime), ctx);
                if (disabled && rotate_one_shot_hooks_) {
                    InstallMoreHooksNoLock(
                        static_cast<std::size_t>(max_hooks_),
                        false,
                        static_cast<std::size_t>(rotate_refill_scan_budget_));
                }
            }

            // Last-line guard: if trampoline target becomes invalid or points
            // back into inspect.dll image space, force a safe jump to original entry.
            if (ctx->target_entry != nullptr) {
                bool bad_jump_target = false;
                void* jump_target = ctx->trampoline;
                if (jump_target == nullptr || !IsExecutableAddress(jump_target)) {
                    bad_jump_target = true;
                } else if (self_module_handle_ != nullptr) {
                    MEMORY_BASIC_INFORMATION mbi{};
                    if (VirtualQuery(jump_target, &mbi, sizeof(mbi)) != sizeof(mbi)) {
                        bad_jump_target = true;
                    } else if (mbi.AllocationBase == self_module_handle_) {
                        bad_jump_target = true;
                    }
                }

                if (bad_jump_target) {
                    ctx->trampoline = ctx->target_entry;
                    ++sanitized_jump_target_count_;
                    if ((sanitized_jump_target_count_ % 128u) == 1u) {
                        DebugPrintf(
                            "[discover] sanitized jump target token={} new_target=0x{:08X} count={}\n",
                            ctx->token,
                            static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(ctx->target_entry)),
                            sanitized_jump_target_count_);
                    }
                }
            }

            if (new_function || record_edges_after_discovered_) {
                const std::uint64_t edge_key = MakeEdgeKey(caller_ret, ctx->callee_ea);
                auto [it, inserted] = edge_counts_.try_emplace(edge_key, 0u);
                ++it->second;
                new_edge = inserted;
                if (new_edge) {
                    ++new_edges_since_flush_;
                }
            }

            if (new_function) {
                should_print = true;
                should_log = true;
                event_type = "discover";
                ++new_discoveries_since_flush_;
            } else if (record_edges_after_discovered_ && new_edge) {
                should_log = true;
                event_type = "new_edge";
            }

            if (!should_log) {
                reentrant = false;
                g_tls_current_hook_ctx = nullptr;
                g_tls_current_caller_ret = 0;
                return;
            }

            discovered_count = discovered_tokens_.size();
            total = watchlist_total_;
            pct = total == 0 ? 100.0 : static_cast<double>(discovered_count) * 100.0 / static_cast<double>(total);

            event_json = std::format(
                "{{\"ts_utc\":\"{}\",\"event\":\"{}\",\"callee\":\"{}\",\"callee_ea\":\"0x{:08X}\",\"caller_ret\":\"0x{:08X}\",\"discovered\":{},\"total\":{},\"pct\":{:.4f},\"events_seen\":{}}}",
                UtcNowIso8601(),
                event_type,
                token,
                ctx->callee_ea,
                caller_ret,
                discovered_count,
                total,
                pct,
                events_seen);

            const auto now = Clock::now();
            const bool flush_by_count =
                new_discoveries_since_flush_ >= kDefaultFlushDiscoveryThreshold ||
                new_edges_since_flush_ >= kDefaultFlushEdgeThreshold;
            const bool flush_by_time = (now - last_flush_) >= kDefaultFlushInterval;
            if (flush_by_count || flush_by_time) {
                should_flush = true;
                snapshot = MakeSnapshotLocked();
                last_flush_ = now;
                new_discoveries_since_flush_ = 0;
                new_edges_since_flush_ = 0;
            }
        }

        if (should_log) {
            AppendEvent(event_json);
        }
        if (should_print) {
            DebugPrintf(
                "[discover] {} caller_ret=0x{:08X} discovered={}/{} ({:.2f}%) events={}\n",
                token,
                caller_ret,
                discovered_count,
                total,
                pct,
                events_seen);
        }
        if (should_flush) {
            WriteProgressJson(snapshot);
        }

        reentrant = false;
        g_tls_current_hook_ctx = nullptr;
        g_tls_current_caller_ret = 0;
#else
        (void)ctx;
        (void)caller_ret;
#endif
    }

private:
#if defined(_M_IX86)
    bool LoadWatchlist() {
        watchlist_tokens_.clear();
        watchlist_addrs_.clear();

        std::ifstream in(watchlist_path_, std::ios::binary);
        if (!in.is_open()) {
            return false;
        }

        std::unordered_set<std::string> seen;
        std::string line;
        while (std::getline(in, line)) {
            const auto trimmed = TrimCopy(line);
            if (trimmed.empty() || trimmed[0] == '#' || trimmed[0] == ';') {
                continue;
            }
            const auto token = NormalizeToken(trimmed);
            if (token.empty()) {
                continue;
            }
            if (!seen.insert(token).second) {
                continue;
            }
            const auto addr = ParseTokenAddress(token);
            if (!addr.has_value()) {
                continue;
            }
            watchlist_tokens_.push_back(token);
            watchlist_addrs_[token] = *addr;
        }

        watchlist_total_ = static_cast<std::uint32_t>(watchlist_tokens_.size());
        return watchlist_total_ > 0;
    }

    void LoadProgressJson() {
        discovered_tokens_.clear();
        edge_counts_.clear();

        std::ifstream in(progress_path_, std::ios::binary);
        if (!in.is_open()) {
            return;
        }

        std::string line;
        while (std::getline(in, line)) {
            const auto s = TrimCopy(line);
            if (s.empty()) {
                continue;
            }

            std::uint32_t caller = 0;
            std::uint32_t count = 0;
            std::string callee;
            if (ParseProgressEdgeLine(s, caller, callee, count)) {
                const auto callee_addr = ParseTokenAddress(callee);
                if (callee_addr.has_value()) {
                    edge_counts_[MakeEdgeKey(caller, *callee_addr)] += count;
                }
                continue;
            }

            if (s.find("\"callee\"") == std::string::npos) {
                const auto pos = s.find("\"FUN_");
                if (pos != std::string::npos) {
                    const auto end = s.find('"', pos + 1);
                    if (end != std::string::npos) {
                        const auto token = NormalizeToken(std::string_view(s).substr(pos + 1, end - pos - 1));
                        if (!token.empty()) {
                            discovered_tokens_.insert(token);
                        }
                    }
                }
            }

            if (const auto p = s.find("\"events_seen\":"); p != std::string::npos) {
                const auto start = p + std::string_view("\"events_seen\":").size();
                auto end = start;
                while (end < s.size() && s[end] >= '0' && s[end] <= '9') {
                    ++end;
                }
                if (end > start) {
                    const auto value = std::string_view(s).substr(start, end - start);
                    char* ptr = nullptr;
                    events_seen_ = strtoull(std::string(value).c_str(), &ptr, 10);
                }
            }

            if (const auto blocked = ParseJsonUint32Field(s, "blocked_hooks"); blocked.has_value()) {
                blocked_hooks_ = *blocked;
            }
            if (const auto epoch = ParseJsonUint32Field(s, "install_epoch"); epoch.has_value()) {
                install_epoch_ = *epoch;
            }
        }
    }

    void FilterDiscoveredToWatchlist() {
        std::unordered_set<std::string> allowed(watchlist_tokens_.begin(), watchlist_tokens_.end());
        for (auto it = discovered_tokens_.begin(); it != discovered_tokens_.end();) {
            if (!allowed.contains(*it)) {
                it = discovered_tokens_.erase(it);
            } else {
                ++it;
            }
        }
    }

    bool OpenEventLog() {
        std::error_code ec;
        std::filesystem::create_directories(event_log_path_.parent_path(), ec);
        event_log_stream_.open(event_log_path_, std::ios::app | std::ios::binary);
        return event_log_stream_.is_open();
    }

    static void __stdcall HookCallback(HookContext* ctx, std::uint32_t caller_ret) {
        if (g_instance != nullptr) {
            g_instance->OnFunctionEnter(ctx, caller_ret);
        }
    }

    static LONG CALLBACK VectoredExceptionHandler(EXCEPTION_POINTERS* ep) {
        if (g_instance != nullptr) {
            g_instance->OnException(ep);
        }
        return EXCEPTION_CONTINUE_SEARCH;
    }

    void OnException(EXCEPTION_POINTERS* ep) {
        if (ep == nullptr || ep->ExceptionRecord == nullptr) {
            return;
        }

        const DWORD code = ep->ExceptionRecord->ExceptionCode;
        if (code != EXCEPTION_ACCESS_VIOLATION &&
            code != EXCEPTION_ILLEGAL_INSTRUCTION &&
            code != EXCEPTION_STACK_OVERFLOW)
        {
            return;
        }

        const auto ip = reinterpret_cast<std::uintptr_t>(ep->ExceptionRecord->ExceptionAddress);
        const auto av_addr = (code == EXCEPTION_ACCESS_VIOLATION && ep->ExceptionRecord->NumberParameters >= 2)
            ? static_cast<std::uintptr_t>(ep->ExceptionRecord->ExceptionInformation[1])
            : 0u;
        const auto av_type = (code == EXCEPTION_ACCESS_VIOLATION && ep->ExceptionRecord->NumberParameters >= 1)
            ? static_cast<unsigned>(ep->ExceptionRecord->ExceptionInformation[0])
            : 0u;

        std::string matched_token;
        std::string matched_where;

        for (const auto& runtime : hooks_) {
            if (!runtime) {
                continue;
            }

            const auto target = reinterpret_cast<std::uintptr_t>(runtime->context.target_entry);
            const auto stub = reinterpret_cast<std::uintptr_t>(runtime->stub);
            const auto tramp = reinterpret_cast<std::uintptr_t>(runtime->context.trampoline);

            if (stub != 0 && ip >= stub && ip < (stub + 32)) {
                matched_token = runtime->token;
                matched_where = "stub";
                break;
            }
            if (target != 0 && ip >= target && ip < (target + 16)) {
                matched_token = runtime->token;
                matched_where = "target";
                break;
            }
            if (tramp != 0 && ip >= tramp && ip < (tramp + 64)) {
                matched_token = runtime->token;
                matched_where = "trampoline";
                break;
            }
        }

        const std::string tls_token = g_tls_current_hook_ctx != nullptr
            ? std::string(g_tls_current_hook_ctx->token)
            : std::string{};
        const std::uint32_t last_stub_target = g_last_stub_jump_target;
        const std::uint32_t last_stub_ctx = g_last_stub_ctx;
        const std::string last_stub_token = TokenFromHookContextAddress(last_stub_ctx);

        const auto ip_bytes = HexBytes(reinterpret_cast<const std::uint8_t*>(ip), 24);
        const auto now = UtcNowIso8601();
        const std::string line = std::format(
            "[discover][crash] ts={} code=0x{:08X} ip=0x{:08X} av_type={} av_addr=0x{:08X} tls_token={} tls_caller_ret=0x{:08X} matched_token={} matched_where={} last_stub_target=0x{:08X} last_stub_ctx=0x{:08X} last_stub_token={} ip_bytes={}\n",
            now,
            code,
            static_cast<std::uint32_t>(ip),
            av_type,
            static_cast<std::uint32_t>(av_addr),
            tls_token.empty() ? "<none>" : tls_token,
            g_tls_current_caller_ret,
            matched_token.empty() ? "<none>" : matched_token,
            matched_where.empty() ? "<none>" : matched_where,
            last_stub_target,
            last_stub_ctx,
            last_stub_token.empty() ? "<none>" : last_stub_token,
            ip_bytes);

        DebugPrintf("{}", line);

        std::ofstream crash_out(crash_log_path_, std::ios::app | std::ios::binary);
        if (crash_out.is_open()) {
            crash_out << line;
        }
    }

    static void* BuildEntryStub(HookContext* ctx) {
        if (ctx == nullptr) {
            return nullptr;
        }
        static_assert(sizeof(void*) == 4, "Entry stub is x86-only.");

        // Keep comfortable headroom for instrumentation fields.
        constexpr std::size_t kStubSize = 64;
        auto* stub = static_cast<std::uint8_t*>(VirtualAlloc(
            nullptr, kStubSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        if (!stub) {
            return nullptr;
        }

        std::memset(stub, 0x90, kStubSize);

        std::size_t i = 0;
        stub[i++] = 0x9C; // pushfd
        stub[i++] = 0x60; // pushad
        stub[i++] = 0x8B; // mov eax, [esp+24h]
        stub[i++] = 0x44;
        stub[i++] = 0x24;
        stub[i++] = 0x24;
        stub[i++] = 0x50; // push eax (caller_ret)
        stub[i++] = 0x68; // push imm32 (HookContext*)
        *reinterpret_cast<std::uint32_t*>(stub + i) = reinterpret_cast<std::uint32_t>(ctx);
        i += 4;
        stub[i++] = 0xE8; // call rel32 HookCallback
        const auto callback = reinterpret_cast<std::uintptr_t>(&HookCallback);
        const auto call_next = reinterpret_cast<std::uintptr_t>(stub + i + 4);
        const auto rel_call = static_cast<std::int32_t>(callback - call_next);
        *reinterpret_cast<std::int32_t*>(stub + i) = rel_call;
        i += 4;
        stub[i++] = 0x61; // popad
        stub[i++] = 0x9D; // popfd
        stub[i++] = 0xA1; // mov eax, moffs32 (ctx->trampoline)
        *reinterpret_cast<std::uint32_t*>(stub + i) = reinterpret_cast<std::uint32_t>(&ctx->trampoline);
        i += 4;
        stub[i++] = 0xA3; // mov moffs32, eax
        *reinterpret_cast<std::uint32_t*>(stub + i) = reinterpret_cast<std::uint32_t>(&g_last_stub_jump_target);
        i += 4;
        stub[i++] = 0xC7; // mov dword ptr [moffs32], imm32
        stub[i++] = 0x05;
        *reinterpret_cast<std::uint32_t*>(stub + i) = reinterpret_cast<std::uint32_t>(&g_last_stub_ctx);
        i += 4;
        *reinterpret_cast<std::uint32_t*>(stub + i) = reinterpret_cast<std::uint32_t>(ctx);
        i += 4;
        stub[i++] = 0xFF; // jmp eax
        stub[i++] = 0xE0;

        if (i > kStubSize) {
            VirtualFree(stub, 0, MEM_RELEASE);
            return nullptr;
        }

        FlushInstructionCache(GetCurrentProcess(), stub, kStubSize);
        return stub;
    }

    void BuildInstallOrderNoLock() {
        install_order_.clear();
        install_cursor_ = 0;

        install_order_.reserve(watchlist_tokens_.size());
        for (const auto& token : watchlist_tokens_) {
            if (!discovered_tokens_.contains(token)) {
                install_order_.push_back(token);
            }
        }

        ++install_epoch_;
        if (spread_hooks_ && install_order_.size() > 1) {
            const std::uint32_t seed =
                (0xC0DEF00Du ^ install_epoch_ ^ static_cast<std::uint32_t>(watchlist_tokens_.size()));
            std::mt19937 rng(seed);
            std::shuffle(install_order_.begin(), install_order_.end(), rng);
        }
    }

    bool TryInstallHookNoLock(const std::string& token) {
        const auto it_addr = watchlist_addrs_.find(token);
        if (it_addr == watchlist_addrs_.end()) {
            ++failed_hooks_;
            return false;
        }

        const std::uint32_t addr = it_addr->second;
        if (skip_crt_risky_range_ && IsCrtRiskyRange(addr)) {
            ++blocked_hooks_;
            return false;
        }

        auto* const target = reinterpret_cast<void*>(static_cast<std::uintptr_t>(addr));
        if (!IsExecutableAddress(target)) {
            ++failed_hooks_;
            return false;
        }
        if (strict_entry_filter_ && IsLikelyUnsafeHookEntry(static_cast<const std::uint8_t*>(target))) {
            ++blocked_hooks_;
            return false;
        }

        // If a suspended thread currently points inside the soon-to-be patched
        // prologue bytes, skip this hook to avoid resuming into mutated bytes.
        std::uint32_t patch_window = asm_utils::compute_stolen_len_covering_seh(
            static_cast<std::uint8_t*>(target));
        if (patch_window < asm_utils::kOpJmpRel32Size) {
            patch_window = asm_utils::kOpJmpRel32Size;
        }
        for (const std::uint32_t ip : suspended_thread_ips_) {
            if (ip >= addr && ip < (addr + patch_window)) {
                ++blocked_hooks_;
                ++blocked_live_ip_hooks_;
                return false;
            }
        }

        auto runtime = std::make_unique<HookRuntime>();
        runtime->token = token;
        runtime->address = addr;
        runtime->context.callee_ea = addr;
        runtime->context.trampoline = nullptr;
        runtime->context.target_entry = target;
        std::snprintf(runtime->context.token, std::size(runtime->context.token), "%s", token.c_str());

        runtime->stub = BuildEntryStub(&runtime->context);
        if (!runtime->stub) {
            ++failed_hooks_;
            return false;
        }

        auto detour = detours::Detour<void(*)()>::create_at_disabled(
            token,
            target,
            reinterpret_cast<void(*)()>(runtime->stub));
        if (!detour) {
            VirtualFree(runtime->stub, 0, MEM_RELEASE);
            runtime->stub = nullptr;
            ++failed_hooks_;
            return false;
        }

        runtime->context.trampoline = reinterpret_cast<void*>(detour->original());
        runtime->context.owner_runtime = runtime.get();

        ScopedOtherThreadsSuspend suspended_others{};
        if (suspend_threads_on_enable_ && !bulk_install_thread_pause_active_) {
            suspended_others.SuspendAll(GetCurrentProcessId(), GetCurrentThreadId());
        }
        detour->enable();
        if (!detour->enabled()) {
            VirtualFree(runtime->stub, 0, MEM_RELEASE);
            runtime->stub = nullptr;
            ++failed_hooks_;
            return false;
        }

        runtime->detour = std::move(detour);
        runtime->armed.store(true, std::memory_order_release);

        hooks_.push_back(std::move(runtime));
        ++installed_hooks_;
        ++active_hooks_;
        return true;
    }

    void InstallMoreHooksNoLock(
        const std::size_t target_active_hooks,
        const bool log_progress,
        const std::size_t max_scan_budget = static_cast<std::size_t>(-1))
    {
        if (target_active_hooks == 0) {
            return;
        }

        std::size_t scanned = 0;
        while (active_hooks_ < target_active_hooks && install_cursor_ < install_order_.size() && scanned < max_scan_budget) {
            const auto& token = install_order_[install_cursor_++];
            ++scanned;
            TryInstallHookNoLock(token);

            if (log_progress && ((install_cursor_ % 5000) == 0)) {
                DebugPrintf("[discover] hook-scan progress: {}/{} installed={} failed={} blocked={} active={}\n",
                    install_cursor_,
                    install_order_.size(),
                    installed_hooks_,
                    failed_hooks_,
                    blocked_hooks_,
                    active_hooks_);
            }
        }

        if (log_progress) {
            DebugPrintf("[discover] hook install done: scanned={} installed={} failed={} blocked={} active={} pending={}\n",
                scanned,
                installed_hooks_,
                failed_hooks_,
                blocked_hooks_,
                active_hooks_,
                install_cursor_ < install_order_.size() ? (install_order_.size() - install_cursor_) : 0);
        } else if (scanned >= max_scan_budget && active_hooks_ < target_active_hooks) {
            // Bounded refill protects game threads from long stalls when remaining
            // watchlist spans are mostly unhookable.
            ++refill_budget_exhausted_count_;
        }
    }

    void InstallHooks() {
        hooks_.clear();
        installed_hooks_ = 0;
        failed_hooks_ = 0;
        blocked_hooks_ = 0;
        blocked_live_ip_hooks_ = 0;
        active_hooks_ = 0;
        refill_budget_exhausted_count_ = 0;
        install_order_.clear();
        install_cursor_ = 0;

        DebugPrintf("[discover] installing hooks: watchlist_total={} already_discovered={}\n",
            watchlist_tokens_.size(),
            discovered_tokens_.size());

        BuildInstallOrderNoLock();
        InstallMoreHooksNoLock(static_cast<std::size_t>(max_hooks_), true);
    }

    void AppendEventUnlocked(const std::string& event_json) {
        if (!event_log_stream_.is_open()) {
            return;
        }
        event_log_stream_ << event_json << "\n";
        event_log_stream_.flush();
    }

    bool DisableRuntimeHookNoLock(HookRuntime* runtime, HookContext* ctx) {
        if (runtime == nullptr || runtime->detour == nullptr) {
            return false;
        }

        bool expected = true;
        if (!runtime->armed.compare_exchange_strong(expected, false, std::memory_order_acq_rel)) {
            return false;
        }

        ScopedOtherThreadsSuspend suspended_others{};
        if (suspend_threads_on_disable_) {
            suspended_others.SuspendAll(GetCurrentProcessId(), GetCurrentThreadId());
        }

        runtime->detour->disable();
        if (!runtime->detour->enabled()) {
            if (ctx != nullptr && ctx->target_entry != nullptr) {
                // We just restored the original bytes, so continue execution at the
                // original entry instead of entering the trampoline.
                ctx->trampoline = ctx->target_entry;
            }
            runtime->detour.reset();
            // Do not free runtime->stub here: this function runs from inside the
            // same stub execution path (HookCallback -> OnFunctionEnter).
            // Freeing now can invalidate the current EIP and crash on return.
            if (active_hooks_ > 0) {
                --active_hooks_;
            }
            return true;
        } else {
            // Failed to disable; keep this hook armed.
            runtime->armed.store(true, std::memory_order_release);
            return false;
        }
    }

    void AppendEvent(const std::string& event_json) {
        std::scoped_lock lock(mu_);
        AppendEventUnlocked(event_json);
    }

    Snapshot MakeSnapshotLocked() const {
        Snapshot snap{};
        snap.events_seen = events_seen_;
        snap.installed_hooks = installed_hooks_;
        snap.failed_hooks = failed_hooks_;
        snap.blocked_hooks = blocked_hooks_;
        snap.install_epoch = install_epoch_;
        snap.active_hooks = active_hooks_;
        snap.pending_install_tokens = install_cursor_ < install_order_.size()
            ? static_cast<std::uint32_t>(install_order_.size() - install_cursor_)
            : 0;
        snap.refill_budget_exhausted_count = refill_budget_exhausted_count_;
        snap.sanitized_jump_target_count = sanitized_jump_target_count_;
        snap.blocked_live_ip_hooks = blocked_live_ip_hooks_;
        snap.discovered_tokens.assign(discovered_tokens_.begin(), discovered_tokens_.end());
        snap.edges.reserve(edge_counts_.size());
        for (const auto& [key, count] : edge_counts_) {
            SnapshotEdge edge{};
            edge.caller_ret = static_cast<std::uint32_t>(key >> 32u);
            edge.callee = static_cast<std::uint32_t>(key & 0xFFFFFFFFull);
            edge.count = count;
            snap.edges.push_back(edge);
        }
        return snap;
    }

    void WriteProgressJson(const Snapshot& snapshot) {
        std::error_code ec;
        std::filesystem::create_directories(progress_path_.parent_path(), ec);
        const auto temp_path = progress_path_.parent_path() / (progress_path_.filename().string() + ".tmp");

        auto discovered = snapshot.discovered_tokens;
        std::sort(discovered.begin(), discovered.end());

        auto edges = snapshot.edges;
        std::sort(edges.begin(), edges.end(), [](const SnapshotEdge& a, const SnapshotEdge& b) {
            if (a.callee != b.callee) {
                return a.callee < b.callee;
            }
            return a.caller_ret < b.caller_ret;
        });

        std::ofstream out(temp_path, std::ios::binary | std::ios::trunc);
        if (!out.is_open()) {
            return;
        }

        out << "{\n";
        out << "  \"version\": 1,\n";
        out << "  \"generated_utc\": \"" << UtcNowIso8601() << "\",\n";
        out << "  \"namespace\": \"" << JsonEscape(namespace_key_) << "\",\n";
        out << "  \"watchlist_path\": \"" << JsonEscape(watchlist_path_.string()) << "\",\n";
        out << "  \"event_log_path\": \"" << JsonEscape(event_log_path_.string()) << "\",\n";
        out << "  \"watchlist_total\": " << watchlist_total_ << ",\n";
        out << "  \"max_hooks\": " << max_hooks_ << ",\n";
        out << "  \"installed_hooks\": " << snapshot.installed_hooks << ",\n";
        out << "  \"failed_hooks\": " << snapshot.failed_hooks << ",\n";
        out << "  \"blocked_hooks\": " << snapshot.blocked_hooks << ",\n";
        out << "  \"active_hooks\": " << snapshot.active_hooks << ",\n";
        out << "  \"pending_install_tokens\": " << snapshot.pending_install_tokens << ",\n";
        out << "  \"refill_budget_exhausted_count\": " << snapshot.refill_budget_exhausted_count << ",\n";
        out << "  \"sanitized_jump_target_count\": " << snapshot.sanitized_jump_target_count << ",\n";
        out << "  \"blocked_live_ip_hooks\": " << snapshot.blocked_live_ip_hooks << ",\n";
        out << "  \"install_epoch\": " << snapshot.install_epoch << ",\n";
        out << "  \"events_seen\": " << snapshot.events_seen << ",\n";
        out << "  \"discovered_count\": " << discovered.size() << ",\n";
        out << "  \"edge_count\": " << edges.size() << ",\n";
        out << "  \"record_edges_after_discovered\": " << (record_edges_after_discovered_ ? "true" : "false") << ",\n";
        out << "  \"one_shot_hooks\": " << (one_shot_hooks_ ? "true" : "false") << ",\n";
        out << "  \"rotate_one_shot_hooks\": " << (rotate_one_shot_hooks_ ? "true" : "false") << ",\n";
        out << "  \"rotate_refill_scan_budget\": " << rotate_refill_scan_budget_ << ",\n";
        out << "  \"spread_hooks\": " << (spread_hooks_ ? "true" : "false") << ",\n";
        out << "  \"skip_crt_risky_range\": " << (skip_crt_risky_range_ ? "true" : "false") << ",\n";
        out << "  \"strict_entry_filter\": " << (strict_entry_filter_ ? "true" : "false") << ",\n";
        out << "  \"pause_main_thread_during_install\": " << (pause_main_thread_during_install_ ? "true" : "false") << ",\n";
        out << "  \"pause_all_threads_during_install\": " << (pause_all_threads_during_install_ ? "true" : "false") << ",\n";
        out << "  \"suspend_threads_on_enable\": " << (suspend_threads_on_enable_ ? "true" : "false") << ",\n";
        out << "  \"suspend_threads_on_disable\": " << (suspend_threads_on_disable_ ? "true" : "false") << ",\n";
        out << "  \"discovered_tokens\": [\n";
        for (std::size_t i = 0; i < discovered.size(); ++i) {
            out << "    \"" << discovered[i] << "\"";
            if (i + 1 < discovered.size()) {
                out << ",";
            }
            out << "\n";
        }
        out << "  ],\n";
        out << "  \"edges\": [\n";
        for (std::size_t i = 0; i < edges.size(); ++i) {
            out << "    {\"caller_ret\":\"0x" << std::format("{:08X}", edges[i].caller_ret)
                << "\",\"callee\":\"" << TokenFromAddress(edges[i].callee)
                << "\",\"count\":" << edges[i].count << "}";
            if (i + 1 < edges.size()) {
                out << ",";
            }
            out << "\n";
        }
        out << "  ]\n";
        out << "}\n";
        out.close();

        std::filesystem::remove(progress_path_, ec);
        std::filesystem::rename(temp_path, progress_path_, ec);
        if (ec) {
            std::filesystem::copy_file(temp_path, progress_path_, std::filesystem::copy_options::overwrite_existing, ec);
            std::filesystem::remove(temp_path, ec);
        }
    }

private:
    static std::optional<std::uint32_t> GetThreadEip(const HANDLE thread) {
        if (thread == nullptr) {
            return std::nullopt;
        }
        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_CONTROL;
        if (!GetThreadContext(thread, &ctx)) {
            return std::nullopt;
        }
        return static_cast<std::uint32_t>(ctx.Eip);
    }

    void CaptureSuspendedThreadIpsNoLock(
        const HANDLE main_thread_handle,
        const bool main_thread_suspended,
        const std::vector<HANDLE>& suspended_other_threads)
    {
        suspended_thread_ips_.clear();
        if (main_thread_suspended) {
            if (const auto eip = GetThreadEip(main_thread_handle); eip.has_value()) {
                suspended_thread_ips_.push_back(*eip);
            }
        }
        for (const HANDLE thread : suspended_other_threads) {
            if (const auto eip = GetThreadEip(thread); eip.has_value()) {
                suspended_thread_ips_.push_back(*eip);
            }
        }
    }

private:
    std::mutex mu_;
    std::atomic<bool> started_{ false };
    std::string namespace_key_;
    std::filesystem::path watchlist_path_;
    std::filesystem::path progress_path_;
    std::filesystem::path event_log_path_;
    std::filesystem::path crash_log_path_;
    std::ofstream event_log_stream_;

    std::vector<std::string> watchlist_tokens_;
    std::unordered_map<std::string, std::uint32_t> watchlist_addrs_;
    std::unordered_set<std::string> discovered_tokens_;
    std::unordered_map<std::uint64_t, std::uint32_t> edge_counts_;
    std::vector<std::unique_ptr<HookRuntime>> hooks_;
    std::vector<std::string> install_order_;
    std::size_t install_cursor_ = 0;

    std::uint64_t events_seen_ = 0;
    std::uint32_t watchlist_total_ = 0;
    std::uint32_t max_hooks_ = kDefaultMaxHooks;
    bool record_edges_after_discovered_ = false;
    bool one_shot_hooks_ = true;
    bool rotate_one_shot_hooks_ = false;
    std::uint32_t rotate_refill_scan_budget_ = kDefaultRotateRefillScanBudget;
    bool spread_hooks_ = true;
    bool skip_crt_risky_range_ = true;
    bool strict_entry_filter_ = true;
    bool pause_main_thread_during_install_ = true;
    bool pause_all_threads_during_install_ = true;
    bool bulk_install_thread_pause_active_ = false;
    bool suspend_threads_on_enable_ = true;
    bool suspend_threads_on_disable_ = true;
    std::uint32_t installed_hooks_ = 0;
    std::uint32_t failed_hooks_ = 0;
    std::uint32_t blocked_hooks_ = 0;
    std::uint32_t active_hooks_ = 0;
    std::uint32_t install_epoch_ = 0;
    std::uint32_t refill_budget_exhausted_count_ = 0;
    std::uint32_t sanitized_jump_target_count_ = 0;
    std::uint32_t blocked_live_ip_hooks_ = 0;
    PVOID veh_handle_ = nullptr;
    HMODULE self_module_handle_ = nullptr;
    std::vector<std::uint32_t> suspended_thread_ips_{};

    Clock::time_point last_flush_ = Clock::now();
    std::uint32_t new_discoveries_since_flush_ = 0;
    std::uint32_t new_edges_since_flush_ = 0;
#endif
};

DiscoveryTracer g_tracer;
DiscoveryTracer* g_instance = &g_tracer;

} // namespace

bool Start(HMODULE module_handle) {
    return g_tracer.Start(module_handle);
}

void Stop() {
    g_tracer.Stop();
}

} // namespace inspect::discovery
