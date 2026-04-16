#include "discovery_tracer.h"

#include <algorithm>
#include <array>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cwchar>
#include <filesystem>
#include <fstream>
#include <format>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
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

struct HookContext {
    std::uint32_t callee_ea = 0;
    char token[kTokenMaxLen]{};
    void* trampoline = nullptr;
};

struct HookRuntime {
    std::string token;
    std::uint32_t address = 0;
    HookContext context{};
    void* stub = nullptr;
    std::unique_ptr<detours::Detour<void(*)()>> detour;

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
};

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

class DiscoveryTracer {
public:
    bool Start(HMODULE module_handle) {
#if !defined(_M_IX86)
        (void)module_handle;
        DebugPrintf("[discover] runtime tracer is only enabled for x86 builds.\n");
        return false;
#else
        std::scoped_lock lock(mu_);
        if (started_) {
            return true;
        }

        const auto module_path = GetModulePath(module_handle);
        const auto module_dir = module_path.has_parent_path() ? module_path.parent_path() : std::filesystem::current_path();
        const auto repo_root = FindRepoRootNear(module_dir);

        namespace_key_ = "fa_full_2026_03_26";
        if (const std::wstring ns_env = GetEnvW(L"INSPECT_DISCOVERY_NAMESPACE"); !ns_env.empty()) {
            namespace_key_ = NarrowAscii(ns_env);
        }

        watchlist_path_ = repo_root / "decomp" / "recovery" / "disasm" / namespace_key_ / "_no_caller_evidence_priority.txt";
        if (const std::wstring watch_env = GetEnvW(L"INSPECT_DISCOVERY_WATCHLIST"); !watch_env.empty()) {
            watchlist_path_ = std::filesystem::path(watch_env);
        }

        progress_path_ = watchlist_path_.parent_path() / "_runtime_discovery_progress.json";
        if (const std::wstring prog_env = GetEnvW(L"INSPECT_DISCOVERY_PROGRESS_JSON"); !prog_env.empty()) {
            progress_path_ = std::filesystem::path(prog_env);
        }

        event_log_path_ = watchlist_path_.parent_path() / "_runtime_discovery_events.ndjson";
        if (const std::wstring log_env = GetEnvW(L"INSPECT_DISCOVERY_EVENT_LOG"); !log_env.empty()) {
            event_log_path_ = std::filesystem::path(log_env);
        }

        max_hooks_ = ParseUint32OrDefault(GetEnvW(L"INSPECT_DISCOVERY_MAX_HOOKS"), 0);
        const std::wstring edge_env = GetEnvW(L"INSPECT_DISCOVERY_RECORD_EDGES_AFTER_DISCOVERED");
        // Default to enabled so call/callee schemes are built without requiring extra setup.
        // Set INSPECT_DISCOVERY_RECORD_EDGES_AFTER_DISCOVERED=0 to only record first-discovery edges.
        record_edges_after_discovered_ = edge_env.empty() ? true : IsTruthy(edge_env);

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

        InstallHooks();
        started_ = true;

        const double pct = watchlist_total_ == 0
            ? 100.0
            : static_cast<double>(discovered_tokens_.size()) * 100.0 / static_cast<double>(watchlist_total_);
        DebugPrintf(
            "[discover] watchlist={} total={} restored={} ({:.2f}%) max_hooks={} installed={} failed={} edges={} log={}\n",
            watchlist_path_.string(),
            watchlist_total_,
            discovered_tokens_.size(),
            pct,
            max_hooks_,
            installed_hooks_,
            failed_hooks_,
            edge_counts_.size(),
            event_log_path_.string());

        WriteProgressJson(MakeSnapshotLocked());
        return true;
#endif
    }

    void Stop() {
#if defined(_M_IX86)
        Snapshot snapshot;
        {
            std::scoped_lock lock(mu_);
            if (!started_) {
                return;
            }
            snapshot = MakeSnapshotLocked();
            started_ = false;
            hooks_.clear();
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

        thread_local bool reentrant = false;
        if (reentrant) {
            return;
        }
        reentrant = true;

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
            if (!started_) {
                reentrant = false;
                return;
            }

            ++events_seen_;
            events_seen = events_seen_;

            token = std::string(ctx->token);
            const bool new_function = discovered_tokens_.insert(token).second;
            bool new_edge = false;

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

    static void* BuildEntryStub(HookContext* ctx) {
        if (ctx == nullptr) {
            return nullptr;
        }
        static_assert(sizeof(void*) == 4, "Entry stub is x86-only.");

        constexpr std::size_t kStubSize = 26;
        auto* stub = static_cast<std::uint8_t*>(VirtualAlloc(
            nullptr, kStubSize, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
        if (!stub) {
            return nullptr;
        }

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
        stub[i++] = 0xFF; // jmp eax
        stub[i++] = 0xE0;

        FlushInstructionCache(GetCurrentProcess(), stub, kStubSize);
        return stub;
    }

    void InstallHooks() {
        hooks_.clear();
        installed_hooks_ = 0;
        failed_hooks_ = 0;

        const std::size_t hook_cap = max_hooks_ == 0 ? static_cast<std::size_t>(-1) : static_cast<std::size_t>(max_hooks_);
        for (const auto& token : watchlist_tokens_) {
            if (hooks_.size() >= hook_cap) {
                break;
            }
            if (discovered_tokens_.contains(token)) {
                continue;
            }
            const auto it_addr = watchlist_addrs_.find(token);
            if (it_addr == watchlist_addrs_.end()) {
                ++failed_hooks_;
                continue;
            }

            const std::uint32_t addr = it_addr->second;
            auto* const target = reinterpret_cast<void*>(static_cast<std::uintptr_t>(addr));
            if (!IsExecutableAddress(target)) {
                ++failed_hooks_;
                continue;
            }

            auto runtime = std::make_unique<HookRuntime>();
            runtime->token = token;
            runtime->address = addr;
            runtime->context.callee_ea = addr;
            runtime->context.trampoline = nullptr;
            std::snprintf(runtime->context.token, std::size(runtime->context.token), "%s", token.c_str());

            runtime->stub = BuildEntryStub(&runtime->context);
            if (!runtime->stub) {
                ++failed_hooks_;
                continue;
            }

            auto detour = detours::Detour<void(*)()>::create_at_disabled(
                token,
                target,
                reinterpret_cast<void(*)()>(runtime->stub));
            if (!detour) {
                VirtualFree(runtime->stub, 0, MEM_RELEASE);
                runtime->stub = nullptr;
                ++failed_hooks_;
                continue;
            }

            runtime->context.trampoline = reinterpret_cast<void*>(detour->original());
            detour->enable();
            runtime->detour = std::move(detour);

            hooks_.push_back(std::move(runtime));
            ++installed_hooks_;
        }
    }

    void AppendEvent(const std::string& event_json) {
        std::scoped_lock lock(mu_);
        if (!event_log_stream_.is_open()) {
            return;
        }
        event_log_stream_ << event_json << "\n";
        event_log_stream_.flush();
    }

    Snapshot MakeSnapshotLocked() const {
        Snapshot snap{};
        snap.events_seen = events_seen_;
        snap.installed_hooks = installed_hooks_;
        snap.failed_hooks = failed_hooks_;
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
        out << "  \"events_seen\": " << snapshot.events_seen << ",\n";
        out << "  \"discovered_count\": " << discovered.size() << ",\n";
        out << "  \"edge_count\": " << edges.size() << ",\n";
        out << "  \"record_edges_after_discovered\": " << (record_edges_after_discovered_ ? "true" : "false") << ",\n";
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
    std::mutex mu_;
    bool started_ = false;
    std::string namespace_key_;
    std::filesystem::path watchlist_path_;
    std::filesystem::path progress_path_;
    std::filesystem::path event_log_path_;
    std::ofstream event_log_stream_;

    std::vector<std::string> watchlist_tokens_;
    std::unordered_map<std::string, std::uint32_t> watchlist_addrs_;
    std::unordered_set<std::string> discovered_tokens_;
    std::unordered_map<std::uint64_t, std::uint32_t> edge_counts_;
    std::vector<std::unique_ptr<HookRuntime>> hooks_;

    std::uint64_t events_seen_ = 0;
    std::uint32_t watchlist_total_ = 0;
    std::uint32_t max_hooks_ = 0;
    bool record_edges_after_discovered_ = false;
    std::uint32_t installed_hooks_ = 0;
    std::uint32_t failed_hooks_ = 0;

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
