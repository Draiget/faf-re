// ReSharper disable CppTooWideScope
#include <format>
#include <windows.h>

#include "moho/entity/Unit.h"
#include "moho/sim/CWldSession.h"
#include "utils/signatures.h"
#include "utils/memory/detours.h"
#include "utils/debug.h"
#include "utils/rtti_dump.h"
#include "moho/sim/Sim.h"

// thiscall (ECX=self), first stack arg = outArmy
using SimCreateArmyFn = moho::CArmyImpl* (__thiscall*)(
    moho::Sim* self,
    moho::CArmyImpl* outArmy,
    int a3, int a4, int* a5, int32_t* a6, char a7
);

using EntityCreateUnitFn = int(__stdcall*)(int a1, int** a2);
using SessionBeginFn = char(__thiscall*)(void*, void*);

std::unique_ptr<detours::Detour<SimCreateArmyFn>> g_Sim_CreateArmy;
std::unique_ptr<detours::Detour<EntityCreateUnitFn>> g_Entity_CreateUnit;
std::unique_ptr<detours::Detour<SessionBeginFn>> g_Session_Begin;

static moho::CWldSession** g_Session;

bool InstallDetours();
void UninstallDetours();

static DWORD EntryThread_Impl(LPVOID) {
    // Any C++/RAII code is allowed here (no SEH in this function).
    OutputDebugStringW(L"[inspect] init...\n");

    // moho_rtti::SetSymbolSearchPath("G:\\projects\\faf-main\\bin\\2025.7.1\\ForgedAlliance.pdb");
    // moho_rtti::DumpOptions opts;
    // opts.ns_mode = moho_rtti::NamespaceMode::DeriveFromType;
    // opts.fixed_namespace = "fa_re";
    // opts.flatten_namespaces = false;
    // opts.exclude_system_modules = true;
    // opts.parallel_scan = true;
    // opts.scan_threads = 4;
    // opts.rename_virtuals_with_symbols = true;
    // opts.collect_type_descriptors = true;
    // opts.emit_td_stubs = true;
    // opts.skip_empty_vftables = false;
    // opts.emit_template_stubs = true;
	// DumpAllRtti("G:\\projects\\faf-main\\rtti_dump_all.hpp", opts);

    InstallDetours();

    OutputDebugStringW(L"[inspect] init done\n");
    return 0;
}

static DWORD WINAPI EntryThread(LPVOID param) {
    // IMPORTANT: keep this function POD-only: no std::string, std::vector, etc.
    __try {
        return EntryThread_Impl(param); // Call into the C++ world.
    } __except (EXCEPTION_EXECUTE_HANDLER) {
        OutputDebugStringW(L"[inspect] exception in EntryThread\n");
        return 0;
    }
}

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID) {
    if (reason == DLL_PROCESS_ATTACH) {
        DisableThreadLibraryCalls(h);
        const HANDLE th = CreateThread(nullptr, 0, EntryThread, nullptr, 0, nullptr);
        if (th) {
            CloseHandle(th);
        }
    }
    return TRUE;
}

moho::CArmyImpl* __fastcall SimCreateArmy_Hook(
    moho::Sim* self, void* /*edx*/,
    moho::CArmyImpl* outArmy,
    int a3, int a4, int* a5, int32_t* a6, char a7)
{
    if (!self || !outArmy) {
        OutputDebugStringW(L"[hook] BAD ABI: self/outArmy is null\n");
    }

    // 'self' is your Sim* (this)
    // You can inspect Sim state here, log, modify args, etc.

    // Call original (the trampoline built by detour)
    auto* army = g_Sim_CreateArmy->original()(self, outArmy, a3, a4, a5, a6, a7);

    DebugPrintf("[inspect] Sim::ArmyCreate[{:p}, sim={:p}]\n", 
        static_cast<void*>(army), 
        static_cast<void*>(self));

    // Post-process, wrap, track, etc.
    return army;
}

int __stdcall EntityCreateUnit_Hook(int a1, int** a2)
{
    // Call original (the trampoline built by detour)
    auto unit = g_Entity_CreateUnit->original()(a1, a2);

    auto casted = reinterpret_cast<moho::Unit*>(unit);

    DebugPrintf("[inspect] Entity::CreateUnit[{:p}, id={}, name={}]\n", 
        reinterpret_cast<void*>(unit),
        casted->id_,
        casted->Name);

    // Post-process, wrap, track, etc.
    return unit;
}

char __fastcall SessionBegin_Hook(void* self, void* /*edx*/, void* arg0)
{
    const char ret = g_Session_Begin->original()(self, arg0);
    DebugPrintf("[inspect] Session::Begin[session={:p}, addr={:p}, arg0={:p}, ret={}]\n", 
        static_cast<void*>(g_Session), 
        static_cast<void*>(*g_Session),
        arg0, 
        static_cast<int>(ret));

    return ret;
}

bool InstallDetours() {
	const HMODULE module = GetModuleHandleW(L"ForgedAlliance.exe");

    g_Sim_CreateArmy = detours::Detour<SimCreateArmyFn>::create_ida(
        "Sim::CreateArmy", 
        module,
        g_Sig_Sim_ArmyCreate, 
        reinterpret_cast<SimCreateArmyFn>(&SimCreateArmy_Hook)
    );

    g_Entity_CreateUnit = detours::Detour<EntityCreateUnitFn>::create_ida(
        "Sim::CreateUnit", 
        module,
        g_Sig_Entity_CreateUnit,
        reinterpret_cast<EntityCreateUnitFn>(&EntityCreateUnit_Hook)
    );

    g_Session_Begin = detours::Detour<SessionBeginFn>::create_ida(
        "Session::Begin", 
        module,
        g_Sig_Session_Begin,
        reinterpret_cast<SessionBeginFn>(&SessionBegin_Hook)
    );

    g_Session = static_cast<moho::CWldSession**>(
        *static_cast<void**>(
            static_cast<void*>(
                (static_cast<uint8_t*>(
                    find_ida(module, g_Sig_Session_Struct, true)) + 0x01)
                )
            )
        );
    
    DebugPrintf("[inspect] g_Session={:p}\n",
        static_cast<void*>(g_Session));

    return
		static_cast<bool>(g_Sim_CreateArmy) && 
        static_cast<bool>(g_Entity_CreateUnit) && 
        static_cast<bool>(g_Session_Begin) && 
        static_cast<bool>(g_Session) != 0;
}

void UninstallDetours() {
    g_Sim_CreateArmy.reset();
}

extern "C" __declspec(dllexport) DWORD WINAPI Inspect_Reinit(LPVOID) {
	/* re-hook, DebugBreak, etc. */
	return 0;
}

extern "C" __declspec(dllexport) DWORD WINAPI Inspect_Cleanup(LPVOID) {
	/* unhook */
	return 0;
}
