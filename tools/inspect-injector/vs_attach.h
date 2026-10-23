// AutoAttachVS_SelectSameInstance.h
// Pick the Visual Studio DTE instance that is debugging THIS injector process,
// then attach it to the target game PID. Comments in English.

#pragma once
#include <windows.h>
#include <oleauto.h>
#include <string>
#include <vector>
#include <cstdio>

#pragma comment(lib, "ole32.lib")
#pragma comment(lib, "oleaut32.lib")

// === COM helpers (reuse if you already have them) ==================================
static HRESULT ComGetDispID(IDispatch* obj, LPCOLESTR name, DISPID* dispid) {
    return obj->GetIDsOfNames(IID_NULL, const_cast<LPOLESTR*>(&name), 1, LOCALE_USER_DEFAULT, dispid);
}

static HRESULT ComGetProp(IDispatch* obj, LPCOLESTR name, VARIANT* out) {
    if (!obj) return E_POINTER;
    DISPID id{};
    const HRESULT hr = ComGetDispID(obj, name, &id);
    if (FAILED(hr)) return hr;
    DISPPARAMS dp{}; VariantInit(out);
    return obj->Invoke(id, IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_PROPERTYGET, &dp, out, nullptr, nullptr);
}
static HRESULT ComGetPropDisp(IDispatch* obj, LPCOLESTR name, IDispatch** out) {
    VARIANT v; VariantInit(&v);
    const HRESULT hr = ComGetProp(obj, name, &v);
    if (SUCCEEDED(hr) && v.vt == VT_DISPATCH && v.pdispVal) { *out = v.pdispVal; return S_OK; }
    VariantClear(&v);
    return FAILED(hr) ? hr : E_FAIL;
}
static HRESULT ComCallMethod(IDispatch* obj, LPCOLESTR name, VARIANT* args, UINT cArgs, VARIANT* ret /*nullable*/) {
    if (!obj) return E_POINTER;
    DISPID id{};
    const HRESULT hr = ComGetDispID(obj, name, &id);
    if (FAILED(hr)) return hr;
    DISPPARAMS dp{};
    dp.cArgs = cArgs; dp.rgvarg = args; // args in reverse order if more than 1
    return obj->Invoke(id, IID_NULL, LOCALE_USER_DEFAULT, DISPATCH_METHOD, &dp, ret, nullptr, nullptr);
}

// === ROT enumeration: get ALL DTE instances =======================================

static bool IsVSDTEMonikerName(LPCOLESTR name) {
    // Typical ROT display name: "!VisualStudio.DTE.17.0:12345"
    return (name && wcsstr(name, L"VisualStudio.DTE.") != nullptr);
}

// Enumerate all DTE objects currently registered in the Running Object Table
static HRESULT EnumAllDTEsFromROT(std::vector<IDispatch*>& out) {
    out.clear();
    IRunningObjectTable* rot = nullptr;
    HRESULT hr = GetRunningObjectTable(0, &rot);
    if (FAILED(hr)) return hr;

    IEnumMoniker* enumMon = nullptr;
    hr = rot->EnumRunning(&enumMon);
    if (FAILED(hr)) { rot->Release(); return hr; }

    IBindCtx* bind = nullptr;
    CreateBindCtx(0, &bind);

    IMoniker* mk = nullptr;
    while (enumMon->Next(1, &mk, nullptr) == S_OK) {
        LPOLESTR dispName = nullptr;
        if (bind && SUCCEEDED(mk->GetDisplayName(bind, nullptr, &dispName)) && IsVSDTEMonikerName(dispName)) {
            IUnknown* unk = nullptr;
            if (SUCCEEDED(rot->GetObject(mk, &unk)) && unk) {
                IDispatch* dte = nullptr;
                if (SUCCEEDED(unk->QueryInterface(IID_IDispatch, reinterpret_cast<void**>(&dte))) && dte) {
                    out.push_back(dte); // keep
                }
                if (unk) unk->Release();
            }
        }
        if (dispName) {
            CoTaskMemFree(dispName);
        }
        mk->Release();
    }

    if (bind) {
        bind->Release();
    }

    enumMon->Release();
    rot->Release();
    return S_OK;
}

// Pick the DTE that is debugging the given PID (our injector)
static IDispatch* PickDTEByDebuggedPid(DWORD myPid) {
    std::vector<IDispatch*> dtes;
    if (FAILED(EnumAllDTEsFromROT(dtes))) {
        return nullptr;
    }

    IDispatch* chosen = nullptr;

    for (auto* dte : dtes) {
        IDispatch* dbg = nullptr;
        if (FAILED(ComGetPropDisp(dte, L"Debugger", &dbg)) || !dbg) {
	        dte->Release();
        	continue;
        }

        // Debugger.DebuggedProcesses (collection) — contains processes currently being debugged
        IDispatch* dbgProcs = nullptr;
        HRESULT hr = ComGetPropDisp(dbg, L"DebuggedProcesses", &dbgProcs);
        if (FAILED(hr) || !dbgProcs) {
	        dbg->Release(); dte->Release();
        	continue;
        }

        VARIANT vCount; VariantInit(&vCount);
        hr = ComGetProp(dbgProcs, L"Count", &vCount);
        bool match = false;
        if (SUCCEEDED(hr) && vCount.vt == VT_I4) {
            for (LONG i = 1; i <= vCount.lVal && !match; ++i) {
                VARIANT arg; VariantInit(&arg); arg.vt = VT_I4; arg.lVal = i;
                VARIANT ret; VariantInit(&ret);
                if (SUCCEEDED(ComCallMethod(dbgProcs, L"Item", &arg, 1, &ret)) &&
                    ret.vt == VT_DISPATCH && ret.pdispVal) {
                    IDispatch* dp = ret.pdispVal;
                    VARIANT vPid; VariantInit(&vPid);
                    if (SUCCEEDED(ComGetProp(dp, L"ProcessID", &vPid)) && (vPid.vt == VT_I4 || vPid.vt == VT_UI4)) {
                        DWORD pid = (vPid.vt == VT_I4) ? 
                            static_cast<DWORD>(vPid.lVal) :
                    		vPid.ulVal;
                        if (pid == myPid) {
                            match = true;
                        }
                    }
                    VariantClear(&vPid);
                    dp->Release();
                }
                VariantClear(&ret);
                VariantClear(&arg);
            }
        }
        VariantClear(&vCount);

        dbgProcs->Release();
        dbg->Release();

        if (match) {
            chosen = dte; // keep this one
            // release all others
            for (auto* x : dtes) if (x != dte) x->Release();
            return chosen;
        } else {
            dte->Release();
        }
    }
    // If no match, release all
    for (auto* x : dtes) x->Release();
    return nullptr;
}

// Fallback: first available DTE (if injector is not being debugged)
static IDispatch* PickAnyDTE() {
    std::vector<IDispatch*> dtes;
    if (FAILED(EnumAllDTEsFromROT(dtes)) || dtes.empty()) return nullptr;
    // take the first, release others
    IDispatch* d0 = dtes[0];
    for (size_t i = 1; i < dtes.size(); ++i) dtes[i]->Release();
    return d0;
}

// Public entry: attach "the same VS instance that debugs this injector" to target PID.
static bool VS_AttachSameVSInstanceToPid(DWORD targetPid) {
    bool didInit = false;
    HRESULT hr = CoInitializeEx(nullptr, COINIT_APARTMENTTHREADED);
    if (SUCCEEDED(hr)) didInit = true;
    else if (hr != RPC_E_CHANGED_MODE) {
        std::fwprintf(stderr, L"[DTE] CoInitializeEx failed: 0x%08X\n", hr);
        return false;
    }

    const DWORD myPid = GetCurrentProcessId();

    IDispatch* dte = PickDTEByDebuggedPid(myPid);
    if (!dte) dte = PickAnyDTE();
    if (!dte) {
        std::fwprintf(stderr, L"[DTE] No Visual Studio DTE found in ROT. Is VS running?\n");
        if (didInit) CoUninitialize();
        return false;
    }

    // dte.Debugger.LocalProcesses → find targetPid → Attach()
    IDispatch* dbg = nullptr;
    if (FAILED(ComGetPropDisp(dte, L"Debugger", &dbg)) || !dbg) {
        std::fwprintf(stderr, L"[DTE] No Debugger on DTE\n");
        dte->Release(); if (didInit) CoUninitialize(); return false;
    }

    IDispatch* procs = nullptr;
    if (FAILED(ComGetPropDisp(dbg, L"LocalProcesses", &procs)) || !procs) {
        std::fwprintf(stderr, L"[DTE] No LocalProcesses on Debugger\n");
        dbg->Release(); dte->Release(); if (didInit) CoUninitialize(); return false;
    }

    VARIANT vCount; VariantInit(&vCount);
    if (FAILED(ComGetProp(procs, L"Count", &vCount)) || vCount.vt != VT_I4) {
        std::fwprintf(stderr, L"[DTE] Cannot read LocalProcesses.Count\n");
        VariantClear(&vCount);
        procs->Release(); dbg->Release(); dte->Release(); if (didInit) CoUninitialize();
        return false;
    }

    bool attached = false;
    for (LONG i = 1; i <= vCount.lVal && !attached; ++i) {
        VARIANT arg; VariantInit(&arg); arg.vt = VT_I4; arg.lVal = i;
        VARIANT ret; VariantInit(&ret);
        if (SUCCEEDED(ComCallMethod(procs, L"Item", &arg, 1, &ret)) &&
            ret.vt == VT_DISPATCH && ret.pdispVal) {
            IDispatch* p = ret.pdispVal;
            VARIANT vPid; VariantInit(&vPid);
            if (SUCCEEDED(ComGetProp(p, L"ProcessID", &vPid)) && (vPid.vt == VT_I4 || vPid.vt == VT_UI4)) {
                DWORD pid = (vPid.vt == VT_I4) ? static_cast<DWORD>(vPid.lVal) : vPid.ulVal;
                if (pid == targetPid) {
                    VARIANT r;
                	VariantInit(&r);
                    attached = SUCCEEDED(ComCallMethod(p, L"Attach", nullptr, 0, &r));
                    VariantClear(&r);
                }
            }
            VariantClear(&vPid);
            p->Release();
        }
        VariantClear(&ret);
        VariantClear(&arg);
    }

    VariantClear(&vCount);
    procs->Release();
    dbg->Release();

    // Bring VS to front (optional)
    if (attached) {
        IDispatch* win = nullptr;
        if (SUCCEEDED(ComGetPropDisp(dte, L"MainWindow", &win)) && win) {
            ComCallMethod(win, L"Activate", nullptr, 0, nullptr);
            win->Release();
        }
    }

    dte->Release();
    if (didInit) CoUninitialize();

    if (!attached) std::fwprintf(stderr, L"[DTE] Target PID not found or Attach() failed\n");
    return attached;
}
