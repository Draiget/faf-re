// SPDX: faf engine recovery
//
// EngineMethodStubs.cpp
//
// Linker stubs for engine class member functions whose recovered source is
// not yet available. Each stub satisfies the link with a no-op default
// return. Methods that must return a reference or a non-default-constructible
// object should be moved out of this stub TU and recovered properly.

#include "gpg/core/reflection/Reflection.h"
#include "moho/effects/rendering/CEfxEmitterTypeInfo.h"
#include "moho/unit/core/Unit.h"
#include "moho/unit/tasks/CFactoryBuildTask.h"

namespace moho
{

// CEfxEmitterTypeInfo NewRef / CtrRef / Delete / Destruct lifecycle hooks
// are recovered in src/sdk/moho/effects/rendering/CEfxEmitterTypeInfo.cpp
// (matches FUN_0065F790 / FUN_0065F830 / FUN_0065F810 / FUN_0065F8A0). The
// real bodies are address-taken from `BindRTypeLifecycleCallbacks` inside
// `CEfxEmitterTypeInfo::Init` (CEfxEmitterTypeInfo.cpp:81-87), so the
// linker resolves the reflection-callback slots to the real allocators /
// destructors. Stubs removed to avoid the multiple-definition shadow.

// CFactoryBuildTask::Create (FUN_005FAD00) is recovered in
// src/sdk/moho/unit/tasks/CFactoryBuildTask.cpp — the real body allocates a
// 0x94-byte CFactoryBuildTask and placement-constructs it via the recovered
// dispatch-bound ctor (FUN_005F9F20). Replaces the no-op null-returning stub
// that left IAiCommandDispatchImpl / CUnitGuardTask build dispatch inert.

// ===== Unit serialization static helpers =====
// Unit::MemberConstruct recovered in src/sdk/moho/unit/core/Unit.cpp
// (FUN_006AD3C0) — reads the owning Sim from the archive, allocates + constructs
// a Unit via the recovered private Unit(Sim*) ctor (FUN_006A5050), and publishes
// it through SerConstructResult::SetUnowned. Stub removed.
// Unit::MemberSerialize (FUN_006B33A0) and Unit::MemberDeserialize (FUN_006B2B50)
// are recovered 1:1 in src/sdk/moho/unit/core/Unit.cpp — the full reflection
// save/load of every Unit member (typed sub-object RRefs via WriteRawPointer/
// ReadPointerOwned, weak refs, primitives, econ events, blip/recon vectors), in
// the exact binary field order. The no-op stubs here are removed.

// ===== gpg::gal device/head accessors =====
// `DeviceAppView` / `DeviceContextAppView` / `HeadAppView` were a duplicate of
// `gpg::gal::Device`, `DeviceContext` and `Head`, all three of which are
// recovered with real bodies -- `Device::IsReady` (0x008E6720),
// `Device::GetInstance` (0x008E6730) and `DeviceContext::GetHead`
// (0x008E69C0 / 0x008E6A90) in `gpg/gal/Device.cpp`. The stubs here returned
// `false` / `nullptr` / a shared zero head, so the one caller --
// `CScApp::AppDoSuppressWindowsKeys` (0x008CE1D0) -- could never return true
// and Windows-key suppression never engaged. It now calls the real singleton,
// and `AppRuntimeView.h` is gone.

} // namespace moho
