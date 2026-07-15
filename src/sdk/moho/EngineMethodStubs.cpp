// SPDX: faf engine recovery
//
// EngineMethodStubs.cpp
//
// Linker stubs for engine class member functions whose recovered source is
// not yet available. Each stub satisfies the link with a no-op default
// return. Methods that must return a reference or a non-default-constructible
// object should be moved out of this stub TU and recovered properly.

#include "gpg/core/reflection/Reflection.h"
#include "gpg/gal/AppRuntimeView.h"
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

// ===== CFactoryBuildTask static factory =====
CFactoryBuildTask* CFactoryBuildTask::Create(
    CCommandTask*, const RUnitBlueprint*, CUnitCommand*, Unit*)
{
    return nullptr;
}

// ===== Unit serialization static helpers =====
// Unit::MemberConstruct recovered in src/sdk/moho/unit/core/Unit.cpp
// (FUN_006AD3C0) — reads the owning Sim from the archive, allocates + constructs
// a Unit via the recovered private Unit(Sim*) ctor (FUN_006A5050), and publishes
// it through SerConstructResult::SetUnowned. Stub removed.
void Unit::MemberDeserialize(gpg::ReadArchive*, Unit*, int) {}
void Unit::MemberSerialize(gpg::WriteArchive*, Unit*, int) {}

} // namespace moho

namespace gpg::gal
{
// ===== DeviceAppView static accessors =====
bool DeviceAppView::IsReady()                { return false; }
DeviceAppView* DeviceAppView::GetInstance()  { return nullptr; }

// ===== DeviceContextAppView head accessor =====
// Returns a reference to a shared zero-init `HeadAppView` placeholder. The
// recovered CScApp path calls this to probe the current head's state; with
// this stub, all probes see the default-constructed head (no flags set).
const HeadAppView& DeviceContextAppView::GetHead(unsigned) const
{
    static const HeadAppView kEmpty{};
    return kEmpty;
}
} // namespace gpg::gal
