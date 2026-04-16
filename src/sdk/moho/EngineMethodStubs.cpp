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

// ===== CEfxEmitterTypeInfo private static type-info hooks =====
gpg::RRef CEfxEmitterTypeInfo::CtrRef(void*)  { return {}; }
gpg::RRef CEfxEmitterTypeInfo::NewRef()       { return {}; }
void      CEfxEmitterTypeInfo::Delete(void*)  {}
void      CEfxEmitterTypeInfo::Destruct(void*) {}

// ===== CFactoryBuildTask static factory =====
CFactoryBuildTask* CFactoryBuildTask::Create(
    CCommandTask*, const RUnitBlueprint*, CUnitCommand*, Unit*)
{
    return nullptr;
}

// ===== Unit serialization static helpers =====
void Unit::MemberConstruct(gpg::ReadArchive&, int, const gpg::RRef&, gpg::SerConstructResult&) {}
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
