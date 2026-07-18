// SPDX: faf engine recovery
//
// EngineMethodStubs2.cpp
//
// More linker stubs for engine class member functions whose recovered source
// is not yet available. Each stub satisfies the link with a no-op default
// return.

#include "gpg/core/reflection/Reflection.h"
#include "moho/ai/CAiAttackerImpl.h"
#include "moho/command/ICommandSink.h"
#include "moho/entity/EntityCollisionUpdater.h"
#include "moho/entity/CollisionBeamEntity.h"
#include "moho/render/CRenFrame.h"
#include "moho/render/MapImager.h"
#include "moho/render/SkyDome.h"
#include "moho/render/camera/CameraImpl.h"
#include "moho/sim/CWldSessionLoaderImpl.h"
#include "moho/sim/SMassInfo.h"
#include "moho/unit/CUnitMotion.h"
#include "moho/unit/tasks/CUnitCarrierLaunch.h"
#include "moho/unit/tasks/CUnitPatrolTask.h"
#include "moho/unit/tasks/CFactoryBuildTask.h"
#include "moho/projectile/Projectile.h"
#include "moho/ui/UiRuntimeTypes.h"

namespace moho
{

// ===== EntityCollisionUpdater virtual collision queries =====
bool EntityCollisionUpdater::CollideBox(const Wm3::Box3<float>*, CollisionPairResult*) const { return false; }
bool EntityCollisionUpdater::CollideLine(const Wm3::Vector3<float>*, const Wm3::Vector3<float>*, CollisionLineResult*) const { return false; }
bool EntityCollisionUpdater::CollideSphere(const Wm3::Sphere3<float>*, CollisionPairResult*) const { return false; }
bool EntityCollisionUpdater::PointInShape(const Wm3::Vector3<float>*) const { return false; }
const Wm3::Box3<float>* EntityCollisionUpdater::GetBox() const { return nullptr; }
const Wm3::Sphere3<float>* EntityCollisionUpdater::GetSphere() const { return nullptr; }
Wm3::Vector3<float>* EntityCollisionUpdater::GetCenter(Wm3::Vector3<float>* out) const { return out; }
const Wm3::Vector3<float>* EntityCollisionUpdater::SetCenter(const Wm3::Vector3<float>* in) { return in; }
const EntityCollisionBoundsView* EntityCollisionUpdater::GetBoundingBox(EntityCollisionBoundsScratch*) const { return nullptr; }
void EntityCollisionUpdater::SetTransform(const EntityTransformPayload&) {}

// ===== IWldSessionLoader (defined in CWldSessionLoaderImpl.h as base) =====
bool IWldSessionLoader::IsLoaded()                       { return false; }
SWldGameData* IWldSessionLoader::LoadGameData(SWldGameData* gd) { return gd; }
SWldScenarioInfo* IWldSessionLoader::CreateScenarioInfo(const char*, msvc8::string*) { return nullptr; }
SWldScenarioInfo* IWldSessionLoader::GetScenarioInfo(const char*, msvc8::string*, bool) { return nullptr; }
void IWldSessionLoader::Finalize() {}
void IWldSessionLoader::SetCreated() {}
void IWldSessionLoader::Update() {}

// ===== ICommandSink =====
void ICommandSink::AdvanceBeat(int) {}
void ICommandSink::EndGame() {}

// ===== Misc instance methods =====
void CMauiMesh::Frame(float) {}
// CRenFrame::Render is recovered 1:1 in
// src/sdk/moho/render/CRenFrame.cpp (matches FUN_007F6030) — the real
// frame/bloom post-process pass that selects the "frame" effect, binds the
// four frame render targets plus blur/glow/width/height/viewport shader
// variables, and issues the full-screen triangle-strip draw. The former empty
// {} stub here was a false recovery; removed.
// CameraImpl::Frame is fully recovered in
// src/sdk/moho/render/camera/CameraImpl.cpp (matches FUN_007A9030). The real
// body drives UpdateTargets / UpdateBasis / InterpolateBasis / UpdateCoords /
// CacheCameraFrustumUnits by name — all five sibling helpers are now
// recovered, so the placeholder stub here is no longer needed.
// CollisionBeamEntity::CheckCollision is recovered 1:1 in
// src/sdk/moho/entity/CollisionBeamEntity.cpp (matches FUN_006732D0) — the beam
// collision pass that resolves the launcher weapon's impact, broadcasts the
// hit/miss/irrelevant event, updates beam length/effect, and fires OnImpact.
// The empty duplicate definition here shadowed that body (a multiple-definition
// link error); removed.
// SMassInfo::MemberDeserialize / MemberSerialize recovered in
// src/sdk/moho/sim/SMassInfo.cpp (matches FUN_00593030 / FUN_00593080).
void SkyDome::CreateTextures() {}

// ===== Virtual destructors =====
// CAiAttackerImpl::~CAiAttackerImpl is recovered in CAiAttackerImpl.cpp
// (matches FUN_005D6BC0); see the typed dtor body there for the real
// teardown sequence that pairs with the recovered default ctor.
SkyDome::~SkyDome() {}

// ===== Virtual Execute() returning int =====
// CFactoryBuildTask::Execute is recovered 1:1 in
// src/sdk/moho/unit/tasks/CFactoryBuildTask.cpp (matches FUN_005FA790,
// Moho::CFactoryBuildTask::TaskTick) — the real factory build-task state
// machine. The empty {return 0;} stub here was a false recovery; removed.
// CUnitCarrierLaunch::Execute is recovered in
// src/sdk/moho/unit/tasks/CUnitCarrierLaunch.cpp (matches FUN_00607000,
// Moho::CUnitCarrierLaunch::TaskTick) — see the real state-machine body
// there that drives the carrier-launch four-state flow.

// MapImager::VirtualDtor (FUN_007D9B90, vtable slot 0 scalar deleting dtor) is
// recovered in src/sdk/moho/render/MapImager.cpp — the real body runs the
// MapImager teardown (ClearBorder + vector-storage release) that the empty
// stub silently skipped (leaking the border mesh instances on viewport
// teardown).

// ===== Constructors (no-op default-init) =====
// CMauiEdit::CMauiEdit(LuaPlus::LuaObject*, CMauiControl*) (FUN_0078EFE0) is
// recovered 1:1 in src/sdk/moho/ui/UiRuntimeTypes.cpp — the former empty-string
// stub here was a false recovery ("" control kind + zero field init); removed in
// favor of the real "edit" ctor that initializes the full edit/font/caret state.
// CUnitPatrolTask parameterized ctor is recovered 1:1 in
// src/sdk/moho/unit/tasks/CUnitPatrolTask.cpp (FUN_0061AE50) — the former
// empty-stub false-recovery here was removed in favor of the real body.

// CLuaWldUIProvider ctor (FUN_0086A530) and dtor (FUN_0086A5D0) are recovered
// 1:1 in src/sdk/moho/ui/UiRuntimeTypes.cpp — the former empty-stub
// false-recoveries here were removed in favor of the real bodies.
// CLuaWldUIProvider::GetClass (FUN_0086A380), GetDerivedObjectRef
// (FUN_0086A3C0), and CreateGameInterface (FUN_0086A6E0) are recovered in
// src/sdk/moho/ui/UiRuntimeTypes.cpp — GetClass returns the cached
// CLuaWldUIProvider reflection type (the nullptr stub broke reflection),
// GetDerivedObjectRef packs the {object, type} RRef handle, and
// CreateGameInterface prefetches the provider's textures and dispatches the
// create-interface script callback (the empty stub did neither).

CameraImpl::CameraImpl(gpg::StrArg, const STIMap&, LuaPlus::LuaState*) {}

Projectile::Projectile(
    const RProjectileBlueprint*, Sim* sim, CArmyImpl*, Entity*,
    const VTransform&, float, float, const msvc8::string&,
    const CAiTarget&, bool)
    : Entity(sim, 0u) {}

} // namespace moho
