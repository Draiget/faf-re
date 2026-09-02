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

// EntityCollisionUpdater (= Moho::CColPrimitiveBase) had all ten of its
// virtuals stubbed here. They are pure in the binary: the class vftable at
// 0x00E0D3F4 points every one of its 10 slots at _purecall (0x00A82547), so
// the base contributes no bodies and these definitions were inventing
// behaviour -- GetBox in particular answered nullptr where a real box
// primitive hands back its payload. The declarations are now `= 0`.
//
// The real bodies belong to Moho::CColPrimitive<T>, a template with two
// instantiations (Box3f @0x00E0D50C, Sphere3f @0x00E0D480), which is what
// the paired addresses in EntityCollisionUpdater.h have always been.
// Recovering that template is the follow-up.

// IWldSessionLoader had all seven of its virtuals stubbed here. They are
// pure in the binary: the interface vftable at 0x00E49FA4 points all 7 slots
// at _purecall (0x00A82547). The declarations are now `= 0`.

// ===== ICommandSink =====

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
// SkyDome::CreateTextures is recovered 1:1 in
// src/sdk/moho/render/SkyDome.cpp (matches FUN_00817850,
// ?CreateTextures@SkyDome@Moho@@AAEXXZ) — the real dome texture-load pass that
// resolves all seven dome/decal/cirrus textures from the D3D device resources
// and extracts each base GAL texture into the matching texture lane. The empty
// {} stub here was a false recovery; removed.

// ===== Virtual destructors =====
// CAiAttackerImpl::~CAiAttackerImpl is recovered in CAiAttackerImpl.cpp
// (matches FUN_005D6BC0); see the typed dtor body there for the real
// teardown sequence that pairs with the recovered default ctor.
// SkyDome::~SkyDome is recovered 1:1 in src/sdk/moho/render/SkyDome.cpp
// (matches FUN_00814CD0). The empty stub that stood here skipped Reset(),
// the decal upload list teardown and the sentinel free.

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

// CameraImpl::CameraImpl(gpg::StrArg, const STIMap&, LuaPlus::LuaState*)
// (FUN_007A7950) is recovered 1:1 in src/sdk/moho/render/camera/CameraImpl.cpp
// — the real runtime camera constructor (broadcaster/CScriptEvent sub-object
// init, name/terrain/GeomCamera3 construction, full camera-state seed, target
// list + time sources, three frustum lanes, Lua object publish, viewport +
// reset). The former empty-body stub here was a false recovery (initialized
// nothing); removed.

// Projectile::Projectile(const RProjectileBlueprint*, Sim*, CArmyImpl*, Entity*,
// const VTransform&, float, float, const msvc8::string&, const CAiTarget&, bool)
// is recovered 1:1 in src/sdk/moho/projectile/Projectile.cpp (matches
// FUN_0069AFE0) — the real runtime launch ctor that reserves the entity id, seeds
// randomized physics lanes, splices launcher/target weak links, computes launch
// velocity, writes transforms, links into the Sim coord list, selects the layer,
// and fires the create scripts. The former `: Entity(sim, 0u) {}` empty stub was a
// false recovery (initialized nothing); removed.

} // namespace moho
