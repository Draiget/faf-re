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
void CRenFrame::Render(int, int) {}
void CameraImpl::Frame(float, float) {}
void CollisionBeamEntity::CheckCollision() {}
void SMassInfo::MemberDeserialize(gpg::ReadArchive*) {}
void SMassInfo::MemberSerialize(gpg::WriteArchive*) const {}
void SkyDome::CreateTextures() {}
bool CUnitMotion::CalcMoveCommon(VTransform&, float*) { return false; }

// ===== Virtual destructors =====
CAiAttackerImpl::~CAiAttackerImpl() {}
SkyDome::~SkyDome() {}

// ===== Virtual Execute() returning int =====
int CFactoryBuildTask::Execute() { return 0; }
int CUnitCarrierLaunch::Execute() { return 0; }

// ===== MapImager virtual destructor proxy =====
void MapImager::VirtualDtor() {}

// ===== CMauiMovie::LoadFile =====
bool CMauiMovie::LoadFile(const char*) { return false; }

// ===== Constructors (no-op default-init) =====
CMauiEdit::CMauiEdit(LuaPlus::LuaObject* lo, CMauiControl* parent)
    : CMauiControl(lo, parent, msvc8::string{}) {}
CUnitPatrolTask::CUnitPatrolTask(CCommandTask*, const void*, IFormationInstance*, bool) {}

CLuaWldUIProvider::CLuaWldUIProvider(LuaPlus::LuaObject*) {}
CLuaWldUIProvider::~CLuaWldUIProvider() {}
gpg::RType* CLuaWldUIProvider::GetClass() const { return nullptr; }
gpg::RRef CLuaWldUIProvider::GetDerivedObjectRef() { return {}; }
void CLuaWldUIProvider::CreateGameInterface(bool) {}

CameraImpl::CameraImpl(gpg::StrArg, const STIMap&, LuaPlus::LuaState*) {}

Projectile::Projectile(
    const RProjectileBlueprint*, Sim* sim, CArmyImpl*, Entity*,
    const VTransform&, float, float, const msvc8::string&,
    const CAiTarget&, bool)
    : Entity(sim, 0u) {}

} // namespace moho
