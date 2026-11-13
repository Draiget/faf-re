#pragma once
#include <type_traits>
#include <utility>
#include <cstdint>
#include <typeinfo>
#include <new>

#include <memory>
#include <memory>
#include <memory>

namespace moho
{
  /**
   * boost::function1<R, A>::operator() as instantiated by the engine's
   * one-argument callbacks (the three `boost::function_void::operator()`
   * twins 0x004135C0 / 0x00413E60 / 0x00461910 dispatch through it):
   * Address: 0x00937290 (FUN_00937290 -- the dispatch: `vtable == 0` raises
   *   `boost::bad_function_call` through `boost::throw_exception`, otherwise
   *   `invoker(functor at this+0x08, arg)` via the manager/invoker table's
   *   second slot; formerly `InvokeBoostFunction1` in
   *   moho/containers/LegacyContainerFillLanes.cpp, file removed 2026-09-10.)
   * Address: 0x00937360 (FUN_00937360 -- its one-instruction `jmp` tail thunk;
   *   formerly `InvokeBoostFunction1TailThunk`.)
   * Address: 0x00937490 (FUN_00937490 -- the pointer-indirected adapter
   *   (`(*self)->operator()(arg)`); formerly `InvokeBoostFunction1IndirectAdapter`.)
   * The bodies live in boost 1.34.1's function_template.hpp; no engine
   * source line maps to them beyond the `boost::function<void(A)>` members
   * that instantiate the template.
   */
  class RScmResource;
  class RScaResource;
  class CHeightField;
  class CMauiFrame;
  class CIntelGrid;
  class CAniPose;
  class CDebugCanvas;
  class CGpgNetInterface;
  class ISimResources;
  class PathPreviewFinder;
  class MeshMaterial;
  class Mesh;
  struct RMeshBlueprintLOD;
  class MeshBatch;
  class IRenTerrain;
  class CD3DTextureBatcher;
  class CD3DPrimBatcher;
  class ID3DVertexSheet;
  class ShoreCell;
  class MeshInstance;
  class CAniDefaultSkel;
  class LaunchInfoNew;
  class LaunchInfoLoad;
  struct SSessionSaveData;
  class UICommandGraph;
  struct SFileStarCloser;
  struct SParticleBuffer;
  class StatItem;
  template <class T>
  class Stats;
  using Stats_StatItem = Stats<StatItem>;
  struct STrigger;
} // namespace moho

namespace gpg::gal
{
  class TextureD3D9;
  class RenderTargetD3D9;
  class CubeRenderTargetD3D9;
  class DepthStencilTargetD3D9;
  class VertexFormatD3D9;
  class VertexBufferD3D9;
  class IndexBufferD3D9;
  class EffectD3D9;
  class PipelineStateD3D9;
  class EffectD3D10;
  class TextureD3D10;
  class RenderTargetD3D10;
  class CubeRenderTargetD3D10;
  class DepthStencilTargetD3D10;
  class VertexFormatD3D10;
  class VertexBufferD3D10;
  class IndexBufferD3D10;
  class PipelineStateD3D10;
  class EffectTechniqueD3D9;
  class EffectVariableD3D9;
  class EffectTechniqueD3D10;
  class EffectVariableD3D10;
} // namespace gpg::gal

namespace gpg
{
  /**
   * The pointer-container errors: what retail throws as `boost::bad_ptr_container_operation` and
   * `boost::bad_pointer` from Boost 1.34.1's ptr_container/exception.hpp, with the same messages. Nothing in the
   * engine catches them by type.
   */
  class BadPtrContainerOperation : public std::exception
  {
  public:
    explicit BadPtrContainerOperation(
      const char* const what
    ) noexcept
      : mWhat(what)
    {}

    [[nodiscard]] const char* what() const noexcept override
    {
      return mWhat;
    }

  private:
    const char* mWhat;
  };

  class BadPointer : public BadPtrContainerOperation
  {
  public:
    BadPointer() noexcept
      : BadPtrContainerOperation("Null pointer not allowed in a pointer container!")
    {}
  };

  /*
   * Address: 0x007BB4E0 (FUN_007BB4E0,
   * boost::weak_ptr<Moho::INetNATTraversalHandler>::weak_ptr(const shared_ptr&))
   * Address: 0x007BC5C0 (FUN_007BC5C0,
   * boost::weak_ptr<Moho::INetNATTraversalProvider>(const
   * shared_ptr<Moho::CGpgNetInterface>&) -- the aliasing/upcast form:
   * `CGpgNetInterface` derives from `INetNATTraversalProvider`, so the
   * binary shares the source's `shared_count`/`weak_count` control block
   * while rebinding the raw pointer to the base sub-object. Same
   * `_InterlockedExchangeAdd(&pi->weak_count_, 1)` shape as the
   * same-type case; the type difference only changes which `px` is
   * stored, not the refcount mechanics.)
   * Address: 0x00796EE0 (FUN_00796EE0 -- another per-T emission of the same
   * constructor: `weak_count(shared_count const&)` on the `pn` at +0x04
   * (call 0x00447030), then the `px` copy at +0x00. Zero callers in the
   * binary and none in source; formerly `ConstructWeakCountFromSharedTailLane`
   * in gpg/core/utils/BoostWrappers.cpp, where a stand-in had the +0x00 lane
   * named `control` and typed `sp_counted_base*` although it is the pointee
   * `px` (RULE ONE), removed 2026-09-18.)
   * Address: 0x008F3930 (FUN_008F3930 -- the `ret 4` register-shape sibling
   * of that emission; zero callers, unreachable; formerly
   * `ConstructWeakCountFromSharedTailLaneAdapterA` in
   * gpg/core/utils/BoostWrappers.cpp (RULE ONE), removed 2026-09-18.)
   * Address: 0x0089AE50 (FUN_0089AE50 -- `weak_ptr<Moho::UICommandGraph>::operator=
   * (shared_ptr const&)`: `px`, then `weak_count = shared_count` with no
   * same-block test - `weak_add_ref` on the incoming block (0x0089AE64), then
   * `weak_release` on the old one (0x0089AE75, `destroy()` through slot +8).
   * `CWldSession::GetCommandGraph` re-pointing the session's weak reference at
   * a graph it just created (0x00895F34). Formerly
   * `CopySharedToWeakCommandGraph` in moho/sim/CWldSession.cpp, removed
   * 2026-09-25.)
   * Address: 0x004AEF90 (FUN_004AEF90 -- `weak_ptr<void>::operator=(shared_ptr const&)`: `px`,
   * weak add-ref on the incoming block, weak release of the old one. `ResourceManager::
   * LoadRecord` storing what it loaded into `ResourceRecord::mResource` (0x004AAB1C). The
   * source had a strong assign here, so the manager held every resource forever;
   * formerly `AssignSharedPairRetainRelease_004AEF90` in moho/resource/ResourceManager.cpp (RULE ONE), removed
   * 2026-09-30.) Address: 0x004AEFF0 (FUN_004AEFF0 -- `weak_ptr<moho::PrefetchData>(shared_ptr const&)`: the temporary
   * `ResourceManager::PrefetchThread` pushes back onto the queue (0x004AB484); formerly
   * `AssignSharedPairRetain_004AEFF0` in moho/resource/ResourceManager.cpp (RULE ONE), removed 2026-09-30.)
   *
   * What it does:
   * Per-T binding of `boost::weak_ptr<TWeak>`'s converting constructor
   * from `boost::shared_ptr<TShared>` -- generic across same-type and
   * base/derived-aliasing instantiations.
   *
   * Callers assign the weak_ptr from the shared_ptr (`weak = shared;`); the
   * former per-T wrapper `AssignWeakFromShared` only did that.
   */

  /*
   * Address: 0x008F3950 (FUN_008F3950 -- `weak_ptr<gpg::gal::EffectD3D9>::lock()`: an
   * empty result when `pn` is null or its use count is zero, otherwise
   * `shared_count(weak_count const&)` into the result and `px` copied. Every
   * EffectTechniqueD3D9/EffectVariableD3D9 entry point calls it on its
   * `effect_` (24 call sites, 0x008F3CDF .. 0x00944DB8); formerly
   * `LockWeakEffectD3D9` in gpg/gal/backends/d3d9/D3D9Interfaces.cpp (RULE
   * ONE), removed 2026-09-24.)
   * Address: 0x004AC0E0 (FUN_004AC0E0 -- `weak_ptr<void>::lock()`, `ResourceRecord::mResource`:
   * `ResourceManager::LoadRecord` (0x004AA729), `PrefetchResource` (0x004AAE32) and
   * `PrefetchThread` (0x004AB3A6). The source added a weak reference here instead of a
   * strong one; formerly `BuildWeakPairFromLiveSharedVariant1` in moho/resource/ResourceManager.cpp (RULE ONE), removed
   * 2026-09-30.) Address: 0x004AC1C0 (FUN_004AC1C0 -- `weak_ptr<moho::PrefetchData>::lock()`, the record's prefetch and
   * the queue's front: `LoadRecord` (0x004AA6C2), `PrefetchResource` (0x004AAD30), `PrefetchThread` (0x004AB368) and
   * `OnDiskWatchEvent` (0x004AB8B8); formerly `BuildWeakPairFromLiveSharedVariant2` in
   * moho/resource/ResourceManager.cpp (RULE ONE), removed 2026-09-30.) Address: 0x00898F70 (FUN_00898F70 --
   * `weak_ptr<Moho::UICommandGraph>::lock()`: empty when the block is gone or its use count is zero, otherwise
   * `shared_count(weak_count const&)` (0x00447030) inside a try whose catch
   * returns empty. `CWldSession::GetCommandGraph` (0x00895EE5) and
   * `DirtyCommandGraph` (0x00895F7F, and inlined into `DoBeat` 0x00894F02 and
   * `ISSUE_RemoveLastCommand` 0x008B1337). Formerly `LockWeakCommandGraph` in
   * moho/sim/CWldSession.cpp, removed 2026-09-25.)
   *
   * What it does:
   * `boost::weak_ptr<T>::lock()`, per T: a retained `shared_ptr` while an owner
   * is alive, an empty one after.
   *
   * Callers call `weak.lock()` (formerly through `gpg::LockWeak`).
   */

  /*
   * Address: 0x00941B90 (FUN_00941B90 --
   * `enable_shared_from_this<gpg::gal::EffectD3D9>::shared_from_this()`: `shared_ptr<T>
   * p(_internal_weak_this)`, so `pn(weak.pn)` first -- 0x00447030, which throws
   * `bad_weak_ptr` once the owner is gone -- then `px`. `EffectD3D9::GetVariable`
   * (0x00941F04), `GetTechnique` (0x009420F3) and `GetTechniques` (0x00942A36)
   * build each wrapper's by-value effect argument with it; formerly
   * `CreateWeakEffectReference` in gpg/gal/backends/d3d9/D3D9Interfaces.cpp,
   * which described it as a weak_ptr construction (RULE ONE), removed 2026-09-24.)
   *
   * What it does:
   * `boost::enable_shared_from_this<T>::shared_from_this()`, per T.
   *
   * Callers call `shared_from_this()`.
   */

  /*
   * Address: 0x00445880 (FUN_00445880)
   *
   * `shared_ptr<Base>::reset(Y*)` for the per-head back-buffer targets: a
   * temporary `shared_ptr(p)` built through the `shared_count(Y*)` emission,
   * swapped in, the old count released. `DeviceD3D9::CreateHeads` calls the
   * first two (0x008EED88, 0x008EEDF6), `DeviceD3D10::CreateRenderTargets`
   * the third (0x008FD781). Each was a per-type `AssignShared<Y>FromRaw`
   * free function (RULE ONE), removed 2026-09-23.
   * Address: 0x008E9E40 (FUN_008E9E40, shared_ptr<RenderTarget>::reset(RenderTargetD3D9*))
   * Address: 0x008E9EB0 (FUN_008E9EB0, shared_ptr<DepthStencilTarget>::reset(DepthStencilTargetD3D9*))
   * Address: 0x008FA550 (FUN_008FA550, shared_ptr<RenderTarget>::reset(RenderTargetD3D10*))
   * Address: 0x008EA250 (FUN_008EA250, shared_ptr<PipelineStateD3D9>::reset(PipelineStateD3D9*) - device setup
   * 0x008F3320 and `Func9` 0x008F3070; formerly `AssignSharedPipelineStateFromRaw` in D3D9Interfaces.cpp, removed
   * 2026-09-23) Address: 0x008FA760 (FUN_008FA760, shared_ptr<PipelineStateD3D10>::reset(PipelineStateD3D10*) -
   * `DeviceD3D10::Setup` 0x00900B30; formerly `AssignSharedPipelineStateD3D10FromRaw` in D3D10Interfaces.cpp, removed
   * 2026-09-23) Address: 0x0089ADE0 (FUN_0089ADE0, shared_ptr<UICommandGraph>::reset(UICommandGraph*) -
   * `CWldSession::GetCommandGraph` adopting a graph it just built, 0x00895F2D; formerly `AssignSharedCommandGraph` +
   * `CreateBoostControlForUICommandGraph` in CWldSession.cpp, removed 2026-09-25)
   *
   * What it does:
   * Rebinds one initialized `boost::shared_ptr<T>` to a raw pointee by
   * constructing one new control block and releasing one previous owner.
   * Address: 0x007E5170 (FUN_007E5170, shared_ptr<RMeshBlueprintLOD>::reset(RMeshBlueprintLOD*) - p in EAX, `this` in
   * EDI: the temporary's `shared_count(p)` 0x007E6650, the no-op `sp_enable_shared_from_this` overload 0x0042AC30, the
   * swap, then the old count released inline; `MeshLOD::Load`'s `lodBlueprintCopy.reset(new
   * RMeshBlueprintLOD(blueprintLod))` at 0x007DCF32; formerly `AssignSharedRefWithEnableRuntime` in
   * moho/sim/SimRecoveryRuntime.cpp (RULE ONE), removed 2026-09-30.)
   *
   * Callers call `shared.reset(raw)`.
   */

  /*
   * Address: 0x00446010 (FUN_00446010)
   * Address: 0x0086EDD0 (FUN_0086EDD0 -- `shared_ptr<Moho::UICommandGraph>::operator=`:
   * `px` first, then retain the incoming count and release the old one
   * through 0x004229B0. `CUIWorldView::RenderCommandGraph` caching the
   * session's graph in `mComGraph` (0x0086ED3F).)
   *
   * What it does:
   * Copies one `boost::shared_ptr<T>` into caller-provided output storage.
   *
   * Callers copy-assign the shared_ptr.
   */

  /**
   * Address: 0x004DBBC0 (FUN_004DBBC0)
   *
   * What it does:
   * The null guard boost's pointer containers put in front of `push_back`.
   * Throws `boost::bad_pointer` carrying "Null pointer in 'push_back()'"
   * rather than letting a null element into the container.
   *
   * Declared here because callers live in other translation units - the sim
   * driver's sync queue reaches it from `SSyncDataQueue::PushBack`.
   */
  void EnsurePtrContainerPushBackInputNotNull(const void* inputPointer);

  /*
   * Retail boost template emissions this file used to recover as hand-written (px, pi) helpers, hand-built
   * control blocks and layout views. The engine now reaches each one through boost::shared_ptr / weak_ptr's own
   * members; the addresses are kept here so they stay findable.
   *
   * - SharedPtrRaw (BoostWrappers.h): Address: 0x00442BC0 (FUN_00442BC0) Address: 0x00442C30 (FUN_00442C30) Address:
   *   0x00442E80 (FUN_00442E80) Address: 0x00442F10 (FUN_00442F10) Address: 0x00442F90 (FUN_00442F90) Address:
   *   0x00443790 (FUN_00443790) Address: 0x004437E0 (FUN_004437E0) Address: 0x00539410 (FUN_00539410) What it does:
   *   Initializes one raw shared-ptr `(px,pi)` pair to empty/null lanes.
   * - weak_release (BoostWrappers.h): Address: 0x00446FC0 (FUN_00446FC0, backing `SpCountedBaseWeakReleaseFromSlot`
   *   in BoostWrappers.cpp) Address: 0x00941730 (FUN_00941730 -- `~weak_ptr<gpg::gal::EffectD3D9>`: the weak release
   *   on `pn` at +0x04, `destroy()` through vtable +0x08 at zero. It is the `enable_shared_from_this<EffectD3D9>`
   *   base's weak-this, so the effect constructors' unwind funclets reach it on `this + 4` (0x00B5DD86, 0x00B5DF62,
   *   0x00B5DF96); the destructor inlines it.) Address: 0x004A9B10 (FUN_004A9B10 -- `~weak_ptr<moho::PrefetchData>`:
   *   the weak release on `pn`; `ResourceManager::PrefetchResource` (0x004AAC20) and `PrefetchThread` (0x004AB180)
   *   drop their queue-element temporaries through it. Formerly `ReleaseWeakControlFromPair` in
   *   moho/resource/ResourceManager.cpp (RULE ONE), removed 2026-09-30.) Address: 0x00796DA0 (FUN_00796DA0 -- an ICF
   *   twin of 0x004A9B10; zero callers.) NOTE (2026-08-20 audit): 0x004229B0 was historically cited here and is WRONG
   *   - that address decrements `use_count_` at +0x04 first and calls vtable slot +0x04 (`dispose()`) before ever
   *   touching `weak_count_`, which is `sp_counted_base::release()` with `weak_release()` inlined into it (see
   *   `release()` below), not a standalone weak drop. The genuine weak-only body only exists at 0x00446FC0: it
   *   touches `weak_count_` at +0x08 exclusively and calls vtable slot +0x08 (`destroy()`) - it never calls
   *   `dispose()` and never touches +0x04. Every call site that actually invokes FUN_004229B0 must call `release()`
   *   on this wrapper, not `weak_release()`; several `src/ **` call sites had this backwards and were corrected in
   *   the same audit (see BoostWrappers.cpp and CWldSession.cpp). What it does: Releases one weak owner from the
   *   control block and clears the borrowed raw-ptr lanes.
   * - release (BoostWrappers.h): Address: 0x004229B0 (FUN_004229B0, boost::detail::sp_counted_base::release) Address:
   *   0x00422B80 (FUN_00422B80, Moho::WeakPtr_CD3DDynamicTextureSheet::Release) Address: 0x004260B0 (FUN_004260B0,
   *   Moho::WeakPtr_CD3DBatchTexture::Release) Address: 0x005383B0 (FUN_005383B0) Address: 0x004D7A20 (FUN_004D7A20,
   *   Moho::WeakPtr_AudioEngine::Release) Address: 0x00442BD0 (FUN_00442BD0) Address: 0x00442C40 (FUN_00442C40)
   *   Address: 0x00442C90 (FUN_00442C90, boost::shared_ptr_TextureD3D9::reset) Address: 0x00442F20 (FUN_00442F20)
   *   Address: 0x00442FA0 (FUN_00442FA0) Address: 0x007D1CD0 (FUN_007D1CD0,
   *   boost::shared_ptr_CD3DBatchTexture::~shared_ptr_CD3DBatchTexture) Address: 0x00873780 (FUN_00873780,
   *   boost::shared_ptr_UICommandGraph::~shared_ptr_UICommandGraph) Address: 0x00824060 (FUN_00824060,
   *   Moho::WeakPtr_UICommandGraph::Release) Address: 0x0053ACA0 (FUN_0053ACA0) Address: 0x005BE250 (FUN_005BE250,
   *   Moho::WeakPtr_CIntelGrid::release) Address: 0x0055FC60 (FUN_0055FC60, boost::shared_ptr_RScmResource::release)
   *   Address: 0x005CE460 (FUN_005CE460, boost::shared_ptr_CIntelGrid::release) Address: 0x007D5D90 (FUN_007D5D90,
   *   another ICF-shape twin of this body -- branch-for-branch identical: use_count decrement at +0x04 / dispose via
   *   vtable+0x04, then weak_count decrement at +0x08 / destroy via vtable+0x08. Reached from 19 real call sites in
   *   Mesh.cpp's mesh-instance/spatial-shard teardown paths.) Address: 0x0053A9A0 (FUN_0053A9A0, another ICF-shape
   *   twin, branch-for-branch identical. Reached from 8 real call sites in CAnimationManipulator.cpp's manipulator
   *   teardown paths.) Address: 0x008F9470 (FUN_008F9470, another copy of the same release in the D3D10 backend, no
   *   direct callers (its vertex-binding slots inline it for their by-value `shared_ptr` parameters); formerly
   *   `ReleaseWeakRefToken` over a `WeakRefCountedToken` stand-in for `sp_counted_base` in D3D10Interfaces.cpp (RULE
   *   ONE), removed 2026-09-23.) Address: 0x007B8DE0 (FUN_007B8DE0, another ICF-shape twin, branch-for-branch
   *   identical -- 31 total twins for this body, canonical=FUN_004260B0. Reached from
   *   Moho::CGpgNetInterface::SendNatPacket (0x007B8BC0).) Address: 0x008F38E0 (FUN_008F38E0 --
   *   `~shared_ptr<gpg::gal::EffectD3D9>`, the same body out of line: the lock every
   *   EffectTechniqueD3D9/EffectVariableD3D9 entry point takes on its effect is released through it on return (twelve
   *   direct calls 0x008F3E7A .. 0x00944F58) and on unwind. Formerly described on `LockWeakEffectD3D9` in
   *   gpg/gal/backends/d3d9/D3D9Interfaces.cpp, removed 2026-09-24.) Address: 0x0042C240 (FUN_0042C240 --
   *   `~shared_ptr<gpg::gal::Effect>`: the `GetBaseEffect()` temporary `ShaderVar::Exists` releases at 0x00437FE1,
   *   and EH funclets across the renderers.) Address: 0x0042C280 (FUN_0042C280 --
   *   `~shared_ptr<gpg::gal::EffectVariable>`: the `GetVariable()` temporaries of `ShaderVar::Exists` (0x00437FD0),
   *   `SkyDome::RenderDecals` (0x00819E70 ..) and the mesh renderer (0x007D5263 ..).) Address: 0x0042C4E0
   *   (FUN_0042C4E0 -- `~shared_ptr<gpg::gal::EffectTechnique>`: `CD3DEffect::SetTechnique` (0x0042D3C1, 0x0042D413)
   *   and `EffectD3D10::GetTechniques` (0x0094BE7D) release their temporaries through it.) Address: 0x0042C330
   *   (FUN_0042C330 -- the same body for a gal handle whose element the callers do not pin down yet:
   *   `REN_MaybeDumpFrame` 0x007F5B98, `RWldMapPreviewChunk::Save` 0x00890B67, 0x0043DB57, 0x007D5A73.) Address:
   *   0x0042C370 (FUN_0042C370 -- likewise, called three times from 0x007FEEA0.) These five were listed as an
   *   "Address family" on `ReleaseSharedHandle` in moho/render/d3d/CD3DEffectTechnique.cpp -- prose, not anchors --
   *   removed 2026-09-24 with the `SharedHandle` overlay. What it does: Releases one shared owner from the control
   *   block, disposes the pointee on last use, and clears the borrowed raw-ptr lanes. Address: 0x007FAD40
   *   (FUN_007FAD40 -- `shared_ptr<T>::reset()` (`px = 0; pn.release()`) as emitted for WRenViewport's
   *   device-resource handles (0x007F70F0); callers 0x007F70F0; formerly `ClearSharedOwnershipPairLaneA` in
   *   moho/containers/LegacyContainerRuntime.cpp (RULE ONE), file removed 2026-09-10.) Address: 0x004ABF80
   *   (FUN_004ABF80 -- `shared_ptr<void>::reset()`: `ResourceManager:: LoadRecord` (0x004AA690) dropping
   *   `PrefetchData::mPrefetchData` once it has been loaded from; formerly `ResetSharedPairReleaseControl` in
   *   moho/resource/ResourceManager.cpp (RULE ONE), removed 2026-09-30.) Address: 0x007FADB0 (FUN_007FADB0 --
   *   `shared_ptr<T>::reset()` (`px = 0; pn.release()`), the second handle type of 0x007F70F0; callers 0x007F70F0;
   *   formerly `ClearSharedOwnershipPairLaneB` in moho/containers/LegacyContainerRuntime.cpp (RULE ONE), file removed
   *   2026-09-10.) Address: 0x008E34E0 (FUN_008E34E0 -- `shared_ptr<T>::~shared_ptr()` reached through the owning
   *   object: the control block at owner +0x04 is dropped, `dispose()` runs at use-count zero and `destroy()` at
   *   weak-count zero. Zero callers, unreachable; formerly `ReleaseOwnerSharedCountControlLane` over a a deleted
   *   overlay stand-in in gpg/core/algorithms/Cluster.cpp (RULE ONE), removed 2026-09-18.) Address: 0x0064DFE0
   *   (FUN_0064DFE0 -- another branch-for-branch copy of this release, object in EAX: the
   *   `shared_ptr<moho::CIntelGrid>` handle inside RDebugRadar's `ReconCoverageDecalPass` stack block, dropped after
   *   every coverage pass by `TraverseRadarCellsRecursive` (eight calls 0x0064DBBA .. 0x0064DEF0) and by its unwind
   *   funclets 0x00B9F81B .. 0x00B9F88B; the accessor's own temporary goes through 0x005BE250 right after; formerly
   *   `ReleaseSharedCounterOwnerRuntime` in moho/sim/SimRecoveryRuntime.cpp (RULE ONE), removed 2026-09-30.)
   * - assign_retain (BoostWrappers.h): Address: 0x00422A70 (FUN_00422A70, boost::detail::shared_count::operator=)
   *   Address: 0x00424EF0 (FUN_00424EF0) Address: 0x004260F0 (FUN_004260F0, boost::shared_ptr_CD3DBatchTexture copy
   *   lane) Address: 0x0042D500 (FUN_0042D500 -- `shared_ptr<gpg::gal::EffectTechnique>::operator=`: `px` first, then
   *   retain the incoming count and release the old one through 0x004229B0. `CD3DEffect::SetTechnique`'s
   *   `mCurrentTechnique = ...` (0x0042D3AD, 0x0042D3FF); formerly `AssignTechniqueHandle` in
   *   moho/render/d3d/CD3DEffectTechnique.cpp (RULE ONE), removed 2026-09-24.) What it does: Rebinds this borrowed
   *   shared-ptr view to another control block while preserving the old reference-count semantics.
   * - ConstructSharedFromRaw (BoostWrappers.h): Address: 0x00445550 (FUN_00445550) Address: 0x00445570 (FUN_00445570)
   *   Address: 0x004455E0 (FUN_004455E0) Address: 0x00445600 (FUN_00445600) Address: 0x00445840 (FUN_00445840)
   *   Address: 0x00446200 (FUN_00446200) The gal target emissions of the same constructor - `shared_ptr<Base>(Y*)`
   *   for each backend target type Y: `px` published first, then one call to the `shared_count(Y*)` emission cited on
   *   `ConstructSharedCountFromRaw`. Each was a per-type `ConstructShared<Y>FromRaw` free function (RULE ONE),
   *   removed 2026-09-23; the backends now write `boost::shared_ptr<RenderTarget>(new RenderTargetD3D9(...))`.
   *   Address: 0x008E9D20 (FUN_008E9D20, shared_ptr<RenderTarget>(RenderTargetD3D9*), formerly in D3D9Interfaces.cpp)
   *   Address: 0x008E9D50 (FUN_008E9D50, shared_ptr<CubeRenderTarget>(CubeRenderTargetD3D9*), formerly in
   *   D3D9Interfaces.cpp) Address: 0x008E9D80 (FUN_008E9D80, shared_ptr<DepthStencilTarget>(DepthStencilTargetD3D9*),
   *   formerly in D3D9Interfaces.cpp) Address: 0x008FA430 (FUN_008FA430,
   *   shared_ptr<RenderTarget>(RenderTargetD3D10*), formerly in D3D10Interfaces.cpp) Address: 0x008FA460
   *   (FUN_008FA460, shared_ptr<CubeRenderTarget>(CubeRenderTargetD3D10*), formerly in D3D10Interfaces.cpp) Address:
   *   0x008FA490 (FUN_008FA490, shared_ptr<DepthStencilTarget>(DepthStencilTargetD3D10*), formerly in
   *   D3D10Interfaces.cpp) Address: 0x008E9CF0 (FUN_008E9CF0, shared_ptr<Texture>(TextureD3D9*) -
   *   `DeviceD3D9::CreateTexture` calls it at 0x008EB5CB; formerly in D3D9Interfaces.cpp) Address: 0x008FA400
   *   (FUN_008FA400, shared_ptr<Texture>(TextureD3D10*), formerly in D3D10Interfaces.cpp) The same constructor for
   *   the buffer, vertex-format and pipeline-state types (`boost::shared_ptr<VertexFormat>(new
   *   VertexFormatD3D9(...))` in the device create slots, `mPipelineState.reset(new PipelineStateD3D9(...))` through
   *   `reset`). Each was a per-type `ConstructShared<Y>FromRaw` free function (RULE ONE), removed 2026-09-23.
   *   Address: 0x008E9DB0 (FUN_008E9DB0, shared_ptr<VertexFormat>(VertexFormatD3D9*), formerly in D3D9Interfaces.cpp)
   *   Address: 0x008E9DE0 (FUN_008E9DE0, shared_ptr<VertexBuffer>(VertexBufferD3D9*), formerly in D3D9Interfaces.cpp)
   *   Address: 0x008E9E10 (FUN_008E9E10, shared_ptr<IndexBuffer>(IndexBufferD3D9*), formerly in D3D9Interfaces.cpp)
   *   Address: 0x008EA060 (FUN_008EA060, shared_ptr<PipelineStateD3D9>(PipelineStateD3D9*), formerly in
   *   D3D9Interfaces.cpp) Address: 0x008FA4C0 (FUN_008FA4C0, shared_ptr<VertexFormat>(VertexFormatD3D10*), formerly
   *   in D3D10Interfaces.cpp) Address: 0x008FA4F0 (FUN_008FA4F0, shared_ptr<VertexBuffer>(VertexBufferD3D10*),
   *   formerly in D3D10Interfaces.cpp) Address: 0x008FA520 (FUN_008FA520, shared_ptr<IndexBuffer>(IndexBufferD3D10*),
   *   formerly in D3D10Interfaces.cpp) Address: 0x008FA5F0 (FUN_008FA5F0,
   *   shared_ptr<PipelineStateD3D10>(PipelineStateD3D10*), formerly in D3D10Interfaces.cpp) The effect family: the
   *   backends write `boost::shared_ptr<Effect>(new EffectD3D9(...))` and the like, and the technique and variable
   *   lookups inline the outer constructor around the `shared_count(Y*)` emission, so only the effect's own copy is
   *   ever called. Each was a per-type `ConstructSharedEffect*FromRaw` free function (RULE ONE), removed 2026-09-24.
   *   Address: 0x008E9F20 (FUN_008E9F20, shared_ptr<Effect>(EffectD3D9*) -- the one with a real
   *   `sp_enable_shared_from_this` step: `EffectD3D9` derives from `enable_shared_from_this`, so after `pn` it
   *   assigns the weak-this at p+4. `DeviceD3D9`'s builders call it (0x008F0F34, 0x008F12A1); the old helper did that
   *   assignment by hand into a `selfWeak_` member the class never had.) Address: 0x008FA3D0 (FUN_008FA3D0,
   *   shared_ptr<Effect>(EffectD3D10*); zero callers, `DeviceD3D10::CreateEffect` inlines it) Address: 0x00941A60
   *   (FUN_00941A60, shared_ptr<EffectTechnique>(EffectTechniqueD3D9*); zero callers) Address: 0x00941A90
   *   (FUN_00941A90, shared_ptr<EffectVariable>(EffectVariableD3D9*); zero callers) Address: 0x0094B840
   *   (FUN_0094B840, shared_ptr<EffectTechnique>(EffectTechniqueD3D10*); zero callers) Address: 0x0094B870
   *   (FUN_0094B870, shared_ptr<EffectVariable>(EffectVariableD3D10*); zero callers) What it does: Constructs one
   *   `boost::shared_ptr<T>` from a raw pointee in caller-provided storage.
   * - ResetSharedPtrRawOwning (BoostWrappers.h): `ResetSharedFromRaw` for a raw `(px,pi)` lane: adopts `rawPointer`
   *   into `target` behind a freshly created control block and releases whatever the lane owned before.
   *   `SharedPtrRaw` otherwise only knows how to retain a control block that already exists (`assign_retain`,
   *   `clone_retained`), so this is the single place that mints one for a lane member. Reference-count contract,
   *   identical to `boost::shared_ptr<T>::reset(T*)` (whose `CAniPose` emission is at 0x0063CA40): - the new control
   *   block is built first, so a throw while allocating it deletes `rawPointer` and leaves `target` untouched; - its
   *   single strong reference is *moved* into `target` rather than re-acquired, keeping `use_count_ == 1`; - the
   *   previous control block is released last, which is what makes it safe to reset a lane from a value derived from
   *   its current referent.
   * - ConstructSharedCountFromRaw (BoostWrappers.h): Address: 0x00446030 (FUN_00446030) Address: 0x004460C0
   *   (FUN_004460C0) Address: 0x00446170 (FUN_00446170) Address: 0x007FBE40 (FUN_007FBE40 -- the
   *   `sp_counted_impl_p<moho::IRenTerrain>::sp_counted_impl_p(IRenTerrain*)` this emits: `[this+4]=1`, `[this+8]=1`,
   *   `[this]=0x00E407E4` (the real vtable), `[this+0xC]=px`, `ret 4`; zero callers; formerly
   *   `InitializeSpCountedImplPIRenTerrainLaneA` in gpg/core/utils/BoostWrappers.cpp (RULE ONE), removed 2026-09-18.)
   *   Address: 0x007FC150 (FUN_007FC150 -- the same constructor emitted for
   *   `sp_counted_impl_p<moho::CD3DTextureBatcher>`, vtable 0x00E407F8; zero callers; formerly
   *   `InitializeSpCountedImplPCD3DTextureBatcherLaneA` in gpg/core/utils/BoostWrappers.cpp (RULE ONE), removed
   *   2026-09-18.) Address: 0x007FBEA0 (FUN_007FBEA0 -- `mov dword ptr [eax], 0x00D42210; ret`: the base
   *   `sp_counted_base` vtable install MSVC emits inside the constructor/destructor chain. No source line produces
   *   it, so nothing calls it here; formerly `RebindSpCountedBaseVtableLaneA` in gpg/core/utils/BoostWrappers.cpp
   *   (RULE ONE), removed 2026-09-18.) Address: 0x004DE730 (FUN_004DE730 --
   *   `sp_counted_impl_p<T>::sp_counted_impl_p(T*)`: counts to 1, real vtable 0xe0b724, `px_` at +0x0C, `ret 4`; zero
   *   callers in the binary and none in source; formerly `SpCountedImplPConstructAudioEngine` in
   *   gpg/core/utils/BoostWrappers.cpp (RULE ONE), removed 2026-09-18.) Address: 0x004DE790 (FUN_004DE790 --
   *   `sp_counted_base`'s scalar deleting destructor: install the base vtable None, then `operator delete` when the
   *   flag is set; zero callers in the binary and none in source; formerly `SpCountedBaseDeletingDtorAudioEngine` in
   *   gpg/core/utils/BoostWrappers.cpp (RULE ONE), removed 2026-09-18.) Address: 0x004DE7B0 (FUN_004DE7B0 -- the
   *   `sp_counted_base` base-subobject vtable install (`mov [reg], 0xd42210; ret`, 2 instructions) MSVC emits inside
   *   the constructor/destructor chain for this instantiation; zero callers in the binary and none in source;
   *   formerly `InitializeSpCountedBaseLaneForAudioEngine` in gpg/core/utils/BoostWrappers.cpp (RULE ONE), removed
   *   2026-09-18.) Address: 0x0053A290 (FUN_0053A290 -- the `sp_counted_base` base-subobject vtable install (`mov
   *   [reg], 0xd42210; ret`, 2 instructions) MSVC emits inside the constructor/destructor chain for this
   *   instantiation; zero callers in the binary and none in source; formerly
   *   `InitializeSpCountedBaseLaneForRScmResource` in gpg/core/utils/BoostWrappers.cpp (RULE ONE), removed
   *   2026-09-18.) Address: 0x0053B420 (FUN_0053B420 -- the `sp_counted_base` base-subobject vtable install (`mov
   *   [reg], 0xd42210; ret`, 2 instructions) MSVC emits inside the constructor/destructor chain for this
   *   instantiation; zero callers in the binary and none in source; formerly
   *   `InitializeSpCountedBaseLaneForRScaResource` in gpg/core/utils/BoostWrappers.cpp (RULE ONE), removed
   *   2026-09-18.) Address: 0x0054EE20 (FUN_0054EE20 -- the `sp_counted_base` base-subobject vtable install (`mov
   *   [reg], 0xd42210; ret`, 2 instructions) MSVC emits inside the constructor/destructor chain for this
   *   instantiation; zero callers in the binary and none in source; formerly
   *   `InitializeSpCountedBaseLaneForAniDefaultSkelDeleter` in gpg/core/utils/BoostWrappers.cpp (RULE ONE), removed
   *   2026-09-18.) Address: 0x005CC7C0 (FUN_005CC7C0 -- `sp_counted_impl_p<T>::sp_counted_impl_p(T*)`: counts to 1,
   *   real vtable 0xe1dbe0, `px_` at +0x0C, `ret 4`; zero callers in the binary and none in source; formerly
   *   `SpCountedImplPConstructStatsStatItem` in gpg/core/utils/BoostWrappers.cpp (RULE ONE), removed 2026-09-18.)
   *   Address: 0x005CC850 (FUN_005CC850 -- the `sp_counted_base` base-subobject vtable install (`mov [reg], 0xd42210;
   *   ret`, 2 instructions) MSVC emits inside the constructor/destructor chain for this instantiation; zero callers
   *   in the binary and none in source; formerly `InitializeSpCountedBaseLaneForStatsStatItem` in
   *   gpg/core/utils/BoostWrappers.cpp (RULE ONE), removed 2026-09-18.) Address: 0x00755FA0 (FUN_00755FA0 --
   *   `sp_counted_impl_p<T>::sp_counted_impl_p(T*)`: counts to 1, real vtable 0xe348ec, `px_` at +0x0C, `ret 4`; zero
   *   callers in the binary and none in source; formerly `SpCountedImplPConstructISimResources` in
   *   gpg/core/utils/BoostWrappers.cpp (RULE ONE), removed 2026-09-18.) Address: 0x007560E0 (FUN_007560E0 -- the
   *   `sp_counted_base` base-subobject vtable install (`mov [reg], 0xd42210; ret`, 2 instructions) MSVC emits inside
   *   the constructor/destructor chain for this instantiation; zero callers in the binary and none in source;
   *   formerly `InitializeSpCountedBaseLaneForISimResources` in gpg/core/utils/BoostWrappers.cpp (RULE ONE), removed
   *   2026-09-18.) Address: 0x00765700 (FUN_00765700 -- `sp_counted_impl_p<T>::sp_counted_impl_p(T*)`: counts to 1,
   *   real vtable 0xe35d90, `px_` at +0x0C, `ret 4`; zero callers in the binary and none in source; formerly
   *   `SpCountedImplPConstructPathPreviewFinder` in gpg/core/utils/BoostWrappers.cpp (RULE ONE), removed 2026-09-18.)
   *   Address: 0x00765790 (FUN_00765790 -- the `sp_counted_base` base-subobject vtable install (`mov [reg], 0xd42210;
   *   ret`, 2 instructions) MSVC emits inside the constructor/destructor chain for this instantiation; zero callers
   *   in the binary and none in source; formerly `InitializeSpCountedBaseLaneForPathPreviewFinder` in
   *   gpg/core/utils/BoostWrappers.cpp (RULE ONE), removed 2026-09-18.) Address: 0x007FC1A0 (FUN_007FC1A0 --
   *   `sp_counted_impl_p<T>::sp_counted_impl_p(T*)`: counts to 1, real vtable 0xe4080c, `px_` at +0x0C, `ret 4`; zero
   *   callers in the binary and none in source; formerly `SpCountedImplPConstructCD3DPrimBatcher` in
   *   gpg/core/utils/BoostWrappers.cpp (RULE ONE), removed 2026-09-18.) Address: 0x007FC230 (FUN_007FC230 -- the
   *   `sp_counted_base` base-subobject vtable install (`mov [reg], 0xd42210; ret`, 2 instructions) MSVC emits inside
   *   the constructor/destructor chain for this instantiation; zero callers in the binary and none in source;
   *   formerly `InitializeSpCountedBaseLaneForCD3DTextureBatcher` in gpg/core/utils/BoostWrappers.cpp (RULE ONE),
   *   removed 2026-09-18.) Address: 0x007FC240 (FUN_007FC240 -- the `sp_counted_base` base-subobject vtable install
   *   (`mov [reg], 0xd42210; ret`, 2 instructions) MSVC emits inside the constructor/destructor chain for this
   *   instantiation; zero callers in the binary and none in source; formerly
   *   `InitializeSpCountedBaseLaneForCD3DPrimBatcher` in gpg/core/utils/BoostWrappers.cpp (RULE ONE), removed
   *   2026-09-18.) Address: 0x008847F0 (FUN_008847F0 -- `sp_counted_impl_pd<T,D>::sp_counted_impl_pd(T*, D)`: counts
   *   to 1, real vtable 0xe49da0, `px_` at +0x0C, deleter at +0x10, `ret 8`; zero callers in the binary and none in
   *   source; formerly `SpCountedImplPdConstructSFileStarCloser` in gpg/core/utils/BoostWrappers.cpp (RULE ONE),
   *   removed 2026-09-18.) Address: 0x00884890 (FUN_00884890 -- the `sp_counted_base` base-subobject vtable install
   *   (`mov [reg], 0xd42210; ret`, 2 instructions) MSVC emits inside the constructor/destructor chain for this
   *   instantiation; zero callers in the binary and none in source; formerly
   *   `InitializeSpCountedBaseLaneForFileStarCloser` in gpg/core/utils/BoostWrappers.cpp (RULE ONE), removed
   *   2026-09-18.) Address: 0x0089B840 (FUN_0089B840 -- `sp_counted_impl_p<T>::sp_counted_impl_p(T*)`: counts to 1,
   *   real vtable 0xe4b35c, `px_` at +0x0C, `ret 4`; zero callers in the binary and none in source; formerly
   *   `SpCountedImplPConstructSSessionSaveData` in gpg/core/utils/BoostWrappers.cpp (RULE ONE), removed 2026-09-18.)
   *   Address: 0x0089B930 (FUN_0089B930 -- the `sp_counted_base` base-subobject vtable install (`mov [reg], 0xd42210;
   *   ret`, 2 instructions) MSVC emits inside the constructor/destructor chain for this instantiation; zero callers
   *   in the binary and none in source; formerly `InitializeSpCountedBaseLaneForSSessionSaveData` in
   *   gpg/core/utils/BoostWrappers.cpp (RULE ONE), removed 2026-09-18.) Address: 0x0089BC70 (FUN_0089BC70 --
   *   `sp_counted_impl_p<T>::sp_counted_impl_p(T*)`: counts to 1, real vtable 0xe4b370, `px_` at +0x0C, `ret 4`; zero
   *   callers in the binary and none in source; formerly `SpCountedImplPConstructUICommandGraph` in
   *   gpg/core/utils/BoostWrappers.cpp (RULE ONE), removed 2026-09-18.) Address: 0x0089BCE0 (FUN_0089BCE0 -- the
   *   `sp_counted_base` base-subobject vtable install (`mov [reg], 0xd42210; ret`, 2 instructions) MSVC emits inside
   *   the constructor/destructor chain for this instantiation; zero callers in the binary and none in source;
   *   formerly `InitializeSpCountedBaseLaneForUICommandGraph` in gpg/core/utils/BoostWrappers.cpp (RULE ONE), removed
   *   2026-09-18.) Address: 0x0089BCC0 (FUN_0089BCC0 -- `sp_counted_impl_p<Moho::UICommandGraph>`'s scalar deleting
   *   destructor, slot 0 of its vtable 0x00E4B370; formerly `SpCountedImplPDeletingDtorUICommandGraph` in
   *   gpg/core/utils/BoostWrappers.cpp, which nothing called, removed 2026-09-25.) Address: 0x008E8B10 (FUN_008E8B10
   *   -- the `sp_counted_base` base-subobject vtable install (`mov [reg], 0xd42210; ret`, 2 instructions) MSVC emits
   *   inside the constructor/destructor chain for this instantiation; zero callers in the binary and none in source;
   *   formerly `InitializeSpCountedBaseLaneForTextureD3D9` in gpg/core/utils/BoostWrappers.cpp (RULE ONE), removed
   *   2026-09-18.) Address: 0x008F9140 (FUN_008F9140 -- the `sp_counted_base` base-subobject vtable install (`mov
   *   [reg], 0xd42210; ret`, 2 instructions) MSVC emits inside the constructor/destructor chain for this
   *   instantiation; zero callers in the binary and none in source; formerly
   *   `InitializeSpCountedBaseLaneForEffectD3D10` in gpg/core/utils/BoostWrappers.cpp (RULE ONE), removed
   *   2026-09-18.) Address: 0x008F9150 (FUN_008F9150 -- the `sp_counted_base` base-subobject vtable install (`mov
   *   [reg], 0xd42210; ret`, 2 instructions) MSVC emits inside the constructor/destructor chain for this
   *   instantiation; zero callers in the binary and none in source; formerly
   *   `InitializeSpCountedBaseLaneForTextureD3D10` in gpg/core/utils/BoostWrappers.cpp (RULE ONE), removed
   *   2026-09-18.) Address: 0x008F9160 (FUN_008F9160 -- the `sp_counted_base` base-subobject vtable install (`mov
   *   [reg], 0xd42210; ret`, 2 instructions) MSVC emits inside the constructor/destructor chain for this
   *   instantiation; zero callers in the binary and none in source; formerly
   *   `InitializeSpCountedBaseLaneForRenderTargetD3D10` in gpg/core/utils/BoostWrappers.cpp (RULE ONE), removed
   *   2026-09-18.) Address: 0x008F9170 (FUN_008F9170 -- the `sp_counted_base` base-subobject vtable install (`mov
   *   [reg], 0xd42210; ret`, 2 instructions) MSVC emits inside the constructor/destructor chain for this
   *   instantiation; zero callers in the binary and none in source; formerly
   *   `InitializeSpCountedBaseLaneForCubeRenderTargetD3D10` in gpg/core/utils/BoostWrappers.cpp (RULE ONE), removed
   *   2026-09-18.) Address: 0x008F9180 (FUN_008F9180 -- the `sp_counted_base` base-subobject vtable install (`mov
   *   [reg], 0xd42210; ret`, 2 instructions) MSVC emits inside the constructor/destructor chain for this
   *   instantiation; zero callers in the binary and none in source; formerly
   *   `InitializeSpCountedBaseLaneForDepthStencilTargetD3D10` in gpg/core/utils/BoostWrappers.cpp (RULE ONE), removed
   *   2026-09-18.) Address: 0x008F9190 (FUN_008F9190 -- the `sp_counted_base` base-subobject vtable install (`mov
   *   [reg], 0xd42210; ret`, 2 instructions) MSVC emits inside the constructor/destructor chain for this
   *   instantiation; zero callers in the binary and none in source; formerly
   *   `InitializeSpCountedBaseLaneForVertexFormatD3D10` in gpg/core/utils/BoostWrappers.cpp (RULE ONE), removed
   *   2026-09-18.) Address: 0x008F91A0 (FUN_008F91A0 -- the `sp_counted_base` base-subobject vtable install (`mov
   *   [reg], 0xd42210; ret`, 2 instructions) MSVC emits inside the constructor/destructor chain for this
   *   instantiation; zero callers in the binary and none in source; formerly
   *   `InitializeSpCountedBaseLaneForVertexBufferD3D10` in gpg/core/utils/BoostWrappers.cpp (RULE ONE), removed
   *   2026-09-18.) Address: 0x008F91B0 (FUN_008F91B0 -- the `sp_counted_base` base-subobject vtable install (`mov
   *   [reg], 0xd42210; ret`, 2 instructions) MSVC emits inside the constructor/destructor chain for this
   *   instantiation; zero callers in the binary and none in source; formerly
   *   `InitializeSpCountedBaseLaneForIndexBufferD3D10` in gpg/core/utils/BoostWrappers.cpp (RULE ONE), removed
   *   2026-09-18.) Address: 0x008F93B0 (FUN_008F93B0 -- the `sp_counted_base` base-subobject vtable install (`mov
   *   [reg], 0xd42210; ret`, 2 instructions) MSVC emits inside the constructor/destructor chain for this
   *   instantiation; zero callers in the binary and none in source; formerly
   *   `InitializeSpCountedBaseLaneForPipelineStateD3D10` in gpg/core/utils/BoostWrappers.cpp (RULE ONE), removed
   *   2026-09-18.) Address: 0x00923700 (FUN_00923700 -- `sp_counted_impl_p<T>::sp_counted_impl_p(T*)`: counts to 1,
   *   real vtable 0xd47090, `px_` at +0x0C, `ret 4`; zero callers in the binary and none in source; formerly
   *   `SpCountedImplPConstructStdStringstreamChar` in gpg/core/utils/BoostWrappers.cpp (RULE ONE), removed
   *   2026-09-18.) Address: 0x00923730 (FUN_00923730 -- the `sp_counted_base` base-subobject vtable install (`mov
   *   [reg], 0xd42210; ret`, 2 instructions) MSVC emits inside the constructor/destructor chain for this
   *   instantiation; zero callers in the binary and none in source; formerly
   *   `InitializeSpCountedBaseLaneForStdStringstreamChar` in gpg/core/utils/BoostWrappers.cpp (RULE ONE), removed
   *   2026-09-18.) Address: 0x00931EE0 (FUN_00931EE0 -- the `sp_counted_base` base-subobject vtable install (`mov
   *   [reg], 0xd42210; ret`, 2 instructions) MSVC emits inside the constructor/destructor chain for this
   *   instantiation; zero callers in the binary and none in source; formerly
   *   `InitializeSpCountedBaseLaneForClusterCacheImpl` in gpg/core/utils/BoostWrappers.cpp (RULE ONE), removed
   *   2026-09-18.) Address: 0x00941660 (FUN_00941660 -- `sp_counted_impl_p<T>::sp_counted_impl_p(T*)`: counts to 1,
   *   real vtable 0xd47d44, `px_` at +0x0C, `ret 4`; zero callers in the binary and none in source; formerly
   *   `SpCountedImplPConstructEffectTechniqueD3D9` in gpg/core/utils/BoostWrappers.cpp (RULE ONE), removed
   *   2026-09-18.) Address: 0x00941690 (FUN_00941690 -- `sp_counted_impl_p<T>::sp_counted_impl_p(T*)`: counts to 1,
   *   real vtable 0xd47d58, `px_` at +0x0C, `ret 4`; zero callers in the binary and none in source; formerly
   *   `SpCountedImplPConstructEffectVariableD3D9` in gpg/core/utils/BoostWrappers.cpp (RULE ONE), removed
   *   2026-09-18.) Address: 0x009416C0 (FUN_009416C0 -- the `sp_counted_base` base-subobject vtable install (`mov
   *   [reg], 0xd42210; ret`, 2 instructions) MSVC emits inside the constructor/destructor chain for this
   *   instantiation; zero callers in the binary and none in source; formerly
   *   `InitializeSpCountedBaseLaneForEffectTechniqueD3D9` in gpg/core/utils/BoostWrappers.cpp (RULE ONE), removed
   *   2026-09-18.) Address: 0x009416D0 (FUN_009416D0 -- the `sp_counted_base` base-subobject vtable install (`mov
   *   [reg], 0xd42210; ret`, 2 instructions) MSVC emits inside the constructor/destructor chain for this
   *   instantiation; zero callers in the binary and none in source; formerly
   *   `InitializeSpCountedBaseLaneForEffectVariableD3D9` in gpg/core/utils/BoostWrappers.cpp (RULE ONE), removed
   *   2026-09-18.) Address: 0x0094B600 (FUN_0094B600 -- `sp_counted_impl_p<T>::sp_counted_impl_p(T*)`: counts to 1,
   *   real vtable 0xd4887c, `px_` at +0x0C, `ret 4`; zero callers in the binary and none in source; formerly
   *   `SpCountedImplPConstructEffectTechniqueD3D10` in gpg/core/utils/BoostWrappers.cpp (RULE ONE), removed
   *   2026-09-18.) Address: 0x0094B630 (FUN_0094B630 -- `sp_counted_impl_p<T>::sp_counted_impl_p(T*)`: counts to 1,
   *   real vtable 0xd48890, `px_` at +0x0C, `ret 4`; zero callers in the binary and none in source; formerly
   *   `SpCountedImplPConstructEffectVariableD3D10` in gpg/core/utils/BoostWrappers.cpp (RULE ONE), removed
   *   2026-09-18.) Address: 0x0094B660 (FUN_0094B660 -- the `sp_counted_base` base-subobject vtable install (`mov
   *   [reg], 0xd42210; ret`, 2 instructions) MSVC emits inside the constructor/destructor chain for this
   *   instantiation; zero callers in the binary and none in source; formerly
   *   `InitializeSpCountedBaseLaneForEffectTechniqueD3D10` in gpg/core/utils/BoostWrappers.cpp (RULE ONE), removed
   *   2026-09-18.) Address: 0x0094B670 (FUN_0094B670 -- the `sp_counted_base` base-subobject vtable install (`mov
   *   [reg], 0xd42210; ret`, 2 instructions) MSVC emits inside the constructor/destructor chain for this
   *   instantiation; zero callers in the binary and none in source; formerly
   *   `InitializeSpCountedBaseLaneForEffectVariableD3D10` in gpg/core/utils/BoostWrappers.cpp (RULE ONE), removed
   *   2026-09-18.) Address: 0x0094E070 (FUN_0094E070 -- `sp_counted_impl_pd<T,D>::sp_counted_impl_pd(T*, D)`: counts
   *   to 1, real vtable 0xd48a00, `px_` at +0x0C, deleter at +0x10, `ret 8`; zero callers in the binary and none in
   *   source; formerly `SpCountedImplPdConstructCharPointerFunctionDeleter` in gpg/core/utils/BoostWrappers.cpp (RULE
   *   ONE), removed 2026-09-18.) Address: 0x0094E0E0 (FUN_0094E0E0 -- the `sp_counted_base` base-subobject vtable
   *   install (`mov [reg], 0xd42210; ret`, 2 instructions) MSVC emits inside the constructor/destructor chain for
   *   this instantiation; zero callers in the binary and none in source; formerly
   *   `InitializeSpCountedBaseLaneForCharPointerFunctionDeleter` in gpg/core/utils/BoostWrappers.cpp (RULE ONE),
   *   removed 2026-09-18.) The `sp_counted_impl_p<Y>` virtuals below are reached only through the vtable that
   *   constructor installs: slot 1 is `dispose()` (`delete px_` through the pointee's virtual deleting destructor,
   *   `push 1; call [vtbl+N]`, skipped for null), slot 3 is `get_deleter()` (`xor eax,eax; ret 4`). Each was formerly
   *   a `Legacy*Runtime*Slot*` transcription in moho/misc/WinApiImportThunks.cpp (RULE ONE), removed 2026-09-22.
   *   Address: 0x00797060 (FUN_00797060, sp_counted_impl_p<Moho::CMauiFrame>::dispose, vtable 0x00E39A8C slot 1)
   *   Address: 0x008F9F50 (FUN_008F9F50, sp_counted_impl_p<gpg::gal::TextureD3D10>::dispose, vtable 0x00D430D8 slot
   *   1) Address: 0x008F9F70 (FUN_008F9F70, sp_counted_impl_p<gpg::gal::CubeRenderTargetD3D10>::dispose, vtable
   *   0x00D43100 slot 1) Address: 0x008F9F80 (FUN_008F9F80,
   *   sp_counted_impl_p<gpg::gal::DepthStencilTargetD3D10>::dispose, vtable 0x00D43114 slot 1) Address: 0x008F9F90
   *   (FUN_008F9F90, sp_counted_impl_p<gpg::gal::VertexFormatD3D10>::dispose, vtable 0x00D43128 slot 1) Address:
   *   0x008F9FA0 (FUN_008F9FA0, sp_counted_impl_p<gpg::gal::VertexBufferD3D10>::dispose, vtable 0x00D4313C slot 1)
   *   Address: 0x0089BC90 (FUN_0089BC90, sp_counted_impl_p<Moho::UICommandGraph>::dispose, vtable 0x00E4B370 slot 1 -
   *   `checked_delete` through 0x0089BCF0; formerly `DisposeCountedUICommandGraphStorage` in CWldSession.cpp, removed
   *   2026-09-25) Address: 0x0089B860 (FUN_0089B860, sp_counted_impl_p<Moho::SSessionSaveData>::dispose, vtable
   *   0x00E4B35C slot 1; formerly `DisposeCountedSessionSaveDataStorage` in CWldSession.cpp, removed 2026-09-25)
   *   Address: 0x005CC800 (FUN_005CC800, sp_counted_impl_p<Moho::Stats<Moho::StatItem>>::get_deleter, vtable
   *   0x00E1DBE0 slot 3) Address: 0x007146B0 (FUN_007146B0, sp_counted_impl_p<Moho::STrigger>::get_deleter, vtable
   *   0x00E312EC slot 3) Address: 0x00797080 (FUN_00797080, sp_counted_impl_p<Moho::CMauiFrame>::get_deleter, vtable
   *   0x00E39A8C slot 3) Address: 0x007E6960 (FUN_007E6960, sp_counted_impl_p<Moho::RMeshBlueprintLOD>::get_deleter,
   *   vtable 0x00E3F4E4 slot 3) Address: 0x008E8A10 (FUN_008E8A10,
   *   sp_counted_impl_p<gpg::gal::CubeRenderTargetD3D9>::get_deleter, vtable 0x00D42318 slot 3) Address: 0x008F9010
   *   (FUN_008F9010, sp_counted_impl_p<gpg::gal::TextureD3D10>::get_deleter, vtable 0x00D430D8 slot 3) Address:
   *   0x008F9070 (FUN_008F9070, sp_counted_impl_p<gpg::gal::CubeRenderTargetD3D10>::get_deleter, vtable 0x00D43100
   *   slot 3) Address: 0x008F90A0 (FUN_008F90A0, sp_counted_impl_p<gpg::gal::DepthStencilTargetD3D10>::get_deleter,
   *   vtable 0x00D43114 slot 3) Address: 0x008F90D0 (FUN_008F90D0,
   *   sp_counted_impl_p<gpg::gal::VertexFormatD3D10>::get_deleter, vtable 0x00D43128 slot 3) Address: 0x008F9100
   *   (FUN_008F9100, sp_counted_impl_p<gpg::gal::VertexBufferD3D10>::get_deleter, vtable 0x00D4313C slot 3) Address:
   *   0x008F9130 (FUN_008F9130, sp_counted_impl_p<gpg::gal::IndexBufferD3D10>::get_deleter, vtable 0x00D43150 slot 3)
   *   Address: 0x0094B620 (FUN_0094B620, sp_counted_impl_p<gpg::gal::EffectTechniqueD3D10>::get_deleter, vtable
   *   0x00D4887C slot 3) Address: 0x0094B650 (FUN_0094B650,
   *   sp_counted_impl_p<gpg::gal::EffectVariableD3D10>::get_deleter, vtable 0x00D48890 slot 3) `shared_count(Y*)` for
   *   the gal target types: `new sp_counted_impl_p<Y>(p)` inside a try whose catch deletes `p` and rethrows. The
   *   create slots call them directly with the outer `shared_ptr` constructor inlined (0x008EB74E, 0x008EB8B3,
   *   0x008EBA15 on D3D9; 0x008FB53C, 0x008FA707, 0x008FB89B on D3D10). Each was a per-type
   *   `ConstructSharedCount<Y>FromRaw` free function (RULE ONE), removed 2026-09-23. Address: 0x008E9330
   *   (FUN_008E9330, shared_count(RenderTargetD3D9*), formerly in D3D9Interfaces.cpp) Address: 0x008E93C0
   *   (FUN_008E93C0, shared_count(CubeRenderTargetD3D9*), formerly in D3D9Interfaces.cpp) Address: 0x008E9450
   *   (FUN_008E9450, shared_count(DepthStencilTargetD3D9*), formerly in D3D9Interfaces.cpp) Address: 0x008F9B90
   *   (FUN_008F9B90, shared_count(RenderTargetD3D10*), formerly in D3D10Interfaces.cpp) Address: 0x008F9C20
   *   (FUN_008F9C20, shared_count(CubeRenderTargetD3D10*), formerly in D3D10Interfaces.cpp) Address: 0x008F9CB0
   *   (FUN_008F9CB0, shared_count(DepthStencilTargetD3D10*), formerly in D3D10Interfaces.cpp) Address: 0x008E92A0
   *   (FUN_008E92A0, shared_count(TextureD3D9*), formerly in D3D9Interfaces.cpp) Address: 0x008F9B00 (FUN_008F9B00,
   *   shared_count(TextureD3D10*) - `DeviceD3D10::CreateTexture` calls it at 0x008FB082; formerly in
   *   D3D10Interfaces.cpp) Address: 0x008E94E0 (FUN_008E94E0, shared_count(VertexFormatD3D9*) -
   *   `DeviceD3D9::CreateVertexFormat` calls it at 0x008EBB7E; formerly in D3D9Interfaces.cpp) Address: 0x008E9570
   *   (FUN_008E9570, shared_count(VertexBufferD3D9*), formerly in D3D9Interfaces.cpp) Address: 0x008E9600
   *   (FUN_008E9600, shared_count(IndexBufferD3D9*), formerly in D3D9Interfaces.cpp) Address: 0x008E99E0
   *   (FUN_008E99E0, shared_count(PipelineStateD3D9*), formerly in D3D9Interfaces.cpp) Address: 0x008F9D40
   *   (FUN_008F9D40, shared_count(VertexFormatD3D10*) - `DeviceD3D10::CreateVertexFormat` calls it; formerly in
   *   D3D10Interfaces.cpp) Address: 0x008F9DD0 (FUN_008F9DD0, shared_count(VertexBufferD3D10*), formerly in
   *   D3D10Interfaces.cpp) Address: 0x008F9E60 (FUN_008F9E60, shared_count(IndexBufferD3D10*), formerly in
   *   D3D10Interfaces.cpp) Address: 0x008FA0E0 (FUN_008FA0E0, shared_count(PipelineStateD3D10*), formerly in
   *   D3D10Interfaces.cpp) Address: 0x008E9690 (FUN_008E9690, shared_count(EffectD3D9*) - from the shared_ptr<Effect>
   *   constructor 0x008E9F20; formerly `ConstructSharedCountEffectD3D9FromRaw` in D3D9Interfaces.cpp) Address:
   *   0x009417B0 (FUN_009417B0, shared_count(EffectTechniqueD3D9*) - `EffectD3D9::GetTechnique` 0x00942122 and
   *   `GetTechniques` 0x00942A69; formerly in D3D9Interfaces.cpp) Address: 0x00941840 (FUN_00941840,
   *   shared_count(EffectVariableD3D9*) - `EffectD3D9::GetVariable` 0x00941F33; formerly in D3D9Interfaces.cpp)
   *   Address: 0x008F9A70 (FUN_008F9A70, shared_count(EffectD3D10*) - `DeviceD3D10::CreateEffect` 0x008FEF8F;
   *   formerly in D3D10Interfaces.cpp) Address: 0x0094B6C0 (FUN_0094B6C0, shared_count(EffectTechniqueD3D10*) -
   *   `EffectD3D10::GetTechnique` 0x0094BC32 and `GetTechniques` 0x0094BE42; formerly in D3D10Interfaces.cpp)
   *   Address: 0x0094B750 (FUN_0094B750, shared_count(EffectVariableD3D10*) - `EffectD3D10::GetVariable` 0x0094BA52;
   *   formerly in D3D10Interfaces.cpp) Address: 0x0089B960 (FUN_0089B960, shared_count(UICommandGraph*) - from
   *   `shared_ptr<UICommandGraph>::reset` 0x0089ADE0) `boost::checked_delete<Y>` as that catch path emits it for the
   *   D3D10 backend types (`if (p) p->~Y()` through the deleting destructor, `push 1; call [vtbl]`). No source line
   *   names them; each was an uncalled `Delete<Y>SharedCountCtorPointeeOnUnwind` in D3D10Interfaces.cpp, removed
   *   2026-09-23. Address: 0x008F9200 (FUN_008F9200, checked_delete<TextureD3D10>) Address: 0x008F9220 (FUN_008F9220,
   *   checked_delete<RenderTargetD3D10>, from 0x008F9B90) Address: 0x008F9240 (FUN_008F9240,
   *   checked_delete<CubeRenderTargetD3D10>) Address: 0x008F9260 (FUN_008F9260,
   *   checked_delete<DepthStencilTargetD3D10>) Address: 0x008F9280 (FUN_008F9280, checked_delete<VertexFormatD3D10>)
   *   Address: 0x008F92A0 (FUN_008F92A0, checked_delete<VertexBufferD3D10>) Address: 0x008F92C0 (FUN_008F92C0,
   *   checked_delete<IndexBufferD3D10>) Address: 0x008F93E0 (FUN_008F93E0, checked_delete<PipelineStateD3D10>)
   *   Address: 0x0094B680 (FUN_0094B680, checked_delete<EffectTechniqueD3D10>) Address: 0x0094B6A0 (FUN_0094B6A0,
   *   checked_delete<EffectVariableD3D10>) Address: 0x0089BCF0 (FUN_0089BCF0, checked_delete<Moho::UICommandGraph> -
   *   `~UICommandGraph` then `operator delete`, the destructor being non-virtual; from dispose 0x0089BC90 and the
   *   catch of 0x0089B960; formerly `DestroyUICommandGraphOwned` in CWldSession.cpp, removed 2026-09-25) What it
   *   does: Constructs one `boost::detail::shared_count` from a raw pointee in caller-provided storage. The two
   *   per-type constructor emissions cited above are what this compiles to for those payloads: `shared_count(Y* p)`
   *   allocates `new sp_counted_impl_p<Y>(p)`, whose constructor sets `use_count_` and `weak_count_` to 1, installs
   *   the real per-`Y` vtable, and stores `px_` at +0x0C. The recovered copies in BoostWrappers.cpp had been writing
   *   the address of a one-byte dummy static in place of that vtable, so the first `dispose()`/`destroy()` dispatch
   *   through such a block would have jumped into unrelated data; they also had no caller at all, in the binary or in
   *   source. Address: 0x007FC250 (FUN_007FC250, checked_delete<Moho::CD3DTextureBatcher> - the non-virtual
   *   `~CD3DTextureBatcher` 0x00448B60 then `operator delete`, pointer in ESI, skipped for null; from the catch of
   *   `shared_count(CD3DTextureBatcher*)` 0x007FBEB0 (0x007FBF21), which `WRenViewport::D3DWindowOnDeviceInit`'s
   *   `mTexBatcher.reset(new CD3DTextureBatcher())` reaches through `shared_ptr::reset` 0x007FB6C0; formerly
   *   `DestroyTextureBatcherObjectRuntime` in moho/sim/SimRecoveryRuntime.cpp (RULE ONE), removed 2026-09-30.)
   *   Address: 0x007FC270 (FUN_007FC270, checked_delete<Moho::CD3DPrimBatcher> - the non-virtual `~CD3DPrimBatcher`
   *   0x00438460 then `operator delete`, pointer in ESI, skipped for null; from the catch of
   *   `shared_count(CD3DPrimBatcher*)` 0x007FBF30 (0x007FBFA1), reached from `D3DWindowOnDeviceInit`'s
   *   `mPrimBatcher.reset(new CD3DPrimBatcher(...))` through `shared_ptr::reset` 0x007FB730; formerly
   *   `DestroyPrimBatcherObjectRuntime` in moho/sim/SimRecoveryRuntime.cpp (RULE ONE), removed 2026-09-30.) Address:
   *   0x00755FC0 (FUN_00755FC0, sp_counted_impl_p<Moho::ISimResources>::dispose, vtable 0x00E348EC slot 1 - `delete
   *   px_` (+0x0C) through ISimResources' virtual deleting destructor, `push 1; call [vtbl]`, skipped for null; the
   *   vtable is installed by `shared_count(ISimResources*)` 0x00754BD0; formerly `ReleaseOptionalOwnedObjectRuntime`
   *   in moho/sim/SimRecoveryRuntime.cpp (RULE ONE), removed 2026-09-30.) Address: 0x007E6AD0 (FUN_007E6AD0,
   *   checked_delete<Moho::RMeshBlueprintLOD> - the non-virtual `~RMeshBlueprintLOD` 0x00519800 then `operator
   *   delete`, pointer in EAX, skipped for null; from the catch of `shared_count(RMeshBlueprintLOD*)` 0x007E6650
   *   (0x007E66C1); formerly `RunCleanupThenDeleteObjectRuntime` in moho/sim/SimRecoveryRuntime.cpp (RULE ONE),
   *   removed 2026-09-30.) Address: 0x007E6650 (FUN_007E6650, shared_count(RMeshBlueprintLOD*) - `pi_ = new
   *   sp_counted_impl_p<RMeshBlueprintLOD>(p)` (vtable 0x00E3F4E4) in a try whose catch runs checked_delete
   *   0x007E6AD0 and rethrows, `this` in ECX, `ret 4`; from `shared_ptr<RMeshBlueprintLOD>::reset` 0x007E5170
   *   (0x007E517F); formerly `ConstructSharedMeshBlueprintLODFromRaw` in moho/mesh/Mesh.h/.cpp, labelled as the
   *   shared_ptr constructor (RULE ONE), removed 2026-09-30.) Address: 0x004AF790 (FUN_004AF790,
   *   shared_count(Moho::PrefetchData*) - `pi_ = new sp_counted_impl_p<PrefetchData>(p)` (vtable 0x00E07668) in a try
   *   whose catch runs checked_delete 0x004AFAE0; `ResourceManager::PrefetchResource` (0x004AAD70); formerly
   *   `ConstructPrefetchSharedCountFromRaw_004AF790` in moho/resource/ResourceManager.cpp (RULE ONE), removed
   *   2026-09-30.) Address: 0x004AFAE0 (FUN_004AFAE0, checked_delete<Moho::PrefetchData> - `~PrefetchData` 0x004A9920
   *   then `operator delete`, skipped for null; formerly `DestroyPrefetchDataPayloadIfPresent_004AFAE0`.) Address:
   *   0x004AEFD0 (FUN_004AEFD0, shared_ptr<Moho::PrefetchData>(PrefetchData*) - `px`, then 0x004AF790; unreferenced,
   *   `PrefetchResource` inlines it; formerly `ConstructSharedPrefetchDataFromRaw_004AEFD0`.) Address: 0x004AFA60
   *   (FUN_004AFA60, sp_counted_impl_p<Moho::PrefetchData>(PrefetchData*) - both counts 1, vtable 0x00E07668, `px_`
   *   at +0x0C; unreferenced, 0x004AF790 inlines it; formerly `InitializePrefetchDataCountedImplStorage_004AFA60`.)
   *   Address: 0x004AFA80 (FUN_004AFA80, sp_counted_impl_p<Moho::PrefetchData>::dispose, vtable 0x00E07668 slot 1 -
   *   `delete px_`; formerly `DisposePrefetchDataCountedPayload_004AFA80`.) Address: 0x004AFAA0 (FUN_004AFAA0,
   *   sp_counted_impl_p<Moho::PrefetchData>::get_deleter - null; formerly
   *   `GetPrefetchDataCountedImplDeleterNullResult_004AFAA0`.) Address: 0x004AFAB0 (FUN_004AFAB0, the deleting
   *   destructor of that block (slot 0); formerly `DestructPrefetchCountedBaseDeleting_004AFAB0`.) Address:
   *   0x004AFAD0 (FUN_004AFAD0, its destructor body, restoring the `sp_counted_base` vtable 0x00D42210; formerly
   *   `DestructPrefetchCountedBaseNonDeleting_004AFAD0`.)
   * - AssignSharedPairRetainWithTail (BoostWrappers.h): Address: 0x00445510 (FUN_00445510) What it does: Copies one
   *   `(px,pi)` pair with retained shared ownership and preserves two trailing 32-bit payload lanes.
   * - ReleaseEmbeddedSharedPair (BoostWrappers.h): Address: 0x00442A20 (FUN_00442A20, embedded shared-pair lane) What
   *   it does: Clears one embedded shared `(px,pi)` member pair and releases one shared control-block reference when
   *   present.
   * - LegacyNullAsNegOne (BoostWrappers.h): Address: 0x00442CF0 (FUN_00442CF0) Address: 0x00443010 (FUN_00443010)
   *   Address: 0x004437C0 (FUN_004437C0) What it does: Returns legacy Win32-bool encoding for null-check (`-1` when
   *   null, `0` otherwise).
   * - LegacyNullSlotAsNegOne (BoostWrappers.h): Address: 0x00446000 (FUN_00446000) What it does: Returns legacy
   *   Win32-bool encoding for null-check on one pointer slot (`-1` when slot points to null, `0` otherwise).
   * - BadWeakPtrWhatLiteral (BoostWrappers.h): Address: 0x00446F20 (FUN_00446F20) What it does: Returns legacy
   *   `boost::bad_weak_ptr::what()` message literal.
   * - LegacyIsNull (BoostWrappers.h): Address: 0x004437D0 (FUN_004437D0) What it does: Returns true when the pointer
   *   lane is null.
   * - LegacyPtrNotEqual (BoostWrappers.h): Address: 0x004438B0 (FUN_004438B0) Address: 0x00443900 (FUN_00443900)
   *   Address: 0x00444E60 (FUN_00444E60) What it does: Returns pointer-lane inequality.
   * - LegacyPtrEqual (BoostWrappers.h): Address: 0x00444170 (FUN_00444170) What it does: Returns pointer-lane
   *   equality.
   * - CopySharedPair (BoostWrappers.h): Address: 0x00444180 (FUN_00444180) Address: 0x00444220 (FUN_00444220)
   *   Address: 0x00444230 (FUN_00444230) Address: 0x00444D90 (FUN_00444D90) Address: 0x00444DA0 (FUN_00444DA0)
   *   Address: 0x004454A0 (FUN_004454A0) What it does: Copies one raw shared-pair payload `(px,pi)` without refcount
   *   mutation.
   * - ZeroDwordLane (BoostWrappers.h): Address: 0x0053B470 (FUN_0053B470) What it does: Clears one single dword lane
   *   and returns the caller-owned output slot.
   * - ReleaseSharedControlOnly (BoostWrappers.h): Address: 0x00443910 (FUN_00443910) What it does: Releases one
   *   shared control-block reference from one `(px,pi)` pair without mutating the `px` lane.
   * - InitSpCountedImplStorage (BoostWrappers.h): Address: 0x00446860 (FUN_00446860) Address: 0x004468A0
   *   (FUN_004468A0) Address: 0x004468E0 (FUN_004468E0) What it does: Initializes one `sp_counted_impl_p<T>` storage
   *   lane with use/weak counts set to one, one concrete vftable pointer, and one owned pointee pointer.
   * - DeleteOwnedObjectIfPresent (BoostWrappers.h): / ** / ** / ** Address: 0x00446880 (FUN_00446880) Address:
   *   0x00446900 (FUN_00446900) Address: 0x00446A60 (FUN_00446A60) Address: 0x00446AA0 (FUN_00446AA0) What it does:
   *   Deletes one owned pointee when present; returns zero on null input.
   * - LegacyGetDeleterNullResult (BoostWrappers.h): Address: 0x00446890 (FUN_00446890) Address: 0x004468D0
   *   (FUN_004468D0) Address: 0x00446910 (FUN_00446910) What it does: Returns the legacy null get-deleter lane.
   * - ReleaseSharedPrefixAndDeleteOwner (BoostWrappers.h): / ** / ** Address: 0x00923920 (FUN_00923920,
   *   boost::detail::sp_counted_impl_p<std::basic_stringstream<char, std::char_traits<char>,
   *   std::allocator<char>>>::dispose) / ** Address: 0x00446C40 (FUN_00446C40) What it does: Releases one shared
   *   `(px,pi)` prefix lane from a heap object and deletes that owning heap object.
   * - DeleteSharedOwnerIfPresent (BoostWrappers.h): Address: 0x004468C0 (FUN_004468C0) Address: 0x00446A70
   *   (FUN_00446A70) What it does: Deletes one heap owner carrying a shared `(px,pi)` prefix when present.
   * - / ** (BoostWrappers.h): Address: 0x00491350 (FUN_00491350 -- `mov eax, [ecx+0x0C]; ret`: the body of
   *   `boost::bad_ptr_container_operation::what()`, which boost 1.34.1 defines inline in ptr_container/exception.hpp
   *   as `return what_;` over the `const char*` that follows the 0x0C `std::exception` sub-object. Zero callers in
   *   the binary and none in source; formerly `GetBadPtrContainerMessage` reading through a a deleted overlay copy of
   *   that same layout (RULE ONE), removed 2026-09-18. Call `what()` on the exception instead.)
   * - SpCountedImplDeletingDtor (BoostWrappers.h): Address: 0x00446920 (FUN_00446920) Address: 0x00446940
   *   (FUN_00446940) Address: 0x00446960 (FUN_00446960) What it does: Models legacy deleting-destructor thunk
   *   behavior for trivial `sp_counted_impl_p<T>` destructors.
   * - SpCountedImplNonDeletingDtor (BoostWrappers.h): Address: 0x00446980 (FUN_00446980) Address: 0x00446990
   *   (FUN_00446990) Address: 0x004469A0 (FUN_004469A0) What it does: Models legacy non-deleting destructor body
   *   epilogue lane for trivial `sp_counted_impl_p<T>` destructors.
   * - AssignWeakPairFromShared (BoostWrappers.h): Address: 0x0043D940 (FUN_0043D940) Address: 0x0043EED0
   *   (FUN_0043EED0) Address: 0x0043F2E0 (FUN_0043F2E0) Address: 0x004438C0 (FUN_004438C0) What it does: Copies one
   *   `(px,pi)` pair and rebinds control ownership by retaining the incoming `pi` then weak-releasing the previous
   *   `pi`.
   * - AssignSharedPairRetain (BoostWrappers.h): Address: 0x0043DCF0 (FUN_0043DCF0) Address: 0x0043F500 (FUN_0043F500)
   *   Address: 0x0043F8E0 (FUN_0043F8E0) Address: 0x0043FD90 (FUN_0043FD90) Address: 0x00446A80 (FUN_00446A80)
   *   Address: 0x004456E0 (FUN_004456E0) Address: 0x00445860 (FUN_00445860) Address: 0x004459A0 (FUN_004459A0)
   *   Address: 0x004459C0 (FUN_004459C0) Address: 0x004459E0 (FUN_004459E0) Address: 0x00446150 (FUN_00446150)
   *   Address: 0x004462F0 (FUN_004462F0) Address: 0x00539AA0 (FUN_00539AA0) Address: 0x00539F70 (FUN_00539F70)
   *   Address: 0x006FE350 (FUN_006FE350, ex `CopySharedOwnerPairAndRetain` in `LegacyContainerFillLanes.cpp`)
   *   Address: 0x00796DC0 (FUN_00796DC0, ex `CopySharedOwnerPairWithUseRetain` in `LegacyContainerFillLanes.cpp`)
   *   Address: 0x00895F50 (FUN_00895F50, ex `LegacyCopySharedOwnerPairRetainedRuntimeSlot1` in
   *   `WinApiImportThunks.cpp`) Address: 0x008971D0 (FUN_008971D0, ex `LegacyCopySharedOwnerPairRetainedRuntimeSlot2`
   *   in `WinApiImportThunks.cpp`) What it does: Copies one `(px,pi)` pair and retains one shared control-block
   *   reference.
   * - ReleaseSharedCount (BoostWrappers.h): Address: 0x00740270 (FUN_00740270) What it does: Releases one shared
   *   control block and disposes/destroys the control block on the final strong and weak transitions.
   * - SharedPtrFromRawAdopt (BoostWrappers.h): Adopts an already-retained (px, pi) pair into a boost::shared_ptr
   *   without touching the count: the caller's reference becomes the shared_ptr's. Use it where the binary hands the
   *   pair straight to a shared_ptr result after a single add_ref (e.g. CAnimTexture::GetFrame -> CWldTerrainDecal::
   *   GetTexture, 0x0089DB50), where SharedPtrFromRawRetained would leak one reference per call.
   * - px_raw (BoostWrappers.h): Address: 0x00442C20 (FUN_00442C20) Address: 0x00442CE0 (FUN_00442CE0) Address:
   *   0x00442E90 (FUN_00442E90) Address: 0x00442FF0 (FUN_00442FF0) Address: 0x00443000 (FUN_00443000) Address:
   *   0x00442F70 (FUN_00442F70) Address: 0x00442F80 (FUN_00442F80) Address: 0x004437A0 (FUN_004437A0) Address:
   *   0x004437B0 (FUN_004437B0) Address: 0x004437F0 (FUN_004437F0) Address: 0x004438E0 (FUN_004438E0) Address:
   *   0x004438F0 (FUN_004438F0) Address: 0x00443CD0 (FUN_00443CD0) Address: 0x00444120 (FUN_00444120) Address:
   *   0x00444160 (FUN_00444160) What it does: Returns the raw pointee lane (`px`) from one borrowed shared-ptr pair.
   * - namespace (BoostWrappers.cpp): boost.thread is no longer built: what the engine used of it is src/legacy/thread
   *   (fa::mutex, fa::condition, fa::thread), with the binary's layout and behaviour; condition_impl's constructor
   *   (0x00AC2190) and thread::~thread (0x00AC2760) are cited there. The binary's two Win32 kernel-mutex helpers
   *   FUN_00AC1C90 and FUN_00AC5480 had no caller here and were removed with it.
   * - AssignWeakPairFromShared (BoostWrappers.cpp): Address: 0x0043D940 (FUN_0043D940) Address: 0x0043EED0
   *   (FUN_0043EED0) Address: 0x0043F2E0 (FUN_0043F2E0) Address: 0x004438C0 (FUN_004438C0) NOTE (2026-08-20 audit):
   *   the name is a legacy misnomer kept for external callers (AudioEngine.cpp, BeamRenderHelpers.cpp,
   *   CWorldParticles.cpp, CD3DDevice.cpp, ResourceManager.cpp) - FUN_0043D940 proves this is a strong shared-count
   *   rebind (`add_ref_copy()` on acquire, real `release()` via FUN_004229B0 on the replaced lane), not a weak one.
   *   See `AssignWeakPairFromSharedCore` above for the evidence. What it does: Copies one `(px,pi)` pair and rebinds
   *   control ownership by retaining the incoming `pi` then releasing the previous `pi`.
   * - AssignSharedPairRetain (BoostWrappers.cpp): Address: 0x0043DCF0 (FUN_0043DCF0) Address: 0x0043F500
   *   (FUN_0043F500) Address: 0x0043F8E0 (FUN_0043F8E0) Address: 0x0043FD90 (FUN_0043FD90) Address: 0x00446A80
   *   (FUN_00446A80) Address: 0x004456E0 (FUN_004456E0) Address: 0x00445860 (FUN_00445860) Address: 0x004459A0
   *   (FUN_004459A0) Address: 0x004459C0 (FUN_004459C0) Address: 0x004459E0 (FUN_004459E0) Address: 0x00446150
   *   (FUN_00446150) Address: 0x004462F0 (FUN_004462F0) Address: 0x00539AA0 (FUN_00539AA0) Address: 0x00539F70
   *   (FUN_00539F70) Address: 0x00544340 (FUN_00544340) Address: 0x006FE350 (FUN_006FE350, ex
   *   `CopySharedOwnerPairAndRetain` in `LegacyContainerFillLanes.cpp`) Address: 0x00796DC0 (FUN_00796DC0, ex
   *   `CopySharedOwnerPairWithUseRetain` in `LegacyContainerFillLanes.cpp`) Address: 0x00895F50 (FUN_00895F50, ex
   *   `LegacyCopySharedOwnerPairRetainedRuntimeSlot1` in `WinApiImportThunks.cpp`) Address: 0x008971D0 (FUN_008971D0,
   *   ex `LegacyCopySharedOwnerPairRetainedRuntimeSlot2` in `WinApiImportThunks.cpp`) What it does: Copies one
   *   `(px,pi)` pair and retains one shared control-block reference.
   */
} // namespace gpg
