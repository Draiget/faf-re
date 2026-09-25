#pragma once

#include <cstddef>
#include <cstdint>

#include "gpg/core/containers/String.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/math/Vector2f.h"
#include "moho/render/camera/GeomCamera3.h"
#include "moho/script/CScriptEvent.h"
#include "moho/sim/WeakEntitySet.h"
#include "moho/unit/Broadcaster.h"
#include "Wm3AxisAlignedBox3.h"
#include "Wm3Vector3.h"

struct lua_State;

namespace LuaPlus
{
  class LuaState;
}

namespace gpg
{
  class RRef;
  class RType;
}

namespace moho
{
  class CScrLuaInitForm;
  class STIMap;
  class UserEntity;
  enum ECamTimeSource : std::int32_t;
  struct SSelectionSetUserEntity;

  struct CameraUserEntityWeakRef
  {
    void* mOwnerLinkSlot;                  // +0x00
    CameraUserEntityWeakRef* mNextOwnerRef; // +0x04
  };

  static_assert(sizeof(CameraUserEntityWeakRef) == 0x08, "CameraUserEntityWeakRef size must be 0x08");
  static_assert(
    offsetof(CameraUserEntityWeakRef, mOwnerLinkSlot) == 0x00,
    "CameraUserEntityWeakRef::mOwnerLinkSlot offset must be 0x00"
  );
  static_assert(
    offsetof(CameraUserEntityWeakRef, mNextOwnerRef) == 0x04,
    "CameraUserEntityWeakRef::mNextOwnerRef offset must be 0x04"
  );

  struct CameraFrustumUserEntityList
  {
    CameraUserEntityWeakRef* mStart;        // +0x00
    CameraUserEntityWeakRef* mFinish;       // +0x04
    CameraUserEntityWeakRef* mCapacity;     // +0x08
    CameraUserEntityWeakRef* mInlineOrigin; // +0x0C

    /**
     * Address: 0x007AFBB0 (FUN_007AFBB0)
     *
     * IDA signature:
     * void** __thiscall sub_7AFBB0(CameraFrustumUserEntityList *this,
     *   unsigned requiredCapacity, CameraUserEntityWeakRef *insertionPos,
     *   CameraUserEntityWeakRef *first, CameraUserEntityWeakRef *last);
     *
     * What it does:
     * Reallocates this lane's storage to `requiredCapacity` slots, splicing
     * `[first, last)` in at `insertionPos` while relocating the existing
     * `[mStart, insertionPos)` head and `[insertionPos, mFinish)` tail into
     * the new buffer (each element's owner-chain link is relinked to the new
     * address by the copy step). Detaches every element at the OLD storage
     * addresses from the owner chains they were just relinked away from,
     * then either releases the old heap buffer or, when the old buffer was
     * the inline block, stashes its capacity bound at the inline origin so a
     * later `Teardown` can restore it. Returns the new `mCapacity` (matching
     * the binary's own return value, which no observed caller actually
     * uses). Called only from `InsertRange`'s grow branch below.
     */
    CameraUserEntityWeakRef* GrowAndInsertRange(
      std::size_t requiredCapacity,
      CameraUserEntityWeakRef* insertionPos,
      CameraUserEntityWeakRef* first,
      CameraUserEntityWeakRef* last
    );

    /**
     * Address: 0x007AF0B0 (FUN_007AF0B0)
     *
     * IDA signature:
     * void __thiscall sub_7AF0B0(CameraFrustumUserEntityList *this,
     *   CameraUserEntityWeakRef *insertionPos, CameraUserEntityWeakRef *first,
     *   CameraUserEntityWeakRef *last);
     *
     * What it does:
     * The VC8 `_Insert_n` dispatcher for this lane's element range: when
     * spare capacity cannot hold `size() + (last-first)`, reallocates via
     * `GrowAndInsertRange` above; otherwise shifts the existing tail
     * in-place (constructing into freshly-exposed raw slots past `mFinish`,
     * assigning over slots that stay live) and places `[first, last)` into
     * the gap at `insertionPos`. Direct callers: the inlined sound-entities
     * lane push in `CacheCameraFrustumUnits` (FUN_007A75A0), and `AssignRange`
     * below (FUN_007F20E0's grow-then-append path).
     */
    CameraUserEntityWeakRef* InsertRange(
      CameraUserEntityWeakRef* insertionPos,
      CameraUserEntityWeakRef* first,
      CameraUserEntityWeakRef* last
    );

    /**
     * Address: 0x007F20E0 (FUN_007F20E0)
     *
     * IDA signature:
     * CameraFrustumUserEntityList* __thiscall sub_7F20E0(
     *   CameraFrustumUserEntityList *this, CameraFrustumUserEntityList *other);
     *
     * What it does:
     * The VC8 vector `assign(first, last)` / `operator=` shape for this lane,
     * taking another lane-shaped object as the source view (matching the
     * binary's own `CameraFrustumUserEntityList*` second parameter, even
     * though only its `mStart`/`mFinish` are ever read): self-assignment
     * no-op guard; when this lane's current size already covers `other`,
     * assigns the retained prefix forward and detaches/drops the excess
     * tail; otherwise ensures capacity for `other`'s element count (via
     * `InsertRange`'s own grow machinery, invoked here with a degenerate
     * empty range purely for its capacity-ensure side effect), assigns
     * forward over the currently-live prefix, then places the remaining
     * source elements past `mFinish` via `InsertRange`. Sole real caller:
     * `SnapshotCameraFrustumWeakRefs` (FUN_007F03D0, RangeRenderer.cpp),
     * always with an empty `this` -- the truncate branch is therefore only
     * exercised when `other` is also empty in every observed call site.
     */
    CameraUserEntityWeakRef* AssignRange(const CameraFrustumUserEntityList& other);
    /**
     * Address: inlined - emitted at 0x007EEB13..0x007EEB52 inside
     * `RangeRenderer::Render` (FUN_007EEA00), and again in the lane teardown
     * `CameraImpl::~CameraImpl` and `CameraImpl::CacheCameraFrustumUnits` run.
     *
     * The destruction half of this lane, and the one operation it was missing.
     * Every element is spliced into its tracked entity's intrusive weak-link
     * chain, so the storage cannot simply be released: each node must first
     * rewire the chain slot pointing back at it (FUN_007AF240), and only then
     * is heap-grown storage handed to `operator delete[]`. Skipping this
     * leaves the entity chains pointing into memory the lane no longer owns,
     * which is fatal for a stack-allocated lane - the next walk of that chain
     * dereferences a dead frame.
     *
     * Leaves `mStart`/`mFinish` as they were: the binary's inlined copy is a
     * dying object's destructor. Callers that go on to reuse the lane restore
     * the inline sentinel state themselves.
     */
    void DetachAndRelease() noexcept;
  };

  static_assert(sizeof(CameraFrustumUserEntityList) == 0x10, "CameraFrustumUserEntityList size must be 0x10");
  static_assert(
    offsetof(CameraFrustumUserEntityList, mStart) == 0x00, "CameraFrustumUserEntityList::mStart offset must be 0x00"
  );
  static_assert(
    offsetof(CameraFrustumUserEntityList, mFinish) == 0x04, "CameraFrustumUserEntityList::mFinish offset must be 0x04"
  );
  static_assert(
    offsetof(CameraFrustumUserEntityList, mCapacity) == 0x08, "CameraFrustumUserEntityList::mCapacity offset must be 0x08"
  );
  static_assert(
    offsetof(CameraFrustumUserEntityList, mInlineOrigin) == 0x0C,
    "CameraFrustumUserEntityList::mInlineOrigin offset must be 0x0C"
  );

  /**
   * Decodes one `CameraFrustumUserEntityList` lane back to the `UserEntity`
   * it tracks. `mOwnerLinkSlot` points at the entity's `mIUnitChainHead`
   * slot (`offsetof(UserEntity, mIUnitChainHead) == 0x08`), so the entity
   * itself sits `0x08` bytes before it; an unlinked or self-pointing lane
   * (`raw <= kUserEntityWeakOwnerOffset`) decodes to null.
   *
   * Named distinctly from `CameraImpl.cpp`'s file-private
   * `DecodeUserEntityWeakRef(const SSelectionWeakRefUserEntity&)` - that one
   * decodes a selection weak-ref, this one a frustum weak-ref; the two types
   * are unrelated despite the coincidentally similar source names.
   *
   * Shared by every walk of `CameraImpl::GetArmyUnitsInFrustum()` - promoted
   * here from a file-private duplicate in `CWldSession.cpp` so
   * `CUIWorldView`'s build-drag adjacency highlighter can use it too.
   */
  [[nodiscard]] UserEntity* DecodeCameraFrustumWeakRef(const CameraUserEntityWeakRef& weakRef) noexcept;

  /**
   * One frustum weak-entity lane: a `gpg::fastvector_n<WeakPtr<UserEntity>, 40>`
   * -- the four-pointer view followed by its own 40-slot inline buffer, which
   * the view's `mInlineOrigin` points at until the lane outgrows it. `CameraImpl`
   * holds three of these back to back at +0x460, +0x5B0 and +0x700.
   */
  struct CameraFrustumUserEntityStorage
  {
    CameraFrustumUserEntityList mView;             // +0x00
    CameraUserEntityWeakRef mInlineStorage[40]{};  // +0x10
  };

  static_assert(sizeof(CameraFrustumUserEntityStorage) == 0x150, "CameraFrustumUserEntityStorage size must be 0x150");
  static_assert(
    offsetof(CameraFrustumUserEntityStorage, mView) == 0x00,
    "CameraFrustumUserEntityStorage::mView offset must be 0x00"
  );
  static_assert(
    offsetof(CameraFrustumUserEntityStorage, mInlineStorage) == 0x10,
    "CameraFrustumUserEntityStorage::mInlineStorage offset must be 0x10"
  );

  struct SCamShakeParams
  {
    Wm3::Vec3f mCenter{};         // +0x00
    float mMaxRange = 0.0f;       // +0x0C
    /// Shake magnitude at the epicentre. Named `mMinMagnitude` until the
    /// falloff at 0x007A67C0 was read: `(field@0x14 - field@0x10) * (dist /
    /// range) + field@0x10`, so this field is what a listener standing on the
    /// epicentre gets and is the LARGER of the two in normal use. The
    /// `ShakeCamera` Lua binding passes its `maxIntensity` argument here.
    float mMagnitudeAtCenter = 0.0f;     // +0x10
    /// Shake magnitude out at `mMaxRange`; the binding's `minIntensity`.
    float mMagnitudeAtMaxRange = 0.0f;   // +0x14
    float mDuration = 0.0f;       // +0x18
  };

  static_assert(sizeof(SCamShakeParams) == 0x1C, "SCamShakeParams size must be 0x1C");
  static_assert(offsetof(SCamShakeParams, mCenter) == 0x00, "SCamShakeParams::mCenter offset must be 0x00");
  static_assert(offsetof(SCamShakeParams, mMaxRange) == 0x0C, "SCamShakeParams::mMaxRange offset must be 0x0C");
  static_assert(
    offsetof(SCamShakeParams, mMagnitudeAtCenter) == 0x10,
    "SCamShakeParams::mMagnitudeAtCenter offset must be 0x10"
  );
  static_assert(
    offsetof(SCamShakeParams, mMagnitudeAtMaxRange) == 0x14,
    "SCamShakeParams::mMagnitudeAtMaxRange offset must be 0x14"
  );
  static_assert(offsetof(SCamShakeParams, mDuration) == 0x18, "SCamShakeParams::mDuration offset must be 0x18");

  struct SCamFollowParams
  {
    std::int32_t mCurrentEntityId = 0; // +0x00
    std::int32_t mTargetEntityId = 0;  // +0x04
    float mTargetTimeLeft = 0.0f;      // +0x08
  };

  static_assert(sizeof(SCamFollowParams) == 0x0C, "SCamFollowParams size must be 0x0C");
  static_assert(
    offsetof(SCamFollowParams, mCurrentEntityId) == 0x00,
    "SCamFollowParams::mCurrentEntityId offset must be 0x00"
  );
  static_assert(
    offsetof(SCamFollowParams, mTargetEntityId) == 0x04,
    "SCamFollowParams::mTargetEntityId offset must be 0x04"
  );
  static_assert(
    offsetof(SCamFollowParams, mTargetTimeLeft) == 0x08,
    "SCamFollowParams::mTargetTimeLeft offset must be 0x08"
  );

  /**
   * The live shake a camera is playing: the `SCamShakeParams` payload the
   * producer in `Entity.cpp` hands over, plus the two lanes only the camera
   * keeps. Deriving means there is one declaration of the payload and the
   * offsets cannot drift apart again -- which is how the old duplicate's
   * `mMinMagnitude`/`mMaxMagnitude` spelling came to disagree with the
   * producer in the first place.
   */
  struct SCamShakeState : SCamShakeParams
  {
    float mElapsed = 0.0f; // +0x1C
    float mScale = 0.0f;   // +0x20
  };

  static_assert(sizeof(SCamShakeState) == 0x24, "SCamShakeState size must be 0x24");
  static_assert(offsetof(SCamShakeState, mElapsed) == 0x1C, "SCamShakeState::mElapsed offset must be 0x1C");
  static_assert(offsetof(SCamShakeState, mScale) == 0x20, "SCamShakeState::mScale offset must be 0x20");

  /**
   * One node of `CameraImpl::mTargetEntities`. The `{next, prev, value}` shape
   * over a 0x0C `{proxy, head, size}` head is the MSVC8 `std::list` node; the
   * value is a weak reference that splices itself into the target entity's
   * owner chain, which is why the node is created and destroyed through the
   * helpers in `CameraImpl.cpp` rather than by a plain allocator.
   */
  struct CameraTargetEntityNode
  {
    CameraTargetEntityNode* mNext = nullptr; // +0x00
    CameraTargetEntityNode* mPrev = nullptr; // +0x04
    SSelectionWeakRefUserEntity mWeakRef{};  // +0x08
  };

  static_assert(sizeof(CameraTargetEntityNode) == 0x10, "CameraTargetEntityNode size must be 0x10");
  static_assert(
    offsetof(CameraTargetEntityNode, mWeakRef) == 0x08,
    "CameraTargetEntityNode::mWeakRef offset must be 0x08"
  );

  /**
   * The head of that list: allocator proxy, self-linked sentinel node, count.
   * Byte-identical to `msvc8::list<SSelectionWeakRefUserEntity>`, whose
   * `_Container_base` proxy sits at +0x00 with `_Myhead` at +0x04 and
   * `_Mysize` at +0x08.
   */
  struct CameraTargetEntityList
  {
    void* mAllocProxy = nullptr;             // +0x00
    CameraTargetEntityNode* mHead = nullptr; // +0x04
    std::int32_t mSize = 0;                  // +0x08
  };

  static_assert(sizeof(CameraTargetEntityList) == 0x0C, "CameraTargetEntityList size must be 0x0C");
  static_assert(offsetof(CameraTargetEntityList, mHead) == 0x04, "CameraTargetEntityList::mHead offset must be 0x04");
  static_assert(offsetof(CameraTargetEntityList, mSize) == 0x08, "CameraTargetEntityList::mSize offset must be 0x08");

  /**
   * Abstract time source behind `CameraImpl::mTimeSources`. Two concrete
   * implementations live in `CameraImpl.cpp` and are heap-allocated into the
   * two slots: system time at index 0, game time at index 1.
   */
  class CameraTimeSourceRuntime
  {
  public:
    /// VTable slot 0, queried as `mTimeSources[mTimeSource]->Time()`.
    virtual float Time() = 0;

    /// VTable slot 1: the scalar-deleting destructor the `eh vector destructor
    /// iterator` lane in `CameraImpl::~CameraImpl` dispatches through
    /// (FUN_007AE630).
    virtual ~CameraTimeSourceRuntime() = default;
  };

  /**
   * Byte size of a live `CameraImpl`.
   *
   * `CameraImpl` derives from `RCamCamera` (vtable + self-linked broadcaster
   * node, +0x00..+0x0C) and `CScriptEvent` (+0x0C..+0x460), but almost all of
   * its own state -- everything past the two real base subobjects -- is
   * reached through the runtime views in `CameraImpl.cpp` (frustum lanes at
   * +0x460..+0x850) rather than declared as ordinary members. Anything
   * allocating a camera must use this size, not `sizeof(CameraImpl)`:
   * `RCamManager::CreateCamera` (0x007AA9C0) calls `operator new(0x858u)`,
   * and the constructor writes the whole block.
   */
  inline constexpr std::size_t kCameraImplRuntimeSize = 0x858u;

  /**
   * Address: 0x007AAC60 (FUN_007AAC60, ??1RCamCamera@Moho@@UAE@XZ,
   * Moho::RCamCamera::~RCamCamera)
   *
   * What it does:
   * The polymorphic camera-manager base `CameraImpl` derives from. Adds
   * nothing but a vtable (destructor slot 0) over the plain, non-virtual
   * `Broadcaster` self-linked ring node it wraps; the reflected base-lane
   * registration in `CameraImplTypeInfo.cpp` (`AddCScriptEventBaseToCameraImplType`,
   * offset `+0x0C`) is what places `CScriptEvent` immediately after this
   * 0x0C-byte base in every `CameraImpl` instance. The real name is proven by
   * the mangled return type of `RCamManager::CreateCamera`/`GetCamera`
   * (`?...@Moho@@QAEPAVRCamCamera@2@...`) and `ForgetCamera`'s parameter
   * (`PBVRCamCamera@2@`) -- MSVC name mangling never encodes a typedef, only
   * a real, distinct class.
   *
   * The destructor's own body (removing this camera from `RCamManager`
   * ownership and restoring the broadcaster ring node to its self-linked
   * idle state) lives in `CameraImpl.cpp` and runs automatically, chained
   * after `CameraImpl::~CameraImpl`'s body, via ordinary C++ base-destructor
   * chaining -- it is never called explicitly.
   */
  class RCamCamera : public Broadcaster
  {
  public:
    virtual ~RCamCamera();

    /// Slot 1.
    [[nodiscard]] virtual const char* CameraGetName() const = 0;

    /// Slot 2.
    [[nodiscard]] virtual const GeomCamera3& CameraGetView() const = 0;

    /// Slot 3.
    virtual void CameraSetViewport(const Wm3::Vector2f& viewportOrigin, const Wm3::Vector2f& viewportSize) = 0;

    /// Slot 4.
    virtual void CameraGetViewport(Wm3::Vector2f& viewportOrigin, Wm3::Vector2f& viewportSize) const = 0;

    /// Slot 5.
    [[nodiscard]] virtual Wm3::Vector2f Project(const Wm3::Vector3f& worldPoint) const = 0;

    /// Slot 6.
    [[nodiscard]] virtual GeomLine3 Unproject(const Wm3::Vector2f& screenPoint) const = 0;

    /// Slot 7.
    [[nodiscard]] virtual Wm3::Vector3f CameraScreenToSurface(const Wm3::Vector2f& screenPoint) const = 0;

    /// Slot 8.
    virtual void CameraReset() = 0;

    /// Slot 9.
    virtual void TargetNothing() = 0;

    /// Slot 10.
    virtual void TargetLocation(const Wm3::Vec3f& position, float seconds) = 0;

    /// Slot 11.
    virtual void TargetEntityBox(UserEntity* entity, float seconds) = 0;

    /// Slot 12.
    virtual void TargetEntities(
      const SSelectionSetUserEntity& entities,
      bool trackEntities,
      float zoom,
      float seconds
    ) = 0;

    /// Slot 13.
    virtual void TargetBox(const Wm3::AxisAlignedBox3f& targetBox, float seconds) = 0;

    /// Slot 14.
    virtual void TargetManual(const Wm3::Vec3f& position, float heading, float pitch, float zoom, float seconds) = 0;

    /// Slot 15.
    [[nodiscard]] virtual UserEntity* GetTargetEntity() const = 0;

    /// Slot 16.
    virtual void CameraFollow(const SCamFollowParams& followParams) = 0;

    /// Slot 17.
    virtual void TargetNextEntity() = 0;

    /// Slot 18.
    [[nodiscard]] virtual const Wm3::Vec3f& CameraGetOffset() const = 0;

    /// Slot 19.
    [[nodiscard]] virtual float CameraGetTargetZoom() const = 0;

    /// Slot 20.
    [[nodiscard]] virtual float GetMaxZoom() const = 0;

    /// Slot 21.
    virtual void SetMaxZoomMult(float maxZoomMult) = 0;

    /// Slot 22.
    [[nodiscard]] virtual float CameraGetZoom() const = 0;

    /// Slot 23.
    [[nodiscard]] virtual float CameraGetPitch() const = 0;

    /// Slot 24.
    [[nodiscard]] virtual float CameraGetHeading() const = 0;

    /// Slot 25.
    virtual void CameraSetPitch(float pitchRadians) = 0;

    /// Slot 26.
    virtual void CameraSetHeading(float headingRadians) = 0;

    /// Slot 27.
    virtual void CameraSpin(const Wm3::Vector2f& spinDelta) = 0;

    /// Slot 28.
    [[nodiscard]] virtual bool CameraIsRotated() const = 0;

    /// Slot 29.
    virtual void CameraRevertRotation() = 0;

    /// Slot 30.
    virtual void CameraSetPivot(const Wm3::Vector2f& pivot) = 0;

    /// Slot 31.
    virtual void CameraZoom(float zoomDelta) = 0;

    /// Slot 32.
    virtual void CameraPan(const Wm3::Vector2f& panDelta) = 0;

    /// Slot 33.
    virtual void CameraSetOrtho(bool enabled) = 0;

    /// Slot 34.
    [[nodiscard]] virtual bool CameraIsOrtho() = 0;

    /// Slot 35.
    [[nodiscard]] virtual float LODMetric(const Wm3::Vec3f& offset) const = 0;

    /// Slot 36.
    virtual void SetLODScale(float scale) = 0;

    /// Slot 37.
    virtual void CanShake(bool canShake) = 0;

    /// Slot 38.
    virtual void CameraShake(const SCamShakeParams& shakeParams) = 0;

    /// Slot 39.
    [[nodiscard]] virtual CameraFrustumUserEntityList& GetAllSoundEntitiesInFrustum() = 0;

    /// Slot 40.
    [[nodiscard]] virtual CameraFrustumUserEntityList* GetAllUnitsInFrustum() = 0;

    /// Slot 41.
    [[nodiscard]] virtual CameraFrustumUserEntityList* GetArmyUnitsInFrustum() = 0;

    /// Slot 42.
    [[nodiscard]] virtual Wm3::AxisAlignedBox3f GetViewBox() const = 0;

    /// Slot 43.
    [[nodiscard]] virtual Wm3::Vector3f GetTargetPosition() const = 0;

  protected:
    RCamCamera() = default;
  };

  class CameraImpl : public RCamCamera, public CScriptEvent
  {
  public:
    /// Cached reflection descriptor for `CameraImpl`, lazily resolved by
    /// `StaticGetClass()`/`GetClass()`. Proven a real static member (not a
    /// free-function-local cache) by the disassembly of
    /// `SCR_FromLua_CameraImpl` (0x007B0E90), which reads/writes
    /// `Moho::CameraImpl::sType` directly.
    static gpg::RType* sType;

    /**
     * Address: 0x007A6990 (FUN_007A6990, ?StaticGetClass@CameraImpl@Moho@@SAPAVRType@gpg@@XZ)
     */
    [[nodiscard]] static gpg::RType* StaticGetClass();

    /**
     * Address: 0x007A69B0 (FUN_007A69B0, ?GetClass@CameraImpl@Moho@@UBEPAVRType@gpg@@XZ)
     *
     * What it does:
     * Overrides `CScriptEvent::GetClass` (which would otherwise report the
     * `CScriptEvent` base's own reflected type) to report `CameraImpl`'s.
     */
    [[nodiscard]] gpg::RType* GetClass() const override;

    /**
     * Address: 0x007A7950 (FUN_007A7950, ??0CameraImpl@Moho@@QAE@VStrArg@gpg@@ABVSTIMap@1@PAVLuaState@LuaPlus@@@Z)
     * Mangled: ??0CameraImpl@Moho@@QAE@VStrArg@gpg@@ABVSTIMap@1@PAVLuaState@LuaPlus@@@Z
     *
     * What it does:
     * Builds one runtime camera instance bound to terrain-map context and
     * optional Lua state ownership.
     */
    CameraImpl(gpg::StrArg name, const STIMap& map, LuaPlus::LuaState* luaState);

    /**
     * Address: 0x007A7F00 (FUN_007A7F00, ??1CameraImpl@Moho@@UAE@XZ)
     * Mangled: ??1CameraImpl@Moho@@UAE@XZ
     *
     * IDA signature:
     * Moho::Broadcaster *__stdcall Moho::CameraImpl::~CameraImpl(int a1);
     *
     * What it does:
     * Tears down one runtime camera in reverse construction order. Unlinks each
     * of the three frustum/spotter inline weak-vector lanes from their tracked
     * `UserEntity` owners and releases any heap-grown storage. Clears the
     * intrusive target-entity weak list (`mTargetEntities`) and frees its head
     * sentinel. Destroys both heap-allocated `CameraTimeSourceRuntime` slots
     * via the EH vector-destructor iterator, whose per-element delete
     * callback is `FUN_007AE630` (`ReleaseOwnedRuntimePointerSlotWithDeleteFlag`,
     * WinApiImportThunks.cpp) -- see the .cpp definition's doc comment for
     * the full citation. Releases the embedded
     * `GeomCamera3` solid-frustum heap storage, tears down the `mName`
     * `msvc8::string` SSO buffer, runs the `CScriptEvent` sub-object teardown,
     * and finally chains into `RCamCamera::~RCamCamera` which forgets this
     * camera from the global manager and rejoins the broadcaster ring to its
     * self-linked idle state.
     *
     * Invoked from the scalar-deleting wrapper at vtable slot 0
     * (`operator_delete`, FUN_007A7DC0); the wrapper itself is referenced from
     * the `CameraImpl` vtable (`??_7CameraImpl@Moho@@6B@` at 0x00E3C474) and
     * its `CScriptEvent` / `CScriptObject` sub-object vtable thunks.
     */
    ~CameraImpl() override;

    /**
     * Address: 0x007A69D0 (FUN_007A69D0, Moho::CameraImpl::GetDerivedObjectRef)
     * Mangled: ?GetDerivedObjectRef@CameraImpl@Moho@@UAE?AVRRef@gpg@@XZ
     *
     * What it does:
     * Overrides `CScriptEvent::GetDerivedObjectRef` to pack `{this, GetClass()}`
     * (the complete `CameraImpl` object, not just the `CScriptEvent` sub-object
     * `CScriptEvent::GetDerivedObjectRef` would report) as a reflected object
     * reference.
     */
    [[nodiscard]] gpg::RRef GetDerivedObjectRef() override;

    /**
     * Address: 0x007A9030 (FUN_007A9030, Moho::CameraImpl::Frame)
     * Mangled: ?Frame@CameraImpl@Moho@@QAEXMM@Z
     * Address context: called from `RCamManager::Frame` (`0x007AABB0`) camera-loop lane.
     *
     * What it does:
     * Advances one camera runtime for the current sim/frame delta pair. When the
     * camera follows the game clock, recomputes the frame delta from the
     * game-time source against the last frame's recorded time, advances the
     * camera-shake elapsed timer (clamped to the shake duration), flips the
     * shake phase sign, then drives the five per-frame lanes by name:
     *   - 0x007A9110 (UpdateTargets — entity-target tracking)
     *   - 0x007A95F0 (UpdateBasis) when no timed transition is active, else
     *     0x007A9BA0 (InterpolateBasis) when `mTimedMoveDuration > 0`
     *   - 0x007AA330 (UpdateCoords — push view transform + projection into mCam)
     *   - 0x007A75A0 (CacheCameraFrustumUnits — rebuild cached in-frustum units)
     * and records the game-clock time for the next frame's delta. Recovered in
     * CameraImpl.cpp.
     */
    void Frame(float interpolationAlpha, float frameSeconds);

    /**
     * Address: 0x007A95F0 (FUN_007A95F0, Moho::CameraImpl::UpdateBasis)
     * Mangled: ?UpdateBasis@CameraImpl@Moho@@QAEXMM@Z
     *
     * What it does:
     * Advances camera target-zoom along its log-space slew curve, optionally
     * pivot-shifts the target focus toward the screen pivot when zooming
     * out of Location/Hermite targeting, refreshes the camera FOV, then
     * resolves heading/pitch lanes from the active target type:
     *
     *   - NoseCam: pulls heading from the entity's interpolated quaternion
     *     orientation and combines `COORDS_Pitch` with the saved nose-cam
     *     pitch adjust into `mFarPitch`.
     *   - Hermite: snaps heading/pitch to the cached transition endpoints.
     *   - Otherwise: in rotated mode, slews heading toward +/-pi and pitch
     *     toward the log-zoom-interpolated camera pitch and clears the
     *     rotation flags when both lanes are within tolerance; in normal
     *     mode, sets pitch to the log-zoom-interpolated camera pitch.
     *
     * Always finishes by snapping the focus to the terrain surface through
     * `ClampFocusPos`.
     */
    void UpdateBasis(float interpolationAlpha, float frameSeconds);

    /**
     * Address: 0x007A9110 (FUN_007A9110, Moho::CameraImpl::UpdateTargets)
     * Mangled: ?UpdateTargets@CameraImpl@Moho@@QAEXMM@Z
     *
     * What it does:
     * Advances entity-target tracking lanes for one Frame tick. Decrements the
     * tracked-target countdown timer (`mTargetTimeLeft`) when armed and
     * dispatches `TargetNextEntity` when it elapses, then resolves behavior by
     * target type:
     *
     *   - Entity/NoseCam: refreshes `mTargetLocation` from the live entity's
     *     interpolated transform; in NoseCam mode also recomputes
     *     `mCurrentPitch` from `COORDS_Pitch + mNoseCamPitchAdjust` and
     *     `mHeadingZoom` from the quaternion-derived heading wrapped relative
     *     to `mTimedMoveHeading`. When the live entity is gone, arms
     *     `mTargetTime` for a tracking-stop broadcast, demotes to Location
     *     mode, and schedules a rotation revert when previously rotated.
     *   - Hermite: integrates `mHeadingZoom` and `mNearZoom` along the cached
     *     spin rates (`mHeadingRate * delta * 2pi` and `mZoomRate * delta`).
     *   - Otherwise (Location/Box): no-op early exit.
     */
    void UpdateTargets(float interpolationAlpha, float frameSeconds);

    /**
     * Address: 0x007A9BA0 (FUN_007A9BA0, Moho::CameraImpl::InterpolateBasis)
     * Mangled: ?InterpolateBasis@CameraImpl@Moho@@QAEXMM@Z
     *
     * What it does:
     * Drives one active timed-move / Hermite camera transition for the current
     * frame. Computes linear transition progress from the active time source,
     * refreshes the entity target when following, and either snaps to the
     * transition endpoint or Hermite-blends offset/heading/far-pitch/target-zoom
     * between the cached endpoints using the acceleration-curve-shaped progress,
     * then snaps the offset to the terrain surface and demotes finished
     * Hermite/Box transitions to Location mode. The second float matches the
     * Frame-lane ABI and is unused on this code path.
     */
    void InterpolateBasis(float interpolationAlpha, float frameSeconds);

    /**
     * Address: 0x007AA330 (FUN_007AA330, Moho::CameraImpl::UpdateCoords)
     * Mangled: ?UpdateCoords@CameraImpl@Moho@@QAEXMM@Z
     *
     * What it does:
     * Rebuilds the embedded `GeomCamera3` view transform and projection from the
     * current camera state: converts target-zoom into an eye distance, derives
     * near/far clip planes, builds the orientation quaternion (heading/pitch in
     * perspective mode, fixed top-down in ortho mode), places the eye at
     * `mOffset` plus the rotated forward axis times the eye distance (with shake
     * in perspective mode), builds the projection matrix, and re-initializes
     * `mCam`. Both floats match the Frame-lane ABI and are unused on this path.
     */
    void UpdateCoords(float interpolationAlpha, float frameSeconds);

    /**
     * Address: 0x007A75A0 (FUN_007A75A0, Moho::CameraImpl::CacheCameraFrustumUnits)
     * Mangled: ?CacheCameraFrustumUnits@CameraImpl@Moho@@QAEXM@Z
     *
     * What it does:
     * Periodically rebuilds the three cached "units in camera frustum" weak
     * lists (all-entities, all-units, focus-army units), gated by a frame-time
     * accumulator. On rebuild it clears the lanes, queries the world spatial DB
     * for every unit/entity intersecting the current camera view, and bins each
     * live entity into the appropriate cached list(s).
     */
    void CacheCameraFrustumUnits(float deltaFrame);

    /**
     * Address: 0x007A6E70 (FUN_007A6E70, Moho::CameraImpl::CameraSetAccType)
     * Mangled: ?CameraSetAccType@CameraImpl@Moho@@QAEXABV?$basic_string@DU?$char_traits@D@std@@V?$allocator@D@2@@std@@@Z
     *
     * What it does:
     * Applies one acceleration mode token (`Linear`, `FastInSlowOut`,
     * `SlowInOut`) into the camera runtime acceleration lane.
     */
    void CameraSetAccType(const msvc8::string& accType);

    /**
     * Address: 0x007A69F0 (Moho::CameraImpl::CameraGetName)
     * Slot: 1
     */
    [[nodiscard]] const char* CameraGetName() const override;
    /**
     * Address: 0x007A6A00 (Moho::CameraImpl::CameraGetView)
     * Slot: 2
     */
    [[nodiscard]] const GeomCamera3& CameraGetView() const override;
    /**
     * Address: 0x007A6A80 (FUN_007A6A80, Moho::CameraImpl::CameraSetViewport)
     * Mangled: ?CameraSetViewport@CameraImpl@Moho@@QAEPAV?$Vector2@M@Wm3@@ABV34@0@Z
     *
     * What it does:
     * Updates camera viewport origin/size lanes, rebuilds viewport row-2
     * normalization from row-1, and refreshes zoom-metric aspect scaling.
     */
    void CameraSetViewport(const Wm3::Vector2f& viewportOrigin, const Wm3::Vector2f& viewportSize) override;
    /**
     * Address: 0x007A6B20 (FUN_007A6B20, Moho::CameraImpl::CameraGetViewport)
     * Mangled: ?CameraGetViewport@CameraImpl@Moho@@UBEXAAV?$Vector2@M@Wm3@@0@Z
     *
     * What it does:
     * Returns current camera viewport origin and viewport size lanes.
     */
    void CameraGetViewport(Wm3::Vector2f& viewportOrigin, Wm3::Vector2f& viewportSize) const override;
    /**
     * Address: 0x007A6B50 (FUN_007A6B50, ?Project@CameraImpl@Moho@@UBE?AV?$Vector2@M@Wm3@@ABV?$Vector3@M@4@@Z)
     *
     * What it does:
     * Projects one world-space point through the embedded camera view and
     * returns screen-space coordinates.
     */
    [[nodiscard]] Wm3::Vector2f Project(const Wm3::Vector3f& worldPoint) const override;
    /**
     * Address: 0x007A6B70 (FUN_007A6B70, ?Unproject@CameraImpl@Moho@@UBE?AU?$GeomLine3@M@2@ABV?$Vector2@M@Wm3@@@Z)
     *
     * What it does:
     * Builds one world-space ray from a screen-space point using the embedded
     * camera view/projection/viewport lanes.
     */
    [[nodiscard]] GeomLine3 Unproject(const Wm3::Vector2f& screenPoint) const override;
    /**
     * Address: 0x007A6BB0 (FUN_007A6BB0, ?CameraScreenToSurface@CameraImpl@Moho@@UBE?AV?$Vector3@M@Wm3@@ABV?$Vector2@M@4@@Z)
     *
     * What it does:
     * Unprojects one screen-space point and resolves the terrain/water surface
     * intersection point on the active map.
     */
    [[nodiscard]] Wm3::Vector3f CameraScreenToSurface(const Wm3::Vector2f& screenPoint) const override;
    /**
     * Address: 0x007A80A0 (FUN_007A80A0, Moho::CameraImpl::CameraReset)
     * Mangled: ?CameraReset@CameraImpl@Moho@@UAEXXZ
     *
     * What it does:
     * Resets runtime camera orientation/target lanes to map-centered defaults.
     */
    void CameraReset() override;
    /**
      * Alias of FUN_007A6BF0 (non-canonical helper lane).
     * Mangled: ?TargetNothing@CameraImpl@Moho@@UAEXXZ
     *
     * What it does:
     * Stops entity tracking broadcasts when needed, resets target mode to
     * location, and clears target-time lanes.
     */
    void TargetNothing() override;
    /**
     * Address: 0x007A82F0 (FUN_007A82F0, Moho::CameraImpl::TargetLocation)
     * Mangled: ?TargetLocation@CameraImpl@Moho@@UAEXABV?$Vector3@M@Wm3@@M@Z
     *
     * What it does:
     * Targets one world-space location with optional timed transition and
     * immediate focus/FOV update when `seconds == 0`.
     */
    void TargetLocation(const Wm3::Vec3f& position, float seconds) override;
    /**
     * Address: 0x007A8580 (FUN_007A8580, Moho::CameraImpl::TargetEntityBox)
     * Mangled: ?TargetEntityBox@CameraImpl@Moho@@UAEXPAVUserEntity@2@M@Z
     *
     * What it does:
     * Targets one entity by expanding its mesh-instance interpolated AABB on
     * the X/Z axes by `cam_EntityBoxExpand` and dispatches through `TargetBox`;
     * when `seconds == 0` additionally clears any active entity target by
     * dispatching through `TargetNothing`.
     */
    void TargetEntityBox(UserEntity* entity, float seconds) override;
    /**
     * Address: 0x007A8640 (FUN_007A8640, Moho::CameraImpl::TargetEntities)
     * Mangled: ?TargetEntities@CameraImpl@Moho@@UAEXABV?$WeakSet@VUserEntity@Moho@@@2@_NMM@Z
     *
     * What it does:
     * Replaces camera target weak-list from one entity weak-set, then starts
     * tracked or untracked multi-entity target behavior.
     */
    void TargetEntities(
      const SSelectionSetUserEntity& entities,
      bool trackEntities,
      float zoom,
      float seconds
    ) override;
    /**
     * Address: 0x007A83E0 (FUN_007A83E0, Moho::CameraImpl::TargetBox)
     * Mangled: ?TargetBox@CameraImpl@Moho@@UAEXABV?$AxisAlignedBox3@M@Wm3@@M@Z
     *
     * What it does:
     * Targets one world-space AABB, derives focus/near-zoom lanes from box
     * bounds, and optionally applies immediate focus+FOV clamping.
     */
    void TargetBox(const Wm3::AxisAlignedBox3f& targetBox, float seconds) override;
    /**
     * Address: 0x007A8D40 (FUN_007A8D40, Moho::CameraImpl::TargetManual)
     * Mangled: ?TargetManual@CameraImpl@Moho@@UAEXABV?$Vector3@M@Wm3@@MMMM@Z
     *
     * What it does:
     * Targets one world-space location plus heading/pitch/zoom lanes and
     * either applies the result immediately or seeds Hermite transition state.
     */
    void TargetManual(const Wm3::Vec3f& position, float heading, float pitch, float zoom, float seconds) override;
    /**
     * Address: 0x007A7290 (FUN_007A7290, Moho::CameraImpl::GetTargetEntity)
     * Mangled: ?GetTargetEntity@CameraImpl@Moho@@UBEPAVUserEntity@2@XZ
     *
     * What it does:
     * Returns current live entity target when target mode is entity/nose-cam.
     */
    [[nodiscard]] UserEntity* GetTargetEntity() const override;
    /**
     * Address: 0x007A71B0 (FUN_007A71B0, Moho::CameraImpl::CameraFollow)
     * Mangled: ?CameraFollow@CameraImpl@Moho@@UAEXABUSCamFollowParams@2@@Z
     *
     * What it does:
     * Promotes one follow target into the active camera target list when the
     * current entity-id gate still matches.
     */
    void CameraFollow(const SCamFollowParams& followParams) override;
    /**
     * Address: 0x007A8EE0 (FUN_007A8EE0, Moho::CameraImpl::TargetNextEntity)
     * Mangled: ?TargetNextEntity@CameraImpl@Moho@@UAEXXZ
     *
     * What it does:
     * Advances active entity-target cursor to the next live weak target,
     * prunes stale weak nodes, and emits tracking stop/start notifications.
     */
    void TargetNextEntity() override;
    /**
     * Address: 0x007A6C80 (Moho::CameraImpl::CameraGetOffset)
     * Slot: 18
     *
     * What it does:
     * Returns the world-camera offset vector used by listener metric updates.
     */
    [[nodiscard]] const Wm3::Vec3f& CameraGetOffset() const override;
    /**
     * Address: 0x007A6CA0 (Moho::CameraImpl::CameraGetTargetZoom)
     * Slot: 19
     */
    [[nodiscard]] float CameraGetTargetZoom() const override;
    /**
     * Address: 0x007A7310 (Moho::CameraImpl::GetMaxZoom)
     * Slot: 20
     */
    [[nodiscard]] float GetMaxZoom() const override;
    /**
     * Address: 0x007A73C0 (FUN_007A73C0, Moho::CameraImpl::SetMaxZoomMult)
     * Slot: 21
     *
     * What it does:
     * Updates one runtime multiplier that scales the max zoom limit.
     */
    void SetMaxZoomMult(float maxZoomMult) override;
    /**
     * Address: 0x007A6C90 (FUN_007A6C90, Moho::CameraImpl::CameraGetZoom)
     * Mangled: ?CameraGetZoom@CameraImpl@Moho@@UBEMXZ
     *
     * What it does:
     * Returns current camera zoom lane.
     */
    [[nodiscard]] float CameraGetZoom() const override;
    /**
     * Address: 0x007A6CD0 (FUN_007A6CD0, Moho::CameraImpl::CameraGetPitch)
     * Mangled: ?CameraGetPitch@CameraImpl@Moho@@UBEMXZ
     *
     * What it does:
     * Returns current camera pitch lane in radians.
     */
    [[nodiscard]] float CameraGetPitch() const override;
    /**
     * Address: 0x007A6CC0 (FUN_007A6CC0, Moho::CameraImpl::CameraGetHeading)
     * Mangled: ?CameraGetHeading@CameraImpl@Moho@@UBEMXZ
     *
     * What it does:
     * Returns current camera heading lane in radians.
     */
    [[nodiscard]] float CameraGetHeading() const override;
    /**
     * Address: 0x007A6DF0 (FUN_007A6DF0, Moho::CameraImpl::CameraSetPitch)
     * Mangled: ?CameraSetPitch@CameraImpl@Moho@@UAEXM@Z
     *
     * What it does:
     * Arms rotated mode, clears revert state, and stores current pitch lane.
     */
    void CameraSetPitch(float pitchRadians) override;
    /**
     * Address: 0x007A6E10 (FUN_007A6E10, Moho::CameraImpl::CameraSetHeading)
     * Mangled: ?CameraSetHeading@CameraImpl@Moho@@UAEXM@Z
     *
     * What it does:
     * Arms rotated mode, clears revert state, and stores current heading lane.
     */
    void CameraSetHeading(float headingRadians) override;
    /**
     * Address: 0x007A6CE0 (FUN_007A6CE0, Moho::CameraImpl::CameraSpin)
     * Mangled: ?CameraSpin@CameraImpl@Moho@@UAEXABV?$Vector2@M@Wm3@@@Z
     *
     * What it does:
     * Applies heading/pitch spin deltas from one 2D input vector using
     * zoom-scaled spin speed and clamps pitch to valid camera limits.
     */
    void CameraSpin(const Wm3::Vector2f& spinDelta) override;
    /**
     * Address: 0x007A6E30 (FUN_007A6E30, Moho::CameraImpl::CameraIsRotated)
     * Mangled: ?CameraIsRotated@CameraImpl@Moho@@UBE_NXZ
     *
     * What it does:
     * Returns whether rotated-camera mode is currently enabled.
     */
    [[nodiscard]] bool CameraIsRotated() const override;
    /**
     * Address: 0x007A6E40 (FUN_007A6E40, Moho::CameraImpl::CameraRevertRotation)
     * Mangled: ?CameraRevertRotation@CameraImpl@Moho@@UAEXXZ
     *
     * What it does:
     * Schedules a rotation revert when the camera is currently in rotated mode.
     */
    void CameraRevertRotation() override;
    /**
     * Address: 0x007A8240 (FUN_007A8240, Moho::CameraImpl::CameraSetPivot)
     * Slot: 30 (+0x78 of ??_7CameraImpl@Moho@@6B@ at 0x00E3C474, between
     * `CameraRevertRotation` at slot 29 and `CameraZoom` at slot 31 - read
     * straight out of the shipped image)
     *
     * IDA signature:
     * Wm3::Vector2f *__thiscall Moho::CameraImpl::CameraSetPivot(
     *     Moho::CameraImpl *this@<ecx>, Wm3::Vector2f *pivot);
     *
     * What it does:
     * Parks the screen-space point the next zoom/spin should pivot around.
     * The whole body is the two-float store `0x007A8246 fstp [ecx+36Ch]` /
     * `0x007A824F fstp [ecx+370h]`, which is `CameraImplRuntimeView::mPivot`
     * (CameraImpl.cpp). The `Wm3::Vector2f*` return is just the incoming
     * argument left in `eax`; no caller reads it.
     */
    void CameraSetPivot(const Wm3::Vector2f& pivot) override;
    /**
     * Address: 0x007A8260 (FUN_007A8260, Moho::CameraImpl::CameraZoom)
     * Mangled: ?CameraZoom@CameraImpl@Moho@@UAEXM@Z
     *
     * What it does:
     * Scales near-zoom exponentially from wheel/input delta and clamps it to
     * `[cam_NearZoom, GetMaxZoom()]`.
     */
    void CameraZoom(float zoomDelta) override;
    /**
     * Address: 0x007A6F00 (FUN_007A6F00, Moho::CameraImpl::CameraPan)
     * Mangled: ?CameraPan@CameraImpl@Moho@@UAEXABV?$Vector2@M@Wm3@@@Z
     * Slot: 32 (vtable ??_7CameraImpl@Moho@@6B@ at 0x00E3C474)
     *
     * IDA signature:
     * _DWORD *__thiscall Moho::CameraImpl::CameraPan(CameraImpl *this, const Wm3::Vector2f *delta);
     *
     * What it does:
     * Pans the camera target location across the ground plane by a 2D input
     * delta, unless the UI is in non-interactive (NIS) mode. The screen-space
     * delta is projected onto the camera's inverse-view right axis (row 0) and
     * a flattened forward axis (row 1 with Y zeroed and renormalized), scaled by
     * the current target zoom, the inverse viewport width, and `cam_PanSpeed`.
     * Panning first clears any active entity target through the virtual
     * `TargetNothing` lane.
     */
    void CameraPan(const Wm3::Vector2f& panDelta) override;
    /**
     * Address: 0x007A6A10 (FUN_007A6A10, Moho::CameraImpl::CameraSetOrtho)
     * Mangled: ?CameraSetOrtho@CameraImpl@Moho@@UAEX_N@Z
     *
     * What it does:
     * Stores orthographic-camera mode flag lane.
     */
    void CameraSetOrtho(bool enabled) override;
    /**
     * Address: 0x007A6A20 (FUN_007A6A20, Moho::CameraImpl::CameraIsOrtho)
     * Mangled: ?CameraIsOrtho@CameraImpl@Moho@@UAE_NXZ
     *
     * What it does:
     * Returns orthographic-camera mode flag lane.
     */
    [[nodiscard]] bool CameraIsOrtho() override;
    /**
     * Address: 0x007A72C0 (FUN_007A72C0, Moho::CameraImpl::LODMetric)
     * Slot: 45
     */
    [[nodiscard]] float LODMetric(const Wm3::Vec3f& offset) const override;
    /**
     * Address: 0x007A72F0 (FUN_007A72F0, ?SetLODScale@CameraImpl@Moho@@UAEXM@Z)
     *
     * What it does:
     * Updates embedded camera LOD scale used by projection/unprojection lanes.
     */
    void SetLODScale(float scale) override;
    /**
     * Address: 0x007A7120 (FUN_007A7120, Moho::CameraImpl::CanShake)
     * Mangled: ?CanShake@CameraImpl@Moho@@UAEX_N@Z
     *
     * What it does:
     * Enables or disables camera-shake application for this camera runtime.
     */
    void CanShake(bool canShake) override;
    /**
     * Address: 0x007A7130 (FUN_007A7130, Moho::CameraImpl::CameraShake)
     * Mangled: ?CameraShake@CameraImpl@Moho@@UAEXABUSCamShakeParams@2@@Z
     *
     * What it does:
     * Arms camera shake params when shaking is enabled and either the previous
     * shake finished or incoming shake has stronger minimum magnitude.
     */
    void CameraShake(const SCamShakeParams& shakeParams) override;
    /**
     * Address: 0x007A78F0 (FUN_007A78F0,
     *   ?GetAllSoundEntitiesInFrustum@CameraImpl@Moho@@UAEAAV?$fastvector_n@V?$WeakPtr@VUserEntity@Moho@@@Moho@@$0CI@@gpg@@XZ)
     * Slot: 39 (vtable ??_7CameraImpl@Moho@@6B@ at 0x00E3C474, VTABLE_CONFIRMED via
     * ctor 0x007A7950)
     *
     * IDA signature:
     * gpg::fastvector_n<Moho::WeakPtr<Moho::UserEntity>, 40> &__thiscall
     *   Moho::CameraImpl::GetAllSoundEntitiesInFrustum(Moho::CameraImpl *this);
     *
     * What it does:
     * Returns the first of the three frustum caches `CacheCameraFrustumUnits`
     * rebuilds -- every live entity currently inside the camera view, held as
     * weak references. The whole body is `lea eax, [ecx+460h]; retn`.
     *
     * Its one caller is `CUserSoundManager::UpdateSoundRequests`, which reaches
     * it through the vtable (`mov edx, [eax+9Ch]; call edx` at 0x008AC9FB), so
     * the slot has to exist and has to be this one. The three consecutive
     * words of the shipped vtable settle both facts: 0x00E3C510 holds
     * 0x007A78F0 (this), 0x00E3C514 holds 0x007A7900 (`GetAllUnitsInFrustum`,
     * slot 40) and 0x00E3C518 holds 0x007A7910 (`GetArmyUnitsInFrustum`, slot
     * 41), with `CameraShake` at 0x007A7130 immediately above in slot 38. The
     * `UAE` in the mangled name says the same thing -- public virtual.
     */
    [[nodiscard]] CameraFrustumUserEntityList& GetAllSoundEntitiesInFrustum() override;
    /**
     * Address: 0x007A7900 (FUN_007A7900, Moho::CameraImpl::GetAllUnitsInFrustum)
     * Mangled: ?GetAllUnitsInFrustum@CameraImpl@Moho@@UAEAAV?$fastvector_n@V?$WeakPtr@VUserEntity@Moho@@@Moho@@$0CI@@gpg@@XZ
     * Slot: 40 (vtable ??_7CameraImpl@Moho@@6B@ at 0x00E3C474, VTABLE_CONFIRMED via
     * ctor 0x007A7950)
     *
     * What it does:
     * One-line accessor returning the camera's *unfiltered* "every unit
     * currently in frustum" weak-vector lane (`mFrustumLaneB`, +0x5B0) - as
     * opposed to `GetArmyUnitsInFrustum()` below (slot 41, +0x700), which is
     * filtered down to the focus army's units.
     *
     * `CWldSession::RenderStrategicIcons` (0x0085B6E0) dispatches through
     * `[eax+0A0h]` at 0x0085BA71 - byte offset 0xA0 from the vtable head is
     * slot 40, confirmed by reading the shipped vtable directly out of
     * `bin/2025.7.1/ForgedAlliance.exe` at 0x00E3C514 (fixed-base, no
     * relocations to account for): that slot holds 0x007A7900, not
     * `GetArmyUnitsInFrustum` at 0x007A7910 (slot 41, +0xA4) as an earlier
     * pass's comment guessed. It then walks every on-screen unit to classify
     * it for the strategic-icon pass, matching "every visible unit" rather
     * than "focus army's units only".
     */
    [[nodiscard]] CameraFrustumUserEntityList* GetAllUnitsInFrustum() override;
    /**
     * Address: 0x007A7910 (FUN_007A7910, Moho::CameraImpl::GetArmyUnitsInFrustum)
     * Mangled: ?GetArmyUnitsInFrustum@CameraImpl@Moho@@UAEAAV?$fastvector_n@V?$WeakPtr@VUserEntity@Moho@@@Moho@@$0CI@@gpg@@XZ
     * Slot: 41 (vtable ??_7CameraImpl@Moho@@6B@ at 0x00E3C474, VTABLE_CONFIRMED via
     * ctor 0x007A7950)
     *
     * What it does:
     * Returns one cached weak-vector view of focus-army units currently in
     * camera frustum.
     */
    [[nodiscard]] CameraFrustumUserEntityList* GetArmyUnitsInFrustum() override;
    /**
     * Address: 0x007A7410 (FUN_007A7410, Moho::CameraImpl::GetViewBox)
     * Mangled: ?GetViewBox@CameraImpl@Moho@@UBE?AV?$AxisAlignedBox3@M@Wm3@@XZ
     *
     * What it does:
     * Returns an axis-aligned box centered on the target location with half
     * extents derived from half of the current near-zoom lane.
     */
    [[nodiscard]] Wm3::AxisAlignedBox3f GetViewBox() const override;
    /**
     * Address: 0x007A73E0 (FUN_007A73E0, Moho::CameraImpl::GetTargetPosition)
     * Mangled: ?GetTargetPosition@CameraImpl@Moho@@UBE?AV?$Vector3@M@Wm3@@XZ
     *
     * What it does:
     * Returns current target-position lane by value.
     */
    [[nodiscard]] Wm3::Vector3f GetTargetPosition() const override;




    /**
     * Address: 0x007A6DE0 (FUN_007A6DE0, Moho::CameraImpl::CameraHoldRotation)
     * Mangled: ?CameraHoldRotation@CameraImpl@Moho@@QAEXXZ
     *
     * What it does:
     * Arms camera rotation hold mode and clears any pending revert flag.
     */
    void CameraHoldRotation();
































    /**
     * Address: 0x007A8E90 (FUN_007A8E90, Moho::CameraImpl::SetZoom)
     * Mangled: ?SetZoom@CameraImpl@Moho@@QAEXMM@Z
     *
     * What it does:
     * Re-applies manual targeting at the current target position while keeping
     * the active heading and far-pitch lanes and substituting a new
     * zoom/seconds pair.
     */
    void SetZoom(float zoom, float seconds);





    /**
     * Address: 0x007A8A20 (FUN_007A8A20, Moho::CameraImpl::TargetNoseCam)
     * Mangled: ?TargetNoseCam@CameraImpl@Moho@@QAEXABV?$WeakSet@VUserEntity@Moho@@@2@MMMM@Z
     *
     * What it does:
     * Targets one entity list in nose-camera mode with pitch-adjust, zoom,
     * transition seconds, and transition parameter lanes.
     */
    void TargetNoseCam(
      const SSelectionSetUserEntity& entities,
      float pitchAdjust,
      float zoom,
      float seconds,
      float transition
    );

    /**
     * Address: 0x007A74C0 (FUN_007A74C0, Moho::CameraImpl::TimedMoveInit)
     * Mangled: ?TimedMoveInit@CameraImpl@Moho@@QAEXMM@Z
     *
     * What it does:
     * Seeds timed-move state lanes for position/zoom/pitch/heading transition.
     */
    void TimedMoveInit(float seconds, float transitionParam);

    /**
     * Address: 0x007A8940 (FUN_007A8940, Moho::CameraImpl::SetupHermite)
     * Mangled: ?SetupHermite@CameraImpl@Moho@@QAEXXZ
     *
     * What it does:
     * Derives Hermite delta lanes for target offset/heading/pitch/zoom when
     * ease-in/out mode is disabled.
     */
    void SetupHermite();

    /**
     * Address: 0x007A9320 (FUN_007A9320, Moho::CameraImpl::ClampTargetPos)
     * Mangled: ?ClampTargetPos@CameraImpl@Moho@@QAEXXZ
     *
     * What it does:
     * Clamps target X/Z to map or playable-rect bounds using zoom-proportional
     * extents.
     */
    void ClampTargetPos();

    /**
     * Address: 0x007A9470 (FUN_007A9470, Moho::CameraImpl::ClampFocusPos)
     * Mangled: ?ClampFocusPos@CameraImpl@Moho@@QAEXXZ
     *
     * What it does:
     * Projects one heading/pitch ray from current offset and snaps focus to the
     * terrain/water surface hit when valid.
     */
    void ClampFocusPos();

    /**
     * Address: 0x007A9550 (FUN_007A9550, Moho::CameraImpl::CalculateFOV)
     * Mangled: ?CalculateFOV@CameraImpl@Moho@@QAEXXZ
     *
     * What it does:
     * Recomputes far-FOV from logarithmic zoom interpolation between near/far
     * camera zoom envelopes.
     */
    void CalculateFOV();





    /**
     * Address: 0x007A6A30 (FUN_007A6A30, Moho::CameraImpl::SetTimeSource)
     * Mangled: ?SetTimeSource@CameraImpl@Moho@@QAEXW4ECamTimeSource@2@@Z
     *
     * What it does:
     * Stores the active runtime time-source selector in the camera runtime
     * view.
     */
    void SetTimeSource(ECamTimeSource timeSource);

    // -------------------------------------------------------------------------
    // Layout. These lanes were reached through a `CameraImplRuntimeView`
    // reinterpret_cast until 2026-09-21; they are the class's own state and
    // are declared here, with the offsets that cast asserted.
    //
    // The two bases fill +0x00..+0x4F exactly: `RCamCamera` is 0x0C and
    // `CScriptEvent` is 0x44. That also accounts for the `LuaObject` the old
    // view carried at +0x3C -- it is `CScriptObject::mLuaObj`, inherited, at
    // 0x0C (CScriptEvent base) + 0x10 (CScriptObject base) + 0x20.
    // -------------------------------------------------------------------------

    msvc8::string mName{};                                     // +0x050
    STIMap* mTerrainMap = nullptr;                             // +0x06C
    GeomCamera3 mCam{};                                        // +0x070
    float mVerticalZoomMetricScale = 0.0f;                     // +0x338
    std::uint8_t mIsOrtho = 0;                                 // +0x33C
    std::uint8_t mIsRotated = 0;                               // +0x33D
    std::uint8_t mRevertRotation = 0;                          // +0x33E
    std::uint8_t mPadding0x33F_ = 0;                           // +0x33F
    float mFarFov = 0.0f;                                      // +0x340
    float mFarPitch = 0.0f;                                    // +0x344
    float mCurrentPitch = 0.0f;                                // +0x348
    float mHeading = 0.0f;                                     // +0x34C
    float mHeadingZoom = 0.0f;                                 // +0x350
    float mTargetZoom = 0.0f;                                  // +0x354
    float mNearZoom = 0.0f;                                    // +0x358
    float mZoom = 0.0f;                                        // +0x35C
    Wm3::Vec3f mOffset{};                                      // +0x360
    Wm3::Vector2f mPivot{};                                    // +0x36C
    float mHeadingRate = 0.0f;                                 // +0x374
    float mZoomRate = 0.0f;                                    // +0x378
    std::int32_t mTargetType = 0;                              // +0x37C
    Wm3::Vec3f mTargetLocation{};                              // +0x380
    Wm3::AxisAlignedBox3f mTargetBox{};                        // +0x38C
    CameraTargetEntityList mTargetEntities{};                  // +0x3A4
    CameraTargetEntityNode* mActiveTargetEntityNode = nullptr; // +0x3B0
    float mTargetTimeLeft = 0.0f;                              // +0x3B4
    std::uint8_t mTargetTime = 0;                              // +0x3B8
    std::uint8_t mPadding0x3B9_[3]{};                          // +0x3B9
    std::int32_t mTimeSource = 0;                              // +0x3BC
    CameraTimeSourceRuntime* mTimeSources[2]{};                // +0x3C0 (System=0, Game=1)
    float mLastFrameTime = 0.0f;                               // +0x3C8
    std::uint8_t mEnableEaseInOut = 0;                         // +0x3CC
    std::uint8_t mPadding0x3CD_[3]{};                          // +0x3CD
    float mNoseCamPitchAdjust = 0.0f;                          // +0x3D0
    Wm3::Vec3f mTimedMoveOffset{};                             // +0x3D4
    float mTimedMoveZoom = 0.0f;                               // +0x3E0
    float mTimedMoveDuration = 0.0f;                           // +0x3E4
    float mTimedMoveTransitionParam = 0.0f;                    // +0x3E8
    float mTimedMoveStartTime = 0.0f;                          // +0x3EC
    float mTimedMovePitch = 0.0f;                              // +0x3F0
    float mTimedMoveHeading = 0.0f;                            // +0x3F4
    Wm3::Vec3f mHermiteOffsetStartDelta{};                     // +0x3F8
    Wm3::Vec3f mHermiteOffsetEndDelta{};                       // +0x404
    float mHermiteHeadingStartDelta = 0.0f;                    // +0x410
    float mHermiteHeadingEndDelta = 0.0f;                      // +0x414
    float mHermitePitchStartDelta = 0.0f;                      // +0x418
    float mHermitePitchEndDelta = 0.0f;                        // +0x41C
    float mHermiteZoomStartDelta = 0.0f;                       // +0x420
    float mHermiteZoomEndDelta = 0.0f;                         // +0x424
    SCamShakeState mCamShakeParams{};                          // +0x428
    std::uint8_t mCanShake = 0;                                // +0x44C
    std::uint8_t mPadding0x44D_[3]{};                          // +0x44D
    std::int32_t mAccType = 0;                                 // +0x450
    float mFrustumCacheTimer = 0.0f;                           // +0x454
    float mFrustumCacheZoomMark = 0.0f;                        // +0x458
    std::uint8_t mPadding0x45C_[4]{};                          // +0x45C

    // The three frustum weak-entity lanes. The constructor at 0x007A7950
    // points each lane's `mView` at its own `mInlineStorage[0]` sentinel; the
    // destructor at 0x007A7F00 walks each lane in reverse and detaches every
    // still-tracked weak entity owner before releasing heap-grown storage.
    // They are plain aggregates, so the compiler emits neither construction
    // nor destruction for them and that explicit wiring is real source.
    CameraFrustumUserEntityStorage mFrustumLaneA{};        // +0x460
    CameraFrustumUserEntityStorage mFrustumLaneB{};        // +0x5B0
    CameraFrustumUserEntityStorage mArmyUnitsInFrustum{};  // +0x700
    float mMaxZoomMult = 0.0f;                             // +0x850
    std::uint8_t mPadding0x854_[4]{};                      // +0x854
  };

  static_assert(offsetof(CameraImpl, mName) == 0x050, "CameraImpl::mName offset must be 0x050");
  static_assert(offsetof(CameraImpl, mTerrainMap) == 0x06C, "CameraImpl::mTerrainMap offset must be 0x06C");
  static_assert(offsetof(CameraImpl, mCam) == 0x070, "CameraImpl::mCam offset must be 0x070");
  static_assert(
    offsetof(CameraImpl, mVerticalZoomMetricScale) == 0x338,
    "CameraImpl::mVerticalZoomMetricScale offset must be 0x338"
  );
  static_assert(offsetof(CameraImpl, mIsOrtho) == 0x33C, "CameraImpl::mIsOrtho offset must be 0x33C");
  static_assert(offsetof(CameraImpl, mIsRotated) == 0x33D, "CameraImpl::mIsRotated offset must be 0x33D");
  static_assert(offsetof(CameraImpl, mRevertRotation) == 0x33E, "CameraImpl::mRevertRotation offset must be 0x33E");
  static_assert(offsetof(CameraImpl, mFarFov) == 0x340, "CameraImpl::mFarFov offset must be 0x340");
  static_assert(offsetof(CameraImpl, mFarPitch) == 0x344, "CameraImpl::mFarPitch offset must be 0x344");
  static_assert(offsetof(CameraImpl, mCurrentPitch) == 0x348, "CameraImpl::mCurrentPitch offset must be 0x348");
  static_assert(offsetof(CameraImpl, mHeading) == 0x34C, "CameraImpl::mHeading offset must be 0x34C");
  static_assert(offsetof(CameraImpl, mHeadingZoom) == 0x350, "CameraImpl::mHeadingZoom offset must be 0x350");
  static_assert(offsetof(CameraImpl, mTargetZoom) == 0x354, "CameraImpl::mTargetZoom offset must be 0x354");
  static_assert(offsetof(CameraImpl, mNearZoom) == 0x358, "CameraImpl::mNearZoom offset must be 0x358");
  static_assert(offsetof(CameraImpl, mZoom) == 0x35C, "CameraImpl::mZoom offset must be 0x35C");
  static_assert(offsetof(CameraImpl, mOffset) == 0x360, "CameraImpl::mOffset offset must be 0x360");
  static_assert(offsetof(CameraImpl, mPivot) == 0x36C, "CameraImpl::mPivot offset must be 0x36C");
  static_assert(offsetof(CameraImpl, mHeadingRate) == 0x374, "CameraImpl::mHeadingRate offset must be 0x374");
  static_assert(offsetof(CameraImpl, mZoomRate) == 0x378, "CameraImpl::mZoomRate offset must be 0x378");
  static_assert(offsetof(CameraImpl, mTargetType) == 0x37C, "CameraImpl::mTargetType offset must be 0x37C");
  static_assert(offsetof(CameraImpl, mTargetLocation) == 0x380, "CameraImpl::mTargetLocation offset must be 0x380");
  static_assert(offsetof(CameraImpl, mTargetBox) == 0x38C, "CameraImpl::mTargetBox offset must be 0x38C");
  static_assert(offsetof(CameraImpl, mTargetEntities) == 0x3A4, "CameraImpl::mTargetEntities offset must be 0x3A4");
  static_assert(
    offsetof(CameraImpl, mActiveTargetEntityNode) == 0x3B0,
    "CameraImpl::mActiveTargetEntityNode offset must be 0x3B0"
  );
  static_assert(offsetof(CameraImpl, mTargetTimeLeft) == 0x3B4, "CameraImpl::mTargetTimeLeft offset must be 0x3B4");
  static_assert(offsetof(CameraImpl, mTargetTime) == 0x3B8, "CameraImpl::mTargetTime offset must be 0x3B8");
  static_assert(offsetof(CameraImpl, mTimeSource) == 0x3BC, "CameraImpl::mTimeSource offset must be 0x3BC");
  static_assert(offsetof(CameraImpl, mTimeSources) == 0x3C0, "CameraImpl::mTimeSources offset must be 0x3C0");
  static_assert(offsetof(CameraImpl, mLastFrameTime) == 0x3C8, "CameraImpl::mLastFrameTime offset must be 0x3C8");
  static_assert(offsetof(CameraImpl, mEnableEaseInOut) == 0x3CC, "CameraImpl::mEnableEaseInOut offset must be 0x3CC");
  static_assert(
    offsetof(CameraImpl, mNoseCamPitchAdjust) == 0x3D0,
    "CameraImpl::mNoseCamPitchAdjust offset must be 0x3D0"
  );
  static_assert(offsetof(CameraImpl, mTimedMoveOffset) == 0x3D4, "CameraImpl::mTimedMoveOffset offset must be 0x3D4");
  static_assert(offsetof(CameraImpl, mTimedMoveZoom) == 0x3E0, "CameraImpl::mTimedMoveZoom offset must be 0x3E0");
  static_assert(
    offsetof(CameraImpl, mTimedMoveStartTime) == 0x3EC,
    "CameraImpl::mTimedMoveStartTime offset must be 0x3EC"
  );
  static_assert(
    offsetof(CameraImpl, mTimedMoveHeading) == 0x3F4,
    "CameraImpl::mTimedMoveHeading offset must be 0x3F4"
  );
  static_assert(
    offsetof(CameraImpl, mHermiteOffsetStartDelta) == 0x3F8,
    "CameraImpl::mHermiteOffsetStartDelta offset must be 0x3F8"
  );
  static_assert(
    offsetof(CameraImpl, mHermiteOffsetEndDelta) == 0x404,
    "CameraImpl::mHermiteOffsetEndDelta offset must be 0x404"
  );
  static_assert(
    offsetof(CameraImpl, mHermiteZoomEndDelta) == 0x424,
    "CameraImpl::mHermiteZoomEndDelta offset must be 0x424"
  );
  static_assert(offsetof(CameraImpl, mCamShakeParams) == 0x428, "CameraImpl::mCamShakeParams offset must be 0x428");
  static_assert(offsetof(CameraImpl, mCanShake) == 0x44C, "CameraImpl::mCanShake offset must be 0x44C");
  static_assert(offsetof(CameraImpl, mAccType) == 0x450, "CameraImpl::mAccType offset must be 0x450");
  static_assert(
    offsetof(CameraImpl, mFrustumCacheTimer) == 0x454,
    "CameraImpl::mFrustumCacheTimer offset must be 0x454"
  );
  static_assert(
    offsetof(CameraImpl, mFrustumCacheZoomMark) == 0x458,
    "CameraImpl::mFrustumCacheZoomMark offset must be 0x458"
  );
  static_assert(offsetof(CameraImpl, mFrustumLaneA) == 0x460, "CameraImpl::mFrustumLaneA offset must be 0x460");
  static_assert(offsetof(CameraImpl, mFrustumLaneB) == 0x5B0, "CameraImpl::mFrustumLaneB offset must be 0x5B0");
  static_assert(
    offsetof(CameraImpl, mArmyUnitsInFrustum) == 0x700,
    "CameraImpl::mArmyUnitsInFrustum offset must be 0x700"
  );
  static_assert(offsetof(CameraImpl, mMaxZoomMult) == 0x850, "CameraImpl::mMaxZoomMult offset must be 0x850");
  static_assert(sizeof(CameraImpl) == 0x858, "CameraImpl size must be 0x858");

  /**
   * The camera's own broadcaster ring node, at `camera+0x04` - the lane every
   * `CameraImpl` tracking broadcast walks and the one `func_SetWorldCamera`
   * splices the global tracking listener into.
   */
  [[nodiscard]] Broadcaster* CameraBroadcasterLink(CameraImpl* camera) noexcept;

  template <>
  class CScrLuaMetatableFactory<CameraImpl> final : public CScrLuaObjectFactory
  {
  public:
    [[nodiscard]]
    static CScrLuaMetatableFactory& Instance();

  protected:
    LuaPlus::LuaObject Create(LuaPlus::LuaState* state) override;

  private:
    static CScrLuaMetatableFactory sInstance;
  };

  static_assert(
    sizeof(CScrLuaMetatableFactory<CameraImpl>) == 0x08,
    "CScrLuaMetatableFactory<CameraImpl> size must be 0x08"
  );

  /**
   * Address: 0x007B0A90 (FUN_007B0A90, func_CreateLuaCameraImpl)
   *
   * What it does:
   * Returns cached `CameraImpl` metatable object from Lua object-factory
   * storage.
   */
  LuaPlus::LuaObject* func_CreateLuaCameraImpl(LuaPlus::LuaObject* object, LuaPlus::LuaState* state);

  /**
   * Address: 0x007AB080 (FUN_007AB080, cfunc_GetCamera)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_GetCameraL`.
   */
  int cfunc_GetCamera(lua_State* luaContext);

  /**
   * Address: 0x007AB0A0 (FUN_007AB0A0, func_GetCamera_LuaFuncDef)
   *
   * What it does:
   * Publishes global Lua binder metadata for `GetCamera(name)`.
   */
  CScrLuaInitForm* func_GetCamera_LuaFuncDef();

  /**
   * Address: 0x007AB100 (FUN_007AB100, cfunc_GetCameraL)
   *
   * What it does:
   * Resolves one camera name from Lua and pushes the camera script object or
   * nil when no camera matches.
   */
  int cfunc_GetCameraL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007AB4E0 (FUN_007AB4E0, cfunc_CameraImplSnapTo)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_CameraImplSnapToL`.
   */
  int cfunc_CameraImplSnapTo(lua_State* luaContext);

  /**
   * Address: 0x007AB500 (FUN_007AB500, func_CameraImplSnapTo_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:SnapTo`.
   */
  CScrLuaInitForm* func_CameraImplSnapTo_LuaFuncDef();

  /**
   * Address: 0x007AB560 (FUN_007AB560, cfunc_CameraImplSnapToL)
   *
   * What it does:
   * Validates `Camera:SnapTo(position, orientationHPR, zoom)`, resolves Lua
   * payloads, and dispatches immediate manual camera targeting.
   */
  int cfunc_CameraImplSnapToL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007AB6E0 (FUN_007AB6E0, cfunc_CameraImplMoveTo)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CameraImplMoveToL`.
   */
  int cfunc_CameraImplMoveTo(lua_State* luaContext);

  /**
   * Address: 0x007AB1B0 (FUN_007AB1B0, cfunc_CameraImplMoveToRegion)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CameraImplMoveToRegionL`.
   */
  int cfunc_CameraImplMoveToRegion(lua_State* luaContext);

  /**
   * Address: 0x007AB1D0 (FUN_007AB1D0, func_CameraImplMoveToRegion_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:MoveToRegion`.
   */
  CScrLuaInitForm* func_CameraImplMoveToRegion_LuaFuncDef();

  /**
   * Address: 0x007AB230 (FUN_007AB230, cfunc_CameraImplMoveToRegionL)
   *
   * What it does:
   * Validates `Camera:MoveTo(region[,seconds])`, quantizes region corners to
   * terrain grid cell centers, samples corner elevations, and targets one
   * world box transition.
   */
  int cfunc_CameraImplMoveToRegionL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007AB760 (FUN_007AB760, cfunc_CameraImplMoveToL)
   *
   * What it does:
   * Validates `Camera:MoveTo(position, orientationHPR, zoom, seconds)`,
   * resolves typed camera/vector payloads from Lua, and dispatches the manual
   * camera-target lane.
   */
  int cfunc_CameraImplMoveToL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007AC760 (FUN_007AC760, cfunc_CameraImplSetZoom)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CameraImplSetZoomL`.
   */
  int cfunc_CameraImplSetZoom(lua_State* luaContext);

  /**
   * Address: 0x007AC780 (FUN_007AC780, func_CameraImplSetZoom_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:SetZoom`.
   */
  CScrLuaInitForm* func_CameraImplSetZoom_LuaFuncDef();

  /**
   * Address: 0x007AC7E0 (FUN_007AC7E0, cfunc_CameraImplSetZoomL)
   *
   * What it does:
   * Validates `Camera:SetZoom(zoom,seconds)`, keeps current target position and
   * heading/pitch lanes, and dispatches manual camera targeting with new zoom
   * and transition seconds.
   */
  int cfunc_CameraImplSetZoomL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007AC930 (FUN_007AC930, cfunc_CameraImplSetTargetZoom)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CameraImplSetTargetZoomL`.
   */
  int cfunc_CameraImplSetTargetZoom(lua_State* luaContext);

  /**
   * Address: 0x007AC950 (FUN_007AC950, func_CameraImplSetTargetZoom_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:SetTargetZoom`.
   */
  CScrLuaInitForm* func_CameraImplSetTargetZoom_LuaFuncDef();

  /**
   * Address: 0x007AC9B0 (FUN_007AC9B0, cfunc_CameraImplSetTargetZoomL)
   *
   * What it does:
   * Validates `Camera:SetTargetZoom(zoom)` and updates one runtime near-zoom
   * lane directly from Lua.
   */
  int cfunc_CameraImplSetTargetZoomL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007AD720 (FUN_007AD720, cfunc_CameraImplSetMaxZoomMult)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CameraImplSetMaxZoomMultL`.
   */
  int cfunc_CameraImplSetMaxZoomMult(lua_State* luaContext);

  /**
   * Address: 0x007AD740 (FUN_007AD740, func_CameraImplSetMaxZoomMult_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:SetMaxZoomMult`.
   */
  CScrLuaInitForm* func_CameraImplSetMaxZoomMult_LuaFuncDef();

  /**
   * Address: 0x007AD7A0 (FUN_007AD7A0, cfunc_CameraImplSetMaxZoomMultL)
   *
   * What it does:
   * Validates `Camera:SetMaxZoomMult(mult)` and applies one max-zoom
   * multiplier through the camera virtual lane.
   */
  int cfunc_CameraImplSetMaxZoomMultL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007AB700 (FUN_007AB700, func_CameraImplMoveTo_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:MoveTo`.
   */
  CScrLuaInitForm* func_CameraImplMoveTo_LuaFuncDef();

  /**
   * Address: 0x007AB930 (FUN_007AB930, cfunc_CameraImplReset)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_CameraImplResetL`.
   */
  int cfunc_CameraImplReset(lua_State* luaContext);

  /**
   * Address: 0x007AB9B0 (FUN_007AB9B0, cfunc_CameraImplResetL)
   *
   * What it does:
   * Validates `Camera:Reset()`, resolves one camera payload, and invokes
   * `CameraImpl::CameraReset`.
   */
  int cfunc_CameraImplResetL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007AB950 (FUN_007AB950, func_CameraImplReset_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:Reset`.
   */
  CScrLuaInitForm* func_CameraImplReset_LuaFuncDef();

  /**
   * Address: 0x007ABA80 (FUN_007ABA80, func_CameraImplTrackEntities_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:TrackEntities`.
   */
  CScrLuaInitForm* func_CameraImplTrackEntities_LuaFuncDef();

  /**
   * Address: 0x007ABA60 (FUN_007ABA60, cfunc_CameraImplTrackEntities)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CameraImplTrackEntitiesL`.
   */
  int cfunc_CameraImplTrackEntities(lua_State* luaContext);

  /**
   * Address: 0x007ABAE0 (FUN_007ABAE0, cfunc_CameraImplTrackEntitiesL)
   *
   * What it does:
   * Validates `Camera:TrackEntities(ents,zoom,seconds)` and dispatches tracked
   * multi-entity targeting.
   */
  int cfunc_CameraImplTrackEntitiesL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007ABE60 (FUN_007ABE60, func_CameraImplTargetEntities_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:TargetEntities`.
   */
  CScrLuaInitForm* func_CameraImplTargetEntities_LuaFuncDef();

  /**
   * Address: 0x007ABE40 (FUN_007ABE40, cfunc_CameraImplTargetEntities)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CameraImplTargetEntitiesL`.
   */
  int cfunc_CameraImplTargetEntities(lua_State* luaContext);

  /**
   * Address: 0x007ABEC0 (FUN_007ABEC0, cfunc_CameraImplTargetEntitiesL)
   *
   * What it does:
   * Validates `Camera:TargetEntities(ents,zoom,seconds)` and dispatches
   * untracked multi-entity targeting.
   */
  int cfunc_CameraImplTargetEntitiesL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007AC1E0 (FUN_007AC1E0, func_CameraImplNoseCam_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:NoseCam`.
   */
  CScrLuaInitForm* func_CameraImplNoseCam_LuaFuncDef();

  /**
   * Address: 0x007AC1C0 (FUN_007AC1C0, cfunc_CameraImplNoseCam)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_CameraImplNoseCamL`.
   */
  int cfunc_CameraImplNoseCam(lua_State* luaContext);

  /**
   * Address: 0x007AC240 (FUN_007AC240, cfunc_CameraImplNoseCamL)
   *
   * What it does:
   * Validates `Camera:NoseCam(ent,pitchAdjust,zoom,seconds,transition)` and
   * dispatches nose-camera targeting.
   */
  int cfunc_CameraImplNoseCamL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007AC520 (FUN_007AC520, func_CameraImplHoldRotation_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:HoldRotation`.
   */
  CScrLuaInitForm* func_CameraImplHoldRotation_LuaFuncDef();

  /**
   * Address: 0x007AC500 (FUN_007AC500, cfunc_CameraImplHoldRotation)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CameraImplHoldRotationL`.
   */
  int cfunc_CameraImplHoldRotation(lua_State* luaContext);

  /**
   * Address: 0x007AC580 (FUN_007AC580, cfunc_CameraImplHoldRotationL)
   *
   * What it does:
   * Validates `Camera:HoldRotation()`, resolves one camera payload, and
   * applies hold-rotation runtime flags.
   */
  int cfunc_CameraImplHoldRotationL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007AC650 (FUN_007AC650, func_CameraImplRevertRotation_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:RevertRotation`.
   */
  CScrLuaInitForm* func_CameraImplRevertRotation_LuaFuncDef();

  /**
   * Address: 0x007AC630 (FUN_007AC630, cfunc_CameraImplRevertRotation)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CameraImplRevertRotationL`.
   */
  int cfunc_CameraImplRevertRotation(lua_State* luaContext);

  /**
   * Address: 0x007AC6B0 (FUN_007AC6B0, cfunc_CameraImplRevertRotationL)
   *
   * What it does:
   * Validates `Camera:RevertRotation()`, resolves one camera payload, and
   * invokes `CameraImpl::CameraRevertRotation`.
   */
  int cfunc_CameraImplRevertRotationL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007AD650 (FUN_007AD650, cfunc_CameraImplGetMinZoom)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CameraImplGetMinZoomL`.
   */
  int cfunc_CameraImplGetMinZoom(lua_State* luaContext);

  /**
   * Address: 0x007AD670 (FUN_007AD670, func_CameraImplGetMinZoom_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:GetMinZoom`.
   */
  CScrLuaInitForm* func_CameraImplGetMinZoom_LuaFuncDef();

  /**
   * Address: 0x007ACC40 (FUN_007ACC40, cfunc_CameraImplGetZoom)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CameraImplGetZoomL`.
   */
  int cfunc_CameraImplGetZoom(lua_State* luaContext);

  /**
   * Address: 0x007ACC60 (FUN_007ACC60, func_CameraImplGetZoom_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:GetZoom`.
   */
  CScrLuaInitForm* func_CameraImplGetZoom_LuaFuncDef();

  /**
   * Address: 0x007ACCC0 (FUN_007ACCC0, cfunc_CameraImplGetZoomL)
   *
   * What it does:
   * Validates `Camera:GetZoom()`, resolves one camera payload, and pushes the
   * current target-zoom scalar.
   */
  int cfunc_CameraImplGetZoomL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007ACDA0 (FUN_007ACDA0, func_CameraImplGetFocusPosition_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:GetFocusPosition`.
   */
  CScrLuaInitForm* func_CameraImplGetFocusPosition_LuaFuncDef();

  /**
   * Address: 0x007ACEE0 (FUN_007ACEE0, cfunc_CameraImplSaveSettings)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CameraImplSaveSettingsL`.
   */
  int cfunc_CameraImplSaveSettings(lua_State* luaContext);

  /**
   * Address: 0x007ACF00 (FUN_007ACF00, func_CameraImplSaveSettings_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:SaveSettings`.
   */
  CScrLuaInitForm* func_CameraImplSaveSettings_LuaFuncDef();

  /**
   * Address: 0x007ACF60 (FUN_007ACF60, cfunc_CameraImplSaveSettingsL)
   *
   * What it does:
   * Captures one camera snapshot table (`Focus`, `Zoom`, `Pitch`, `Heading`)
   * from the current camera runtime and returns it to Lua.
   */
  int cfunc_CameraImplSaveSettingsL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007AD0D0 (FUN_007AD0D0, cfunc_CameraImplRestoreSettings)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CameraImplRestoreSettingsL`.
   */
  int cfunc_CameraImplRestoreSettings(lua_State* luaContext);

  /**
   * Address: 0x007AD0F0 (FUN_007AD0F0, func_CameraImplRestoreSettings_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:RestoreSettings`.
   */
  CScrLuaInitForm* func_CameraImplRestoreSettings_LuaFuncDef();

  /**
   * Address: 0x007AD150 (FUN_007AD150, cfunc_CameraImplRestoreSettingsL)
   *
   * What it does:
   * Reads one saved camera snapshot table (`Focus`, `Zoom`, `Pitch`,
   * `Heading`), restores manual target state immediately, then clears timed
   * targeting and reapplies rotation-revert semantics.
   */
  int cfunc_CameraImplRestoreSettingsL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007AD3D0 (FUN_007AD3D0, cfunc_CameraImplGetTargetZoom)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CameraImplGetTargetZoomL`.
   */
  int cfunc_CameraImplGetTargetZoom(lua_State* luaContext);

  /**
   * Address: 0x007AD3F0 (FUN_007AD3F0, func_CameraImplGetTargetZoom_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:GetTargetZoom`.
   */
  CScrLuaInitForm* func_CameraImplGetTargetZoom_LuaFuncDef();

  /**
   * Address: 0x007AD450 (FUN_007AD450, cfunc_CameraImplGetTargetZoomL)
   *
   * What it does:
   * Validates `Camera:GetTargetZoom()`, resolves typed camera payload, pushes
   * current near-zoom lane, and returns one Lua result.
   */
  int cfunc_CameraImplGetTargetZoomL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007AD510 (FUN_007AD510, cfunc_CameraImplGetMaxZoom)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CameraImplGetMaxZoomL`.
   */
  int cfunc_CameraImplGetMaxZoom(lua_State* luaContext);

  /**
   * Address: 0x007AD530 (FUN_007AD530, func_CameraImplGetMaxZoom_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:GetMaxZoom`.
   */
  CScrLuaInitForm* func_CameraImplGetMaxZoom_LuaFuncDef();

  /**
   * Address: 0x007AD590 (FUN_007AD590, cfunc_CameraImplGetMaxZoomL)
   *
   * What it does:
   * Validates `Camera:GetMaxZoom()`, resolves typed camera payload, queries
   * runtime max zoom through virtual lane, and returns one Lua result.
   */
  int cfunc_CameraImplGetMaxZoomL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007AD6D0 (FUN_007AD6D0, cfunc_CameraImplGetMinZoomL)
   *
   * What it does:
   * Validates `Camera:GetMinZoom()`, pushes the global near-zoom value, and
   * returns one Lua result.
   */
  int cfunc_CameraImplGetMinZoomL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007ACAA0 (FUN_007ACAA0, cfunc_CameraImplSetAccMode)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CameraImplSetAccModeL`.
   */
  int cfunc_CameraImplSetAccMode(lua_State* luaContext);

  /**
   * Address: 0x007ACB20 (FUN_007ACB20, cfunc_CameraImplSetAccModeL)
   *
   * What it does:
   * Validates `Camera:SetAccMode(accTypeName)`, resolves typed camera payload
   * and one string mode token from Lua, then dispatches
   * `CameraImpl::CameraSetAccType`.
   */
  int cfunc_CameraImplSetAccModeL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007ACAC0 (FUN_007ACAC0, func_CameraImplSetAccMode_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:SetAccMode`.
   */
  CScrLuaInitForm* func_CameraImplSetAccMode_LuaFuncDef();

  /**
   * Address: 0x007AD890 (FUN_007AD890, cfunc_CameraImplSpin)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to `cfunc_CameraImplSpinL`.
   */
  int cfunc_CameraImplSpin(lua_State* luaContext);

  /**
   * Address: 0x007AD910 (FUN_007AD910, cfunc_CameraImplSpinL)
   *
   * What it does:
   * Reads heading/optional zoom spin rates from Lua and arms camera spin target
   * lanes for Hermite targeting.
   */
  int cfunc_CameraImplSpinL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007AD8B0 (FUN_007AD8B0, func_CameraImplSpin_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:Spin`.
   */
  CScrLuaInitForm* func_CameraImplSpin_LuaFuncDef();

  /**
   * Address: 0x007ADAB0 (FUN_007ADAB0, func_CameraImplUseGameClock_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:UseGameClock`.
   */
  CScrLuaInitForm* func_CameraImplUseGameClock_LuaFuncDef();

  /**
   * Address: 0x007ADA90 (FUN_007ADA90, cfunc_CameraImplUseGameClock)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CameraImplUseGameClockL`.
   */
  int cfunc_CameraImplUseGameClock(lua_State* luaContext);

  /**
   * Address: 0x007ADB10 (FUN_007ADB10, cfunc_CameraImplUseGameClockL)
   *
   * What it does:
   * Validates `Camera:UseGameClock()`, resolves one camera payload, and
   * switches camera timing to game-clock mode.
   */
  int cfunc_CameraImplUseGameClockL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007ADBE0 (FUN_007ADBE0, func_CameraImplUseSystemClock_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:UseSystemClock`.
   */
  CScrLuaInitForm* func_CameraImplUseSystemClock_LuaFuncDef();

  /**
   * Address: 0x007ADBC0 (FUN_007ADBC0, cfunc_CameraImplUseSystemClock)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CameraImplUseSystemClockL`.
   */
  int cfunc_CameraImplUseSystemClock(lua_State* luaContext);

  /**
   * Address: 0x007ADC40 (FUN_007ADC40, cfunc_CameraImplUseSystemClockL)
   *
   * What it does:
   * Validates `Camera:UseSystemClock()`, resolves one camera payload, and
   * switches camera timing to system-clock mode.
   */
  int cfunc_CameraImplUseSystemClockL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007ADD10 (FUN_007ADD10, func_CameraImplEnableEaseInOut_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:EnableEaseInOut`.
   */
  CScrLuaInitForm* func_CameraImplEnableEaseInOut_LuaFuncDef();

  /**
   * Address: 0x007ADCF0 (FUN_007ADCF0, cfunc_CameraImplEnableEaseInOut)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CameraImplEnableEaseInOutL`.
   */
  int cfunc_CameraImplEnableEaseInOut(lua_State* luaContext);

  /**
   * Address: 0x007ADD70 (FUN_007ADD70, cfunc_CameraImplEnableEaseInOutL)
   *
   * What it does:
   * Validates `Camera:EnableEaseInOut()`, resolves one camera payload, and
   * enables ease-in/out targeting behavior.
   */
  int cfunc_CameraImplEnableEaseInOutL(LuaPlus::LuaState* state);

  /**
   * Address: 0x007ADE40 (FUN_007ADE40, func_CameraImplDisableEaseInOut_LuaFuncDef)
   *
   * What it does:
   * Publishes Lua binder metadata for `CameraImpl:DisableEaseInOut`.
   */
  CScrLuaInitForm* func_CameraImplDisableEaseInOut_LuaFuncDef();

  /**
   * Address: 0x007ADE20 (FUN_007ADE20, cfunc_CameraImplDisableEaseInOut)
   *
   * What it does:
   * Unwraps raw Lua callback context and forwards to
   * `cfunc_CameraImplDisableEaseInOutL`.
   */
  int cfunc_CameraImplDisableEaseInOut(lua_State* luaContext);

  /**
   * Address: 0x007ADEA0 (FUN_007ADEA0, cfunc_CameraImplDisableEaseInOutL)
   *
   * What it does:
   * Validates `Camera:DisableEaseInOut()`, resolves one camera payload, and
   * disables ease-in/out targeting behavior.
   */
  int cfunc_CameraImplDisableEaseInOutL(LuaPlus::LuaState* state);

  static_assert(sizeof(RCamCamera) == 0x0Cu, "RCamCamera size must be 0x0C (vtable + Broadcaster prev/next)");
  static_assert(
    offsetof(CameraImpl, mName) == 0x0Cu + sizeof(CScriptEvent),
    "CameraImpl's two real bases, RCamCamera then CScriptEvent, must sit back to back with no padding"
  );
  static_assert(
    sizeof(CameraImpl) == kCameraImplRuntimeSize,
    "CameraImpl must be exactly the 0x858-byte block RCamManager::CreateCamera allocates"
  );

  /**
   * Address: 0x00871640 (FUN_00871640, func_SetWorldCamera)
   *
   * Registers `camera` as the world camera by splicing its Broadcaster subobject
   * (camera+0x04) into the process-global camera-tracking-listener registry.
   */
  void func_SetWorldCamera(CameraImpl* camera);
} // namespace moho
