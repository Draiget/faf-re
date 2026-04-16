#include "moho/render/Shadow.h"

#include <Windows.h>

#include <new>

namespace
{
  struct ShadowRuntimeSharedRefRuntimeView
  {
    void* mVtable = nullptr;             // +0x00
    volatile long mStrongRefs = 0;       // +0x04
    volatile long mWeakRefs = 0;         // +0x08
  };

  static_assert(sizeof(ShadowRuntimeSharedRefRuntimeView) == 0x0C, "ShadowRuntimeSharedRefRuntimeView size must be 0xC");
  static_assert(
    offsetof(ShadowRuntimeSharedRefRuntimeView, mStrongRefs) == 0x04,
    "ShadowRuntimeSharedRefRuntimeView::mStrongRefs offset must be 0x4"
  );
  static_assert(
    offsetof(ShadowRuntimeSharedRefRuntimeView, mWeakRefs) == 0x08,
    "ShadowRuntimeSharedRefRuntimeView::mWeakRefs offset must be 0x8"
  );

  using ReleaseVirtualFn = void(__thiscall*)(ShadowRuntimeSharedRefRuntimeView*);

  [[nodiscard]] inline ReleaseVirtualFn ResolveReleaseVirtual(
    ShadowRuntimeSharedRefRuntimeView* const resource,
    const std::size_t slotIndex
  ) noexcept
  {
    auto** const vtable = reinterpret_cast<void**>(resource->mVtable);
    return reinterpret_cast<ReleaseVirtualFn>(vtable[slotIndex]);
  }

  void ReleaseShadowRuntimeSharedRef(moho::ShadowRuntimeSharedRef* const resource) noexcept
  {
    auto* const runtime = reinterpret_cast<ShadowRuntimeSharedRefRuntimeView*>(resource);
    if (runtime == nullptr) {
      return;
    }

    if (::InterlockedDecrement(&runtime->mStrongRefs) == 0) {
      ResolveReleaseVirtual(runtime, 1)(runtime);
      if (::InterlockedDecrement(&runtime->mWeakRefs) == 0) {
        ResolveReleaseVirtual(runtime, 2)(runtime);
      }
    }
  }

  /**
   * Address: 0x007FE760 (FUN_007FE760)
   *
   * What it does:
   * Clears shadow fidelity/size state and resets all seven runtime
   * `(state,shared-ref)` lanes at `+0x2E0`, releasing each previous shared-ref.
   */
  [[maybe_unused]] int ResetShadowRuntimeLanesAndReleaseRefs(
    moho::Shadow* const shadow
  ) noexcept
  {
    shadow->mShadowFidelity = 0;
    shadow->mShadowBlurEnabled = false;
    for (moho::ShadowRuntimeLane& lane : shadow->mRuntimeLanes) {
      lane.mState = 0;
      moho::ShadowRuntimeSharedRef* const previous = lane.mResource;
      lane.mResource = nullptr;
      ReleaseShadowRuntimeSharedRef(previous);
    }
    shadow->mShadowSize = 0;
    return 0;
  }

  struct BlinkyBoxListNode
  {
    BlinkyBoxListNode* next;
    BlinkyBoxListNode* prev;
  };

  BlinkyBoxListNode gBlinkyBoxesListHead{&gBlinkyBoxesListHead, &gBlinkyBoxesListHead};

  /**
   * Address: 0x007FE040 (FUN_007FE040)
   *
   * What it does:
   * Unlinks one blinky-box node from its current intrusive list and reinserts
   * it at the head of the global blinky-box list.
   */
  [[maybe_unused]] [[nodiscard]] BlinkyBoxListNode* RelinkBlinkyBoxNodeToGlobalHead(BlinkyBoxListNode* const node)
  {
    if (node == nullptr || node->next == nullptr || node->prev == nullptr) {
      return node;
    }

    node->next->prev = node->prev;
    node->prev->next = node->next;
    node->next = node;
    node->prev = node;

    node->next = gBlinkyBoxesListHead.next;
    node->prev = &gBlinkyBoxesListHead;
    gBlinkyBoxesListHead.next = node;
    node->next->prev = node;
    return node;
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x007FE120 (FUN_007FE120, ??0Shadow@Moho@@QAE@@Z)
   *
   * What it does:
   * Initializes shadow-renderer fidelity/size flags, constructs the embedded
   * camera at `+0x18`, and clears runtime state lanes.
   */
  Shadow::Shadow()
    : mShadowFidelity(0)
    , mShadowBlurEnabled(false)
    , mShadowSize(0)
    , mUnknown14(false)
    , mCamera()
    , mRuntimeLanes{}
  {}

  /**
   * Address: 0x007FE200 (FUN_007FE200, ??1Shadow@Moho@@UAE@XZ)
   *
   * What it does:
   * Runs non-deleting teardown for one shadow runtime object.
   */
  Shadow::~Shadow()
  {
    (void)ResetShadowRuntimeLanesAndReleaseRefs(this);
  }

  /**
   * Address: 0x007FE1A0 (FUN_007FE1A0)
   *
   * What it does:
   * Runs one deleting-destructor thunk for `Shadow`, forwarding through
   * `Shadow::~Shadow` and optional storage release.
   */
  [[nodiscard]] Shadow* DestroyShadowDeleting(Shadow* const shadow, const unsigned char deleteFlag)
  {
    shadow->~Shadow();
    if ((deleteFlag & 1u) != 0u) {
      ::operator delete(static_cast<void*>(shadow));
    }
    return shadow;
  }
} // namespace moho

