#include "CSimSoundManager.h"

#include <algorithm>
#include <cstddef>
#include <new>

#include "moho/entity/Entity.h"

namespace
{
  using LoopNode = moho::TDatListItem<moho::HSound, void>;
  using LoopList = moho::TDatList<moho::HSound, void>;

  moho::HSound* LoopOwnerFromNode(LoopNode* node)
  {
    return LoopList::owner_from_member_node<moho::HSound, &moho::HSound::mSimLoopLink>(node);
  }

  /**
   * Address: 0x00761860 (FUN_00761860, inlined push-back lane)
   *
   * What it does:
   * Appends one `SAudioRequest` into the owner request queue. The binary
   * emits this append sequence as a partially-inlined helper at
   * `0x00761860` for each call site (`AddEntitySound`, `AddLoop`,
   * `StopLoop`). When the active-end lane equals the capacity lane it
   * forwards to the grow-and-emplace helper at `0x00761F80`; otherwise
   * it copies the request payload into the next slot and bumps the
   * active-end pointer. Expressed here as a direct `fastvector::PushBack`
   * call which inlines to the same control flow at
   * `sizeof(SAudioRequest)=0x1C` stride.
   */
  void QueueRequest(moho::CSimSoundManager& manager, const moho::SAudioRequest& request)
  {
    manager.mRequests.PushBack(request);
  }

  /**
   * Address: 0x007618B0 (FUN_007618B0, sub_7618B0)
   *
   * What it does:
   * Assigns one `fastvector_n<SAudioRequest, 64>` into another while reusing
   * destination storage when capacity is sufficient.
   */
  [[nodiscard]] gpg::fastvector_n<moho::SAudioRequest, 64>* CopyRequests(
    gpg::fastvector_n<moho::SAudioRequest, 64>& destination, const gpg::fastvector_n<moho::SAudioRequest, 64>& source
  )
  {
    if (&destination == &source) {
      return &destination;
    }

    const std::size_t destinationCount = destination.Size();
    const std::size_t sourceCount = source.Size();

    if (destinationCount >= sourceCount) {
      if (sourceCount != 0u) {
        std::copy_n(source.start_, sourceCount, destination.start_);
      }
      destination.SetSizeUnchecked(sourceCount);
      return &destination;
    }

    if (destination.Capacity() < sourceCount) {
      destination.Grow(sourceCount);
    }

    if (destinationCount != 0u) {
      std::copy_n(source.start_, destinationCount, destination.start_);
    }
    if (sourceCount > destinationCount) {
      std::copy(
        source.start_ + static_cast<std::ptrdiff_t>(destinationCount),
        source.start_ + static_cast<std::ptrdiff_t>(sourceCount),
        destination.start_ + static_cast<std::ptrdiff_t>(destinationCount)
      );
    }

    destination.SetSizeUnchecked(sourceCount);
    return &destination;
  }

  void ResetRequestQueueInline(moho::CSimSoundManager& manager)
  {
    manager.mRequests.ResetStorageToInline();
  }

  void ResetLoopList(LoopList& loops)
  {
    loops.ListUnlink();
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00760C80 (FUN_00760C80)
   *
   * Sim* ownerSim
   *
   * IDA signature:
   * Moho::ISimSoundManager_vtbl **__usercall sub_760C80@<eax>(Moho::ISimSoundManager_vtbl **result@<eax>,
   * Moho::ISimSoundManager_vtbl *a2@<ecx>);
   *
   * What it does:
   * Initializes one `CSimSoundManager` runtime object with owner-sim pointer,
   * inline request-vector lanes, and self-linked active-loop sentinel.
   */
  CSimSoundManager::CSimSoundManager(Sim* const ownerSim)
    : mOwnerSim(ownerSim)
    , mRequests()
    , mActiveLoops()
  {
    mRequests.ResetStorageToInline();
    mActiveLoops.ListUnlink();
  }

  /**
   * Address: 0x00760CC0 (FUN_00760CC0)
   *
   * Moho::Entity*, Moho::CSndParams*
   *
   * IDA signature:
   * void __thiscall Moho::CSimSoundManager::AddEntitySound(Moho::CSimSoundManager *this, Moho::Entity *entity,
   * Moho::CSndParams *params);
   *
   * What it does:
   * Queues opcode-0 (one-shot) request with entity position/current layer.
   */
  void CSimSoundManager::AddEntitySound(Entity* entity, CSndParams* params)
  {
    SAudioRequest request{};
    request.position = entity->Position;
    request.layer = entity->mCurrentLayer;
    request.params = params;
    request.sound = nullptr;
    request.requestType = EAudioRequestType::EntitySound;
    QueueRequest(*this, request);
  }

  /**
   * Address: 0x00760EB0 (FUN_00760EB0)
   *
   * gpg::fastvector_n<Moho::SAudioRequest, 64>& outRequests
   *
   * IDA signature:
   * Moho::SAudioRequest *__thiscall sub_760EB0(Moho::CSimSoundManager *this, gpg::fastvector_n64_SAudioRequest
   * *outRequests);
   *
   * What it does:
   * Copies pending requests into caller-owned vector and resets local queue
   * to inline storage.
   */
  void CSimSoundManager::DrainRequests(gpg::fastvector_n<SAudioRequest, 64>& outRequests)
  {
    if (&outRequests != &mRequests) {
      CopyRequests(outRequests, mRequests);
    }

    ResetRequestQueueInline(*this);
  }

  /**
   * Address: 0x00760D20 (FUN_00760D20)
   *
   * Moho::HSound*
   *
   * IDA signature:
   * Moho::TDatListItem_HSound *__thiscall Moho::CSimSoundManager::AddLoop(Moho::CSimSoundManager *this, Moho::HSound
   * *sound);
   *
   * What it does:
   * Queues opcode-1 loop-start request and links handle at list tail.
   */
  TDatListItem<HSound, void>* CSimSoundManager::AddLoop(HSound* sound)
  {
    SAudioRequest request{};
    request.position = Wm3::Vec3f{};
    request.layer = LAYER_None;
    request.params = nullptr;
    request.sound = sound;
    request.requestType = EAudioRequestType::StartLoop;
    QueueRequest(*this, request);

    auto* const loopNode = &sound->mSimLoopLink;
    loopNode->ListLinkBefore(static_cast<LoopNode*>(&mActiveLoops));
    return loopNode;
  }

  /**
   * Address: 0x00760D90 (FUN_00760D90)
   *
   * Moho::HSound*
   *
   * IDA signature:
   * Moho::TDatListItem_HSound *__thiscall Moho::CSimSoundManager::Func4(Moho::CSimSoundManager *this, Moho::HSound
   * *sound);
   *
   * What it does:
   * If the handle is active, queues opcode-2 stop-loop request and unlinks it.
   */
  TDatListItem<HSound, void>* CSimSoundManager::StopLoop(HSound* sound)
  {
    auto* const sentinel = static_cast<LoopNode*>(&mActiveLoops);
    auto* node = mActiveLoops.mNext;
    while (node != sentinel) {
      if (LoopOwnerFromNode(node) == sound) {
        break;
      }
      node = node->mNext;
    }

    if (node == sentinel) {
      return node;
    }

    SAudioRequest request{};
    request.position = Wm3::Vec3f{};
    request.layer = LAYER_None;
    request.params = nullptr;
    request.sound = sound;
    request.requestType = EAudioRequestType::StopLoop;
    QueueRequest(*this, request);

    sound->mSimLoopLink.ListUnlink();
    return &sound->mSimLoopLink;
  }

  /**
   * Address: 0x00760E70 (FUN_00760E70)
   *
   * void
   *
   * IDA signature:
   * void __thiscall Moho::CSimSoundManager::Shutdown(Moho::CSimSoundManager *this);
   *
   * What it does:
   * Drains active loop list by repeatedly dispatching slot-3 stop requests.
   */
  void CSimSoundManager::Shutdown()
  {
    auto* const sentinel = static_cast<LoopNode*>(&mActiveLoops);
    ISoundManager* const soundManager = this;
    while (mActiveLoops.mNext != sentinel) {
      HSound* const sound = LoopOwnerFromNode(mActiveLoops.mNext);
      soundManager->StopLoop(sound);
    }
  }

  /**
   * Address: 0x00761520 (FUN_00761520)
   *
   * IDA signature:
   * Moho::SAudioRequest *__usercall sub_761520@<eax>(Moho::CSimSoundManager *this@<esi>);
   *
   * What it does:
   * Non-deleting teardown helper used by slot-5 destroy wrapper.
   */
  void CSimSoundManager::TeardownNonDeleting()
  {
    ResetLoopList(mActiveLoops);
    ResetRequestQueueInline(*this);
  }

  /**
   * Address: 0x00760EF0 (FUN_00760EF0)
   *
   * std::uint8_t deleteFlags
   *
   * IDA signature:
   * void *__thiscall sub_760EF0(void *this, char deleteFlags);
   *
   * What it does:
   * Performs deleting-style destruction and optional free.
   */
  ISoundManager* CSimSoundManager::Destroy(const std::uint8_t flags)
  {
    TeardownNonDeleting();

    if ((flags & 1u) != 0u) {
      operator delete(this);
    }
    return this;
  }
} // namespace moho
