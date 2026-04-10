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

  void QueueRequest(moho::CSimSoundManager& manager, const moho::SAudioRequest& request)
  {
    manager.mRequests.PushBack(request);
  }

  void CopyRequests(
    gpg::fastvector_n<moho::SAudioRequest, 64>& destination, const gpg::fastvector_n<moho::SAudioRequest, 64>& source
  )
  {
    // Mirrors FUN_007618B0 behavior: reuse destination storage when possible.
    const std::size_t requestCount = source.Size();
    if (destination.Capacity() < requestCount) {
      destination.Grow(requestCount);
    }

    if (requestCount != 0u) {
      std::copy_n(source.start_, requestCount, destination.start_);
    }
    destination.SetSizeUnchecked(requestCount);
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
