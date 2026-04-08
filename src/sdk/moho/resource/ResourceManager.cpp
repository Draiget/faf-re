#include "moho/resource/ResourceManager.h"
#include "moho/resource/CResourceWatcher.h"
#include "moho/resource/ResourceFactory.h"
#include "moho/resource/PrefetchRuntime.h"
#include "moho/serialization/PrefetchHandleBase.h"
#include "moho/misc/FileWaitHandleSet.h"

#include <algorithm>
#include <chrono>
#include <cstddef>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <map>
#include <mutex>
#include <new>
#include <stdexcept>
#include <string>
#include <thread>
#include <Windows.h>

#include "boost/bind.hpp"
#include "boost/function/function_base.hpp"
#include "gpg/core/utils/Global.h"
#include "gpg/core/utils/Logging.h"
#include "gpg/core/utils/BoostWrappers.h"
#include "moho/console/CConCommand.h"

namespace moho
{
  bool res_EnablePrefetching = true;
  int res_PrefetcherActivityDelay = 0;
  int res_AfterPrefetchDelay = 0;
  bool res_SpewLoadSpam = false;
} // namespace moho

namespace
{
  using IntrusiveListLink = moho::PrefetchListLink;

  struct PrefetchWatchNode
  {
    IntrusiveListLink mListLink; // +0x00
    msvc8::string mPath;         // +0x08
    void* mWatcher;              // +0x24
    std::uint8_t mIsFinished;    // +0x28
    std::uint8_t mPad29[3];
  };

  static_assert(offsetof(PrefetchWatchNode, mListLink) == 0x00, "PrefetchWatchNode::mListLink offset must be 0x00");
  static_assert(offsetof(PrefetchWatchNode, mPath) == 0x08, "PrefetchWatchNode::mPath offset must be 0x08");
  static_assert(offsetof(PrefetchWatchNode, mWatcher) == 0x24, "PrefetchWatchNode::mWatcher offset must be 0x24");
  static_assert(offsetof(PrefetchWatchNode, mIsFinished) == 0x28, "PrefetchWatchNode::mIsFinished offset must be 0x28");
  static_assert(sizeof(PrefetchWatchNode) == 0x2C, "PrefetchWatchNode size must be 0x2C");

  using WeakSharedPair = boost::SharedCountPair;
  using PrefetchRequestRuntime = moho::PrefetchRequestRuntime;

  struct DualSharedPairCleanupView
  {
    std::uint32_t mReserved00;    // +0x00
    std::uint32_t mReserved04;    // +0x04
    boost::SharedCountPair mPair0; // +0x08
    boost::SharedCountPair mPair1; // +0x10
  };

  static_assert(offsetof(DualSharedPairCleanupView, mPair0) == 0x08, "DualSharedPairCleanupView::mPair0 offset must be 0x08");
  static_assert(offsetof(DualSharedPairCleanupView, mPair1) == 0x10, "DualSharedPairCleanupView::mPair1 offset must be 0x10");
  static_assert(sizeof(DualSharedPairCleanupView) == 0x18, "DualSharedPairCleanupView size must be 0x18");

  /**
   * Address: 0x004A9B30 (FUN_004A9B30)
   *
   * What it does:
   * Unlinks one intrusive list node and rewires it to self-linked state.
   */
  IntrusiveListLink* UnlinkIntrusiveListNode(IntrusiveListLink* const node) noexcept
  {
    node->ListUnlink();
    return node;
  }

  /**
   * Address: 0x004A99C0 (FUN_004A99C0)
   *
   * What it does:
   * Initializes one prefetch watcher node with self-linked intrusive lanes,
   * path text, owning watcher pointer, and cleared completion flag.
   */
  PrefetchWatchNode* InitializePrefetchWatchNode(
    PrefetchWatchNode* const node,
    const gpg::StrArg path,
    void* const watcher
  )
  {
    node->mListLink.ListResetLinks();
    ::new (&node->mPath) msvc8::string(path ? path : "");
    node->mWatcher = watcher;
    node->mIsFinished = 0;
    return node;
  }

  /**
   * Address: 0x004A9A40 (FUN_004A9A40)
   *
   * What it does:
   * Initializes one resource-prefetch request runtime entry from path + type,
   * clears active state lanes, and resets waiter-list head to self-linked.
   */
  PrefetchRequestRuntime* InitializePrefetchRequestFromPath(
    PrefetchRequestRuntime* const request,
    const gpg::StrArg path,
    gpg::RType* const resourceType
  )
  {
    request->mResourceId.name = msvc8::string(path ? path : "");
    request->mResourceType = resourceType;
    request->mIsLoading = 0;
    request->mLoadWakePending = 0;
    request->mResolved.px = nullptr;
    request->mResolved.pi = nullptr;
    request->mHadLoadFailure = 0;
    request->mPrefetch.px = nullptr;
    request->mPrefetch.pi = nullptr;
    request->mWaiterListHead.ListResetLinks();
    return request;
  }

  /**
   * Address: 0x004A9AA0 (FUN_004A9AA0)
   *
   * What it does:
   * Copy-initializes one prefetch request runtime entry from an existing key
   * while clearing active load/result lanes.
   */
  PrefetchRequestRuntime* InitializePrefetchRequestFromTemplate(
    PrefetchRequestRuntime* const request,
    const PrefetchRequestRuntime& source
  )
  {
    request->mResourceId.name = source.mResourceId.name;
    request->mResourceType = source.mResourceType;
    request->mIsLoading = 0;
    request->mLoadWakePending = 0;
    request->mResolved.px = nullptr;
    request->mResolved.pi = nullptr;
    request->mHadLoadFailure = 0;
    request->mPrefetch.px = nullptr;
    request->mPrefetch.pi = nullptr;
    request->mWaiterListHead.ListResetLinks();
    return request;
  }

  /**
   * Address: 0x004A9B10 (FUN_004A9B10)
   *
   * What it does:
   * Releases one weak control-block lane (`pi`) from a `(px,pi)` pair.
   */
  boost::detail::sp_counted_base* ReleaseWeakControlFromPair(WeakSharedPair* const weakPair) noexcept
  {
    return boost::SpCountedBaseWeakReleaseFromSlot(&weakPair->pi);
  }

  /**
   * Address: 0x004A9920 (FUN_004A9920)
   *
   * What it does:
   * Releases two shared control-block lanes at offsets `+0x10` then `+0x08`.
   */
  void ReleaseDualSharedPairs(DualSharedPairCleanupView* const view) noexcept
  {
    boost::ReleaseSharedControlOnly(&view->mPair1);
    boost::ReleaseSharedControlOnly(&view->mPair0);
  }

  /**
   * Address: 0x004AA560 (FUN_004AA560)
   *
   * What it does:
   * Tears down one prefetch request runtime entry: unlinks waiter head,
   * weak-releases both control lanes, then tidies the path string.
   */
  PrefetchRequestRuntime* DestroyPrefetchRequestRuntime(PrefetchRequestRuntime* const request) noexcept
  {
    (void)UnlinkIntrusiveListNode(&request->mWaiterListHead);
    (void)ReleaseWeakControlFromPair(&request->mPrefetch);
    (void)ReleaseWeakControlFromPair(&request->mResolved);
    request->mResourceId.name.tidy(true, 0U);
    return request;
  }

  std::once_flag sResourceManagerOnce;
  moho::ResourceManager* sPResourceManager = nullptr;

  /**
   * Recovered view of the hidden factory registration payload used by the
   * bootstrap registry. The second dword is the factory key consumed by the
   * active keyed registry.
   */
  struct FactoryRegistrationView
  {
    void* vTable;
    unsigned int registrationKey;
  };

  [[nodiscard]] unsigned int GetFactoryRegistrationKey(const moho::ResourceFactoryBase* factory)
  {
    return reinterpret_cast<const FactoryRegistrationView*>(factory)->registrationKey;
  }

  void RemovePendingFactory(std::vector<moho::ResourceFactoryBase*>& pendingFactories,
                            const moho::ResourceFactoryBase* factory)
  {
    const auto factoryIt = std::find(pendingFactories.begin(), pendingFactories.end(), factory);
    if (factoryIt != pendingFactories.end()) {
      pendingFactories.erase(factoryIt);
    }
  }

  /**
   * Address: 0x004AC330 (FUN_004AC330)
   *
   * What it does:
   * Appends one factory pointer into the pending registration vector.
   */
  moho::ResourceFactoryBase* AppendPendingFactoryRegistration(
    std::vector<moho::ResourceFactoryBase*>& pendingFactories,
    moho::ResourceFactoryBase* const factory
  )
  {
    pendingFactories.push_back(factory);
    return factory;
  }

  [[nodiscard]] boost::SharedCountPair* ResetSharedPairToNullCore(boost::SharedCountPair* const pair) noexcept
  {
    if (pair == nullptr) {
      return nullptr;
    }
    pair->px = nullptr;
    pair->pi = nullptr;
    return pair;
  }

  /**
   * Address: 0x004ABF70 (FUN_004ABF70)
   *
   * What it does:
   * Clears one shared pair to `(nullptr,nullptr)` in-place.
   */
  boost::SharedCountPair* ResetSharedPairToNullVariant1(boost::SharedCountPair* const pair) noexcept
  {
    return ResetSharedPairToNullCore(pair);
  }

  /**
   * Address: 0x004ABF80 (FUN_004ABF80)
   *
   * What it does:
   * Releases one shared control-block lane then clears one shared pair.
   */
  [[maybe_unused]] boost::SharedCountPair* ResetSharedPairReleaseControl(
    boost::SharedCountPair* const pair
  ) noexcept
  {
    if (pair == nullptr) {
      return nullptr;
    }

    pair->px = nullptr;
    boost::detail::sp_counted_base* const control = pair->pi;
    pair->pi = nullptr;
    if (control != nullptr) {
      control->release();
    }
    return pair;
  }

  /**
   * Address: 0x004AC0D0 (FUN_004AC0D0)
   *
   * What it does:
   * Clears one shared pair to `(nullptr,nullptr)`.
   */
  boost::SharedCountPair* ResetSharedPairToNullVariant2(boost::SharedCountPair* const pair) noexcept
  {
    return ResetSharedPairToNullCore(pair);
  }

  [[nodiscard]] boost::SharedCountPair* BuildWeakPairFromLiveSharedCore(
    const boost::SharedCountPair* const sourceSharedPair,
    boost::SharedCountPair* const outWeakPair
  ) noexcept
  {
    if (outWeakPair == nullptr) {
      return nullptr;
    }
    if (sourceSharedPair == nullptr) {
      outWeakPair->px = nullptr;
      outWeakPair->pi = nullptr;
      return outWeakPair;
    }

    outWeakPair->px = sourceSharedPair->px;
    if (sourceSharedPair->pi != nullptr && boost::SpCountedBaseUseCount(sourceSharedPair->pi) != 0) {
      outWeakPair->pi = boost::SpCountedBaseWeakAddRefReturn(sourceSharedPair->pi);
      return outWeakPair;
    }

    outWeakPair->px = nullptr;
    outWeakPair->pi = nullptr;
    return outWeakPair;
  }

  /**
   * Address: 0x004AC0E0 (FUN_004AC0E0)
   *
   * What it does:
   * Builds one weak `(px,pi)` pair from one live shared `(px,pi)` pair;
   * otherwise writes a null pair.
   */
  boost::SharedCountPair* BuildWeakPairFromLiveSharedVariant1(
    const boost::SharedCountPair* const sourceSharedPair,
    boost::SharedCountPair* const outWeakPair
  ) noexcept
  {
    return BuildWeakPairFromLiveSharedCore(sourceSharedPair, outWeakPair);
  }

  /**
   * Address: 0x004AC1B0 (FUN_004AC1B0)
   *
   * What it does:
   * Clears one shared pair to `(nullptr,nullptr)`.
   */
  boost::SharedCountPair* ResetSharedPairToNullVariant3(boost::SharedCountPair* const pair) noexcept
  {
    return ResetSharedPairToNullVariant2(pair);
  }

  /**
   * Address: 0x004AC1C0 (FUN_004AC1C0)
   *
   * What it does:
   * Duplicate lane of weak-pair construction from one live shared pair.
   */
  boost::SharedCountPair* BuildWeakPairFromLiveSharedVariant2(
    const boost::SharedCountPair* const sourceSharedPair,
    boost::SharedCountPair* const outWeakPair
  ) noexcept
  {
    return BuildWeakPairFromLiveSharedVariant1(sourceSharedPair, outWeakPair);
  }

  /**
   * Address: 0x004AC070 (FUN_004AC070)
   *
   * What it does:
   * Returns one dword-array element address from `base + index * 4`.
   */
  [[maybe_unused]] std::uintptr_t ComputeDwordElementAddress(
    const std::uintptr_t* const baseAddressSlot,
    const std::int32_t elementIndex
  ) noexcept
  {
    return *baseAddressSlot + static_cast<std::uintptr_t>(4 * elementIndex);
  }

  /**
   * Address: 0x004AC080 (FUN_004AC080)
   *
   * What it does:
   * Returns one raw dword lane from caller-provided storage.
   */
  [[maybe_unused]] std::uintptr_t ReadDwordSlot(const std::uintptr_t* const dwordSlot) noexcept
  {
    return *dwordSlot;
  }

  /**
   * Address: 0x004AC310 (FUN_004AC310)
   *
   * What it does:
   * Copies one dword from source offset `+0x04` into output storage.
   */
  [[maybe_unused]] std::uint32_t* CopyDwordFromOffset4Variant1(
    std::uint32_t* const outValue,
    const std::uint8_t* const source
  ) noexcept
  {
    *outValue = *reinterpret_cast<const std::uint32_t*>(source + 0x04);
    return outValue;
  }

  /**
   * Address: 0x004AC320 (FUN_004AC320)
   *
   * What it does:
   * Copies one dword from source offset `+0x08` into output storage.
   */
  [[maybe_unused]] std::uint32_t* CopyDwordFromOffset8(
    std::uint32_t* const outValue,
    const std::uint8_t* const source
  ) noexcept
  {
    *outValue = *reinterpret_cast<const std::uint32_t*>(source + 0x08);
    return outValue;
  }

  /**
   * Address: 0x004AC450 (FUN_004AC450)
   *
   * What it does:
   * Duplicate lane that copies one dword from source offset `+0x04`.
   */
  [[maybe_unused]] std::uint32_t* CopyDwordFromOffset4Variant2(
    std::uint32_t* const outValue,
    const std::uint8_t* const source
  ) noexcept
  {
    return CopyDwordFromOffset4Variant1(outValue, source);
  }

  struct PrefetchWeakPairRingQueueRuntime
  {
    std::uint32_t mReserved00;                    // +0x00
    boost::SharedCountPair** mChunkPairBlocks;    // +0x04
    std::uint32_t mChunkCount;                    // +0x08
    std::uint32_t mReadCursor;                    // +0x0C
    std::uint32_t mQueuedCount;                   // +0x10
  };

  static_assert(
    offsetof(PrefetchWeakPairRingQueueRuntime, mChunkPairBlocks) == 0x04,
    "PrefetchWeakPairRingQueueRuntime::mChunkPairBlocks offset must be 0x04"
  );
  static_assert(
    offsetof(PrefetchWeakPairRingQueueRuntime, mChunkCount) == 0x08,
    "PrefetchWeakPairRingQueueRuntime::mChunkCount offset must be 0x08"
  );
  static_assert(
    offsetof(PrefetchWeakPairRingQueueRuntime, mReadCursor) == 0x0C,
    "PrefetchWeakPairRingQueueRuntime::mReadCursor offset must be 0x0C"
  );
  static_assert(
    offsetof(PrefetchWeakPairRingQueueRuntime, mQueuedCount) == 0x10,
    "PrefetchWeakPairRingQueueRuntime::mQueuedCount offset must be 0x10"
  );
  static_assert(sizeof(PrefetchWeakPairRingQueueRuntime) == 0x14, "PrefetchWeakPairRingQueueRuntime size must be 0x14");

  constexpr std::uint32_t kPrefetchWeakPairRingMaxChunkCount_004AD900 = 0x0FFFFFFFU;

  /**
   * Address: 0x004AE590 (FUN_004AE590)
   *
   * What it does:
   * Throws the legacy deque growth overflow error path.
   */
  [[noreturn]] void ThrowDequeTooLong_004AE590()
  {
    throw std::length_error("deque<T> too long");
  }

  /**
   * Address: 0x004ADB30 (FUN_004ADB30)
   *
   * What it does:
   * Allocates one 2-lane weak-pair chunk block for ring storage.
   */
  [[maybe_unused]] boost::SharedCountPair* AllocateWeakPairChunkBlock_004ADB30()
  {
    return static_cast<boost::SharedCountPair*>(::operator new(sizeof(boost::SharedCountPair) * 2U));
  }

  /**
   * Address: 0x004AD900 (FUN_004AD900)
   *
   * What it does:
   * Grows and reflows the ring chunk-pointer index while preserving queued
   * logical order around the read cursor.
   */
  [[maybe_unused]] boost::SharedCountPair** GrowPrefetchWeakPairRingChunkIndex_004AD900(
    PrefetchWeakPairRingQueueRuntime* const queue
  )
  {
    if (queue == nullptr) {
      return nullptr;
    }

    const std::uint32_t currentChunkCount = queue->mChunkCount;
    if (currentChunkCount == kPrefetchWeakPairRingMaxChunkCount_004AD900) {
      ThrowDequeTooLong_004AE590();
    }

    std::uint32_t growthCount = 1U;
    std::uint32_t halfCount = currentChunkCount >> 1U;
    if (halfCount < 8U) {
      halfCount = 8U;
    }
    if (halfCount > 1U && currentChunkCount <= (kPrefetchWeakPairRingMaxChunkCount_004AD900 - halfCount)) {
      growthCount = halfCount;
    }

    const std::uint32_t readChunk = queue->mReadCursor >> 1U;
    const std::uint32_t newChunkCount = currentChunkCount + growthCount;
    auto** const newChunkIndex = static_cast<boost::SharedCountPair**>(
      newChunkCount != 0U ? ::operator new(sizeof(boost::SharedCountPair*) * newChunkCount) : ::operator new(0U)
    );

    boost::SharedCountPair** const oldChunkIndex = queue->mChunkPairBlocks;
    if (oldChunkIndex != nullptr && currentChunkCount > 0U) {
      const std::size_t tailCount = static_cast<std::size_t>(currentChunkCount - readChunk);
      if (tailCount > 0U) {
        std::memmove(
          newChunkIndex + readChunk,
          oldChunkIndex + readChunk,
          tailCount * sizeof(boost::SharedCountPair*)
        );
      }

      boost::SharedCountPair** const tailEnd = newChunkIndex + currentChunkCount;
      if (readChunk > growthCount) {
        if (growthCount > 0U) {
          std::memmove(
            tailEnd,
            oldChunkIndex,
            static_cast<std::size_t>(growthCount) * sizeof(boost::SharedCountPair*)
          );
        }

        const std::size_t rotatedPrefixCount = static_cast<std::size_t>(readChunk - growthCount);
        if (rotatedPrefixCount > 0U) {
          std::memmove(
            newChunkIndex,
            oldChunkIndex + growthCount,
            rotatedPrefixCount * sizeof(boost::SharedCountPair*)
          );
        }

        std::memset(
          newChunkIndex + (readChunk - growthCount),
          0,
          static_cast<std::size_t>(growthCount) * sizeof(boost::SharedCountPair*)
        );
      } else {
        if (readChunk > 0U) {
          std::memmove(
            tailEnd,
            oldChunkIndex,
            static_cast<std::size_t>(readChunk) * sizeof(boost::SharedCountPair*)
          );
        }

        if (growthCount != readChunk) {
          std::memset(
            tailEnd + readChunk,
            0,
            static_cast<std::size_t>(growthCount - readChunk) * sizeof(boost::SharedCountPair*)
          );
        }

        if (readChunk > 0U) {
          std::memset(newChunkIndex, 0, static_cast<std::size_t>(readChunk) * sizeof(boost::SharedCountPair*));
        }
      }
    } else if (newChunkCount > 0U) {
      std::memset(newChunkIndex, 0, static_cast<std::size_t>(newChunkCount) * sizeof(boost::SharedCountPair*));
    }

    ::operator delete(queue->mChunkPairBlocks);
    queue->mChunkPairBlocks = newChunkIndex;
    queue->mChunkCount = newChunkCount;
    return newChunkIndex;
  }

  [[nodiscard]] boost::SharedCountPair* GetPrefetchWeakPairRingSlot(
    PrefetchWeakPairRingQueueRuntime* const queue,
    const std::uint32_t logicalCursor,
    const bool allocateMissingBlock
  ) noexcept
  {
    if (queue == nullptr || queue->mChunkPairBlocks == nullptr || queue->mChunkCount == 0) {
      return nullptr;
    }

    std::uint32_t chunkIndex = logicalCursor >> 1U;
    while (chunkIndex >= queue->mChunkCount) {
      chunkIndex -= queue->mChunkCount;
    }

    boost::SharedCountPair*& chunkPairs = queue->mChunkPairBlocks[chunkIndex];
    if (allocateMissingBlock && chunkPairs == nullptr) {
      chunkPairs = AllocateWeakPairChunkBlock_004ADB30();
      (void)ResetSharedPairToNullVariant1(&chunkPairs[0]);
      (void)ResetSharedPairToNullVariant1(&chunkPairs[1]);
    }

    if (chunkPairs == nullptr) {
      return nullptr;
    }

    return &chunkPairs[logicalCursor & 1U];
  }

  /**
   * Address: 0x004ACAA0 (FUN_004ACAA0)
   *
   * What it does:
   * Pops one weak pair from the prefetch ring-front cursor and weak-releases
   * its control lane.
   */
  [[maybe_unused]] std::uint32_t PopPrefetchWeakPairRingFront(
    PrefetchWeakPairRingQueueRuntime* const queue
  ) noexcept
  {
    std::uint32_t nextCursor = queue != nullptr ? queue->mReadCursor : 0U;
    if (queue == nullptr || queue->mQueuedCount == 0) {
      return nextCursor;
    }

    if (boost::SharedCountPair* const slot = GetPrefetchWeakPairRingSlot(queue, queue->mReadCursor, false);
        slot != nullptr) {
      (void)boost::SpCountedBaseWeakReleaseFromSlot(&slot->pi);
    }

    nextCursor = queue->mReadCursor + 1U;
    queue->mReadCursor = nextCursor;
    if (2U * queue->mChunkCount <= nextCursor) {
      queue->mReadCursor = 0U;
    }

    const std::uint32_t priorQueuedCount = queue->mQueuedCount--;
    if (priorQueuedCount == 1U) {
      queue->mReadCursor = 0U;
    }

    return queue->mReadCursor;
  }

  /**
   * Address: 0x004ACA20 (FUN_004ACA20)
   *
   * What it does:
   * Pushes one weak pair at the logical front of the prefetch ring queue.
   */
  [[maybe_unused]] boost::SharedCountPair* PushPrefetchWeakPairRingFront(
    PrefetchWeakPairRingQueueRuntime* const queue,
    const boost::SharedCountPair* const sourceWeakPair
  )
  {
    if (queue == nullptr || sourceWeakPair == nullptr) {
      return nullptr;
    }

    if (((queue->mReadCursor & 1U) == 0U) && queue->mChunkCount <= ((queue->mQueuedCount + 2U) >> 1U)) {
      (void)GrowPrefetchWeakPairRingChunkIndex_004AD900(queue);
    }
    if (queue->mChunkCount == 0U) {
      return nullptr;
    }

    std::uint32_t insertCursor = queue->mReadCursor;
    if (insertCursor == 0U) {
      insertCursor = 2U * queue->mChunkCount;
    }
    insertCursor -= 1U;

    boost::SharedCountPair* const slot = GetPrefetchWeakPairRingSlot(queue, insertCursor, true);
    if (slot != nullptr) {
      slot->px = sourceWeakPair->px;
      slot->pi = sourceWeakPair->pi;
      if (slot->pi != nullptr) {
        (void)boost::SpCountedBaseWeakAddRef(slot->pi);
      }
    }

    ++queue->mQueuedCount;
    queue->mReadCursor = insertCursor;
    return slot;
  }

  /**
   * Address: 0x004ACB00 (FUN_004ACB00)
   *
   * What it does:
   * Pushes one weak pair at the logical back of the prefetch ring queue.
   */
  [[maybe_unused]] boost::SharedCountPair* PushPrefetchWeakPairRingBack(
    PrefetchWeakPairRingQueueRuntime* const queue,
    const boost::SharedCountPair* const sourceWeakPair
  )
  {
    if (queue == nullptr || sourceWeakPair == nullptr) {
      return nullptr;
    }

    if ((((queue->mQueuedCount + queue->mReadCursor) & 1U) == 0U)
        && queue->mChunkCount <= ((queue->mQueuedCount + 2U) >> 1U)) {
      (void)GrowPrefetchWeakPairRingChunkIndex_004AD900(queue);
    }
    if (queue->mChunkCount == 0U) {
      return nullptr;
    }

    const std::uint32_t logicalInsertCursor = queue->mReadCursor + queue->mQueuedCount;
    boost::SharedCountPair* const slot = GetPrefetchWeakPairRingSlot(queue, logicalInsertCursor, true);
    if (slot != nullptr) {
      slot->px = sourceWeakPair->px;
      slot->pi = sourceWeakPair->pi;
      if (slot->pi != nullptr) {
        (void)boost::SpCountedBaseWeakAddRef(slot->pi);
      }
    }

    ++queue->mQueuedCount;
    return slot;
  }

  /**
   * Address: 0x004ADA70 (FUN_004ADA70)
   *
   * What it does:
   * Releases all queued weak control blocks, deletes all chunk blocks, and
   * resets ring queue storage lanes.
   */
  [[maybe_unused]] void CleanupPrefetchWeakPairRingQueue_004ADA70(
    PrefetchWeakPairRingQueueRuntime* const queue
  ) noexcept
  {
    if (queue == nullptr) {
      return;
    }

    while (queue->mQueuedCount != 0U) {
      (void)PopPrefetchWeakPairRingFront(queue);
    }

    std::uint32_t remainingChunks = queue->mChunkCount;
    while (remainingChunks > 0U) {
      --remainingChunks;
      ::operator delete(queue->mChunkPairBlocks[remainingChunks]);
    }

    ::operator delete(queue->mChunkPairBlocks);
    queue->mChunkPairBlocks = nullptr;
    queue->mChunkCount = 0U;
    queue->mReadCursor = 0U;
    queue->mQueuedCount = 0U;
  }

  PrefetchWeakPairRingQueueRuntime sPrefetchPayloadQueue_004AB180{};
  std::chrono::steady_clock::time_point sLastResourceResolveTime_004AA690{};

  [[nodiscard]] boost::SharedCountPair SharedPairBorrowFromPrefetchShared(
    const boost::shared_ptr<moho::PrefetchData>& sharedPayload
  ) noexcept
  {
    const boost::SharedPtrRaw<moho::PrefetchData> raw = boost::SharedPtrRawFromSharedBorrow(sharedPayload);
    boost::SharedCountPair out{};
    out.px = raw.px;
    out.pi = raw.pi;
    return out;
  }

  void AssignLiveWeakPair_004AB180(
    boost::SharedCountPair* const outWeakPair,
    const boost::SharedCountPair* const sourcePair
  ) noexcept
  {
    boost::SharedCountPair liveWeak{};
    (void)BuildWeakPairFromLiveSharedVariant1(sourcePair, &liveWeak);
    (void)boost::AssignWeakPairFromShared(outWeakPair, &liveWeak);
    (void)ReleaseWeakControlFromPair(&liveWeak);
  }

  void EnqueuePrefetchPayloadBack_004AB180(const boost::shared_ptr<moho::PrefetchData>& payload)
  {
    if (!payload) {
      return;
    }

    const boost::SharedCountPair sharedPayloadPair = SharedPairBorrowFromPrefetchShared(payload);
    boost::SharedCountPair weakPayloadPair{};
    (void)boost::AssignWeakPairFromShared(&weakPayloadPair, &sharedPayloadPair);
    (void)PushPrefetchWeakPairRingBack(&sPrefetchPayloadQueue_004AB180, &weakPayloadPair);
    (void)ReleaseWeakControlFromPair(&weakPayloadPair);
  }

  void EnqueuePrefetchPayloadFront_004AB180(const boost::shared_ptr<moho::PrefetchData>& payload)
  {
    if (!payload) {
      return;
    }

    const boost::SharedCountPair sharedPayloadPair = SharedPairBorrowFromPrefetchShared(payload);
    boost::SharedCountPair weakPayloadPair{};
    (void)boost::AssignWeakPairFromShared(&weakPayloadPair, &sharedPayloadPair);
    (void)PushPrefetchWeakPairRingFront(&sPrefetchPayloadQueue_004AB180, &weakPayloadPair);
    (void)ReleaseWeakControlFromPair(&weakPayloadPair);
  }

  [[nodiscard]] boost::shared_ptr<moho::PrefetchData> PopQueuedPrefetchPayload_004AB180()
  {
    boost::shared_ptr<moho::PrefetchData> payload{};
    if (sPrefetchPayloadQueue_004AB180.mQueuedCount == 0U) {
      return payload;
    }

    const boost::SharedCountPair* const frontSlot = GetPrefetchWeakPairRingSlot(
      &sPrefetchPayloadQueue_004AB180,
      sPrefetchPayloadQueue_004AB180.mReadCursor,
      false
    );
    if (frontSlot != nullptr && frontSlot->px != nullptr && frontSlot->pi != nullptr
        && boost::SpCountedBaseAddRefLock(frontSlot->pi)) {
      auto* const layout = reinterpret_cast<boost::SharedPtrLayoutView<moho::PrefetchData>*>(&payload);
      layout->px = static_cast<moho::PrefetchData*>(frontSlot->px);
      layout->pi = frontSlot->pi;
    }

    (void)PopPrefetchWeakPairRingFront(&sPrefetchPayloadQueue_004AB180);
    return payload;
  }

  /**
   * Address: 0x004ADB10 (FUN_004ADB10, nullsub_706)
   *
   * What it does:
   * No-op helper thunk retained for callsite parity.
   */
  [[maybe_unused]] void NoOpHelperThunk_004ADB10(const std::uint32_t /*unused*/) noexcept {}

  /**
   * Address: 0x004ADB20 (FUN_004ADB20, nullsub_707)
   *
   * What it does:
   * No-op helper thunk retained for callsite parity.
   */
  [[maybe_unused]] void NoOpHelperThunk_004ADB20() noexcept {}

  struct DwordAndBytePayload_004ADB80
  {
    std::uint32_t dwordLane; // +0x00
    std::uint8_t byteLane;   // +0x04
  };

  static_assert(
    offsetof(DwordAndBytePayload_004ADB80, dwordLane) == 0x00,
    "DwordAndBytePayload_004ADB80::dwordLane offset must be 0x00"
  );
  static_assert(
    offsetof(DwordAndBytePayload_004ADB80, byteLane) == 0x04,
    "DwordAndBytePayload_004ADB80::byteLane offset must be 0x04"
  );

  /**
   * Address: 0x004ADB80 (FUN_004ADB80)
   *
   * What it does:
   * Copies one dword lane and one byte lane from separate sources into output.
   */
  [[maybe_unused]] DwordAndBytePayload_004ADB80* CopyDwordAndBytePayload_004ADB80(
    DwordAndBytePayload_004ADB80* const outPayload,
    const std::uint32_t* const dwordSource,
    const std::uint8_t* const byteSource
  ) noexcept
  {
    outPayload->dwordLane = *dwordSource;
    outPayload->byteLane = *byteSource;
    return outPayload;
  }

  /**
   * Address: 0x004ADB90 (FUN_004ADB90)
   *
   * What it does:
   * Stores one dword lane into caller-provided output storage.
   */
  [[maybe_unused]] std::uint32_t* StoreDwordLane_004ADB90(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    *outValue = value;
    return outValue;
  }

  /**
   * Address: 0x004ADBE0 (FUN_004ADBE0)
   *
   * What it does:
   * Reads one dword lane from caller-provided storage.
   */
  [[maybe_unused]] std::uint32_t ReadDwordLane_004ADBE0(const std::uint32_t* const valueSlot) noexcept
  {
    return *valueSlot;
  }

  /**
   * Address: 0x004ADBF0 (FUN_004ADBF0)
   *
   * What it does:
   * Duplicate lane that stores one dword into output storage.
   */
  [[maybe_unused]] std::uint32_t* StoreDwordLane_004ADBF0(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreDwordLane_004ADB90(outValue, value);
  }

  /**
   * Address: 0x004ADC00 (FUN_004ADC00)
   *
   * What it does:
   * Duplicate lane that reads one dword from caller-provided storage.
   */
  [[maybe_unused]] std::uint32_t ReadDwordLane_004ADC00(const std::uint32_t* const valueSlot) noexcept
  {
    return ReadDwordLane_004ADBE0(valueSlot);
  }

  /**
   * Address: 0x004ADC30 (FUN_004ADC30)
   *
   * What it does:
   * Duplicate lane that copies one dword + one byte payload.
   */
  [[maybe_unused]] DwordAndBytePayload_004ADB80* CopyDwordAndBytePayload_004ADC30(
    DwordAndBytePayload_004ADB80* const outPayload,
    const std::uint32_t* const dwordSource,
    const std::uint8_t* const byteSource
  ) noexcept
  {
    return CopyDwordAndBytePayload_004ADB80(outPayload, dwordSource, byteSource);
  }

  /**
   * Address: 0x004ADC40 (FUN_004ADC40)
   *
   * What it does:
   * Duplicate lane that stores one dword into output storage.
   */
  [[maybe_unused]] std::uint32_t* StoreDwordLane_004ADC40(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreDwordLane_004ADB90(outValue, value);
  }

  /**
   * Address: 0x004ADC80 (FUN_004ADC80)
   *
   * What it does:
   * Duplicate lane that reads one dword from caller-provided storage.
   */
  [[maybe_unused]] std::uint32_t ReadDwordLane_004ADC80(const std::uint32_t* const valueSlot) noexcept
  {
    return ReadDwordLane_004ADBE0(valueSlot);
  }

  /**
   * Address: 0x004ADC90 (FUN_004ADC90)
   *
   * What it does:
   * Duplicate lane that stores one dword into output storage.
   */
  [[maybe_unused]] std::uint32_t* StoreDwordLane_004ADC90(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreDwordLane_004ADB90(outValue, value);
  }

  struct LegacyDwordSpliceRuntime4_004ADCE0
  {
    std::uint32_t* begin;            // +0x00
    std::uint32_t* end;              // +0x04
    std::uint32_t* capacityEnd;      // +0x08
    std::uint32_t** storageOwnerSlot; // +0x0C
  };

  static_assert(
    offsetof(LegacyDwordSpliceRuntime4_004ADCE0, begin) == 0x00,
    "LegacyDwordSpliceRuntime4_004ADCE0::begin offset must be 0x00"
  );
  static_assert(
    offsetof(LegacyDwordSpliceRuntime4_004ADCE0, end) == 0x04,
    "LegacyDwordSpliceRuntime4_004ADCE0::end offset must be 0x04"
  );
  static_assert(
    offsetof(LegacyDwordSpliceRuntime4_004ADCE0, capacityEnd) == 0x08,
    "LegacyDwordSpliceRuntime4_004ADCE0::capacityEnd offset must be 0x08"
  );
  static_assert(
    offsetof(LegacyDwordSpliceRuntime4_004ADCE0, storageOwnerSlot) == 0x0C,
    "LegacyDwordSpliceRuntime4_004ADCE0::storageOwnerSlot offset must be 0x0C"
  );
  static_assert(
    sizeof(LegacyDwordSpliceRuntime4_004ADCE0) == 0x10,
    "LegacyDwordSpliceRuntime4_004ADCE0 size must be 0x10"
  );

  /**
   * Address: 0x004ADDB0 (FUN_004ADDB0)
   *
   * What it does:
   * Copies one forward dword range and returns the advanced destination lane.
   */
  [[maybe_unused]] std::uint32_t* CopyDwordRangeForward_004ADDB0(
    std::uint32_t* destination,
    const std::uint32_t* sourceBegin,
    const std::uint32_t* sourceEnd
  ) noexcept
  {
    std::uintptr_t destinationLane = reinterpret_cast<std::uintptr_t>(destination);
    while (sourceBegin != sourceEnd) {
      if (destinationLane != 0U) {
        *reinterpret_cast<std::uint32_t*>(destinationLane) = *sourceBegin;
      }
      ++sourceBegin;
      destinationLane += sizeof(std::uint32_t);
    }
    return reinterpret_cast<std::uint32_t*>(destinationLane);
  }

  /**
   * Address: 0x004ADCE0 (FUN_004ADCE0)
   *
   * What it does:
   * Reallocates one dword vector lane and splices `[spliceBegin,spliceEnd)`
   * into the stream at `insertPosition`.
   */
  [[maybe_unused]] std::uint32_t ReallocateAndSpliceDwordRange_004ADCE0(
    LegacyDwordSpliceRuntime4_004ADCE0& vectorRuntime,
    std::uint32_t* const insertPosition,
    const std::uint32_t newElementCount,
    const std::uint32_t* const spliceBegin,
    const std::uint32_t* const spliceEnd
  )
  {
    auto* const newBegin = static_cast<std::uint32_t*>(
      ::operator new(static_cast<std::size_t>(newElementCount) * sizeof(std::uint32_t))
    );

    std::uint32_t* writeCursor = newBegin;
    writeCursor = CopyDwordRangeForward_004ADDB0(writeCursor, vectorRuntime.begin, insertPosition);
    writeCursor = CopyDwordRangeForward_004ADDB0(writeCursor, spliceBegin, spliceEnd);
    writeCursor = CopyDwordRangeForward_004ADDB0(writeCursor, insertPosition, vectorRuntime.end);

    if (vectorRuntime.begin == reinterpret_cast<std::uint32_t*>(vectorRuntime.storageOwnerSlot)) {
      *vectorRuntime.storageOwnerSlot = vectorRuntime.capacityEnd;
    } else {
      ::operator delete[](vectorRuntime.begin);
    }

    vectorRuntime.end = writeCursor;
    vectorRuntime.begin = newBegin;
    vectorRuntime.capacityEnd = newBegin + newElementCount;
    return newElementCount;
  }

  /**
   * Address: 0x004ADDD0 (FUN_004ADDD0)
   *
   * What it does:
   * Returns one legacy max-count constant for dword ring/vector growth lanes.
   */
  [[maybe_unused]] std::uint32_t ReadLegacyDwordGrowthMax_004ADDD0() noexcept
  {
    return 0x3FFFFFFFU;
  }

  struct LegacyDwordVectorContainer4_004ADDE0
  {
    std::uint32_t reserved00;     // +0x00
    std::uint32_t* begin;         // +0x04
    std::uint32_t* end;           // +0x08
    std::uint32_t* capacityEnd;   // +0x0C
  };

  static_assert(
    offsetof(LegacyDwordVectorContainer4_004ADDE0, begin) == 0x04,
    "LegacyDwordVectorContainer4_004ADDE0::begin offset must be 0x04"
  );
  static_assert(
    offsetof(LegacyDwordVectorContainer4_004ADDE0, end) == 0x08,
    "LegacyDwordVectorContainer4_004ADDE0::end offset must be 0x08"
  );
  static_assert(
    offsetof(LegacyDwordVectorContainer4_004ADDE0, capacityEnd) == 0x0C,
    "LegacyDwordVectorContainer4_004ADDE0::capacityEnd offset must be 0x0C"
  );
  static_assert(
    sizeof(LegacyDwordVectorContainer4_004ADDE0) == 0x10,
    "LegacyDwordVectorContainer4_004ADDE0 size must be 0x10"
  );

  /**
   * Address: 0x004ADFF0 (FUN_004ADFF0)
   *
   * What it does:
   * Throws the legacy "vector<T> too long" length-error path.
   */
  [[maybe_unused]] void ThrowVectorTooLong_004ADFF0()
  {
    throw std::length_error("vector<T> too long");
  }

  /**
   * Address: 0x004AE070 (FUN_004AE070, nullsub_708)
   *
   * What it does:
   * No-op helper thunk retained for callsite parity.
   */
  [[maybe_unused]] void NoOpHelperThunk_004AE070() noexcept {}

  /**
   * Address: 0x004AE0C0 (FUN_004AE0C0)
   *
   * What it does:
   * Returns one legacy max-count constant for 0x18-byte node vectors.
   */
  [[maybe_unused]] std::uint32_t ReadLegacyNodeVectorGrowthMax_004AE0C0() noexcept
  {
    return 0x1FFFFFFFU;
  }

  /**
   * Address: 0x004AE230 (FUN_004AE230, nullsub_709)
   *
   * What it does:
   * No-op helper thunk retained for callsite parity (`__stdcall` one arg).
   */
  [[maybe_unused]] void NoOpHelperThunk_004AE230(const std::uint32_t /*unused*/) noexcept {}

  /**
   * Address: 0x004AE240 (FUN_004AE240, nullsub_710)
   *
   * What it does:
   * No-op helper thunk retained for callsite parity.
   */
  [[maybe_unused]] void NoOpHelperThunk_004AE240() noexcept {}

  /**
   * Address: 0x004AE250 (FUN_004AE250, nullsub_711)
   *
   * What it does:
   * No-op helper thunk retained for callsite parity.
   */
  [[maybe_unused]] void NoOpHelperThunk_004AE250() noexcept {}

  struct DwordPairView_004AE290
  {
    std::uint32_t lane0; // +0x00
    std::uint32_t lane1; // +0x04
  };

  static_assert(
    offsetof(DwordPairView_004AE290, lane1) == 0x04,
    "DwordPairView_004AE290::lane1 offset must be 0x04"
  );
  static_assert(
    sizeof(DwordPairView_004AE290) == 0x08,
    "DwordPairView_004AE290 size must be 0x08"
  );

  /**
   * Address: 0x004AE290 (FUN_004AE290)
   *
   * What it does:
   * Copies one dword at offset `+0x04` into caller-provided output storage.
   */
  [[maybe_unused]] std::uint32_t* CopyDwordLaneAtOffset4_004AE290(
    std::uint32_t* const outLane,
    const DwordPairView_004AE290* const sourcePair
  ) noexcept
  {
    *outLane = sourcePair != nullptr ? sourcePair->lane1 : 0U;
    return outLane;
  }

  /**
   * Address: 0x004AE2A0 (FUN_004AE2A0)
   *
   * What it does:
   * Returns one legacy max-count constant for wider node/vector lanes.
   */
  [[maybe_unused]] std::uint32_t ReadLegacyWideNodeGrowthMax_004AE2A0() noexcept
  {
    return 0x03FFFFFFU;
  }

  /**
   * Address: 0x004ADDE0 (FUN_004ADDE0)
   *
   * What it does:
   * Inserts one dword value into a legacy vector container at a target slot,
   * growing storage when capacity is exhausted.
   */
  [[maybe_unused]] std::uint32_t* InsertSingleDwordIntoLegacyVector_004ADDE0(
    const std::uint32_t* const valueSlot,
    LegacyDwordVectorContainer4_004ADDE0& vectorRuntime,
    std::uint32_t* const insertionPosition
  )
  {
    const std::uint32_t value = valueSlot != nullptr ? *valueSlot : 0U;
    const std::uint32_t* const begin = vectorRuntime.begin;
    const std::uint32_t* const end = vectorRuntime.end;
    const std::uint32_t* const capacityEnd = vectorRuntime.capacityEnd;

    const std::uint32_t capacity =
      (begin != nullptr && capacityEnd != nullptr && capacityEnd >= begin)
        ? static_cast<std::uint32_t>(capacityEnd - begin)
        : 0U;
    const std::uint32_t size =
      (begin != nullptr && end != nullptr && end >= begin)
        ? static_cast<std::uint32_t>(end - begin)
        : 0U;

    if (size == 0x3FFFFFFFU) {
      ThrowVectorTooLong_004ADFF0();
    }

    std::uint32_t insertIndex = size;
    if (begin != nullptr && insertionPosition != nullptr
        && insertionPosition >= begin && insertionPosition <= end) {
      insertIndex = static_cast<std::uint32_t>(insertionPosition - begin);
    }

    if (capacity >= size + 1U) {
      std::uint32_t* const writeAt = vectorRuntime.begin + insertIndex;
      if (writeAt != vectorRuntime.end) {
        std::memmove(
          writeAt + 1,
          writeAt,
          static_cast<std::size_t>(vectorRuntime.end - writeAt) * sizeof(std::uint32_t)
        );
      }
      *writeAt = value;
      ++vectorRuntime.end;
      return vectorRuntime.begin;
    }

    std::uint32_t newCapacity = 0U;
    if (0x3FFFFFFFU - (capacity >> 1U) >= capacity) {
      newCapacity = capacity + (capacity >> 1U);
    }
    if (newCapacity < size + 1U) {
      newCapacity = size + 1U;
    }

    auto* const newBegin = static_cast<std::uint32_t*>(
      newCapacity != 0U
        ? ::operator new(static_cast<std::size_t>(newCapacity) * sizeof(std::uint32_t))
        : ::operator new(0U)
    );

    std::uint32_t* const newInsert = newBegin + insertIndex;
    if (insertIndex > 0U) {
      std::memmove(
        newBegin,
        vectorRuntime.begin,
        static_cast<std::size_t>(insertIndex) * sizeof(std::uint32_t)
      );
    }
    *newInsert = value;

    if (size > insertIndex) {
      std::memmove(
        newInsert + 1,
        vectorRuntime.begin + insertIndex,
        static_cast<std::size_t>(size - insertIndex) * sizeof(std::uint32_t)
      );
    }

    if (vectorRuntime.begin != nullptr) {
      ::operator delete(vectorRuntime.begin);
    }
    vectorRuntime.begin = newBegin;
    vectorRuntime.end = newBegin + size + 1U;
    vectorRuntime.capacityEnd = newBegin + newCapacity;
    return vectorRuntime.begin;
  }

  /**
   * Address: 0x004ACB80 (FUN_004ACB80)
   *
   * What it does:
   * Writes two dword lanes into one output pair storage.
   */
  [[maybe_unused]] std::uint32_t* CopyTwoDwordLanes(
    std::uint32_t* const outPairStorage,
    const std::uint32_t* const sourceLane0,
    const std::uint32_t* const sourceLane1
  ) noexcept
  {
    outPairStorage[0] = *sourceLane0;
    outPairStorage[1] = *sourceLane1;
    return outPairStorage;
  }

  /**
   * Address: 0x004ACBB0 (FUN_004ACBB0)
   *
   * What it does:
   * Reads one dword lane from caller-provided storage.
   */
  [[maybe_unused]] std::uint32_t ReadDwordLaneVariant1(const std::uint32_t* const dwordSlot) noexcept
  {
    return *dwordSlot;
  }

  /**
   * Address: 0x004ACC30 (FUN_004ACC30)
   *
   * What it does:
   * Rebinds one dword slot to the value at referenced offset `+0x04`.
   */
  [[maybe_unused]] std::uint32_t* RebindDwordSlotToOffset4(std::uint32_t* const slot) noexcept
  {
    const auto* const base = reinterpret_cast<const std::uint8_t*>(*slot);
    *slot = *reinterpret_cast<const std::uint32_t*>(base + 0x04);
    return slot;
  }

  /**
   * Address: 0x004ACC40 (FUN_004ACC40)
   *
   * What it does:
   * Reads one dword lane from caller-provided storage.
   */
  [[maybe_unused]] std::uint32_t ReadDwordLaneVariant2(const std::uint32_t* const dwordSlot) noexcept
  {
    return *dwordSlot;
  }

  /**
   * Address: 0x004ACC50 (FUN_004ACC50)
   *
   * What it does:
   * Duplicate lane that reads one dword from caller-provided storage.
   */
  [[maybe_unused]] std::uint32_t ReadDwordLaneVariant3(const std::uint32_t* const dwordSlot) noexcept
  {
    return ReadDwordLaneVariant2(dwordSlot);
  }

  struct LegacyPointerHeader4_004ACC70
  {
    std::uintptr_t lane0;
    std::uintptr_t lane1;
    std::uintptr_t lane2;
    std::uintptr_t lane3;
  };

  /**
   * Address: 0x004ACC70 (FUN_004ACC70)
   *
   * What it does:
   * Initializes one legacy 4-lane pointer header with fixed self offsets.
   */
  [[maybe_unused]] LegacyPointerHeader4_004ACC70* InitializeLegacyPointerHeader4(
    LegacyPointerHeader4_004ACC70* const header
  ) noexcept
  {
    const std::uintptr_t base = reinterpret_cast<std::uintptr_t>(header);
    header->lane0 = base + 0x10U;
    header->lane1 = base + 0x10U;
    header->lane2 = base + 0x30U;
    header->lane3 = base + 0x10U;
    return header;
  }

  /**
   * Address: 0x004ACD60 (FUN_004ACD60)
   *
   * What it does:
   * Swaps two dword lanes between two 2-lane storage slots.
   */
  [[maybe_unused]] std::uint32_t* SwapTwoDwordLanesVariant1(
    std::uint32_t* const lhsPairStorage,
    std::uint32_t* const rhsPairStorage
  ) noexcept
  {
    std::swap(lhsPairStorage[0], rhsPairStorage[0]);
    std::swap(lhsPairStorage[1], rhsPairStorage[1]);
    return lhsPairStorage;
  }

  struct LegacyDwordVectorRuntime3_004ACD80
  {
    std::uint32_t* begin;       // +0x00
    std::uint32_t* end;         // +0x04
    std::uint32_t* capacityEnd; // +0x08
  };

  static_assert(
    offsetof(LegacyDwordVectorRuntime3_004ACD80, begin) == 0x00,
    "LegacyDwordVectorRuntime3_004ACD80::begin offset must be 0x00"
  );
  static_assert(
    offsetof(LegacyDwordVectorRuntime3_004ACD80, end) == 0x04,
    "LegacyDwordVectorRuntime3_004ACD80::end offset must be 0x04"
  );
  static_assert(
    offsetof(LegacyDwordVectorRuntime3_004ACD80, capacityEnd) == 0x08,
    "LegacyDwordVectorRuntime3_004ACD80::capacityEnd offset must be 0x08"
  );
  static_assert(
    sizeof(LegacyDwordVectorRuntime3_004ACD80) == 0x0C,
    "LegacyDwordVectorRuntime3_004ACD80 size must be 0x0C"
  );

  /**
   * Address: 0x004ACD80 (FUN_004ACD80)
   *
   * What it does:
   * Inserts one dword range into one legacy 3-lane vector runtime at a target
   * insertion position, growing storage as needed.
   */
  [[maybe_unused]] int InsertDwordRangeIntoVectorRuntime(
    LegacyDwordVectorRuntime3_004ACD80& vectorRuntime,
    std::uint32_t* const insertionPosition,
    const std::uint32_t* const sourceBegin,
    const std::uint32_t* const sourceEnd
  )
  {
    if (sourceBegin == nullptr || sourceEnd == nullptr || sourceEnd < sourceBegin) {
      return 0;
    }

    const std::size_t insertCount = static_cast<std::size_t>(sourceEnd - sourceBegin);
    if (insertCount == 0U) {
      return 0;
    }

    const std::size_t currentSize =
      (vectorRuntime.begin != nullptr && vectorRuntime.end != nullptr && vectorRuntime.end >= vectorRuntime.begin)
        ? static_cast<std::size_t>(vectorRuntime.end - vectorRuntime.begin)
        : 0U;
    const std::size_t currentCapacity =
      (vectorRuntime.begin != nullptr && vectorRuntime.capacityEnd != nullptr
       && vectorRuntime.capacityEnd >= vectorRuntime.begin)
        ? static_cast<std::size_t>(vectorRuntime.capacityEnd - vectorRuntime.begin)
        : 0U;
    const std::size_t insertIndex =
      (vectorRuntime.begin != nullptr && insertionPosition != nullptr && insertionPosition >= vectorRuntime.begin)
        ? static_cast<std::size_t>(insertionPosition - vectorRuntime.begin)
        : currentSize;
    const std::size_t clampedInsertIndex = std::min(insertIndex, currentSize);
    const std::size_t requiredSize = currentSize + insertCount;

    if (requiredSize > currentCapacity) {
      std::size_t newCapacity = currentCapacity * 2U;
      if (newCapacity < requiredSize) {
        newCapacity = requiredSize;
      }

      std::uint32_t* const newBegin =
        static_cast<std::uint32_t*>(::operator new(newCapacity * sizeof(std::uint32_t), std::nothrow));
      if (newBegin == nullptr) {
        throw std::bad_alloc();
      }

      if (clampedInsertIndex > 0U) {
        std::memmove(
          newBegin,
          vectorRuntime.begin,
          clampedInsertIndex * sizeof(std::uint32_t)
        );
      }

      std::memmove(
        newBegin + clampedInsertIndex,
        sourceBegin,
        insertCount * sizeof(std::uint32_t)
      );

      const std::size_t tailCount = currentSize - clampedInsertIndex;
      if (tailCount > 0U) {
        std::memmove(
          newBegin + clampedInsertIndex + insertCount,
          vectorRuntime.begin + clampedInsertIndex,
          tailCount * sizeof(std::uint32_t)
        );
      }

      ::operator delete(vectorRuntime.begin);
      vectorRuntime.begin = newBegin;
      vectorRuntime.end = newBegin + requiredSize;
      vectorRuntime.capacityEnd = newBegin + newCapacity;
      return 0;
    }

    std::uint32_t* const insertAt = vectorRuntime.begin + clampedInsertIndex;
    std::uint32_t* const oldEnd = vectorRuntime.end;
    if (insertAt + insertCount <= oldEnd) {
      std::uint32_t* const tailCopyBegin = oldEnd - insertCount;
      if (insertCount > 0U) {
        std::memmove(oldEnd, tailCopyBegin, insertCount * sizeof(std::uint32_t));
      }

      vectorRuntime.end = oldEnd + insertCount;

      const std::size_t shiftedMiddleCount = static_cast<std::size_t>(tailCopyBegin - insertAt);
      if (shiftedMiddleCount > 0U) {
        std::memmove(oldEnd - shiftedMiddleCount, insertAt, shiftedMiddleCount * sizeof(std::uint32_t));
      }

      std::memmove(
        insertAt,
        sourceBegin,
        insertCount * sizeof(std::uint32_t)
      );
      return 0;
    }

    const std::size_t leftCount = static_cast<std::size_t>(oldEnd - insertAt);
    if (leftCount > 0U) {
      std::memmove(oldEnd, insertAt, leftCount * sizeof(std::uint32_t));
    }

    const std::size_t rightCount = insertCount - leftCount;
    std::uint32_t* writeCursor = oldEnd + leftCount;
    if (rightCount > 0U) {
      std::memmove(writeCursor, sourceBegin + leftCount, rightCount * sizeof(std::uint32_t));
      writeCursor += rightCount;
    }

    std::memmove(insertAt, sourceBegin, leftCount * sizeof(std::uint32_t));
    vectorRuntime.end = writeCursor;
    return 0;
  }

  struct LegacyDwordPointerWindow4_004ACE90
  {
    std::uint32_t* lane0;
    std::uint32_t* lane1;
    std::uint32_t* lane2;
    std::uint32_t* lane3;
  };

  /**
   * Address: 0x004ACE90 (FUN_004ACE90)
   *
   * What it does:
   * Initializes one 4-lane dword-pointer window from base + element count.
   */
  [[maybe_unused]] LegacyDwordPointerWindow4_004ACE90* InitializeDwordPointerWindow4(
    LegacyDwordPointerWindow4_004ACE90* const window,
    const std::uint32_t elementCount,
    std::uint32_t* const base
  ) noexcept
  {
    window->lane0 = base;
    window->lane1 = base;
    window->lane2 = base + elementCount;
    window->lane3 = base;
    return window;
  }

  /**
   * Address: 0x004ACED0 (FUN_004ACED0, nullsub_695)
   *
   * What it does:
   * No-op helper thunk retained for callsite parity.
   */
  [[maybe_unused]] void NoOpHelperThunkVariant1() noexcept {}

  using IntrusivePairLink_004ACF00 = moho::TDatListItem<void, void>;

  /**
   * Address: 0x004ACF00 (FUN_004ACF00)
   *
   * What it does:
   * Unlinks one intrusive pair-link node and rewires it to self-linked state.
   */
  [[maybe_unused]] IntrusivePairLink_004ACF00* UnlinkIntrusivePairLinkNode(
    IntrusivePairLink_004ACF00* const node
  ) noexcept
  {
    node->ListUnlink();
    return node;
  }

  /**
   * Address: 0x004ACF80 (FUN_004ACF80)
   *
   * What it does:
   * Duplicate lane that swaps two dword lanes across two 2-lane slots.
   */
  [[maybe_unused]] std::uint32_t* SwapTwoDwordLanesVariant2(
    std::uint32_t* const lhsPairStorage,
    std::uint32_t* const rhsPairStorage
  ) noexcept
  {
    return SwapTwoDwordLanesVariant1(lhsPairStorage, rhsPairStorage);
  }

  /**
   * Address: 0x004AD040 (FUN_004AD040)
   *
   * What it does:
   * Moves one dword tail range in a legacy vector runtime and exports the
   * destination iterator into output storage.
   */
  [[maybe_unused]] std::uint32_t** MoveDwordVectorTailAndExportDestinationVariant1(
    LegacyDwordVectorRuntime3_004ACD80& vectorRuntime,
    std::uint32_t** const outIterator,
    std::uint32_t* const destination,
    const std::uint32_t* const source
  ) noexcept
  {
    if (destination != source) {
      const std::size_t copyCount = static_cast<std::size_t>(vectorRuntime.end - source);
      if (copyCount > 0U) {
        std::memmove(destination, source, copyCount * sizeof(std::uint32_t));
      }
      vectorRuntime.end = destination + copyCount;
    }

    *outIterator = destination;
    return outIterator;
  }

  /**
   * Address: 0x004AD0D0 (FUN_004AD0D0, nullsub_696)
   *
   * What it does:
   * No-op helper thunk retained for callsite parity.
   */
  [[maybe_unused]] void NoOpHelperThunkVariant2() noexcept {}

  /**
   * Address: 0x004AD110 (FUN_004AD110)
   *
   * What it does:
   * Fills one dword range from one scalar source slot and returns end pointer.
   */
  [[maybe_unused]] std::uint32_t* FillDwordRangeFromScalarSlot(
    const std::uint32_t* const sourceSlot,
    std::uint32_t* const destination,
    const std::size_t count
  ) noexcept
  {
    std::fill_n(destination, count, *sourceSlot);
    return destination + count;
  }

  /**
   * Address: 0x004AD140 (FUN_004AD140, nullsub_697)
   *
   * What it does:
   * No-op helper thunk retained for callsite parity.
   */
  [[maybe_unused]] void NoOpHelperThunkVariant3(const std::uint32_t /*unused*/) noexcept {}

  /**
   * Address: 0x004AD150 (FUN_004AD150, nullsub_698)
   *
   * What it does:
   * No-op helper thunk retained for callsite parity.
   */
  [[maybe_unused]] void NoOpHelperThunkVariant4() noexcept {}

  /**
   * Address: 0x004AD190 (FUN_004AD190, nullsub_699)
   *
   * What it does:
   * No-op helper thunk retained for callsite parity.
   */
  [[maybe_unused]] void NoOpHelperThunkVariant5() noexcept {}

  struct RedBlackTreeNodeRuntime_004AD230
  {
    RedBlackTreeNodeRuntime_004AD230* left;   // +0x00
    RedBlackTreeNodeRuntime_004AD230* parent; // +0x04
    RedBlackTreeNodeRuntime_004AD230* right;  // +0x08
    std::uint32_t keyLane;                    // +0x0C
    std::uint32_t valueLane;                  // +0x10
    std::uint8_t color;                       // +0x14
    std::uint8_t isNil;                       // +0x15
    std::uint8_t pad16[2];
  };

  static_assert(
    offsetof(RedBlackTreeNodeRuntime_004AD230, left) == 0x00,
    "RedBlackTreeNodeRuntime_004AD230::left offset must be 0x00"
  );
  static_assert(
    offsetof(RedBlackTreeNodeRuntime_004AD230, parent) == 0x04,
    "RedBlackTreeNodeRuntime_004AD230::parent offset must be 0x04"
  );
  static_assert(
    offsetof(RedBlackTreeNodeRuntime_004AD230, right) == 0x08,
    "RedBlackTreeNodeRuntime_004AD230::right offset must be 0x08"
  );
  static_assert(
    offsetof(RedBlackTreeNodeRuntime_004AD230, color) == 0x14,
    "RedBlackTreeNodeRuntime_004AD230::color offset must be 0x14"
  );
  static_assert(
    offsetof(RedBlackTreeNodeRuntime_004AD230, isNil) == 0x15,
    "RedBlackTreeNodeRuntime_004AD230::isNil offset must be 0x15"
  );
  static_assert(
    sizeof(RedBlackTreeNodeRuntime_004AD230) == 0x18,
    "RedBlackTreeNodeRuntime_004AD230 size must be 0x18"
  );

  struct RedBlackTreeRuntime_004AD230
  {
    std::uint32_t reserved00;                 // +0x00
    RedBlackTreeNodeRuntime_004AD230* head;   // +0x04
    std::uint32_t nodeCount;                  // +0x08
  };

  static_assert(
    offsetof(RedBlackTreeRuntime_004AD230, head) == 0x04,
    "RedBlackTreeRuntime_004AD230::head offset must be 0x04"
  );
  static_assert(
    offsetof(RedBlackTreeRuntime_004AD230, nodeCount) == 0x08,
    "RedBlackTreeRuntime_004AD230::nodeCount offset must be 0x08"
  );
  static_assert(
    sizeof(RedBlackTreeRuntime_004AD230) == 0x0C,
    "RedBlackTreeRuntime_004AD230 size must be 0x0C"
  );

  constexpr std::uint8_t kRedBlackTreeColorRed_004AD230 = 0;
  constexpr std::uint8_t kRedBlackTreeColorBlack_004AD230 = 1;

  /**
   * Address: 0x004AD1F0 (FUN_004AD1F0)
   *
   * What it does:
   * Copies one tree-head leftmost-node pointer into caller-provided storage.
   */
  [[maybe_unused]] RedBlackTreeNodeRuntime_004AD230** CopyTreeHeadLeftmostNodeVariant1(
    RedBlackTreeNodeRuntime_004AD230** const outNode,
    const RedBlackTreeRuntime_004AD230& tree
  ) noexcept
  {
    *outNode = tree.head->left;
    return outNode;
  }

  [[nodiscard]] RedBlackTreeNodeRuntime_004AD230* RotateSubtreeLeft(
    RedBlackTreeNodeRuntime_004AD230* pivot,
    RedBlackTreeRuntime_004AD230& tree
  ) noexcept;

  [[nodiscard]] RedBlackTreeNodeRuntime_004AD230* RotateSubtreeRight(
    RedBlackTreeNodeRuntime_004AD230* pivot,
    RedBlackTreeRuntime_004AD230& tree
  ) noexcept;

  /**
   * Address: 0x004AE1F0 (FUN_004AE1F0)
   *
   * What it does:
   * Allocates one 0x18-byte red-black-tree node and seeds `{left,parent,right}`
   * plus one `{key,value}` payload pair.
   */
  [[nodiscard]] RedBlackTreeNodeRuntime_004AD230* AllocateTreeNodeFromPair_004AE1F0(
    RedBlackTreeNodeRuntime_004AD230* const head,
    RedBlackTreeNodeRuntime_004AD230* const parentHint,
    const std::uint32_t* const keyValuePair
  )
  {
    auto* const node = static_cast<RedBlackTreeNodeRuntime_004AD230*>(
      ::operator new(sizeof(RedBlackTreeNodeRuntime_004AD230))
    );
    node->left = head;
    node->parent = parentHint;
    node->right = head;
    node->keyLane = keyValuePair != nullptr ? keyValuePair[0] : 0U;
    node->valueLane = keyValuePair != nullptr ? keyValuePair[1] : 0U;
    node->color = kRedBlackTreeColorRed_004AD230;
    node->isNil = 0;
    node->pad16[0] = 0;
    node->pad16[1] = 0;
    return node;
  }

  /**
   * Address: 0x004AD230 (FUN_004AD230)
   *
   * What it does:
   * Inserts one node into one red-black tree runtime and rebalances the tree.
   */
  [[maybe_unused]] RedBlackTreeNodeRuntime_004AD230** InsertTreeNodeAndRebalance(
    RedBlackTreeRuntime_004AD230& tree,
    RedBlackTreeNodeRuntime_004AD230** const outInsertedNode,
    const bool insertToLeftOfParent,
    RedBlackTreeNodeRuntime_004AD230* const parentNode,
    const std::uint32_t* const keyValuePair
  )
  {
    if (tree.nodeCount >= 0x1FFFFFFEU) {
      throw std::length_error("map/set<T> too long");
    }

    RedBlackTreeNodeRuntime_004AD230* const head = tree.head;
    RedBlackTreeNodeRuntime_004AD230* insertedNode =
      AllocateTreeNodeFromPair_004AE1F0(head, parentNode, keyValuePair);
    ++tree.nodeCount;

    if (parentNode == head) {
      head->parent = insertedNode;
      head->left = insertedNode;
      head->right = insertedNode;
    } else if (!insertToLeftOfParent) {
      parentNode->right = insertedNode;
      if (parentNode == head->right) {
        head->right = insertedNode;
      }
    } else {
      parentNode->left = insertedNode;
      if (parentNode == head->left) {
        head->left = insertedNode;
      }
    }

    RedBlackTreeNodeRuntime_004AD230* rebalanceNode = insertedNode;
    while (rebalanceNode->parent->color == kRedBlackTreeColorRed_004AD230) {
      RedBlackTreeNodeRuntime_004AD230* const parent = rebalanceNode->parent;
      RedBlackTreeNodeRuntime_004AD230* const grandParent = parent->parent;
      if (parent == grandParent->left) {
        RedBlackTreeNodeRuntime_004AD230* const uncle = grandParent->right;
        if (uncle->color == kRedBlackTreeColorRed_004AD230) {
          parent->color = kRedBlackTreeColorBlack_004AD230;
          uncle->color = kRedBlackTreeColorBlack_004AD230;
          grandParent->color = kRedBlackTreeColorRed_004AD230;
          rebalanceNode = grandParent;
        } else {
          if (rebalanceNode == parent->right) {
            rebalanceNode = parent;
            (void)RotateSubtreeLeft(rebalanceNode, tree);
          }
          rebalanceNode->parent->color = kRedBlackTreeColorBlack_004AD230;
          rebalanceNode->parent->parent->color = kRedBlackTreeColorRed_004AD230;
          (void)RotateSubtreeRight(rebalanceNode->parent->parent, tree);
        }
      } else {
        RedBlackTreeNodeRuntime_004AD230* const uncle = grandParent->left;
        if (uncle->color == kRedBlackTreeColorRed_004AD230) {
          parent->color = kRedBlackTreeColorBlack_004AD230;
          uncle->color = kRedBlackTreeColorBlack_004AD230;
          grandParent->color = kRedBlackTreeColorRed_004AD230;
          rebalanceNode = grandParent;
        } else {
          if (rebalanceNode == parent->left) {
            rebalanceNode = parent;
            (void)RotateSubtreeRight(rebalanceNode, tree);
          }
          rebalanceNode->parent->color = kRedBlackTreeColorBlack_004AD230;
          rebalanceNode->parent->parent->color = kRedBlackTreeColorRed_004AD230;
          (void)RotateSubtreeLeft(rebalanceNode->parent->parent, tree);
        }
      }
    }

    tree.head->parent->color = kRedBlackTreeColorBlack_004AD230;
    *outInsertedNode = insertedNode;
    return outInsertedNode;
  }

  /**
   * Address: 0x004AD3E0 (FUN_004AD3E0)
   *
   * What it does:
   * Returns one node's parent pointer.
   */
  [[maybe_unused]] RedBlackTreeNodeRuntime_004AD230* ReadTreeNodeParent(
    RedBlackTreeNodeRuntime_004AD230* const node
  ) noexcept
  {
    return node->parent;
  }

  /**
   * Address: 0x004AD3F0 (FUN_004AD3F0)
   *
   * What it does:
   * Performs one left rotation around a red-black tree node.
   */
  [[nodiscard]] RedBlackTreeNodeRuntime_004AD230* RotateSubtreeLeft(
    RedBlackTreeNodeRuntime_004AD230* const pivot,
    RedBlackTreeRuntime_004AD230& tree
  ) noexcept
  {
    RedBlackTreeNodeRuntime_004AD230* const newRoot = pivot->right;
    pivot->right = newRoot->left;
    if (newRoot->left->isNil == 0) {
      newRoot->left->parent = pivot;
    }

    newRoot->parent = pivot->parent;
    RedBlackTreeNodeRuntime_004AD230* const head = tree.head;
    if (pivot == head->parent) {
      head->parent = newRoot;
    } else if (pivot == pivot->parent->left) {
      pivot->parent->left = newRoot;
    } else {
      pivot->parent->right = newRoot;
    }

    newRoot->left = pivot;
    pivot->parent = newRoot;
    return newRoot;
  }

  /**
   * Address: 0x004AD440 (FUN_004AD440)
   *
   * What it does:
   * Walks to the rightmost descendant while skipping the sentinel node.
   */
  [[maybe_unused]] RedBlackTreeNodeRuntime_004AD230* FindRightmostDescendant(
    RedBlackTreeNodeRuntime_004AD230* node
  ) noexcept
  {
    RedBlackTreeNodeRuntime_004AD230* cursor = node->right;
    while (cursor->isNil == 0) {
      node = cursor;
      cursor = node->right;
    }
    return node;
  }

  /**
   * Address: 0x004AD460 (FUN_004AD460)
   *
   * What it does:
   * Walks to the leftmost descendant while skipping the sentinel node.
   */
  [[maybe_unused]] RedBlackTreeNodeRuntime_004AD230* FindLeftmostDescendant(
    RedBlackTreeNodeRuntime_004AD230* node
  ) noexcept
  {
    RedBlackTreeNodeRuntime_004AD230* cursor = node->left;
    while (cursor->isNil == 0) {
      node = cursor;
      cursor = node->left;
    }
    return node;
  }

  /**
   * Address: 0x004AD4A0 (FUN_004AD4A0)
   *
   * What it does:
   * Performs one right rotation around a red-black tree node.
   */
  [[nodiscard]] RedBlackTreeNodeRuntime_004AD230* RotateSubtreeRight(
    RedBlackTreeNodeRuntime_004AD230* const pivot,
    RedBlackTreeRuntime_004AD230& tree
  ) noexcept
  {
    RedBlackTreeNodeRuntime_004AD230* const newRoot = pivot->left;
    pivot->left = newRoot->right;
    if (newRoot->right->isNil == 0) {
      newRoot->right->parent = pivot;
    }

    newRoot->parent = pivot->parent;
    RedBlackTreeNodeRuntime_004AD230* const head = tree.head;
    if (pivot == head->parent) {
      head->parent = newRoot;
    } else if (pivot == pivot->parent->right) {
      pivot->parent->right = newRoot;
    } else {
      pivot->parent->left = newRoot;
    }

    newRoot->right = pivot;
    pivot->parent = newRoot;
    return newRoot;
  }

  /**
   * Address: 0x004AD520 (FUN_004AD520, nullsub_700)
   *
   * What it does:
   * No-op helper thunk retained for callsite parity.
   */
  [[maybe_unused]] void NoOpHelperThunkVariant6() noexcept {}

  /**
   * Address: 0x004AD530 (FUN_004AD530, nullsub_701)
   *
   * What it does:
   * No-op helper thunk retained for callsite parity.
   */
  [[maybe_unused]] void NoOpHelperThunkVariant7() noexcept {}

  /**
   * Address: 0x004AD550 (FUN_004AD550, nullsub_702)
   *
   * What it does:
   * No-op helper thunk retained for callsite parity.
   */
  [[maybe_unused]] void NoOpHelperThunkVariant8() noexcept {}

  /**
   * Address: 0x004AD580 (FUN_004AD580, nullsub_703)
   *
   * What it does:
   * No-op helper thunk retained for callsite parity.
   */
  [[maybe_unused]] void NoOpHelperThunkVariant9() noexcept {}

  /**
   * Address: 0x004AD5D0 (FUN_004AD5D0)
   *
   * What it does:
   * Duplicate lane that copies the tree-head leftmost-node pointer.
   */
  [[maybe_unused]] RedBlackTreeNodeRuntime_004AD230** CopyTreeHeadLeftmostNodeVariant2(
    RedBlackTreeNodeRuntime_004AD230** const outNode,
    const RedBlackTreeRuntime_004AD230& tree
  ) noexcept
  {
    return CopyTreeHeadLeftmostNodeVariant1(outNode, tree);
  }

  struct RedBlackTreeWideNodeRuntime_004AE3B0
  {
    RedBlackTreeWideNodeRuntime_004AE3B0* left;   // +0x00
    RedBlackTreeWideNodeRuntime_004AE3B0* parent; // +0x04
    RedBlackTreeWideNodeRuntime_004AE3B0* right;  // +0x08
    PrefetchRequestRuntime runtime;               // +0x0C
    std::uint8_t color;                           // +0x4C
    std::uint8_t isNil;                           // +0x4D
    std::uint8_t pad4E[2];
  };

  static_assert(
    offsetof(RedBlackTreeWideNodeRuntime_004AE3B0, left) == 0x00,
    "RedBlackTreeWideNodeRuntime_004AE3B0::left offset must be 0x00"
  );
  static_assert(
    offsetof(RedBlackTreeWideNodeRuntime_004AE3B0, parent) == 0x04,
    "RedBlackTreeWideNodeRuntime_004AE3B0::parent offset must be 0x04"
  );
  static_assert(
    offsetof(RedBlackTreeWideNodeRuntime_004AE3B0, right) == 0x08,
    "RedBlackTreeWideNodeRuntime_004AE3B0::right offset must be 0x08"
  );
  static_assert(
    offsetof(RedBlackTreeWideNodeRuntime_004AE3B0, runtime) == 0x0C,
    "RedBlackTreeWideNodeRuntime_004AE3B0::runtime offset must be 0x0C"
  );
  static_assert(
    offsetof(RedBlackTreeWideNodeRuntime_004AE3B0, color) == 0x4C,
    "RedBlackTreeWideNodeRuntime_004AE3B0::color offset must be 0x4C"
  );
  static_assert(
    offsetof(RedBlackTreeWideNodeRuntime_004AE3B0, isNil) == 0x4D,
    "RedBlackTreeWideNodeRuntime_004AE3B0::isNil offset must be 0x4D"
  );
  static_assert(
    sizeof(RedBlackTreeWideNodeRuntime_004AE3B0) == 0x50,
    "RedBlackTreeWideNodeRuntime_004AE3B0 size must be 0x50"
  );

  struct RedBlackTreeWideRuntime_004AE3B0
  {
    std::uint32_t reserved00;                      // +0x00
    RedBlackTreeWideNodeRuntime_004AE3B0* head;    // +0x04
    std::uint32_t nodeCount;                       // +0x08
  };

  static_assert(
    offsetof(RedBlackTreeWideRuntime_004AE3B0, head) == 0x04,
    "RedBlackTreeWideRuntime_004AE3B0::head offset must be 0x04"
  );
  static_assert(
    offsetof(RedBlackTreeWideRuntime_004AE3B0, nodeCount) == 0x08,
    "RedBlackTreeWideRuntime_004AE3B0::nodeCount offset must be 0x08"
  );
  static_assert(
    sizeof(RedBlackTreeWideRuntime_004AE3B0) == 0x0C,
    "RedBlackTreeWideRuntime_004AE3B0 size must be 0x0C"
  );

  /**
   * Address: 0x004AE3A0 (FUN_004AE3A0)
   *
   * What it does:
   * Returns one wide red-black-tree node parent lane.
   */
  [[maybe_unused]] RedBlackTreeWideNodeRuntime_004AE3B0* ReadWideTreeNodeParent_004AE3A0(
    const RedBlackTreeWideNodeRuntime_004AE3B0* const node
  ) noexcept
  {
    return node != nullptr ? node->parent : nullptr;
  }

  /**
   * Address: 0x004AE3B0 (FUN_004AE3B0)
   *
   * What it does:
   * Performs one left rotation around a wide red-black-tree node.
   */
  [[maybe_unused]] RedBlackTreeWideNodeRuntime_004AE3B0* RotateWideSubtreeLeft_004AE3B0(
    RedBlackTreeWideNodeRuntime_004AE3B0* const pivot,
    RedBlackTreeWideRuntime_004AE3B0& tree
  ) noexcept
  {
    RedBlackTreeWideNodeRuntime_004AE3B0* const newRoot = pivot->right;
    pivot->right = newRoot->left;
    if (newRoot->left->isNil == 0) {
      newRoot->left->parent = pivot;
    }

    newRoot->parent = pivot->parent;
    RedBlackTreeWideNodeRuntime_004AE3B0* const head = tree.head;
    if (pivot == head->parent) {
      head->parent = newRoot;
    } else if (pivot == pivot->parent->left) {
      pivot->parent->left = newRoot;
    } else {
      pivot->parent->right = newRoot;
    }

    newRoot->left = pivot;
    pivot->parent = newRoot;
    return newRoot;
  }

  /**
   * Address: 0x004AE410 (FUN_004AE410)
   *
   * What it does:
   * Performs one right rotation around a wide red-black-tree node.
   */
  [[maybe_unused]] RedBlackTreeWideNodeRuntime_004AE3B0* RotateWideSubtreeRight_004AE410(
    RedBlackTreeWideNodeRuntime_004AE3B0* const pivot,
    RedBlackTreeWideRuntime_004AE3B0& tree
  ) noexcept
  {
    RedBlackTreeWideNodeRuntime_004AE3B0* const newRoot = pivot->left;
    pivot->left = newRoot->right;
    if (newRoot->right->isNil == 0) {
      newRoot->right->parent = pivot;
    }

    newRoot->parent = pivot->parent;
    RedBlackTreeWideNodeRuntime_004AE3B0* const head = tree.head;
    if (pivot == head->parent) {
      head->parent = newRoot;
    } else if (pivot == pivot->parent->right) {
      pivot->parent->right = newRoot;
    } else {
      pivot->parent->left = newRoot;
    }

    newRoot->right = pivot;
    pivot->parent = newRoot;
    return newRoot;
  }

  /**
   * Address: 0x004AE4F0 (FUN_004AE4F0, nullsub_712)
   *
   * What it does:
   * No-op helper thunk retained for callsite parity (`__stdcall` one arg).
   */
  [[maybe_unused]] void NoOpHelperThunk_004AE4F0(const std::uint32_t /*unused*/) noexcept {}

  /**
   * Address: 0x004AE500 (FUN_004AE500, nullsub_713)
   *
   * What it does:
   * No-op helper thunk retained for callsite parity.
   */
  [[maybe_unused]] void NoOpHelperThunk_004AE500() noexcept {}

  /**
   * Address: 0x004AE520 (FUN_004AE520, nullsub_714)
   *
   * What it does:
   * No-op helper thunk retained for callsite parity.
   */
  [[maybe_unused]] void NoOpHelperThunk_004AE520() noexcept {}

  /**
   * Address: 0x004AE530 (FUN_004AE530)
   *
   * What it does:
   * Returns one legacy max-count constant for wide tree/map node growth.
   */
  [[maybe_unused]] std::uint32_t ReadLegacyWideTreeGrowthMax_004AE530() noexcept
  {
    return 0x1FFFFFFFU;
  }

  /**
   * Address: 0x004AE610 (FUN_004AE610, nullsub_715)
   *
   * What it does:
   * No-op helper thunk retained for callsite parity (`__stdcall` one arg).
   */
  [[maybe_unused]] void NoOpHelperThunk_004AE610(const std::uint32_t /*unused*/) noexcept {}

  /**
   * Address: 0x004AE620 (FUN_004AE620, nullsub_716)
   *
   * What it does:
   * No-op helper thunk retained for callsite parity.
   */
  [[maybe_unused]] void NoOpHelperThunk_004AE620() noexcept {}

  /**
   * Address: 0x004AE670 (FUN_004AE670, nullsub_717)
   *
   * What it does:
   * No-op helper thunk retained for callsite parity.
   */
  [[maybe_unused]] void NoOpHelperThunk_004AE670() noexcept {}

  /**
   * Address: 0x004AE680 (FUN_004AE680)
   *
   * What it does:
   * Copies one caller-provided dword lane into output storage.
   */
  [[maybe_unused]] std::uint32_t* CopyDwordLane_004AE680(
    std::uint32_t* const outLane,
    const std::uint32_t value
  ) noexcept
  {
    *outLane = value;
    return outLane;
  }

  /**
   * Address: 0x004AE6C0 (FUN_004AE6C0)
   *
   * What it does:
   * Stores one dword address lane computed as `base + index*4`.
   */
  [[maybe_unused]] std::uint32_t* ComputeDwordAddressLane_004AE6C0(
    std::uint32_t* const outLane,
    const std::uint32_t* const baseAddressLane,
    const std::int32_t elementIndex
  ) noexcept
  {
    *outLane = *baseAddressLane + (static_cast<std::uint32_t>(elementIndex) * 4U);
    return outLane;
  }

  /**
   * Address: 0x004AE6E0 (FUN_004AE6E0)
   *
   * What it does:
   * Duplicate lane that copies one caller-provided dword into output storage.
   */
  [[maybe_unused]] std::uint32_t* CopyDwordLane_004AE6E0(
    std::uint32_t* const outLane,
    const std::uint32_t value
  ) noexcept
  {
    return CopyDwordLane_004AE680(outLane, value);
  }

  /**
   * Address: 0x004AE6F0 (FUN_004AE6F0)
   *
   * What it does:
   * Duplicate lane that copies one caller-provided dword into output storage.
   */
  [[maybe_unused]] std::uint32_t* CopyDwordLane_004AE6F0(
    std::uint32_t* const outLane,
    const std::uint32_t value
  ) noexcept
  {
    return CopyDwordLane_004AE680(outLane, value);
  }

  /**
   * Address: 0x004AE710 (FUN_004AE710)
   *
   * What it does:
   * Advances one wide red-black-tree iterator to its in-order successor.
   */
  [[maybe_unused]] RedBlackTreeWideNodeRuntime_004AE3B0* AdvanceWideTreeIterator_004AE710(
    RedBlackTreeWideNodeRuntime_004AE3B0*& iterator
  ) noexcept
  {
    RedBlackTreeWideNodeRuntime_004AE3B0* result = iterator;
    if (result != nullptr && result->isNil == 0) {
      RedBlackTreeWideNodeRuntime_004AE3B0* right = result->right;
      if (right->isNil != 0) {
        result = result->parent;
        while (result->isNil == 0) {
          if (iterator != result->right) {
            break;
          }
          iterator = result;
          result = result->parent;
        }
        iterator = result;
      } else {
        result = right->left;
        if (right->left->isNil == 0) {
          do {
            right = result;
            result = result->left;
          } while (result->isNil == 0);
        }
        iterator = right;
      }
    }
    return result;
  }

  /**
   * Address: 0x004AE760 (FUN_004AE760)
   *
   * What it does:
   * Duplicate lane that copies one caller-provided dword into output storage.
   */
  [[maybe_unused]] std::uint32_t* CopyDwordLane_004AE760(
    std::uint32_t* const outLane,
    const std::uint32_t value
  ) noexcept
  {
    return CopyDwordLane_004AE680(outLane, value);
  }

  /**
   * Address: 0x004AE770 (FUN_004AE770)
   *
   * What it does:
   * Stores two caller-provided dword lanes into output pair storage.
   */
  [[maybe_unused]] std::uint32_t* StoreTwoDwordLanes_004AE770(
    std::uint32_t* const outPair,
    const std::uint32_t lane1,
    const std::uint32_t lane0
  ) noexcept
  {
    outPair[0] = lane0;
    outPair[1] = lane1;
    return outPair;
  }

  /**
   * Address: 0x004AE7B0 (FUN_004AE7B0)
   *
   * What it does:
   * Returns one legacy max-count constant for dword lane growth.
   */
  [[maybe_unused]] std::uint32_t ReadLegacyDwordGrowthMax_004AE7B0() noexcept
  {
    return 0x3FFFFFFFU;
  }

  /**
   * Address: 0x004AE7F0 (FUN_004AE7F0)
   *
   * What it does:
   * Allocates one 0x18-byte red-black-tree node and seeds zero links with
   * black color in legacy constructor lanes.
   */
  [[maybe_unused]] RedBlackTreeNodeRuntime_004AD230* AllocateBlackTreeNode_004AE7F0()
  {
    auto* const node = static_cast<RedBlackTreeNodeRuntime_004AD230*>(
      ::operator new(sizeof(RedBlackTreeNodeRuntime_004AD230))
    );
    node->left = nullptr;
    node->parent = nullptr;
    node->right = nullptr;
    node->color = kRedBlackTreeColorBlack_004AD230;
    node->isNil = 0;
    return node;
  }

  /**
   * Address: 0x004AE830 (FUN_004AE830, nullsub_718)
   *
   * What it does:
   * No-op helper thunk retained for callsite parity (`__stdcall` one arg).
   */
  [[maybe_unused]] void NoOpHelperThunk_004AE830(const std::uint32_t /*unused*/) noexcept {}

  /**
   * Address: 0x004AE840 (FUN_004AE840)
   *
   * What it does:
   * Returns one legacy max-count constant for 0x18-byte node lanes.
   */
  [[maybe_unused]] std::uint32_t ReadLegacyNodeGrowthMax_004AE840() noexcept
  {
    return 0x1FFFFFFFU;
  }

  /**
   * Address: 0x004AE850 (FUN_004AE850)
   *
   * What it does:
   * Allocates raw storage for one 0x18-byte red-black-tree node lane.
   */
  [[maybe_unused]] RedBlackTreeNodeRuntime_004AD230* AllocateRawTreeNodeStorage_004AE850()
  {
    return static_cast<RedBlackTreeNodeRuntime_004AD230*>(
      ::operator new(sizeof(RedBlackTreeNodeRuntime_004AD230))
    );
  }

  /**
   * Address: 0x004AEB50 (FUN_004AEB50)
   *
   * What it does:
   * Walks one wide tree node down its left chain to the leftmost descendant.
   */
  [[maybe_unused]] RedBlackTreeWideNodeRuntime_004AE3B0* FindWideTreeLeftmostDescendant_004AEB50(
    RedBlackTreeWideNodeRuntime_004AE3B0* node
  ) noexcept
  {
    RedBlackTreeWideNodeRuntime_004AE3B0* cursor = node->left;
    if (cursor->isNil == 0) {
      do {
        node = cursor;
        cursor = cursor->left;
      } while (cursor->isNil == 0);
    }
    return node;
  }

  /**
   * Address: 0x004AEE80 (FUN_004AEE80)
   *
   * What it does:
   * Walks one wide tree node down its right chain to the rightmost descendant.
   */
  [[maybe_unused]] RedBlackTreeWideNodeRuntime_004AE3B0* FindWideTreeRightmostDescendant_004AEE80(
    RedBlackTreeWideNodeRuntime_004AE3B0* node
  ) noexcept
  {
    RedBlackTreeWideNodeRuntime_004AE3B0* cursor = node->right;
    while (cursor->isNil == 0) {
      node = cursor;
      cursor = node->right;
    }
    return node;
  }

  /**
   * Address: 0x004AEB70 (FUN_004AEB70)
   *
   * What it does:
   * Allocates one wide tree node with cleared link lanes and black color.
   */
  [[maybe_unused]] RedBlackTreeWideNodeRuntime_004AE3B0* AllocateBlackWideTreeNode_004AEB70()
  {
    auto* const node = static_cast<RedBlackTreeWideNodeRuntime_004AE3B0*>(
      ::operator new(sizeof(RedBlackTreeWideNodeRuntime_004AE3B0))
    );
    node->left = nullptr;
    node->parent = nullptr;
    node->right = nullptr;
    node->color = kRedBlackTreeColorBlack_004AD230;
    node->isNil = 0;
    return node;
  }

  /**
   * Address: 0x004AEBB0 (FUN_004AEBB0, nullsub_719)
   *
   * What it does:
   * No-op helper thunk retained for callsite parity (`__stdcall` one arg).
   */
  [[maybe_unused]] void NoOpHelperThunk_004AEBB0(const std::uint32_t /*unused*/) noexcept {}

  /**
   * Address: 0x004AEBC0 (FUN_004AEBC0)
   *
   * What it does:
   * Returns one legacy max-count constant for dword lane growth.
   */
  [[maybe_unused]] std::uint32_t ReadLegacyDwordGrowthMax_004AEBC0() noexcept
  {
    return 0x03FFFFFFU;
  }

  /**
   * Address: 0x004AEBD0 (FUN_004AEBD0)
   *
   * What it does:
   * Allocates raw storage for one wide (0x50-byte) tree node lane.
   */
  [[maybe_unused]] RedBlackTreeWideNodeRuntime_004AE3B0* AllocateRawWideTreeNodeStorage_004AEBD0()
  {
    return static_cast<RedBlackTreeWideNodeRuntime_004AE3B0*>(
      ::operator new(sizeof(RedBlackTreeWideNodeRuntime_004AE3B0))
    );
  }

  /**
   * Address: 0x004AEBE0 (FUN_004AEBE0)
   *
   * What it does:
   * Returns one legacy max-count constant for wide-node growth.
   */
  [[maybe_unused]] std::uint32_t ReadLegacyWideNodeGrowthMax_004AEBE0() noexcept
  {
    return 0x1FFFFFFFU;
  }

  /**
   * Address: 0x004AEC00 (FUN_004AEC00)
   *
   * What it does:
   * Moves one narrow red-black-tree iterator to its in-order predecessor.
   */
  [[maybe_unused]] RedBlackTreeNodeRuntime_004AD230* RetreatTreeIterator_004AEC00(
    RedBlackTreeNodeRuntime_004AD230*& iterator
  ) noexcept
  {
    RedBlackTreeNodeRuntime_004AD230* result = iterator;
    if (result->isNil != 0) {
      result = result->right;
      iterator = result;
      return result;
    }

    RedBlackTreeNodeRuntime_004AD230* left = result->left;
    if (left->isNil != 0) {
      result = result->parent;
      while (result->isNil == 0) {
        if (iterator != result->left) {
          break;
        }
        iterator = result;
        result = result->parent;
      }

      if (iterator->isNil == 0) {
        iterator = result;
      }
      return result;
    }

    result = left->right;
    while (result->isNil == 0) {
      left = result;
      result = result->right;
    }
    iterator = left;
    return result;
  }

  /**
   * Address: 0x004AEC60 (FUN_004AEC60)
   *
   * What it does:
   * Advances one narrow red-black-tree iterator to its in-order successor.
   */
  [[maybe_unused]] RedBlackTreeNodeRuntime_004AD230* AdvanceTreeIterator_004AEC60(
    RedBlackTreeNodeRuntime_004AD230*& iterator
  ) noexcept
  {
    RedBlackTreeNodeRuntime_004AD230* result = iterator;
    if (result->isNil != 0) {
      return result;
    }

    RedBlackTreeNodeRuntime_004AD230* right = result->right;
    if (right->isNil != 0) {
      result = result->parent;
      while (result->isNil == 0) {
        if (iterator != result->right) {
          break;
        }
        iterator = result;
        result = result->parent;
      }
      iterator = result;
      return result;
    }

    result = right->left;
    if (right->left->isNil == 0) {
      do {
        right = result;
        result = result->left;
      } while (result->isNil == 0);
    }
    iterator = right;
    return result;
  }

  /**
   * Address: 0x004AECE0 (FUN_004AECE0)
   *
   * What it does:
   * Moves one wide red-black-tree iterator to its in-order predecessor.
   */
  [[maybe_unused]] RedBlackTreeWideNodeRuntime_004AE3B0* RetreatWideTreeIterator_004AECE0(
    RedBlackTreeWideNodeRuntime_004AE3B0*& iterator
  ) noexcept
  {
    RedBlackTreeWideNodeRuntime_004AE3B0* result = iterator;
    if (result->isNil != 0) {
      result = result->right;
      iterator = result;
      return result;
    }

    RedBlackTreeWideNodeRuntime_004AE3B0* left = result->left;
    if (left->isNil != 0) {
      result = result->parent;
      while (result->isNil == 0) {
        if (iterator != result->left) {
          break;
        }
        iterator = result;
        result = result->parent;
      }

      if (iterator->isNil == 0) {
        iterator = result;
      }
      return result;
    }

    result = left->right;
    while (result->isNil == 0) {
      left = result;
      result = result->right;
    }
    iterator = left;
    return result;
  }

  /**
   * Address: 0x004AED40 (FUN_004AED40)
   *
   * What it does:
   * Stores two caller-provided dword lanes into output pair storage.
   */
  [[maybe_unused]] std::uint32_t* StoreTwoDwordLanes_004AED40(
    std::uint32_t* const outPair,
    const std::uint32_t lane1,
    const std::uint32_t lane0
  ) noexcept
  {
    outPair[0] = lane0;
    outPair[1] = lane1;
    return outPair;
  }

  /**
   * Address: 0x004AEDE0 (FUN_004AEDE0)
   *
   * What it does:
   * Recursively destroys one narrow-tree node subtree (right branch first),
   * then deletes each traversed node while walking left links.
   */
  [[maybe_unused]] void DestroyTreeNodeSubtree_004AEDE0(
    RedBlackTreeNodeRuntime_004AD230* node
  ) noexcept
  {
    RedBlackTreeNodeRuntime_004AD230* current = node;
    if (current->isNil != 0) {
      return;
    }

    do {
      DestroyTreeNodeSubtree_004AEDE0(current->right);
      RedBlackTreeNodeRuntime_004AD230* const next = current->left;
      ::operator delete(current);
      current = next;
    } while (current->isNil == 0);
  }

  /**
   * Address: 0x004AEE20 (FUN_004AEE20, nullsub_720)
   *
   * What it does:
   * No-op helper thunk retained for callsite parity (`__stdcall` one arg).
   */
  [[maybe_unused]] void NoOpHelperThunk_004AEE20(const std::uint32_t /*unused*/) noexcept {}

  /**
   * Address: 0x004AEE40 (FUN_004AEE40)
   *
   * What it does:
   * Recursively destroys one wide-tree node subtree (right branch first),
   * destroys each node runtime payload, then deletes each traversed node while
   * walking left links.
   */
  [[maybe_unused]] void DestroyWideTreeNodeSubtree_004AEE40(
    RedBlackTreeWideNodeRuntime_004AE3B0* node
  ) noexcept
  {
    RedBlackTreeWideNodeRuntime_004AE3B0* current = node;
    if (current->isNil != 0) {
      return;
    }

    do {
      DestroyWideTreeNodeSubtree_004AEE40(current->right);
      RedBlackTreeWideNodeRuntime_004AE3B0* const next = current->left;
      (void)DestroyPrefetchRequestRuntime(&current->runtime);
      ::operator delete(current);
      current = next;
    } while (current->isNil == 0);
  }

  /**
   * Address: 0x004AEEA0 (FUN_004AEEA0, nullsub_721)
   *
   * What it does:
   * No-op helper thunk retained for callsite parity (`__stdcall` one arg).
   */
  [[maybe_unused]] void NoOpHelperThunk_004AEEA0(const std::uint32_t /*unused*/) noexcept {}

  /**
   * Address: 0x004AEEE0 (FUN_004AEEE0, nullsub_722)
   *
   * What it does:
   * No-op helper thunk retained for callsite parity (`__stdcall` one arg).
   */
  [[maybe_unused]] void NoOpHelperThunk_004AEEE0(const std::uint32_t /*unused*/) noexcept {}

  /**
   * Address: 0x004AEEF0 (FUN_004AEEF0, nullsub_723)
   *
   * What it does:
   * No-op helper thunk retained for callsite parity (`__stdcall` one arg).
   */
  [[maybe_unused]] void NoOpHelperThunk_004AEEF0(const std::uint32_t /*unused*/) noexcept {}

  /**
   * Address: 0x004AEF90 (FUN_004AEF90)
   *
   * What it does:
   * Rebinds one shared `(px,pi)` pair: retains incoming control, releases
   * previously bound shared control, then stores the incoming control lane.
   */
  [[maybe_unused]] boost::SharedCountPair* AssignSharedPairRetainRelease_004AEF90(
    const boost::SharedCountPair* const sourcePair,
    boost::SharedCountPair* const outPair
  ) noexcept
  {
    outPair->px = sourcePair->px;
    boost::detail::sp_counted_base* const incomingControl = sourcePair->pi;
    if (incomingControl != nullptr) {
      incomingControl->add_ref_copy();
    }

    boost::detail::sp_counted_base* const previousControl = outPair->pi;
    if (previousControl != nullptr) {
      previousControl->release();
    }

    outPair->pi = incomingControl;
    return outPair;
  }

  /**
   * Address: 0x004AEFD0 (FUN_004AEFD0)
   *
   * What it does:
   * Constructs one shared prefetch-data pointer from one raw payload pointer.
   */
  [[maybe_unused]] boost::shared_ptr<moho::PrefetchData>* ConstructSharedPrefetchDataFromRaw_004AEFD0(
    boost::shared_ptr<moho::PrefetchData>* const outShared,
    moho::PrefetchData* const payload
  )
  {
    return boost::ConstructSharedFromRaw(outShared, payload);
  }

  /**
   * Address: 0x004AEFF0 (FUN_004AEFF0)
   *
   * What it does:
   * Copies one shared `(px,pi)` pair and retains one shared control-block ref.
   */
  [[maybe_unused]] boost::SharedCountPair* AssignSharedPairRetain_004AEFF0(
    boost::SharedCountPair* const outPair,
    const boost::SharedCountPair* const sourcePair
  ) noexcept
  {
    return boost::AssignSharedPairRetain(outPair, sourcePair);
  }

  struct DwordTripleRuntime_004AF050
  {
    std::uint32_t lane0; // +0x00
    std::uint32_t lane1; // +0x04
    std::uint32_t lane2; // +0x08
  };

  static_assert(sizeof(DwordTripleRuntime_004AF050) == 0x0C, "DwordTripleRuntime_004AF050 size must be 0x0C");

  /**
   * Address: 0x004AF050 (FUN_004AF050)
   *
   * What it does:
   * Stores three caller-provided dword lanes into output tuple storage.
   */
  [[maybe_unused]] DwordTripleRuntime_004AF050* StoreThreeDwordLanes_004AF050(
    DwordTripleRuntime_004AF050* const outTriple,
    const std::uint32_t lane0,
    const std::uint32_t lane1,
    const std::uint32_t lane2
  ) noexcept
  {
    outTriple->lane0 = lane0;
    outTriple->lane1 = lane1;
    outTriple->lane2 = lane2;
    return outTriple;
  }

  /**
   * Address: 0x004AF250 (FUN_004AF250)
   *
   * What it does:
   * Swaps one dword lane between two caller-provided slots.
   */
  [[maybe_unused]] std::uint32_t* SwapDwordSlots_004AF250(
    std::uint32_t* const lhsSlot,
    std::uint32_t* const rhsSlot
  ) noexcept
  {
    const std::uint32_t temp = *rhsSlot;
    *rhsSlot = *lhsSlot;
    *lhsSlot = temp;
    return lhsSlot;
  }

  /**
   * Address: 0x004AF2C0 (FUN_004AF2C0, nullsub_724)
   *
   * What it does:
   * No-op helper thunk retained for callsite parity.
   */
  [[maybe_unused]] void NoOpHelperThunk_004AF2C0() noexcept {}

  /**
   * Address: 0x004AF2F0 (FUN_004AF2F0, nullsub_725)
   *
   * What it does:
   * No-op helper thunk retained for callsite parity.
   */
  [[maybe_unused]] void NoOpHelperThunk_004AF2F0() noexcept {}

  /**
   * Address: 0x004AF350 (FUN_004AF350, nullsub_726)
   *
   * What it does:
   * No-op helper thunk retained for callsite parity.
   */
  [[maybe_unused]] void NoOpHelperThunk_004AF350() noexcept {}

  /**
   * Address: 0x004AF360 (FUN_004AF360)
   *
   * What it does:
   * Allocates one contiguous buffer sized `elementCount * 8` with legacy
   * overflow guard and `std::bad_alloc` throw path.
   */
  [[maybe_unused]] void* AllocateChecked8ByteStride_004AF360(const std::uint32_t elementCount)
  {
    if (elementCount > 0x1FFFFFFFU) {
      throw std::bad_alloc();
    }
    return ::operator new(static_cast<std::size_t>(elementCount) * 8U);
  }

  /**
   * Address: 0x004AF3F0 (FUN_004AF3F0)
   *
   * What it does:
   * Moves one dword range `[sourceBegin, sourceEnd)` into `destination` and
   * returns the end pointer after moved lanes.
   */
  [[maybe_unused]] std::uint32_t* MoveDwordRangeAndReturnEnd_004AF3F0(
    std::uint32_t* const destination,
    const std::uint32_t* const sourceBegin,
    const std::uint32_t* const sourceEnd
  ) noexcept
  {
    if (sourceEnd <= sourceBegin) {
      return destination;
    }

    const std::size_t dwordCount = static_cast<std::size_t>(sourceEnd - sourceBegin);
    std::memmove(destination, sourceBegin, dwordCount * sizeof(std::uint32_t));
    return destination + dwordCount;
  }

  /**
   * Address: 0x004AF430 (FUN_004AF430)
   *
   * What it does:
   * Copies one dword range `[sourceBegin, sourceEnd)` into the lane ending at
   * `destinationEnd`, returning the computed destination-begin pointer.
   */
  [[maybe_unused]] std::uint32_t* CopyDwordRangeToEndAndReturnBegin_004AF430(
    std::uint32_t* const destinationEnd,
    const std::uint32_t* const sourceBegin,
    const std::uint32_t* const sourceEnd
  ) noexcept
  {
    if (sourceEnd <= sourceBegin) {
      return destinationEnd;
    }

    const std::size_t dwordCount = static_cast<std::size_t>(sourceEnd - sourceBegin);
    std::uint32_t* const destinationBegin = destinationEnd - dwordCount;
    std::memmove(destinationBegin, sourceBegin, dwordCount * sizeof(std::uint32_t));
    return destinationBegin;
  }

  /**
   * Address: 0x004AF460 (FUN_004AF460)
   *
   * What it does:
   * Allocates one contiguous buffer sized `elementCount * 4` with legacy
   * overflow guard and `std::bad_alloc` throw path.
   */
  [[maybe_unused]] void* AllocateChecked4ByteStride_004AF460(const std::uint32_t elementCount)
  {
    if (elementCount > 0x3FFFFFFFU) {
      throw std::bad_alloc();
    }
    return ::operator new(static_cast<std::size_t>(elementCount) * 4U);
  }

  /**
   * Address: 0x004AF4B0 (FUN_004AF4B0, nullsub_727)
   *
   * What it does:
   * No-op helper thunk retained for callsite parity.
   */
  [[maybe_unused]] void NoOpHelperThunk_004AF4B0() noexcept {}

  /**
   * Address: 0x004AF4C0 (FUN_004AF4C0, nullsub_728)
   *
   * What it does:
   * No-op helper thunk retained for callsite parity.
   */
  [[maybe_unused]] void NoOpHelperThunk_004AF4C0() noexcept {}

  /**
   * Address: 0x004AF4D0 (FUN_004AF4D0, nullsub_729)
   *
   * What it does:
   * No-op helper thunk retained for callsite parity.
   */
  [[maybe_unused]] void NoOpHelperThunk_004AF4D0() noexcept {}

  /**
   * Address: 0x004AF4E0 (FUN_004AF4E0)
   *
   * What it does:
   * Duplicate lane for checked allocation of `elementCount * 4` bytes.
   */
  [[maybe_unused]] void* AllocateChecked4ByteStride_004AF4E0(const std::uint32_t elementCount)
  {
    return AllocateChecked4ByteStride_004AF460(elementCount);
  }

  /**
   * Address: 0x004AF530 (FUN_004AF530, nullsub_730)
   *
   * What it does:
   * No-op helper thunk retained for callsite parity.
   */
  [[maybe_unused]] void NoOpHelperThunk_004AF530() noexcept {}

  /**
   * Address: 0x004AF540 (FUN_004AF540, nullsub_731)
   *
   * What it does:
   * No-op helper thunk retained for callsite parity.
   */
  [[maybe_unused]] void NoOpHelperThunk_004AF540() noexcept {}

  /**
   * Address: 0x004AF550 (FUN_004AF550)
   *
   * What it does:
   * Allocates one contiguous buffer sized `elementCount * 24` with legacy
   * overflow guard and `std::bad_alloc` throw path.
   */
  [[maybe_unused]] void* AllocateChecked24ByteStride_004AF550(const std::uint32_t elementCount)
  {
    if (elementCount > 0x0AAAAAAAU) {
      throw std::bad_alloc();
    }
    return ::operator new(static_cast<std::size_t>(elementCount) * 24U);
  }

  /**
   * Address: 0x004AF5B0 (FUN_004AF5B0, nullsub_732)
   *
   * What it does:
   * No-op helper thunk retained for callsite parity.
   */
  [[maybe_unused]] void NoOpHelperThunk_004AF5B0() noexcept {}

  /**
   * Address: 0x004AF5C0 (FUN_004AF5C0)
   *
   * What it does:
   * Allocates one contiguous buffer sized `elementCount * 80` with legacy
   * overflow guard and `std::bad_alloc` throw path.
   */
  [[maybe_unused]] void* AllocateChecked80ByteStride_004AF5C0(const std::uint32_t elementCount)
  {
    if (elementCount > 0x03333333U) {
      throw std::bad_alloc();
    }
    return ::operator new(static_cast<std::size_t>(elementCount) * 80U);
  }

  /**
   * Address: 0x004AF610 (FUN_004AF610, nullsub_733)
   *
   * What it does:
   * No-op helper thunk retained for callsite parity.
   */
  [[maybe_unused]] void NoOpHelperThunk_004AF610() noexcept {}

  /**
   * Address: 0x004AF630 (FUN_004AF630, nullsub_734)
   *
   * What it does:
   * No-op helper thunk retained for callsite parity.
   */
  [[maybe_unused]] void NoOpHelperThunk_004AF630() noexcept {}

  struct DwordPairRuntime_004AF6F0
  {
    std::uint32_t lane0; // +0x00
    std::uint32_t lane1; // +0x04
  };

  static_assert(sizeof(DwordPairRuntime_004AF6F0) == 0x08, "DwordPairRuntime_004AF6F0 size must be 0x08");

  /**
   * Address: 0x004AF6D0 (FUN_004AF6D0)
   *
   * What it does:
   * Stores two caller-provided dword lanes and one dereferenced lane into
   * output triple storage.
   */
  [[maybe_unused]] DwordTripleRuntime_004AF050* StoreDwordPairAndDereferencedLane_004AF6D0(
    DwordTripleRuntime_004AF050* const outTriple,
    const std::uint32_t lane0,
    const std::uint32_t lane1,
    const std::uint32_t* const lane2Source
  ) noexcept
  {
    outTriple->lane0 = lane0;
    outTriple->lane1 = lane1;
    outTriple->lane2 = lane2Source != nullptr ? *lane2Source : 0U;
    return outTriple;
  }

  /**
   * Address: 0x004AF6F0 (FUN_004AF6F0)
   *
   * What it does:
   * Stores two caller-provided dword lanes into output pair storage.
   */
  [[maybe_unused]] DwordPairRuntime_004AF6F0* StoreTwoDwordLanes_004AF6F0(
    DwordPairRuntime_004AF6F0* const outPair,
    const std::uint32_t lane0,
    const std::uint32_t lane1
  ) noexcept
  {
    outPair->lane0 = lane0;
    outPair->lane1 = lane1;
    return outPair;
  }

  [[nodiscard]] std::uint32_t* StoreDwordLaneFromValueCore_004AF700(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    *outValue = value;
    return outValue;
  }

  /**
   * Address: 0x004AF700 (FUN_004AF700)
   *
   * What it does:
   * Stores one caller-provided dword lane into output storage.
   */
  [[maybe_unused]] std::uint32_t* StoreDwordLaneFromValue_004AF700(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreDwordLaneFromValueCore_004AF700(outValue, value);
  }

  /**
   * Address: 0x004AF710 (FUN_004AF710)
   *
   * What it does:
   * Copies one dword lane from source storage into output storage.
   */
  [[maybe_unused]] std::uint32_t* CopyDwordLaneFromSource_004AF710(
    std::uint32_t* const outValue,
    const std::uint32_t* const sourceValue
  ) noexcept
  {
    *outValue = *sourceValue;
    return outValue;
  }

  /**
   * Address: 0x004AF720 (FUN_004AF720)
   *
   * What it does:
   * Duplicate lane of single-dword store into output storage.
   */
  [[maybe_unused]] std::uint32_t* StoreDwordLaneFromValue_004AF720(
    std::uint32_t* const outValue,
    const std::uint32_t value
  ) noexcept
  {
    return StoreDwordLaneFromValueCore_004AF700(outValue, value);
  }

  /**
   * Address: 0x004AF790 (FUN_004AF790)
   *
   * What it does:
   * Constructs one `boost::detail::shared_count` for prefetch payload
   * ownership from one raw `PrefetchData*`.
   */
  [[maybe_unused]] boost::detail::shared_count* ConstructPrefetchSharedCountFromRaw_004AF790(
    boost::detail::shared_count* const outCount,
    moho::PrefetchData* const payload
  )
  {
    return boost::ConstructSharedCountFromRaw(outCount, payload);
  }

  /**
   * Address: 0x004AF870 (FUN_004AF870, nullsub_735)
   *
   * What it does:
   * No-op helper thunk retained for callsite parity.
   */
  [[maybe_unused]] void NoOpHelperThunk_004AF870() noexcept {}

  [[nodiscard]] std::uint8_t ExtractHighByteCore_004AF880(const std::uint32_t packedValue) noexcept
  {
    return static_cast<std::uint8_t>((packedValue >> 8U) & 0xFFU);
  }

  /**
   * Address: 0x004AF880 (FUN_004AF880)
   *
   * What it does:
   * Returns the high byte from one caller-provided dword lane.
   */
  [[maybe_unused]] std::uint8_t ExtractHighByte_004AF880(const std::uint32_t packedValue) noexcept
  {
    return ExtractHighByteCore_004AF880(packedValue);
  }

  /**
   * Address: 0x004AF8B0 (FUN_004AF8B0, nullsub_736)
   *
   * What it does:
   * No-op helper thunk retained for callsite parity.
   */
  [[maybe_unused]] void NoOpHelperThunk_004AF8B0() noexcept {}

  /**
   * Address: 0x004AF8C0 (FUN_004AF8C0)
   *
   * What it does:
   * Duplicate lane of high-byte extraction from one dword input.
   */
  [[maybe_unused]] std::uint8_t ExtractHighByte_004AF8C0(const std::uint32_t packedValue) noexcept
  {
    return ExtractHighByteCore_004AF880(packedValue);
  }

  /**
   * Address: 0x004AF8F0 (FUN_004AF8F0, nullsub_737)
   *
   * What it does:
   * No-op helper thunk retained for callsite parity.
   */
  [[maybe_unused]] void NoOpHelperThunk_004AF8F0() noexcept {}

  /**
   * Address: 0x004AF900 (FUN_004AF900)
   *
   * What it does:
   * Duplicate lane of high-byte extraction from one dword input.
   */
  [[maybe_unused]] std::uint8_t ExtractHighByte_004AF900(const std::uint32_t packedValue) noexcept
  {
    return ExtractHighByteCore_004AF880(packedValue);
  }

  /**
   * Address: 0x004AF930 (FUN_004AF930, nullsub_738)
   *
   * What it does:
   * No-op helper thunk retained for callsite parity.
   */
  [[maybe_unused]] void NoOpHelperThunk_004AF930() noexcept {}

  /**
   * Address: 0x004AF960 (FUN_004AF960)
   *
   * What it does:
   * Duplicate lane of high-byte extraction from one dword input.
   */
  [[maybe_unused]] std::uint8_t ExtractHighByte_004AF960(const std::uint32_t packedValue) noexcept
  {
    return ExtractHighByteCore_004AF880(packedValue);
  }

  /**
   * Address: 0x004AF9B0 (FUN_004AF9B0, nullsub_739)
   *
   * What it does:
   * No-op helper thunk retained for callsite parity.
   */
  [[maybe_unused]] void NoOpHelperThunk_004AF9B0() noexcept {}

  /**
   * Address: 0x004AFA00 (FUN_004AFA00)
   *
   * What it does:
   * Duplicate lane of high-byte extraction from one dword input.
   */
  [[maybe_unused]] std::uint8_t ExtractHighByte_004AFA00(const std::uint32_t packedValue) noexcept
  {
    return ExtractHighByteCore_004AF880(packedValue);
  }

  using PrefetchDataCountedImplStorage_004AFA60 = boost::SpCountedImplStorage<moho::PrefetchData>;
  static_assert(
    sizeof(PrefetchDataCountedImplStorage_004AFA60) == 0x10,
    "PrefetchDataCountedImplStorage_004AFA60 size must be 0x10"
  );

  [[nodiscard]] void* ResolvePrefetchDataCountedImplVtable_004AFA60()
  {
    static void* sVtable = []() -> void* {
      boost::detail::sp_counted_impl_p<moho::PrefetchData> probe(nullptr);
      return *reinterpret_cast<void**>(&probe);
    }();
    return sVtable;
  }

  /**
   * Address: 0x004AFA60 (FUN_004AFA60)
   *
   * What it does:
   * Initializes one `sp_counted_impl_p<PrefetchData>` storage lane with
   * use/weak counts set to one and owned payload pointer at `+0x0C`.
   */
  [[maybe_unused]] PrefetchDataCountedImplStorage_004AFA60* InitializePrefetchDataCountedImplStorage_004AFA60(
    PrefetchDataCountedImplStorage_004AFA60* const outStorage,
    moho::PrefetchData* const payload
  ) noexcept
  {
    return boost::InitSpCountedImplStorage(
      outStorage,
      ResolvePrefetchDataCountedImplVtable_004AFA60(),
      payload
    );
  }

  [[maybe_unused]] void ReleasePrefetchDataSharedPairsForDelete_004AFA80(
    moho::PrefetchData* const payload
  ) noexcept
  {
    boost::ReleaseSharedControlOnly(&payload->mPrefetch);
    boost::ReleaseSharedControlOnly(&payload->mResolved);
  }

  /**
   * Address: 0x004AFA80 (FUN_004AFA80)
   *
   * What it does:
   * Disposes one counted prefetch payload by releasing nested shared lanes
   * then deleting the payload storage.
   */
  [[maybe_unused]] void DisposePrefetchDataCountedPayload_004AFA80(
    const PrefetchDataCountedImplStorage_004AFA60* const countedImpl
  ) noexcept
  {
    moho::PrefetchData* const payload = countedImpl != nullptr ? countedImpl->px : nullptr;
    if (payload != nullptr) {
      ReleasePrefetchDataSharedPairsForDelete_004AFA80(payload);
      ::operator delete(payload);
    }
  }

  /**
   * Address: 0x004AFAA0 (FUN_004AFAA0)
   *
   * What it does:
   * Returns legacy null get-deleter lane for counted prefetch payload storage.
   */
  [[maybe_unused]] int GetPrefetchDataCountedImplDeleterNullResult_004AFAA0(
    const void* const typeInfoQuery
  ) noexcept
  {
    return boost::LegacyGetDeleterNullResult(typeInfoQuery);
  }

  /**
   * Address: 0x004AFAB0 (FUN_004AFAB0)
   *
   * What it does:
   * Models the deleting-destructor thunk lane for prefetch counted-base
   * storage, with optional heap delete controlled by `deleteFlag & 1`.
   */
  [[maybe_unused]] boost::detail::sp_counted_base* DestructPrefetchCountedBaseDeleting_004AFAB0(
    boost::detail::sp_counted_base* const self,
    const unsigned char deleteFlag
  ) noexcept
  {
    return boost::SpCountedImplDeletingDtor(self, deleteFlag);
  }

  /**
   * Address: 0x004AFAD0 (FUN_004AFAD0)
   *
   * What it does:
   * Models the non-deleting destructor body lane for prefetch counted-base
   * storage.
   */
  [[maybe_unused]] boost::detail::sp_counted_base* DestructPrefetchCountedBaseNonDeleting_004AFAD0(
    boost::detail::sp_counted_base* const self
  ) noexcept
  {
    return boost::SpCountedImplNonDeletingDtor(self);
  }

  /**
   * Address: 0x004AFAE0 (FUN_004AFAE0)
   *
   * What it does:
   * Releases one prefetch payload's nested shared lanes and deletes payload
   * storage when the payload pointer is non-null.
   */
  [[maybe_unused]] void DestroyPrefetchDataPayloadIfPresent_004AFAE0(
    moho::PrefetchData* const payload
  ) noexcept
  {
    if (payload != nullptr) {
      ReleasePrefetchDataSharedPairsForDelete_004AFA80(payload);
      ::operator delete(payload);
    }
  }

  struct ScopedRecursiveMutexLockRuntime_004AEF30
  {
    boost::recursive_mutex* mutex; // +0x00
    std::uint8_t isLocked;         // +0x04
    std::uint8_t pad05[3];
  };

  static_assert(
    offsetof(ScopedRecursiveMutexLockRuntime_004AEF30, mutex) == 0x00,
    "ScopedRecursiveMutexLockRuntime_004AEF30::mutex offset must be 0x00"
  );
  static_assert(
    offsetof(ScopedRecursiveMutexLockRuntime_004AEF30, isLocked) == 0x04,
    "ScopedRecursiveMutexLockRuntime_004AEF30::isLocked offset must be 0x04"
  );
  static_assert(
    sizeof(ScopedRecursiveMutexLockRuntime_004AEF30) == 0x08,
    "ScopedRecursiveMutexLockRuntime_004AEF30 size must be 0x08"
  );

  /**
   * Address: 0x004AEF30 (FUN_004AEF30)
   *
   * What it does:
   * Validates one scoped recursive lock lane, enters one condition wait by
   * unlocking with cv-state transfer, blocks, then re-acquires the lock.
   */
  [[maybe_unused]] void WaitConditionWithScopedRecursiveLock_004AEF30(
    ScopedRecursiveMutexLockRuntime_004AEF30* const scopedLock,
    boost::detail::condition_impl* const conditionImpl
  )
  {
    if (scopedLock == nullptr || scopedLock->isLocked == 0) {
      throw boost::lock_error();
    }

    using LockOps_004AEF30 = boost::detail::thread::lock_ops<boost::recursive_mutex>;
    LockOps_004AEF30::lock_state state{};
    conditionImpl->enter_wait();
    LockOps_004AEF30::unlock(*scopedLock->mutex, state);
    conditionImpl->do_wait();
    LockOps_004AEF30::lock(*scopedLock->mutex, state);
  }

  struct PrefetchThreadCallableBuffer_004AFB20
  {
    std::uint32_t lane0; // +0x00
    std::uint32_t lane1; // +0x04
    std::uint32_t lane2; // +0x08
    std::uint32_t lane3; // +0x0C
  };

  static_assert(sizeof(PrefetchThreadCallableBuffer_004AFB20) == 0x10, "PrefetchThreadCallableBuffer_004AFB20 size must be 0x10");

  using PrefetchThreadEntryThunk_004AFDE0 = void(__thiscall *)(char*);

  using PrefetchThreadBindType_004AFDF0 = boost::_bi::bind_t<
    void,
    boost::_mfi::mf0<void, moho::ResourceManager>,
    boost::_bi::list1<boost::_bi::value<moho::ResourceManager*>>
  >;

  using PrefetchThreadManagerFn_004AFDF0 = void(__cdecl *)(
    const PrefetchThreadCallableBuffer_004AFB20*,
    PrefetchThreadCallableBuffer_004AFB20*,
    boost::detail::function::functor_manager_operation_type
  );

  using PrefetchThreadInvokerFn_004AFDE0 = void(__cdecl *)(
    PrefetchThreadCallableBuffer_004AFB20*,
    moho::ResourceManager*
  );

  struct PrefetchThreadCallableVtable_004AF810
  {
    PrefetchThreadManagerFn_004AFDF0 manager; // +0x00
    PrefetchThreadInvokerFn_004AFDE0 invoker; // +0x04
  };

  static_assert(sizeof(PrefetchThreadCallableVtable_004AF810) == 0x08, "PrefetchThreadCallableVtable_004AF810 size must be 0x08");

  struct PrefetchThreadCallableRuntime_004AF070
  {
    PrefetchThreadCallableVtable_004AF810* vtable;  // +0x00
    std::uint32_t reserved04;                       // +0x04
    PrefetchThreadCallableBuffer_004AFB20 payload;  // +0x08
  };

  static_assert(sizeof(PrefetchThreadCallableRuntime_004AF070) == 0x18, "PrefetchThreadCallableRuntime_004AF070 size must be 0x18");

  std::uint32_t sPrefetchThreadCallableInitFlags_004AF810 = 0;
  PrefetchThreadCallableVtable_004AF810 sPrefetchThreadCallableVtable_004AF810{};

  /**
   * Address: 0x004AFB20 (FUN_004AFB20)
   *
   * What it does:
   * Builds one 4-lane callable payload; rejects placement when guard reports
   * failure, otherwise copies lanes into caller output when provided.
   */
  [[maybe_unused]] bool BuildPrefetchThreadCallablePayload_004AFB20(
    PrefetchThreadCallableBuffer_004AFB20* const outPayload,
    const std::uint32_t lane0,
    const std::uint32_t lane1,
    const std::uint32_t lane2,
    const std::uint32_t lane3
  ) noexcept
  {
    const PrefetchThreadCallableBuffer_004AFB20 pending{
      lane0,
      lane1,
      lane2,
      lane3
    };

    // The inlined placement guard lane (`sub_412B30`) evaluates false in the
    // recovered binary path here, so payload construction proceeds.
    const bool shouldRejectPlacement = false;
    if (shouldRejectPlacement) {
      return false;
    }

    if (outPayload != nullptr) {
      *outPayload = pending;
    }
    return true;
  }

  /**
   * Address: 0x004AFDE0 (FUN_004AFDE0)
   *
   * What it does:
   * Invokes one bound prefetch-thread callable by computing adjusted `this`
   * pointer lane (`lane1 + lane2`) and jumping through callable entry lane.
   */
  [[maybe_unused]] void InvokePrefetchThreadCallable_004AFDE0(
    PrefetchThreadCallableBuffer_004AFB20* const callablePayload,
    moho::ResourceManager* const /*unusedContext*/
  )
  {
    const auto entryThunk = reinterpret_cast<PrefetchThreadEntryThunk_004AFDE0>(
      static_cast<std::uintptr_t>(callablePayload->lane0)
    );
    char* const objectBase = reinterpret_cast<char*>(static_cast<std::uintptr_t>(callablePayload->lane1));
    const std::uintptr_t thisOffset = static_cast<std::uintptr_t>(callablePayload->lane2);
    entryThunk(objectBase + thisOffset);
  }

  /**
   * Address: 0x004AFDF0 (FUN_004AFDF0)
   *
   * What it does:
   * Manages one prefetch-thread callable payload for clone/destroy/type-check/
   * type-query operations.
   */
  [[maybe_unused]] void ManagePrefetchThreadCallable_004AFDF0(
    const PrefetchThreadCallableBuffer_004AFB20* const inPayload,
    PrefetchThreadCallableBuffer_004AFB20* const outPayload,
    const boost::detail::function::functor_manager_operation_type operation
  )
  {
    using Operation_004AFDF0 = boost::detail::function::functor_manager_operation_type;

    if (operation == Operation_004AFDF0::get_functor_type_tag) {
      outPayload->lane0 = static_cast<std::uint32_t>(
        reinterpret_cast<std::uintptr_t>(&typeid(PrefetchThreadBindType_004AFDF0))
      );
      return;
    }

    if (operation == Operation_004AFDF0::clone_functor_tag) {
      if (outPayload != nullptr) {
        *outPayload = *inPayload;
      }
      return;
    }

    if (operation == Operation_004AFDF0::destroy_functor_tag) {
      return;
    }

    const auto* const checkType = reinterpret_cast<const std::type_info*>(
      static_cast<std::uintptr_t>(outPayload->lane0)
    );
    outPayload->lane0 = (checkType != nullptr && (*checkType == typeid(PrefetchThreadBindType_004AFDF0)))
      ? static_cast<std::uint32_t>(reinterpret_cast<std::uintptr_t>(inPayload))
      : 0U;
  }

  [[nodiscard]] PrefetchThreadCallableVtable_004AF810* InitializePrefetchThreadCallableVtableGlobalCore_004AFB00() noexcept
  {
    sPrefetchThreadCallableVtable_004AF810.invoker = &InvokePrefetchThreadCallable_004AFDE0;
    sPrefetchThreadCallableVtable_004AF810.manager = &ManagePrefetchThreadCallable_004AFDF0;
    return &sPrefetchThreadCallableVtable_004AF810;
  }

  /**
   * Address: 0x004AFB00 (FUN_004AFB00)
   *
   * What it does:
   * Stores the prefetch callable invoker/manager pair in global vtable
   * storage and returns that global vtable address.
   */
  [[maybe_unused]] PrefetchThreadCallableVtable_004AF810* InitializePrefetchThreadCallableVtableGlobal_004AFB00(
    const std::uint32_t /*unusedLane0*/,
    const std::uint32_t /*unusedLane1*/,
    const std::uint32_t /*unusedLane2*/,
    const std::uint32_t /*unusedLane3*/
  ) noexcept
  {
    return InitializePrefetchThreadCallableVtableGlobalCore_004AFB00();
  }

  /**
   * Address: 0x004AFC30 (FUN_004AFC30)
   *
   * What it does:
   * Duplicate lane of global prefetch callable vtable initialization.
   */
  [[maybe_unused]] void InitializePrefetchThreadCallableVtableGlobal_004AFC30(
    const std::uint32_t /*unusedLane0*/,
    const std::uint32_t /*unusedLane1*/,
    const std::uint32_t /*unusedLane2*/,
    const std::uint32_t /*unusedLane3*/
  ) noexcept
  {
    (void)InitializePrefetchThreadCallableVtableGlobalCore_004AFB00();
  }

  /**
   * Address: 0x004AFC90 (FUN_004AFC90, nullsub_740)
   *
   * What it does:
   * No-op helper thunk retained for callsite parity.
   */
  [[maybe_unused]] void NoOpHelperThunk_004AFC90() noexcept {}

  /**
   * Address: 0x004AFCC0 (FUN_004AFCC0, nullsub_741)
   *
   * What it does:
   * No-op helper thunk retained for callsite parity.
   */
  [[maybe_unused]] void NoOpHelperThunk_004AFCC0() noexcept {}

  /**
   * Address: 0x004AFD20 (FUN_004AFD20)
   *
   * What it does:
   * Duplicate lane of global prefetch callable vtable initialization.
   */
  [[maybe_unused]] void InitializePrefetchThreadCallableVtableGlobal_004AFD20(
    const std::uint32_t /*unusedLane0*/,
    const std::uint32_t /*unusedLane1*/,
    const std::uint32_t /*unusedLane2*/,
    const std::uint32_t /*unusedLane3*/,
    const std::uint32_t /*unusedLane4*/
  ) noexcept
  {
    (void)InitializePrefetchThreadCallableVtableGlobalCore_004AFB00();
  }

  /**
   * Address: 0x004AFD40 (FUN_004AFD40, nullsub_742)
   *
   * What it does:
   * No-op helper thunk retained for callsite parity.
   */
  [[maybe_unused]] void NoOpHelperThunk_004AFD40() noexcept {}

  /**
   * Address: 0x004AFF00 (FUN_004AFF00, nullsub_743)
   *
   * What it does:
   * No-op helper thunk retained for callsite parity.
   */
  [[maybe_unused]] void NoOpHelperThunk_004AFF00() noexcept {}

  /**
   * Address: 0x004AFF10 (FUN_004AFF10, nullsub_744)
   *
   * What it does:
   * No-op helper thunk retained for callsite parity.
   */
  [[maybe_unused]] void NoOpHelperThunk_004AFF10() noexcept {}

  /**
   * Address: 0x004AF810 (FUN_004AF810)
   *
   * What it does:
   * Lazily initializes one callable vtable pair, builds payload lanes at
   * output `+0x08`, and stores vtable pointer at output `+0x00` when build
   * succeeds (otherwise stores null).
   */
  [[maybe_unused]] PrefetchThreadCallableVtable_004AF810* AssignPrefetchThreadCallableVtable_004AF810(
    PrefetchThreadCallableRuntime_004AF070* const outCallable,
    const std::uint32_t lane0,
    const std::uint32_t lane1,
    const std::uint32_t lane2,
    const std::uint32_t lane3
  ) noexcept
  {
    if ((sPrefetchThreadCallableInitFlags_004AF810 & 1U) == 0U) {
      sPrefetchThreadCallableInitFlags_004AF810 |= 1U;
      sPrefetchThreadCallableVtable_004AF810.invoker = &InvokePrefetchThreadCallable_004AFDE0;
      sPrefetchThreadCallableVtable_004AF810.manager = &ManagePrefetchThreadCallable_004AFDF0;
    }

    PrefetchThreadCallableVtable_004AF810* const resolvedVtable =
      BuildPrefetchThreadCallablePayload_004AFB20(&outCallable->payload, lane0, lane1, lane2, lane3)
      ? &sPrefetchThreadCallableVtable_004AF810
      : nullptr;
    outCallable->vtable = resolvedVtable;
    return resolvedVtable;
  }

  /**
   * Address: 0x004AF070 (FUN_004AF070)
   *
   * What it does:
   * Clears callable vtable lane and then assigns one lazily-built callable
   * payload/vtable tuple from four caller-provided dword lanes.
   */
  [[maybe_unused]] PrefetchThreadCallableRuntime_004AF070* InitializePrefetchThreadCallable_004AF070(
    PrefetchThreadCallableRuntime_004AF070* const outCallable,
    const std::uint32_t lane0,
    const std::uint32_t lane1,
    const std::uint32_t lane2,
    const std::uint32_t lane3
  ) noexcept
  {
    outCallable->vtable = nullptr;
    (void)AssignPrefetchThreadCallableVtable_004AF810(outCallable, lane0, lane1, lane2, lane3);
    return outCallable;
  }

  /**
   * Address: 0x004AE860 (FUN_004AE860)
   *
   * What it does:
   * Erases one wide red-black-tree node, rebalances colors/rotations, and
   * returns the successor iterator through caller-provided output storage.
   */
  [[maybe_unused]] RedBlackTreeWideNodeRuntime_004AE3B0** EraseWideTreeNode_004AE860(
    RedBlackTreeWideRuntime_004AE3B0& tree,
    RedBlackTreeWideNodeRuntime_004AE3B0** const outNext,
    RedBlackTreeWideNodeRuntime_004AE3B0* eraseNode
  )
  {
    if (eraseNode->isNil != 0) {
      throw std::out_of_range("invalid map/set<T> iterator");
    }

    RedBlackTreeWideNodeRuntime_004AE3B0* successor = eraseNode;
    (void)AdvanceWideTreeIterator_004AE710(successor);

    RedBlackTreeWideNodeRuntime_004AE3B0* replacement = nullptr;
    RedBlackTreeWideNodeRuntime_004AE3B0* fixupParent = nullptr;
    RedBlackTreeWideNodeRuntime_004AE3B0* const head = tree.head;

    if (eraseNode->left->isNil != 0) {
      replacement = eraseNode->right;
      fixupParent = eraseNode->parent;
    } else if (eraseNode->right->isNil != 0) {
      replacement = eraseNode->left;
      fixupParent = eraseNode->parent;
    } else {
      RedBlackTreeWideNodeRuntime_004AE3B0* const spliceNode = successor;
      replacement = spliceNode->right;

      eraseNode->left->parent = spliceNode;
      spliceNode->left = eraseNode->left;

      if (spliceNode == eraseNode->right) {
        fixupParent = spliceNode;
      } else {
        fixupParent = spliceNode->parent;
        if (replacement->isNil == 0) {
          replacement->parent = fixupParent;
        }
        fixupParent->left = replacement;
        spliceNode->right = eraseNode->right;
        eraseNode->right->parent = spliceNode;
      }

      if (head->parent == eraseNode) {
        head->parent = spliceNode;
      } else if (eraseNode->parent->left == eraseNode) {
        eraseNode->parent->left = spliceNode;
      } else {
        eraseNode->parent->right = spliceNode;
      }

      spliceNode->parent = eraseNode->parent;
      std::swap(spliceNode->color, eraseNode->color);
      goto fixup_after_transplant;
    }

    if (replacement->isNil == 0) {
      replacement->parent = fixupParent;
    }

    if (head->parent == eraseNode) {
      head->parent = replacement;
    } else if (fixupParent->left == eraseNode) {
      fixupParent->left = replacement;
    } else {
      fixupParent->right = replacement;
    }

    if (head->left == eraseNode) {
      head->left = (replacement->isNil != 0)
        ? fixupParent
        : FindWideTreeLeftmostDescendant_004AEB50(replacement);
    }

    if (head->right == eraseNode) {
      head->right = (replacement->isNil != 0)
        ? fixupParent
        : FindWideTreeRightmostDescendant_004AEE80(replacement);
    }

fixup_after_transplant:
    if (eraseNode->color == kRedBlackTreeColorBlack_004AD230) {
      if (replacement != head->parent) {
        while (replacement->color == kRedBlackTreeColorBlack_004AD230) {
          RedBlackTreeWideNodeRuntime_004AE3B0* sibling = nullptr;
          if (replacement == fixupParent->left) {
            sibling = fixupParent->right;
            if (sibling->color == kRedBlackTreeColorRed_004AD230) {
              sibling->color = kRedBlackTreeColorBlack_004AD230;
              fixupParent->color = kRedBlackTreeColorRed_004AD230;
              (void)RotateWideSubtreeLeft_004AE3B0(fixupParent, tree);
              sibling = fixupParent->right;
            }

            if (sibling->isNil == 0) {
              if (sibling->left->color != kRedBlackTreeColorBlack_004AD230
                  || sibling->right->color != kRedBlackTreeColorBlack_004AD230) {
                if (sibling->right->color == kRedBlackTreeColorBlack_004AD230) {
                  sibling->left->color = kRedBlackTreeColorBlack_004AD230;
                  sibling->color = kRedBlackTreeColorRed_004AD230;
                  (void)RotateWideSubtreeRight_004AE410(sibling, tree);
                  sibling = fixupParent->right;
                }
                sibling->color = fixupParent->color;
                fixupParent->color = kRedBlackTreeColorBlack_004AD230;
                sibling->right->color = kRedBlackTreeColorBlack_004AD230;
                (void)RotateWideSubtreeLeft_004AE3B0(fixupParent, tree);
                break;
              }
              sibling->color = kRedBlackTreeColorRed_004AD230;
            }
          } else {
            sibling = fixupParent->left;
            if (sibling->color == kRedBlackTreeColorRed_004AD230) {
              sibling->color = kRedBlackTreeColorBlack_004AD230;
              fixupParent->color = kRedBlackTreeColorRed_004AD230;
              (void)RotateWideSubtreeRight_004AE410(fixupParent, tree);
              sibling = fixupParent->left;
            }

            if (sibling->isNil == 0) {
              if (sibling->right->color != kRedBlackTreeColorBlack_004AD230
                  || sibling->left->color != kRedBlackTreeColorBlack_004AD230) {
                if (sibling->left->color == kRedBlackTreeColorBlack_004AD230) {
                  sibling->right->color = kRedBlackTreeColorBlack_004AD230;
                  sibling->color = kRedBlackTreeColorRed_004AD230;
                  (void)RotateWideSubtreeLeft_004AE3B0(sibling, tree);
                  sibling = fixupParent->left;
                }
                sibling->color = fixupParent->color;
                fixupParent->color = kRedBlackTreeColorBlack_004AD230;
                sibling->left->color = kRedBlackTreeColorBlack_004AD230;
                (void)RotateWideSubtreeRight_004AE410(fixupParent, tree);
                break;
              }
              sibling->color = kRedBlackTreeColorRed_004AD230;
            }
          }

          replacement = fixupParent;
          const bool reachedRoot = (fixupParent == head->parent);
          fixupParent = fixupParent->parent;
          if (reachedRoot) {
            break;
          }
        }
      }
      replacement->color = kRedBlackTreeColorBlack_004AD230;
    }

    (void)DestroyPrefetchRequestRuntime(&eraseNode->runtime);
    ::operator delete(eraseNode);
    if (tree.nodeCount > 0U) {
      --tree.nodeCount;
    }

    *outNext = successor;
    return outNext;
  }

  /**
   * Address: 0x004AC7D0 (FUN_004AC7D0)
   *
   * What it does:
   * Returns lower-bound iterator for one factory registration key.
   */
  [[nodiscard]] std::map<unsigned int, moho::ResourceFactoryBase*>::iterator LowerBoundFactoryRegistrationKey(
    std::map<unsigned int, moho::ResourceFactoryBase*>& activeFactoryRegistrationsByKey,
    const unsigned int registrationKey
  )
  {
    return activeFactoryRegistrationsByKey.lower_bound(registrationKey);
  }

  struct FactoryRegistrationLookupResult_004AC460
  {
    std::map<unsigned int, moho::ResourceFactoryBase*>::iterator iterator;
    bool inserted;
  };

  /**
   * Address: 0x004AC460 (FUN_004AC460)
   *
   * What it does:
   * Finds or inserts one active-factory map entry for registration key.
   */
  [[nodiscard]] FactoryRegistrationLookupResult_004AC460 FindOrInsertFactoryRegistrationKey(
    std::map<unsigned int, moho::ResourceFactoryBase*>& activeFactoryRegistrationsByKey,
    const unsigned int registrationKey
  )
  {
    const auto lowerBound =
      LowerBoundFactoryRegistrationKey(activeFactoryRegistrationsByKey, registrationKey);
    if (lowerBound == activeFactoryRegistrationsByKey.end() || registrationKey < lowerBound->first) {
      const auto insertedIt =
        activeFactoryRegistrationsByKey.emplace_hint(lowerBound, registrationKey, nullptr);
      return {insertedIt, true};
    }
    return {lowerBound, false};
  }

  /**
   * Address: 0x004AC520 (FUN_004AC520)
   *
   * What it does:
   * Erases one active-factory map iterator and throws on invalid end-iterator.
   */
  std::map<unsigned int, moho::ResourceFactoryBase*>::iterator EraseFactoryRegistrationAtIterator(
    std::map<unsigned int, moho::ResourceFactoryBase*>& activeFactoryRegistrationsByKey,
    const std::map<unsigned int, moho::ResourceFactoryBase*>::iterator eraseIt
  )
  {
    if (eraseIt == activeFactoryRegistrationsByKey.end()) {
      throw std::out_of_range("invalid map/set<T> iterator");
    }
    return activeFactoryRegistrationsByKey.erase(eraseIt);
  }

  /**
   * Address: 0x004AE0D0 (FUN_004AE0D0)
   *
   * What it does:
   * Erases one iterator range from the active-factory keyed registry and
   * returns the next iterator through caller-provided output storage.
   */
  [[maybe_unused]] std::map<unsigned int, moho::ResourceFactoryBase*>::iterator*
  EraseFactoryRegistrationRange_004AE0D0(
    std::map<unsigned int, moho::ResourceFactoryBase*>& activeFactoryRegistrationsByKey,
    std::map<unsigned int, moho::ResourceFactoryBase*>::iterator* const outNext,
    std::map<unsigned int, moho::ResourceFactoryBase*>::iterator first,
    const std::map<unsigned int, moho::ResourceFactoryBase*>::iterator last
  )
  {
    if (first == activeFactoryRegistrationsByKey.begin() && last == activeFactoryRegistrationsByKey.end()) {
      activeFactoryRegistrationsByKey.clear();
      *outNext = activeFactoryRegistrationsByKey.begin();
      return outNext;
    }

    while (first != last) {
      first = EraseFactoryRegistrationAtIterator(activeFactoryRegistrationsByKey, first);
    }

    *outNext = first;
    return outNext;
  }

  struct PrefetchRequestKey;

  /**
   * Address: 0x004AD8B0 (FUN_004AD8B0)
   *
   * What it does:
   * Orders prefetch-request keys by case-insensitive path, then by type lane.
   */
  [[nodiscard]] bool IsPrefetchRequestKeyLess_004AD8B0(
    const PrefetchRequestKey& lhs,
    const PrefetchRequestKey& rhs
  ) noexcept;

  struct PrefetchRequestKey
  {
    std::string canonicalPath;
    const gpg::RType* resourceType = nullptr;

    [[nodiscard]] bool operator<(const PrefetchRequestKey& rhs) const noexcept
    {
      return IsPrefetchRequestKeyLess_004AD8B0(*this, rhs);
    }
  };

  struct PrefetchRequestEntry
  {
    PrefetchRequestRuntime runtime{};
    boost::weak_ptr<moho::PrefetchData> weakPayload{};
  };

  using PrefetchRequestEntryMap = std::map<PrefetchRequestKey, PrefetchRequestEntry>;
  PrefetchRequestEntryMap sPrefetchRequestEntries{};

  /**
   * Address: 0x004AED80 (FUN_004AED80)
   *
   * What it does:
   * Initializes one wide prefetch-request tree node from link lanes and key.
   */
  [[maybe_unused]] RedBlackTreeWideNodeRuntime_004AE3B0* InitializePrefetchRequestWideNode_004AED80(
    RedBlackTreeWideNodeRuntime_004AE3B0* const node,
    RedBlackTreeWideNodeRuntime_004AE3B0* const left,
    RedBlackTreeWideNodeRuntime_004AE3B0* const right,
    RedBlackTreeWideNodeRuntime_004AE3B0* const parent,
    const PrefetchRequestKey& key
  )
  {
    node->left = left;
    node->parent = parent;
    node->right = right;
    (void)InitializePrefetchRequestFromPath(
      &node->runtime,
      key.canonicalPath.c_str(),
      const_cast<gpg::RType*>(key.resourceType)
    );
    node->color = kRedBlackTreeColorRed_004AD230;
    node->isNil = 0;
    node->pad4E[0] = 0;
    node->pad4E[1] = 0;
    return node;
  }

  /**
   * Address: 0x004AE460 (FUN_004AE460)
   *
   * What it does:
   * Allocates one wide prefetch-request tree node and seeds its runtime
   * payload from the request key.
   */
  [[maybe_unused]] RedBlackTreeWideNodeRuntime_004AE3B0* AllocatePrefetchRequestTreeNode_004AE460(
    RedBlackTreeWideNodeRuntime_004AE3B0* const head,
    RedBlackTreeWideNodeRuntime_004AE3B0* const parentHint,
    const PrefetchRequestKey& key
  )
  {
    auto* const node = static_cast<RedBlackTreeWideNodeRuntime_004AE3B0*>(
      ::operator new(sizeof(RedBlackTreeWideNodeRuntime_004AE3B0))
    );
    return InitializePrefetchRequestWideNode_004AED80(
      node,
      head,
      head,
      parentHint,
      key
    );
  }

  /**
   * Address: 0x004AE2B0 (FUN_004AE2B0)
   *
   * What it does:
   * Erases one iterator range from the prefetch-request entry map and
   * returns the next iterator through caller-provided output storage.
   */
  [[maybe_unused]] PrefetchRequestEntryMap::iterator* ErasePrefetchRequestEntryRange_004AE2B0(
    PrefetchRequestEntryMap& requestEntries,
    PrefetchRequestEntryMap::iterator* const outNext,
    PrefetchRequestEntryMap::iterator first,
    const PrefetchRequestEntryMap::iterator last
  )
  {
    if (first == requestEntries.begin() && last == requestEntries.end()) {
      for (auto it = requestEntries.begin(); it != requestEntries.end(); ++it) {
        (void)DestroyPrefetchRequestRuntime(&it->second.runtime);
      }
      requestEntries.clear();
      *outNext = requestEntries.begin();
      return outNext;
    }

    while (first != last) {
      if (first == requestEntries.end()) {
        throw std::out_of_range("invalid map/set<T> iterator");
      }
      (void)DestroyPrefetchRequestRuntime(&first->second.runtime);
      first = requestEntries.erase(first);
    }

    *outNext = first;
    return outNext;
  }

  /**
   * Address: 0x004AD790 (FUN_004AD790)
   *
   * What it does:
   * Returns lower-bound iterator for one prefetch-request key.
   */
  [[maybe_unused]] PrefetchRequestEntryMap::iterator LowerBoundPrefetchRequestEntry_004AD790(
    PrefetchRequestEntryMap& requestEntries,
    const PrefetchRequestKey& key
  )
  {
    return requestEntries.lower_bound(key);
  }

  /**
   * Address: 0x004AD800 (FUN_004AD800)
   *
   * What it does:
   * Returns upper-bound iterator for one prefetch-request key.
   */
  [[maybe_unused]] PrefetchRequestEntryMap::iterator UpperBoundPrefetchRequestEntry_004AD800(
    PrefetchRequestEntryMap& requestEntries,
    const PrefetchRequestKey& key
  )
  {
    return requestEntries.upper_bound(key);
  }

  /**
   * Address: 0x004AD890 (FUN_004AD890, nullsub_704)
   *
   * What it does:
   * No-op helper thunk retained for callsite parity.
   */
  [[maybe_unused]] void NoOpHelperThunk_004AD890() noexcept {}

  /**
   * Address: 0x004AD8A0 (FUN_004AD8A0, nullsub_705)
   *
   * What it does:
   * No-op helper thunk retained for callsite parity.
   */
  [[maybe_unused]] void NoOpHelperThunk_004AD8A0() noexcept {}

  /**
   * Address: 0x004AD8F0 (FUN_004AD8F0)
   *
   * What it does:
   * Stores one tree-node pointer and its key lane into output pair storage.
   */
  [[maybe_unused]] std::uintptr_t* StoreNodePointerAndKeyLane_004AD8F0(
    std::uintptr_t* const outPair,
    const RedBlackTreeNodeRuntime_004AD230* const node
  ) noexcept
  {
    outPair[0] = reinterpret_cast<std::uintptr_t>(node);
    outPair[1] = node != nullptr ? static_cast<std::uintptr_t>(node->keyLane) : 0U;
    return outPair;
  }

  [[nodiscard]] bool IsPrefetchRequestKeyLess_004AD8B0(
    const PrefetchRequestKey& lhs,
    const PrefetchRequestKey& rhs
  ) noexcept
  {
    const int compare = _stricmp(lhs.canonicalPath.c_str(), rhs.canonicalPath.c_str());
    return (compare < 0) || (compare == 0 && lhs.resourceType < rhs.resourceType);
  }

  struct PrefetchRequestLookupResult_004AC890
  {
    PrefetchRequestEntryMap::iterator iterator;
    bool inserted;
  };

  struct PrefetchRequestInsertResult_004AD5E0
  {
    PrefetchRequestEntryMap::iterator iterator;
    bool inserted;
  };

  /**
   * Address: 0x004AD5E0 (FUN_004AD5E0)
   *
   * What it does:
   * Inserts one prefetch-request entry by key and returns iterator + inserted
   * status after map rebalancing.
   */
  [[maybe_unused]] PrefetchRequestInsertResult_004AD5E0 InsertPrefetchRequestEntry_004AD5E0(
    PrefetchRequestEntryMap& requestEntries,
    const PrefetchRequestKey& key
  )
  {
    auto lowerBound = LowerBoundPrefetchRequestEntry_004AD790(requestEntries, key);
    if (lowerBound == requestEntries.end() || IsPrefetchRequestKeyLess_004AD8B0(key, lowerBound->first)) {
      lowerBound = requestEntries.emplace_hint(lowerBound, key, PrefetchRequestEntry{});
      return {lowerBound, true};
    }
    return {lowerBound, false};
  }

  /**
   * Address: 0x004AC890 (FUN_004AC890)
   *
   * What it does:
   * Finds or inserts one prefetch-request runtime map entry by key.
   */
  [[nodiscard]] PrefetchRequestLookupResult_004AC890 FindOrInsertPrefetchRequestEntry(
    const PrefetchRequestKey& key
  )
  {
    const auto insertResult = InsertPrefetchRequestEntry_004AD5E0(sPrefetchRequestEntries, key);
    return {insertResult.iterator, insertResult.inserted};
  }

  [[nodiscard]] msvc8::string ResolvePrefetchPath(const char* const path)
  {
    if (path != nullptr && path[0] != '\0' && (path[0] != '/' || path[1] == '/')) {
      return msvc8::string(path);
    }

    moho::FILE_EnsureWaitHandleSet();
    moho::FWaitHandleSet* const waitHandleSet = moho::FILE_GetWaitHandleSet();
    if (waitHandleSet == nullptr || waitHandleSet->mHandle == nullptr) {
      return {};
    }

    msvc8::string mountedPath{};
    (void)waitHandleSet->mHandle->FindFile(&mountedPath, path != nullptr ? path : "", nullptr);
    return mountedPath;
  }

  [[nodiscard]] bool TryResolveResourcePathForGet(
    const char* const path,
    msvc8::string* const outPath
  )
  {
    if (outPath == nullptr) {
      return false;
    }
    *outPath = msvc8::string();

    if (path == nullptr || path[0] == '\0') {
      return false;
    }

    if (path[0] == '/' && path[1] != '/') {
      const char second = path[1];
      if (second == ':' || second == '/' || second == '\0') {
        return false;
      }

      *outPath = ResolvePrefetchPath(path);
      return !outPath->empty();
    }

    *outPath = msvc8::string(path);
    return true;
  }

  [[nodiscard]] bool HasWatcherNodeForRequest(
    const PrefetchRequestRuntime& request,
    const moho::CResourceWatcher* const watcher
  ) noexcept
  {
    if (watcher == nullptr) {
      return true;
    }

    const IntrusiveListLink* const head = &request.mWaiterListHead;
    for (const IntrusiveListLink* it = head->mNext; it != head; it = it->mNext) {
      const auto* const node = reinterpret_cast<const PrefetchWatchNode*>(it);
      if (node->mWatcher == watcher) {
        return true;
      }
    }

    return false;
  }

  void AppendWatcherNodeReference(
    moho::CResourceWatcher* const watcher,
    PrefetchWatchNode* const watchNode
  )
  {
    if (watcher == nullptr || watchNode == nullptr) {
      return;
    }

    auto** begin = reinterpret_cast<PrefetchWatchNode**>(watcher->mWatchedBegin);
    auto** end = reinterpret_cast<PrefetchWatchNode**>(watcher->mWatchedEnd);
    auto** capacityEnd = reinterpret_cast<PrefetchWatchNode**>(watcher->mWatchedStorageEnd);
    auto** const inlineOrigin = reinterpret_cast<PrefetchWatchNode**>(watcher->mWatchedStorageOrigin);

    if (end == capacityEnd) {
      const std::size_t oldSize = static_cast<std::size_t>(end - begin);
      const std::size_t oldCapacity = static_cast<std::size_t>(capacityEnd - begin);
      std::size_t newCapacity = oldCapacity + (oldCapacity >> 1U);
      if (newCapacity < oldSize + 1U) {
        newCapacity = oldSize + 1U;
      }
      if (newCapacity == 0U) {
        newCapacity = 1U;
      }

      auto** const newStorage = static_cast<PrefetchWatchNode**>(
        ::operator new[](newCapacity * sizeof(PrefetchWatchNode*))
      );
      if (oldSize > 0U) {
        std::memmove(newStorage, begin, oldSize * sizeof(PrefetchWatchNode*));
      }

      if (begin != inlineOrigin) {
        ::operator delete[](begin);
      }

      begin = newStorage;
      end = newStorage + oldSize;
      capacityEnd = newStorage + newCapacity;
      watcher->mWatchedBegin = begin;
      watcher->mWatchedEnd = end;
      watcher->mWatchedStorageEnd = capacityEnd;
    }

    *end = watchNode;
    ++end;
    watcher->mWatchedEnd = end;
  }

  constexpr const char* kResSpewLoadSpamDescription = "Enable resource-manager load/prefetch debug spew.";
  constexpr const char* kResEnablePrefetchingDescription = "Enable asynchronous resource prefetching.";
  constexpr const char* kResPrefetcherActivityDelayDescription =
    "Delay in seconds between prefetcher work iterations.";
  constexpr const char* kResAfterPrefetchDelayDescription =
    "Sleep duration in seconds after each prefetch work item.";

  moho::TConVar<bool> gTConVar_res_SpewLoadSpam(
    "res_SpewLoadSpam",
    kResSpewLoadSpamDescription,
    &moho::res_SpewLoadSpam
  );
  moho::TConVar<bool> gTConVar_res_EnablePrefetching(
    "res_EnablePrefetching",
    kResEnablePrefetchingDescription,
    &moho::res_EnablePrefetching
  );
  moho::TConVar<int> gTConVar_res_PrefetcherActivityDelay(
    "res_PrefetcherActivityDelay",
    kResPrefetcherActivityDelayDescription,
    &moho::res_PrefetcherActivityDelay
  );
  moho::TConVar<int> gTConVar_res_AfterPrefetchDelay(
    "res_AfterPrefetchDelay",
    kResAfterPrefetchDelayDescription,
    &moho::res_AfterPrefetchDelay
  );

  void DestroyResourceManager()
  {
    delete sPResourceManager;
    sPResourceManager = nullptr;
  }

  void EnsureResourceManagerOnce()
  {
    if (sPResourceManager != nullptr) {
      return;
    }

    sPResourceManager = new moho::ResourceManager();
    std::atexit(&DestroyResourceManager);
  }
} // namespace

namespace moho
{
  /**
   * Address: 0x00BF04F0 (FUN_00BF04F0, ??1TConVar_res_SpewLoadSpam@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `res_SpewLoadSpam`.
   */
  void cleanup_TConVar_res_SpewLoadSpam()
  {
    TeardownConCommandRegistration(gTConVar_res_SpewLoadSpam);
  }

  /**
   * Address: 0x00BC5AC0 (FUN_00BC5AC0, register_TConVar_res_SpewLoadSpam)
   *
   * What it does:
   * Registers startup convar for `res_SpewLoadSpam`.
   */
  void register_TConVar_res_SpewLoadSpam()
  {
    RegisterConCommand(gTConVar_res_SpewLoadSpam);
    (void)std::atexit(&cleanup_TConVar_res_SpewLoadSpam);
  }

  /**
   * Address: 0x00BF0520 (FUN_00BF0520, ??1TConVar_res_EnablePrefetching@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `res_EnablePrefetching`.
   */
  void cleanup_TConVar_res_EnablePrefetching()
  {
    TeardownConCommandRegistration(gTConVar_res_EnablePrefetching);
  }

  /**
   * Address: 0x00BC5B00 (FUN_00BC5B00, register_TConVar_res_EnablePrefetching)
   *
   * What it does:
   * Registers startup convar for `res_EnablePrefetching`.
   */
  void register_TConVar_res_EnablePrefetching()
  {
    RegisterConCommand(gTConVar_res_EnablePrefetching);
    (void)std::atexit(&cleanup_TConVar_res_EnablePrefetching);
  }

  /**
   * Address: 0x00BF0550 (FUN_00BF0550, ??1TConVar_res_PrefetcherActivityDelay@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `res_PrefetcherActivityDelay`.
   */
  void cleanup_TConVar_res_PrefetcherActivityDelay()
  {
    TeardownConCommandRegistration(gTConVar_res_PrefetcherActivityDelay);
  }

  /**
   * Address: 0x00BC5B40 (FUN_00BC5B40, register_TConVar_res_PrefetcherActivityDelay)
   *
   * What it does:
   * Registers startup convar for `res_PrefetcherActivityDelay`.
   */
  void register_TConVar_res_PrefetcherActivityDelay()
  {
    RegisterConCommand(gTConVar_res_PrefetcherActivityDelay);
    (void)std::atexit(&cleanup_TConVar_res_PrefetcherActivityDelay);
  }

  /**
   * Address: 0x00BF0580 (FUN_00BF0580, ??1TConVar_res_AfterPrefetchDelay@Moho@@QAE@@Z)
   *
   * What it does:
   * Unregisters startup convar storage for `res_AfterPrefetchDelay`.
   */
  void cleanup_TConVar_res_AfterPrefetchDelay()
  {
    TeardownConCommandRegistration(gTConVar_res_AfterPrefetchDelay);
  }

  /**
   * Address: 0x00BC5B80 (FUN_00BC5B80, register_TConVar_res_AfterPrefetchDelay)
   *
   * What it does:
   * Registers startup convar for `res_AfterPrefetchDelay`.
   */
  void register_TConVar_res_AfterPrefetchDelay()
  {
    RegisterConCommand(gTConVar_res_AfterPrefetchDelay);
    (void)std::atexit(&cleanup_TConVar_res_AfterPrefetchDelay);
  }
} // namespace moho

namespace
{
  struct ResourceManagerConVarStartupBootstrap
  {
    ResourceManagerConVarStartupBootstrap()
    {
      moho::register_TConVar_res_SpewLoadSpam();
      moho::register_TConVar_res_EnablePrefetching();
      moho::register_TConVar_res_PrefetcherActivityDelay();
      moho::register_TConVar_res_AfterPrefetchDelay();
    }
  };

  [[maybe_unused]] ResourceManagerConVarStartupBootstrap gResourceManagerConVarStartupBootstrap;
} // namespace

/**
 * Address: 0x004A9DD0 (FUN_004A9DD0)
 * Mangled: ??0ResourceManager@Moho@@QAE@@Z
 *
 * What it does:
 * Initializes singleton resource-manager startup state.
 */
moho::ResourceManager::ResourceManager()
  : CDiskWatchListener(nullptr)
  , mFactoryMutex()
  , mFactoriesActivated(false)
  , mWorkerLock()
  , mWorkerRunning(false)
  , mWorkerWakeCondition()
  , mWorkerIdleCondition()
  , mWorkerThread(nullptr)
  , mActiveLoadCount(0)
{
}

/**
 * Address: 0x004A9C00 (FUN_004A9C00)
 * Mangled context: teardown helper used by singleton cleanup.
 */
moho::ResourceManager::~ResourceManager()
{
  ShutdownBackgroundThread();
  CleanupPrefetchWeakPairRingQueue_004ADA70(&sPrefetchPayloadQueue_004AB180);
}

/**
 * Address: 0x00461DC0 (?OnEvent@CDiskWatchListener@Moho@@EAEXABUSDiskWatchEvent@2@@Z)
 */
void moho::ResourceManager::OnEvent(const SDiskWatchEvent& event)
{
  CDiskWatchListener::OnEvent(event);
}

/**
 * Address: 0x004A9B90 (FUN_004A9B90)
 *
 * What it does:
 * Overrides disk-watch filtering and accepts every incoming event.
 */
bool moho::ResourceManager::FilterEvent(const SDiskWatchEvent& event)
{
  (void)event;
  return true;
}

/**
 * Address: 0x004AB780 (FUN_004AB780, ?OnDiskWatchEvent@ResourceManager@Moho@@UAEXABUSDiskWatchEvent@2@@Z)
 *
 * What it does:
 * Invalidates all matching prefetch request entries for the changed path,
 * clears cached runtime/payload pairs, then notifies attached watchers.
 */
void moho::ResourceManager::OnDiskWatchEvent(const SDiskWatchEvent& event)
{
  boost::recursive_mutex::scoped_lock workerLock(mWorkerLock);

  PrefetchRequestKey rangeBeginKey{};
  rangeBeginKey.canonicalPath = std::string(event.mPath.c_str());
  rangeBeginKey.resourceType = nullptr;

  const auto rangeBegin = LowerBoundPrefetchRequestEntry_004AD790(sPrefetchRequestEntries, rangeBeginKey);

  PrefetchRequestKey rangeEndKey{};
  rangeEndKey.canonicalPath = rangeBeginKey.canonicalPath;
  rangeEndKey.resourceType = reinterpret_cast<const gpg::RType*>(static_cast<std::uintptr_t>(~0u));

  const auto rangeEnd = UpperBoundPrefetchRequestEntry_004AD800(sPrefetchRequestEntries, rangeEndKey);
  if (rangeBegin == rangeEnd) {
    return;
  }

  std::vector<PrefetchWatchNode*> changedWatchNodes{};
  for (auto requestIt = rangeBegin; requestIt != rangeEnd; ++requestIt) {
    PrefetchRequestEntry& entry = requestIt->second;
    PrefetchRequestRuntime& request = entry.runtime;

    if (request.mIsLoading != 0) {
      request.mLoadWakePending = 1;
    }

    request.mResolved.px = nullptr;
    (void)ReleaseWeakControlFromPair(&request.mResolved);
    request.mHadLoadFailure = 0;

    boost::shared_ptr<PrefetchData> payload = entry.weakPayload.lock();
    if (payload) {
      (void)ResetSharedPairReleaseControl(&payload->mResolved);
      (void)ResetSharedPairReleaseControl(&payload->mPrefetch);
    }

    request.mPrefetch.px = nullptr;
    (void)ReleaseWeakControlFromPair(&request.mPrefetch);

    IntrusiveListLink* const waiterHead = &request.mWaiterListHead;
    for (IntrusiveListLink* waiterNode = waiterHead->mNext; waiterNode != waiterHead; waiterNode = waiterNode->mNext) {
      auto* const watchNode = reinterpret_cast<PrefetchWatchNode*>(waiterNode);
      watchNode->mIsFinished = 1;
      changedWatchNodes.push_back(watchNode);
    }
  }

  for (PrefetchWatchNode* const watchNode : changedWatchNodes) {
    if (watchNode == nullptr) {
      continue;
    }

    if (watchNode->mWatcher != nullptr) {
      auto* const watcher = static_cast<CResourceWatcher*>(watchNode->mWatcher);
      watcher->OnResourceChanged(watchNode->mPath.c_str());
      watchNode->mIsFinished = 0;
      continue;
    }

    watchNode->mPath.tidy(true, 0U);
    watchNode->mListLink.ListUnlink();
    watchNode->mListLink.ListResetLinks();
    ::operator delete(watchNode);
  }
}

/**
 * Address: 0x004AA090 (FUN_004AA090)
 *
 * What it does:
 * Marks factory bootstrap as active and drains pending startup hooks.
 */
void moho::ResourceManager::ActivatePendingFactories()
{
  boost::recursive_mutex::scoped_lock lock(mFactoryMutex);
  mFactoriesActivated = true;

  if (mPendingFactoryRegistrations.empty()) {
    return;
  }

  for (ResourceFactoryBase* const factory : mPendingFactoryRegistrations) {
    factory->Init();
    const unsigned int registrationKey = GetFactoryRegistrationKey(factory);
    const auto registrationResult =
      FindOrInsertFactoryRegistrationKey(mActiveFactoryRegistrationsByKey, registrationKey);
    registrationResult.iterator->second = factory;
  }

  mPendingFactoryRegistrations.clear();
}

/**
 * Address: 0x004A9F30 (FUN_004A9F30)
 *
 * What it does:
 * Registers one factory into the pending lane before activation, then stores
 * it in the active keyed registry once bootstrap is live.
 */
void moho::ResourceManager::AttachFactory(ResourceFactoryBase* const factory)
{
  boost::recursive_mutex::scoped_lock lock(mFactoryMutex);

  if (!mFactoriesActivated) {
    (void)AppendPendingFactoryRegistration(mPendingFactoryRegistrations, factory);
    return;
  }

  const unsigned int registrationKey = GetFactoryRegistrationKey(factory);
  const auto registrationResult =
    FindOrInsertFactoryRegistrationKey(mActiveFactoryRegistrationsByKey, registrationKey);
  registrationResult.iterator->second = factory;
}

/**
 * Address: 0x004A9FC0 (FUN_004A9FC0)
 *
 * What it does:
 * Removes one factory from both the pending bootstrap lane and the active
 * keyed registry.
 */
void moho::ResourceManager::DetachFactory(ResourceFactoryBase* const factory)
{
  boost::recursive_mutex::scoped_lock lock(mFactoryMutex);

  RemovePendingFactory(mPendingFactoryRegistrations, factory);
  const unsigned int registrationKey = GetFactoryRegistrationKey(factory);
  const auto activeFactoryIt =
    LowerBoundFactoryRegistrationKey(mActiveFactoryRegistrationsByKey, registrationKey);
  if (activeFactoryIt != mActiveFactoryRegistrationsByKey.end() && activeFactoryIt->first == registrationKey) {
    (void)EraseFactoryRegistrationAtIterator(mActiveFactoryRegistrationsByKey, activeFactoryIt);
  }
}

/**
 * Address: 0x004AB600 (FUN_004AB600)
 *
 * What it does:
 * Returns one active factory registration lane from lower-bound lookup by key.
 */
moho::ResourceFactoryBase* moho::ResourceManager::FindFactoryByRegistrationKey(const unsigned int registrationKey)
{
  const auto it = LowerBoundFactoryRegistrationKey(mActiveFactoryRegistrationsByKey, registrationKey);
  if (it == mActiveFactoryRegistrationsByKey.end()) {
    return nullptr;
  }
  return it->second;
}

/**
 * Address: 0x004AB620 (FUN_004AB620, func_ManageWatchedResources)
 *
 * What it does:
 * Flushes watched-resource node ownership for one watcher and resets watcher
 * storage back to inline mode.
 */
void moho::ResourceManager::ManageWatchedResources(CResourceWatcher* const watcher)
{
  if (watcher == nullptr) {
    return;
  }

  boost::recursive_mutex::scoped_lock lock(mFactoryMutex);
  auto** watchedBegin = reinterpret_cast<PrefetchWatchNode**>(watcher->mWatchedBegin);
  auto** watchedEnd = reinterpret_cast<PrefetchWatchNode**>(watcher->mWatchedEnd);
  if (watchedBegin != nullptr && watchedEnd != nullptr) {
    for (auto** it = watchedBegin; it != watchedEnd; ++it) {
      PrefetchWatchNode* const node = *it;
      if (node == nullptr) {
        continue;
      }

      if (node->mIsFinished != 0) {
        node->mWatcher = nullptr;
        continue;
      }

      node->mPath.tidy(true, 0U);
      node->mListLink.ListUnlink();
      node->mListLink.ListResetLinks();
      ::operator delete(node);
    }
  }

  auto** const watchedInlineOrigin = reinterpret_cast<PrefetchWatchNode**>(watcher->mWatchedStorageOrigin);
  if (watchedBegin != watchedInlineOrigin) {
    ::operator delete[](watchedBegin);
    watcher->mWatchedBegin = watchedInlineOrigin;
    watcher->mWatchedStorageEnd = watchedInlineOrigin != nullptr ? watchedInlineOrigin[0] : nullptr;
  }

  watcher->mWatchedEnd = watcher->mWatchedBegin;
}

/**
 * Address: 0x004AA160 (FUN_004AA160, sub_4AA160)
 *
 * What it does:
 * Clears the worker-running flag, wakes worker wait conditions, then joins
 * and releases the worker thread object.
 */
void moho::ResourceManager::ShutdownBackgroundThread()
{
  boost::thread* workerToDestroy = nullptr;
  {
    boost::recursive_mutex::scoped_lock lock(mWorkerLock);
    mWorkerRunning = false;

    if (mWorkerThread != nullptr) {
      mWorkerWakeCondition.notify_all();
      mWorkerIdleCondition.notify_all();
      workerToDestroy = mWorkerThread;
    }
  }

  if (workerToDestroy != nullptr) {
    try {
      workerToDestroy->join();
    } catch (...) {
      // Boost 1.34 does not expose joinable(); preserve best-effort shutdown.
    }
    mWorkerThread = nullptr;
    delete workerToDestroy;
  }
}

/**
 * Address: 0x004AB180 (FUN_004AB180, func_PrefetchThread)
 *
 * What it does:
 * Worker-thread loop that drains queued prefetch payloads and runs factory
 * preload dispatch while coordinating wake/idle conditions.
 */
void moho::ResourceManager::PrefetchThreadMain()
{
  gpg::SetThreadName(0xFFFFFFFFU, "Prefetcher thread.");
  (void)::SetThreadPriority(::GetCurrentThread(), THREAD_PRIORITY_BELOW_NORMAL);

  boost::recursive_mutex::scoped_lock workerLock(mWorkerLock);

  while (mWorkerRunning) {
    if (!moho::res_EnablePrefetching) {
      workerLock.unlock();
      std::this_thread::sleep_for(std::chrono::seconds(10));
      workerLock.lock();
      continue;
    }

    if (sPrefetchPayloadQueue_004AB180.mQueuedCount == 0U) {
      mWorkerWakeCondition.wait(workerLock);
      continue;
    }

    if (mActiveLoadCount != 0U) {
      mWorkerIdleCondition.wait(workerLock);
      continue;
    }

    if (moho::res_PrefetcherActivityDelay > 0) {
      const auto nextAllowed =
        sLastResourceResolveTime_004AA690 + std::chrono::seconds(moho::res_PrefetcherActivityDelay);
      const auto now = std::chrono::steady_clock::now();
      if (now < nextAllowed) {
        workerLock.unlock();
        std::this_thread::sleep_for(nextAllowed - now);
        workerLock.lock();
        continue;
      }
    }

    boost::shared_ptr<PrefetchData> payload = PopQueuedPrefetchPayload_004AB180();
    if (!payload || payload->mRequest == nullptr) {
      continue;
    }

    PrefetchRequestRuntime* const request = payload->mRequest;
    if (request->mIsLoading != 0 || request->mHadLoadFailure != 0) {
      continue;
    }

    AssignLiveWeakPair_004AB180(&payload->mPrefetch, &request->mResolved);
    if (payload->mPrefetch.px != nullptr) {
      continue;
    }

    ResourceFactoryBase* const factory =
      FindFactoryByRegistrationKey(static_cast<unsigned int>(reinterpret_cast<std::uintptr_t>(request->mResourceType)));
    request->mIsLoading = 1;

    workerLock.unlock();

    boost::SharedCountPair prefetchedData{};
    (void)ResetSharedPairToNullVariant1(&prefetchedData);
    if (factory != nullptr) {
      if (moho::res_SpewLoadSpam && request->mResourceType != nullptr) {
        gpg::Debugf("Prefetching %s resource from %s", request->mResourceType->GetName(), request->mResourceId.name.c_str());
      }
      (void)factory->PreloadResourcePair(
        &prefetchedData,
        request->mResourceId.name.c_str(),
        request->mResourceType
      );
    }

    workerLock.lock();

    (void)boost::AssignWeakPairFromShared(&payload->mResolved, &prefetchedData);
    boost::ReleaseSharedControlOnly(&prefetchedData);

    if (request->mLoadWakePending != 0) {
      request->mLoadWakePending = 0;
      EnqueuePrefetchPayloadFront_004AB180(payload);
    }

    request->mIsLoading = 0;
    mWorkerIdleCondition.notify_all();

    if (moho::res_AfterPrefetchDelay > 0) {
      workerLock.unlock();
      std::this_thread::sleep_for(std::chrono::seconds(moho::res_AfterPrefetchDelay));
      workerLock.lock();
    }
  }
}

/**
 * Address: 0x004AAC20 (FUN_004AAC20, Moho::ResourceManager::CreatePrefetchData)
 *
 * boost::shared_ptr<Moho::PrefetchData> &,const char *,gpg::RType *
 *
 * What it does:
 * Canonicalizes one path, resolves/creates one keyed prefetch runtime entry,
 * and returns the shared payload handle for that entry.
 */
boost::shared_ptr<moho::PrefetchData>* moho::ResourceManager::CreatePrefetchData(
  boost::shared_ptr<PrefetchData>* const outPrefetchData,
  const char* const path,
  gpg::RType* const resourceType
)
{
  if (outPrefetchData == nullptr) {
    return nullptr;
  }

  boost::recursive_mutex::scoped_lock lock(mWorkerLock);
  outPrefetchData->reset();

  const msvc8::string canonicalPath = ResolvePrefetchPath(path);
  if (canonicalPath.empty()) {
    return outPrefetchData;
  }

  PrefetchRequestKey key{};
  key.canonicalPath = std::string(canonicalPath.c_str());
  key.resourceType = resourceType;

  const auto requestLookup = FindOrInsertPrefetchRequestEntry(key);
  PrefetchRequestEntry& entry = requestLookup.iterator->second;
  if (requestLookup.inserted || entry.runtime.mResourceId.name.empty()) {
    (void)InitializePrefetchRequestFromPath(&entry.runtime, canonicalPath.c_str(), resourceType);
  }

  boost::shared_ptr<PrefetchData> payload = entry.weakPayload.lock();
  if (!payload) {
    payload.reset(new PrefetchData{});
    payload->mRequest = &entry.runtime;
    (void)ResetSharedPairToNullVariant1(&payload->mResolved);
    (void)ResetSharedPairToNullVariant3(&payload->mPrefetch);

    (void)ReleaseWeakControlFromPair(&entry.runtime.mPrefetch);
    const auto* const payloadSharedPair = reinterpret_cast<const boost::SharedCountPair*>(&payload);
    (void)BuildWeakPairFromLiveSharedVariant2(payloadSharedPair, &entry.runtime.mPrefetch);
    entry.weakPayload = payload;
  }

  boost::SharedCountPair resolvedWeak{};
  (void)BuildWeakPairFromLiveSharedVariant1(&entry.runtime.mResolved, &resolvedWeak);
  const bool requestHasResolvedResource = (resolvedWeak.px != nullptr);
  (void)ReleaseWeakControlFromPair(&resolvedWeak);

  if (!requestHasResolvedResource) {
    EnqueuePrefetchPayloadBack_004AB180(payload);
    if (mWorkerThread != nullptr) {
      mWorkerWakeCondition.notify_all();
    } else {
      mWorkerRunning = true;
      mWorkerThread = new boost::thread(boost::bind(&moho::ResourceManager::PrefetchThreadMain, this));
    }
  }

  *outPrefetchData = payload;
  return outPrefetchData;
}

/**
 * Address: 0x004AA690 (FUN_004AA690)
 *
 * What it does:
 * Waits for in-flight loads, performs one resource load/finish dispatch lane,
 * and publishes resolved weak state for the request runtime entry.
 */
boost::SharedCountPair* moho::ResourceManager::ResolvePendingResourceRequest(
  boost::SharedCountPair* const outResource,
  PrefetchRequestRuntime& request,
  boost::recursive_mutex::scoped_lock& workerLock
)
{
  if (outResource == nullptr) {
    return nullptr;
  }

  boost::SharedCountPair pendingPrefetchWeak{};
  (void)BuildWeakPairFromLiveSharedVariant2(&request.mPrefetch, &pendingPrefetchWeak);

  struct PendingWeakReleaseGuard
  {
    boost::SharedCountPair* weakPair;
    ~PendingWeakReleaseGuard()
    {
      if (weakPair != nullptr) {
        (void)ReleaseWeakControlFromPair(weakPair);
      }
    }
  } pendingWeakGuard{&pendingPrefetchWeak};

  while (request.mIsLoading != 0) {
    mWorkerIdleCondition.wait(workerLock);
  }

  (void)BuildWeakPairFromLiveSharedVariant1(&request.mResolved, outResource);
  if (outResource->px == nullptr && request.mHadLoadFailure == 0) {
    ResourceFactoryBase* const factory =
      FindFactoryByRegistrationKey(static_cast<unsigned int>(reinterpret_cast<std::uintptr_t>(request.mResourceType)));

    request.mIsLoading = 1;
    ++mActiveLoadCount;

    while (true) {
      workerLock.unlock();

      boost::SharedCountPair loadedResource{};
      (void)ResetSharedPairToNullVariant1(&loadedResource);

      if (pendingPrefetchWeak.px != nullptr) {
        auto* const prefetchPayload = static_cast<PrefetchData*>(pendingPrefetchWeak.px);
        if (prefetchPayload->mResolved.px != nullptr) {
          if (moho::res_SpewLoadSpam && request.mResourceType != nullptr) {
            gpg::Debugf(
              "Finishing %s resource prefetched from %s",
              request.mResourceType->GetName(),
              request.mResourceId.name.c_str()
            );
          }

          if (factory != nullptr) {
            (void)factory->LoadResourceFromPrefetchPair(
              &loadedResource,
              request.mResourceId.name.c_str(),
              request.mResourceType,
              &prefetchPayload->mResolved,
              nullptr
            );
          }

          (void)ResetSharedPairReleaseControl(&prefetchPayload->mResolved);
        } else {
          if (moho::res_SpewLoadSpam && request.mResourceType != nullptr) {
            gpg::Debugf("Loading %s resource from %s", request.mResourceType->GetName(), request.mResourceId.name.c_str());
          }

          if (factory != nullptr) {
            (void)factory->LoadResourcePair(
              &loadedResource,
              request.mResourceId.name.c_str(),
              request.mResourceType
            );
          }
        }

        (void)AssignSharedPairRetainRelease_004AEF90(&prefetchPayload->mPrefetch, outResource);
      } else {
        if (moho::res_SpewLoadSpam && request.mResourceType != nullptr) {
          gpg::Debugf("Loading %s resource from %s", request.mResourceType->GetName(), request.mResourceId.name.c_str());
        }

        if (factory != nullptr) {
          (void)factory->LoadResourcePair(
            &loadedResource,
            request.mResourceId.name.c_str(),
            request.mResourceType
          );
        }
      }

      (void)boost::AssignWeakPairFromShared(outResource, &loadedResource);
      boost::ReleaseSharedControlOnly(&loadedResource);

      workerLock.lock();

      if (request.mLoadWakePending == 0) {
        break;
      }

      request.mLoadWakePending = 0;
    }

    (void)AssignSharedPairRetainRelease_004AEF90(&request.mResolved, outResource);
    if (outResource->px == nullptr) {
      request.mHadLoadFailure = 1;
    }

    request.mIsLoading = 0;
    if (mActiveLoadCount > 0U) {
      --mActiveLoadCount;
    }
    sLastResourceResolveTime_004AA690 = std::chrono::steady_clock::now();
    mWorkerIdleCondition.notify_all();
  }

  return outResource;
}

/**
 * Address: 0x004AA220 (FUN_004AA220, Moho::ResourceManager::GetResource)
 *
 * boost::weak_ptr<gpg::RObject> &,const char *,Moho::CResourceWatcher *,gpg::RType *
 *
 * What it does:
 * Canonicalizes one resource path, ensures one typed request runtime lane,
 * attaches optional watcher tracking, and resolves one weak resource handle
 * while preserving lock-drop/reacquire semantics around factory calls.
 */
boost::SharedCountPair* moho::ResourceManager::GetResource(
  boost::SharedCountPair* const outResource,
  const char* const path,
  CResourceWatcher* const resourceWatcher,
  gpg::RType* const resourceType
)
{
  if (outResource == nullptr) {
    return nullptr;
  }

  boost::recursive_mutex::scoped_lock workerLock(mWorkerLock);

  (void)ResetSharedPairToNullVariant1(outResource);

  const bool invalidPath =
    (path == nullptr || path[0] == '\0')
    || (path[0] == '/' && path[1] != '/' && (path[1] == ':' || path[1] == '/' || path[1] == '\0'));

  msvc8::string canonicalPath{};
  if (!TryResolveResourcePathForGet(path, &canonicalPath)) {
    if (invalidPath) {
      gpg::Warnf("GetResource: Invalid name \"%s\"", path != nullptr ? path : "");
    }
    return outResource;
  }

  PrefetchRequestKey key{};
  key.canonicalPath = std::string(canonicalPath.c_str());
  key.resourceType = resourceType;

  const auto requestLookup = FindOrInsertPrefetchRequestEntry(key);
  PrefetchRequestEntry& entry = requestLookup.iterator->second;
  if (requestLookup.inserted || entry.runtime.mResourceId.name.empty()) {
    (void)InitializePrefetchRequestFromPath(&entry.runtime, canonicalPath.c_str(), resourceType);
  }
  PrefetchRequestRuntime& request = entry.runtime;

  if (resourceWatcher != nullptr && !HasWatcherNodeForRequest(request, resourceWatcher)) {
    auto* const watchNode = static_cast<PrefetchWatchNode*>(::operator new(sizeof(PrefetchWatchNode)));
    (void)InitializePrefetchWatchNode(watchNode, path != nullptr ? path : "", resourceWatcher);
    watchNode->mListLink.ListLinkBefore(&request.mWaiterListHead);
    AppendWatcherNodeReference(resourceWatcher, watchNode);
  }

  return ResolvePendingResourceRequest(outResource, request, workerLock);
}

bool moho::ResourceManager::AreFactoriesActivated() const
{
  boost::recursive_mutex::scoped_lock lock(mFactoryMutex);
  return mFactoriesActivated;
}

/**
 * Address: 0x004A9BA0 (func_EnsureResourceManager)
 *
 * What it does:
 * Ensures singleton creation for startup paths that require a live manager.
 */
void moho::RES_EnsureResourceManager()
{
  std::call_once(sResourceManagerOnce, &EnsureResourceManagerOnce);
}

moho::ResourceManager* moho::RES_GetResourceManager()
{
  RES_EnsureResourceManager();
  return sPResourceManager;
}

/**
 * Address: 0x004ABEE0 (FUN_004ABEE0, ?RES_GetResource@Moho@@...)
 *
 * What it does:
 * Ensures singleton initialization and forwards one resource lookup to
 * `ResourceManager::GetResource`.
 */
boost::SharedCountPair* moho::RES_GetResource(
  boost::SharedCountPair* const outResource,
  const char* const path,
  CResourceWatcher* const resourceWatcher,
  gpg::RType* const resourceType
)
{
  ResourceManager* const manager = RES_GetResourceManager();
  if (manager == nullptr || outResource == nullptr) {
    return outResource;
  }

  return manager->GetResource(outResource, path, resourceWatcher, resourceType);
}

/**
 * Address: 0x004AA090 (FUN_004AA090)
 *
 * What it does:
 * Executes the startup pending-factory activation phase on the singleton.
 */
void moho::RES_ActivatePendingFactories()
{
  ResourceManager* const manager = RES_GetResourceManager();
  if (manager != nullptr) {
    manager->ActivatePendingFactories();
  }
}

/**
 * Address: 0x004ABEB0 (FUN_004ABEB0, ?RES_Exit@Moho@@YAXXZ)
 *
 * What it does:
 * Ensures the singleton exists and runs resource-manager worker shutdown.
 */
void moho::RES_Exit()
{
  ResourceManager* const manager = RES_GetResourceManager();
  if (manager != nullptr) {
    manager->ShutdownBackgroundThread();
  }
}
