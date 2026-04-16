#include "CGpgNetInterface.h"

#include <cstring>
#include <cstdint>
#include <limits>
#include <new>
#include <stdexcept>
#include <utility>
#include <vector>

#include "Common.h"
#include "gpg/core/containers/String.h"
#include "gpg/core/streams/BinaryReader.h"
#include "gpg/core/utils/Logging.h"
#include "IClient.h"
#include "CClientManagerImpl.h"
#include "INetTCPServer.h"
#include "INetTCPSocket.h"
#include "moho/app/CWaitHandleSet.h"
#include "moho/app/WinApp.h"
#include "moho/app/WxRuntimeTypes.h"
#include "moho/client/Localization.h"
#include "moho/console/CConCommand.h"
#include "moho/lua/CScrLuaBinder.h"
#include "moho/lua/CScrLuaObjectFactory.h"
#include "moho/lua/CScrLuaInitForm.h"
#include "moho/misc/StartupHelpers.h"
#include "moho/net/INetNATTraversalProviderWeakPtrReflection.h"
#include "moho/sim/ISTIDriver.h"
#include "moho/sim/SimDriver.h"
#include "moho/ui/UiRuntimeTypes.h"
#include "platform/Platform.h"
#include <array>
#include <float.h>
#include <shellapi.h>
#include <wchar.h>
#include <windows.h>

using namespace moho;

namespace moho
{
  class IEditorDispatchHook
  {
  public:
    virtual ~IEditorDispatchHook() = default;
    virtual int Dispatch() = 0;
  };

  IEditorDispatchHook* ed_Hook = nullptr;
} // namespace moho

namespace
{
  constexpr const char* kLuaExpectedArgsWarning = "%s\n  expected %d args, but got %d";
  constexpr const char* kLuaExpectedAtLeastArgsWarning = "%s\n  expected at least %d args, but got %d";
  constexpr const char* kGpgNetActiveHelpText = "bool GpgNetActive()";
  constexpr const char* kGpgNetSendHelpText = "GpgNetSend(cmd,args...)";

  boost::shared_ptr<CGpgNetInterface> sGPGNet;

  /**
   * Address: 0x007B6450 (FUN_007B6450)
   *
   * What it does:
   * Dispatches one optional editor hook lane when present and returns its
   * integer result; returns `0` when no hook is installed.
   */
  [[maybe_unused]] int DispatchEditorHookIfPresent()
  {
    return moho::ed_Hook != nullptr ? moho::ed_Hook->Dispatch() : 0;
  }

  /**
   * Address: 0x007BBC10 (FUN_007BBC10, swap helper for global sGPGNet raw lane)
   *
   * What it does:
   * Swaps the process-global GPGNet shared-pointer lane with another shared
   * pointer lane and preserves the reference-counted payload ownership.
   */
  void SwapGlobalGpgNetPtr(
    boost::shared_ptr<CGpgNetInterface>& lane
  ) noexcept
  {
    using std::swap;
    swap(sGPGNet, lane);
  }

  struct SharedPtrRawLaneView
  {
    void* object = nullptr;  // +0x00
    void* counter = nullptr; // +0x04
  };

  static_assert(sizeof(SharedPtrRawLaneView) == 0x8, "SharedPtrRawLaneView size must be 0x8");

  /**
   * Address: 0x007BCCC0 (FUN_007BCCC0, raw-object lane swap for global sGPGNet)
   *
   * What it does:
   * Swaps only the raw object pointer lane (`px`) of process-global `sGPGNet`
   * with caller-provided pointer storage, preserving legacy lane semantics.
   */
  [[maybe_unused]] CGpgNetInterface** SwapGlobalGpgNetRawObjectLane(CGpgNetInterface** const lane) noexcept
  {
    auto* const rawShared = reinterpret_cast<SharedPtrRawLaneView*>(&sGPGNet);
    CGpgNetInterface* const previous = static_cast<CGpgNetInterface*>(rawShared->object);
    rawShared->object = (lane != nullptr) ? *lane : nullptr;
    if (lane != nullptr) {
      *lane = previous;
    }
    return lane;
  }

  /**
   * Address: 0x007BDB70 (FUN_007BDB70, register_WeakPtr_INetNATTraversalProvider_Type_00)
   *
   * What it does:
   * Forces the `boost::weak_ptr<INetNATTraversalProvider>` reflection lane to
   * materialize during startup.
   */
  [[nodiscard]] gpg::RType* RegisterWeakPtrINetNATTraversalProviderType()
  {
    return gpg::ResolveWeakPtrINetNATTraversalProviderType();
  }

  namespace
  {
    struct GpgNetReflectionBootstrap
    {
      GpgNetReflectionBootstrap()
      {
        (void)RegisterWeakPtrINetNATTraversalProviderType();
      }
    };

    GpgNetReflectionBootstrap gGpgNetReflectionBootstrap;
  } // namespace

  [[nodiscard]] moho::CScrLuaInitFormSet* FindUserLuaInitSet() noexcept
  {
    return moho::SCR_FindLuaInitFormSet("User");
  }

  [[nodiscard]] moho::CScrLuaInitFormSet& UserLuaInitSet()
  {
    if (moho::CScrLuaInitFormSet* const set = FindUserLuaInitSet(); set != nullptr) {
      return *set;
    }

    static moho::CScrLuaInitFormSet fallbackSet("User");
    return fallbackSet;
  }

  int32_t ExpectIntArg(
    CGpgNetInterface& owner,
    const SNetCommandArg* arg
  )
  {
    if (!arg || arg->mType != SNetCommandArg::NETARG_Num) {
      owner.ExpectedInt();
    }
    return arg->mNum;
  }

  void ReadExactFromSocket(
    INetTCPSocket* socket,
    char* out,
    const size_t size,
    const char* eofMessage
  )
  {
    size_t total = 0;
    while (total < size) {
      const size_t got = socket->Read(out + total, size - total);
      if (got == 0) {
        throw std::runtime_error(eofMessage);
      }
      total += got;
    }
  }

  /**
   * Address: 0x007B9040 (FUN_007B9040, func_UnknownCommand)
   *
   * What it does:
   * Emits a `gpg::Warnf` warning naming the unrecognized GPGNET command and
   * returns; the original engine quietly drops unknown commands rather than
   * propagating an exception.
   */
  void LogUnknownCommand(
    const msvc8::string& commandName
  )
  {
    gpg::Warnf("GPGNET: Ignoring unknown gpg.net command \"%s\".", commandName.c_str());
  }

  /**
   * Address: 0x007B7DB0 (FUN_007B7DB0)
   *
   * What it does:
   * Resets one legacy VC8 string lane back to empty SSO storage and releases
   * any heap buffer owned by that string.
   */
  [[maybe_unused]] void ResetLegacyStringStorage(
    msvc8::string& value
  ) noexcept
  {
    value.tidy(true, 0U);
  }

  /**
   * Address: 0x007B6500 (FUN_007B6500)
   *
   * What it does:
   * Returns whether one `LuaStackObject` currently points at a Lua boolean
   * stack slot (`lua_type == LUA_TBOOLEAN`).
   */
  [[maybe_unused]] bool IsLuaStackObjectBooleanType(
    const LuaPlus::LuaStackObject& stackObject
  ) noexcept
  {
    if (stackObject.m_state == nullptr || stackObject.m_state->GetCState() == nullptr) {
      return false;
    }

    return lua_type(stackObject.m_state->GetCState(), stackObject.m_stackIndex) == LUA_TBOOLEAN;
  }

  /**
   * Address: 0x007B8190 (FUN_007B8190)
   *
   * What it does:
   * Drops one shared pointer lane and releases the last ownership reference
   * when this was the final live handle.
   */
  void ReleaseGlobalGpgNetPtr(
    boost::shared_ptr<CGpgNetInterface>& ptr
  ) noexcept
  {
    ptr.reset();
  }

  struct SharedCountControlBlockVTable
  {
    std::uint8_t reserved_00[0x04];
    void(__thiscall* disposeObject)(void* self); // +0x04
    void(__thiscall* destroySelf)(void* self);   // +0x08
  };

  struct SharedCountControlBlockRuntime
  {
    SharedCountControlBlockVTable* vtable; // +0x00
    volatile long useCount;                // +0x04
    volatile long weakCount;               // +0x08
  };

  struct SharedCountRuntimeLane
  {
    std::uint32_t reserved_00 = 0u;
    SharedCountControlBlockRuntime* control = nullptr; // +0x04
  };

  /**
   * Address: 0x007B8DE0 (FUN_007B8DE0)
   *
   * What it does:
   * Releases one shared-count control block lane by decrementing strong/weak
   * reference counts and dispatching dispose/destroy virtual callbacks on the
   * last references.
   */
  [[maybe_unused]] SharedCountRuntimeLane* ReleaseSharedCountRuntimeLane(
    SharedCountRuntimeLane* const lane
  ) noexcept
  {
    if (lane == nullptr || lane->control == nullptr) {
      return lane;
    }

    SharedCountControlBlockRuntime* const control = lane->control;
    if (_InterlockedExchangeAdd(&control->useCount, -1) == 1) {
      if (control->vtable != nullptr && control->vtable->disposeObject != nullptr) {
        control->vtable->disposeObject(control);
      }

      if (_InterlockedExchangeAdd(&control->weakCount, -1) == 1) {
        if (control->vtable != nullptr && control->vtable->destroySelf != nullptr) {
          control->vtable->destroySelf(control);
        }
      }
    }

    return lane;
  }

  /**
   * Address: 0x007BB0E0 (FUN_007BB0E0)
   *
   * What it does:
   * Returns the live element count for one legacy vector lane.
   */
  [[nodiscard]] std::size_t GetCommandArgCount(
    const msvc8::vector<SNetCommandArg>& args
  ) noexcept
  {
    return args.size();
  }

  /**
   * Address: 0x007BB0A0 (FUN_007BB0A0)
   *
   * What it does:
   * Clears one command-argument vector lane before the owning command object
   * finishes destruction.
   */
  void DestroyCommandArgStorage(
    msvc8::vector<SNetCommandArg>& args
  ) noexcept
  {
    args = msvc8::vector<SNetCommandArg>{};
  }

  /**
   * Address: 0x007BBA90 (FUN_007BBA90)
   *
   * What it does:
   * Clears the queued command deque and releases its element payload lanes.
   */
  void ClearCommandQueue(
    msvc8::deque<SNetCommand>& commands
  ) noexcept
  {
    commands.clear();
  }

  /**
   * Address: 0x007BB3C0 (FUN_007BB3C0, queue-clear thunk)
   * Address: 0x007BB4D0 (FUN_007BB4D0, queue-clear thunk)
   *
   * What it does:
   * Tail-forwards one queued-command deque clear lane into
   * `ClearCommandQueue`.
   */
  [[maybe_unused]] void ClearCommandQueueThunk(
    msvc8::deque<SNetCommand>& commands
  ) noexcept
  {
    ClearCommandQueue(commands);
  }

  template <class T>
  struct LegacyDequeRuntimeView
  {
    void* mProxy;
    T** mMap;
    std::size_t mMapSize;
    std::size_t mOffset;
    std::size_t mSize;
  };

  static_assert(sizeof(LegacyDequeRuntimeView<SNetCommand>) == 0x14, "LegacyDequeRuntimeView size must be 0x14");

  template <class T>
  [[nodiscard]] LegacyDequeRuntimeView<T>& AsLegacyDequeRuntimeView(
    msvc8::deque<T>& deque
  ) noexcept
  {
    return *reinterpret_cast<LegacyDequeRuntimeView<T>*>(&deque);
  }

  /**
   * Address: 0x007BCF50 (FUN_007BCF50)
   *
   * What it does:
   * Swaps one legacy deque's map/offset/size storage lanes with another
   * deque, preserving proxy ownership in each object.
   */
  [[maybe_unused]] msvc8::deque<SNetCommand>& SwapQueuedCommandDequeStorage(
    msvc8::deque<SNetCommand>& left,
    msvc8::deque<SNetCommand>& right
  ) noexcept
  {
    LegacyDequeRuntimeView<SNetCommand>& leftView = AsLegacyDequeRuntimeView(left);
    LegacyDequeRuntimeView<SNetCommand>& rightView = AsLegacyDequeRuntimeView(right);

    std::swap(leftView.mMap, rightView.mMap);
    std::swap(leftView.mMapSize, rightView.mMapSize);
    std::swap(leftView.mOffset, rightView.mOffset);
    std::swap(leftView.mSize, rightView.mSize);
    return left;
  }

  /**
   * Address: 0x007BC5B0 (FUN_007BC5B0)
   *
   * What it does:
   * Jump-adapter lane that forwards deque storage swap to
   * `SwapQueuedCommandDequeStorage`.
   */
  [[maybe_unused]] msvc8::deque<SNetCommand>& SwapQueuedCommandDequeStorageThunk(
    msvc8::deque<SNetCommand>& left,
    msvc8::deque<SNetCommand>& right
  ) noexcept
  {
    return SwapQueuedCommandDequeStorage(left, right);
  }

  /**
   * Address: 0x007BB920 (FUN_007BB920)
   *
   * What it does:
   * Grows one legacy deque map by the binary's guarded step policy, moves the
   * existing slot map into the new allocation, and zero-fills the newly added
   * pointer lanes.
   */
  [[maybe_unused]] SNetCommand** GrowLegacyDequeMap(
    msvc8::deque<SNetCommand>& deque
  )
  {
    LegacyDequeRuntimeView<SNetCommand>& view = AsLegacyDequeRuntimeView(deque);

    constexpr std::size_t kMaxDequeSlots = 0x05555555u;
    if (view.mMapSize == kMaxDequeSlots) {
      throw std::length_error("deque<T> too long");
    }

    std::size_t growth = 1U;
    const std::size_t halfMapSize = view.mMapSize >> 1U;
    if (halfMapSize >= 8U) {
      if (halfMapSize > 1U) {
        growth = halfMapSize;
      }
    } else {
      growth = 8U;
    }

    if (view.mMapSize > kMaxDequeSlots - growth) {
      growth = 1U;
    }

    const std::size_t newMapSize = view.mMapSize + growth;
    SNetCommand** const newMap = static_cast<SNetCommand**>(::operator new(sizeof(SNetCommand*) * newMapSize));
    std::memset(newMap, 0, sizeof(SNetCommand*) * newMapSize);

    const std::size_t oldMapSize = view.mMapSize;
    const std::size_t offset = view.mOffset;
    SNetCommand** const oldMap = view.mMap;

    if (oldMap != nullptr && oldMapSize != 0U) {
      const std::size_t tailCount = offset < oldMapSize ? oldMapSize - offset : 0U;
      if (tailCount != 0U) {
        (void)memmove_s(
          newMap + offset,
          tailCount * sizeof(SNetCommand*),
          oldMap + offset,
          tailCount * sizeof(SNetCommand*)
        );
      }

      if (offset > growth) {
        const std::size_t prefixCount = growth;
        if (prefixCount != 0U) {
          (void)memmove_s(
            newMap + oldMapSize,
            prefixCount * sizeof(SNetCommand*),
            oldMap,
            prefixCount * sizeof(SNetCommand*)
          );
        }

        const std::size_t middleCount = offset - growth;
        if (middleCount != 0U) {
          (void)memmove_s(
            newMap,
            middleCount * sizeof(SNetCommand*),
            oldMap + growth,
            middleCount * sizeof(SNetCommand*)
          );
        }
      } else {
        const std::size_t copiedCount = offset;
        if (copiedCount != 0U) {
          (void)memmove_s(
            newMap + oldMapSize,
            copiedCount * sizeof(SNetCommand*),
            oldMap,
            copiedCount * sizeof(SNetCommand*)
          );
        }

        if (growth > copiedCount) {
          std::memset(
            newMap + oldMapSize + copiedCount,
            0,
            (growth - copiedCount) * sizeof(SNetCommand*)
          );
        }
      }
    }

    if (oldMap != nullptr) {
      ::operator delete(static_cast<void*>(oldMap));
    }

    view.mMap = newMap;
    view.mMapSize = newMapSize;
    return newMap;
  }

  /**
   * Address: 0x007BB440 (FUN_007BB440, deque push-back lane)
   *
   * What it does:
   * Appends one `SNetCommand` to the back of the legacy deque command queue.
   */
  [[maybe_unused]] void PushBackQueuedCommand(
    msvc8::deque<SNetCommand>& commandQueue,
    const SNetCommand& command
  )
  {
    commandQueue.push_back(command);
  }

  /**
   * Address: 0x007BE750 (FUN_007BE750, deque push-front lane)
   *
   * What it does:
   * Prepends one `SNetCommand` to the front of the legacy deque command queue
   * and returns the stored front element address.
   */
  [[maybe_unused]] [[nodiscard]] SNetCommand* PushFrontQueuedCommand(
    msvc8::deque<SNetCommand>& commandQueue,
    const SNetCommand& command
  )
  {
    commandQueue.push_front(command);
    return commandQueue.empty() ? nullptr : &commandQueue.front();
  }

  /**
   * Address: 0x007BB400 (FUN_007BB400)
   *
   * What it does:
   * Destroys one queued command at the front ring slot, advances the ring
   * offset, and decrements queue size.
   */
  [[maybe_unused]] [[nodiscard]] std::uint32_t PopFrontQueuedCommandRing(
    msvc8::deque<SNetCommand>& commandQueue
  )
  {
    LegacyDequeRuntimeView<SNetCommand>& view = AsLegacyDequeRuntimeView(commandQueue);
    if (view.mSize == 0U) {
      return static_cast<std::uint32_t>(view.mOffset);
    }

    view.mMap[view.mOffset]->~SNetCommand();
    ++view.mOffset;
    if (view.mOffset >= view.mMapSize) {
      view.mOffset = 0U;
    }

    const std::size_t previousSize = view.mSize;
    view.mSize = previousSize - 1U;
    if (previousSize == 1U) {
      view.mOffset = 0U;
    }

    return static_cast<std::uint32_t>(view.mOffset);
  }

  /**
   * Address: 0x007BC110 (FUN_007BC110)
   *
   * What it does:
   * Destroys one queued command at the back ring slot and decrements queue
   * size, resetting offset when the queue becomes empty.
   */
  [[maybe_unused]] void PopBackQueuedCommandRing(
    msvc8::deque<SNetCommand>& commandQueue
  )
  {
    LegacyDequeRuntimeView<SNetCommand>& view = AsLegacyDequeRuntimeView(commandQueue);
    const std::size_t size = view.mSize;
    if (size == 0U) {
      return;
    }

    std::size_t tailOffset = (view.mOffset + size) - 1U;
    if (tailOffset >= view.mMapSize) {
      tailOffset -= view.mMapSize;
    }

    view.mMap[tailOffset]->~SNetCommand();
    view.mSize = size - 1U;
    if (size == 1U) {
      view.mOffset = 0U;
    }
  }

  /**
   * Address: 0x007BDBB0 (FUN_007BDBB0)
   *
   * What it does:
   * Resets one command-argument string lane to empty SSO storage while
   * preserving the scalar `mType/mNum` lanes.
   */
  [[maybe_unused]] void ResetSingleCommandArgStorage(
    SNetCommandArg& arg
  ) noexcept
  {
    ResetLegacyStringStorage(arg.mStr);
  }

  /**
   * Address: 0x007B6D80 (FUN_007B6D80)
   *
   * What it does:
   * Resets one `SNetCommandArg` string payload lane back to empty storage
   * while preserving `mType/mNum` scalars and returns `0`.
   */
  [[maybe_unused]] int ResetSingleCommandArgStringStorageLaneA(
    SNetCommandArg* const arg
  ) noexcept
  {
    if (arg != nullptr) {
      ResetLegacyStringStorage(arg->mStr);
    }
    return 0;
  }

  /**
   * Address: 0x007B6570 (FUN_007B6570)
   *
   * What it does:
   * Initializes one `SNetCommandArg` as `NETARG_Data` and copies a byte range
   * into the embedded legacy string payload.
   */
  [[maybe_unused]] [[nodiscard]] SNetCommandArg* ConstructDataCommandArgFromRangeLaneA(
    const std::size_t length,
    const char* const begin,
    SNetCommandArg* const out
  )
  {
    if (out == nullptr) {
      return nullptr;
    }

    out->mType = SNetCommandArg::NETARG_Data;
    out->mNum = 0;
    ResetLegacyStringStorage(out->mStr);
    if (begin != nullptr && length != 0U) {
      out->mStr.assign(begin, length);
    }
    return out;
  }

  /**
   * Address: 0x007BE4B0 (FUN_007BE4B0)
   *
   * What it does:
   * Copy-assigns one `SNetCommandArg` lane by mirroring scalar fields and
   * rebuilding the legacy string payload from source text.
   */
  [[maybe_unused]] SNetCommandArg* CopyAssignSingleCommandArg(
    SNetCommandArg* const destination,
    const SNetCommandArg& source
  )
  {
    if (destination == nullptr) {
      return nullptr;
    }

    destination->mType = source.mType;
    destination->mNum = source.mNum;
    destination->mStr.reset_and_assign(source.mStr);
    return destination;
  }

  /**
   * Address: 0x007BDBA0 (FUN_007BDBA0)
   *
   * What it does:
   * Register-shape adapter that forwards one single-lane command-argument
   * copy-assignment into the canonical `CopyAssignSingleCommandArg` helper.
   */
  [[maybe_unused]] SNetCommandArg* CopyAssignSingleCommandArgRegisterAdapter(
    SNetCommandArg* const destination,
    const SNetCommandArg& source
  )
  {
    return CopyAssignSingleCommandArg(destination, source);
  }

  /**
   * Address: 0x007BAE30 (FUN_007BAE30)
   *
   * What it does:
   * Copy-assigns one command-argument lane by mirroring scalar fields and
   * assigning the full legacy string payload via `assign`.
   */
  [[maybe_unused]] SNetCommandArg* CopyAssignSingleCommandArgLaneA(
    SNetCommandArg* const destination,
    const SNetCommandArg& source
  )
  {
    if (destination == nullptr) {
      return nullptr;
    }

    destination->mType = source.mType;
    destination->mNum = source.mNum;
    destination->mStr.assign(source.mStr, 0, msvc8::string::npos);
    return destination;
  }

  /**
   * Address: 0x007BD950 (FUN_007BD950)
   *
   * What it does:
   * Fills one half-open command-arg range with a single prototype argument by
   * copying scalar lanes and cloning the legacy string payload.
   */
  [[maybe_unused]] [[nodiscard]] SNetCommandArg* FillCommandArgRangeFromPrototype(
    SNetCommandArg* destinationBegin,
    SNetCommandArg* destinationEnd,
    const SNetCommandArg& prototype
  )
  {
    while (destinationBegin != destinationEnd) {
      destinationBegin->mType = prototype.mType;
      destinationBegin->mNum = prototype.mNum;
      destinationBegin->mStr.assign(prototype.mStr, 0, msvc8::string::npos);
      ++destinationBegin;
    }
    return destinationEnd;
  }

  /**
   * Address: 0x007BD810 (FUN_007BD810)
   *
   * What it does:
   * Writes `count` copies of one command-argument prototype into contiguous
   * destination lanes, and on exception destroys already-written lanes before
   * rethrowing.
   */
  [[maybe_unused]] void CopyAssignCommandArgRangeWithRollback(
    const SNetCommandArg& prototype,
    std::uint32_t count,
    SNetCommandArg* const destination
  )
  {
    if (destination == nullptr || count == 0U) {
      return;
    }

    SNetCommandArg* const begin = destination;
    SNetCommandArg* cursor = destination;
    try {
      for (std::uint32_t i = 0; i < count; ++i, ++cursor) {
        (void)CopyAssignSingleCommandArg(cursor, prototype);
      }
    } catch (...) {
      for (SNetCommandArg* rollback = begin; rollback != cursor; ++rollback) {
        ResetSingleCommandArgStorage(*rollback);
      }
      throw;
    }
  }

  /**
   * Address: 0x007BCB90 (FUN_007BCB90)
   *
   * What it does:
   * Register-order adapter for prototype-range copy/rollback; forwards to
   * `CopyAssignCommandArgRangeWithRollback` and returns destination lane.
   */
  [[maybe_unused]] [[nodiscard]] SNetCommandArg* CopyAssignCommandArgRangeWithRollbackAdapterA(
    const SNetCommandArg* const prototype,
    const std::uint32_t count,
    SNetCommandArg* const destination
  )
  {
    if (prototype != nullptr) {
      CopyAssignCommandArgRangeWithRollback(*prototype, count, destination);
    }
    return destination;
  }

  /**
   * Address: 0x007BEE10 (FUN_007BEE10, command-arg range copy-assign)
   *
   * What it does:
   * Copy-assigns one half-open contiguous `SNetCommandArg` range into
   * destination lanes and returns one-past-last written pointer.
   */
  [[maybe_unused]] [[nodiscard]] SNetCommandArg* CopyAssignCommandArgRange(
    SNetCommandArg* destination,
    const SNetCommandArg* sourceBegin,
    const SNetCommandArg* sourceEnd
  )
  {
    while (sourceBegin != sourceEnd) {
      destination->mType = sourceBegin->mType;
      destination->mNum = sourceBegin->mNum;
      destination->mStr.assign(sourceBegin->mStr, 0, msvc8::string::npos);
      ++destination;
      ++sourceBegin;
    }
    return destination;
  }

  /**
   * Address: 0x007BDE40 (FUN_007BDE40)
   *
   * What it does:
   * Copy-assigns one half-open command-argument source range into destination
   * lanes and rolls back already-written destination entries on exception.
   */
  [[maybe_unused]] [[nodiscard]] SNetCommandArg* CopyAssignCommandArgRangeWithRollbackFromSourceLaneA(
    const SNetCommandArg* sourceBegin,
    const SNetCommandArg* sourceEnd,
    SNetCommandArg* destination
  )
  {
    SNetCommandArg* const writtenBegin = destination;
    SNetCommandArg* cursor = destination;
    try {
      while (sourceBegin != sourceEnd) {
        (void)CopyAssignSingleCommandArg(cursor, *sourceBegin);
        ++cursor;
        ++sourceBegin;
      }
    } catch (...) {
      for (SNetCommandArg* rollback = writtenBegin; rollback != cursor; ++rollback) {
        ResetSingleCommandArgStorage(*rollback);
      }
      throw;
    }
    return cursor;
  }

  /**
   * Address: 0x007BD7D0 (FUN_007BD7D0)
   *
   * What it does:
   * Register-lane adapter that forwards source-range command-argument
   * copy/rollback into `CopyAssignCommandArgRangeWithRollbackFromSourceLaneA`.
   */
  [[maybe_unused]] void CopyAssignCommandArgRangeWithRollbackFromSourceAdapterRegisterLane(
    SNetCommandArg* const destination,
    const SNetCommandArg* const sourceBegin,
    const SNetCommandArg* const sourceEnd
  )
  {
    (void)CopyAssignCommandArgRangeWithRollbackFromSourceLaneA(sourceBegin, sourceEnd, destination);
  }

  /**
   * Address: 0x007BCB00 (FUN_007BCB00)
   *
   * What it does:
   * Adapter lane that forwards source-range command-argument copy/rollback
   * into `CopyAssignCommandArgRangeWithRollbackFromSourceLaneA`.
   */
  [[maybe_unused]] [[nodiscard]] SNetCommandArg* CopyAssignCommandArgRangeWithRollbackFromSourceAdapterA(
    const SNetCommandArg* const sourceBegin,
    const SNetCommandArg* const sourceEnd,
    SNetCommandArg* const destination
  )
  {
    return CopyAssignCommandArgRangeWithRollbackFromSourceLaneA(sourceBegin, sourceEnd, destination);
  }

  /**
   * Address: 0x007BD1B0 (FUN_007BD1B0)
   *
   * What it does:
   * Assigns one command-argument vector lane from source into destination,
   * preserving self-assignment and empty-source clear semantics.
   */
  [[maybe_unused]] msvc8::vector<SNetCommandArg>* AssignCommandArgVectorStorage(
    msvc8::vector<SNetCommandArg>* const destination,
    const int /*destroyContext*/,
    const msvc8::vector<SNetCommandArg>* const source
  )
  {
    if (destination == nullptr || source == nullptr) {
      return destination;
    }

    if (destination == source) {
      return destination;
    }

    if (source->empty()) {
      destination->clear();
      return destination;
    }

    *destination = *source;
    return destination;
  }

  struct RuntimeSharedPtrLikeLane
  {
    void* object = nullptr;                 // +0x00
    boost::detail::shared_count count{};    // +0x04
  };
  static_assert(sizeof(RuntimeSharedPtrLikeLane) == 0x08, "RuntimeSharedPtrLikeLane size must be 0x08");

  struct RuntimeWeakPtrLikeLane
  {
    void* object = nullptr;               // +0x00
    boost::detail::weak_count count{};    // +0x04
  };
  static_assert(sizeof(RuntimeWeakPtrLikeLane) == 0x08, "RuntimeWeakPtrLikeLane size must be 0x08");

  /**
   * Address: 0x007BCB30 (FUN_007BCB30)
   *
   * What it does:
   * Copies one pointer lane and rebuilds one weak-count lane from source
   * shared-count ownership.
   */
  [[maybe_unused]] [[nodiscard]] RuntimeWeakPtrLikeLane* CopyWeakPtrLikeLaneFromSharedLaneA(
    const RuntimeSharedPtrLikeLane* const source,
    RuntimeWeakPtrLikeLane* const destination
  )
  {
    if (source == nullptr || destination == nullptr) {
      return destination;
    }

    destination->count = boost::detail::weak_count(source->count);
    destination->object = source->object;
    return destination;
  }

  /**
   * Address: 0x007BCB70 (FUN_007BCB70)
   *
   * What it does:
   * Secondary copy lane for shared-to-weak pointer payload cloning.
   */
  [[maybe_unused]] [[nodiscard]] RuntimeWeakPtrLikeLane* CopyWeakPtrLikeLaneFromSharedLaneB(
    const RuntimeSharedPtrLikeLane* const source,
    RuntimeWeakPtrLikeLane* const destination
  )
  {
    return CopyWeakPtrLikeLaneFromSharedLaneA(source, destination);
  }

  struct RuntimeCommandDispatchLane
  {
    using DispatchFn = int(__thiscall*)(std::uint32_t adjustedThis, std::uint32_t dwordArg, std::uint32_t wordArg);

    DispatchFn dispatch;        // +0x00
    std::uint32_t thisBase;     // +0x04
    std::uint32_t thisOffset;   // +0x08
    std::uint32_t dwordArg;     // +0x0C
    std::uint16_t wordArg;      // +0x10
    std::uint16_t reserved12;   // +0x12
  };
  static_assert(sizeof(RuntimeCommandDispatchLane) == 0x14, "RuntimeCommandDispatchLane size must be 0x14");

  /**
   * Address: 0x007BEE50 (FUN_007BEE50)
   *
   * What it does:
   * Rebuilds one adjusted this-pointer lane (`base + offset`) and dispatches
   * through the stored thiscall function pointer with one dword and one
   * zero-extended word payload argument.
   */
  [[maybe_unused]] int DispatchCommandThroughAdjustedThiscall(
    RuntimeCommandDispatchLane* const lane
  )
  {
    const std::uint32_t adjustedThis = lane->thisBase + lane->thisOffset;
    return lane->dispatch(adjustedThis, lane->dwordArg, static_cast<std::uint32_t>(lane->wordArg));
  }

  /**
   * Address: 0x007BD8F0 (FUN_007BD8F0)
   *
   * What it does:
   * Destroys one half-open `SNetCommandArg` range by releasing each string
   * payload lane in turn.
   */
  [[maybe_unused]] void DestroyCommandArgRange(
    SNetCommandArg* first,
    SNetCommandArg* last
  ) noexcept
  {
    for (; first != last; ++first) {
      ResetLegacyStringStorage(first->mStr);
    }
  }

  /**
   * Address: 0x007BBD40 (FUN_007BBD40)
   *
   * What it does:
   * Adapts one thiscall range-destroy lane into
   * `DestroyCommandArgRange(begin, end)`.
   */
  [[maybe_unused]] void DestroyCommandArgRangeThiscallAdapter(
    SNetCommandArg* const rangeEnd,
    SNetCommandArg* const rangeBegin
  ) noexcept
  {
    DestroyCommandArgRange(rangeBegin, rangeEnd);
  }

  [[nodiscard]] moho::SNetCommand* CopyConstructSNetCommandIfPresent(
    moho::SNetCommand* const destination,
    const moho::SNetCommand* const source
  )
  {
    if (source == nullptr) {
      return nullptr;
    }

    return ::new (destination) moho::SNetCommand(*source);
  }

  /**
   * Address: 0x007BBB90 (FUN_007BBB90)
   *
   * What it does:
   * Primary adapter lane for nullable `SNetCommand` copy-construction into
   * caller-provided queue storage.
   */
  [[maybe_unused]] [[nodiscard]] moho::SNetCommand* CopyConstructSNetCommandIfPresentPrimary(
    moho::SNetCommand* const destination,
    const moho::SNetCommand* const source
  )
  {
    return CopyConstructSNetCommandIfPresent(destination, source);
  }

  /**
   * Address: 0x007BCC60 (FUN_007BCC60)
   *
   * What it does:
   * Secondary adapter lane for nullable `SNetCommand` copy-construction into
   * caller-provided queue storage.
   */
  [[maybe_unused]] [[nodiscard]] moho::SNetCommand* CopyConstructSNetCommandIfPresentSecondary(
    moho::SNetCommand* const destination,
    const moho::SNetCommand* const source
  )
  {
    return CopyConstructSNetCommandIfPresent(destination, source);
  }
} // namespace

/**
 * Address: 0x007B9470 (FUN_007B9470, Moho::GPGNET_SetPtr)
 *
 * What it does:
 * Replaces the process-global GPGNet shared-pointer lane (`sGPGNet`).
 */
void moho::GPGNET_SetPtr(
  const boost::shared_ptr<CGpgNetInterface>& ptr
)
{
  boost::shared_ptr<CGpgNetInterface> lane = ptr;
  SwapGlobalGpgNetPtr(lane);
}

boost::shared_ptr<moho::CGpgNetInterface> moho::GPGNET_GetPtr()
{
  return sGPGNet;
}

/**
 * Address: 0x007B94C0 (FUN_007B94C0, ?GPGNET_ReportBottleneck@Moho@@YAXABUSClientBottleneckInfo@1@@Z)
 *
 * What it does:
 * Formats one bottleneck report payload and sends `"Bottleneck"` through the
 * active process-global GPGNet interface.
 */
void moho::GPGNET_ReportBottleneck(
  const SClientBottleneckInfo& info
)
{
  const boost::shared_ptr<CGpgNetInterface> active = GPGNET_GetPtr();
  ISTIDriver* const activeDriver = SIM_GetActiveDriver();
  if (!active || activeDriver == nullptr) {
    return;
  }

  CClientManagerImpl* const clientManager = activeDriver->GetClientManager();

  const char* bottleneckType = "unknown";
  switch (info.mType) {
    case SClientBottleneckInfo::Nothing:
      bottleneckType = "nothing";
      break;
    case SClientBottleneckInfo::Readiness:
      bottleneckType = "readiness";
      break;
    case SClientBottleneckInfo::Data:
      bottleneckType = "data";
      break;
    case SClientBottleneckInfo::Ack:
      bottleneckType = "ack";
      break;
    default:
      break;
  }

  msvc8::string impactedOwners{};
  const unsigned int endValue = info.mSubobj.Max();
  unsigned int ownerIndex = info.mSubobj.GetNext(std::numeric_limits<unsigned int>::max());
  if (ownerIndex != endValue) {
    if (IClient* const first = clientManager->GetClient(static_cast<int>(ownerIndex)); first != nullptr) {
      impactedOwners = gpg::STR_Printf("%u", static_cast<unsigned int>(first->GetOwnerId()));
    }

    for (ownerIndex = info.mSubobj.GetNext(ownerIndex); ownerIndex != endValue;
         ownerIndex = info.mSubobj.GetNext(ownerIndex)) {
      if (IClient* const next = clientManager->GetClient(static_cast<int>(ownerIndex)); next != nullptr) {
        impactedOwners += gpg::STR_Printf(",%u", static_cast<unsigned int>(next->GetOwnerId()));
      }
    }
  }

  msvc8::string bottleneckTypeText{};
  bottleneckTypeText.assign_owned(bottleneckType);
  const msvc8::string beatText = gpg::STR_Printf("%u", static_cast<unsigned int>(info.mVal));
  const msvc8::string millisText = gpg::STR_Printf("%.1f", static_cast<double>(info.mFloat));

  const SNetCommandArg typeArg(bottleneckTypeText);
  const SNetCommandArg beatArg(beatText);
  const SNetCommandArg ownersArg(impactedOwners);
  const SNetCommandArg millisArg(millisText);
  active->WriteCommandWith4Args("Bottleneck", &typeArg, &beatArg, &ownersArg, &millisArg);
}

/**
 * Address: 0x007B9A20 (FUN_007B9A20, Moho::GPGNET_ReportBottleneckCleared)
 *
 * What it does:
 * Sends one `BottleneckCleared` command through the active process-global
 * GPGNet interface pointer (when available).
 */
void moho::GPGNET_ReportBottleneckCleared()
{
  const boost::shared_ptr<CGpgNetInterface> active = GPGNET_GetPtr();
  if (!active) {
    return;
  }

  active->SendBottleneckCleared();
}

/**
 * Address: 0x007B9AC0 (FUN_007B9AC0, Moho::GPGNET_ReportDesync)
 *
 * What it does:
 * Sends one GPGNet `"Desync"` command carrying beat/army ids and both hash
 * strings from one desync record.
 */
void moho::GPGNET_ReportDesync(
  const int beat,
  const int army,
  const msvc8::string& hash1,
  const msvc8::string& hash2
)
{
  const boost::shared_ptr<CGpgNetInterface> active = GPGNET_GetPtr();
  if (!active) {
    return;
  }

  const SNetCommandArg beatArg(beat);
  const SNetCommandArg armyArg(army);
  const SNetCommandArg hash1Arg(hash1);
  const SNetCommandArg hash2Arg(hash2);
  active->WriteCommandWith4Args("Desync", &beatArg, &armyArg, &hash1Arg, &hash2Arg);
}

/**
 * Address: 0x007B9CD0 (FUN_007B9CD0, Moho::GPGNET_SubmitArmyStats)
 *
 * What it does:
 * Sends one GPGNet `"Stats"` command carrying one serialized army-stats
 * payload string.
 */
void moho::GPGNET_SubmitArmyStats(
  const msvc8::string& statsPayload
)
{
  const boost::shared_ptr<CGpgNetInterface> active = GPGNET_GetPtr();
  if (!active) {
    return;
  }

  const SNetCommandArg payloadArg(statsPayload);
  active->WriteCommandWith1Arg("Stats", &payloadArg);
}

/**
 * Address: 0x007B9360 (FUN_007B9360, ?GPGNET_Attach@Moho@@YAXIG@Z)
 *
 * What it does:
 * Creates and connects the process-global GPGNet interface.
 */
void moho::GPGNET_Attach(
  const u_long addr,
  const u_short port
)
{
  if (GPGNET_GetPtr()) {
    throw std::runtime_error("Can't attach to a gpg.net if we already are.");
  }

  boost::shared_ptr<CGpgNetInterface> created = CGpgNetInterface::CreatePtr(new CGpgNetInterface{});
  created->Connect(addr, port);
  GPGNET_SetPtr(created);
}

/**
 * Address: 0x007B9DD0 (FUN_007B9DD0, ?GPGNET_Shutdown@Moho@@YAXXZ thunk)
 * Address: 0x007BB590 (FUN_007BB590, ?GPGNET_Shutdown@Moho@@YAXXZ body)
 *
 * What it does:
 * Clears the process-global GPGNet interface shared-pointer lane.
 */
void moho::GPGNET_Shutdown()
{
  ReleaseGlobalGpgNetPtr(sGPGNet);
}

/**
 * Address: 0x007B9DE0 (FUN_007B9DE0, cfunc_GpgNetActive)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GpgNetActiveL`.
 */
int moho::cfunc_GpgNetActive(
  lua_State* const luaContext
)
{
  return cfunc_GpgNetActiveL(SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007B9E00 (FUN_007B9E00, func_GpgNetActive_LuaFuncDef)
 *
 * What it does:
 * Publishes global `GpgNetActive()` Lua binder in the user init set.
 */
moho::CScrLuaInitForm* moho::func_GpgNetActive_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(), "GpgNetActive", &moho::cfunc_GpgNetActive, nullptr, "<global>", kGpgNetActiveHelpText
  );
  return &binder;
}

/**
 * Address: 0x007B9E60 (FUN_007B9E60, cfunc_GpgNetActiveL)
 *
 * What it does:
 * Validates no Lua args and pushes whether a process-global GPGNet
 * interface pointer is active.
 */
int moho::cfunc_GpgNetActiveL(
  LuaPlus::LuaState* const state
)
{
  if (!state || !state->m_state) {
    return 0;
  }

  const int argumentCount = lua_gettop(state->m_state);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kGpgNetActiveHelpText, 0, argumentCount);
  }

  lua_pushboolean(state->m_state, GPGNET_GetPtr() ? 1 : 0);
  (void)lua_gettop(state->m_state);
  return 1;
}

/**
 * Address: 0x007B9EB0 (FUN_007B9EB0, cfunc_GpgNetSend)
 *
 * What it does:
 * Unwraps raw Lua callback context and forwards to `cfunc_GpgNetSendL`.
 */
int moho::cfunc_GpgNetSend(
  lua_State* const luaContext
)
{
  return cfunc_GpgNetSendL(SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007B9ED0 (FUN_007B9ED0, func_GpgNetSend_LuaFuncDef)
 *
 * What it does:
 * Publishes global `GpgNetSend(command, args...)` Lua binder in the user init
 * set.
 */
moho::CScrLuaInitForm* moho::func_GpgNetSend_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(), "GpgNetSend", &moho::cfunc_GpgNetSend, nullptr, "<global>", kGpgNetSendHelpText
  );
  return &binder;
}

/**
 * Address: 0x007B9F30 (FUN_007B9F30, cfunc_GpgNetSendL)
 *
 * What it does:
 * Validates and marshals Lua args into `SNetCommandArg` lanes, then sends one
 * command through active process-global GPGNet interface (if present).
 */
int moho::cfunc_GpgNetSendL(
  LuaPlus::LuaState* const state
)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount < 1) {
    LuaPlus::LuaState::Error(state, kLuaExpectedAtLeastArgsWarning, kGpgNetSendHelpText, 1, argumentCount);
  }

  LuaPlus::LuaStackObject commandArg(state, 1);
  const char* commandName = lua_tostring(rawState, 1);
  if (commandName == nullptr) {
    commandArg.TypeError("string");
    commandName = "";
  }

  msvc8::vector<SNetCommandArg> args;
  for (int index = 2; index <= argumentCount; ++index) {
    const int luaType = lua_type(rawState, index);
    if (luaType == LUA_TNUMBER) {
      LuaPlus::LuaStackObject numberArg(state, index);
      if (lua_type(rawState, index) != LUA_TNUMBER) {
        numberArg.TypeError("integer");
      }

      args.push_back(SNetCommandArg(static_cast<int32_t>(lua_tonumber(rawState, index))));
      continue;
    }

    if (luaType == LUA_TBOOLEAN) {
      LuaPlus::LuaStackObject boolArg(state, index);
      if (lua_type(rawState, index) != LUA_TBOOLEAN && lua_type(rawState, index) != LUA_TNONE) {
        boolArg.TypeError("boolean");
      }

      args.push_back(SNetCommandArg(lua_toboolean(rawState, index) ? 1 : 0));
      continue;
    }

    if (lua_isstring(rawState, index)) {
      LuaPlus::LuaStackObject stringArg(state, index);
      const char* text = lua_tostring(rawState, index);
      if (text == nullptr) {
        stringArg.TypeError("string");
        text = "";
      }

      args.push_back(SNetCommandArg(msvc8::string(text)));
      continue;
    }

    LuaPlus::LuaState::Error(state, "invalid kind of argument to GpgNetSend(): can only deal with ints and strings.");
  }

  if (const boost::shared_ptr<CGpgNetInterface> active = GPGNET_GetPtr(); active) {
    active->WriteCommand(commandName, args);
  }

  return 1;
}

/**
 * Address: 0x007B6720 (FUN_007B6720, ??0SNetCommand@Moho@@QAE@@Z)
 *
 * What it does:
 * Initializes one queued command entry with copied name, argument vector, and
 * value lanes.
 */
moho::SNetCommand::SNetCommand(
  const char* const name,
  const msvc8::vector<SNetCommandArg>& args,
  const int val
)
  : mName(name)
  , mArgs(args)
  , mVal(val)
{}

/**
 * Address: 0x007BCE70 (FUN_007BCE70)
 *
 * What it does:
 * Copy-constructs one queued command entry by initializing destination name
 * and argument-vector storage from source lanes, then copying queued value.
 */
moho::SNetCommand::SNetCommand(
  const SNetCommand& source
)
  : mName()
  , mArgs()
  , mVal(0)
{
  mName.reset_and_assign(source.mName);
  (void)AssignCommandArgVectorStorage(&mArgs, 0, &source.mArgs);
  mVal = source.mVal;
}

/**
 * Address: 0x007BAEF0 (FUN_007BAEF0, ??1SNetCommand@Moho@@QAE@@Z)
 *
 * What it does:
 * Runs member destructors for queued-command name/argument storage.
 */
moho::SNetCommand::~SNetCommand()
{
  DestroyCommandArgStorage(mArgs);
}

/**
 * Address: 0x007BCA70 (FUN_007BCA70, Moho::CGpgNetInterface::CreatePtr)
 *
 * What it does:
 * Creates one owning `boost::shared_ptr<CGpgNetInterface>` from a raw instance
 * pointer and binds `enable_shared_from_this` ownership lanes.
 */
boost::shared_ptr<moho::CGpgNetInterface> moho::CGpgNetInterface::CreatePtr(
  CGpgNetInterface* const inter
)
{
  return boost::shared_ptr<CGpgNetInterface>(inter);
}

/**
 * Address: 0x007B6800 (FUN_007B6800)
 *
 * What it does:
 * Initializes GPGNet task/provider state, creates queue event, and registers
 * the event with the global wait-handle set.
 */
CGpgNetInterface::CGpgNetInterface()
  : enable_shared_from_this()
  , mConnectionState(kNetStatePending)
  , mTcpServer(nullptr)
  , mTcpSocket(nullptr)
  , mCommands()
  , mQueueEvent(nullptr)
  , mConnectThreadWorker(nullptr)
  , mLobbyObject()
  , mNATHandler()
{
  mQueueEvent = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  if (mQueueEvent) {
    if (auto* const waitHandleSet = WIN_GetWaitHandleSet()) {
      waitHandleSet->AddHandle(mQueueEvent);
    }
  }
}

/**
 * Address: 0x007B6900 (FUN_007B6900 non-deleting body)
 * Address: 0x007B68C0 (FUN_007B68C0 deleting wrapper)
 *
 * What it does:
 * Shuts down transport resources, unregisters the queue event, and releases
 * NAT-traversal callback ownership.
 */
CGpgNetInterface::~CGpgNetInterface()
{
  Shutdown();

  if (mQueueEvent) {
    if (auto* const waitHandleSet = WIN_GetWaitHandleSet()) {
      waitHandleSet->RemoveHandle(mQueueEvent);
    }
    CloseHandle(mQueueEvent);
    mQueueEvent = nullptr;
  }

  mNATHandler.reset();
}

/**
 * Address: 0x007B7680 (FUN_007B7680)
 *
 * What it does:
 * Closes active TCP endpoints, stops the connect worker thread, clears the
 * pending command queue, resets connection state, and resets queue event.
 */
bool CGpgNetInterface::Shutdown()
{
  if (mTcpSocket) {
    mTcpSocket->VirtClose(gpg::Stream::ModeBoth);
  }

  if (mTcpServer) {
    mTcpServer->CloseSocket();
  }

  if (mConnectThreadWorker) {
    mConnectThreadWorker->join();
    delete mConnectThreadWorker;
    mConnectThreadWorker = nullptr;
  }

  ClearCommandQueue(mCommands);

  if (mTcpSocket) {
    delete mTcpSocket;
    mTcpSocket = nullptr;
  }

  if (mTcpServer) {
    delete mTcpServer;
    mTcpServer = nullptr;
  }

  mConnectionState = kNetStatePending;
  return mQueueEvent ? ResetEvent(mQueueEvent) != FALSE : true;
}

/**
 * Address: 0x007B9070 (FUN_007B9070)
 * Address: 0x10381F80 (sub_10381F80)
 *
 * What it does:
 * Updates weak NAT handler pointer used by SendNatPacket command path.
 */
void CGpgNetInterface::SetTraversalHandler(
  const int port,
  boost::shared_ptr<INetNATTraversalHandler>* handler
)
{
  (void)port;
  boost::mutex::scoped_lock lock(mLock);
  gpg::Logf("GPGNET: setting nat handler to 0x%08x", reinterpret_cast<uintptr_t>(handler->get()));
  mNATHandler = *handler;
}

/**
 * Address: 0x007B9160 (FUN_007B9160)
 * Address: 0x10382070 (sub_10382070)
 *
 * What it does:
 * Wraps NAT payload into `ProcessNatPacket` command (`"ip:port"`, binary blob)
 * and forwards it to the GPGNet command stream.
 */
void CGpgNetInterface::ReceivePacket(
  const u_long address,
  u_short port,
  const char* data,
  size_t size
)
{
  const auto ip = NET_GetDottedOctetFromUInt32(address);
  gpg::Logf("GPGNET: received nat packet from %s:%d", ip.c_str(), port);

  const msvc8::string connStr = gpg::STR_Printf("%s:%d", ip.c_str(), static_cast<int>(port));
  SNetCommandArg argFrom(connStr);

  SNetCommandArg argData(0);
  (void)ConstructDataCommandArgFromRangeLaneA(size, data, &argData);

  WriteCommandWith2Args("ProcessNatPacket", &argFrom, &argData);
}

/**
 * Address: 0x007BB250 (FUN_007BB250)
 *
 * What it does:
 * Executes one command-queue processing pass and returns task continuation (`1`).
 */
int CGpgNetInterface::Execute()
{
  Process();
  return 1;
}

/**
 * Address: 0x007B65C0 (FUN_007B65C0)
 *
 * What it does:
 * Throws argument-type error for expected integer argument.
 */
void CGpgNetInterface::ExpectedInt() noexcept(
  false
)
{
  throw std::runtime_error("incorrect argument type, expected int");
}

/**
 * Address: 0x007B6630 (FUN_007B6630)
 *
 * What it does:
 * Returns string payload reference or throws type-error if arg is not string.
 */
const msvc8::string& CGpgNetInterface::ExpectedString(const SNetCommandArg* arg) noexcept(false)
{
  if (arg->mType != SNetCommandArg::NETARG_String) {
    throw std::runtime_error("incorrect argument type, expected string");
  }
  return arg->mStr;
}

/**
 * Address: 0x007B66B0 (FUN_007B66B0)
 *
 * What it does:
 * Throws argument-type error for expected binary-data argument.
 */
void CGpgNetInterface::ExpectedData() noexcept(
  false
)
{
  throw std::runtime_error("incorrect argument type, expected data");
}

/**
 * Address: 0x007B67A0 (FUN_007B67A0)
 *
 * What it does:
 * Enqueues a named command with zero arguments and explicit state value.
 */
void CGpgNetInterface::EnqueueCommand0(
  const char* str,
  int val
)
{
  msvc8::vector<SNetCommandArg> args;
  EnqueueCommand(str, args, val);
}

/**
 * Address: 0x007B6A30 (FUN_007B6A30)
 *
 * What it does:
 * Starts async TCP connect worker and marks connection state as connecting.
 */
void CGpgNetInterface::Connect(
  const u_long address,
  const u_short port
)
{
  boost::mutex::scoped_lock lock(mLock);

  if (mConnectionState != kNetStatePending) {
    throw std::runtime_error("Already connected.");
  }

  mConnectionState = kNetStateConnecting;

  boost::thread* const thread = new boost::thread([this, address, port] {
    ConnectThread(address, port);
  });

  boost::thread* const oldThread = mConnectThreadWorker;
  mConnectThreadWorker = thread;
  if (oldThread) {
    oldThread->join();
    delete oldThread;
  }
}

/**
 * Address: 0x007B6BA0 (FUN_007B6BA0, func_NET_connect)
 *
 * What it does:
 * Starts async GPGNet-launch connect worker from one command-line template
 * (for example containing `%s` endpoint substitution).
 */
void CGpgNetInterface::Connect(
  const msvc8::string& launchCommandTemplate
)
{
  boost::mutex::scoped_lock lock(mLock);

  if (mConnectionState != kNetStatePending) {
    throw std::runtime_error("Already connected.");
  }

  mConnectionState = kNetStateConnecting;

  boost::thread* const thread = new boost::thread([this, launchCommandTemplate] {
    ConnectThread(launchCommandTemplate);
  });

  boost::thread* const oldThread = mConnectThreadWorker;
  mConnectThreadWorker = thread;
  if (oldThread != nullptr) {
    delete oldThread;
  }
}

/**
 * Address: 0x007B6DB0 (FUN_007B6DB0)
 *
 * What it does:
 * Writes a command name plus argument vector to active GPGNet socket stream.
 */
void CGpgNetInterface::WriteCommand(
  const char* name,
  const msvc8::vector<SNetCommandArg>& args
)
{
  boost::mutex::scoped_lock lock(mLock);

  if (mConnectionState != kNetStateEstablishing) {
    throw std::runtime_error("Gpg.net not connected");
  }

  if (!mTcpSocket) {
    return;
  }

  WriteCommandName(name);

  const uint32_t argc = static_cast<uint32_t>(GetCommandArgCount(args));
  mTcpSocket->Write(argc);

  for (const SNetCommandArg& arg : args) {
    WriteArg(&arg);
  }

  mTcpSocket->VirtFlush();
}

/**
 * Address: 0x007B6F00 (FUN_007B6F00)
 *
 * What it does:
 * Emits `BottleneckCleared` notification over active GPGNet command stream.
 */
void CGpgNetInterface::SendBottleneckCleared()
{
  boost::mutex::scoped_lock lock(mLock);

  if (mConnectionState != kNetStateEstablishing) {
    throw std::runtime_error("Gpg.net not connected");
  }

  if (!mTcpSocket) {
    return;
  }

  WriteCommandName("BottleneckCleared");
  constexpr uint32_t argc = 0;
  mTcpSocket->Write(argc);
  mTcpSocket->VirtFlush();
}

/**
 * Address: 0x007B6FF0 (FUN_007B6FF0)
 *
 * What it does:
 * Writes command name with one serialized argument and flushes stream.
 */
void CGpgNetInterface::WriteCommandWith1Arg(
  const char* name,
  const SNetCommandArg* arg
)
{
  boost::mutex::scoped_lock lock(mLock);

  if (mConnectionState != kNetStateEstablishing) {
    throw std::runtime_error("Gpg.net not connected");
  }

  if (!mTcpSocket) {
    return;
  }

  WriteCommandName(name);
  constexpr uint32_t argc = 1;
  mTcpSocket->Write(argc);
  WriteArg(arg);
  mTcpSocket->VirtFlush();
}

/**
 * Address: 0x007B70F0 (FUN_007B70F0)
 *
 * What it does:
 * Writes command name with two serialized arguments and flushes stream.
 */
void CGpgNetInterface::WriteCommandWith2Args(
  const char* name,
  const SNetCommandArg* arg1,
  const SNetCommandArg* arg2
)
{
  boost::mutex::scoped_lock lock(mLock);

  if (mConnectionState != kNetStateEstablishing) {
    throw std::runtime_error("Gpg.net not connected");
  }

  if (!mTcpSocket) {
    return;
  }

  WriteCommandName(name);

  constexpr uint32_t argc = 2;
  mTcpSocket->Write(argc);
  WriteArg(arg1);
  WriteArg(arg2);
  mTcpSocket->VirtFlush();
}

/**
 * Address: 0x007B7200 (FUN_007B7200)
 *
 * What it does:
 * Writes command name with three serialized arguments and flushes stream.
 */
void CGpgNetInterface::WriteCommandWith3Args(
  const char* name,
  const SNetCommandArg* arg1,
  const SNetCommandArg* arg2,
  const SNetCommandArg* arg3
)
{
  boost::mutex::scoped_lock lock(mLock);

  if (mConnectionState != kNetStateEstablishing) {
    throw std::runtime_error("Gpg.net not connected");
  }

  if (!mTcpSocket) {
    return;
  }

  WriteCommandName(name);

  constexpr uint32_t argc = 3;
  mTcpSocket->Write(argc);
  WriteArg(arg1);
  WriteArg(arg2);
  WriteArg(arg3);
  mTcpSocket->VirtFlush();
}

/**
 * Address: 0x007B7310 (FUN_007B7310)
 *
 * What it does:
 * Writes command name with four serialized arguments and flushes stream.
 */
void CGpgNetInterface::WriteCommandWith4Args(
  const char* name,
  const SNetCommandArg* arg1,
  const SNetCommandArg* arg2,
  const SNetCommandArg* arg3,
  const SNetCommandArg* arg4
)
{
  boost::mutex::scoped_lock lock(mLock);

  if (mConnectionState != kNetStateEstablishing) {
    throw std::runtime_error("Gpg.net not connected");
  }

  if (!mTcpSocket) {
    return;
  }

  WriteCommandName(name);

  constexpr uint32_t argc = 4;
  mTcpSocket->Write(argc);
  WriteArg(arg1);
  WriteArg(arg2);
  WriteArg(arg3);
  WriteArg(arg4);
  mTcpSocket->VirtFlush();
}

/**
 * Address: 0x007B7420 (FUN_007B7420)
 *
 * What it does:
 * Writes command name as `uint32 len + raw bytes`.
 */
void CGpgNetInterface::WriteCommandName(
  const char* name
)
{
  if (!mTcpSocket) {
    return;
  }

  const char* const value = name ? name : "";
  const uint32_t len = static_cast<uint32_t>(std::strlen(value));
  mTcpSocket->Write(len);
  if (len != 0) {
    mTcpSocket->Write(value, len);
  }
}

/**
 * Address: 0x007B74A0 (FUN_007B74A0)
 *
 * What it does:
 * Writes `msvc8::string` payload as `uint32 len + raw bytes`.
 */
void CGpgNetInterface::WriteString(
  const msvc8::string& str
)
{
  if (!mTcpSocket) {
    return;
  }

  const uint32_t len = static_cast<uint32_t>(str.size());
  mTcpSocket->Write(len);
  if (len != 0) {
    mTcpSocket->Write(str.data(), len);
  }
}

/**
 * Address: 0x007B7520 (FUN_007B7520)
 *
 * What it does:
 * Serializes one `SNetCommandArg` as tagged payload (`type` + body).
 */
void CGpgNetInterface::WriteArg(
  const SNetCommandArg* arg
)
{
  if (!mTcpSocket || !arg) {
    return;
  }

  const uint8_t type = static_cast<uint8_t>(arg->mType);
  mTcpSocket->Write(type);
  switch (arg->mType) {
  case SNetCommandArg::NETARG_Num:
    mTcpSocket->Write(arg->mNum);
    return;
  case SNetCommandArg::NETARG_String:
    WriteString(ExpectedString(arg));
    return;
  case SNetCommandArg::NETARG_Data:
    WriteString(arg->mStr);
    return;
  default:
    return;
  }
}

/**
 * Address: 0x007B75D0 (FUN_007B75D0)
 *
 * What it does:
 * Validates GPGNet connected state under `mLock` and closes one active TCP
 * socket lane with bidirectional shutdown.
 */
void CGpgNetInterface::EnsureConnectedAndCloseSocket()
{
  boost::mutex::scoped_lock lock(mLock);

  if (mConnectionState != kNetStateEstablishing) {
    throw std::runtime_error("Gpg.net not connected");
  }

  if (mTcpSocket != nullptr) {
    mTcpSocket->VirtClose(gpg::Stream::ModeBoth);
  }
}

/**
 * Address: 0x007B7710 (FUN_007B7710 / func_GPGNETProcess)
 *
 * What it does:
 * Drains queued inbound commands, updates state from each command envelope,
 * and dispatches to command-specific handlers.
 */
void CGpgNetInterface::Process()
{
  msvc8::deque<SNetCommand> pending;

  {
    boost::mutex::scoped_lock lock(mLock);
    (void)SwapQueuedCommandDequeStorage(mCommands, pending);
    if (mQueueEvent) {
      ResetEvent(mQueueEvent);
    }
  }

  while (!pending.empty()) {
    SNetCommand& command = pending.front();
    mConnectionState = static_cast<DWORD>(command.mVal);

    try {
      const auto commandName = command.mName.view();
      if (commandName == "Test") {
        Test(command.mArgs);
      } else if (commandName == "Connected") {
        Connected(command.mArgs);
      } else if (commandName == "CreateLobby") {
        CreateLobby(command.mArgs);
      } else if (commandName == "HasSupcom") {
        HasSupCom(command.mArgs);
      } else if (commandName == "HasForgedAlliance") {
        HasForgedAlliance(command.mArgs);
      } else if (commandName == "HostGame") {
        HostGame(command.mArgs);
      } else if (commandName == "JoinGame") {
        JoinGame(command.mArgs);
      } else if (commandName == "ConnectToPeer") {
        ConnectToPeer(command.mArgs);
      } else if (commandName == "DisconnectFromPeer") {
        DisconnectFromPeer(command.mArgs);
      } else if (commandName == "SendNatPacket") {
        SendNatPacket(command.mArgs);
      } else if (commandName == "EjectPlayer") {
        EjectPlayer(command.mArgs);
      } else {
        LogUnknownCommand(command.mName);
      }
    } catch (const std::exception& ex) {
      gpg::Logf("GPGNET: command processing failed: %s", ex.what());
    }

    pending.pop_front();
  }
}

/**
 * Address: 0x007B7A30 (FUN_007B7A30)
 *
 * What it does:
 * Logs diagnostic dump for Test command arguments.
 */
void CGpgNetInterface::Test(
  msvc8::vector<SNetCommandArg>& args
)
{
  const std::size_t argCount = GetCommandArgCount(args);
  gpg::Logf("GPGNET: test message, %d args", static_cast<int>(argCount));

  for (std::size_t i = 0; i < argCount; ++i) {
    const SNetCommandArg& arg = args[i];
    switch (arg.mType) {
    case SNetCommandArg::NETARG_Num:
      gpg::Logf(" arg[%d]=%d [int]", static_cast<int>(i), arg.mNum);
      break;
    case SNetCommandArg::NETARG_String:
      gpg::Logf(" arg[%d]=\"%s\" [str]", static_cast<int>(i), arg.mStr.c_str());
      break;
    case SNetCommandArg::NETARG_Data: {
      msvc8::string hexDump;
      for (std::size_t b = 0; b < arg.mStr.size(); ++b) {
        if (b != 0) {
          hexDump.append(1, ' ');
        }
        const auto chunk = gpg::STR_Printf("%02x", static_cast<unsigned char>(arg.mStr[b]));
        hexDump.append(chunk.data(), chunk.size());
      }
      gpg::Logf(" arg[%d]={%s}", static_cast<int>(i), hexDump.c_str());
      break;
    }
    default:
      gpg::Logf(" arg[%d]=? [unknown type %d]", static_cast<int>(i), static_cast<int>(arg.mType));
      break;
    }
  }
}

/**
 * Address: 0x007B7C50 (FUN_007B7C50)
 *
 * What it does:
 * Verifies empty argument list and sends `GameState = "Idle"` to GPGNet.
 */
void CGpgNetInterface::Connected(
  msvc8::vector<SNetCommandArg>& args
)
{
  if (!args.empty()) {
    throw std::runtime_error("Wrong number of arguments to Connected command, expected 0");
  }

  gpg::Logf("GPGNET: entering idle state.");
  SNetCommandArg stateArg(msvc8::string("Idle"));
  WriteCommandWith1Arg("GameState", &stateArg);
}

/**
 * Address: 0x007B7DE0 (FUN_007B7DE0)
 *
 * What it does:
 * Calls Lua-side `CreateLobby` factory and stores returned lobby object.
 *
 * Note:
 * NAT traversal object argument is currently passed as `nil` until
 * `NET_MakeNATTraversal` binding is fully reconstructed.
 */
void CGpgNetInterface::CreateLobby(
  msvc8::vector<SNetCommandArg>& args
)
{
  if (args.size() != 5) {
    throw std::runtime_error("Wrong number of arguments to CreateLobby command, expected 5");
  }

  if (!mLobbyObject.IsNil()) {
    throw std::runtime_error("Lobby already exists.");
  }

  LuaPlus::LuaState* const state = LuaPlus::g_ConsoleLuaState();
  if (!state) {
    throw std::runtime_error("No active Lua state.");
  }

  LuaPlus::LuaObject createLobby = state->GetGlobal("CreateLobby");
  if (createLobby.IsNil()) {
    throw std::runtime_error("Failed to load \"/lua/multiplayer/onlineprovider.lua\".");
  }

  const bool useUdp = ExpectIntArg(*this, &args[0]) != 0;
  const int localPort = ExpectIntArg(*this, &args[1]);
  const msvc8::string& playerName = ExpectedString(&args[2]);
  const int playerUid = ExpectIntArg(*this, &args[3]);
  const int natPort = ExpectIntArg(*this, &args[4]);
  const msvc8::string playerUidText = gpg::STR_Printf("%d", playerUid);

  LuaPlus::LuaFunction<LuaPlus::LuaObject> createLobbyFn(createLobby);
  mLobbyObject = createLobbyFn.Call_UDP(useUdp, localPort, playerName, playerUidText.c_str(), nullptr, natPort);

  gpg::Logf("GPGNET: entering lobby state.");
  SNetCommandArg stateArg(msvc8::string("Lobby"));
  WriteCommandWith1Arg("GameState", &stateArg);
}

/**
 * Address: 0x007B81D0 (FUN_007B81D0)
 *
 * What it does:
 * Invokes lobby `HostGame` script callback with optional scenario path.
 */
void CGpgNetInterface::HostGame(
  msvc8::vector<SNetCommandArg>& args
)
{
  if (args.size() > 1) {
    throw std::runtime_error("Wrong number of arguments to HostGame command, expected 0 or 1");
  }

  LuaPlus::LuaObject hostGameObj = moho::SCR_GetLuaTableFieldOrThrow(
    mLobbyObject, "HostGame", "No lobby.", "Lobby method \"%s\" is unavailable."
  );
  LuaPlus::LuaFunction<void> hostGame(hostGameObj);

  msvc8::string scenarioPath;
  if (!args.empty()) {
    const msvc8::string& mapName = ExpectedString(&args[0]);
    scenarioPath = gpg::STR_Printf("/maps/%s/%s_scenario.lua", mapName.c_str(), mapName.c_str());
  }

  hostGame(scenarioPath.c_str());
}

/**
 * Address: 0x007B83C0 (FUN_007B83C0)
 *
 * What it does:
 * Invokes lobby `JoinGame` script callback with host/player/uid parameters.
 */
void CGpgNetInterface::JoinGame(
  msvc8::vector<SNetCommandArg>& args
)
{
  if (args.size() != 3) {
    throw std::runtime_error("Wrong number of arguments to JoinGame command, expected 3");
  }

  LuaPlus::LuaObject joinGameObj = moho::SCR_GetLuaTableFieldOrThrow(
    mLobbyObject, "JoinGame", "No lobby.", "Lobby method \"%s\" is unavailable."
  );
  LuaPlus::LuaFunction<void> joinGame(joinGameObj);

  const msvc8::string& hostAddress = ExpectedString(&args[0]);
  const msvc8::string& playerName = ExpectedString(&args[1]);
  const int playerUid = ExpectIntArg(*this, &args[2]);
  const msvc8::string playerUidText = gpg::STR_Printf("%d", playerUid);

  joinGame(hostAddress.c_str(), false, playerName.c_str(), playerUidText.c_str());
}

/**
 * Address: 0x007B85A0 (FUN_007B85A0)
 *
 * What it does:
 * Invokes lobby `ConnectToPeer` script callback.
 */
void CGpgNetInterface::ConnectToPeer(
  msvc8::vector<SNetCommandArg>& args
)
{
  if (args.size() != 3) {
    throw std::runtime_error("Wrong number of arguments to ConnectToPeer command, expected 3");
  }

  LuaPlus::LuaObject connectToPeerObj = moho::SCR_GetLuaTableFieldOrThrow(
    mLobbyObject, "ConnectToPeer", "No lobby.", "Lobby method \"%s\" is unavailable."
  );
  LuaPlus::LuaFunction<void> connectToPeer(connectToPeerObj);

  const msvc8::string& endpoint = ExpectedString(&args[0]);
  const msvc8::string& playerName = ExpectedString(&args[1]);
  const int peerUid = ExpectIntArg(*this, &args[2]);
  const msvc8::string peerUidText = gpg::STR_Printf("%d", peerUid);

  connectToPeer(endpoint.c_str(), playerName.c_str(), peerUidText.c_str());
}

/**
 * Address: 0x007B8780 (FUN_007B8780)
 *
 * What it does:
 * Invokes lobby `DisconnectFromPeer` script callback for one uid.
 */
void CGpgNetInterface::DisconnectFromPeer(
  msvc8::vector<SNetCommandArg>& args
)
{
  if (args.size() != 1) {
    throw std::runtime_error("Wrong number of arguments to DisconnectFromPeer command, expected 1");
  }

  LuaPlus::LuaObject disconnectObj = moho::SCR_GetLuaTableFieldOrThrow(
    mLobbyObject, "DisconnectFromPeer", "No lobby.", "Lobby method \"%s\" is unavailable."
  );
  LuaPlus::LuaFunction<void> disconnectFromPeer(disconnectObj);

  const int peerUid = ExpectIntArg(*this, &args[0]);
  const msvc8::string peerUidText = gpg::STR_Printf("%d", peerUid);
  disconnectFromPeer(peerUidText.c_str());
}

/**
 * Address: 0x007B8920 (FUN_007B8920)
 *
 * What it does:
 * Invokes lobby `SetHasSupcom` script callback.
 */
void CGpgNetInterface::HasSupCom(
  msvc8::vector<SNetCommandArg>& args
)
{
  if (args.size() != 1) {
    throw std::runtime_error("Wrong number of arguments to SetHasSupcom command, expected 1");
  }

  LuaPlus::LuaObject hasSupComObj = moho::SCR_GetLuaTableFieldOrThrow(
    mLobbyObject, "SetHasSupcom", "No lobby.", "Lobby method \"%s\" is unavailable."
  );
  LuaPlus::LuaFunction<void> setHasSupCom(hasSupComObj);
  setHasSupCom(ExpectIntArg(*this, &args[0]));
}

/**
 * Address: 0x007B8A70 (FUN_007B8A70)
 *
 * What it does:
 * Invokes lobby `SetHasForgedAlliance` script callback.
 */
void CGpgNetInterface::HasForgedAlliance(
  msvc8::vector<SNetCommandArg>& args
)
{
  if (args.size() != 1) {
    throw std::runtime_error("Wrong number of arguments to SetHasForgedAlliance command, expected 1");
  }

  LuaPlus::LuaObject hasFaObj = moho::SCR_GetLuaTableFieldOrThrow(
    mLobbyObject, "SetHasForgedAlliance", "No lobby.", "Lobby method \"%s\" is unavailable."
  );
  LuaPlus::LuaFunction<void> setHasFa(hasFaObj);
  setHasFa(ExpectIntArg(*this, &args[0]));
}

/**
 * Address: 0x007B8BC0 (FUN_007B8BC0)
 *
 * What it does:
 * Validates NAT command args (`"ip:port"`, binary payload), resolves remote
 * endpoint, and forwards payload through registered NAT traversal handler.
 */
void CGpgNetInterface::SendNatPacket(
  msvc8::vector<SNetCommandArg>& args
)
{
  if (args.size() != 2) {
    throw std::runtime_error("Wrong number of arguments to SendNatPacket command, expected 2");
  }

  const auto natHandler = mNATHandler.lock();
  if (!natHandler) {
    throw std::runtime_error("Can't send nat packets if we don't have a nat handler.");
  }

  const msvc8::string& endpoint = ExpectedString(&args[0]);

  u_long remoteAddress = 0;
  u_short remotePort = 0;
  if (!NET_GetAddrInfo(endpoint.c_str(), 0, false, remoteAddress, remotePort) || remotePort == 0) {
    throw std::runtime_error("Invalid remote address");
  }

  const auto& payloadArg = args[1];
  if (payloadArg.mType != SNetCommandArg::NETARG_Data) {
    ExpectedData();
  }

  const auto remoteHost = NET_GetDottedOctetFromUInt32(remoteAddress);
  gpg::Logf("GPGNET: sending nat packet to %s:%d", remoteHost.c_str(), static_cast<int>(remotePort));

  natHandler->ReceivePacket(remoteAddress, remotePort, payloadArg.mStr.data(), payloadArg.mStr.size());
}

/**
 * Address: 0x007B8E20 (FUN_007B8E20)
 *
 * What it does:
 * Validates eject request, resolves the target client from the active sim
 * driver, then disconnects/ejects it and prints the localized console notice.
 */
void CGpgNetInterface::EjectPlayer(
  msvc8::vector<SNetCommandArg>& args
)
{
  if (args.size() != 1) {
    throw std::runtime_error("Wrong number of arguments to EjectPlayer, expected 1");
  }

  ISTIDriver* const activeDriver = SIM_GetActiveDriver();
  if (activeDriver == nullptr) {
    throw std::runtime_error("No active session.");
  }

  const int playerUid = ExpectIntArg(*this, &args[0]);
  CClientManagerImpl* const clientManager = activeDriver->GetClientManager();
  IClient* const targetClient = clientManager->GetClientWithData(playerUid);
  if (targetClient == nullptr) {
    throw std::runtime_error(gpg::STR_Printf("No client with uid %d", playerUid).c_str());
  }

  if (targetClient == clientManager->GetLocalClient()) {
    clientManager->Disconnect();

    const msvc8::string localizedMessage = Loc(
      USER_GetLuaState(),
      "<LOC Engine0016>You have been ejected due to connectivity issues."
    );
    CON_Printf(localizedMessage.c_str());
    return;
  }

  targetClient->Eject();

  const msvc8::string localizedMessage = Loc(
    USER_GetLuaState(),
    "<LOC Engine0017>%s has been ejected due to connectivity issues."
  );
  CON_Printf(localizedMessage.c_str(), targetClient->GetNickname().c_str());
}

/**
 * Address: 0x007BA5E0 (FUN_007BA5E0)
 *
 * What it does:
 * Performs synchronous TCP connect and starts inbound socket read loop.
 */
void CGpgNetInterface::ConnectThread(
  const u_long address,
  const u_short port
)
{
  INetTCPSocket* const connectedSocket = NET_TCPConnect(address, port);
  INetTCPSocket* const oldSocket = mTcpSocket;
  mTcpSocket = connectedSocket;
  if (oldSocket) {
    delete oldSocket;
  }

  if (mTcpSocket) {
    ReadFromSocket();
  } else {
    EnqueueCommand0("ConnectFailed", kNetStateTimedOut);
  }
}

/**
 * Address: 0x007BA640 (FUN_007BA640, func_NET_ConnectThread)
 *
 * What it does:
 * Creates a local loopback TCP listener, launches external GPGNet process
 * using one command-line template, accepts the incoming socket, and starts
 * command read loop.
 */
void CGpgNetInterface::ConnectThread(
  const msvc8::string& launchCommandTemplate
)
{
  const msvc8::string loopbackAddress("127.0.0.1");
  INetTCPServer* const createdServer = NET_CreateTCPServer(
    NET_GetUInt32FromDottedOcted(loopbackAddress),
    0
  );

  INetTCPServer* const oldServer = mTcpServer;
  mTcpServer = createdServer;
  if (oldServer != nullptr) {
    delete oldServer;
  }

  if (mTcpServer == nullptr) {
    EnqueueCommand0("LaunchFailed", kNetStateTimedOut);
    return;
  }

  STARTUPINFOA startupInfo{};
  startupInfo.cb = sizeof(startupInfo);
  PROCESS_INFORMATION processInformation{};

  const u_short localPort = mTcpServer->GetLocalPort();
  const msvc8::string listenerAddress = gpg::STR_Printf("127.0.0.1:%d", static_cast<int>(localPort));
  const msvc8::string launchCommand = gpg::STR_Printf(launchCommandTemplate.c_str(), listenerAddress.c_str());

  std::vector<char> launchCommandBuffer(launchCommand.size() + 1u, '\0');
  if (!launchCommand.empty()) {
    std::memcpy(launchCommandBuffer.data(), launchCommand.data(), launchCommand.size());
  }

  const BOOL launchOk = ::CreateProcessA(
    nullptr,
    launchCommandBuffer.data(),
    nullptr,
    nullptr,
    FALSE,
    0,
    nullptr,
    nullptr,
    &startupInfo,
    &processInformation
  );

  if (!launchOk) {
    const msvc8::string lastError = WIN_GetLastError();
    gpg::Logf("CreateProcess() failed: %s", lastError.c_str());
    EnqueueCommand0("LaunchFailed", kNetStateTimedOut);
    return;
  }

  ::CloseHandle(processInformation.hProcess);
  ::CloseHandle(processInformation.hThread);

  INetTCPSocket* const acceptedSocket = mTcpServer->Accept();
  INetTCPSocket* const oldSocket = mTcpSocket;
  mTcpSocket = acceptedSocket;
  if (oldSocket != nullptr) {
    delete oldSocket;
  }

  INetTCPServer* const serverToDestroy = mTcpServer;
  mTcpServer = nullptr;
  if (serverToDestroy != nullptr) {
    delete serverToDestroy;
  }

  if (mTcpSocket == nullptr) {
    EnqueueCommand0("LaunchFailed", kNetStateTimedOut);
    return;
  }

  ReadFromSocket();
}

/**
 * Address: 0x007BA880 (FUN_007BA880)
 *
 * What it does:
 * Reads and decodes framed commands from TCP stream and enqueues them for
 * pull-task dispatch.
 */
void CGpgNetInterface::ReadFromSocket()
{
  if (!mTcpSocket) {
    return;
  }

  EnqueueCommand0("Connected", kNetStateEstablishing);

  try {
    for (;;) {
      uint32_t commandNameLength = 0;
      const size_t got = mTcpSocket->Read(reinterpret_cast<char*>(&commandNameLength), sizeof(commandNameLength));
      if (got == 0) {
        EnqueueCommand0("ConnectionShutdown", kNetStateEstablishing);
        return;
      }
      if (got < sizeof(commandNameLength)) {
        throw std::runtime_error("premature EOF reading from gpg.net socket");
      }

      msvc8::string commandName;
      if (commandNameLength != 0) {
        std::vector<char> nameBuffer(commandNameLength);
        ReadExactFromSocket(
          mTcpSocket, nameBuffer.data(), commandNameLength, "premature EOF reading from gpg.net socket"
        );
        commandName.assign(nameBuffer.data(), commandNameLength);
      }

      gpg::BinaryReader reader(mTcpSocket);
      uint32_t argCount = 0;
      reader.ReadExact(argCount);

      msvc8::vector<SNetCommandArg> args;
      if (argCount) {
        args.reserve(argCount);
      }

      for (uint32_t i = 0; i < argCount; ++i) {
        args.push_back(moho::NET_DecodeSocketArg(reader));
      }

      EnqueueCommand(commandName.c_str(), args, kNetStateEstablishing);
    }
  } catch (const std::exception& ex) {
    msvc8::vector<SNetCommandArg> args;
    args.push_back(SNetCommandArg(msvc8::string(ex.what() ? ex.what() : "communication error")));
    EnqueueCommand("CommunicationError", args, kNetStateTimedOut);
  }
}

/**
 * Address: 0x007BAE50 (FUN_007BAE50)
 *
 * What it does:
 * Queues one decoded command and signals queue event if queue transitions
 * from empty to non-empty.
 */
void CGpgNetInterface::EnqueueCommand(
  const char* name,
  msvc8::vector<SNetCommandArg>& args,
  int val
)
{
  boost::mutex::scoped_lock lock(mLock);

  if (mCommands.empty() && mQueueEvent) {
    SetEvent(mQueueEvent);
  }

  const SNetCommand command(name, args, val);
  PushBackQueuedCommand(mCommands, command);
}

namespace
{
  constexpr const char* kLaunchGPGNetName = "LaunchGPGNet";
  constexpr const char* kLaunchGPGNetHelpText = "LaunchGPGNet()";
  constexpr const wchar_t* kGPGNetDefaultPath =
    L"c:\\Program Files\\THQ\\Gas Powered Games\\GPGNet\\GPG.Multiplayer.Client.exe";
  constexpr const wchar_t* kGPGNetDevExePath =
    L"C:\\work\\rts\\main\\code\\src\\Multiplayer\\MultiplayerClient\\bin\\Debug\\MultiplayerClient.exe";
  constexpr const wchar_t* kGPGNetDevParams =
    L"/luapath=\"C:\\work\\rts\\main\\code\\src\\Multiplayer\\MultiplayerClient\\\"";
  constexpr const wchar_t* kGPGNetDevWorkingDir =
    L"C:\\work\\rts\\main\\code\\src\\Multiplayer\\MultiplayerClient\\bin\\Debug\\";

  [[nodiscard]] bool TryLoadGPGNetPathFromRegistry(const char* const keyPath, std::wstring& outPath)
  {
    std::array<std::uint8_t, 256> buffer{};
    const std::uint32_t length = moho::PLAT_GetRegistryValue(keyPath, buffer.data(), static_cast<std::uint32_t>(buffer.size()));
    if (length == 0) {
      return false;
    }

    outPath.assign(length, L'\0');
    std::mbstowcs(outPath.data(), reinterpret_cast<const char*>(buffer.data()), length);

    return GetFileAttributesW(outPath.c_str()) != INVALID_FILE_ATTRIBUTES;
  }
} // namespace

/**
 * Address: 0x007BA340 (FUN_007BA340, cfunc_LaunchGPGNetL)
 *
 * What it does:
 * Resolves the GPGNet client executable path (developer override via
 * `/gpgnetdev`, then `HKCU\Software\GPG\GPGNet\GPGNetPath`, then
 * `HKLM\Software\GPG\GPGNet\GPGNetPath`, then a hardcoded default) and
 * launches it via `ShellExecuteExW` with the main window as owner.
 * Restores the x87 control word afterward and pushes the boolean launch
 * result back to Lua.
 */
int moho::cfunc_LaunchGPGNetL(LuaPlus::LuaState* const state)
{
  if (!state || !state->m_state) {
    return 0;
  }

  lua_State* const rawState = state->m_state;
  const int argumentCount = lua_gettop(rawState);
  if (argumentCount != 0) {
    LuaPlus::LuaState::Error(state, kLuaExpectedArgsWarning, kLaunchGPGNetHelpText, 0, argumentCount);
  }

  HWND ownerWindow = nullptr;
  if (moho::sMainWindow != nullptr) {
    ownerWindow = reinterpret_cast<HWND>(static_cast<std::uintptr_t>(moho::sMainWindow->GetHandle()));
  }

  SHELLEXECUTEINFOW execInfo{};
  execInfo.cbSize = sizeof(execInfo);
  execInfo.fMask = SEE_MASK_NOCLOSEPROCESS;
  execInfo.hwnd = ownerWindow;
  execInfo.lpVerb = L"open";
  execInfo.nShow = SW_SHOWDEFAULT;

  std::wstring resolvedPath;
  if (moho::CFG_GetArgOption(gpg::StrArg{"/gpgnetdev"}, 0u, nullptr)) {
    execInfo.lpFile = kGPGNetDevExePath;
    execInfo.lpParameters = kGPGNetDevParams;
    execInfo.lpDirectory = kGPGNetDevWorkingDir;
  } else {
    if (TryLoadGPGNetPathFromRegistry("HKEY_CURRENT_USER\\Software\\GPG\\GPGNet\\GPGNetPath", resolvedPath)) {
      execInfo.lpFile = resolvedPath.c_str();
    } else if (TryLoadGPGNetPathFromRegistry("HKEY_LOCAL_MACHINE\\Software\\GPG\\GPGNet\\GPGNetPath", resolvedPath)) {
      execInfo.lpFile = resolvedPath.c_str();
    } else {
      execInfo.lpFile = kGPGNetDefaultPath;
    }
    execInfo.lpParameters = L"";
    execInfo.lpDirectory = L"";
  }

  const BOOL launched = ShellExecuteExW(&execInfo);

  // ShellExecuteExW can perturb the x87 FPU control word; restore the engine's
  // preferred precision/rounding configuration before returning to Lua.
  _controlfp(_PC_64, _MCW_PC);

  lua_pushboolean(rawState, launched ? 1 : 0);
  (void)lua_gettop(rawState);
  return 1;
}

/**
 * Address: 0x007BA2C0 (FUN_007BA2C0, cfunc_LaunchGPGNet)
 *
 * What it does:
 * Unwraps the raw `lua_State` callback context and forwards to
 * `cfunc_LaunchGPGNetL`.
 */
int moho::cfunc_LaunchGPGNet(lua_State* const luaContext)
{
  return cfunc_LaunchGPGNetL(SCR_ResolveBindingState(luaContext));
}

/**
 * Address: 0x007BA2E0 (FUN_007BA2E0, func_LaunchGPGNet_LuaFuncDef)
 *
 * What it does:
 * Publishes the `LaunchGPGNet()` binder into the user Lua init set.
 */
moho::CScrLuaInitForm* moho::func_LaunchGPGNet_LuaFuncDef()
{
  static CScrLuaBinder binder(
    UserLuaInitSet(),
    kLaunchGPGNetName,
    &moho::cfunc_LaunchGPGNet,
    nullptr,
    "<global>",
    kLaunchGPGNetHelpText
  );
  return &binder;
}
